//go:build linux

package sandboxexec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type JobState string

const (
	JobQueued    JobState = "queued"
	JobRunning   JobState = "running"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed"
	JobCanceled  JobState = "canceled"
	JobTimedOut  JobState = "timed_out"
)

type JobStatus struct {
	ID    string   `json:"id"`
	State JobState `json:"state"`
	// Stdout and Stderr hold output after the supplied cursors. Cursors are
	// absolute stream offsets; once more than the retention limit has been
	// produced the oldest bytes are dropped and reported in the *DroppedBytes
	// fields. A cursor older than the retained window resumes at its start.
	Stdout             string `json:"stdout"`
	Stderr             string `json:"stderr"`
	StdoutCursor       int    `json:"stdout_cursor"`
	StderrCursor       int    `json:"stderr_cursor"`
	StdoutTruncated    bool   `json:"stdout_truncated"`
	StderrTruncated    bool   `json:"stderr_truncated"`
	StdoutDroppedBytes int    `json:"stdout_dropped_bytes,omitempty"`
	StderrDroppedBytes int    `json:"stderr_dropped_bytes,omitempty"`
	ExitCode           int    `json:"exit_code,omitempty"`
	Signal             string `json:"signal,omitempty"`
	DurationMS         int64  `json:"duration_ms,omitempty"`
	Error              string `json:"error,omitempty"`
	CreatedAt          string `json:"created_at"`
	StartedAt          string `json:"started_at,omitempty"`
	CompletedAt        string `json:"completed_at,omitempty"`
}

const (
	// defaultFinishedJobsRetained bounds finished jobs kept for later reads. Only
	// queued and running jobs count against ExecMaxJobs, so finished jobs never
	// block new work.
	defaultFinishedJobsRetained = 32
	// tombstonesRetained bounds the record of dropped jobs, which lets
	// exec_status say why a job's output is gone instead of "not found".
	tombstonesRetained = 256
)

// tombstone remembers a job that was dropped from the table.
type tombstone struct {
	owner    string
	state    JobState
	exitCode int
	reason   string
}

type Jobs struct {
	runner         *Runner
	run            func(context.Context, Request, map[string]string, bool, *limitBuffer, *limitBuffer, func()) (Result, error)
	mu             sync.Mutex
	jobs           map[string]*job
	maxFinished    int
	tombstones     map[string]tombstone
	tombstoneOrder []string
	closed         bool
	now            func() time.Time
	wg             sync.WaitGroup
}

type job struct {
	id          string
	owner       string
	state       JobState
	createdAt   time.Time
	startedAt   time.Time
	completedAt time.Time
	stdout      *limitBuffer
	stderr      *limitBuffer
	result      Result
	err         error
	cancel      context.CancelFunc
	// read is set once the job has finished and a status call returned its
	// output, so it is the preferred victim when finished jobs are trimmed.
	read bool
}

func NewJobs(runner *Runner) (*Jobs, error) {
	if runner == nil {
		return nil, errors.New("sandbox runner is required")
	}
	return &Jobs{
		runner: runner, run: runner.runWithBuffers, jobs: make(map[string]*job),
		maxFinished: defaultFinishedJobsRetained, tombstones: make(map[string]tombstone), now: time.Now,
	}, nil
}

func (m *Jobs) Start(owner string, request Request) (JobStatus, error) {
	if owner == "" {
		return JobStatus{}, errors.New("job owner is required")
	}
	if err := validateRequest(request); err != nil {
		return JobStatus{}, err
	}
	if request.TimeoutMS == 0 {
		request.TimeoutMS = int(m.runner.cfg.ExecJobTimeout / time.Millisecond)
	}
	if time.Duration(request.TimeoutMS)*time.Millisecond > m.runner.cfg.ExecJobTimeout {
		return JobStatus{}, errors.New("timeout exceeds configured maximum")
	}
	id, err := randomJobID()
	if err != nil {
		return JobStatus{}, errors.New("job ID generation failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := m.now()
	j := &job{
		id: id, owner: owner, state: JobQueued, createdAt: now, cancel: cancel,
		stdout: &limitBuffer{limit: m.runner.cfg.ExecMaxOutput, mode: bufferRolling},
		stderr: &limitBuffer{limit: m.runner.cfg.ExecMaxOutput, mode: bufferRolling},
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		cancel()
		return JobStatus{}, errors.New("job manager is closed")
	}
	m.evictLocked(now)
	if m.activeLocked() >= m.runner.cfg.ExecMaxJobs {
		cancel()
		return JobStatus{}, fmt.Errorf("job capacity reached: %d jobs are queued or running; wait for one to finish or cancel one", m.runner.cfg.ExecMaxJobs)
	}
	m.jobs[id] = j
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.execute(ctx, j, request)
	}()
	return m.statusLocked(j, 0, 0)
}

func (m *Jobs) Status(owner, id string, stdoutCursor, stderrCursor int) (JobStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictLocked(m.now())
	j, err := m.ownedJobLocked(owner, id)
	if err != nil {
		return JobStatus{}, err
	}
	status, err := m.statusLocked(j, stdoutCursor, stderrCursor)
	if err == nil && terminalState(j.state) {
		j.read = true
	}
	return status, err
}

// waitPollInterval is how often Wait re-checks a job. The check is cheap (it
// compares buffer lengths and does not copy output).
const waitPollInterval = 25 * time.Millisecond

// Wait is Status that first waits, up to wait, for the job to finish or for output
// to appear past the given cursors, so a client does not have to poll. wait is
// capped at the configured synchronous exec timeout, which is always below the
// HTTP timeout. A zero or negative wait behaves exactly like Status.
func (m *Jobs) Wait(ctx context.Context, owner, id string, stdoutCursor, stderrCursor int, wait time.Duration) (JobStatus, error) {
	if limit := m.runner.cfg.ExecTimeout; wait > limit {
		wait = limit
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		tick := time.NewTicker(waitPollInterval)
		defer tick.Stop()
	poll:
		for {
			m.mu.Lock()
			m.evictLocked(m.now())
			j, err := m.ownedJobLocked(owner, id)
			// A cursor that differs from the stream length is either new output or
			// invalid; Status below reports it, so neither is worth waiting on.
			ready := err != nil || terminalState(j.state) || j.stdout.Total() != stdoutCursor || j.stderr.Total() != stderrCursor
			m.mu.Unlock()
			if ready {
				break
			}
			select {
			case <-tick.C:
			case <-timer.C:
				break poll
			case <-ctx.Done():
				break poll
			}
		}
	}
	return m.Status(owner, id, stdoutCursor, stderrCursor)
}

func (m *Jobs) Cancel(owner, id string) (JobStatus, error) {
	m.mu.Lock()
	m.evictLocked(m.now())
	j, err := m.ownedJobLocked(owner, id)
	if err != nil {
		m.mu.Unlock()
		return JobStatus{}, err
	}
	if terminalState(j.state) {
		status, statusErr := m.statusLocked(j, 0, 0)
		m.mu.Unlock()
		return status, statusErr
	}
	cancel := j.cancel
	m.mu.Unlock()
	cancel()
	return m.Status(owner, id, 0, 0)
}

func (m *Jobs) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	cancels := make([]context.CancelFunc, 0, len(m.jobs))
	for _, j := range m.jobs {
		if !terminalState(j.state) {
			cancels = append(cancels, j.cancel)
		}
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	m.wg.Wait()
}

func (m *Jobs) execute(ctx context.Context, j *job, request Request) {
	result, err := m.run(ctx, request, nil, true, j.stdout, j.stderr, func() {
		m.mu.Lock()
		if j.state == JobQueued {
			j.state = JobRunning
			j.startedAt = m.now()
		}
		m.mu.Unlock()
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	j.result = result
	j.err = err
	j.completedAt = m.now()
	switch {
	case result.TimedOut:
		j.state = JobTimedOut
	case result.Canceled || errors.Is(err, context.Canceled):
		j.state = JobCanceled
	case err != nil || result.ExitCode != 0:
		j.state = JobFailed
	default:
		j.state = JobSucceeded
	}
	m.trimFinishedLocked()
}

func (m *Jobs) statusLocked(j *job, stdoutCursor, stderrCursor int) (JobStatus, error) {
	stdout, stdoutNext, stdoutTruncated, err := j.stdout.Slice(stdoutCursor)
	if err != nil {
		return JobStatus{}, err
	}
	stderr, stderrNext, stderrTruncated, err := j.stderr.Slice(stderrCursor)
	if err != nil {
		return JobStatus{}, err
	}
	status := JobStatus{
		ID: j.id, State: j.state,
		Stdout: stdout, Stderr: stderr,
		StdoutCursor: stdoutNext, StderrCursor: stderrNext,
		StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
		StdoutDroppedBytes: j.stdout.Dropped(), StderrDroppedBytes: j.stderr.Dropped(),
		ExitCode: j.result.ExitCode, Signal: j.result.Signal, DurationMS: j.result.DurationMS,
		CreatedAt: j.createdAt.UTC().Format(time.RFC3339Nano),
	}
	if !j.startedAt.IsZero() {
		status.StartedAt = j.startedAt.UTC().Format(time.RFC3339Nano)
	}
	if !j.completedAt.IsZero() {
		status.CompletedAt = j.completedAt.UTC().Format(time.RFC3339Nano)
	}
	if j.err != nil {
		status.Error = j.err.Error()
	}
	return status, nil
}

func (m *Jobs) ownedJobLocked(owner, id string) (*job, error) {
	j, ok := m.jobs[id]
	if ok && owner != "" && j.owner == owner {
		return j, nil
	}
	if !ok && owner != "" {
		if t, dropped := m.tombstones[id]; dropped && t.owner == owner {
			return nil, fmt.Errorf("job output is no longer available: %s (state %s, exit code %d)", t.reason, t.state, t.exitCode)
		}
	}
	return nil, errors.New("job not found")
}

func (m *Jobs) evictLocked(now time.Time) {
	for _, j := range m.jobs {
		if terminalState(j.state) && now.Sub(j.completedAt) >= m.runner.cfg.ExecJobTTL {
			m.dropLocked(j, fmt.Sprintf("expired after %s", m.runner.cfg.ExecJobTTL))
		}
	}
}

// activeLocked counts queued and running jobs, the only ones limited by ExecMaxJobs.
func (m *Jobs) activeLocked() int {
	n := 0
	for _, j := range m.jobs {
		if !terminalState(j.state) {
			n++
		}
	}
	return n
}

// trimFinishedLocked keeps at most maxFinished finished jobs. Jobs whose output
// was already read go first, then the oldest unread ones.
func (m *Jobs) trimFinishedLocked() {
	var finished []*job
	for _, j := range m.jobs {
		if terminalState(j.state) {
			finished = append(finished, j)
		}
	}
	excess := len(finished) - m.maxFinished
	if excess <= 0 {
		return
	}
	sort.Slice(finished, func(a, b int) bool {
		x, y := finished[a], finished[b]
		if x.read != y.read {
			return x.read
		}
		if !x.completedAt.Equal(y.completedAt) {
			return x.completedAt.Before(y.completedAt)
		}
		return x.id < y.id
	})
	for _, j := range finished[:excess] {
		m.dropLocked(j, fmt.Sprintf("evicted to keep at most %d finished jobs", m.maxFinished))
	}
}

// dropLocked removes a job and leaves a bounded tombstone behind.
func (m *Jobs) dropLocked(j *job, reason string) {
	delete(m.jobs, j.id)
	if _, exists := m.tombstones[j.id]; !exists {
		m.tombstoneOrder = append(m.tombstoneOrder, j.id)
	}
	m.tombstones[j.id] = tombstone{owner: j.owner, state: j.state, exitCode: j.result.ExitCode, reason: reason}
	for len(m.tombstoneOrder) > tombstonesRetained {
		delete(m.tombstones, m.tombstoneOrder[0])
		m.tombstoneOrder = m.tombstoneOrder[1:]
	}
}

func terminalState(state JobState) bool {
	switch state {
	case JobSucceeded, JobFailed, JobCanceled, JobTimedOut:
		return true
	default:
		return false
	}
}

func randomJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
