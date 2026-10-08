//go:build linux

package sandboxexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestJobsOwnershipCursorsAndCompletion(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, stdout, stderr *limitBuffer, started func()) (Result, error) {
		started()
		_, _ = stdout.Write([]byte("hello"))
		_, _ = stderr.Write([]byte("warning"))
		return Result{ExitCode: 0, DurationMS: 12}, nil
	})

	created, err := manager.Start("client-a", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, manager, "client-a", created.ID, JobSucceeded)
	status, err := manager.Status("client-a", created.ID, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if status.Stdout != "llo" || status.Stderr != "ing" || status.StdoutCursor != 5 || status.StderrCursor != 7 {
		t.Fatalf("unexpected cursor output: %#v", status)
	}
	if _, err := manager.Status("client-b", created.ID, 0, 0); err == nil {
		t.Fatal("different owner accessed job")
	}
}

func TestJobsCancelAndCapacity(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	manager := testJobs(t, func(ctx context.Context, _ Request, _ map[string]string, _ bool, _, _ *limitBuffer, markStarted func()) (Result, error) {
		markStarted()
		close(started)
		<-ctx.Done()
		return Result{ExitCode: -1, Canceled: true}, nil
	})
	manager.runner.cfg.ExecMaxJobs = 1

	created, err := manager.Start("client", Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := manager.Start("client", Request{Argv: []string{"second"}}); err == nil {
		t.Fatal("capacity limit not enforced")
	}
	if _, err := manager.Cancel("client", created.ID); err != nil {
		t.Fatal(err)
	}
	waitJob(t, manager, "client", created.ID, JobCanceled)
}

func TestJobsFinishedJobsDoNotBlockNewWork(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, _, _ *limitBuffer, started func()) (Result, error) {
		started()
		return Result{}, nil
	})
	manager.runner.cfg.ExecMaxJobs = 1

	for i := 0; i < 4; i++ {
		created, err := manager.Start("client", Request{Argv: []string{"true"}})
		if err != nil {
			t.Fatalf("start %d with only finished jobs retained: %v", i, err)
		}
		waitJob(t, manager, "client", created.ID, JobSucceeded)
	}
}

func TestJobsTrimPrefersReadJobsAndLeavesTombstone(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, stdout, _ *limitBuffer, started func()) (Result, error) {
		started()
		_, _ = stdout.Write([]byte("output"))
		return Result{}, nil
	})
	manager.maxFinished = 2

	unreadOld, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitFinishedUnread(t, manager, unreadOld.ID)
	read, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, manager, "client", read.ID, JobSucceeded) // reading marks the job as read
	unreadNew, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitFinishedUnread(t, manager, unreadNew.ID)

	// Three finished jobs, room for two: the one already read goes, even
	// though an unread job is older.
	if _, err := manager.Status("client", unreadOld.ID, 0, 0); err != nil {
		t.Fatalf("older unread job evicted: %v", err)
	}
	if _, err := manager.Status("client", unreadNew.ID, 0, 0); err != nil {
		t.Fatalf("newest job evicted: %v", err)
	}
	_, err = manager.Status("client", read.ID, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "no longer available") || !strings.Contains(err.Error(), "succeeded") {
		t.Fatalf("evicted job error = %v, want tombstone message", err)
	}
	if _, err := manager.Status("other", read.ID, 0, 0); err == nil || strings.Contains(err.Error(), "no longer available") {
		t.Fatalf("tombstone leaked to another owner: %v", err)
	}
}

func TestJobsTombstonesAreBounded(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(context.Context, Request, map[string]string, bool, *limitBuffer, *limitBuffer, func()) (Result, error) {
		return Result{}, nil
	})
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for i := 0; i < tombstonesRetained+10; i++ {
		manager.dropLocked(&job{id: fmt.Sprintf("job-%d", i), owner: "client", state: JobSucceeded}, "test")
	}
	if len(manager.tombstones) != tombstonesRetained || len(manager.tombstoneOrder) != tombstonesRetained {
		t.Fatalf("tombstones = %d, order = %d, want %d", len(manager.tombstones), len(manager.tombstoneOrder), tombstonesRetained)
	}
	if _, ok := manager.tombstones["job-0"]; ok {
		t.Fatal("oldest tombstone retained")
	}
}

func TestJobsEvictsExpiredCompletedJobs(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, _, _ *limitBuffer, started func()) (Result, error) {
		started()
		return Result{}, nil
	})
	now := time.Now()
	manager.now = func() time.Time { return now }
	created, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, manager, "client", created.ID, JobSucceeded)
	now = now.Add(manager.runner.cfg.ExecJobTTL)
	if _, err := manager.Status("client", created.ID, 0, 0); err == nil {
		t.Fatal("expired job retained")
	}
}

func TestJobsRecordsRunnerError(t *testing.T) {
	t.Parallel()

	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, _, _ *limitBuffer, started func()) (Result, error) {
		started()
		return Result{}, errors.New("launch failed")
	})
	created, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	status := waitJob(t, manager, "client", created.ID, JobFailed)
	if status.Error != "launch failed" {
		t.Fatalf("error = %q", status.Error)
	}
}

func testJobs(t *testing.T, run func(context.Context, Request, map[string]string, bool, *limitBuffer, *limitBuffer, func()) (Result, error)) *Jobs {
	t.Helper()
	runner := &Runner{cfg: testConfig(), sem: make(chan struct{}, 1)}
	manager, err := NewJobs(runner)
	if err != nil {
		t.Fatal(err)
	}
	manager.run = run
	t.Cleanup(manager.Close)
	return manager
}

func waitJob(t *testing.T, manager *Jobs, owner, id string, want JobState) JobStatus {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.Status(owner, id, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if terminalState(status.State) {
			if status.State != want {
				t.Fatalf("state = %q, want %q", status.State, want)
			}
			return status
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not finish")
	return JobStatus{}
}

// waitFinishedUnread waits for a job to finish without calling Status, which
// would mark it as read.
func waitFinishedUnread(t *testing.T, manager *Jobs, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		j, ok := manager.jobs[id]
		done := ok && terminalState(j.state)
		manager.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not finish")
}

func TestNewJobsNil(t *testing.T) {
	t.Parallel()
	if _, err := NewJobs(nil); err == nil {
		t.Fatal("NewJobs(nil) accepted")
	}
}

func TestJobsValidationAndLifecycle(t *testing.T) {
	t.Parallel()
	manager := testJobs(t, func(_ context.Context, _ Request, _ map[string]string, _ bool, _, _ *limitBuffer, started func()) (Result, error) {
		started()
		return Result{ExitCode: 0}, nil
	})

	// Empty owner.
	if _, err := manager.Start("", Request{Argv: []string{"true"}}); err == nil {
		t.Fatal("empty owner accepted")
	}

	// Invalid request.
	if _, err := manager.Start("client", Request{}); err == nil {
		t.Fatal("empty request accepted")
	}

	// Timeout exceeds limit.
	if _, err := manager.Start("client", Request{Argv: []string{"true"}, TimeoutMS: 10000000}); err == nil {
		t.Fatal("excessive timeout accepted")
	}

	// Status with nonexistent job.
	if _, err := manager.Status("client", "missing-id", 0, 0); err == nil {
		t.Fatal("nonexistent job status succeeded")
	}

	// Cancel nonexistent job.
	if _, err := manager.Cancel("client", "missing-id"); err == nil {
		t.Fatal("nonexistent job cancel succeeded")
	}

	// Successful run and cancelling already completed job.
	created, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, manager, "client", created.ID, JobSucceeded)
	status, err := manager.Cancel("client", created.ID)
	if err != nil || status.State != JobSucceeded {
		t.Fatalf("cancel on completed job failed: %v, %#v", err, status)
	}

	// Close manager and attempt start on closed.
	manager.Close()
	manager.Close() // Idempotent close
	if _, err := manager.Start("client", Request{Argv: []string{"true"}}); err == nil {
		t.Fatal("start on closed manager accepted")
	}
}

// blockingJobs returns a manager whose jobs run until release is closed or the
// job is canceled, optionally writing output first.
func blockingJobs(t *testing.T, output string, release chan struct{}) *Jobs {
	t.Helper()
	return testJobs(t, func(ctx context.Context, _ Request, _ map[string]string, _ bool, stdout, _ *limitBuffer, started func()) (Result, error) {
		started()
		select {
		case <-release:
		case <-ctx.Done():
			return Result{ExitCode: -1, Canceled: true}, nil
		}
		if output != "" {
			_, _ = stdout.Write([]byte(output))
		}
		return Result{}, nil
	})
}

func TestJobsWaitReturnsWhenJobFinishes(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	manager := blockingJobs(t, "done", release)
	manager.runner.cfg.ExecTimeout = 10 * time.Second
	created, err := manager.Start("client", Request{Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(60*time.Millisecond, func() { close(release) })

	start := time.Now()
	status, err := manager.Wait(context.Background(), "client", created.ID, 0, 0, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != JobSucceeded || status.Stdout != "done" {
		t.Fatalf("status = %#v, want finished job with output", status)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Wait took %s; it must return as soon as the job finishes", elapsed)
	}
}

func TestJobsWaitTimesOutAndRespectsContext(t *testing.T) {
	t.Parallel()

	manager := blockingJobs(t, "", make(chan struct{}))
	manager.runner.cfg.ExecTimeout = 10 * time.Second
	created, err := manager.Start("client", Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	status, err := manager.Wait(context.Background(), "client", created.ID, 0, 0, 80*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if terminalState(status.State) {
		t.Fatalf("state = %q, job should still be running", status.State)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Fatalf("Wait returned after %s, before the wait elapsed", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(40*time.Millisecond, cancel)
	start = time.Now()
	if _, err := manager.Wait(ctx, "client", created.ID, 0, 0, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Wait ignored context cancellation (%s)", elapsed)
	}
}

func TestJobsWaitIsCappedAtExecTimeout(t *testing.T) {
	t.Parallel()

	manager := blockingJobs(t, "", make(chan struct{}))
	manager.runner.cfg.ExecTimeout = 60 * time.Millisecond
	created, err := manager.Start("client", Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := manager.Wait(context.Background(), "client", created.ID, 0, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Wait was not capped (%s)", elapsed)
	}
}

func TestJobsWaitNoWaitAndErrors(t *testing.T) {
	t.Parallel()

	manager := blockingJobs(t, "", make(chan struct{}))
	manager.runner.cfg.ExecTimeout = 10 * time.Second
	created, err := manager.Start("client", Request{Argv: []string{"sleep"}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := manager.Wait(context.Background(), "client", created.ID, 0, 0, 0); err != nil {
		t.Fatalf("zero wait: %v", err)
	}
	if _, err := manager.Wait(context.Background(), "client", created.ID, 0, 0, -time.Second); err != nil {
		t.Fatalf("negative wait: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("zero or negative wait blocked")
	}
	// Unknown job and foreign owner fail immediately instead of waiting.
	start = time.Now()
	if _, err := manager.Wait(context.Background(), "client", "missing", 0, 0, 5*time.Second); err == nil {
		t.Fatal("missing job accepted")
	}
	if _, err := manager.Wait(context.Background(), "other", created.ID, 0, 0, 5*time.Second); err == nil {
		t.Fatal("foreign owner accepted")
	}
	// A cursor beyond the stream is an error, reported without waiting.
	if _, err := manager.Wait(context.Background(), "client", created.ID, 99, 0, 5*time.Second); err == nil {
		t.Fatal("out-of-range cursor accepted")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("error paths waited")
	}
}
