//go:build linux

package sandboxexec

import (
	"context"
	"errors"
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
