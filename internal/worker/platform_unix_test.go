//go:build unix

package worker

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStartSupervisedSetsPgid(t *testing.T) {
	cmd := exec.Command("true")
	terminate, err := startSupervised(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(terminate)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("SysProcAttr = %+v, want Setpgid", cmd.SysProcAttr)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// A grandchild outlives the child that spawned it until its process group is
// signalled. It inherits the pipe's write end, so EOF on the read end is its
// exit whether or not an ancestor reaps it.
func TestStartSupervisedReapsGrandchild(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	cmd := exec.Command("sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!")
	cmd.ExtraFiles = []*os.File{w}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	rawTerminate, err := startSupervised(cmd)
	if err != nil {
		t.Fatal(err)
	}
	terminate := sync.OnceFunc(rawTerminate)
	t.Cleanup(terminate)
	out, err := io.ReadAll(stdout)
	_ = w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("grandchild pid from %q: %v", out, err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("grandchild %d not running before terminate: %v", pid, err)
	}

	terminate()

	exited := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d still alive after terminate", pid)
	}
}
