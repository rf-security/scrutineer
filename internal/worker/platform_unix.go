//go:build unix

package worker

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startSupervised starts cmd in its own process group, so a terminal interrupt
// reaches scrutineer's shutdown path rather than the child, and returns the
// func that sends SIGTERM to that whole group, reaping children the runtime or
// harness CLI left running. Call it once Wait has returned.
func startSupervised(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	return func() { _ = syscall.Kill(-pid, syscall.SIGTERM) }, nil
}

func startBackendProbe(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = cmd.Cancel() }, nil
}

// containerUserArgs maps the container user onto the invoking host user so
// bind-mount writes stay host-owned.
func containerUserArgs() []string {
	return []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
}
