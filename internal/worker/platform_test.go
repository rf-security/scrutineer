package worker

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"testing"
)

func skipOnWindows(t *testing.T, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip(why)
	}
}

// exeName is what a fake binary must be called for `exec.LookPath` to resolve
// it: Windows finds a bare name only through a `PATHEXT` extension.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// skipWithoutPOSIXShell skips a test whose fake binary is a shell script.
// Windows runs one through the shell Git for Windows ships, so the machine
// having a shell at all is the only requirement left.
func skipWithoutPOSIXShell(t *testing.T) {
	t.Helper()
	if hostShell == "" {
		t.Skip("needs a POSIX shell to run the fake binary")
	}
}

// skipWithoutPython3 skips a test that runs a skill's own Python entry point.
func skipWithoutPython3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3 to run the skill script")
	}
}

// skipWithoutBash skips a test that runs a skill's own bash entry point.
func skipWithoutBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("needs bash to run the skill script")
	}
}

func TestContainerUserArgs(t *testing.T) {
	got := containerUserArgs()
	if runtime.GOOS == "windows" {
		if len(got) != 0 {
			t.Fatalf("containerUserArgs() = %v, want none: no host uid to map", got)
		}
		return
	}
	want := []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
	if !slices.Equal(got, want) {
		t.Fatalf("containerUserArgs() = %v, want %v", got, want)
	}
}

// A start that fails hands back an error rather than a terminator with no
// process behind it, so the caller never runs a scan it cannot cancel.
func TestStartSupervisedReportsStartFailure(t *testing.T) {
	terminate, err := startSupervised(exec.Command("scrutineer-never-started"))
	if err == nil {
		terminate()
		t.Fatal("startSupervised() error = nil, want the exec failure")
	}
	if terminate != nil {
		t.Error("startSupervised() returned a terminator alongside its error")
	}
}
