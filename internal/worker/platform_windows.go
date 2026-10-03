//go:build windows

package worker

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startSupervised starts cmd inside a job object limited to kill-on-close and
// returns the func that closes it. Windows has no signalable process group, so
// a job is the only handle on a whole tree: closing it kills the descendants a
// dead CLI left behind, and the kernel closes it for us if scrutineer itself
// dies. A process joins the job its parent is already in as it is created, so
// the child is started suspended and only runs once it has been assigned;
// anything it spawned in between would stay outside the job and survive
// cancellation. CREATE_NEW_PROCESS_GROUP is the counterpart of Setpgid: it
// detaches the child from the console's Ctrl+C group, so the interrupt reaches
// scrutineer's shutdown path, which cancels the context and kills the child.
func startSupervised(cmd *exec.Cmd) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	closeJob := func() { _ = windows.CloseHandle(job) }

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		closeJob()
		return nil, fmt.Errorf("limit job object to kill-on-close: %w", err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED}
	if err := cmd.Start(); err != nil {
		closeJob()
		return nil, err
	}
	if err := adoptAndResume(job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		closeJob()
		return nil, err
	}
	return closeJob, nil
}

func startBackendProbe(cmd *exec.Cmd) (func(), error) {
	return startSupervised(cmd)
}

// adoptAndResume assigns the suspended process to job and lets it run. Go's
// exec keeps no handle on the initial thread, so a toolhelp snapshot is the
// only route to ResumeThread; a process created suspended has exactly one
// thread, and resuming it is what the CREATE_SUSPENDED start defers.
func adoptAndResume(job windows.Handle, pid int) error {
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		return fmt.Errorf("assign process %d to job: %w", pid, err)
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("snapshot threads: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err := windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != uint32(pid) {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return fmt.Errorf("open thread %d: %w", entry.ThreadID, err)
		}
		_, err = windows.ResumeThread(thread)
		_ = windows.CloseHandle(thread)
		if err != nil {
			return fmt.Errorf("resume thread %d: %w", entry.ThreadID, err)
		}
		return nil
	}
	return fmt.Errorf("no thread to resume for process %d", pid)
}

// containerUserArgs is empty on Windows: os.Getuid reports -1 there, so the
// container keeps the runner image's own non-root user.
func containerUserArgs() []string {
	return nil
}
