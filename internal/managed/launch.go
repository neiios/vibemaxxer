package managed

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func launch(c Config, base string, owner *os.File) error {
	logFile, err := privateFile(base + ".log")
	if err != nil {
		return err
	}
	defer logFile.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, logFile.Fd(), syscall.F_SETFL, syscall.O_APPEND); errno != 0 {
		return errno
	}
	snapshot, err := os.CreateTemp(filepath.Dir(base), ".snapshot-")
	if err != nil {
		return err
	}
	defer snapshot.Close()
	if err = os.Remove(snapshot.Name()); err != nil {
		return err
	}
	if err = json.NewEncoder(snapshot).Encode(c); err != nil {
		return err
	}
	if _, err = snapshot.Seek(0, 0); err != nil {
		return err
	}
	cmd := exec.Command("/proc/self/exe", "_managed", base)
	cmd.ExtraFiles = []*os.File{owner, snapshot}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
