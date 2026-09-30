package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func RuntimeDir(path string) (string, error) {
	if path == "" {
		path = filepath.Join("/tmp", "vibemaxxer-"+strconv.Itoa(os.Getuid()))
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			path = filepath.Join(dir, "vibemaxxer")
		}
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("-runtime-dir must be absolute")
	}
	path = filepath.Clean(path)
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Getuid())) || (st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0) {
			return "", fmt.Errorf("unsafe runtime ancestor %s", p)
		}
		if p == "/" {
			break
		}
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return "", fmt.Errorf("runtime directory %s must be owned by this user and mode 0700 (no symlinks)", path)
	}
	if len(filepath.Join(path, "0123456789012345678901234567890123456789.sock")) >= 108 {
		return "", errors.New("runtime directory path too long for Unix socket")
	}
	return path, nil
}

func privateFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("unsafe private file %s", path)
	}
	return f, nil
}

func lockUntil(f *os.File, deadline time.Time) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("managed bridge startup timed out waiting for lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
