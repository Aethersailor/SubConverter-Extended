//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func atomicSwapDirectories(left, right string) error {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return err
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return err
	}
	if !leftInfo.IsDir() || !rightInfo.IsDir() {
		return errors.New("atomic exchange requires two directories")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, left, unix.AT_FDCWD, right, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("renameat2(RENAME_EXCHANGE) is unavailable on this filesystem: %w", err)
	}
	if err := syncDirectory(filepath.Dir(left)); err != nil {
		return err
	}
	if filepath.Dir(left) != filepath.Dir(right) {
		return syncDirectory(filepath.Dir(right))
	}
	return nil
}

func processAlive(pid int) bool {
	if pid < 1 {
		return false
	}
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func terminateProcess(process *os.Process) error {
	if process == nil {
		return errors.New("runtime process is unavailable")
	}
	return process.Signal(syscall.SIGTERM)
}

func syncDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	directory := path
	if !info.IsDir() {
		directory = filepath.Dir(path)
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Sync(); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	return nil
}
