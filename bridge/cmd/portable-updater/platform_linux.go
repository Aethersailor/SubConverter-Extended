//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func validationCommand(root string) (*exec.Cmd, error) {
	command := exec.Command(filepath.Join(root, "start.sh"))
	command.Dir = root
	return command, nil
}

func requiresCleanRuntimeShutdown() bool {
	return true
}

func canUpdateWhileRunning() bool {
	return true
}

func resolvePortableRoot(executable string) (string, error) {
	return filepath.Abs(filepath.Dir(executable))
}

func portableTarget() (portableTargetInfo, error) {
	architecture := ""
	switch runtime.GOARCH {
	case "amd64":
		architecture = "amd64"
	case "arm64":
		architecture = "arm64"
	case "arm":
		architecture = "armv7"
	default:
		return portableTargetInfo{}, fmt.Errorf("unsupported portable Linux architecture: %s", runtime.GOARCH)
	}
	return portableTargetInfo{
		Platform:       "linux",
		Architecture:   architecture,
		AssetName:      "SubConverter-Extended-%s-linux-" + architecture + ".tar.gz",
		MaxArchiveSize: 26_214_400,
	}, nil
}

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

func repairInterruptedSwap(_, _ string) error {
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
