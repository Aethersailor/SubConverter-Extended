//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
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
	if root := os.Getenv("SUBCONVERTER_PORTABLE_ROOT"); root != "" {
		return filepath.Abs(root)
	}
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
	leftInfo, err := os.Lstat(left)
	if err != nil {
		return err
	}
	rightInfo, err := os.Lstat(right)
	if err != nil {
		return err
	}
	if !leftInfo.IsDir() || !rightInfo.IsDir() {
		return errors.New("atomic exchange requires two directories")
	}
	if pathWithin(left, right) || pathWithin(right, left) {
		return errors.New("portable exchange directories must not overlap")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, left, unix.AT_FDCWD, right, unix.RENAME_EXCHANGE); err != nil {
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("exchange portable roots: %w", err)
		}
		return swapDirectoriesByRename(left, right)
	}
	if err := syncExchangeParents(left, right); err != nil {
		return fmt.Errorf("%w: %w", errSwapIncomplete, err)
	}
	return nil
}

func syncExchangeParents(left, right string) error {
	if err := syncDirectory(filepath.Dir(left)); err != nil {
		return err
	}
	if filepath.Dir(left) != filepath.Dir(right) {
		return syncDirectory(filepath.Dir(right))
	}
	return nil
}

func swapDirectoriesByRename(left, right string) error {
	exchangeOld := right + ".exchange-old"
	if _, err := os.Lstat(exchangeOld); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("exchange backup must not already exist: %s: %v", exchangeOld, err)
	}
	// This executable and script remain reachable even while left is absent.
	if err := prepareLinuxRecovery(left); err != nil {
		return fmt.Errorf("prepare portable recovery worker: %w", err)
	}
	if err := os.Rename(left, exchangeOld); err != nil {
		return fmt.Errorf("move current portable root aside: %w", err)
	}
	if err := syncExchangeParents(left, exchangeOld); err != nil {
		return fmt.Errorf("%w: %w", errSwapIncomplete, err)
	}
	if err := os.Rename(right, left); err != nil {
		if restoreErr := os.Rename(exchangeOld, left); restoreErr != nil {
			return fmt.Errorf("%w: activate candidate: %v; restore current root: %w", errSwapIncomplete, err, restoreErr)
		}
		if syncErr := syncExchangeParents(left, exchangeOld); syncErr != nil {
			return fmt.Errorf("%w: activate candidate: %v; sync restored root: %w", errSwapIncomplete, err, syncErr)
		}
		return fmt.Errorf("activate portable candidate: %w", err)
	}
	if err := syncExchangeParents(left, right); err != nil {
		return fmt.Errorf("%w: %w", errSwapIncomplete, err)
	}
	if err := os.Rename(exchangeOld, right); err != nil {
		return fmt.Errorf("%w: retain previous portable root: %w", errSwapIncomplete, err)
	}
	if err := syncExchangeParents(left, right); err != nil {
		return fmt.Errorf("%w: %w", errSwapIncomplete, err)
	}
	return nil
}

func prepareLinuxRecovery(root string) error {
	stateDir := root + ".update"
	info, err := os.Lstat(stateDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("persistent updater path must be a real directory: %s: %v", stateDir, err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	input, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer input.Close()
	worker, err := os.CreateTemp(stateDir, ".recovery-worker-*")
	if err != nil {
		return err
	}
	defer os.Remove(worker.Name())
	_, copyErr := io.Copy(worker, input)
	if copyErr == nil {
		copyErr = worker.Chmod(0o700)
	}
	if copyErr == nil {
		copyErr = worker.Sync()
	}
	closeErr := worker.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(worker.Name(), filepath.Join(stateDir, "subconverter-update-recover")); err != nil {
		return err
	}
	// Derive root from the sibling state directory, so moving both stays supported.
	script := []byte("#!/bin/sh\nset -e\nSTATE=$(CDPATH='' cd -- \"$(dirname \"$0\")\" && pwd)\nSUBCONVERTER_PORTABLE_ROOT=${STATE%.update}\nexport SUBCONVERTER_PORTABLE_ROOT\ncd -- \"$STATE\"\nexec ./subconverter-update-recover recover\n")
	launcher, err := os.CreateTemp(stateDir, ".recovery-launcher-*")
	if err != nil {
		return err
	}
	defer os.Remove(launcher.Name())
	_, writeErr := launcher.Write(script)
	if writeErr == nil {
		writeErr = launcher.Chmod(0o700)
	}
	if writeErr == nil {
		writeErr = launcher.Sync()
	}
	closeErr = launcher.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(launcher.Name(), filepath.Join(stateDir, "recover.sh")); err != nil {
		return err
	}
	return syncDirectory(stateDir)
}

func repairInterruptedSwap(root, candidate string) error {
	exchangeOld := candidate + ".exchange-old"
	if _, err := os.Lstat(exchangeOld); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var pending pendingTransaction
	if err := readJSONFile(filepath.Join(root+".update", "pending.json"), maxStateFileSize, &pending); err != nil {
		return err
	}
	if pending.Schema != stateSchema || pending.Root != root || pending.CandidateRoot != candidate {
		return errors.New("interrupted exchange does not match the pending transaction")
	}
	identity := func(path string) (buildInfo, bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return buildInfo{}, false, nil
		}
		if err != nil || !info.IsDir() {
			return buildInfo{}, false, fmt.Errorf("exchange path must be a real directory: %s: %v", path, err)
		}
		var build buildInfo
		if err := readJSONFile(filepath.Join(path, "BUILD-INFO.json"), maxStateFileSize, &build); err != nil {
			return buildInfo{}, false, err
		}
		if err := validateBuildInfo(build); err != nil {
			return buildInfo{}, false, err
		}
		if build != pending.Old && build != pending.New {
			return buildInfo{}, false, fmt.Errorf("unrecognized interrupted exchange identity: %s", path)
		}
		return build, true, nil
	}
	oldBuild, _, err := identity(exchangeOld)
	if err != nil {
		return err
	}
	rootBuild, rootExists, err := identity(root)
	if err != nil {
		return err
	}
	candidateBuild, candidateExists, err := identity(candidate)
	if err != nil {
		return err
	}
	switch {
	case !rootExists && candidateExists && oldBuild != candidateBuild:
		// Restore the pre-exchange layout; recover then validates before retrying.
		if err := os.Rename(exchangeOld, root); err != nil {
			return err
		}
	case rootExists && !candidateExists && oldBuild != rootBuild:
		if err := os.Rename(exchangeOld, candidate); err != nil {
			return err
		}
	default:
		return fmt.Errorf("ambiguous interrupted Linux exchange: root=%t candidate=%t", rootExists, candidateExists)
	}
	return syncExchangeParents(root, candidate)
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
