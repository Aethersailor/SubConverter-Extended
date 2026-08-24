//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// These build-time-only hooks are empty in every production artifact. Local
// fault injection binaries use them to prove post-swap rollback and recovery.
var testWindowsSwapDelayMillis string
var testWindowsFailInstalled string

const windowsStillActive = 259

func resolvePortableRoot(executable string) (string, error) {
	root := os.Getenv("SUBCONVERTER_PORTABLE_ROOT")
	if root == "" {
		root = filepath.Dir(executable)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return root, nil
}

func portableTarget() (portableTargetInfo, error) {
	if runtime.GOARCH != "amd64" {
		return portableTargetInfo{}, fmt.Errorf("unsupported portable Windows architecture: %s", runtime.GOARCH)
	}
	return portableTargetInfo{
		Platform:       "windows",
		Architecture:   "amd64",
		AssetName:      "SubConverter-Extended-%s-windows-amd64.zip",
		MaxArchiveSize: 18_874_368,
	}, nil
}

func validationCommand(root string) (*exec.Cmd, error) {
	if testWindowsFailInstalled == "1" && !strings.Contains(strings.ToLower(root), ".update\\staging\\") {
		command := exec.Command("cmd.exe", "/d", "/c", "exit", "88")
		command.Dir = filepath.Dir(root)
		return command, nil
	}
	pref := ""
	for _, name := range []string{"pref.toml", "pref.yml", "pref.ini"} {
		candidate := filepath.Join(root, "base", name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			pref = candidate
			break
		}
	}
	if pref == "" {
		example := filepath.Join(root, "base", "pref.example.toml")
		content, err := os.ReadFile(example)
		if err != nil {
			return nil, fmt.Errorf("read Windows validation configuration example: %w", err)
		}
		pref = filepath.Join(root, "base", "pref.toml")
		if err := os.WriteFile(pref, content, 0o600); err != nil {
			return nil, fmt.Errorf("create Windows validation configuration: %w", err)
		}
	}
	command := exec.Command(filepath.Join(root, "subconverter.exe"), "-f", pref)
	command.Dir = root
	return command, nil
}

func requiresCleanRuntimeShutdown() bool {
	return false
}

func canUpdateWhileRunning() bool {
	return false
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
		return errors.New("portable root exchange requires two directories")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if pathWithin(left, executable) {
		return errors.New("Windows updates must run through update.ps1 or update.bat so the worker executable is outside the portable root")
	}
	exchangeOld := right + ".exchange-old"
	if _, err := os.Stat(exchangeOld); err == nil {
		return fmt.Errorf("interrupted exchange path already exists: %s", exchangeOld)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(left, exchangeOld); err != nil {
		return fmt.Errorf("move current Windows portable root aside: %w", err)
	}
	if milliseconds, err := strconv.Atoi(testWindowsSwapDelayMillis); err == nil && milliseconds > 0 {
		time.Sleep(time.Duration(milliseconds) * time.Millisecond)
	}
	if err := os.Rename(right, left); err != nil {
		restoreErr := os.Rename(exchangeOld, left)
		if restoreErr != nil {
			return fmt.Errorf("activate Windows candidate: %v; restoring the current root also failed: %w", err, restoreErr)
		}
		return fmt.Errorf("activate Windows candidate: %w", err)
	}
	if err := os.Rename(exchangeOld, right); err != nil {
		return fmt.Errorf("retain previous Windows root after activation: %w", err)
	}
	return nil
}

func repairInterruptedSwap(root, candidate string) error {
	exchangeOld := candidate + ".exchange-old"
	rootExists := pathExists(root)
	candidateExists := pathExists(candidate)
	oldExists := pathExists(exchangeOld)

	switch {
	case !oldExists:
		return nil
	case !rootExists && candidateExists:
		if err := os.Rename(candidate, root); err != nil {
			return err
		}
		return os.Rename(exchangeOld, candidate)
	case rootExists && !candidateExists:
		return os.Rename(exchangeOld, candidate)
	default:
		return fmt.Errorf("ambiguous interrupted Windows exchange: root=%t candidate=%t old=%t", rootExists, candidateExists, oldExists)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func processAlive(pid int) bool {
	if pid < 1 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(handle)
	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return true
	}
	return exitCode == windowsStillActive
}

func terminateProcess(process *os.Process) error {
	if process == nil {
		return errors.New("runtime process is unavailable")
	}
	return process.Kill()
}

func syncDirectory(string) error {
	return nil
}
