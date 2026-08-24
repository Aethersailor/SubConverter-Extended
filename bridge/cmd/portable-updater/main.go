package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	repository                 = "Aethersailor/SubConverter-Extended"
	stateSchema                = 1
	defaultCheckInterval       = 24 * time.Hour
	updaterExitChanged         = 10
	maxStateFileSize     int64 = 1 << 20
)

// testSourceURL is deliberately build-time only. Production artifacts leave it
// empty, so users cannot redirect the updater away from this project's Release.
var testSourceURL string

type buildInfo struct {
	BuildDate string `json:"build_date"`
	Revision  string `json:"revision"`
	Version   string `json:"version"`
}

type updateConfig struct {
	Schema               int    `json:"schema"`
	Enabled              bool   `json:"enabled"`
	AutoCheck            bool   `json:"auto_check"`
	AutoInstall          bool   `json:"auto_install"`
	CheckIntervalSeconds int64  `json:"check_interval_seconds"`
	ProxyMode            string `json:"proxy_mode"`
}

type updateState struct {
	Schema            int    `json:"schema"`
	OK                bool   `json:"ok"`
	State             string `json:"state"`
	CurrentVersion    string `json:"current_version"`
	LatestVersion     string `json:"latest_version"`
	Architecture      string `json:"architecture"`
	Available         bool   `json:"available"`
	UpdatedAt         int64  `json:"updated_at"`
	MetadataSource    string `json:"metadata_source"`
	DownloadSource    string `json:"download_source"`
	Message           string `json:"message"`
	Error             string `json:"error"`
	RollbackAvailable bool   `json:"rollback_available"`
	RollbackVersion   string `json:"rollback_version"`
	RestartRequired   bool   `json:"restart_required"`
}

type pendingTransaction struct {
	Schema        int       `json:"schema"`
	Phase         string    `json:"phase"`
	Root          string    `json:"root"`
	CandidateRoot string    `json:"candidate_root"`
	Old           buildInfo `json:"old"`
	New           buildInfo `json:"new"`
	StartedAt     int64     `json:"started_at"`
}

type updater struct {
	root       string
	stateDir   string
	configPath string
	statePath  string
	pending    string
	lockPath   string
	logPath    string
	platform   string
	arch       string
	assetName  string
	maxArchive int64
	config     updateConfig
}

type portableTargetInfo struct {
	Platform       string
	Architecture   string
	AssetName      string
	MaxArchiveSize int64
}

func defaultConfig() updateConfig {
	return updateConfig{
		Schema:               stateSchema,
		Enabled:              true,
		AutoCheck:            false,
		AutoInstall:          false,
		CheckIntervalSeconds: int64(defaultCheckInterval.Seconds()),
		ProxyMode:            "auto",
	}
}

func newUpdater() (*updater, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve updater executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, fmt.Errorf("resolve updater executable symlinks: %w", err)
	}
	root, err := resolvePortableRoot(executable)
	if err != nil {
		return nil, fmt.Errorf("resolve portable root: %w", err)
	}
	if root == string(filepath.Separator) {
		return nil, errors.New("refusing to use the filesystem root as the portable root")
	}

	target, err := portableTarget()
	if err != nil {
		return nil, err
	}
	stateDir := root + ".update"
	u := &updater{
		root:       root,
		stateDir:   stateDir,
		configPath: filepath.Join(stateDir, "config.json"),
		statePath:  filepath.Join(stateDir, "status.json"),
		pending:    filepath.Join(stateDir, "pending.json"),
		lockPath:   filepath.Join(stateDir, "update.lock"),
		logPath:    filepath.Join(stateDir, "update.log"),
		platform:   target.Platform,
		arch:       target.Architecture,
		assetName:  target.AssetName,
		maxArchive: target.MaxArchiveSize,
	}
	if info, err := os.Lstat(stateDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("persistent updater path must be a real directory: %s", stateDir)
		}
		if err := os.Chmod(stateDir, 0o700); err != nil {
			return nil, fmt.Errorf("restrict persistent updater directory %s: %w", stateDir, err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			return nil, fmt.Errorf("create persistent updater directory %s: %w", stateDir, err)
		}
	} else {
		return nil, fmt.Errorf("inspect persistent updater directory %s: %w", stateDir, err)
	}
	if err := u.loadConfig(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *updater) loadConfig() error {
	config := defaultConfig()
	err := readJSONFile(u.configPath, maxStateFileSize, &config)
	if errors.Is(err, os.ErrNotExist) {
		u.config = config
		return u.saveConfig()
	}
	if err != nil {
		return fmt.Errorf("read updater configuration: %w", err)
	}
	if config.Schema != stateSchema {
		return fmt.Errorf("unsupported updater configuration schema: %d", config.Schema)
	}
	if config.CheckIntervalSeconds < 300 || config.CheckIntervalSeconds > 604800 {
		return errors.New("check_interval_seconds must be between 300 and 604800")
	}
	if !validProxyMode(config.ProxyMode) {
		return fmt.Errorf("unsupported proxy mode: %s", config.ProxyMode)
	}
	u.config = config
	return nil
}

func (u *updater) saveConfig() error {
	u.config.Schema = stateSchema
	return writeJSONAtomic(u.configPath, u.config, 0o600)
}

func (u *updater) currentBuildInfo(root string) (buildInfo, error) {
	var info buildInfo
	if err := readJSONFile(filepath.Join(root, "BUILD-INFO.json"), maxStateFileSize, &info); err != nil {
		return info, err
	}
	if err := validateBuildInfo(info); err != nil {
		return info, err
	}
	return info, nil
}

func validateBuildInfo(info buildInfo) error {
	if !validVersion(info.Version) {
		return fmt.Errorf("invalid build version: %q", info.Version)
	}
	if !validRevision(info.Revision) {
		return fmt.Errorf("invalid build revision: %q", info.Revision)
	}
	if _, err := time.Parse(time.RFC3339, info.BuildDate); err != nil || !strings.HasSuffix(info.BuildDate, "Z") {
		return fmt.Errorf("invalid canonical build date: %q", info.BuildDate)
	}
	return nil
}

func (u *updater) baseState() updateState {
	current := "unknown"
	if info, err := u.currentBuildInfo(u.root); err == nil {
		current = info.Version
	}
	rollbackVersion := ""
	rollbackAvailable := false
	if info, err := u.currentBuildInfo(u.rollbackRoot()); err == nil {
		rollbackVersion = info.Version
		rollbackAvailable = true
	}
	return updateState{
		Schema:            stateSchema,
		OK:                true,
		State:             "idle",
		CurrentVersion:    current,
		LatestVersion:     "unknown",
		Architecture:      u.arch,
		UpdatedAt:         time.Now().Unix(),
		Message:           "Updater is idle.",
		RollbackAvailable: rollbackAvailable,
		RollbackVersion:   rollbackVersion,
	}
}

func (u *updater) readState() updateState {
	state := u.baseState()
	if err := readJSONFile(u.statePath, maxStateFileSize, &state); err != nil || state.Schema != stateSchema {
		return u.baseState()
	}
	if current, err := u.currentBuildInfo(u.root); err == nil {
		state.CurrentVersion = current.Version
	}
	state.Architecture = u.arch
	state.RollbackAvailable = false
	state.RollbackVersion = ""
	if rollback, err := u.currentBuildInfo(u.rollbackRoot()); err == nil {
		state.RollbackAvailable = true
		state.RollbackVersion = rollback.Version
	}
	return state
}

func (u *updater) writeState(state updateState) error {
	state.Schema = stateSchema
	state.UpdatedAt = time.Now().Unix()
	if current, err := u.currentBuildInfo(u.root); err == nil {
		state.CurrentVersion = current.Version
	}
	state.Architecture = u.arch
	state.RollbackAvailable = false
	state.RollbackVersion = ""
	if rollback, err := u.currentBuildInfo(u.rollbackRoot()); err == nil {
		state.RollbackAvailable = true
		state.RollbackVersion = rollback.Version
	}
	return writeJSONAtomic(u.statePath, state, 0o600)
}

func (u *updater) emitState(state updateState) error {
	if err := u.writeState(state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func (u *updater) rollbackRoot() string {
	return filepath.Join(u.stateDir, "rollback", "SubConverter-Extended")
}

func (u *updater) logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	message = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, message)
	if len(message) > 800 {
		message = message[:800]
	}
	if info, err := os.Stat(u.logPath); err == nil && info.Size() > 256*1024 {
		_ = os.Rename(u.logPath, u.logPath+".1")
	}
	file, err := os.OpenFile(u.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%s %s\n", time.Now().UTC().Format(time.RFC3339), message)
}

func (u *updater) withLock(operation func() (int, error)) (int, error) {
	lock, err := os.OpenFile(u.lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return 1, fmt.Errorf("create updater lock: %w", err)
		}
		data, readErr := os.ReadFile(u.lockPath)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if readErr == nil && parseErr == nil && processAlive(pid) {
			return 1, fmt.Errorf("another updater process is active with pid %d", pid)
		}
		if removeErr := os.Remove(u.lockPath); removeErr != nil {
			return 1, fmt.Errorf("remove stale updater lock: %w", removeErr)
		}
		return u.withLock(operation)
	}
	if _, err := fmt.Fprintf(lock, "%d\n", os.Getpid()); err != nil {
		lock.Close()
		_ = os.Remove(u.lockPath)
		return 1, err
	}
	if err := lock.Sync(); err != nil {
		lock.Close()
		_ = os.Remove(u.lockPath)
		return 1, err
	}
	_ = lock.Close()
	defer os.Remove(u.lockPath)
	return operation()
}

func readJSONFile(path string, maximum int64, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 1 || info.Size() > maximum {
		return fmt.Errorf("unexpected JSON file size for %s: %d", path, info.Size())
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximum+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON document contains trailing content")
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".json-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: subconverter-update {status|check|apply|rollback|recover|auto|enable-auto|disable-auto|set-proxy <auto|gh-proxy|yylx|direct>}")
}

func main() {
	u, err := newUpdater()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	command := "status"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	exitCode := 0

	switch command {
	case "status":
		err = u.emitState(u.readState())
	case "check":
		exitCode, err = u.withLock(func() (int, error) { return 0, u.checkAndEmit(false) })
	case "apply":
		exitCode, err = u.withLock(u.apply)
	case "rollback":
		exitCode, err = u.withLock(u.rollback)
	case "recover":
		exitCode, err = u.withLock(u.recover)
	case "auto":
		exitCode, err = u.withLock(u.auto)
	case "enable-auto":
		u.config.Enabled = true
		u.config.AutoCheck = true
		u.config.AutoInstall = true
		err = u.saveConfig()
		if err == nil {
			_ = os.Remove(u.statePath)
		}
	case "disable-auto":
		u.config.AutoInstall = false
		err = u.saveConfig()
	case "set-proxy":
		if len(os.Args) != 3 || !validProxyMode(os.Args[2]) {
			usage()
			os.Exit(2)
		}
		u.config.ProxyMode = os.Args[2]
		err = u.saveConfig()
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		u.logf("%s failed: %v", command, err)
		fmt.Fprintln(os.Stderr, err)
		if exitCode == 0 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}
