package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maxMutableFileSize int64 = 32 << 20
)

type runtimeIdentity struct {
	PID int `json:"pid"`
}

func (u *updater) apply() (int, error) {
	if _, err := os.Stat(u.pending); err == nil {
		return u.recover()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 1, err
	}
	if u.applicationRunning() && !canUpdateWhileRunning() {
		return 1, errors.New("stop the Windows portable runtime before applying an update")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	metadata, err := u.resolveRelease(ctx)
	if err != nil {
		return 1, err
	}
	checkState, err := u.stateForMetadata(metadata)
	if err != nil {
		return 1, err
	}
	if !checkState.Available {
		if err := u.emitState(checkState); err != nil {
			return 1, err
		}
		return 0, nil
	}

	current, err := u.currentBuildInfo(u.root)
	if err != nil {
		return 1, fmt.Errorf("read current portable identity: %w", err)
	}
	archivePath, downloadSource, err := u.downloadRelease(ctx, metadata)
	if err != nil {
		return 1, err
	}
	metadata.DownloadSource = downloadSource
	candidateRoot, err := u.extractCandidate(archivePath)
	if err != nil {
		return 1, err
	}
	defer func() {
		if _, pendingErr := os.Stat(u.pending); errors.Is(pendingErr, os.ErrNotExist) {
			_ = os.RemoveAll(filepath.Dir(candidateRoot))
		}
	}()

	candidate, err := u.currentBuildInfo(candidateRoot)
	if err != nil {
		return 1, fmt.Errorf("read candidate portable identity: %w", err)
	}
	if candidate.Version != metadata.Version || candidate.Revision != metadata.Revision || candidate.BuildDate != metadata.BuildDate {
		return 1, errors.New("candidate BUILD-INFO.json does not match the selected stable Release manifest")
	}
	if err := u.preserveMutableFiles(u.root, candidateRoot); err != nil {
		return 1, fmt.Errorf("preserve portable user data: %w", err)
	}
	if err := u.validateRuntime(candidateRoot, candidate.Version); err != nil {
		return 1, fmt.Errorf("candidate runtime validation failed before installation: %w", err)
	}

	pending := pendingTransaction{
		Schema:        stateSchema,
		Phase:         "prepared",
		Root:          u.root,
		CandidateRoot: candidateRoot,
		Old:           current,
		New:           candidate,
		StartedAt:     time.Now().Unix(),
	}
	if err := writeJSONAtomic(u.pending, pending, 0o600); err != nil {
		return 1, err
	}
	u.logf("installing %s over %s from %s", candidate.Version, current.Version, downloadSource)

	if err := atomicSwapDirectories(u.root, candidateRoot); err != nil {
		_ = os.Remove(u.pending)
		return 1, fmt.Errorf("atomically exchange portable roots: %w", err)
	}
	pending.Phase = "exchanged"
	if err := writeJSONAtomic(u.pending, pending, 0o600); err != nil {
		if rollbackErr := atomicSwapDirectories(u.root, candidateRoot); rollbackErr != nil {
			return 1, fmt.Errorf("persist exchanged transaction: %v; emergency rollback also failed: %w", err, rollbackErr)
		}
		return 1, err
	}
	if err := u.validateRuntime(u.root, candidate.Version); err != nil {
		rollbackErr := atomicSwapDirectories(u.root, candidateRoot)
		_ = os.Remove(u.pending)
		state := u.baseState()
		state.OK = false
		state.State = "rolled_back"
		state.Error = err.Error()
		state.Message = "Candidate validation failed; the previous portable root was restored."
		_ = u.writeState(state)
		if rollbackErr != nil {
			return 1, fmt.Errorf("post-install validation failed: %v; rollback failed: %w", err, rollbackErr)
		}
		return 1, fmt.Errorf("post-install validation failed and was rolled back: %w", err)
	}

	if err := u.finalizeAppliedRoot(candidateRoot); err != nil {
		return 1, err
	}
	_ = os.Remove(u.pending)
	_ = syncDirectory(u.stateDir)
	state := u.baseState()
	state.State = "installed"
	state.LatestVersion = candidate.Version
	state.MetadataSource = metadata.MetadataSource
	state.DownloadSource = downloadSource
	state.Message = fmt.Sprintf("Installed stable Release %s.", candidate.Version)
	state.RestartRequired = u.applicationRunning()
	if err := u.emitState(state); err != nil {
		return 1, err
	}
	u.logf("installed %s revision %s", candidate.Version, candidate.Revision)
	return updaterExitChanged, nil
}

func (u *updater) finalizeAppliedRoot(oldRoot string) error {
	rollbackRoot := u.rollbackRoot()
	rollbackParent := filepath.Dir(rollbackRoot)
	if err := os.MkdirAll(rollbackParent, 0o700); err != nil {
		return err
	}
	if err := os.RemoveAll(rollbackRoot); err != nil {
		return fmt.Errorf("remove previous rollback root: %w", err)
	}
	if err := os.Rename(oldRoot, rollbackRoot); err != nil {
		return fmt.Errorf("retain previous portable root for rollback: %w", err)
	}
	return syncDirectory(rollbackParent)
}

func (u *updater) rollback() (int, error) {
	if _, err := os.Stat(u.pending); err == nil {
		return u.recover()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 1, err
	}
	if u.applicationRunning() && !canUpdateWhileRunning() {
		return 1, errors.New("stop the Windows portable runtime before rolling back")
	}
	rollbackRoot := u.rollbackRoot()
	current, err := u.currentBuildInfo(u.root)
	if err != nil {
		return 1, err
	}
	rollbackInfo, err := u.currentBuildInfo(rollbackRoot)
	if err != nil {
		return 1, errors.New("no validated rollback root is available")
	}
	if err := u.preserveMutableFiles(u.root, rollbackRoot); err != nil {
		return 1, err
	}
	if err := u.validateRuntime(rollbackRoot, rollbackInfo.Version); err != nil {
		return 1, fmt.Errorf("rollback root validation failed before exchange: %w", err)
	}
	pending := pendingTransaction{
		Schema:        stateSchema,
		Phase:         "rollback-prepared",
		Root:          u.root,
		CandidateRoot: rollbackRoot,
		Old:           current,
		New:           rollbackInfo,
		StartedAt:     time.Now().Unix(),
	}
	if err := writeJSONAtomic(u.pending, pending, 0o600); err != nil {
		return 1, err
	}
	if err := atomicSwapDirectories(u.root, rollbackRoot); err != nil {
		_ = os.Remove(u.pending)
		return 1, err
	}
	pending.Phase = "rollback-exchanged"
	_ = writeJSONAtomic(u.pending, pending, 0o600)
	if err := u.validateRuntime(u.root, rollbackInfo.Version); err != nil {
		restoreErr := atomicSwapDirectories(u.root, rollbackRoot)
		_ = os.Remove(u.pending)
		if restoreErr != nil {
			return 1, fmt.Errorf("rollback validation failed: %v; restoring the newer root also failed: %w", err, restoreErr)
		}
		return 1, fmt.Errorf("rollback validation failed and the newer root was restored: %w", err)
	}
	_ = os.Remove(u.pending)
	state := u.baseState()
	state.State = "rolled_back"
	state.LatestVersion = current.Version
	state.Message = fmt.Sprintf("Rolled back to %s.", rollbackInfo.Version)
	state.RestartRequired = u.applicationRunning()
	if err := u.emitState(state); err != nil {
		return 1, err
	}
	u.logf("rolled back from %s to %s", current.Version, rollbackInfo.Version)
	return updaterExitChanged, nil
}

func (u *updater) recover() (int, error) {
	var pending pendingTransaction
	if err := readJSONFile(u.pending, maxStateFileSize, &pending); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 1, fmt.Errorf("read pending portable update: %w", err)
	}
	if pending.Schema != stateSchema || pending.Root != u.root || pending.CandidateRoot == "" {
		return 1, errors.New("pending portable update metadata is invalid")
	}
	if !pathWithin(u.stateDir, pending.CandidateRoot) {
		return 1, errors.New("pending candidate root is outside the persistent updater directory")
	}
	if err := repairInterruptedSwap(u.root, pending.CandidateRoot); err != nil {
		return 1, fmt.Errorf("repair interrupted portable root exchange: %w", err)
	}
	rootInfo, rootErr := u.currentBuildInfo(u.root)
	candidateInfo, candidateErr := u.currentBuildInfo(pending.CandidateRoot)

	rootIsNew := rootErr == nil && rootInfo.Revision == pending.New.Revision
	rootIsOld := rootErr == nil && rootInfo.Revision == pending.Old.Revision
	candidateIsNew := candidateErr == nil && candidateInfo.Revision == pending.New.Revision
	candidateIsOld := candidateErr == nil && candidateInfo.Revision == pending.Old.Revision

	if rootIsOld && candidateIsNew {
		if err := u.validateRuntime(pending.CandidateRoot, pending.New.Version); err != nil {
			return 1, fmt.Errorf("pending candidate no longer validates: %w", err)
		}
		if err := atomicSwapDirectories(u.root, pending.CandidateRoot); err != nil {
			return 1, err
		}
		rootIsNew = true
		candidateIsOld = true
	}
	if !rootIsNew || !candidateIsOld {
		return 1, errors.New("cannot safely reconcile the pending portable update roots")
	}
	if err := u.validateRuntime(u.root, pending.New.Version); err != nil {
		if rollbackErr := atomicSwapDirectories(u.root, pending.CandidateRoot); rollbackErr != nil {
			return 1, fmt.Errorf("recovered root validation failed: %v; rollback also failed: %w", err, rollbackErr)
		}
		_ = os.Remove(u.pending)
		return 1, fmt.Errorf("pending update validation failed and was rolled back: %w", err)
	}
	if strings.HasPrefix(pending.Phase, "rollback-") {
		// The exchanged rollback directory already contains the newer root and
		// remains a valid one-step forward rollback target.
	} else if err := u.finalizeAppliedRoot(pending.CandidateRoot); err != nil {
		return 1, err
	}
	_ = os.Remove(u.pending)
	state := u.baseState()
	state.State = "recovered"
	state.LatestVersion = pending.New.Version
	state.Message = fmt.Sprintf("Recovered and validated portable Release %s.", pending.New.Version)
	if err := u.emitState(state); err != nil {
		return 1, err
	}
	u.logf("recovered pending transaction to %s", pending.New.Version)
	return updaterExitChanged, nil
}

func (u *updater) extractCandidate(archivePath string) (string, error) {
	stagingRoot := filepath.Join(u.stateDir, "staging")
	if err := os.RemoveAll(stagingRoot); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return "", err
	}
	candidateRoot, err := extractPortableArchive(archivePath, stagingRoot)
	if err != nil {
		return "", err
	}
	if err := validateCandidateLayout(candidateRoot); err != nil {
		return "", err
	}
	if err := syncDirectory(stagingRoot); err != nil {
		return "", err
	}
	return candidateRoot, nil
}

func pathWithin(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, targetAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (u *updater) preserveMutableFiles(sourceRoot, destinationRoot string) error {
	paths := []string{
		filepath.Join("base", "pref.toml"),
		filepath.Join("base", "pref.yml"),
		filepath.Join("base", "pref.yaml"),
		filepath.Join("base", "pref.ini"),
		filepath.Join("base", "generate.ini"),
		filepath.Join("base", "gistconf.ini"),
		filepath.Join("base", "profiles"),
		filepath.Join("base", "cache"),
		filepath.Join("base", "stats"),
		"stats",
	}
	if configured := os.Getenv("PREF_PATH"); configured != "" {
		configuredPath := configured
		if !filepath.IsAbs(configuredPath) {
			configuredPath = filepath.Join(sourceRoot, configuredPath)
		}
		if pathWithin(sourceRoot, configuredPath) {
			relative, err := filepath.Rel(sourceRoot, configuredPath)
			if err == nil {
				paths = append(paths, relative)
			}
		}
	}
	seen := map[string]struct{}{}
	for _, relative := range paths {
		relative = filepath.Clean(relative)
		if _, exists := seen[relative]; exists {
			continue
		}
		seen[relative] = struct{}{}
		source := filepath.Join(sourceRoot, relative)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := copyMutablePath(source, filepath.Join(destinationRoot, relative)); err != nil {
			return fmt.Errorf("copy mutable path %s: %w", relative, err)
		}
	}
	return nil
}

func copyMutablePath(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(source)
		if err != nil {
			return err
		}
		if target == "" {
			return fmt.Errorf("refusing to preserve empty symlink %s", source)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := os.RemoveAll(destination); err != nil {
			return err
		}
		return os.Symlink(target, destination)
	}
	if info.IsDir() {
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyMutablePath(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() || info.Size() > maxMutableFileSize {
		return fmt.Errorf("unsupported mutable file %s", source)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".mutable-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	written, err := io.Copy(temporary, io.LimitReader(input, maxMutableFileSize+1))
	if err == nil && written != info.Size() {
		err = errors.New("mutable file size changed while copying")
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporaryPath, destination)
}

func (u *updater) applicationRunning() bool {
	content, err := os.ReadFile(filepath.Join(u.stateDir, "runtime.json"))
	if err != nil || len(content) > int(maxStateFileSize) {
		return false
	}
	var identity runtimeIdentity
	if json.Unmarshal(content, &identity) != nil || identity.PID < 1 {
		return false
	}
	return processAlive(identity.PID)
}

func (u *updater) validateRuntime(root, expectedVersion string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	runtimeState := filepath.Join(u.stateDir, fmt.Sprintf("validation-runtime-%d.json", os.Getpid()))
	_ = os.Remove(runtimeState)

	command, err := validationCommand(root)
	if err != nil {
		return err
	}
	command.Env = append(os.Environ(),
		"PREF_PATH="+filepath.Join(root, "base", "pref.toml"),
		"PORT="+strconv.Itoa(port),
		"SUBCONVERTER_LISTEN_ADDRESS=127.0.0.1",
		"SUBCONVERTER_LISTEN_PORT="+strconv.Itoa(port),
		"SUBCONVERTER_RUNTIME_STATE_FILE="+runtimeState,
		"SUBCONVERTER_UPDATE_VALIDATION=1",
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 3 * time.Second}
	ready := false
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case processErr := <-waited:
			return fmt.Errorf("portable runtime exited before readiness: %v; stdout=%s; stderr=%s", processErr, truncateOutput(stdout.String()), truncateOutput(stderr.String()))
		default:
		}
		response, requestErr := client.Get(baseURL + "/healthz")
		if requestErr == nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 32))
			response.Body.Close()
			if response.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "ok" {
				ready = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		_ = terminateProcess(command.Process)
		<-waited
		return fmt.Errorf("portable runtime did not become healthy; stdout=%s; stderr=%s", truncateOutput(stdout.String()), truncateOutput(stderr.String()))
	}

	versionRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/version", nil)
	versionRequest.Header.Set("Origin", "http://127.0.0.1")
	versionResponse, err := client.Do(versionRequest)
	if err != nil {
		_ = terminateProcess(command.Process)
		<-waited
		return err
	}
	versionBody, _ := io.ReadAll(io.LimitReader(versionResponse.Body, 512))
	versionResponse.Body.Close()
	expectedPrefix := "SubConverter-Extended " + expectedVersion
	if versionResponse.StatusCode != http.StatusOK || !strings.HasPrefix(strings.TrimSpace(string(versionBody)), expectedPrefix) || !strings.HasSuffix(strings.TrimSpace(string(versionBody)), " backend") {
		_ = terminateProcess(command.Process)
		<-waited
		return fmt.Errorf("portable runtime version mismatch: %q", strings.TrimSpace(string(versionBody)))
	}

	parameters := url.Values{}
	parameters.Set("target", "clash")
	parameters.Set("url", "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388#Smoke")
	parameters.Set("insert", "false")
	parameters.Set("emoji", "false")
	parameters.Set("list", "true")
	conversionResponse, err := client.Get(baseURL + "/sub?" + parameters.Encode())
	if err != nil {
		_ = terminateProcess(command.Process)
		<-waited
		return err
	}
	conversionBody, _ := io.ReadAll(io.LimitReader(conversionResponse.Body, 1<<20))
	conversionResponse.Body.Close()
	if conversionResponse.StatusCode != http.StatusOK || !bytes.Contains(conversionBody, []byte("name: Smoke")) || !bytes.Contains(conversionBody, []byte("server: example.com")) {
		_ = terminateProcess(command.Process)
		<-waited
		return errors.New("portable runtime conversion validation failed")
	}

	if err := terminateProcess(command.Process); err != nil {
		return err
	}
	select {
	case processErr := <-waited:
		if processErr != nil && requiresCleanRuntimeShutdown() {
			return fmt.Errorf("portable runtime did not stop cleanly: %w", processErr)
		}
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		<-waited
		return errors.New("portable runtime did not stop after SIGTERM")
	}
	if _, err := os.Stat(runtimeState); !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(runtimeState)
		if requiresCleanRuntimeShutdown() {
			return errors.New("portable runtime state was not removed after shutdown")
		}
	}
	return nil
}

func truncateOutput(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 1600 {
		return value[len(value)-1600:]
	}
	return value
}
