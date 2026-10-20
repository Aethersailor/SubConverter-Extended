//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func testBuild(version, revision string) buildInfo {
	return buildInfo{Version: version, Revision: strings.Repeat(revision, 40), BuildDate: "2026-10-20T00:00:00Z"}
}

func testWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func testIdentity(t *testing.T, root string, info buildInfo) {
	t.Helper()
	data, _ := json.Marshal(info)
	testWrite(t, filepath.Join(root, "BUILD-INFO.json"), data, 0o600)
}

func testUpdater(t *testing.T) *updater {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Portable with spaces")
	state := root + ".update"
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return &updater{root: root, stateDir: state, pending: filepath.Join(state, "pending.json"), statePath: filepath.Join(state, "status.json"), logPath: filepath.Join(state, "update.log"), config: defaultConfig(), arch: runtime.GOARCH, assetName: "SubConverter-Extended-%s-linux-" + runtime.GOARCH + ".tar.gz", maxArchive: 26_214_400}
}

// Run the errno filter in a child, so neither the test runner nor later tests
// inherit it. Only RENAME_EXCHANGE is rejected; ordinary renames still work.
func TestLinuxExchangeErrnos(t *testing.T) {
	for _, errno := range []unix.Errno{0, unix.EINVAL, unix.ENOSYS, unix.EOPNOTSUPP, unix.EACCES, unix.EXDEV, unix.EIO, unix.EPERM} {
		t.Run(strconv.Itoa(int(errno)), func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestLinuxExchangeChild$", "-test.v")
			command.Env = append(os.Environ(), "SCE_TEST_EXCHANGE_ERRNO="+strconv.Itoa(int(errno)))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
			if bytes.Contains(output, []byte("--- SKIP: TestLinuxExchangeChild")) {
				t.Skip(string(output))
			}
		})
	}
}

func TestLinuxExchangeChild(t *testing.T) {
	value := os.Getenv("SCE_TEST_EXCHANGE_ERRNO")
	if value == "" {
		t.Skip("subprocess helper")
	}
	number, _ := strconv.Atoi(value)
	if number != 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Skipf("seccomp fault injection is unavailable: %v", err)
		}
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_RENAMEAT2), Jf: 3},
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 48}, // args[4]: flags
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.RENAME_EXCHANGE, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(number)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if _, _, err := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program))); err != 0 {
			if err == unix.ENOSYS || err == unix.EPERM || err == unix.EACCES || err == unix.EINVAL {
				t.Skipf("seccomp fault injection is unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	u := testUpdater(t)
	right := filepath.Join(u.stateDir, "staging", "SubConverter-Extended")
	old, next := testBuild("v1.10.1", "1"), testBuild("v1.10.4", "4")
	testIdentity(t, u.root, old)
	testIdentity(t, right, next)
	err := atomicSwapDirectories(u.root, right)
	supportedFallback := number == int(unix.EINVAL) || number == int(unix.ENOSYS) || number == int(unix.EOPNOTSUPP)
	if number != 0 && !supportedFallback {
		if !errors.Is(err, unix.Errno(number)) || errors.Is(err, errSwapIncomplete) {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, _ := u.currentBuildInfo(u.root); got != old {
			t.Fatalf("current root changed on error: %+v", got)
		}
		if got, _ := u.currentBuildInfo(right); got != next {
			t.Fatalf("candidate changed on error: %+v", got)
		}
		if _, err := os.Stat(filepath.Join(u.stateDir, "recover.sh")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unrelated error entered the fallback")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := u.currentBuildInfo(u.root); got != next {
		t.Fatalf("candidate was not activated: %+v", got)
	}
	if got, _ := u.currentBuildInfo(right); got != old {
		t.Fatalf("old root was not retained: %+v", got)
	}
	if supportedFallback {
		for _, name := range []string{"recover.sh", "subconverter-update-recover"} {
			if info, err := os.Stat(filepath.Join(u.stateDir, name)); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("recovery entry %s: %v", name, err)
			}
		}
	}
	if err := atomicSwapDirectories(u.root, right); err != nil {
		t.Fatal(err)
	}
	if got, _ := u.currentBuildInfo(u.root); got != old {
		t.Fatal("reverse exchange did not restore original root")
	}
	// Verify the entire install/rollback flow under the same filter.
	testInstallAndRollback(t)
}

func TestLinuxInterruptedExchange(t *testing.T) {
	for _, stage := range []string{"first", "second", "reverse-first", "reverse-second", "all-present", "foreign", "symlink"} {
		t.Run(stage, func(t *testing.T) {
			u := testUpdater(t)
			candidate := filepath.Join(u.stateDir, "staging", "SubConverter-Extended")
			old, next := testBuild("v1.10.1", "1"), testBuild("v1.10.4", "4")
			leftInfo, rightInfo := old, next
			if strings.HasPrefix(stage, "reverse-") {
				leftInfo, rightInfo = next, old
			}
			testIdentity(t, u.root, leftInfo)
			testIdentity(t, candidate, rightInfo)
			pending := pendingTransaction{Schema: stateSchema, Root: u.root, CandidateRoot: candidate, Old: old, New: next, Phase: "prepared"}
			if err := writeJSONAtomic(u.pending, pending, 0o600); err != nil {
				t.Fatal(err)
			}
			backup := candidate + ".exchange-old"
			if err := os.Rename(u.root, backup); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(stage, "second") {
				if err := os.Rename(candidate, u.root); err != nil {
					t.Fatal(err)
				}
				leftInfo, rightInfo = rightInfo, leftInfo
			}
			if stage == "all-present" {
				testIdentity(t, u.root, old)
			}
			if stage == "foreign" {
				testIdentity(t, backup, testBuild("v9.9.9", "9"))
			}
			if stage == "symlink" {
				if err := os.Rename(backup, backup+"-target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup+"-target", backup); err != nil {
					t.Fatal(err)
				}
			}
			err := repairInterruptedSwap(u.root, candidate)
			if stage == "all-present" || stage == "foreign" || stage == "symlink" {
				if err == nil {
					t.Fatal("unsafe layout was accepted")
				}
				if _, err := os.Lstat(backup); err != nil {
					t.Fatal("rejected recovery removed evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for path, want := range map[string]buildInfo{u.root: leftInfo, candidate: rightInfo} {
				if got, err := u.currentBuildInfo(path); err != nil || got != want {
					t.Fatalf("%s: %+v, %v", path, got, err)
				}
			}
			if err := repairInterruptedSwap(u.root, candidate); err != nil {
				t.Fatalf("repair is not idempotent: %v", err)
			}
		})
	}
}

// The runtime fixture exercises updater validation and clean shutdown, without
// claiming to test the converter backend or any DSM-specific runtime behavior.
func TestLinuxRuntimeHelper(t *testing.T) {
	if os.Getenv("SCE_TEST_RUNTIME") != "1" {
		t.Skip("runtime fixture")
	}
	var info buildInfo
	if err := readJSONFile("BUILD-INFO.json", maxStateFileSize, &info); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("PORT"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			fmt.Fprint(w, "ok")
		case "/version":
			fmt.Fprintf(w, "SubConverter-Extended %s backend", info.Version)
		case "/sub":
			fmt.Fprint(w, "name: Smoke\nserver: example.com\n")
		}
	})}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	go func() { <-signals; server.Close() }()
	if err := server.Serve(listener); err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func testInstallAndRollback(t *testing.T) {
	t.Helper()
	u := testUpdater(t)
	old, next := testBuild("v1.10.1", "1"), testBuild("v1.10.4", "4")
	executable, _ := os.Executable()
	t.Setenv("SCE_TEST_BINARY", executable)
	launcher := []byte("#!/bin/sh\nexport SCE_TEST_RUNTIME=1\nexec \"$SCE_TEST_BINARY\" -test.run=^TestLinuxRuntimeHelper$\n")
	oldJSON, _ := json.Marshal(old)
	newJSON, _ := json.Marshal(next)
	files := map[string][]byte{"BUILD-INFO.json": oldJSON, "start.sh": launcher, "subconverter": []byte("fixture"), "subconverter-update": []byte("fixture"), "update.sh": []byte("#!/bin/sh\n"), "base/pref.example.toml": []byte("fixture")}
	for path, data := range files {
		testWrite(t, filepath.Join(u.root, path), data, 0o700)
	}
	testWrite(t, filepath.Join(u.root, "base", "pref.toml"), []byte("user configuration"), 0o600)
	testWrite(t, filepath.Join(u.root, "stats", "marker"), []byte("user statistics"), 0o600)
	files["BUILD-INFO.json"] = newJSON
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(gz)
	for name, data := range files {
		if err := archive.WriteHeader(&tar.Header{Name: "SubConverter-Extended/" + name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	assetName := fmt.Sprintf(u.assetName, next.Version)
	manifest, _ := json.Marshal(releaseManifest{Schema: 1, Version: next.Version, Tag: next.Version, Revision: next.Revision, BuildDate: next.BuildDate, Assets: []manifestAsset{{Name: assetName, Size: int64(buffer.Len()), SHA256: digestBytes(buffer.Bytes())}}})
	api, _ := json.Marshal(apiRelease{TagName: next.Version, HTMLURL: "https://github.com/" + repository + "/releases/tag/" + next.Version, PublishedAt: next.BuildDate, Assets: []apiAsset{
		{Name: assetName, BrowserDownloadURL: expectedAssetURL(next.Version, assetName), Size: int64(buffer.Len()), Digest: "sha256:" + digestBytes(buffer.Bytes())},
		{Name: "RELEASE-MANIFEST.json", BrowserDownloadURL: expectedAssetURL(next.Version, "RELEASE-MANIFEST.json"), Size: int64(len(manifest)), Digest: "sha256:" + digestBytes(manifest)},
	}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/releases/latest":
			w.Write(api)
		case strings.HasSuffix(r.URL.Path, "/RELEASE-MANIFEST.json"):
			w.Write(manifest)
		case strings.HasSuffix(r.URL.Path, "/"+assetName):
			w.Write(buffer.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	previous := testSourceURL
	testSourceURL = server.URL
	defer func() { testSourceURL = previous }()
	if code, err := u.apply(); code != updaterExitChanged || err != nil {
		t.Fatalf("apply: code=%d error=%v", code, err)
	}
	if got, err := u.currentBuildInfo(u.root); err != nil || got != next {
		t.Fatalf("installed identity: %+v, %v", got, err)
	}
	if code, err := u.rollback(); code != updaterExitChanged || err != nil {
		t.Fatalf("rollback: code=%d error=%v", code, err)
	}
	for path, want := range map[string]string{"base/pref.toml": "user configuration", "stats/marker": "user statistics"} {
		if got, err := os.ReadFile(filepath.Join(u.root, path)); err != nil || string(got) != want {
			t.Fatalf("preserved %s: %q, %v", path, got, err)
		}
	}
	if got, err := u.currentBuildInfo(u.root); err != nil || got != old {
		t.Fatalf("rollback identity: %+v, %v", got, err)
	}
}
