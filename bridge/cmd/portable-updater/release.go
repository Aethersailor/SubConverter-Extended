package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxAPIResponseSize     int64 = 4 << 20
	maxReleaseManifestSize int64 = 1 << 20
	userAgent                    = "SubConverter-Extended-Portable-Updater/1"
)

var (
	versionPattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shaPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type apiAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
}

type apiRelease struct {
	TagName     string     `json:"tag_name"`
	HTMLURL     string     `json:"html_url"`
	Draft       bool       `json:"draft"`
	Prerelease  bool       `json:"prerelease"`
	PublishedAt string     `json:"published_at"`
	Assets      []apiAsset `json:"assets"`
}

type manifestAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type releaseManifest struct {
	Schema    int             `json:"schema"`
	Version   string          `json:"version"`
	Tag       string          `json:"tag"`
	Revision  string          `json:"revision"`
	BuildDate string          `json:"build_date"`
	Assets    []manifestAsset `json:"assets"`
}

type releaseMetadata struct {
	Version        string
	Revision       string
	BuildDate      string
	AssetName      string
	AssetURL       string
	AssetSize      int64
	AssetSHA256    string
	MetadataSource string
	DownloadSource string
}

func validVersion(value string) bool {
	return versionPattern.MatchString(value)
}

func validRevision(value string) bool {
	return revisionPattern.MatchString(value)
}

func validSHA256(value string) bool {
	return shaPattern.MatchString(value)
}

func validProxyMode(value string) bool {
	switch value {
	case "auto", "gh-proxy", "yylx", "direct":
		return true
	default:
		return false
	}
}

func compareVersions(left, right string) (int, error) {
	if !validVersion(left) || !validVersion(right) {
		return 0, fmt.Errorf("compare invalid versions %q and %q", left, right)
	}
	parse := func(value string) ([3]uint64, error) {
		var result [3]uint64
		parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
		for index, part := range parts {
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return result, err
			}
			result[index] = number
		}
		return result, nil
	}
	a, err := parse(left)
	if err != nil {
		return 0, err
	}
	b, err := parse(right)
	if err != nil {
		return 0, err
	}
	for index := range a {
		if a[index] < b[index] {
			return -1, nil
		}
		if a[index] > b[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func (u *updater) apiSources() []string {
	if testSourceURL != "" {
		return []string{"test"}
	}
	switch u.config.ProxyMode {
	case "auto":
		return []string{"gh-proxy", "yylx", "direct"}
	case "gh-proxy", "yylx", "direct":
		return []string{u.config.ProxyMode}
	default:
		return nil
	}
}

func (u *updater) downloadSources() []string {
	if testSourceURL != "" {
		return []string{"test"}
	}
	switch u.config.ProxyMode {
	case "auto":
		return []string{"ghfast", "gh-proxy", "yylx", "direct"}
	case "gh-proxy", "yylx", "direct":
		return []string{u.config.ProxyMode}
	default:
		return nil
	}
}

func apiURL(source string) (string, error) {
	if source == "test" && testSourceURL != "" {
		return strings.TrimRight(testSourceURL, "/") + "/api/releases/latest", nil
	}
	direct := "https://api.github.com/repos/" + repository + "/releases/latest"
	switch source {
	case "gh-proxy":
		return "https://gh-proxy.com/" + direct, nil
	case "yylx":
		return "https://git.yylx.win/" + direct, nil
	case "direct":
		return direct, nil
	default:
		return "", fmt.Errorf("unsupported API source: %s", source)
	}
}

func proxiedDownloadURL(source, direct string) (string, error) {
	if source == "test" && testSourceURL != "" {
		parsed, err := url.Parse(direct)
		if err != nil {
			return "", err
		}
		marker := "/releases/download/"
		index := strings.Index(parsed.Path, marker)
		if index < 0 {
			return "", fmt.Errorf("test download URL has no Release path: %s", direct)
		}
		return strings.TrimRight(testSourceURL, "/") + "/download/" + strings.TrimPrefix(parsed.Path[index+len(marker):], "/"), nil
	}
	switch source {
	case "ghfast":
		return "https://ghfast.top/" + direct, nil
	case "gh-proxy":
		return "https://gh-proxy.com/" + direct, nil
	case "yylx":
		return "https://git.yylx.win/" + direct, nil
	case "direct":
		return direct, nil
	default:
		return "", fmt.Errorf("unsupported download source: %s", source)
	}
}

func latestManifestURL(source string) (string, error) {
	if source == "test" && testSourceURL != "" {
		return strings.TrimRight(testSourceURL, "/") + "/latest/RELEASE-MANIFEST.json", nil
	}
	direct := "https://github.com/" + repository + "/releases/latest/download/RELEASE-MANIFEST.json"
	return proxiedDownloadURL(source, direct)
}

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   5 * time.Minute,
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many HTTP redirects")
			}
			if testSourceURL == "" && request.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", request.URL.Redacted())
			}
			return nil
		},
	}
}

func request(ctx context.Context, target string) (*http.Response, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if testSourceURL == "" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-HTTPS updater URL: %s", parsed.Redacted())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", userAgent)
	response, err := newHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s", response.StatusCode, parsed.Redacted())
	}
	return response, nil
}

func fetchBytes(ctx context.Context, target string, maximum int64) ([]byte, error) {
	response, err := request(ctx, target)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > maximum {
		return nil, fmt.Errorf("response exceeds size limit: %d > %d", response.ContentLength, maximum)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("response exceeds size limit: %d > %d", len(content), maximum)
	}
	return content, nil
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func parseAPIDigest(value string) (string, error) {
	value = strings.TrimPrefix(value, "sha256:")
	if !validSHA256(value) {
		return "", fmt.Errorf("invalid GitHub asset digest: %q", value)
	}
	return value, nil
}

func expectedAssetURL(tag, name string) string {
	return "https://github.com/" + repository + "/releases/download/" + tag + "/" + name
}

func findAPIAsset(assets []apiAsset, name string) (apiAsset, error) {
	var found []apiAsset
	for _, asset := range assets {
		if asset.Name == name {
			found = append(found, asset)
		}
	}
	if len(found) != 1 {
		return apiAsset{}, fmt.Errorf("expected exactly one Release asset %s, found %d", name, len(found))
	}
	return found[0], nil
}

func parseManifest(content []byte) (releaseManifest, error) {
	var manifest releaseManifest
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != 1 {
		return manifest, fmt.Errorf("unsupported Release manifest schema: %d", manifest.Schema)
	}
	if !validVersion(manifest.Version) || manifest.Tag != manifest.Version {
		return manifest, errors.New("Release manifest version and tag are not the same stable version")
	}
	if !validRevision(manifest.Revision) {
		return manifest, errors.New("Release manifest revision is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.BuildDate); err != nil || !strings.HasSuffix(manifest.BuildDate, "Z") {
		return manifest, errors.New("Release manifest build date is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		if asset.Name == "" || !validSHA256(asset.SHA256) || asset.Size < 1 {
			return manifest, fmt.Errorf("invalid Release manifest asset: %q", asset.Name)
		}
		if _, exists := seen[asset.Name]; exists {
			return manifest, fmt.Errorf("duplicate Release manifest asset: %s", asset.Name)
		}
		seen[asset.Name] = struct{}{}
	}
	return manifest, nil
}

func findManifestAsset(manifest releaseManifest, name string) (manifestAsset, error) {
	for _, asset := range manifest.Assets {
		if asset.Name == name {
			return asset, nil
		}
	}
	return manifestAsset{}, fmt.Errorf("Release manifest does not contain %s", name)
}

func (u *updater) metadataFromAPI(ctx context.Context, source string) (releaseMetadata, bool, error) {
	endpoint, err := apiURL(source)
	if err != nil {
		return releaseMetadata{}, false, err
	}
	content, err := fetchBytes(ctx, endpoint, maxAPIResponseSize)
	if err != nil {
		return releaseMetadata{}, false, err
	}
	var release apiRelease
	if err := json.Unmarshal(content, &release); err != nil {
		return releaseMetadata{}, false, fmt.Errorf("parse GitHub Release response: %w", err)
	}
	if release.Draft || release.Prerelease || !validVersion(release.TagName) {
		return releaseMetadata{}, false, errors.New("GitHub latest Release is not a stable vX.Y.Z Release")
	}
	expectedHTML := "https://github.com/" + repository + "/releases/tag/" + release.TagName
	if release.HTMLURL != expectedHTML {
		return releaseMetadata{}, false, fmt.Errorf("GitHub Release repository identity mismatch: %s", release.HTMLURL)
	}
	if _, err := time.Parse(time.RFC3339, release.PublishedAt); err != nil {
		return releaseMetadata{}, false, errors.New("GitHub Release published_at is invalid")
	}

	assetName := fmt.Sprintf(u.assetName, release.TagName)
	targetAsset, err := findAPIAsset(release.Assets, assetName)
	if err != nil {
		return releaseMetadata{}, true, err
	}
	manifestAPIAsset, err := findAPIAsset(release.Assets, "RELEASE-MANIFEST.json")
	if err != nil {
		return releaseMetadata{}, true, err
	}
	for _, asset := range []apiAsset{targetAsset, manifestAPIAsset} {
		if asset.BrowserDownloadURL != expectedAssetURL(release.TagName, asset.Name) {
			return releaseMetadata{}, true, fmt.Errorf("Release asset URL identity mismatch for %s", asset.Name)
		}
		if asset.Size < 1 {
			return releaseMetadata{}, true, fmt.Errorf("Release asset size is invalid for %s", asset.Name)
		}
		if _, err := parseAPIDigest(asset.Digest); err != nil {
			return releaseMetadata{}, true, err
		}
	}
	if targetAsset.Size > u.maxArchive || manifestAPIAsset.Size > maxReleaseManifestSize {
		return releaseMetadata{}, true, errors.New("Release asset exceeds the portable updater size budget")
	}
	manifestDigest, _ := parseAPIDigest(manifestAPIAsset.Digest)

	var manifest releaseManifest
	manifestSource := ""
	var downloadErrors []string
	for _, downloadSource := range u.downloadSources() {
		manifestURL, urlErr := proxiedDownloadURL(downloadSource, manifestAPIAsset.BrowserDownloadURL)
		if urlErr != nil {
			downloadErrors = append(downloadErrors, urlErr.Error())
			continue
		}
		manifestContent, fetchErr := fetchBytes(ctx, manifestURL, maxReleaseManifestSize)
		if fetchErr != nil {
			downloadErrors = append(downloadErrors, fmt.Sprintf("%s: %v", downloadSource, fetchErr))
			continue
		}
		if int64(len(manifestContent)) != manifestAPIAsset.Size || digestBytes(manifestContent) != manifestDigest {
			downloadErrors = append(downloadErrors, fmt.Sprintf("%s: Release manifest digest or size mismatch", downloadSource))
			continue
		}
		manifest, err = parseManifest(manifestContent)
		if err != nil {
			downloadErrors = append(downloadErrors, fmt.Sprintf("%s: %v", downloadSource, err))
			continue
		}
		manifestSource = downloadSource
		break
	}
	if manifestSource == "" {
		return releaseMetadata{}, true, fmt.Errorf("validated GitHub metadata but could not verify RELEASE-MANIFEST.json: %s", strings.Join(downloadErrors, "; "))
	}
	if manifest.Version != release.TagName {
		return releaseMetadata{}, true, errors.New("GitHub Release tag and Release manifest version differ")
	}
	manifestTarget, err := findManifestAsset(manifest, assetName)
	if err != nil {
		return releaseMetadata{}, true, err
	}
	targetDigest, _ := parseAPIDigest(targetAsset.Digest)
	if manifestTarget.Size != targetAsset.Size || manifestTarget.SHA256 != targetDigest {
		return releaseMetadata{}, true, errors.New("GitHub API and Release manifest disagree on the portable archive")
	}
	return releaseMetadata{
		Version:        manifest.Version,
		Revision:       manifest.Revision,
		BuildDate:      manifest.BuildDate,
		AssetName:      assetName,
		AssetURL:       targetAsset.BrowserDownloadURL,
		AssetSize:      manifestTarget.Size,
		AssetSHA256:    manifestTarget.SHA256,
		MetadataSource: source,
		DownloadSource: manifestSource,
	}, true, nil
}

func (u *updater) metadataFromLatestManifest(ctx context.Context) (releaseMetadata, error) {
	var failures []string
	for _, source := range u.downloadSources() {
		manifestURL, err := latestManifestURL(source)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		content, err := fetchBytes(ctx, manifestURL, maxReleaseManifestSize)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		manifest, err := parseManifest(content)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		assetName := fmt.Sprintf(u.assetName, manifest.Version)
		asset, err := findManifestAsset(manifest, assetName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		if asset.Size > u.maxArchive {
			return releaseMetadata{}, errors.New("portable archive exceeds the updater size budget")
		}
		return releaseMetadata{
			Version:        manifest.Version,
			Revision:       manifest.Revision,
			BuildDate:      manifest.BuildDate,
			AssetName:      assetName,
			AssetURL:       expectedAssetURL(manifest.Version, assetName),
			AssetSize:      asset.Size,
			AssetSHA256:    asset.SHA256,
			MetadataSource: source + "-release-manifest",
			DownloadSource: source,
		}, nil
	}
	return releaseMetadata{}, fmt.Errorf("all latest Release manifest sources failed: %s", strings.Join(failures, "; "))
}

func (u *updater) resolveRelease(ctx context.Context) (releaseMetadata, error) {
	var failures []string
	validatedAPI := false
	for _, source := range u.apiSources() {
		metadata, strong, err := u.metadataFromAPI(ctx, source)
		validatedAPI = validatedAPI || strong
		if err == nil {
			return metadata, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", source, err))
	}
	if validatedAPI {
		return releaseMetadata{}, fmt.Errorf("validated GitHub Release metadata could not be completed safely: %s", strings.Join(failures, "; "))
	}
	metadata, err := u.metadataFromLatestManifest(ctx)
	if err != nil {
		failures = append(failures, err.Error())
		return releaseMetadata{}, fmt.Errorf("Release metadata lookup failed: %s", strings.Join(failures, "; "))
	}
	return metadata, nil
}

func (u *updater) stateForMetadata(metadata releaseMetadata) (updateState, error) {
	current, err := u.currentBuildInfo(u.root)
	if err != nil {
		return updateState{}, fmt.Errorf("read installed BUILD-INFO.json: %w", err)
	}
	comparison, err := compareVersions(current.Version, metadata.Version)
	if err != nil {
		return updateState{}, err
	}
	state := u.baseState()
	state.LatestVersion = metadata.Version
	state.MetadataSource = metadata.MetadataSource
	state.DownloadSource = metadata.DownloadSource
	switch comparison {
	case -1:
		state.State = "available"
		state.Available = true
		state.Message = fmt.Sprintf("Stable Release %s is available.", metadata.Version)
	case 0:
		state.State = "up_to_date"
		state.Message = "The portable installation is up to date."
	case 1:
		state.State = "newer_local"
		state.Message = "The portable installation is newer than the latest stable Release."
	}
	return state, nil
}

func (u *updater) checkAndEmit(silent bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	metadata, err := u.resolveRelease(ctx)
	if err != nil {
		state := u.baseState()
		state.OK = false
		state.State = "error"
		state.Error = err.Error()
		state.Message = "Unable to check the latest stable Release."
		_ = u.writeState(state)
		return err
	}
	state, err := u.stateForMetadata(metadata)
	if err != nil {
		return err
	}
	if err := u.writeState(state); err != nil {
		return err
	}
	if !silent {
		encoded, _ := json.Marshal(state)
		fmt.Println(string(encoded))
	}
	return nil
}

func (u *updater) downloadRelease(ctx context.Context, metadata releaseMetadata) (string, string, error) {
	downloadDir := filepath.Join(u.stateDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0o700); err != nil {
		return "", "", err
	}
	finalPath := filepath.Join(downloadDir, metadata.AssetName)
	var failures []string
	for _, source := range u.downloadSources() {
		target, err := proxiedDownloadURL(source, metadata.AssetURL)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		temporary, err := os.CreateTemp(downloadDir, ".archive-*")
		if err != nil {
			return "", "", err
		}
		temporaryPath := temporary.Name()
		_ = temporary.Close()
		err = downloadExpectedFile(ctx, target, temporaryPath, metadata.AssetSize, metadata.AssetSHA256, u.maxArchive)
		if err != nil {
			_ = os.Remove(temporaryPath)
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		if err := os.Rename(temporaryPath, finalPath); err != nil {
			_ = os.Remove(temporaryPath)
			return "", "", err
		}
		if err := syncDirectory(downloadDir); err != nil {
			return "", "", err
		}
		return finalPath, source, nil
	}
	return "", "", fmt.Errorf("all portable archive sources failed: %s", strings.Join(failures, "; "))
}

func downloadExpectedFile(ctx context.Context, target, destination string, expectedSize int64, expectedSHA string, maximumSize int64) error {
	if expectedSize < 1 || expectedSize > maximumSize || !validSHA256(expectedSHA) {
		return errors.New("invalid expected archive identity")
	}
	response, err := request(ctx, target)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength > maximumSize || (response.ContentLength >= 0 && response.ContentLength != expectedSize) {
		return fmt.Errorf("archive Content-Length mismatch: %d != %d", response.ContentLength, expectedSize)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maximumSize+1))
	if copyErr != nil {
		file.Close()
		return copyErr
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("archive size mismatch: %d != %d", written, expectedSize)
	}
	actualSHA := hex.EncodeToString(hash.Sum(nil))
	if actualSHA != expectedSHA {
		return fmt.Errorf("archive SHA-256 mismatch: %s != %s", actualSHA, expectedSHA)
	}
	return nil
}

func (u *updater) auto() (int, error) {
	if !u.config.Enabled || !u.config.AutoCheck {
		return 0, nil
	}
	state := u.baseState()
	if _, err := os.Stat(u.statePath); err == nil {
		state = u.readState()
		if state.OK && state.State != "error" && state.UpdatedAt > 0 &&
			time.Since(time.Unix(state.UpdatedAt, 0)) < time.Duration(u.config.CheckIntervalSeconds)*time.Second {
			return 0, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := u.checkAndEmit(true); err != nil {
		return 0, nil
	}
	state = u.readState()
	if !state.Available || !u.config.AutoInstall {
		if state.Available {
			fmt.Fprintf(os.Stderr, "SubConverter-Extended %s is available; run ./update.sh apply or enable automatic installation.\n", state.LatestVersion)
		}
		return 0, nil
	}
	return u.apply()
}
