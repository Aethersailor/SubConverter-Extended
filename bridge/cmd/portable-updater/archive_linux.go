//go:build linux

package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxExtractedArchiveBytes int64 = 512 << 20
	maxExtractedFileCount          = 8192
)

func extractPortableArchive(archivePath, stagingRoot string) (string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer gzipReader.Close()
	targetRoot := filepath.Join(stagingRoot, "SubConverter-Extended")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(targetRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	tarReader := tar.NewReader(gzipReader)
	fileCount := 0
	var totalBytes int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		fileCount++
		if fileCount > maxExtractedFileCount {
			return "", errors.New("portable archive contains too many entries")
		}
		name := strings.TrimPrefix(header.Name, "./")
		if strings.Contains(name, "\\") || (name != "SubConverter-Extended" && !strings.HasPrefix(name, "SubConverter-Extended/")) {
			return "", fmt.Errorf("portable archive entry is outside the expected root: %q", header.Name)
		}
		relative := strings.TrimPrefix(strings.TrimPrefix(name, "SubConverter-Extended"), "/")
		relative = strings.TrimSuffix(relative, "/")
		localName := "."
		if relative != "" {
			if !fs.ValidPath(relative) || !filepath.IsLocal(relative) {
				return "", fmt.Errorf("unsafe portable archive path: %q", header.Name)
			}
			localName, err = filepath.Localize(relative)
			if err != nil || !filepath.IsLocal(localName) {
				return "", fmt.Errorf("unsafe portable archive path: %q", header.Name)
			}
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(localName, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || totalBytes+header.Size > maxExtractedArchiveBytes {
				return "", errors.New("portable archive exceeds the extracted-size limit")
			}
			totalBytes += header.Size
			if err := root.MkdirAll(filepath.Dir(localName), 0o755); err != nil {
				return "", err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			output, err := root.OpenFile(localName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return "", err
			}
			written, copyErr := io.CopyN(output, tarReader, header.Size)
			if copyErr == nil {
				copyErr = output.Sync()
			}
			closeErr := output.Close()
			if copyErr != nil {
				return "", copyErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			if written != header.Size {
				return "", errors.New("portable archive entry was truncated")
			}
		case tar.TypeSymlink, tar.TypeLink:
			return "", fmt.Errorf("portable archive links are not supported: %q", header.Name)
		default:
			return "", fmt.Errorf("unsupported portable archive entry type %d for %q", header.Typeflag, header.Name)
		}
	}
	return targetRoot, nil
}

func validateCandidateLayout(root string) error {
	for _, required := range []string{"subconverter", "subconverter-update", "start.sh", "update.sh", "BUILD-INFO.json", "base/pref.example.toml"} {
		info, err := os.Lstat(filepath.Join(root, required))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("portable candidate is missing regular file %s", required)
		}
	}
	for _, executable := range []string{"subconverter", "subconverter-update", "start.sh", "update.sh"} {
		info, _ := os.Stat(filepath.Join(root, executable))
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("portable candidate executable bit is missing: %s", executable)
		}
	}
	return nil
}
