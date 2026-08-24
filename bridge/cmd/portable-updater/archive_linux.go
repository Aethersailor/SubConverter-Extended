//go:build linux

package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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
		relative := strings.TrimPrefix(name, "SubConverter-Extended")
		relative = strings.TrimPrefix(relative, "/")
		cleanRelative := filepath.Clean(filepath.FromSlash(relative))
		if relative == "" {
			cleanRelative = "."
		}
		if cleanRelative == ".." || strings.HasPrefix(cleanRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanRelative) {
			return "", fmt.Errorf("unsafe portable archive path: %q", header.Name)
		}
		target := filepath.Join(targetRoot, cleanRelative)
		if !pathWithin(targetRoot, target) {
			return "", fmt.Errorf("portable archive path escapes candidate root: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || totalBytes+header.Size > maxExtractedArchiveBytes {
				return "", errors.New("portable archive exceeds the extracted-size limit")
			}
			totalBytes += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
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
		case tar.TypeSymlink:
			if filepath.IsAbs(header.Linkname) || strings.Contains(header.Linkname, "\\") {
				return "", fmt.Errorf("unsafe absolute symlink in portable archive: %q", header.Name)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(cleanRelative), filepath.FromSlash(header.Linkname)))
			if resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("portable archive symlink escapes candidate root: %q", header.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			if err := os.Symlink(filepath.FromSlash(header.Linkname), target); err != nil {
				return "", err
			}
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
