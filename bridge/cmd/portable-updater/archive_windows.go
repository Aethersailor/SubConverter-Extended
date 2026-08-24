//go:build windows

package main

import (
	"archive/zip"
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
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	if len(archive.File) > maxExtractedFileCount {
		return "", errors.New("portable archive contains too many entries")
	}
	targetRoot := filepath.Join(stagingRoot, "SubConverter-Extended")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(targetRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	var totalBytes int64
	for _, entry := range archive.File {
		name := strings.TrimPrefix(entry.Name, "./")
		if strings.Contains(name, "\\") || (name != "SubConverter-Extended" && !strings.HasPrefix(name, "SubConverter-Extended/")) {
			return "", fmt.Errorf("portable archive entry is outside the expected root: %q", entry.Name)
		}
		relative := strings.TrimPrefix(strings.TrimPrefix(name, "SubConverter-Extended"), "/")
		relative = strings.TrimSuffix(relative, "/")
		localName := "."
		if relative != "" {
			if !fs.ValidPath(relative) || !filepath.IsLocal(relative) {
				return "", fmt.Errorf("unsafe portable archive path: %q", entry.Name)
			}
			localName, err = filepath.Localize(relative)
			if err != nil || !filepath.IsLocal(localName) {
				return "", fmt.Errorf("unsafe portable archive path: %q", entry.Name)
			}
		}
		info := entry.FileInfo()
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("Windows portable archive contains an unsupported symlink: %q", entry.Name)
		}
		if info.IsDir() {
			if err := root.MkdirAll(localName, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if !info.Mode().IsRegular() || entry.UncompressedSize64 > uint64(maxExtractedArchiveBytes) {
			return "", fmt.Errorf("unsupported Windows portable archive entry: %q", entry.Name)
		}
		totalBytes += int64(entry.UncompressedSize64)
		if totalBytes > maxExtractedArchiveBytes {
			return "", errors.New("portable archive exceeds the extracted-size limit")
		}
		if err := root.MkdirAll(filepath.Dir(localName), 0o755); err != nil {
			return "", err
		}
		input, err := entry.Open()
		if err != nil {
			return "", err
		}
		output, err := root.OpenFile(localName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			input.Close()
			return "", err
		}
		written, copyErr := io.CopyN(output, input, int64(entry.UncompressedSize64))
		closeInputErr := input.Close()
		closeOutputErr := output.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeInputErr != nil {
			return "", closeInputErr
		}
		if closeOutputErr != nil {
			return "", closeOutputErr
		}
		if written != int64(entry.UncompressedSize64) {
			return "", errors.New("portable archive entry was truncated")
		}
	}
	return targetRoot, nil
}

func validateCandidateLayout(root string) error {
	for _, required := range []string{
		"subconverter.exe",
		"subconverter-update.exe",
		"start.ps1",
		"start.bat",
		"update.ps1",
		"update.bat",
		"BUILD-INFO.json",
		filepath.Join("base", "pref.example.toml"),
	} {
		info, err := os.Lstat(filepath.Join(root, required))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("portable candidate is missing regular file %s", required)
		}
	}
	return nil
}
