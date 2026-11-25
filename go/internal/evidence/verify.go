// Package evidence checks offline LovelyHawk evidence bundles without opening
// a connection or modifying the collected files.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	Schema           = "lovelyres-file-evidence/v1"
	MaxSampleBytes   = 512 << 20
	maxManifestBytes = 1 << 20
)

var ErrMismatch = errors.New("sample does not match its manifest")

type manifest struct {
	Schema      string `json:"schema"`
	SampleFile  string `json:"sample_file"`
	Observation struct {
		Bytes  *int64 `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"observation"`
}

// Result describes a local byte-for-byte check, not authenticity or collection provenance.
type Result struct {
	SampleFile string `json:"sample_file"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

// Verify checks a completed bundle stored in a stable, local directory.
// It checks only the sample named by the v1 manifest and never interprets it.
func Verify(dir string) (Result, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Result{}, fmt.Errorf("open bundle: %w", err)
	}
	defer root.Close()

	m, err := readManifest(root)
	if err != nil {
		return Result{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != Schema {
		return Result{}, errors.New("unsupported evidence manifest schema")
	}
	switch m.SampleFile {
	case "sample.bin", "capture.pcap", "pod-file.bin":
	default:
		return Result{}, errors.New("unsupported evidence sample name")
	}
	if m.Observation.Bytes == nil || *m.Observation.Bytes < 0 || *m.Observation.Bytes > MaxSampleBytes {
		return Result{}, errors.New("missing or out-of-range sample size in manifest")
	}
	claimed, err := hex.DecodeString(m.Observation.SHA256)
	if err != nil || len(claimed) != sha256.Size {
		return Result{}, errors.New("invalid SHA-256 in manifest")
	}
	expected := *m.Observation.Bytes

	f, info, err := openRegular(root, m.SampleFile)
	if err != nil {
		return Result{}, fmt.Errorf("sample: %w", err)
	}
	defer f.Close()
	if info.Size() != expected {
		return Result{}, fmt.Errorf("%w: size", ErrMismatch)
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(f, expected+1))
	if err != nil {
		return Result{}, fmt.Errorf("read sample: %w", err)
	}
	after, err := f.Stat()
	if err != nil {
		return Result{}, fmt.Errorf("recheck sample: %w", err)
	}
	current, err := root.Lstat(m.SampleFile)
	if err != nil {
		return Result{}, fmt.Errorf("recheck sample path: %w", err)
	}
	observed := hex.EncodeToString(digest.Sum(nil))
	if n != expected || after.Size() != expected || !after.ModTime().Equal(info.ModTime()) ||
		!os.SameFile(info, current) || observed != hex.EncodeToString(claimed) {
		return Result{}, fmt.Errorf("%w: bytes changed or SHA-256 differs", ErrMismatch)
	}
	return Result{SampleFile: m.SampleFile, Bytes: n, SHA256: observed}, nil
}

func readManifest(root *os.Root) (manifest, error) {
	f, _, err := openRegular(root, "manifest.json")
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return manifest{}, err
	}
	if len(data) > maxManifestBytes {
		return manifest{}, errors.New("manifest exceeds 1 MiB")
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return manifest{}, fmt.Errorf("malformed JSON: %w", err)
	}
	return m, nil
}

func openRegular(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, errors.New("file changed while opening")
	}
	return f, after, nil
}
