package evidence

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func receipt(name, size, hash string) []byte {
	return []byte(fmt.Sprintf(`{"schema":%q,"sample_file":%q,"source":{"host":"example.invalid"},"observation":{"bytes":%s,"sha256":%q}}`, Schema, name, size, hash))
}

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sample []byte
	}{
		{"sample.bin", []byte{'a', 0, 255, '\r', '\n'}},
		{"capture.pcap", []byte{0xd4, 0xc3, 0xb2, 0xa1}},
		{"pod-file.bin", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hash := fmt.Sprintf("%x", sha256.Sum256(tc.sample))
			write(t, dir, tc.name, tc.sample)
			write(t, dir, "manifest.json", receipt(tc.name, fmt.Sprint(len(tc.sample)), strings.ToUpper(hash)))
			got, err := Verify(dir)
			if err != nil || got != (Result{tc.name, int64(len(tc.sample)), hash}) {
				t.Fatalf("Verify = %+v, %v", got, err)
			}
			again, err := os.ReadFile(filepath.Join(dir, tc.name))
			if err != nil || !bytes.Equal(again, tc.sample) {
				t.Fatal("verification changed sample")
			}
		})
	}
}

func TestMismatch(t *testing.T) {
	for _, sample := range []string{"abd", "ab", "abcd"} {
		t.Run(sample, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "sample.bin", []byte(sample))
			write(t, dir, "manifest.json", receipt("sample.bin", "3", fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))))
			if _, err := Verify(dir); !errors.Is(err, ErrMismatch) {
				t.Fatalf("expected integrity mismatch, got %v", err)
			}
		})
	}
}

func TestRejectIncompleteInvalidAndUnsafeBundles(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, reason string
		data         []byte
	}{
		{"no manifest", "manifest", nil},
		{"partial", "malformed JSON", []byte(`{"schema":`)},
		{"oversize manifest", "exceeds", bytes.Repeat([]byte(" "), maxManifestBytes+1)},
		{"wrong schema", "schema", []byte(`{"schema":"other"}`)},
		{"traversal", "sample name", receipt("../sample.bin", "0", hash)},
		{"backslash", "sample name", receipt(`..\sample.bin`, "0", hash)},
		{"missing size", "sample size", receipt("sample.bin", "null", hash)},
		{"oversize sample", "sample size", receipt("sample.bin", fmt.Sprint(MaxSampleBytes+1), hash)},
		{"bad hash", "SHA-256", receipt("sample.bin", "0", "xyz")},
		{"no sample", "sample:", receipt("sample.bin", "0", hash)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.data != nil {
				write(t, dir, "manifest.json", tc.data)
			}
			if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("expected %q, got %v", tc.reason, err)
			}
		})
	}
}

func TestRejectSymlink(t *testing.T) {
	for _, name := range []string{"manifest.json", "sample.bin"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			hash := fmt.Sprintf("%x", sha256.Sum256(nil))
			m := receipt("sample.bin", "0", hash)
			data := []byte(nil)
			if name == "manifest.json" {
				data = m
				write(t, dir, "sample.bin", nil)
			} else {
				write(t, dir, "manifest.json", m)
			}
			write(t, dir, "other", data)
			if err := os.Symlink("other", filepath.Join(dir, name)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("expected a regular-file rejection, got %v", err)
			}
		})
	}
}
