package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage:") {
		t.Fatalf("usage: code=%d, stderr=%s", code, errOut.String())
	}
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.bin")
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte("abc")))
	m := fmt.Sprintf(`{"schema":"lovelyres-file-evidence/v1","sample_file":"sample.bin","observation":{"bytes":3,"sha256":"%s"}}`, wantHash)
	for name, data := range map[string]string{"sample.bin": "abc", "manifest.json": m} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"verify", dir}
	errOut.Reset()
	if code := run(args, &out, &errOut); code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), wantHash) {
		t.Fatalf("verify: code=%d, stdout=%s, stderr=%s", code, out.String(), errOut.String())
	}
	if err := os.WriteFile(sample, []byte("abd"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run(args, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Fatalf("tampered sample: code=%d, stdout=%s", code, out.String())
	}
}
