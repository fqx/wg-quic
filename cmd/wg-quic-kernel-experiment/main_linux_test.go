package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestTestKeyFilesRejectOversizePublicPermissionsAndMalformedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh-test-key")
	data := base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestKey(path); err == nil {
		t.Fatal("world readable key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, 257), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestKey(path); err == nil {
		t.Fatal("oversized key accepted")
	}
	if _, err := decodeKey("short"); err == nil {
		t.Fatal("malformed key accepted")
	}
}
