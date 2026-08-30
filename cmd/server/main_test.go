package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWardveilScanSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wardveil-scan.secret")
	secret := strings.Repeat("s", 64)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadWardveilScanSecret(path)
	if err != nil {
		t.Fatalf("loadWardveilScanSecret: %v", err)
	}
	if got != secret {
		t.Fatal("loaded Wardveil Scan secret did not match")
	}
}

func TestLoadWardveilScanSecretRejectsGroupAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wardveil-scan.secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("s", 64)), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := loadWardveilScanSecret(path); err == nil {
		t.Fatal("loadWardveilScanSecret accepted group-readable credential")
	}
}

func TestLoadWardveilScanSecretRejectsMultilineValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wardveil-scan.secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("s", 32)+"\n"+strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := loadWardveilScanSecret(path); err == nil {
		t.Fatal("loadWardveilScanSecret accepted multiline credential")
	}
}
