package config

import "testing"

func TestDefaultConfigurationIsLoopbackOnly(t *testing.T) {
	t.Setenv("GC_DRIVE_BIND", "")
	t.Setenv("GC_DRIVE_DATA_DIR", "")
	t.Setenv("GC_DRIVE_WEB_DIR", "")
	t.Setenv("GC_DRIVE_ALLOW_PUBLIC_BIND", "")
	t.Setenv("GC_DRIVE_SHUTDOWN_TIMEOUT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Bind != "127.0.0.1:8080" {
		t.Fatalf("Bind = %q, want loopback default", cfg.Bind)
	}
}

func TestPublicBindFailsClosedByDefault(t *testing.T) {
	t.Setenv("GC_DRIVE_BIND", "0.0.0.0:8080")
	t.Setenv("GC_DRIVE_ALLOW_PUBLIC_BIND", "false")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted public bind without explicit opt-in")
	}
}
