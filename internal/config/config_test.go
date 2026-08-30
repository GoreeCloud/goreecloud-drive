package config

import "testing"

func clearUploadEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GC_DRIVE_UPLOADS_ENABLED",
		"GC_DRIVE_UPLOAD_MAX_CHUNK_BYTES",
		"GC_DRIVE_UPLOAD_SESSION_TTL",
		"GC_DRIVE_WARDVEIL_SCAN_ENDPOINT",
		"GC_DRIVE_WARDVEIL_SCAN_CALLER_ID",
		"GC_DRIVE_WARDVEIL_SCAN_KEY_ID",
		"GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE",
	} {
		t.Setenv(key, "")
	}
}

func TestDefaultConfigurationIsLoopbackOnly(t *testing.T) {
	t.Setenv("GC_DRIVE_BIND", "")
	t.Setenv("GC_DRIVE_DATA_DIR", "")
	t.Setenv("GC_DRIVE_WEB_DIR", "")
	t.Setenv("GC_DRIVE_ALLOW_PUBLIC_BIND", "")
	t.Setenv("GC_DRIVE_SHUTDOWN_TIMEOUT", "")
	clearUploadEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Bind != "127.0.0.1:8080" {
		t.Fatalf("Bind = %q, want loopback default", cfg.Bind)
	}
	if cfg.UploadsEnabled {
		t.Fatal("uploads unexpectedly enabled by default")
	}
	if cfg.WardveilScanEndpoint != "http://127.0.0.1:8791/v1/scan" {
		t.Fatalf("WardveilScanEndpoint = %q", cfg.WardveilScanEndpoint)
	}
}

func TestPublicBindFailsClosedByDefault(t *testing.T) {
	t.Setenv("GC_DRIVE_BIND", "0.0.0.0:8080")
	t.Setenv("GC_DRIVE_ALLOW_PUBLIC_BIND", "false")
	clearUploadEnv(t)

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted public bind without explicit opt-in")
	}
}

func TestUploadsRequireWardveilSecretFile(t *testing.T) {
	t.Setenv("GC_DRIVE_UPLOADS_ENABLED", "true")
	t.Setenv("GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted enabled uploads without Wardveil Scan secret file")
	}
}

func TestUploadSecurityConfiguration(t *testing.T) {
	t.Setenv("GC_DRIVE_UPLOADS_ENABLED", "true")
	t.Setenv("GC_DRIVE_UPLOAD_MAX_CHUNK_BYTES", "1048576")
	t.Setenv("GC_DRIVE_UPLOAD_SESSION_TTL", "2h")
	t.Setenv("GC_DRIVE_WARDVEIL_SCAN_ENDPOINT", "http://127.0.0.1:8791/v1/scan")
	t.Setenv("GC_DRIVE_WARDVEIL_SCAN_CALLER_ID", "goreecloud-drive")
	t.Setenv("GC_DRIVE_WARDVEIL_SCAN_KEY_ID", "scan-current")
	t.Setenv("GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE", "/run/secrets/goreecloud-drive-wardveil-scan")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.UploadsEnabled {
		t.Fatal("uploads not enabled")
	}
	if cfg.UploadMaxChunkBytes != 1048576 {
		t.Fatalf("UploadMaxChunkBytes = %d", cfg.UploadMaxChunkBytes)
	}
	if cfg.UploadSessionTTL.String() != "2h0m0s" {
		t.Fatalf("UploadSessionTTL = %s", cfg.UploadSessionTTL)
	}
	if cfg.WardveilScanSecretFile != "/run/secrets/goreecloud-drive-wardveil-scan" {
		t.Fatalf("WardveilScanSecretFile = %q", cfg.WardveilScanSecretFile)
	}
}
