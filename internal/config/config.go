// Package config owns runtime configuration parsing and safe defaults.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// Config contains the minimum runtime settings for the development service.
type Config struct {
	Bind                   string
	DataDir                string
	WebDir                 string
	AllowPublicBind        bool
	ShutdownTimeout        time.Duration
	WardveilServiceToken   string
	UploadsEnabled         bool
	UploadMaxChunkBytes    int64
	UploadSessionTTL       time.Duration
	WardveilScanEndpoint   string
	WardveilScanCallerID   string
	WardveilScanKeyID      string
	WardveilScanSecretFile string
}

// Load reads environment configuration and rejects unsafe or malformed values.
func Load() (Config, error) {
	cfg := Config{
		Bind:                   envOr("GC_DRIVE_BIND", "127.0.0.1:8080"),
		DataDir:                envOr("GC_DRIVE_DATA_DIR", "./data"),
		WebDir:                 envOr("GC_DRIVE_WEB_DIR", "./web"),
		ShutdownTimeout:        10 * time.Second,
		WardveilServiceToken:   os.Getenv("GC_DRIVE_WARDVEIL_SERVICE_TOKEN"),
		UploadMaxChunkBytes:    8 << 20,
		UploadSessionTTL:       24 * time.Hour,
		WardveilScanEndpoint:   envOr("GC_DRIVE_WARDVEIL_SCAN_ENDPOINT", "http://127.0.0.1:8791/v1/scan"),
		WardveilScanCallerID:   envOr("GC_DRIVE_WARDVEIL_SCAN_CALLER_ID", "goreecloud-drive"),
		WardveilScanKeyID:      envOr("GC_DRIVE_WARDVEIL_SCAN_KEY_ID", "scan-current"),
		WardveilScanSecretFile: os.Getenv("GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE"),
	}

	if raw := os.Getenv("GC_DRIVE_ALLOW_PUBLIC_BIND"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("GC_DRIVE_ALLOW_PUBLIC_BIND: %w", err)
		}
		cfg.AllowPublicBind = value
	}

	if raw := os.Getenv("GC_DRIVE_UPLOADS_ENABLED"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("GC_DRIVE_UPLOADS_ENABLED: %w", err)
		}
		cfg.UploadsEnabled = value
	}

	if raw := os.Getenv("GC_DRIVE_SHUTDOWN_TIMEOUT"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("GC_DRIVE_SHUTDOWN_TIMEOUT must be a positive duration")
		}
		cfg.ShutdownTimeout = value
	}

	if raw := os.Getenv("GC_DRIVE_UPLOAD_MAX_CHUNK_BYTES"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("GC_DRIVE_UPLOAD_MAX_CHUNK_BYTES must be a positive integer")
		}
		cfg.UploadMaxChunkBytes = value
	}

	if raw := os.Getenv("GC_DRIVE_UPLOAD_SESSION_TTL"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("GC_DRIVE_UPLOAD_SESSION_TTL must be a positive duration")
		}
		cfg.UploadSessionTTL = value
	}

	if cfg.DataDir == "" || cfg.WebDir == "" {
		return Config{}, fmt.Errorf("data and web directories must not be empty")
	}

	host, _, err := net.SplitHostPort(cfg.Bind)
	if err != nil {
		return Config{}, fmt.Errorf("GC_DRIVE_BIND: %w", err)
	}
	if !cfg.AllowPublicBind && !isLoopbackHost(host) {
		return Config{}, fmt.Errorf("refusing non-loopback bind %q unless GC_DRIVE_ALLOW_PUBLIC_BIND=true", host)
	}

	if cfg.UploadsEnabled && cfg.WardveilScanSecretFile == "" {
		return Config{}, fmt.Errorf("GC_DRIVE_WARDVEIL_SCAN_SECRET_FILE is required when uploads are enabled")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
