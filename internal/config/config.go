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
	Bind              string
	DataDir           string
	WebDir            string
	AllowPublicBind   bool
	ShutdownTimeout   time.Duration
}

// Load reads environment configuration and rejects unsafe or malformed values.
func Load() (Config, error) {
	cfg := Config{
		Bind:            envOr("GC_DRIVE_BIND", "127.0.0.1:8080"),
		DataDir:         envOr("GC_DRIVE_DATA_DIR", "./data"),
		WebDir:          envOr("GC_DRIVE_WEB_DIR", "./web"),
		ShutdownTimeout: 10 * time.Second,
	}

	if raw := os.Getenv("GC_DRIVE_ALLOW_PUBLIC_BIND"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("GC_DRIVE_ALLOW_PUBLIC_BIND: %w", err)
		}
		cfg.AllowPublicBind = value
	}

	if raw := os.Getenv("GC_DRIVE_SHUTDOWN_TIMEOUT"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("GC_DRIVE_SHUTDOWN_TIMEOUT must be a positive duration")
		}
		cfg.ShutdownTimeout = value
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
