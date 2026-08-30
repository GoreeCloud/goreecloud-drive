// Command server starts the GoreeCloud Drive development HTTP service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/httpapi"
	"github.com/GoreeCloud/goreecloud-drive/internal/quarantine"
	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
	"github.com/GoreeCloud/goreecloud-drive/internal/uploads"
	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration rejected", "error", err)
		os.Exit(1)
	}

	store, err := storage.NewLocal(cfg.DataDir)
	if err != nil {
		logger.Error("storage initialization failed", "error", err)
		os.Exit(1)
	}
	if err := store.EnsureLayout(); err != nil {
		logger.Error("storage layout initialization failed", "error", err)
		os.Exit(1)
	}

	deps := httpapi.Dependencies{
		Quarantine:           quarantine.New(store),
		WardveilServiceToken: cfg.WardveilServiceToken,
	}
	server := httpapi.NewWithDependencies(cfg, logger, deps)

	if cfg.UploadsEnabled {
		secret, err := loadWardveilScanSecret(cfg.WardveilScanSecretFile)
		if err != nil {
			logger.Error("Wardveil Scan credential rejected", "error", err)
			os.Exit(1)
		}
		scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
			Endpoint: cfg.WardveilScanEndpoint,
			CallerID: cfg.WardveilScanCallerID,
			KeyID:    cfg.WardveilScanKeyID,
			Secret:   secret,
		})
		if err != nil {
			logger.Error("Wardveil Scan client initialization failed", "error", err)
			os.Exit(1)
		}
		gate := wardveil.StagedFileGate{Store: store, Scanner: scanner}
		uploadService := uploads.New(
			uploads.NewMemoryRepository(),
			store,
			gate,
			cfg.UploadMaxChunkBytes,
			cfg.UploadSessionTTL,
		)
		server = httpapi.NewWithUploads(cfg, logger, deps, uploadService)
		logger.Info("resumable uploads enabled with Wardveil Scan gate", "session_repository", "memory", "lifecycle", "Development")
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "bind", cfg.Bind, "lifecycle", "Development", "uploads_enabled", cfg.UploadsEnabled)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func loadWardveilScanSecret(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat Wardveil Scan secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("Wardveil Scan secret file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("Wardveil Scan secret file must not be readable or writable by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Wardveil Scan secret file: %w", err)
	}
	if len(raw) > 4096 {
		return "", fmt.Errorf("Wardveil Scan secret file exceeds 4096 bytes")
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", fmt.Errorf("Wardveil Scan secret file is empty")
	}
	if strings.ContainsAny(secret, "\r\n") {
		return "", fmt.Errorf("Wardveil Scan secret file must contain one credential value")
	}
	return secret, nil
}
