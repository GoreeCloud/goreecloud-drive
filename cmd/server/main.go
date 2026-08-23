// Command server starts the GoreeCloud Drive development HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/httpapi"
	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
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

	server := httpapi.New(cfg, logger)
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "bind", cfg.Bind, "lifecycle", "Development")
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
