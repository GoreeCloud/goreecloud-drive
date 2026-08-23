// Package httpapi exposes the versioned GoreeCloud Drive HTTP boundary.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/authn"
	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/spaceaccess"
)

const developmentVersion = "0.0.0-dev"

// Dependencies are security-sensitive runtime boundaries injected into the HTTP
// service. The default constructor intentionally supplies no trusted identity or
// membership source.
type Dependencies struct {
	Principals  authn.Resolver
	Memberships spaceaccess.MembershipResolver
}

// Server wraps the standard library HTTP server so startup and shutdown stay
// explicit and testable.
type Server struct {
	http *http.Server
}

// New constructs the development API with fail-closed authorization defaults.
func New(cfg config.Config, logger *slog.Logger) *Server {
	return NewWithDependencies(cfg, logger, Dependencies{Principals: authn.DenyAllResolver{}})
}

// NewWithDependencies constructs the development API with explicit trusted
// authentication and membership boundaries.
func NewWithDependencies(cfg config.Config, logger *slog.Logger, deps Dependencies) *Server {
	if deps.Principals == nil {
		deps.Principals = authn.DenyAllResolver{}
	}
	access := spaceaccess.New(deps.Memberships)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/v1/status", statusHandler)
	mux.HandleFunc("GET /api/v1/spaces/{spaceID}/capabilities/{action}", capabilityHandler(deps.Principals, access))
	mux.Handle("/", http.FileServer(http.Dir(cfg.WebDir)))

	handler := requestLogging(logger, securityHeaders(requestID(mux)))
	return &Server{http: &http.Server{
		Addr:              cfg.Bind,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}}
}

// ListenAndServe starts the HTTP listener.
func (s *Server) ListenAndServe() error              { return s.http.ListenAndServe() }

// Shutdown gracefully stops the HTTP listener.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func statusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   "GoreeCloud Drive",
		"version":   developmentVersion,
		"lifecycle": "Development",
		"capabilities": map[string]bool{
			"authentication":     false,
			"authorization_core": true,
			"resumable_uploads":  false,
			"private_spaces":     false,
			"shared_spaces":      false,
		},
	})
}

func capabilityHandler(principals authn.Resolver, access spaceaccess.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := principals.Resolve(r.Context(), r)
		if err != nil || principal.AccountID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		spaceID := r.PathValue("spaceID")
		action := authz.Action(r.PathValue("action"))
		if !access.Allows(r.Context(), principal.AccountID, spaceID, action) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"space_id": spaceID,
			"action":   action,
			"allowed":  true,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := make([]byte, 12)
		if _, err := rand.Read(id); err == nil {
			w.Header().Set("X-Request-ID", hex.EncodeToString(id))
		}
		next.ServeHTTP(w, r)
	})
}

func requestLogging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("http request", "method", r.Method, "route", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}
