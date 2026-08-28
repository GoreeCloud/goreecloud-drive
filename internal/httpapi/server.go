// Package httpapi exposes the versioned GoreeCloud Drive HTTP boundary.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/authn"
	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/nodes"
	"github.com/GoreeCloud/goreecloud-drive/internal/quarantine"
	"github.com/GoreeCloud/goreecloud-drive/internal/spaceaccess"
)

const developmentVersion = "0.0.0-dev"

// Dependencies are security-sensitive runtime boundaries injected into the HTTP
// service. The default constructor intentionally supplies no trusted identity,
// membership source, persistent node repository, or Wardveil mutation target.
type Dependencies struct {
	Principals           authn.Resolver
	Memberships          spaceaccess.MembershipResolver
	Nodes                nodes.Repository
	Quarantine           quarantine.Target
	WardveilServiceToken string
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
// authentication, membership, persistence, and internal Wardveil boundaries.
func NewWithDependencies(cfg config.Config, logger *slog.Logger, deps Dependencies) *Server {
	if deps.Principals == nil {
		deps.Principals = authn.DenyAllResolver{}
	}
	access := spaceaccess.New(deps.Memberships)
	nodeService := nodes.New(deps.Nodes, access)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/v1/status", statusHandler)
	mux.HandleFunc("GET /api/v1/spaces/{spaceID}/capabilities/{action}", capabilityHandler(deps.Principals, access))
	mux.HandleFunc("GET /api/v1/spaces/{spaceID}/nodes", listNodesHandler(deps.Principals, nodeService))
	mux.HandleFunc("POST /api/v1/spaces/{spaceID}/nodes", createNodeHandler(deps.Principals, nodeService))
	mux.HandleFunc("GET /api/v1/spaces/{spaceID}/nodes/{nodeID}", getNodeHandler(deps.Principals, nodeService))
	mux.HandleFunc("PATCH /api/v1/spaces/{spaceID}/nodes/{nodeID}", renameNodeHandler(deps.Principals, nodeService))
	mux.HandleFunc("DELETE /api/v1/spaces/{spaceID}/nodes/{nodeID}", trashNodeHandler(deps.Principals, nodeService))
	mux.HandleFunc("POST /internal/v1/wardveil/quarantine/apply", quarantineApplyHandler(deps.Quarantine, deps.WardveilServiceToken))
	mux.HandleFunc("POST /internal/v1/wardveil/quarantine/read", quarantineReadHandler(deps.Quarantine, deps.WardveilServiceToken))
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
func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

// Shutdown gracefully stops the HTTP listener.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func statusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   "GoreeCloud Drive",
		"version":   developmentVersion,
		"lifecycle": "Development",
		"capabilities": map[string]bool{
			"authentication":       false,
			"authorization_core":   true,
			"persistent_node_crud": true,
			"file_content_io":      false,
			"resumable_uploads":    false,
			"private_spaces":       false,
			"shared_spaces":        false,
		},
	})
}

func capabilityHandler(principals authn.Resolver, access spaceaccess.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
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

func listNodesHandler(principals authn.Resolver, service nodes.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		var parentID *string
		if value := strings.TrimSpace(r.URL.Query().Get("parent_id")); value != "" {
			parentID = &value
		}
		items, err := service.List(r.Context(), principal.AccountID, r.PathValue("spaceID"), parentID)
		if err != nil {
			writeNodeError(w, err)
			return
		}
		if items == nil {
			items = []nodes.Node{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"nodes": items})
	}
}

func createNodeHandler(principals authn.Resolver, service nodes.Service) http.HandlerFunc {
	type request struct {
		ParentID *string    `json:"parent_id"`
		Kind     nodes.Kind `json:"kind"`
		Name     string     `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		var body request
		if err := decodeJSON(w, r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		node, err := service.Create(r.Context(), principal.AccountID, r.PathValue("spaceID"), body.ParentID, body.Kind, body.Name)
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, node)
	}
}

func getNodeHandler(principals authn.Resolver, service nodes.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		node, err := service.Get(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("nodeID"))
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, node)
	}
}

func renameNodeHandler(principals authn.Resolver, service nodes.Service) http.HandlerFunc {
	type request struct {
		Name string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		var body request
		if err := decodeJSON(w, r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		node, err := service.Rename(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("nodeID"), body.Name)
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, node)
	}
}

func trashNodeHandler(principals authn.Resolver, service nodes.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		node, err := service.Trash(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("nodeID"))
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, node)
	}
}

func resolvePrincipal(w http.ResponseWriter, r *http.Request, principals authn.Resolver) (authn.Principal, bool) {
	principal, err := principals.Resolve(r.Context(), r)
	if err != nil || principal.AccountID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return authn.Principal{}, false
	}
	return principal, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func writeNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, nodes.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
	case errors.Is(err, nodes.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node input"})
	case errors.Is(err, nodes.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
	case errors.Is(err, nodes.ErrUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "node service unavailable"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "node operation failed"})
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
