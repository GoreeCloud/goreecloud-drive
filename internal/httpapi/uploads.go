package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/GoreeCloud/goreecloud-drive/internal/authn"
	"github.com/GoreeCloud/goreecloud-drive/internal/authz"
	"github.com/GoreeCloud/goreecloud-drive/internal/config"
	"github.com/GoreeCloud/goreecloud-drive/internal/nodes"
	"github.com/GoreeCloud/goreecloud-drive/internal/spaceaccess"
	"github.com/GoreeCloud/goreecloud-drive/internal/uploads"
)

// UploadService is the HTTP-facing resumable-transfer boundary.
type UploadService interface {
	Create(ctx context.Context, accountID, spaceID, nodeID string) (uploads.Session, error)
	Get(ctx context.Context, accountID, spaceID, uploadID string) (uploads.Session, error)
	Append(ctx context.Context, accountID, spaceID, uploadID string, expectedOffset int64, body io.Reader) (uploads.Session, error)
	Complete(ctx context.Context, accountID, spaceID, uploadID string) (uploads.Session, error)
}

// NewWithUploads extends the core Drive API with resumable upload routes while
// retaining the same fail-closed authentication, authorization, and node checks.
func NewWithUploads(cfg config.Config, logger *slog.Logger, deps Dependencies, uploadService UploadService) *Server {
	server := NewWithDependencies(cfg, logger, deps)
	if uploadService == nil {
		return server
	}
	access := spaceaccess.New(deps.Memberships)
	nodeService := nodes.New(deps.Nodes, access)
	uploadMux := http.NewServeMux()
	uploadMux.HandleFunc("POST /api/v1/spaces/{spaceID}/uploads", createUploadHandler(deps.Principals, access, nodeService, uploadService))
	uploadMux.HandleFunc("GET /api/v1/spaces/{spaceID}/uploads/{uploadID}", getUploadHandler(deps.Principals, uploadService))
	uploadMux.HandleFunc("PATCH /api/v1/spaces/{spaceID}/uploads/{uploadID}", appendUploadHandler(deps.Principals, uploadService))
	uploadMux.HandleFunc("POST /api/v1/spaces/{spaceID}/uploads/{uploadID}/complete", completeUploadHandler(deps.Principals, uploadService))
	uploadMux.Handle("/", server.http.Handler)
	server.http.Handler = requestLogging(logger, securityHeaders(requestID(uploadMux)))
	return server
}

func createUploadHandler(principals authn.Resolver, access spaceaccess.Service, nodeService nodes.Service, service UploadService) http.HandlerFunc {
	type request struct {
		NodeID string `json:"node_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		spaceID := r.PathValue("spaceID")
		if !access.Allows(r.Context(), principal.AccountID, spaceID, authz.ActionCreateFile) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
			return
		}
		var body request
		if err := decodeJSON(w, r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		node, err := nodeService.Get(r.Context(), principal.AccountID, spaceID, body.NodeID)
		if err != nil {
			writeNodeError(w, err)
			return
		}
		if node.Kind != nodes.KindFile {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uploads require a file node"})
			return
		}
		session, err := service.Create(r.Context(), principal.AccountID, spaceID, node.ID)
		if err != nil {
			writeUploadError(w, err)
			return
		}
		w.Header().Set("Upload-Offset", "0")
		w.Header().Set("Location", "/api/v1/spaces/"+spaceID+"/uploads/"+session.ID)
		writeJSON(w, http.StatusCreated, session)
	}
}

func getUploadHandler(principals authn.Resolver, service UploadService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		session, err := service.Get(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("uploadID"))
		if err != nil {
			writeUploadError(w, err)
			return
		}
		w.Header().Set("Upload-Offset", strconv.FormatInt(session.Offset, 10))
		writeJSON(w, http.StatusOK, session)
	}
}

func appendUploadHandler(principals authn.Resolver, service UploadService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
		if err != nil || offset < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid Upload-Offset header required"})
			return
		}
		session, err := service.Append(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("uploadID"), offset, r.Body)
		if err != nil {
			if errors.Is(err, uploads.ErrOffsetMismatch) {
				w.Header().Set("Upload-Offset", strconv.FormatInt(session.Offset, 10))
			}
			writeUploadError(w, err)
			return
		}
		w.Header().Set("Upload-Offset", strconv.FormatInt(session.Offset, 10))
		w.WriteHeader(http.StatusNoContent)
	}
}

func completeUploadHandler(principals authn.Resolver, service UploadService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := resolvePrincipal(w, r, principals)
		if !ok {
			return
		}
		session, err := service.Complete(r.Context(), principal.AccountID, r.PathValue("spaceID"), r.PathValue("uploadID"))
		if err != nil {
			writeUploadError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, session)
	}
}

func writeUploadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, uploads.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload session not found"})
	case errors.Is(err, uploads.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
	case errors.Is(err, uploads.ErrOffsetMismatch):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "upload offset mismatch"})
	case errors.Is(err, uploads.ErrCompleted):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "upload session already completed"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upload operation failed"})
	}
}
