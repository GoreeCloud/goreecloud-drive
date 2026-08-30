package uploads

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

var (
	ErrNotFound            = errors.New("upload session not found")
	ErrForbidden           = errors.New("upload session access denied")
	ErrOffsetMismatch      = errors.New("upload offset mismatch")
	ErrCompleted           = errors.New("upload session already completed")
	ErrInvalidTarget       = errors.New("upload target is invalid")
	ErrSecurityUnavailable = errors.New("upload security verification unavailable")
	ErrSecurityBlocked     = errors.New("upload blocked by security policy")
)

type State string

const (
	StateActive    State = "active"
	StateCompleted State = "completed"
)

type Session struct {
	ID           string    `json:"id"`
	SpaceID      string    `json:"space_id"`
	AccountID    string    `json:"account_id"`
	ParentNodeID string    `json:"parent_node_id,omitempty"`
	TargetName   string    `json:"target_name"`
	NodeID       string    `json:"node_id,omitempty"`
	Offset       int64     `json:"offset"`
	State        State     `json:"state"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Repository interface {
	Create(context.Context, Session) error
	Get(context.Context, string) (Session, error)
	Update(context.Context, Session) error
}

type StagingStore interface {
	AppendStaging(spaceID, uploadID string, expectedOffset int64, src io.Reader, maxChunkBytes int64) (int64, error)
	OpenStaging(spaceID, uploadID string) (io.ReadCloser, error)
	Finalize(spaceID, uploadID, nodeID string) error
}

type SecurityGate interface {
	EvaluateUpload(ctx context.Context, spaceID, uploadID, nodeID string) (wardveil.Decision, error)
}

type SecurityBlockedError struct {
	Decision wardveil.Decision
}

func (e *SecurityBlockedError) Error() string {
	if e == nil {
		return ErrSecurityBlocked.Error()
	}
	return fmt.Sprintf("%s: disposition=%s reasons=%s", ErrSecurityBlocked, e.Decision.Disposition, strings.Join(e.Decision.ReasonCodes, ","))
}

func (e *SecurityBlockedError) Unwrap() error { return ErrSecurityBlocked }

type Service struct {
	repo     Repository
	store    StagingStore
	security SecurityGate
	maxChunk int64
	ttl      time.Duration
	now      func() time.Time
}

func New(repo Repository, store StagingStore, security SecurityGate, maxChunk int64, ttl time.Duration) Service {
	return Service{repo: repo, store: store, security: security, maxChunk: maxChunk, ttl: ttl, now: time.Now}
}

func (s Service) Create(ctx context.Context, accountID, spaceID, parentNodeID, targetName string) (Session, error) {
	if s.repo == nil || s.store == nil || s.maxChunk <= 0 || s.ttl <= 0 {
		return Session{}, fmt.Errorf("upload service unavailable")
	}
	targetName = strings.TrimSpace(targetName)
	if targetName == "" || len(targetName) > 255 || targetName == "." || targetName == ".." || strings.ContainsAny(targetName, "/\\\x00") {
		return Session{}, ErrInvalidTarget
	}
	id, err := newUUID()
	if err != nil {
		return Session{}, err
	}
	now := s.now().UTC()
	session := Session{ID: id, AccountID: accountID, SpaceID: spaceID, ParentNodeID: parentNodeID, TargetName: targetName, State: StateActive, ExpiresAt: now.Add(s.ttl)}
	if err := s.repo.Create(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s Service) Get(ctx context.Context, accountID, spaceID, uploadID string) (Session, error) {
	session, err := s.repo.Get(ctx, uploadID)
	if err != nil {
		return Session{}, err
	}
	if session.AccountID != accountID || session.SpaceID != spaceID {
		return Session{}, ErrForbidden
	}
	return session, nil
}

func (s Service) Append(ctx context.Context, accountID, spaceID, uploadID string, expectedOffset int64, body io.Reader) (Session, error) {
	session, err := s.Get(ctx, accountID, spaceID, uploadID)
	if err != nil {
		return Session{}, err
	}
	if session.State != StateActive {
		return Session{}, ErrCompleted
	}
	if session.Offset != expectedOffset {
		return session, ErrOffsetMismatch
	}
	next, err := s.store.AppendStaging(spaceID, uploadID, expectedOffset, body, s.maxChunk)
	if err != nil {
		return session, err
	}
	session.Offset = next
	if err := s.repo.Update(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s Service) Complete(ctx context.Context, accountID, spaceID, uploadID string) (Session, error) {
	session, err := s.Get(ctx, accountID, spaceID, uploadID)
	if err != nil {
		return Session{}, err
	}
	if session.State != StateActive {
		return Session{}, ErrCompleted
	}
	if session.NodeID == "" {
		return session, fmt.Errorf("%w: final node is not assigned", ErrInvalidTarget)
	}
	if s.security == nil {
		return session, ErrSecurityUnavailable
	}
	decision, err := s.security.EvaluateUpload(ctx, session.SpaceID, session.ID, session.NodeID)
	if err != nil {
		return session, fmt.Errorf("%w: %v", ErrSecurityUnavailable, err)
	}
	if !decision.CanRelease {
		return session, &SecurityBlockedError{Decision: decision}
	}
	if err := s.store.Finalize(spaceID, uploadID, session.NodeID); err != nil {
		return Session{}, err
	}
	session.State = StateCompleted
	if err := s.repo.Update(ctx, session); err != nil {
		return Session{}, err
	}
	return session, nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate upload ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
