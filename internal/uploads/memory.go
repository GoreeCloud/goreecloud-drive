package uploads

import (
	"context"
	"fmt"
	"sync"
)

type MemoryRepository struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{sessions: make(map[string]Session)}
}

func (r *MemoryRepository) Create(_ context.Context, session Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[session.ID]; exists {
		return fmt.Errorf("upload session already exists")
	}
	r.sessions[session.ID] = session
	return nil
}

func (r *MemoryRepository) Get(_ context.Context, id string) (Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (r *MemoryRepository) Update(_ context.Context, session Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[session.ID]; !ok {
		return ErrNotFound
	}
	r.sessions[session.ID] = session
	return nil
}
