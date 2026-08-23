// Package authn defines the authenticated-principal boundary used by Drive.
package authn

import (
	"context"
	"errors"
	"net/http"
)

// ErrUnauthenticated means no trusted authenticated principal is available.
var ErrUnauthenticated = errors.New("unauthenticated")

// Principal is the minimum identity Drive authorization needs from an
// authenticated session. Authentication providers may carry more information,
// but authorization keys off the durable Drive account ID.
type Principal struct {
	AccountID string
}

// Resolver translates an already-authenticated request/session into a trusted
// Drive principal. Implementations must not trust arbitrary client-supplied
// account identifiers.
type Resolver interface {
	Resolve(context.Context, *http.Request) (Principal, error)
}

// DenyAllResolver is the safe default until production authentication is
// explicitly integrated. It prevents development endpoints from accidentally
// treating untrusted request data as identity.
type DenyAllResolver struct{}

func (DenyAllResolver) Resolve(context.Context, *http.Request) (Principal, error) {
	return Principal{}, ErrUnauthenticated
}
