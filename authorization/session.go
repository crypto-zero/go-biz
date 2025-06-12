package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/crypto-zero/go-kit/text"
)

const (
	// UserSessionLength is the length of the user session.
	UserSessionLength = 32
	// UserSessionExpiration is the expiration time of the user session.
	UserSessionExpiration = 24 * time.Hour
)

// ErrSessionNotFound The session not found error
var ErrSessionNotFound = errors.New("session not found")

// SessionCachePrefix The session cache prefix
type SessionCachePrefix string

// SessionIDGenerator The session id generator interface
type SessionIDGenerator interface {
	// GenerateSessionID generates a session id.
	GenerateSessionID(ctx context.Context, userID int64) (string, error)
}

// SessionCache The session cache interface
type SessionCache interface {
	// SetUserSessionID sets the user session id.
	SetUserSessionID(ctx context.Context, sessionID string, userID int64, expire time.Duration) error
	// GetUserIDBySessionID gets the user id by session id and refresh the session id expire time.
	GetUserIDBySessionID(ctx context.Context, sessionID string, expire time.Duration) (int64, error)
}

// FixedSessionIDGenerator The fixed session id generator
type FixedSessionIDGenerator struct {
	size int
}

func (f FixedSessionIDGenerator) GenerateSessionID(_ context.Context, _ int64,
) (string, error) {
	return text.RandString(f.size), nil
}

// NewFixedSessionIDGenerator returns a new FixedSessionIDGenerator.
func NewFixedSessionIDGenerator(size int) SessionIDGenerator {
	return &FixedSessionIDGenerator{size: size}
}

// NewDefaultSessionGenerator returns a default SessionIDGenerator.
func NewDefaultSessionGenerator() SessionIDGenerator {
	return NewFixedSessionIDGenerator(UserSessionLength)
}
