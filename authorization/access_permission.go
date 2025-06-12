package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/go-kratos/kratos/v2/transport"
)

// ErrHTTPHeaderNotFound is the error that the header is not found.
var ErrHTTPHeaderNotFound = errors.New("header not found")

// userKey is the context key for the User value.
type userKey struct{}

// UserFromContext returns the User value stored in ctx
func UserFromContext[T any](ctx context.Context) *T {
	value := ctx.Value(userKey{})
	if value == nil {
		return nil
	}
	out, ok := value.(*T)
	if !ok {
		return nil
	}
	return out
}

// NewUserContext returns a new Context that carries value u.
func NewUserContext[T any](ctx context.Context, u *T) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// AccessPermission is the interface that accesses permission.
type AccessPermission interface {
	// UserAuthenticateBuilder returns the user authenticate builder.
	UserAuthenticateBuilder(errorMap map[error]error) *selector.Builder
	// OptionalUserAuthenticateBuilder returns the optional user authenticate builder.
	OptionalUserAuthenticateBuilder(errorMap map[error]error) *selector.Builder
}

// AccessPermissionProvisioner is the access permission provisioner.
type AccessPermissionProvisioner[T any] interface {
	// GetUserByID gets the user by user id.
	GetUserByID(ctx context.Context, userID int64) (*T, error)
}

// HTTPHeaderAccessPermissionHeader is the HTTP header user access permission header.
type HTTPHeaderAccessPermissionHeader string

// HTTPHeaderAccessPermissionRefreshSessionExpireTime
// is the HTTP header user access permission refresh session expire time.
type HTTPHeaderAccessPermissionRefreshSessionExpireTime time.Duration

// HTTPHeaderAccessPermission is the HTTP header user access permission.
type HTTPHeaderAccessPermission[T any] struct {
	header       HTTPHeaderAccessPermissionHeader
	expire       HTTPHeaderAccessPermissionRefreshSessionExpireTime
	sessionCache SessionCache
	provisioner  AccessPermissionProvisioner[T]
}

func (u *HTTPHeaderAccessPermission[T]) ErrorMappingMiddleware(errorMap map[error]error) middleware.Middleware {
	errorReplaceMiddleware := func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			reply, err := handler(ctx, req)
			for k, v := range errorMap {
				if errors.Is(err, k) {
					return nil, v
				}
			}
			return reply, err
		}
	}
	return errorReplaceMiddleware
}

func (u *HTTPHeaderAccessPermission[T]) UserAuthenticateBuilder(errorMap map[error]error,
) *selector.Builder {
	return selector.Server(u.ErrorMappingMiddleware(errorMap), u.userAuthenticateMiddleware)
}

func (u *HTTPHeaderAccessPermission[T]) OptionalUserAuthenticateBuilder(errorMap map[error]error,
) *selector.Builder {
	return selector.Server(u.ErrorMappingMiddleware(errorMap), u.optionalUserAuthenticateMiddleware)
}

func (u *HTTPHeaderAccessPermission[T]) optionalUserAuthenticateMiddleware(
	handler middleware.Handler,
) middleware.Handler {
	return func(ctx context.Context, req any) (any, error) {
		// Skip if the user is already in the context.
		if originUser := UserFromContext[T](ctx); originUser != nil {
			return handler(ctx, req)
		}
		tr, ok := transport.FromServerContext(ctx)
		if !ok {
			return handler(ctx, req)
		}
		token := tr.RequestHeader().Get(string(u.header))
		if token == "" {
			return handler(ctx, req)
		}
		userID, err := u.sessionCache.GetUserIDBySessionID(ctx, token, time.Duration(u.expire))
		if errors.Is(err, ErrSessionNotFound) {
			return handler(ctx, req)
		}
		if err != nil {
			return nil, err
		}
		user, err := u.provisioner.GetUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return handler(NewUserContext(ctx, user), req)
	}
}

func (u *HTTPHeaderAccessPermission[T]) userAuthenticateMiddleware(handler middleware.Handler,
) middleware.Handler {
	return func(ctx context.Context, req any) (any, error) {
		// Skip if the user is already in the context.
		if originUser := UserFromContext[T](ctx); originUser != nil {
			return handler(ctx, req)
		}
		tr, ok := transport.FromServerContext(ctx)
		if !ok {
			return nil, ErrHTTPHeaderNotFound
		}
		token := tr.RequestHeader().Get(string(u.header))
		if token == "" {
			return nil, ErrHTTPHeaderNotFound
		}
		userID, err := u.sessionCache.GetUserIDBySessionID(ctx, token, time.Duration(u.expire))
		if err != nil {
			return nil, err
		}
		user, err := u.provisioner.GetUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return handler(NewUserContext(ctx, user), req)
	}
}

// NewHTTPHeaderAccessPermissionRefreshSessionExpireTime
// returns a new HTTPHeaderAccessPermissionRefreshSessionExpireTime.
func NewHTTPHeaderAccessPermissionRefreshSessionExpireTime() HTTPHeaderAccessPermissionRefreshSessionExpireTime {
	return HTTPHeaderAccessPermissionRefreshSessionExpireTime(UserSessionExpiration)
}

// NewHTTPHeaderAccessPermission creates a new HTTP header user access permission.
func NewHTTPHeaderAccessPermission[T any](
	header HTTPHeaderAccessPermissionHeader,
	expire HTTPHeaderAccessPermissionRefreshSessionExpireTime,
	sessionCache SessionCache,
	provisioner AccessPermissionProvisioner[T],
) AccessPermission {
	return &HTTPHeaderAccessPermission[T]{
		header:       header,
		expire:       expire,
		sessionCache: sessionCache,
		provisioner:  provisioner,
	}
}
