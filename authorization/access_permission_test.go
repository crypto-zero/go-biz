package authorization

import (
	"context"
	"fmt"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

type TestUser struct {
	ID int64
}

type TestUserAccessPermissionProvisioner struct{}

func (p *TestUserAccessPermissionProvisioner) GetUserByID(ctx context.Context, userID int64) (*TestUser, error) {
	return &TestUser{ID: userID}, nil
}

func NewTestUserAccessPermissionProvisioner() AccessPermissionProvisioner[TestUser] {
	return &TestUserAccessPermissionProvisioner{}
}

func TestAccessPermission(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		t.Skip()
	}
	redisClient := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{redisAddr}})

	errorMap := map[error]error{
		ErrHTTPHeaderNotFound: errors.New(stdhttp.StatusUnauthorized,
			"http header not found", "http header not found"),
		ErrSessionNotFound: errors.New(stdhttp.StatusForbidden,
			"session not found", "session not found"),
	}

	sessionCache := NewSessionCacheImpl("TEST", redisClient)
	sessionID := "SESSION_ID_001"
	userID := int64(1)
	if err := sessionCache.SetUserSessionID(context.Background(), sessionID, userID, time.Hour); err != nil {
		t.Fatal(err)
	}

	accessPermission := NewHTTPHeaderAccessPermission(
		"X-Accession-Permission",
		NewHTTPHeaderAccessPermissionRefreshSessionExpireTime(),
		sessionCache,
		NewTestUserAccessPermissionProvisioner(),
	)

	srv := http.NewServer(
		http.Middleware(
			func(handler middleware.Handler) middleware.Handler {
				return func(ctx context.Context, req interface{}) (interface{}, error) {
					return handler(ctx, req)
				}
			},
			accessPermission.UserAuthenticateBuilder(errorMap).Path("/v1/foo", "/v1/bar").Build(),
			accessPermission.OptionalUserAuthenticateBuilder(errorMap).
				Match(func(_ context.Context, _ string) bool {
					return true
				}).
				Build(),
		),
	)
	router := srv.Route("/v1")
	router.GET("/hello", func(c http.Context) error {
		h := c.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "hello world", nil
		})
		out, err := h(c, nil)
		if err != nil {
			return err
		}
		reply := out.(string)
		return c.Result(stdhttp.StatusOK, reply)
	})
	router.GET("/foo", func(c http.Context) error {
		h := c.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "hello foo", nil
		})
		out, err := h(c, nil)
		if err != nil {
			return err
		}
		reply := out.(string)
		return c.Result(stdhttp.StatusOK, reply)
	})
	router.GET("/bar", func(c http.Context) error {
		h := c.Middleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			user := UserFromContext[TestUser](ctx)
			if user == nil {
				return nil, ErrSessionNotFound
			}
			return fmt.Sprintf("hello, %d", user.ID), nil
		})
		out, err := h(c, nil)
		if err != nil {
			return err
		}
		reply := out.(string)
		return c.Result(stdhttp.StatusOK, reply)
	})

	{
		req := httptest.NewRequest(stdhttp.MethodGet, "http://127.0.0.1:8000/v1/hello", nil)
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, req)
		assert.Equal(t, stdhttp.StatusOK, rw.Code)
		assert.Equal(t, "\"hello world\"", rw.Body.String())
	}
	{
		req := httptest.NewRequest(stdhttp.MethodGet, "http://127.0.0.1:8000/v1/foo", nil)
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, req)
		assert.Equal(t, stdhttp.StatusUnauthorized, rw.Code)
	}
	{
		req := httptest.NewRequest(stdhttp.MethodGet, "http://127.0.0.1:8000/v1/bar", nil)
		req.Header.Set("X-Accession-Permission", sessionID)
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, req)
		assert.Equal(t, stdhttp.StatusOK, rw.Code)
		assert.Equal(t, "\"hello, 1\"", rw.Body.String())
	}
	{
		req := httptest.NewRequest(stdhttp.MethodGet, "http://127.0.0.1:8000/v1/bar", nil)
		req.Header.Set("X-Accession-Permission", "_session_id_not_found_")
		rw := httptest.NewRecorder()
		srv.ServeHTTP(rw, req)
		assert.Equal(t, stdhttp.StatusForbidden, rw.Code)
	}
}
