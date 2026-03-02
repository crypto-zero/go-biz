package verification

import "strings"

// CodeCacheKeyPrefix represents a verification code cache key prefix.
type CodeCacheKeyPrefix string

// CacheKeyBuilder constructs Redis keys with a consistent prefix and format.
type CacheKeyBuilder struct {
	prefix CodeCacheKeyPrefix
}

// NewCacheKeyBuilder creates a new key builder with the given prefix.
func NewCacheKeyBuilder(prefix CodeCacheKeyPrefix) *CacheKeyBuilder {
	return &CacheKeyBuilder{prefix: prefix}
}

func (b *CacheKeyBuilder) buildKey(category, medium string, typ CodeType, parts ...string) string {
	all := []string{string(b.prefix), category, medium, strings.ToUpper(string(typ))}
	return strings.Join(append(all, parts...), ":")
}

// CodeKey builds a verification-code storage key.
func (b *CacheKeyBuilder) CodeKey(medium string, typ CodeType, parts ...string) string {
	return b.buildKey("VERIFICATION_CODE", medium, typ, parts...)
}

// LimitKey builds a send-rate-limit key.
func (b *CacheKeyBuilder) LimitKey(medium string, typ CodeType, parts ...string) string {
	return b.buildKey("VERIFICATION_SEND_LIMIT", medium, typ, parts...)
}

// IncorrectKey builds a verification-incorrect-count key.
func (b *CacheKeyBuilder) IncorrectKey(medium string, typ CodeType, parts ...string) string {
	return b.buildKey("VERIFICATION_FAILURE", medium, typ, parts...)
}
