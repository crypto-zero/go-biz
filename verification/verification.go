package verification

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/crypto-zero/go-kit/text"
	"github.com/redis/go-redis/v9"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	tea "github.com/alibabacloud-go/tea/tea"
)

var (
	// ErrCodeNotFound represents a verification code not found error.
	ErrCodeNotFound = errors.New("verification code not found")
	// ErrCodeTypeIsEmpty represents a verification code type is empty error.
	ErrCodeTypeIsEmpty = errors.New("verification code type is empty")
)

type Code struct {
	// user id
	UserID int64
	// type of the verification code
	Type string
	// sequence of this verification
	Sequence string
	// code size
	CodeLength int32
	// code
	Code string
	// content
	Content string
	// context arguments
	Args []any
	// content format function
	Format func(content string, args ...any) string
}

// MobileCode represents a mobile verification code.
type MobileCode struct {
	Code
	// mobile
	Mobile string
	// country code
	CountryCode string
}

// EmailCode represents an email verification code.
type EmailCode struct {
	Code
	// email
	Email string
}

// EcdsaCode represents an ecdsa verification code.
type EcdsaCode struct {
	Code
	// chain
	Chain string
	// The chain address
	Address string
}

// CodeGenerator represents a verification code generator.
type CodeGenerator interface {
	// NewMobileCode generates a new mobile verification code.
	NewMobileCode(ctx context.Context, typ string, userID int64, mobile,
		countryCode string) (*MobileCode, error)
	// NewEmailCode generates a new email verification code.
	NewEmailCode(ctx context.Context, typ string, userID int64, email string,
	) (*EmailCode, error)
	// NewEcdsaCode generates a new ecdsa verification code.
	NewEcdsaCode(ctx context.Context, typ string, userID int64, chain,
		address string) (*EcdsaCode, error)
}

// MobileCodeSender represents a mobile verification code sender.
type MobileCodeSender interface {
	// Send the mobile verification code via SMS.
	Send(ctx context.Context, code *MobileCode) error
}

// Compile-time assertion: StaticCodeGenerator implements CodeGenerator.
var _ CodeGenerator = (*StaticCodeGenerator)(nil)

// CodeCacheKeyPrefix represents a verification code cache key prefix.
type CodeCacheKeyPrefix string

// CodeCache represents a verification code cache.
type CodeCache interface {
	// SetMobileCode sets the mobile verification code.
	SetMobileCode(ctx context.Context, code *MobileCode,
		expire time.Duration) error
	// SetEmailCode sets the email verification code.
	SetEmailCode(ctx context.Context, code *EmailCode,
		expire time.Duration) error
	// SetEcdsaCode sets the ecdsa verification code.
	SetEcdsaCode(ctx context.Context, code *EcdsaCode,
		expire time.Duration) error
	// GetMobileCode gets the mobile verification code.
	GetMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) (
		*MobileCode, error)
	// PeekMobileCode gets the mobile verification code without deleting it.
	PeekMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) (*MobileCode, error)
	// DeleteMobileCode deletes the stored mobile verification code.
	DeleteMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) error
	// GetEmailCode gets the email verification code.
	GetEmailCode(ctx context.Context, typ, sequence, email string) (
		*EmailCode, error)
	// PeekEmailCode gets the email verification code without deleting it.
	PeekEmailCode(ctx context.Context, typ, sequence, email string) (*EmailCode, error)
	// DeleteEmailCode deletes the stored email verification code.
	DeleteEmailCode(ctx context.Context, typ, sequence, email string) error
	// GetEcdsaCode gets the ecdsa verification code.
	GetEcdsaCode(ctx context.Context, typ, sequence, chain, address string) (
		*EcdsaCode, error)
	// PeekEcdsaCode gets the ecdsa verification code without deleting it.
	PeekEcdsaCode(ctx context.Context, typ, sequence, chain, address string) (*EcdsaCode, error)
	// DeleteEcdsaCode deletes the stored ecdsa verification code.
	DeleteEcdsaCode(ctx context.Context, typ, sequence, chain, address string) error
}

// ============================================================================
// Generator (static) and helpers
// ============================================================================

// StaticCodeGenerator generates verification codes. It has two modes:
//   - fixed test mode (returns "666666"), used by DefaultCodeGenerator
//   - random numeric mode (returns N-digit numeric), used by FourDigitCodeGenerator
type StaticCodeGenerator struct {
	useRandom bool
	digits    int
}

// randomDigits returns an n-length numeric string using go-kit helper.
func randomDigits(n int) string {
	if n <= 0 {
		n = 4
	}
	// Use shared helper from go-kit to generate numeric-only random string.
	return text.RandStringWithCharset(n, "0123456789")
}

func (s StaticCodeGenerator) NewSequence() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int64())
}

func (s StaticCodeGenerator) NewTestCode() (string, int32) { return "666666", 6 }

func (s StaticCodeGenerator) codeAndLen() (string, int32) {
	if s.useRandom {
		d := s.digits
		if d <= 0 {
			d = 4
		}
		return randomDigits(d), int32(d)
	}
	return s.NewTestCode()
}

func (s StaticCodeGenerator) NewMobileCode(_ context.Context,
	typ string, userID int64, mobile, countryCode string,
) (*MobileCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.codeAndLen()
	return &MobileCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Mobile:      mobile,
		CountryCode: countryCode,
	}, nil
}

func (s StaticCodeGenerator) NewEmailCode(_ context.Context,
	typ string, userID int64, email string,
) (*EmailCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.codeAndLen()
	return &EmailCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Email: email,
	}, nil
}

func (s StaticCodeGenerator) NewEcdsaCode(_ context.Context,
	typ string, userID int64, chain, publicKeyHex string,
) (*EcdsaCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.codeAndLen()
	code = fmt.Sprintf("%s-%d", code, time.Now().UnixNano())
	return &EcdsaCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Chain:   chain,
		Address: publicKeyHex,
	}, nil
}

// DefaultCodeGenerator returns the fixed test code ("666666").
var DefaultCodeGenerator CodeGenerator = &StaticCodeGenerator{useRandom: false, digits: 6}

// FourDigitCodeGenerator returns random 4-digit numeric codes.
var FourDigitCodeGenerator CodeGenerator = &StaticCodeGenerator{useRandom: true, digits: 4}

// ============================================================================
// Cache (Redis gob serialization)
// ============================================================================

// CodeCacheImpl is a struct that implements CodeCache interface
type CodeCacheImpl struct {
	prefix CodeCacheKeyPrefix
	client redis.UniversalClient
}

// Compile-time assertion: CodeCacheImpl implements CodeCache.
var _ CodeCache = (*CodeCacheImpl)(nil)

func (v CodeCacheImpl) MobileCodeKey(typ, sequence, mobile, countryCode string) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:MOBILE:%s:%s:%s:%s", v.prefix, typ,
		sequence, mobile, countryCode)
}

func (v CodeCacheImpl) EmailCodeKey(typ, sequence, email string) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:EMAIL:%s:%s:%s", v.prefix, typ, sequence,
		email)
}

func (v CodeCacheImpl) EcdsaCodeKey(typ, sequence, chain,
	address string,
) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:ECDSA:%s:%s:%s:%s", v.prefix, typ, sequence, chain, address)
}

func (v CodeCacheImpl) SetMobileCode(ctx context.Context, code *MobileCode, expire time.Duration) (err error) {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err = encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode mobile verification code: %w", err)
	}
	key := v.MobileCodeKey(code.Type, code.Sequence, code.Mobile, code.CountryCode)
	if err = v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set mobile verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) SetEmailCode(ctx context.Context, code *EmailCode, expire time.Duration) error {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err := encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode email verification code: %w", err)
	}
	key := v.EmailCodeKey(code.Type, code.Sequence, code.Email)
	if err := v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set email verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) SetEcdsaCode(ctx context.Context, code *EcdsaCode, expire time.Duration) error {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err := encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode ecdsa verification code: %w", err)
	}
	key := v.EcdsaCodeKey(code.Type, code.Sequence, code.Chain, code.Address)
	if err := v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set ecdsa verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) GetMobileCode(ctx context.Context,
	typ, sequence, mobile, countryCode string,
) (*MobileCode, error) {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mobile verification code: %w", err)
	}
	var code MobileCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode mobile verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) GetEmailCode(ctx context.Context, typ, sequence, email string,
) (*EmailCode, error) {
	key := v.EmailCodeKey(typ, sequence, email)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get email verification code: %w", err)
	}
	var code EmailCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode email verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) GetEcdsaCode(ctx context.Context, typ, sequence, chain, address string,
) (*EcdsaCode, error) {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ecdsa verification code: %w", err)
	}
	var code EcdsaCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) PeekMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) (*MobileCode, error) {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek mobile verification code: %w", err)
	}
	var code MobileCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode mobile verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) error {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete mobile verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) PeekEmailCode(ctx context.Context, typ, sequence, email string) (*EmailCode, error) {
	key := v.EmailCodeKey(typ, sequence, email)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek email verification code: %w", err)
	}
	var code EmailCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode email verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteEmailCode(ctx context.Context, typ, sequence, email string) error {
	key := v.EmailCodeKey(typ, sequence, email)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete email verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) PeekEcdsaCode(ctx context.Context, typ, sequence, chain, address string) (*EcdsaCode, error) {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek ecdsa verification code: %w", err)
	}
	var code EcdsaCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteEcdsaCode(ctx context.Context, typ, sequence, chain, address string) error {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete ecdsa verification code: %w", err)
	}
	return nil
}

// ============================================================================
// SMS Sender (Aliyun Dysms)
// ============================================================================

// AliyunSmsSender implements MobileCodeSender using Alibaba Cloud Dysms API.
type AliyunSmsSender struct {
	accessKeyID     string
	accessKeySecret string
	regionID        string
	signName        string
	templateCode    string
}

// Compile-time assertion: AliyunSmsSender implements MobileCodeSender.
var _ MobileCodeSender = (*AliyunSmsSender)(nil)

// newClient builds a Dysms client with the configured credentials.
func (a *AliyunSmsSender) newClient() (*dysms.Client, error) {
	cfg := &openapi.Config{
		AccessKeyId:     tea.String(a.accessKeyID),
		AccessKeySecret: tea.String(a.accessKeySecret),
		RegionId:        tea.String(a.regionID),
	}
	cfg.Endpoint = tea.String("dysmsapi.aliyuncs.com")
	return dysms.NewClient(cfg)
}

func formatAliyunPhone(mobile, countryCode string) string {
	cc := strings.TrimSpace(countryCode)
	m := strings.TrimSpace(mobile)
	if cc == "" || cc == "86" {
		return m // Mainland China numbers can be used directly
	}
	return cc + m
}

// Send sends the SMS using Alibaba Cloud Dysms SendSms API.
func (a *AliyunSmsSender) Send(ctx context.Context, mc *MobileCode) error {
	if mc == nil {
		return errors.New("mobile code is nil")
	}
	client, err := a.newClient()
	if err != nil {
		return fmt.Errorf("aliyun sms: create client: %w", err)
	}

	// Build template params.
	payload := map[string]string{
		"code": mc.Code.Code,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("aliyun sms: marshal template params: %w", err)
	}

	req := &dysms.SendSmsRequest{
		PhoneNumbers:  tea.String(formatAliyunPhone(mc.Mobile, mc.CountryCode)),
		SignName:      tea.String(a.signName),
		TemplateCode:  tea.String(a.templateCode),
		TemplateParam: tea.String(string(b)),
		OutId:         tea.String(mc.Sequence), // helpful for tracing/idempotency on our side
	}

	resp, err := client.SendSms(req)
	if err != nil {
		return fmt.Errorf("aliyun sms: send failed: %w", err)
	}
	if resp == nil || resp.Body == nil {
		return errors.New("aliyun sms: empty response body")
	}
	if code := tea.StringValue(resp.Body.Code); strings.ToUpper(code) != "ok" {
		return fmt.Errorf("aliyun sms: send not ok: code=%s, msg=%s, requestId=%s, bizId=%s",
			tea.StringValue(resp.Body.Code), tea.StringValue(resp.Body.Message), tea.StringValue(resp.Body.RequestId), tea.StringValue(resp.Body.BizId))
	}
	return nil
}

func NewAliyunSmsSender(ak, sk, regionID, signName, templateCode string) *AliyunSmsSender {
	return &AliyunSmsSender{
		accessKeyID:     ak,
		accessKeySecret: sk,
		regionID:        regionID,
		signName:        signName,
		templateCode:    templateCode,
	}
}

// ============================================================================
// Verification Service
// ============================================================================

// VerificationService encapsulates sending and verifying OTP codes.
type VerificationService struct {
	cache     CodeCache
	smssender MobileCodeSender
	generator CodeGenerator
	// Policy
	ttl time.Duration // e.g., 5 * time.Minute
}

// NewService returns a configured VerificationService.
// It keeps internal fields unexported while providing a simple constructor
// for external packages to initialize the service.
func NewService(cache CodeCache, sender MobileCodeSender, gen CodeGenerator, ttl time.Duration) *VerificationService {
	return &VerificationService{
		cache:     cache,
		smssender: sender,
		generator: gen,
		ttl:       ttl,
	}
}

// NewDefaultService returns a service that generates the fixed test code ("666666").
func NewDefaultService(cache CodeCache, sender MobileCodeSender, ttl time.Duration) *VerificationService {
	return NewService(cache, sender, DefaultCodeGenerator, ttl)
}

// NewRandom4Service returns a service that generates a random 4-digit numeric code.
func NewRandom4Service(cache CodeCache, sender MobileCodeSender, ttl time.Duration) *VerificationService {
	return NewService(cache, sender, FourDigitCodeGenerator, ttl)
}

// SendMobileOTP generates a code, stores it, sends SMS, and returns the sequence.
func (s *VerificationService) SendMobileOTP(ctx context.Context, typ string, userID int64, mobile, countryCode string) (string, error) {
	mc, err := s.generator.NewMobileCode(ctx, typ, userID, mobile, countryCode)
	if err != nil {
		return "", err
	}
	if err := s.cache.SetMobileCode(ctx, mc, s.ttl); err != nil {
		return "", err
	}
	if err := s.smssender.Send(ctx, mc); err != nil {
		return "", err
	}
	return mc.Sequence, nil
}

func (s *VerificationService) VerifyMobileOTP(ctx context.Context, typ, sequence, mobile, countryCode, input string) (bool, error) {
	// Non-destructive read
	stored, err := s.cache.PeekMobileCode(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return false, err
	}
	if stored.Code.Code != input {
		return false, nil
	}
	// Delete after successful verification (one-time code)
	if err := s.cache.DeleteMobileCode(ctx, typ, sequence, mobile, countryCode); err != nil {
		return false, err
	}
	return true, nil
}

// NewCodeCacheImpl is a function that returns a new CodeCacheImpl
func NewCodeCacheImpl(prefix CodeCacheKeyPrefix, client redis.UniversalClient) CodeCache {
	return &CodeCacheImpl{
		prefix: prefix,
		client: client,
	}
}
