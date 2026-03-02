# go-biz

Reusable Go business logic modules for building backend services. Each package is an independent Go module with its own `go.mod`, allowing selective dependency management.

## Modules

```
go-biz/
├── authorization/       # Session management & access control middleware
├── nats/
│   ├── publisher/       # NATS JetStream message publishing
│   └── subscriber/      # NATS JetStream message consumption
└── verification/        # OTP service (SMS, Email, ECDSA)
    └── aliyun/          # Alibaba Cloud SMS sender
```

### Authorization

```
go get github.com/crypto-zero/go-biz/authorization
```

Session-based authentication middleware for [Kratos](https://github.com/go-kratos/kratos) HTTP services, backed by Redis.

**Core Components:**

| Component | Description |
|---|---|
| `SessionCache` | Redis-backed session store with Lua-script-based atomic set/get/delete and auto-expiry cleanup |
| `SessionIDGenerator` | Pluggable session ID generation (default: 32-char random string) |
| `AccessPermission` | Kratos `selector.Builder` middleware for mandatory & optional user authentication |
| `UserFromContext[T]` | Generic helper to extract user from `context.Context` |

**Usage:**

```go
// Create session cache
cache := authorization.NewSessionCacheImpl("myapp", redisClient)

// Create access permission middleware
perm := authorization.NewHTTPHeaderAccessPermission[User](
    "X-Token",
    authorization.NewHTTPHeaderAccessPermissionRefreshSessionExpireTime(),
    cache,
    userProvisioner, // implements GetUserByID
)

// Use in Kratos server
httpSrv := http.NewServer(
    http.Middleware(
        selector.Server(perm.UserAuthenticateBuilder(errorMap)).
            Path("/api/v1/protected").Build(),
    ),
)
```

---

### NATS Publisher

```
go get github.com/crypto-zero/go-biz/nats/publisher
```

JetStream publisher with automatic stream creation and message deduplication.

**Features:**
- Auto-creates stream with configurable retention, replicas, compression (S2), and max age/bytes
- Built-in message deduplication via `Nats-Msg-Id` header
- Supports stream republish
- `Message` interface for structured publishing

```go
pub, err := publisher.NewJetStreamPublisher(natsConn, publisher.JetStreamPublisherOptions{
    StreamName:     "ORDERS",
    SubjectPattern: "orders.>",
})

// Low-level publish
pub.Publish(ctx, "orders.created", "order-123", jsonBytes)

// Or use Message interface
msgPub, _ := publisher.NewJetStreamMessagePublisher(natsConn, opts)
msgPub.Publish(ctx, myMessage) // myMessage implements publisher.Message
```

---

### NATS Subscriber

```
go get github.com/crypto-zero/go-biz/nats/subscriber
```

JetStream pull subscriber with automatic consumer setup, graceful shutdown, and jitter-based retry.

```go
sub := subscriber.NewJetStreamSubscriber(natsConn, subscriber.JetStreamSubscriberOptions{
    ConsumerPrefix: "order-service-",
    StreamName:     "ORDERS",
    AckWait:        10 * time.Second,
}, logger)

// Block and consume messages until context cancellation
sub.Subscribe(ctx, "orders.created", "processor", subscriber.HandlerFunc(
    func(ctx context.Context, subject, id string, data []byte,
        inProgress func(ctx context.Context) error,
    ) error {
        // Process message...
        return nil
    },
))
```

---

### Verification

```
go get github.com/crypto-zero/go-biz/verification
```

Full-featured OTP (One-Time Password) service supporting **SMS**, **Email**, and **ECDSA** verification flows, with Redis-backed storage and rate limiting.

**Architecture:**

```
OTPService
├── CodeGenerator       # Generates sequences & codes (static/random/4-digit/6-digit)
├── CodeCache           # Redis storage with gob serialization & TTL
├── CodeLimiterCache    # Fixed-window rate limiting (send & verify)
├── MobileCodeSender    # SMS delivery (Aliyun impl)
└── EmailCodeSender     # Email delivery (SMTP impl)
```

**Quick Start:**

```go
// Create OTP service
otpSvc := verification.NewOTPService(
    codeCache, limiterCache,
    smsSender, emailSender,
    verification.FourDigitCodeGenerator,
    1*time.Hour,  // send window
    1*time.Hour,  // verify window
    5*time.Minute, // code TTL
    5,  // max send attempts per window
    5,  // max verify attempts per window
)

// Send & Verify Email OTP
seq, err := otpSvc.SendEmailOTP(ctx, "LOGIN", userID, "user@example.com")
err = otpSvc.VerifyEmailOTP(ctx, "LOGIN", seq, "user@example.com", "1234")

// Send & Verify Mobile OTP
seq, err = otpSvc.SendMobileOTP(ctx, "LOGIN", userID, "13800138000", "86")
err = otpSvc.VerifyMobileOTP(ctx, "LOGIN", seq, "13800138000", "86", "1234")
```

#### Email Sender (SMTP)

Supports **STARTTLS** (port 587) and **implicit SSL/TLS** (port 465):

```go
sender := verification.NewSMTPEmailSender(
    &verification.SMTPConfig{
        Host:     "smtp.hostinger.com",
        Port:     465,
        Username: "noreply@yourdomain.com",
        Password: "your-password",
        From:     "noreply@yourdomain.com",
        SSL:      true, // implicit TLS for port 465
    },
    verification.EmailTemplateMapper{
        "LOGIN": {
            Subject:     "Verification Code",
            ContentType: "text/html",
            BodyFormat:  "<p>Your code: <b>%s</b></p>",
        },
    },
)
```

#### Aliyun SMS Sender

```
go get github.com/crypto-zero/go-biz/verification/aliyun
```

```go
client, _ := aliyun.NewAliyunMainlandSMSClient(
    accessKeyID, accessKeySecret, "cn-hangzhou", "dysmsapi.aliyuncs.com",
)
smsSender := aliyun.NewSMS(client, aliyun.TemplateMapper{
    "LOGIN": {
        Code:         "SMS_123456",
        SignName:     "YourApp",
        ParamsFormat: `{"code":"%s"}`,
    },
})
```

## Testing

Each module can be tested independently:

```bash
# Authorization
cd authorization && go test ./...

# NATS Publisher
cd nats/publisher && go test ./...

# NATS Subscriber
cd nats/subscriber && go test ./...

# Verification (unit tests with embedded Redis)
cd verification && go test ./...

# Verification (real SMTP email sending via Mailpit)
docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
cd verification && SMTP_HOST=localhost go test -v -run TestSMTPEmailSender_RealSend ./...
# Open http://localhost:8025 to view captured emails
```

## License

Private repository — all rights reserved.
