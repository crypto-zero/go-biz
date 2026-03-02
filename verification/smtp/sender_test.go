package smtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/crypto-zero/go-biz/verification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSMTPServer spins up a minimal SMTP server that captures the last message.
type mockSMTPServer struct {
	listener net.Listener
	wg       sync.WaitGroup

	mu      sync.Mutex
	lastMsg string // raw message received
	lastTo  string // RCPT TO address
}

func newMockSMTPServer(t *testing.T) *mockSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &mockSMTPServer{listener: ln}
	s.wg.Add(1)
	go s.serve(t)
	return s
}

func (s *mockSMTPServer) addr() string { return s.listener.Addr().String() }
func (s *mockSMTPServer) host() string {
	h, _, _ := net.SplitHostPort(s.addr())
	return h
}
func (s *mockSMTPServer) port() int {
	_, p, _ := net.SplitHostPort(s.addr())
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

func (s *mockSMTPServer) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockSMTPServer) getLastMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastMsg
}

func (s *mockSMTPServer) getLastTo() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTo
}

// serve handles one connection then stops (sufficient for single-test usage).
func (s *mockSMTPServer) serve(t *testing.T) {
	t.Helper()
	defer s.wg.Done()
	conn, err := s.listener.Accept()
	if err != nil {
		return // listener closed
	}
	defer conn.Close()

	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	write := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}

	// SMTP greeting
	write("220 localhost SMTP mock")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-localhost")
			write("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			// Extract recipient
			s.mu.Lock()
			s.lastTo = line[len("RCPT TO:"):]
			s.lastTo = strings.Trim(s.lastTo, " <>")
			s.mu.Unlock()
			write("250 OK")
		case upper == "DATA":
			write("354 Go ahead")
			var msg strings.Builder
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(dataLine) == "." {
					break
				}
				msg.WriteString(dataLine)
			}
			s.mu.Lock()
			s.lastMsg = msg.String()
			s.mu.Unlock()
			write("250 OK")
		case upper == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}

// testTemplateProvider is a test helper that implements verification.TemplateProvider.
type testTemplateProvider map[verification.CodeType]*Template

func (p testTemplateProvider) GetTemplate(typ verification.CodeType) (*Template, error) {
	t, ok := p[typ]
	if !ok {
		return nil, verification.ErrEmailTemplateNotFound
	}
	return t, nil
}

func testEmailTemplate() testTemplateProvider {
	return testTemplateProvider{
		"LOGIN": {
			Subject:     "Login Code",
			BodyFormat:  "<p>Your code: <b>%s</b></p>",
			ContentType: "text/html",
		},
		"REGISTER": {
			Subject:    "Register Code",
			BodyFormat: "Your code is: %s",
			// ContentType defaults to text/plain
		},
	}
}

func TestSender_Validation(t *testing.T) {
	sender := NewSender(&Config{Host: "localhost", Port: 587}, testEmailTemplate())

	tests := []struct {
		name string
		code *verification.EmailCode
		err  error
	}{
		{"nil code", nil, verification.ErrNilEmailCode},
		{"empty email", &verification.EmailCode{Code: verification.Code{Code: "123456", Type: "LOGIN"}}, verification.ErrEmailCodeEmailIsEmpty},
		{"empty code", &verification.EmailCode{Code: verification.Code{Type: "LOGIN"}, Email: "a@b.com"}, verification.ErrEmailCodeCodeIsEmpty},
		{"empty type", &verification.EmailCode{Code: verification.Code{Code: "123456"}, Email: "a@b.com"}, verification.ErrEmailCodeTypeIsEmpty},
		{"template not found", &verification.EmailCode{
			Code: verification.Code{Code: "123456", Type: "UNKNOWN"}, Email: "a@b.com",
		}, verification.ErrEmailTemplateNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sender.Send(context.Background(), tt.code)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestSender_BuildMessage(t *testing.T) {
	sender := NewSender(&Config{
		Host: "smtp.example.com", Port: 587,
		Username: "user", Password: "pass",
		From: "noreply@example.com",
	}, testEmailTemplate())

	t.Run("html content type", func(t *testing.T) {
		msg := string(sender.buildMessage("user@example.com", "Login Code", "text/html", "<p>Code: <b>123456</b></p>"))
		assert.Contains(t, msg, "From: noreply@example.com")
		assert.Contains(t, msg, "To: user@example.com")
		assert.Contains(t, msg, "Content-Type: text/html; charset=UTF-8")
		assert.Contains(t, msg, "<p>Code: <b>123456</b></p>")
		assert.Contains(t, msg, "MIME-Version: 1.0")
	})

	t.Run("plain text content type", func(t *testing.T) {
		msg := string(sender.buildMessage("user@example.com", "Register Code", "text/plain", "Your code is: 654321"))
		assert.Contains(t, msg, "Content-Type: text/plain; charset=UTF-8")
		assert.Contains(t, msg, "Your code is: 654321")
	})

	t.Run("utf8 subject encoding", func(t *testing.T) {
		msg := string(sender.buildMessage("user@example.com", "验证码", "text/plain", "code"))
		assert.Contains(t, msg, "Subject: =?UTF-8?")
	})
}

func TestSender_Send_Integration(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSender(&Config{
		Host: srv.host(), Port: srv.port(),
		From: "noreply@example.com",
		// no auth for mock server
	}, testEmailTemplate())

	t.Run("html email", func(t *testing.T) {
		ec := &verification.EmailCode{
			Code:  verification.Code{Code: "888888", Type: "LOGIN"},
			Email: "user@example.com",
		}
		err := sender.Send(context.Background(), ec)
		require.NoError(t, err)

		msg := srv.getLastMessage()
		assert.Contains(t, msg, "<p>Your code: <b>888888</b></p>")
		assert.Contains(t, msg, "Content-Type: text/html")
		assert.Equal(t, "user@example.com", srv.getLastTo())
	})
}

// TestSender_RealSend sends a real email via SMTP.
// Skipped unless SMTP_HOST is set. Designed to work with Mailpit:
//
//	docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
//
// Then run:
//
//	SMTP_HOST=localhost SMTP_TEST_TO=test@example.com go test -v -run TestSender_RealSend ./...
//
// Open http://localhost:8025 to view the captured email.
//
// For STARTTLS servers (e.g. Gmail, port 587):
//
//	SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USERNAME=you@gmail.com \
//	SMTP_PASSWORD=app-password SMTP_FROM=you@gmail.com \
//	SMTP_TEST_TO=recipient@example.com go test -v -run TestSender_RealSend ./...
//
// For SSL/TLS servers (e.g. Hostinger, port 465):
//
//	SMTP_HOST=smtp.hostinger.com SMTP_PORT=465 SMTP_SSL=true \
//	SMTP_USERNAME=you@yourdomain.com SMTP_PASSWORD=your-password \
//	SMTP_FROM=you@yourdomain.com SMTP_TEST_TO=recipient@example.com \
//	go test -v -run TestSender_RealSend ./...
func TestSender_RealSend(t *testing.T) {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		t.Skip("SMTP_HOST not set, skipping real SMTP test")
	}

	port := 1025 // Mailpit default
	if p := os.Getenv("SMTP_PORT"); p != "" {
		var err error
		port, err = strconv.Atoi(p)
		require.NoError(t, err, "invalid SMTP_PORT")
	}

	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = "test@example.com" // Mailpit accepts any sender
	}

	to := os.Getenv("SMTP_TEST_TO")
	if to == "" {
		to = "user@example.com" // Mailpit accepts any recipient
	}

	useSSL := os.Getenv("SMTP_SSL") == "true"

	config := &Config{
		Host:     host,
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     from,
		SSL:      useSSL,
	}

	tmpl := testTemplateProvider{
		"LOGIN": {
			Subject:     "Login Verification Code",
			ContentType: "text/html",
			BodyFormat: `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#f4f5f7;font-family:'Helvetica Neue',Arial,sans-serif;">
  <table width="100%%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
    <tr><td align="center">
      <table width="420" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);overflow:hidden;">
        <tr>
          <td style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:32px 40px;text-align:center;">
            <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:600;">Verification Code</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:36px 40px;">
            <p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6;">
              Please use the following code to complete your login. This code will expire in 5 minutes.
            </p>
            <div style="background:#f8f5ff;border:2px dashed #8b5cf6;border-radius:8px;padding:20px;text-align:center;margin:0 0 24px;">
              <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#6366f1;">%s</span>
            </div>
            <p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.5;">
              If you did not request this code, please ignore this email.
            </p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
            <p style="margin:0;color:#9ca3af;font-size:12px;">© 2026 YourApp. All rights reserved.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
		},
	}

	sender := NewSender(config, tmpl)
	ec := &verification.EmailCode{
		Code:  verification.Code{Code: "888888", Type: "LOGIN"},
		Email: to,
	}
	err := sender.Send(context.Background(), ec)
	require.NoError(t, err)
	t.Logf("Email sent to %s via %s:%d (SSL=%v) — check your inbox", to, host, port, useSSL)
}
