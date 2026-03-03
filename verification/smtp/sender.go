package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/crypto-zero/go-biz/verification"
)

// Config holds the SMTP connection configuration.
type Config struct {
	Host     string // SMTP server host, e.g., "smtp.gmail.com"
	Port     int    // SMTP server port, e.g., 587
	Username string // SMTP auth username
	Password string // SMTP auth password
	From     string // Sender email address
	SSL      bool   // Use implicit TLS (port 465); false uses STARTTLS (port 587)
}

// Addr returns "host:port".
func (c *Config) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// Sender implements CodeSender[EmailCode] using Go standard library net/smtp.
type Sender struct {
	config   *Config
	template verification.TemplateProvider[verification.EmailTemplate]
}

// Compile-time assertion: Sender implements CodeSender[EmailCode].
var _ verification.CodeSender[verification.EmailCode] = (*Sender)(nil)

// NewSender creates a new Sender.
func NewSender(config *Config, template verification.TemplateProvider[verification.EmailTemplate]) *Sender {
	return &Sender{
		config:   config,
		template: template,
	}
}

// Send sends the email verification code via SMTP.
func (s *Sender) Send(ctx context.Context, emailCode *verification.EmailCode) error {
	tmpl, err := s.template.GetTemplate(emailCode.Type)
	if err != nil {
		return err
	}

	contentType := tmpl.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}

	t, err := template.New("email").Parse(tmpl.BodyFormat)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	var buf strings.Builder
	if err = t.Execute(&buf, emailCode); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	msg := s.buildMessage(emailCode.Email, tmpl.Subject, contentType, buf.String())

	if s.config.SSL {
		return s.sendWithSSL(ctx, emailCode.Email, msg)
	}
	return s.sendWithSTARTTLS(ctx, emailCode.Email, msg)
}

// sendWithSTARTTLS sends email using STARTTLS (port 587) with context support.
func (s *Sender) sendWithSTARTTLS(ctx context.Context, to string, msg []byte) error {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", s.config.Addr())
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp new client failed: %w", err)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err = client.StartTLS(&tls.Config{ServerName: s.config.Host}); err != nil {
			_ = client.Close()
			return fmt.Errorf("smtp STARTTLS failed: %w", err)
		}
	}

	// Set deadline after TLS upgrade so it applies to the final connection.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err = client.Auth(auth); err != nil {
			_ = client.Close()
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	return s.sendMessage(client, to, msg)
}

// sendWithSSL sends email using implicit TLS (port 465) with context support.
func (s *Sender) sendWithSSL(ctx context.Context, to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: s.config.Host}
	dialer := &tls.Dialer{Config: tlsConfig, NetDialer: &net.Dialer{}}
	conn, err := dialer.DialContext(ctx, "tcp", s.config.Addr())
	if err != nil {
		return fmt.Errorf("smtp tls dial failed: %w", err)
	}

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp new client failed: %w", err)
	}

	// Set deadline from context.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err = client.Auth(auth); err != nil {
			_ = client.Close()
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	return s.sendMessage(client, to, msg)
}

// sendMessage writes the message envelope and body, then gracefully closes the SMTP session.
func (s *Sender) sendMessage(client *smtp.Client, to string, msg []byte) error {
	if err := client.Mail(s.config.From); err != nil {
		_ = client.Close()
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		_ = client.Close()
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		_ = client.Close()
		return fmt.Errorf("smtp write message failed: %w", err)
	}
	if err = w.Close(); err != nil {
		_ = client.Close()
		return fmt.Errorf("smtp close data writer failed: %w", err)
	}
	return client.Quit()
}

// buildMessage constructs the raw RFC 5322 message bytes with required Date and Message-ID headers.
func (s *Sender) buildMessage(to, subject, contentType, body string) []byte {
	now := time.Now()
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(s.config.From)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
	b.WriteString("Date: ")
	b.WriteString(now.Format(time.RFC1123Z))
	b.WriteString("\r\n")
	b.WriteString("Message-ID: <")
	b.WriteString(strconv.FormatInt(now.UnixNano(), 10))
	b.WriteByte('.')
	b.WriteString(s.config.From)
	b.WriteString(">\r\n")
	b.WriteString("Subject: ")
	b.WriteString(mime.QEncoding.Encode("UTF-8", subject))
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: ")
	b.WriteString(contentType)
	b.WriteString("; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
