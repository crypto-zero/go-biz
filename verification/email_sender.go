package verification

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
)

var (
	// ErrNilEmailCode represents a nil email code error.
	ErrNilEmailCode = errors.New("email code is nil")
	// ErrEmailCodeEmailIsEmpty represents an empty email error.
	ErrEmailCodeEmailIsEmpty = errors.New("email code email is empty")
	// ErrEmailCodeCodeIsEmpty represents an empty code error.
	ErrEmailCodeCodeIsEmpty = errors.New("email code code is empty")
	// ErrEmailCodeTypeIsEmpty represents an empty code type error.
	ErrEmailCodeTypeIsEmpty = errors.New("email code type is empty")
	// ErrEmailTemplateNotFound represents an email template not found error.
	ErrEmailTemplateNotFound = errors.New("email template not found")
)

// EmailTemplateMapper maps CodeType to EmailTemplate.
type EmailTemplateMapper map[CodeType]*EmailTemplate

// EmailTemplate represents an email template with subject and body format.
type EmailTemplate struct {
	// Subject is the email subject line, supports fmt.Sprintf with the code as argument.
	// e.g., "Your verification code"
	Subject string `json:"subject"`
	// BodyFormat is the email body format string.
	// Use %s as the placeholder for the verification code.
	// Supports both plain text and HTML.
	// e.g., "<p>Your verification code is: <b>%s</b></p>"
	BodyFormat string `json:"body_format"`
	// ContentType specifies the MIME type for the body: "text/plain" or "text/html".
	// Defaults to "text/plain" if empty.
	ContentType string `json:"content_type"`
}

// SMTPConfig holds the SMTP connection configuration.
type SMTPConfig struct {
	Host     string // SMTP server host, e.g., "smtp.gmail.com"
	Port     int    // SMTP server port, e.g., 587
	Username string // SMTP auth username
	Password string // SMTP auth password
	From     string // Sender email address
	SSL      bool   // Use implicit TLS (port 465); false uses STARTTLS (port 587)
}

// Addr returns "host:port".
func (c *SMTPConfig) Addr() string {
	return net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
}

// SMTPEmailSender implements EmailCodeSender using Go standard library net/smtp.
type SMTPEmailSender struct {
	config   *SMTPConfig
	template EmailTemplateMapper
}

// Compile-time assertion: SMTPEmailSender implements EmailCodeSender.
var _ EmailCodeSender = (*SMTPEmailSender)(nil)

// NewSMTPEmailSender creates a new SMTPEmailSender.
func NewSMTPEmailSender(config *SMTPConfig, template EmailTemplateMapper) *SMTPEmailSender {
	return &SMTPEmailSender{
		config:   config,
		template: template,
	}
}

// Send sends the email verification code via SMTP.
func (s *SMTPEmailSender) Send(_ context.Context, emailCode *EmailCode) error {
	if emailCode == nil {
		return ErrNilEmailCode
	}
	if emailCode.Email == "" {
		return ErrEmailCodeEmailIsEmpty
	}
	if emailCode.Code.Code == "" {
		return ErrEmailCodeCodeIsEmpty
	}
	if emailCode.Type == "" {
		return ErrEmailCodeTypeIsEmpty
	}

	tmpl, ok := s.template[emailCode.Type]
	if !ok {
		return ErrEmailTemplateNotFound
	}

	contentType := tmpl.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}

	body := fmt.Sprintf(tmpl.BodyFormat, emailCode.Code.Code)
	msg := s.buildMessage(emailCode.Email, tmpl.Subject, contentType, body)

	if s.config.SSL {
		return s.sendWithSSL(emailCode.Email, msg)
	}
	return s.sendWithSTARTTLS(emailCode.Email, msg)
}

// sendWithSTARTTLS sends email using STARTTLS (port 587).
func (s *SMTPEmailSender) sendWithSTARTTLS(to string, msg []byte) error {
	var auth smtp.Auth
	if s.config.Username != "" {
		auth = smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	}
	if err := smtp.SendMail(s.config.Addr(), auth, s.config.From, []string{to}, msg); err != nil {
		return fmt.Errorf("smtp send email failed: %w", err)
	}
	return nil
}

// sendWithSSL sends email using implicit TLS (port 465).
func (s *SMTPEmailSender) sendWithSSL(to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: s.config.Host}
	conn, err := tls.Dial("tcp", s.config.Addr(), tlsConfig)
	if err != nil {
		return fmt.Errorf("smtp tls dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("smtp new client failed: %w", err)
	}
	defer client.Close()

	if s.config.Username != "" {
		auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	if err = client.Mail(s.config.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	if _, err = w.Write(msg); err != nil {
		return fmt.Errorf("smtp write message failed: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("smtp close data writer failed: %w", err)
	}
	return client.Quit()
}

// buildMessage constructs the raw RFC 2822 message bytes.
func (s *SMTPEmailSender) buildMessage(to, subject, contentType, body string) []byte {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(s.config.From)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
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
