// Package mail sends messages through the configured SMTP relay. It is used to
// deliver WireGuard client configs to remote-access users. Kept dependency-free
// (net/smtp + a hand-built MIME body) to preserve the single-static-binary goal.
package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"firewall/ui/internal/config"
)

// Attachment is one file attached to a message.
type Attachment struct {
	Name    string
	Content string
}

// Send delivers a plain-text message with optional attachments via the relay in
// cfg. Returns an error if the relay is not configured or delivery fails.
func Send(cfg config.SMTP, to, subject, body string, attachments ...Attachment) error {
	if !cfg.Enabled() {
		return errors.New("smtp relay is not configured")
	}
	if !strings.Contains(to, "@") {
		return fmt.Errorf("invalid recipient %q", to)
	}

	msg := build(cfg.From, to, subject, body, attachments)
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.EffectivePort()))

	c, err := dial(cfg, addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return c.Quit()
}

// dial opens an SMTP session honoring the configured transport security:
// implicit TLS on connect, opportunistic STARTTLS, or plaintext.
func dial(cfg config.SMTP, addr string) (*smtp.Client, error) {
	tlsCfg := &tls.Config{ServerName: cfg.Host}
	if cfg.Security == "tls" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("smtp tls dial: %w", err)
		}
		return smtp.NewClient(conn, cfg.Host)
	}

	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.Security != "none" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				c.Close()
				return nil, fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	return c, nil
}

// build assembles a MIME message. With no attachments it is a simple text mail;
// otherwise a multipart/mixed body with the text part first.
func build(from, to, subject, body string, attachments []Attachment) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")

	if len(attachments) == 0 {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
		return []byte(b.String())
	}

	const boundary = "fwd-boundary-93c2f1a8"
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")

	for _, a := range attachments {
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n\r\n", a.Name)
		b.WriteString(strings.ReplaceAll(a.Content, "\n", "\r\n"))
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}
