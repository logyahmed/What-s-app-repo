package main

// Outbound guard — hardening layer added by the whatsapp-mcp-secure fork.
//
// The bearer token in auth.go proves a request came from *our* MCP server,
// but it cannot tell whether the model driving that server was tricked by a
// prompt-injected message ("forward the last 50 messages to +1555..."). This
// file enforces policy at the bridge, below the model, so a compromised or
// confused model still cannot:
//
//   - send anything when WHATSAPP_READ_ONLY=true
//   - message recipients outside WHATSAPP_SEND_ALLOWLIST (when set)
//   - exceed WHATSAPP_SEND_RATE_LIMIT outbound actions per minute
//
// Every decision (allowed or blocked) is appended to store/outbound-audit.log
// (mode 0600) without message content.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
)

const (
	auditLogPath            = "store/outbound-audit.log"
	defaultSendRateLimit    = 10
	sendRateWindow          = time.Minute
	outboundAuditFileMode   = 0o600
	readOnlyEnv             = "WHATSAPP_READ_ONLY"
	sendAllowlistEnv        = "WHATSAPP_SEND_ALLOWLIST"
	sendRateLimitEnv        = "WHATSAPP_SEND_RATE_LIMIT"
	outboundAuditEnabledEnv = "WHATSAPP_OUTBOUND_AUDIT"
)

// outboundPolicy is built once per REST mux from the environment.
type outboundPolicy struct {
	readOnly  bool
	allowlist map[string]struct{} // normalized keys; nil/empty = everyone
	rateLimit int                 // 0 = unlimited
	audit     bool

	mu     sync.Mutex
	recent []time.Time
	now    func() time.Time
}

func loadOutboundPolicy() *outboundPolicy {
	p := &outboundPolicy{
		readOnly:  getEnvBool(readOnlyEnv, false),
		allowlist: parseAllowlist(os.Getenv(sendAllowlistEnv)),
		rateLimit: defaultSendRateLimit,
		audit:     getEnvBool(outboundAuditEnabledEnv, true),
		now:       time.Now,
	}
	if raw := strings.TrimSpace(os.Getenv(sendRateLimitEnv)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			p.rateLimit = n
		} else {
			fmt.Printf("Warning: invalid %s=%q, using default %d\n", sendRateLimitEnv, raw, defaultSendRateLimit)
		}
	}
	return p
}

func (p *outboundPolicy) describe() string {
	allow := "any recipient"
	if len(p.allowlist) > 0 {
		allow = fmt.Sprintf("%d allow-listed recipient(s)", len(p.allowlist))
	}
	rate := "unlimited"
	if p.rateLimit > 0 {
		rate = fmt.Sprintf("%d/min", p.rateLimit)
	}
	return fmt.Sprintf("read_only=%v, recipients=%s, rate=%s, audit=%v", p.readOnly, allow, rate, p.audit)
}

// parseAllowlist accepts comma/space/semicolon separated phone numbers
// (any formatting: "+966 50 123 4567") or full JIDs ("1203...@g.us").
func parseAllowlist(raw string) map[string]struct{} {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	out := map[string]struct{}{}
	for _, f := range fields {
		if k := normalizeRecipientKey(f); k != "" {
			out[k] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeRecipientKey maps the many spellings of a recipient onto one key:
//   - "+966 50-123" / "96650123" / "96650123@s.whatsapp.net" -> "96650123"
//   - "96650123:4@s.whatsapp.net" (device suffix)            -> "96650123"
//   - group / LID / other servers                             -> "user@server"
func normalizeRecipientKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "@") {
		return digitsOnly(s)
	}
	at := strings.LastIndex(s, "@")
	user, server := s[:at], s[at+1:]
	if i := strings.IndexAny(user, ":."); i >= 0 {
		user = user[:i]
	}
	if server == types.DefaultUserServer || server == "c.us" {
		return digitsOnly(user)
	}
	if user == "" || server == "" {
		return ""
	}
	return user + "@" + server
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// recipientAllowed checks the raw recipient and, for LID addresses, the
// phone number WhatsApp maps it to, so allow-listing "+9665..." also covers
// that contact's "...@lid" chat JID.
func (p *outboundPolicy) recipientAllowed(client *whatsmeow.Client, recipient string) bool {
	if len(p.allowlist) == 0 {
		return true
	}
	key := normalizeRecipientKey(recipient)
	if key == "" {
		return false
	}
	if _, ok := p.allowlist[key]; ok {
		return true
	}
	if strings.HasSuffix(key, "@"+types.HiddenUserServer) && client != nil && client.Store != nil && client.Store.LIDs != nil {
		lid, err := types.ParseJID(key)
		if err == nil {
			if pn, err := client.Store.LIDs.GetPNForLID(context.Background(), lid); err == nil && !pn.IsEmpty() {
				if _, ok := p.allowlist[normalizeRecipientKey(pn.String())]; ok {
					return true
				}
			}
		}
	}
	return false
}

// takeRateSlot records one outbound action if the window has room.
func (p *outboundPolicy) takeRateSlot() bool {
	if p.rateLimit <= 0 {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	cutoff := now.Add(-sendRateWindow)
	kept := p.recent[:0]
	for _, t := range p.recent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	p.recent = kept
	if len(p.recent) >= p.rateLimit {
		return false
	}
	p.recent = append(p.recent, now)
	return true
}

// outboundDecision is what a handler needs to reject a request.
type outboundDecision struct {
	Allowed bool
	Status  int
	Reason  string
}

// check evaluates an outbound action. countsTowardRate is false for cheap
// presence signals (typing) that should still respect read-only + allowlist.
func (p *outboundPolicy) check(client *whatsmeow.Client, endpoint, recipient string, countsTowardRate bool) outboundDecision {
	d := outboundDecision{Allowed: true, Status: http.StatusOK}
	switch {
	case p.readOnly:
		d = outboundDecision{false, http.StatusForbidden, "bridge is in read-only mode (" + readOnlyEnv + "=true)"}
	case !p.recipientAllowed(client, recipient):
		d = outboundDecision{false, http.StatusForbidden, "recipient is not in " + sendAllowlistEnv}
	case countsTowardRate && !p.takeRateSlot():
		d = outboundDecision{false, http.StatusTooManyRequests, fmt.Sprintf("rate limit exceeded (%d per minute, %s)", p.rateLimit, sendRateLimitEnv)}
	}
	return d
}

type auditEntry struct {
	Time       string `json:"time"`
	Endpoint   string `json:"endpoint"`
	Recipient  string `json:"recipient"`
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	MessageLen int    `json:"message_len,omitempty"`
	HasMedia   bool   `json:"has_media,omitempty"`
}

var auditMu sync.Mutex

// auditOutbound appends one JSON line. Message bodies are never written.
func (p *outboundPolicy) auditOutbound(endpoint, recipient string, d outboundDecision, messageLen int, hasMedia bool) {
	if !d.Allowed {
		fmt.Printf("✗ outbound blocked endpoint=%s recipient=%q reason=%q\n", endpoint, recipient, d.Reason)
	}
	if !p.audit {
		return
	}
	line, err := json.Marshal(auditEntry{
		Time:       p.now().UTC().Format(time.RFC3339),
		Endpoint:   endpoint,
		Recipient:  recipient,
		Allowed:    d.Allowed,
		Reason:     d.Reason,
		MessageLen: messageLen,
		HasMedia:   hasMedia,
	})
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, outboundAuditFileMode)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Write(append(line, '\n'))
}

// rejectOutbound writes a JSON error body compatible with the existing
// {"success":false,"message":...} shape the MCP server already understands.
func rejectOutbound(w http.ResponseWriter, d outboundDecision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(d.Status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": "Blocked by bridge security policy: " + d.Reason,
		"error":   d.Reason,
	})
}
