package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

const guardTestToken = "guardtesttoken1234567890abcdef00"

func guardPost(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+guardTestToken)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	return resp
}

func TestNormalizeRecipientKey(t *testing.T) {
	cases := map[string]string{
		"+966 50-123-4567":              "966501234567",
		"966501234567":                  "966501234567",
		"966501234567@s.whatsapp.net":   "966501234567",
		"966501234567:3@s.whatsapp.net": "966501234567",
		"120363000000000000@g.us":       "120363000000000000@g.us",
		"ABC123@LID":                    "abc123@lid",
		"   ":                           "",
	}
	for in, want := range cases {
		if got := normalizeRecipientKey(in); got != want {
			t.Errorf("normalizeRecipientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAllowlistEmptyMeansNil(t *testing.T) {
	if got := parseAllowlist(" , ;"); got != nil {
		t.Fatalf("expected nil allowlist, got %v", got)
	}
}

func TestReadOnlyBlocksSend(t *testing.T) {
	t.Setenv(readOnlyEnv, "true")
	t.Setenv(outboundAuditEnabledEnv, "false")
	h := newRESTMux(newTestClient(&mockLIDStore{}), newTestMessageStore(t), 8080, guardTestToken, nil)

	resp := guardPost(t, h, "/api/send", `{"recipient":"966501234567","message":"hi"}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 in read-only mode, got %d: %s", resp.Code, resp.Body.String())
	}
	var body map[string]interface{}
	_ = json.Unmarshal(resp.Body.Bytes(), &body)
	if body["success"] != false || !strings.Contains(body["message"].(string), "read-only") {
		t.Fatalf("unexpected body: %v", body)
	}

	for _, path := range []string{"/api/react", "/api/typing"} {
		r := guardPost(t, h, path, `{"recipient":"966501234567@s.whatsapp.net","message_id":"X","emoji":"👍","is_typing":true}`)
		if r.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403 in read-only mode, got %d", path, r.Code)
		}
	}
}

func TestAllowlistBlocksUnknownRecipient(t *testing.T) {
	t.Setenv(sendAllowlistEnv, "+966 50 111 2222, 120363000000000000@g.us")
	t.Setenv(outboundAuditEnabledEnv, "false")
	h := newRESTMux(newTestClient(&mockLIDStore{}), newTestMessageStore(t), 8080, guardTestToken, nil)

	resp := guardPost(t, h, "/api/send", `{"recipient":"15550001111","message":"exfil"}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-allow-listed recipient, got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), sendAllowlistEnv) {
		t.Fatalf("expected allowlist reason, got %s", resp.Body.String())
	}
}

func TestAllowlistAcceptsListedRecipientAndLID(t *testing.T) {
	pn := types.JID{User: "966501112222", Server: types.DefaultUserServer}
	lid := types.JID{User: "99887766", Server: types.HiddenUserServer}
	client := newTestClient(&mockLIDStore{pnByLID: map[types.JID]types.JID{lid: pn}})

	p := &outboundPolicy{allowlist: parseAllowlist("+966501112222"), now: time.Now}
	for _, r := range []string{"966501112222", "+966 50 111 2222", "966501112222@s.whatsapp.net", "99887766@lid"} {
		if !p.recipientAllowed(client, r) {
			t.Errorf("expected %q to be allowed", r)
		}
	}
	if p.recipientAllowed(client, "11112222@lid") {
		t.Error("unmapped LID must not be allowed")
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &outboundPolicy{rateLimit: 2, now: func() time.Time { return now }}
	if !p.takeRateSlot() || !p.takeRateSlot() {
		t.Fatal("first two slots should be granted")
	}
	if p.takeRateSlot() {
		t.Fatal("third slot within a minute must be refused")
	}
	now = now.Add(sendRateWindow + time.Second)
	if !p.takeRateSlot() {
		t.Fatal("slot should be granted after the window passes")
	}
}

func TestRateLimitZeroIsUnlimited(t *testing.T) {
	p := &outboundPolicy{rateLimit: 0, now: time.Now}
	for i := 0; i < 100; i++ {
		if !p.takeRateSlot() {
			t.Fatal("rate limit 0 must be unlimited")
		}
	}
}

func TestLoadOutboundPolicyDefaults(t *testing.T) {
	t.Setenv(readOnlyEnv, "")
	t.Setenv(sendAllowlistEnv, "")
	t.Setenv(sendRateLimitEnv, "")
	p := loadOutboundPolicy()
	if p.readOnly || p.allowlist != nil || p.rateLimit != defaultSendRateLimit || !p.audit {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	t.Setenv(sendRateLimitEnv, "not-a-number")
	if loadOutboundPolicy().rateLimit != defaultSendRateLimit {
		t.Fatal("invalid rate limit must fall back to the default")
	}
}

func TestReplyWindowAllowsRecentInboundOnly(t *testing.T) {
	ms := newTestMessageStore(t)
	now := time.Now()
	for _, row := range []struct {
		chat   string
		ts     time.Time
		fromMe bool
	}{
		{"966500000001@s.whatsapp.net", now.Add(-2 * time.Hour), false},       // recent customer
		{"966500000002@s.whatsapp.net", now.Add(-30 * 24 * time.Hour), false}, // old customer
		{"966500000003@s.whatsapp.net", now.Add(-1 * time.Hour), true},        // only we wrote
		{"55554444@lid", now.Add(-1 * time.Hour), false},                      // LID chat
	} {
		if _, err := ms.db.Exec(`INSERT INTO chats (jid) VALUES (?)`, row.chat); err != nil {
			t.Fatal(err)
		}
		if _, err := ms.db.Exec(`INSERT INTO messages (id, chat_jid, sender, content, timestamp, is_from_me) VALUES (?, ?, ?, 'x', ?, ?)`,
			"m-"+row.chat, row.chat, row.chat, row.ts, row.fromMe); err != nil {
			t.Fatal(err)
		}
	}
	p := &outboundPolicy{
		allowlist:   parseAllowlist("+966597532622"),
		replyWindow: 14 * 24 * time.Hour,
		lastInbound: lastInboundFromStore(ms),
		now:         time.Now,
	}
	client := newTestClient(&mockLIDStore{})
	cases := map[string]bool{
		"966500000001":                true, // messaged us 2h ago
		"966500000001@s.whatsapp.net": true,
		"966500000002":                false, // outside window
		"966500000003":                false, // no inbound message
		"15550001111":                 false, // stranger
		"966597532622":                true,  // allow-listed (owner)
		"55554444@lid":                true,  // LID chat that messaged us
	}
	for r, want := range cases {
		if got := p.recipientAllowed(client, r); got != want {
			t.Errorf("recipientAllowed(%q) = %v, want %v", r, got, want)
		}
	}
}

func TestReplyWindowEnvParsing(t *testing.T) {
	t.Setenv(replyWindowEnv, "336")
	if got := loadOutboundPolicy().replyWindow; got != 336*time.Hour {
		t.Fatalf("replyWindow = %v", got)
	}
	t.Setenv(replyWindowEnv, "-1")
	if got := loadOutboundPolicy().replyWindow; got != 0 {
		t.Fatalf("negative window must be ignored, got %v", got)
	}
}
