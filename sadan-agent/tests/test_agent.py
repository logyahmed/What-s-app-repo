import json
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agent as A  # noqa: E402
from learn_style import build_examples  # noqa: E402

CHAT = "966500000001@s.whatsapp.net"
OWNER = "966597532622"


class FakeBridge:
    def __init__(self):
        self.sent = []

    def send(self, recipient, text):
        self.sent.append((recipient, text))
        return True, "ok"

    def token(self):
        return "tok"


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make_db(path: Path, rows):
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE messages (id TEXT, chat_jid TEXT, sender TEXT, content TEXT, timestamp TIMESTAMP,"
        " is_from_me BOOLEAN, media_type TEXT, deleted_at TIMESTAMP)"
    )
    for i, (chat, content, from_me, ts) in enumerate(rows):
        con.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,NULL,NULL)", (f"m{i}", chat, chat, content, ts, from_me))
    con.commit()
    con.close()


@pytest.fixture
def env(tmp_path):
    # Noon in Riyadh (09:00 UTC) so we're inside active hours.
    clock = Clock(datetime(2026, 11, 22, 9, 0, tzinfo=timezone.utc).timestamp())
    db = tmp_path / "messages.db"
    make_db(db, [(CHAT, "السلام عليكم ابي شقة للايجار في النرجس", 0, "2026-11-22 12:00:00")])
    cfg = A.Config(messages_db=str(db), state_db=str(tmp_path / "s.db"), owner_number=OWNER, reply_delay_seconds=999)
    replies = []

    def llm(msgs):
        replies.append(msgs)
        return llm.next

    llm.next = {"reply": "هلا والله، أبشر. كم ميزانيتك تقريبًا؟", "handoff": False, "summary": "يبي شقة إيجار بالنرجس"}
    bridge = FakeBridge()
    ag = A.Agent(cfg, A.State(cfg.state_db), bridge, llm, clock=clock)
    return ag, bridge, llm, clock, replies


def inbound(ag, text="ابي شقة", chat=CHAT):
    ag.on_webhook({"chatJID": chat, "sender": chat, "content": text, "isFromMe": False})


def test_replies_to_the_chat_that_wrote(env):
    ag, bridge, llm, clock, calls = env
    inbound(ag)
    ag.process_chat(CHAT)
    assert bridge.sent == [(CHAT, llm.next["reply"])]
    sys_prompt = calls[0][0]["content"]
    assert "سدن الصروح" in sys_prompt and "رخصة فال" in sys_prompt
    assert calls[0][-1]["role"] == "user" and "النرجس" in calls[0][-1]["content"]


def test_groups_and_reactions_ignored(env):
    ag, bridge, *_ = env
    ag.on_webhook({"chatJID": "123@g.us", "sender": "x", "content": "hi"})
    ag.on_webhook({"chatJID": CHAT, "sender": CHAT, "content": "👍", "eventType": "reaction"})
    assert ag.state.conv("123@g.us") is None and ag.state.conv(CHAT) is None


def test_handoff_notifies_owner_and_pauses(env):
    ag, bridge, llm, *_ = env
    llm.next = {"reply": "أبشر، بيكلمك الأستاذ أحمد", "handoff": True, "handoff_reason": "سأل عن العمولة", "summary": "s"}
    inbound(ag, "كم العمولة؟")
    ag.process_chat(CHAT)
    assert bridge.sent[0][0] == CHAT
    owner_msg = bridge.sent[1]
    assert owner_msg[0] == OWNER and "عميل عايز يكلمك" in owner_msg[1] and "العمولة" in owner_msg[1]
    inbound(ag, "وش صار؟")
    ag.process_chat(CHAT)
    assert len(bridge.sent) == 2  # paused: no more auto replies


def test_unknown_number_in_reply_is_blocked(env):
    ag, bridge, llm, *_ = env
    llm.next = {"reply": "كلمني على 0551234567", "handoff": False, "summary": ""}
    inbound(ag)
    ag.process_chat(CHAT)
    assert bridge.sent[0] == (CHAT, A.HANDOFF_FALLBACK)
    assert "رقم غير معروف" in bridge.sent[1][1]


def test_allowed_number_and_domain_pass():
    cfg = A.Config()
    assert A.unsafe_reason(cfg, "واتساب 0570391199 أو salsuruh.sa") == ""
    assert A.unsafe_reason(cfg, "شوف evil.com") != ""


def test_egyptian_dialect_is_regenerated(env):
    ag, bridge, llm, clock, calls = env
    answers = iter(
        [{"reply": "انت عايز شقة؟", "handoff": False, "summary": ""}, {"reply": "تبي شقة؟", "handoff": False, "summary": ""}]
    )
    ag.llm = lambda m: (calls.append(m), next(answers))[1]
    inbound(ag)
    ag.process_chat(CHAT)
    assert bridge.sent == [(CHAT, "تبي شقة؟")]


def test_human_takeover_pauses_chat(env):
    ag, bridge, *_ = env
    inbound(ag)
    ag.on_webhook({"chatJID": CHAT, "sender": "me", "content": "هلا أخوي معك أحمد", "isFromMe": True})
    ag.process_chat(CHAT)
    assert bridge.sent == []


def test_agent_echo_is_not_takeover(env):
    ag, bridge, llm, *_ = env
    inbound(ag)
    ag.process_chat(CHAT)
    ag.on_webhook({"chatJID": CHAT, "sender": "me", "content": llm.next["reply"], "isFromMe": True})
    assert ag.state.conv(CHAT)["paused_until"] == 0


def test_owner_commands(env):
    ag, bridge, *_ = env
    ag.on_webhook({"chatJID": OWNER + "@s.whatsapp.net", "sender": OWNER + "@s.whatsapp.net", "content": "وقف"})
    assert ag.paused_globally()
    inbound(ag)
    ag.process_chat(CHAT)
    assert all(r == OWNER for r, _ in bridge.sent)
    ag.on_webhook({"chatJID": OWNER + "@s.whatsapp.net", "sender": OWNER, "content": "شغل"})
    assert not ag.paused_globally()


def test_unanswered_reminder(env):
    ag, bridge, llm, clock, _ = env
    ag.state.set("paused", "1")
    inbound(ag)
    clock.t += 16 * 60
    ag.tick()
    alerts = [t for r, t in bridge.sent if r == OWNER]
    assert any("عميل مستني رد" in t for t in alerts)
    ag.tick()
    assert sum("عميل مستني رد" in t for _, t in bridge.sent) == 1  # alert once


def test_followups_then_cold_alert(env):
    ag, bridge, llm, clock, _ = env
    ag.cfg.daily_summary_hour = 24  # keep summary out of this test
    inbound(ag)
    ag.process_chat(CHAT)
    for _ in range(2):
        clock.t += 25 * 3600
        ag.tick()
    assert sum("متابعة عميل سكت" in t for _, t in bridge.sent) == 2
    clock.t += 25 * 3600
    ag.tick()
    assert any("عميل سكت" in t and "متابعات" in t for _, t in bridge.sent)


def test_no_followup_at_night(env):
    ag, bridge, llm, clock, _ = env
    ag.cfg.daily_summary_hour = 24
    inbound(ag)
    ag.process_chat(CHAT)
    clock.t += 41 * 3600  # 12:00 -> 05:00 local, 41h after our reply
    n = len(bridge.sent)
    ag.tick()
    assert len(bridge.sent) == n


def test_daily_summary(env):
    ag, bridge, llm, clock, _ = env
    inbound(ag)
    ag.process_chat(CHAT)
    clock.t = datetime(2026, 11, 22, 18, 5, tzinfo=timezone.utc).timestamp()  # 21:05 Riyadh
    ag.tick()
    summaries = [t for r, t in bridge.sent if r == OWNER and "ملخص اليوم" in t]
    assert len(summaries) == 1 and "عملاء جدد: 1" in summaries[0]
    ag.tick()
    assert len([t for _, t in bridge.sent if "ملخص اليوم" in t]) == 1


def test_learn_style(tmp_path):
    db = tmp_path / "m.db"
    make_db(
        db,
        [
            (CHAT, "السلام عليكم عندكم أراضي؟", 0, "2026-01-01 10:00:00"),
            (CHAT, "وعليكم السلام حياك الله، وش الحي اللي تبيه؟", 1, "2026-01-01 10:01:00"),
            (CHAT, "تمام", 0, "2026-01-01 10:02:00"),
            (CHAT, "ok", 1, "2026-01-01 10:03:00"),  # too short
            ("1@g.us", "group", 0, "2026-01-01 10:00:00"),
            ("1@g.us", "reply in group", 1, "2026-01-01 10:01:00"),
        ],
    )
    out = tmp_path / "ex.json"
    assert build_examples(db, out) == 1
    ex = json.loads(out.read_text(encoding="utf-8"))
    assert ex[0]["reply"].startswith("وعليكم السلام")


def test_webhook_requires_token(env):
    ag, *_ = env
    srv = ThreadingHTTPServer(("127.0.0.1", 0), A.make_handler(ag, lambda: "secret-token"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/whatsapp/webhook"
    body = json.dumps({"chatJID": CHAT, "content": "x"}).encode()
    try:
        with pytest.raises(Exception) as e:
            urlopen(Request(url, data=body, headers={"X-Bridge-Token": "wrong"}))
        assert "401" in str(e.value)
        with urlopen(Request(url, data=body, headers={"X-Bridge-Token": "secret-token"})) as r:
            assert r.status == 200
    finally:
        srv.shutdown()


def test_config_rejects_unknown_keys(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"bogus": 1}')
    with pytest.raises(SystemExit):
        A.Config.load(p)
