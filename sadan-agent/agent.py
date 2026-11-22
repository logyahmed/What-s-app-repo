"""سدن الصروح — WhatsApp auto-reply agent (local, Ollama-powered).

Flow:
  bridge (WEBHOOK_ENABLED=true) --POST--> this agent (127.0.0.1:8769)
  agent --> Ollama (local LLM) --> reply JSON
  agent --> bridge /api/send   (bridge enforces reply-window + allowlist)

Security model:
  * The LLM never chooses a recipient. Replies always go to the chat that
    wrote to us; alerts always go to the configured owner number.
  * The webhook requires the bridge token (X-Bridge-Token).
  * Replies with links/phone numbers that are not in the whitelist are
    blocked and handed to the owner instead.

Stdlib only, so it runs on Windows with a plain Python 3.11+ install.
"""

from __future__ import annotations

import hmac
import json
import random
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------- config


@dataclass
class Config:
    bridge_url: str = "http://127.0.0.1:8080/api"
    bridge_token_file: str = "../whatsapp-bridge/store/.bridge-token"
    messages_db: str = "../whatsapp-bridge/store/messages.db"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8769
    owner_number: str = "966597532622"
    owner_aliases: list[str] = field(default_factory=list)
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"
    utc_offset_hours: float = 3.0
    auto_reply: bool = True
    reply_delay_seconds: float = 20.0
    history_messages: int = 20
    style_examples: int = 10
    unanswered_alert_minutes: float = 15.0
    followup_after_hours: float = 24.0
    max_followups: int = 2
    active_hours: tuple[int, int] = (9, 22)
    daily_summary_hour: int = 21
    human_takeover_hours: float = 12.0
    max_reply_chars: int = 700
    allowed_numbers: list[str] = field(default_factory=lambda: ["0570391199", "0570251177", "0557446308"])
    allowed_domains: list[str] = field(default_factory=lambda: ["salsuruh.sa"])
    state_db: str = "agent_state.db"

    @classmethod
    def load(cls, path: Path) -> Config:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        cfg = cls()
        for k, v in data.items():
            if k.startswith("_"):
                continue
            if not hasattr(cfg, k):
                raise SystemExit(f"Unknown config key: {k}")
            setattr(cfg, k, tuple(v) if k == "active_hours" else v)
        return cfg

    def path(self, p: str) -> Path:
        q = Path(p)
        return q if q.is_absolute() else (HERE / q).resolve()

    def tz(self) -> timezone:
        return timezone(timedelta(hours=self.utc_offset_hours))


def digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def jid_user(jid: str) -> str:
    """'9665..:3@s.whatsapp.net' -> '9665..'."""
    return re.split(r"[:@.]", jid or "", maxsplit=1)[0]


def is_owner(cfg: Config, jid_or_number: str) -> bool:
    u = jid_user(jid_or_number)
    keys = {digits(cfg.owner_number)} | {jid_user(a) for a in cfg.owner_aliases} | {digits(a) for a in cfg.owner_aliases}
    keys.discard("")
    return u in keys or digits(u) in keys


# ---------------------------------------------------------------- state


class State:
    """Agent bookkeeping (separate from the bridge DB, which we only read)."""

    def __init__(self, path: Path | str):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS conversations (
                    chat_jid TEXT PRIMARY KEY,
                    name TEXT,
                    first_seen_at REAL,
                    last_inbound_at REAL,
                    last_inbound_text TEXT,
                    last_outbound_at REAL,
                    followups_sent INTEGER NOT NULL DEFAULT 0,
                    paused_until REAL NOT NULL DEFAULT 0,
                    unanswered_alerted INTEGER NOT NULL DEFAULT 0,
                    cold_alerted INTEGER NOT NULL DEFAULT 0,
                    lead_stage TEXT,
                    summary TEXT
                );
                CREATE TABLE IF NOT EXISTS agent_sent (chat_jid TEXT, text TEXT, sent_at REAL);
                CREATE TABLE IF NOT EXISTS events (ts REAL, chat_jid TEXT, kind TEXT, detail TEXT);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                """
            )
            self.db.commit()

    def conv(self, chat: str) -> sqlite3.Row | None:
        with self.lock:
            return self.db.execute("SELECT * FROM conversations WHERE chat_jid=?", (chat,)).fetchone()

    def upsert(self, chat: str, **cols: Any) -> None:
        with self.lock:
            if self.conv(chat) is None:
                self.db.execute("INSERT INTO conversations (chat_jid, first_seen_at) VALUES (?, ?)", (chat, time.time()))
            if cols:
                sets = ", ".join(f"{k}=?" for k in cols)
                self.db.execute(f"UPDATE conversations SET {sets} WHERE chat_jid=?", (*cols.values(), chat))
            self.db.commit()

    def all_convs(self) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.db.execute("SELECT * FROM conversations"))

    def event(self, chat: str, kind: str, detail: str = "") -> None:
        with self.lock:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?)", (time.time(), chat, kind, detail))
            self.db.commit()

    def events_since(self, ts: float) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.db.execute("SELECT * FROM events WHERE ts>=? ORDER BY ts", (ts,)))

    def record_sent(self, chat: str, text: str) -> None:
        with self.lock:
            self.db.execute("INSERT INTO agent_sent VALUES (?,?,?)", (chat, text, time.time()))
            self.db.commit()

    def sent_by_agent(self, chat: str, text: str, within: float = 600) -> bool:
        # Match on text + time only: the bridge may echo the chat as a LID
        # while we addressed it by phone number (or the other way round).
        with self.lock:
            row = self.db.execute(
                "SELECT 1 FROM agent_sent WHERE text=? AND sent_at>=?",
                (text, time.time() - within),
            ).fetchone()
            return row is not None

    def agent_texts(self) -> set[str]:
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT text FROM agent_sent")}

    def get(self, key: str, default: str = "") -> str:
        with self.lock:
            r = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return r[0] if r else default

    def set(self, key: str, value: str) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
            self.db.commit()


# ---------------------------------------------------------------- IO adapters


class Bridge:
    def __init__(self, cfg: Config):
        self.url = cfg.bridge_url.rstrip("/")
        self.token_file = cfg.path(cfg.bridge_token_file)

    def token(self) -> str:
        return self.token_file.read_text(encoding="utf-8").strip()

    def send(self, recipient: str, text: str) -> tuple[bool, str]:
        body = json.dumps({"recipient": recipient, "message": text}).encode()
        req = urllib.request.Request(
            self.url + "/send",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token()},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read() or b"{}")
                return bool(data.get("success")), str(data.get("message", ""))
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("message", str(e))
            except Exception:
                msg = str(e)
            return False, msg
        except Exception as e:  # bridge down
            return False, str(e)


class Ollama:
    SCHEMA = {
        "type": "object",
        "properties": {
            "reply": {"type": "string"},
            "handoff": {"type": "boolean"},
            "handoff_reason": {"type": "string"},
            "lead_stage": {"type": "string"},
            "summary": {"type": "string"},
        },
        "required": ["reply", "handoff", "summary"],
    }

    def __init__(self, cfg: Config):
        self.url = cfg.ollama_url.rstrip("/") + "/api/chat"
        self.model = cfg.model

    def chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "format": self.SCHEMA,
                "options": {"temperature": 0.4},
            }
        ).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            content = json.loads(r.read())["message"]["content"]
        return json.loads(content)


def read_history(db_path: Path, chat: str, limit: int) -> list[sqlite3.Row]:
    if not db_path.exists():
        return []
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT content, is_from_me, timestamp, media_type FROM messages "
            "WHERE chat_jid=? AND deleted_at IS NULL ORDER BY timestamp DESC LIMIT ?",
            (chat, limit),
        ).fetchall()
    except sqlite3.OperationalError:  # older schema without deleted_at
        rows = con.execute(
            "SELECT content, is_from_me, timestamp, media_type FROM messages WHERE chat_jid=? ORDER BY timestamp DESC LIMIT ?",
            (chat, limit),
        ).fetchall()
    finally:
        con.close()
    return list(reversed(rows))


# ---------------------------------------------------------------- safety filters

EGYPTIAN_MARKERS = re.compile(r"(عايز|عاوز|إزيك|ازيك|دلوقتي|كده|بتاع|أوي|اوي|فين|ليه|هيك|شو )")
URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:com|net|org|sa|io|me|ly)\S*)", re.I)
NUM_RE = re.compile(r"\+?\d[\d\s-]{6,}\d")


def unsafe_reason(cfg: Config, text: str) -> str:
    """Return why a generated reply must not be sent, or '' if it's fine."""
    allowed_nums = {digits(n)[-9:] for n in cfg.allowed_numbers}
    for m in NUM_RE.findall(text):
        if digits(m)[-9:] not in allowed_nums:
            return f"الرد فيه رقم غير معروف ({m.strip()})"
    for m in URL_RE.findall(text):
        if not any(d in m.lower() for d in cfg.allowed_domains):
            return f"الرد فيه رابط غير مسموح ({m})"
    return ""


def clean_reply(cfg: Config, text: str) -> str:
    text = (text or "").strip()
    if len(text) > cfg.max_reply_chars:
        cut = text[: cfg.max_reply_chars]
        text = cut[: max(cut.rfind("\n"), cut.rfind("."), cut.rfind("،"), 200)].strip()
    return text


# ---------------------------------------------------------------- the agent

HANDOFF_FALLBACK = "أبشر، بيتواصل معك الأستاذ أحمد بنفسه في أقرب وقت إن شاء الله 🙏"


class Agent:
    def __init__(
        self,
        cfg: Config,
        state: State,
        bridge: Bridge,
        llm: Callable[[list[dict[str, str]]], dict[str, Any]],
        clock: Callable[[], float] = time.time,
    ):
        self.cfg = cfg
        self.state = state
        self.bridge = bridge
        self.llm = llm
        self.clock = clock
        self.timers: dict[str, threading.Timer] = {}
        self.chat_locks: dict[str, threading.Lock] = {}
        self.lock = threading.Lock()

    # --- helpers
    def now_local(self) -> datetime:
        return datetime.fromtimestamp(self.clock(), self.cfg.tz())

    def in_active_hours(self) -> bool:
        start, end = self.cfg.active_hours
        return start <= self.now_local().hour < end

    def paused_globally(self) -> bool:
        return self.state.get("paused") == "1"

    def notify_owner(self, text: str) -> None:
        ok, msg = self.bridge.send(digits(self.cfg.owner_number), text)
        if not ok:
            print(f"[agent] owner alert failed: {msg}", file=sys.stderr)

    def persona_messages(self) -> list[dict[str, str]]:
        persona = (HERE / "persona.md").read_text(encoding="utf-8")
        knowledge = (HERE / "knowledge.md").read_text(encoding="utf-8")
        system = persona + "\n\n" + knowledge
        msgs = [{"role": "system", "content": system}]
        ex_file = HERE / "style_examples.json"
        if ex_file.exists():
            examples = json.loads(ex_file.read_text(encoding="utf-8"))
            random.shuffle(examples)
            for ex in examples[: self.cfg.style_examples]:
                msgs.append({"role": "user", "content": ex["customer"]})
                msgs.append(
                    {
                        "role": "assistant",
                        "content": json.dumps(
                            {"reply": ex["reply"], "handoff": False, "lead_stage": "qualifying", "summary": ""},
                            ensure_ascii=False,
                        ),
                    }
                )
        return msgs

    def conversation_messages(self, chat: str) -> list[dict[str, str]]:
        rows = read_history(self.cfg.path(self.cfg.messages_db), chat, self.cfg.history_messages)
        out: list[dict[str, str]] = []
        for r in rows:
            text = (r["content"] or "").strip() or (f"[أرسل {r['media_type']}]" if r["media_type"] else "")
            if not text:
                continue
            role = "assistant" if r["is_from_me"] else "user"
            if role == "assistant":
                text = json.dumps({"reply": text, "handoff": False, "summary": ""}, ensure_ascii=False)
            if out and out[-1]["role"] == role and role == "user":
                out[-1]["content"] += "\n" + text
            else:
                out.append({"role": role, "content": text})
        return out

    def generate(self, chat: str, extra_instruction: str = "") -> dict[str, Any]:
        msgs = self.persona_messages() + self.conversation_messages(chat)
        if extra_instruction:
            msgs.append({"role": "system", "content": extra_instruction})
        result = self.llm(msgs)
        reply = result.get("reply", "")
        if EGYPTIAN_MARKERS.search(reply):
            msgs.append({"role": "system", "content": "ردك فيه كلمات مصرية. أعد كتابته بلهجة أهل الرياض فقط."})
            result = self.llm(msgs)
        result["reply"] = clean_reply(self.cfg, result.get("reply", ""))
        return result

    def send_to_chat(self, chat: str, text: str) -> bool:
        self.state.record_sent(chat, text)
        ok, msg = self.bridge.send(chat, text)
        if ok:
            self.state.upsert(chat, last_outbound_at=self.clock(), unanswered_alerted=0)
        else:
            self.state.event(chat, "send_failed", msg)
            print(f"[agent] send to {chat} failed: {msg}", file=sys.stderr)
        return ok

    def label(self, chat: str) -> str:
        c = self.state.conv(chat)
        name = (c["name"] if c else "") or ""
        num = jid_user(chat)
        return f"{name} ({num})" if name else num

    # --- webhook entry
    def on_webhook(self, p: dict[str, Any]) -> None:
        chat = p.get("chatJID") or ""
        if not chat or chat.endswith("@g.us") or chat.endswith("@broadcast") or chat.endswith("@newsletter"):
            return
        if p.get("eventType") and p.get("eventType") != "message":
            return
        content = (p.get("content") or "").strip()
        if not content and p.get("mediaType"):
            content = f"[أرسل {p['mediaType']}]"

        if p.get("isFromMe"):
            if not is_owner(self.cfg, chat):  # our own alerts to the owner
                self.on_self_message(chat, content)
            return
        if is_owner(self.cfg, p.get("sender") or "") or is_owner(self.cfg, chat):
            self.on_owner_command(content)
            return
        if not content:
            return

        c = self.state.conv(chat)
        self.state.upsert(
            chat,
            last_inbound_at=self.clock(),
            last_inbound_text=content[:500],
            followups_sent=0,
            cold_alerted=0,
            name=(c["name"] if c and c["name"] else p.get("senderName") or None),
        )
        if c is None:
            self.state.event(chat, "new_lead", content[:200])
        self.schedule(chat)

    def on_self_message(self, chat: str, content: str) -> None:
        if not content or self.state.sent_by_agent(chat, content):
            return
        # The owner answered this chat himself: step back for a while.
        until = self.clock() + self.cfg.human_takeover_hours * 3600
        self.state.upsert(chat, paused_until=until, last_outbound_at=self.clock(), unanswered_alerted=0)
        self.state.event(chat, "human_takeover", content[:200])
        with self.lock:
            t = self.timers.pop(chat, None)
        if t:
            t.cancel()

    def on_owner_command(self, text: str) -> None:
        t = text.strip()
        if t in {"وقف", "ايقاف", "إيقاف", "stop"}:
            self.state.set("paused", "1")
            self.notify_owner("⏸️ وقّفت الرد الأوتوماتيك. ابعت «شغل» عشان أرجع.")
        elif t in {"شغل", "تشغيل", "start"}:
            self.state.set("paused", "0")
            self.notify_owner("▶️ رجعت أرد على العملاء.")
        elif t in {"ملخص", "summary"}:
            self.notify_owner(self.daily_summary())
        elif t in {"حالة", "status"}:
            state = "واقف" if self.paused_globally() else "شغال"
            self.notify_owner(f"الوكيل {state} — الموديل {self.cfg.model}")

    def schedule(self, chat: str) -> None:
        with self.lock:
            old = self.timers.pop(chat, None)
            if old:
                old.cancel()
            t = threading.Timer(self.cfg.reply_delay_seconds, self.process_chat, args=(chat,))
            t.daemon = True
            self.timers[chat] = t
            t.start()

    # --- reply
    def process_chat(self, chat: str) -> None:
        with self.lock:
            self.timers.pop(chat, None)
            lock = self.chat_locks.setdefault(chat, threading.Lock())
        with lock:
            c = self.state.conv(chat)
            if c is None or not self.cfg.auto_reply or self.paused_globally():
                return
            if c["paused_until"] and c["paused_until"] > self.clock():
                return
            if c["last_outbound_at"] and c["last_inbound_at"] and c["last_outbound_at"] >= c["last_inbound_at"]:
                return  # already answered
            try:
                result = self.generate(chat)
            except Exception as e:
                self.state.event(chat, "llm_error", str(e))
                print(f"[agent] LLM error for {chat}: {e}", file=sys.stderr)
                return  # the unanswered-reminder will alert the owner
            self.apply_result(chat, result, is_followup=False)

    def apply_result(self, chat: str, result: dict[str, Any], is_followup: bool) -> None:
        reply = result.get("reply", "")
        handoff = bool(result.get("handoff"))
        reason = (result.get("handoff_reason") or "").strip()
        bad = unsafe_reason(self.cfg, reply)
        if bad:
            handoff, reason, reply = True, bad, HANDOFF_FALLBACK
        if not reply:
            handoff, reason, reply = True, reason or "ما قدر يكتب رد", HANDOFF_FALLBACK
        self.state.upsert(chat, lead_stage=result.get("lead_stage") or None, summary=(result.get("summary") or None))
        self.send_to_chat(chat, reply)
        if is_followup:
            c = self.state.conv(chat)
            self.state.upsert(chat, followups_sent=(c["followups_sent"] if c else 0) + 1)
            self.state.event(chat, "followup", reply[:200])
        if handoff:
            until = self.clock() + self.cfg.human_takeover_hours * 3600
            self.state.upsert(chat, paused_until=until)
            self.state.event(chat, "handoff", reason)
            c = self.state.conv(chat)
            self.notify_owner(
                "🔔 *عميل عايز يكلمك*\n"
                f"العميل: {self.label(chat)}\n"
                f"السبب: {reason or 'طلب يكلم شخص'}\n"
                f"آخر رسالة: {(c['last_inbound_text'] if c else '') or '-'}\n"
                f"الملخص: {(c['summary'] if c else '') or '-'}\n"
                f"وقّفت الرد على المحادثة دي {int(self.cfg.human_takeover_hours)} ساعة."
            )

    # --- periodic work
    def tick(self) -> None:
        now = self.clock()
        for c in self.state.all_convs():
            chat = c["chat_jid"]
            inbound, outbound = c["last_inbound_at"] or 0, c["last_outbound_at"] or 0
            # 1) Customer waiting (agent paused/handed off/failed).
            if inbound > outbound and not c["unanswered_alerted"] and now - inbound >= self.cfg.unanswered_alert_minutes * 60:
                self.state.upsert(chat, unanswered_alerted=1)
                self.state.event(chat, "unanswered")
                mins = int((now - inbound) // 60)
                self.notify_owner(
                    f"⏰ *عميل مستني رد* من {mins} دقيقة\nالعميل: {self.label(chat)}\nرسالته: {c['last_inbound_text'] or '-'}"
                )
            # 2) Customer went silent after our reply.
            if outbound and inbound and outbound >= inbound and now - outbound >= self.cfg.followup_after_hours * 3600:
                if c["paused_until"] and c["paused_until"] > now:
                    continue
                if c["followups_sent"] < self.cfg.max_followups:
                    if self.cfg.auto_reply and not self.paused_globally() and self.in_active_hours():
                        self.followup(chat)
                elif not c["cold_alerted"]:
                    self.state.upsert(chat, cold_alerted=1)
                    self.state.event(chat, "cold")
                    self.notify_owner(
                        f"🧊 *عميل سكت* بعد {self.cfg.max_followups} متابعات\nالعميل: {self.label(chat)}\nالملخص: {c['summary'] or '-'}\nممكن تكلمه بنفسك."
                    )
        # 3) Daily summary + nightly style refresh.
        local = self.now_local()
        today = local.strftime("%Y-%m-%d")
        if local.hour >= self.cfg.daily_summary_hour and self.state.get("last_summary") != today:
            self.state.set("last_summary", today)
            self.notify_owner(self.daily_summary())
            try:
                from learn_style import build_examples

                build_examples(self.cfg.path(self.cfg.messages_db), HERE / "style_examples.json", self.state.agent_texts())
            except Exception as e:
                print(f"[agent] style refresh failed: {e}", file=sys.stderr)

    def followup(self, chat: str) -> None:
        c = self.state.conv(chat)
        n = (c["followups_sent"] if c else 0) + 1
        try:
            result = self.generate(
                chat,
                f"العميل ما رد من فترة. اكتب رسالة متابعة رقم {n} قصيرة ولطيفة بدون إلحاح، "
                "تذكّره بطلبه وتسأله سؤال واحد سهل يخليه يرد. لا تكرر نفس رسالتك السابقة.",
            )
        except Exception as e:
            self.state.event(chat, "llm_error", str(e))
            return
        result["handoff"] = bool(result.get("handoff"))
        self.apply_result(chat, result, is_followup=True)
        self.notify_owner(f"🔁 *متابعة عميل سكت* ({n}/{self.cfg.max_followups})\nالعميل: {self.label(chat)}")

    def daily_summary(self) -> str:
        local = self.now_local()
        start = local.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        evs = self.state.events_since(start)
        count = lambda k: sum(1 for e in evs if e["kind"] == k)  # noqa: E731
        active = [c for c in self.state.all_convs() if (c["last_inbound_at"] or 0) >= start]
        waiting = [c for c in self.state.all_convs() if (c["last_inbound_at"] or 0) > (c["last_outbound_at"] or 0)]
        lines = [
            f"📊 *ملخص اليوم* {local.strftime('%Y-%m-%d')}",
            f"محادثات اليوم: {len(active)} — عملاء جدد: {count('new_lead')}",
            f"تحويل ليك: {count('handoff')} — متابعات: {count('followup')} — مستنيين رد: {len(waiting)}",
        ]
        for c in active[:15]:
            lines.append(f"• {self.label(c['chat_jid'])}: {c['summary'] or (c['last_inbound_text'] or '')[:80]}")
        if self.paused_globally():
            lines.append("⏸️ الرد الأوتوماتيك واقف حاليًا.")
        return "\n".join(lines)


# ---------------------------------------------------------------- HTTP


def make_handler(agent: Agent, token_getter: Callable[[], str]):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep stdout quiet; no message content in logs
            pass

        def do_POST(self):
            if self.path.rstrip("/") != "/whatsapp/webhook":
                self.send_error(404)
                return
            got = self.headers.get("X-Bridge-Token", "")
            try:
                expected = token_getter()
            except OSError:
                expected = ""
            if not expected or not hmac.compare_digest(got, expected):
                self.send_error(401)
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 20 * 1024 * 1024:
                self.send_error(413)
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self.send_error(400)
                return
            self.send_response(200)
            self.end_headers()
            threading.Thread(target=agent.on_webhook, args=(payload,), daemon=True).start()

    return Handler


def main() -> None:
    cfg = Config.load(HERE / "config.json")
    if cfg.listen_host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("listen_host must be loopback")
    state = State(cfg.path(cfg.state_db))
    bridge = Bridge(cfg)
    agent = Agent(cfg, state, bridge, Ollama(cfg).chat)

    def loop():
        while True:
            try:
                agent.tick()
            except Exception as e:
                print(f"[agent] tick error: {e}", file=sys.stderr)
            time.sleep(60)

    threading.Thread(target=loop, daemon=True).start()
    server = ThreadingHTTPServer((cfg.listen_host, cfg.listen_port), make_handler(agent, bridge.token))
    print(f"سدن الصروح agent listening on http://{cfg.listen_host}:{cfg.listen_port}/whatsapp/webhook (model {cfg.model})")
    server.serve_forever()


if __name__ == "__main__":
    main()
