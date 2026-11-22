"""Learn Ahmed's reply style from his own past WhatsApp replies.

Reads the bridge's messages.db (read-only), finds customer message -> owner
reply pairs in one-to-one chats, and writes a sample of them to
style_examples.json. The agent shows these to the model as examples, so its
replies sound like Ahmed. Replies the agent itself sent are excluded.

Run:  python learn_style.py
The agent also refreshes this file every night after the daily summary.
"""

from __future__ import annotations

import json
import random
import sqlite3
import sys
from pathlib import Path

MIN_REPLY_CHARS = 8
MAX_EXAMPLES = 60


def build_examples(db_path: Path, out_path: Path, agent_texts: set[str] | None = None) -> int:
    agent_texts = agent_texts or set()
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT chat_jid, content, is_from_me FROM messages "
            "WHERE chat_jid NOT LIKE '%@g.us' AND chat_jid NOT LIKE '%@broadcast' "
            "AND content IS NOT NULL AND content != '' ORDER BY chat_jid, timestamp"
        ).fetchall()
    finally:
        con.close()

    pairs: list[dict[str, str]] = []
    pending: list[str] = []
    current_chat = None
    for chat, content, from_me in rows:
        if chat != current_chat:
            current_chat, pending = chat, []
        if not from_me:
            pending.append(content.strip())
            continue
        reply = content.strip()
        if pending and len(reply) >= MIN_REPLY_CHARS and reply not in agent_texts:
            pairs.append({"customer": "\n".join(pending[-3:])[:600], "reply": reply[:600]})
        pending = []

    random.seed(7)
    random.shuffle(pairs)
    pairs = pairs[:MAX_EXAMPLES]
    Path(out_path).write_text(json.dumps(pairs, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(pairs)


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    cfg = json.loads((here / "config.json").read_text(encoding="utf-8")) if (here / "config.json").exists() else {}
    db = Path(cfg.get("messages_db", "../whatsapp-bridge/store/messages.db"))
    db = db if db.is_absolute() else (here / db).resolve()
    if not db.exists():
        sys.exit(f"messages.db not found at {db} — start the bridge and pair WhatsApp first")
    n = build_examples(db, here / "style_examples.json")
    print(f"اتعلمت من {n} رد من ردودك القديمة -> style_examples.json")
