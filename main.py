import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from fastapi import File, FastAPI, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "uploads")))
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "chat.db")))

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SESSION_COOKIE = "private_chat_session"
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-this-session-secret")
SESSION_TTL = 60 * 60 * 24 * 30
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"

PASSWORD_SALT = os.getenv("PASSWORD_SALT", "private-chat-salt").encode()
PASSWORD_VALUE = os.getenv("APP_PASSWORD", "291210")
PASSWORD_HASH = os.getenv("APP_PASSWORD_HASH", "")

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "25000000"))

DEFAULT_ICE_SERVERS = [
    {
        "urls": [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
        ]
    }
]


def password_digest(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        PASSWORD_SALT,
        210_000,
    ).hex()


def verify_password(password: str) -> bool:
    expected = PASSWORD_HASH or password_digest(PASSWORD_VALUE)
    actual = password_digest(password)
    return hmac.compare_digest(actual, expected)


def clean_name(name: str) -> str:
    name = " ".join(str(name or "").split())
    return name[:32] or "You"


def create_session(name: str) -> str:
    payload = {
        "name": clean_name(name),
        "nonce": secrets.token_urlsafe(18),
        "expires": int(time.time()) + SESSION_TTL,
    }

    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")

    signature = hmac.new(
        SESSION_SECRET.encode(),
        encoded.encode(),
        hashlib.sha256,
    ).hexdigest()

    return f"{encoded}.{signature}"


def read_session(token: str | None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None

    encoded, signature = token.rsplit(".", 1)

    expected = hmac.new(
        SESSION_SECRET.encode(),
        encoded.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return None

    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded + padding).decode()
        )
    except Exception:
        return None

    if int(payload.get("expires", 0)) < int(time.time()):
        return None

    return payload


def get_cookie(cookie_header: str | None, name: str) -> str | None:
    cookies = SimpleCookie()
    cookies.load(cookie_header or "")
    morsel = cookies.get(name)
    return morsel.value if morsel else None


def current_user(request: Request) -> str:
    session = read_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    return session["name"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    connection = db_connection()

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL DEFAULT 'text',
            meta TEXT NOT NULL DEFAULT '{}',
            reply_to INTEGER,
            reactions TEXT NOT NULL DEFAULT '{}',
            edited INTEGER NOT NULL DEFAULT 0,
            deleted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS shared_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        """
    )

    connection.commit()
    connection.close()


def decode_json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return default


def row_to_message(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "sender": row["sender"],
        "body": row["body"],
        "kind": row["kind"],
        "meta": decode_json(row["meta"], {}),
        "reply_to": row["reply_to"],
        "reactions": decode_json(row["reactions"], {}),
        "edited": bool(row["edited"]),
        "deleted": bool(row["deleted"]),
        "created_at": row["created_at"],
    }


def list_messages(limit: int = 200) -> list[dict[str, Any]]:
    connection = db_connection()

    rows = connection.execute(
        """
        SELECT *
        FROM messages
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, min(limit, 500)),),
    ).fetchall()

    connection.close()

    return [row_to_message(row) for row in reversed(rows)]


def insert_message(
    sender: str,
    body: str,
    kind: str = "text",
    meta: dict[str, Any] | None = None,
    reply_to: int | None = None,
) -> dict[str, Any]:
    connection = db_connection()

    cursor = connection.execute(
        """
        INSERT INTO messages
            (sender, body, kind, meta, reply_to, created_at)
        VALUES
            (?, ?, ?, ?, ?, ?)
        """,
        (
            sender,
            body,
            kind,
            json.dumps(meta or {}),
            reply_to,
            utc_now(),
        ),
    )

    connection.commit()

    row = connection.execute(
        "SELECT * FROM messages WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    connection.close()

    return row_to_message(row)


def edit_message(
    message_id: int,
    sender: str,
    body: str,
) -> dict[str, Any] | None:
    connection = db_connection()

    connection.execute(
        """
        UPDATE messages
        SET body = ?, edited = 1
        WHERE id = ? AND sender = ? AND deleted = 0
        """,
        (body[:4000], message_id, sender),
    )

    connection.commit()

    row = connection.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    connection.close()

    return row_to_message(row) if row else None


def delete_message(
    message_id: int,
    sender: str,
) -> dict[str, Any] | None:
    connection = db_connection()

    connection.execute(
        """
        UPDATE messages
        SET
            body = 'Message deleted',
            kind = 'text',
            meta = '{}',
            deleted = 1
        WHERE id = ? AND sender = ?
        """,
        (message_id, sender),
    )

    connection.commit()

    row = connection.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    connection.close()

    return row_to_message(row) if row else None


def toggle_reaction(
    message_id: int,
    sender: str,
    reaction: str,
) -> dict[str, Any] | None:
    allowed_reactions = {"heart", "smile", "fire"}

    if reaction not in allowed_reactions:
        return None

    connection = db_connection()

    row = connection.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    if not row:
        connection.close()
        return None

    reactions = decode_json(row["reactions"], {})
    users = list(reactions.get(reaction, []))

    if sender in users:
        users.remove(sender)
    else:
        users.append(sender)

    reactions[reaction] = users

    connection.execute(
        """
        UPDATE messages
        SET reactions = ?
        WHERE id = ?
        """,
        (json.dumps(reactions), message_id),
    )

    connection.commit()

    updated = connection.execute(
        "SELECT * FROM messages WHERE id = ?",
        (message_id,),
    ).fetchone()

    connection.close()

    return row_to_message(updated)


def read_shared_state() -> dict[str, str]:
    connection = db_connection()

    rows = connection.execute(
        "SELECT key, value FROM shared_state"
    ).fetchall()

    connection.close()

    return {row["key"]: row["value"] for row in rows}


def save_shared_state(key: str, value: str) -> dict[str, str]:
    connection = db_connection()

    connection.execute(
        """
        INSERT INTO shared_state (key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value
        """,
        (key, value[:500]),
    )

    connection.commit()
    connection.close()

    return read_shared_state()


def get_ice_servers() -> list[dict[str, Any]]:
    raw = os.getenv("ICE_SERVERS_JSON", "").strip()

    if not raw:
        return DEFAULT_ICE_SERVERS

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass

    return DEFAULT_ICE_SERVERS


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, name: str) -> None:
        await websocket.accept()
        self.connections[websocket] = name

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.pop(websocket, None)

    def online_names(self) -> list[str]:
        return sorted(set(self.connections.values()))

    async def broadcast(
        self,
        payload: dict[str, Any],
        exclude: WebSocket | None = None,
    ) -> None:
        dead_connections: list[WebSocket] = []

        for websocket in list(self.connections):
            if websocket is exclude:
                continue

            try:
                await websocket.send_json(payload)
            except Exception:
                dead_connections.append(websocket)

        for websocket in dead_connections:
            self.disconnect(websocket)


init_database()
manager = ConnectionManager()
app = FastAPI(title="Private Chat")


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML, headers={"Cache-Control": "no-store"})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me")
async def api_me(request: Request) -> dict[str, Any]:
    session = read_session(request.cookies.get(SESSION_COOKIE))

    if not session:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "name": session["name"],
    }


@app.post("/api/login")
async def api_login(request: Request) -> JSONResponse:
    payload = await request.json()

    password = str(payload.get("password", ""))
    name = clean_name(payload.get("name", ""))

    if not verify_password(password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    response = JSONResponse(
        {
            "ok": True,
            "name": name,
        }
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session(name),
        max_age=SESSION_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )

    return response


@app.post("/api/logout")
async def api_logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/messages")
async def api_messages(request: Request) -> dict[str, Any]:
    current_user(request)
    return {"messages": list_messages()}


@app.get("/api/state")
async def api_state(request: Request) -> dict[str, Any]:
    current_user(request)
    return {"state": read_shared_state()}


@app.post("/api/state")
async def api_state_update(request: Request) -> dict[str, Any]:
    user = current_user(request)
    payload = await request.json()

    key = str(payload.get("key", ""))
    value = str(payload.get("value", ""))

    if key not in {"intention", "focus_until"}:
        raise HTTPException(status_code=400, detail="Unsupported state key")

    shared_state = save_shared_state(key, value)

    await manager.broadcast(
        {
            "type": "shared_state",
            "state": shared_state,
            "updated_by": user,
        }
    )

    return {"state": shared_state}


@app.get("/api/rtc-config")
async def api_rtc_config(request: Request) -> dict[str, Any]:
    current_user(request)
    return {"iceServers": get_ice_servers()}


@app.post("/api/upload")
async def api_upload(
    request: Request,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    current_user(request)

    filename = Path(file.filename or "upload.bin").name
    content_type = file.content_type or "application/octet-stream"

    allowed_prefixes = (
        "image/",
        "audio/",
        "video/",
    )

    allowed_exact = {
        "application/pdf",
        "text/plain",
        "application/zip",
    }

    if not (
        content_type.startswith(allowed_prefixes)
        or content_type in allowed_exact
    ):
        raise HTTPException(
            status_code=415,
            detail="This file type is not supported",
        )

    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail="File is too large",
        )

    stored_name = f"{uuid.uuid4().hex}{Path(filename).suffix.lower()}"
    destination = UPLOAD_DIR / stored_name
    destination.write_bytes(content)

    return {
        "url": f"/media/{stored_name}",
        "name": filename,
        "content_type": content_type,
        "size": len(content),
    }


@app.get("/media/{filename}")
async def media(filename: str, request: Request) -> FileResponse:
    current_user(request)

    safe_name = Path(filename).name
    path = UPLOAD_DIR / safe_name

    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Media not found")

    return FileResponse(path)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    session_token = get_cookie(
        websocket.headers.get("cookie"),
        SESSION_COOKIE,
    )
    session = read_session(session_token)

    if not session:
        await websocket.close(code=1008)
        return

    user = session["name"]

    await manager.connect(websocket, user)

    await websocket.send_json(
        {
            "type": "ready",
            "me": user,
            "messages": list_messages(),
            "state": read_shared_state(),
            "online": manager.online_names(),
        }
    )

    await manager.broadcast(
        {
            "type": "presence",
            "online": manager.online_names(),
        }
    )

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")

            if message_type == "message":
                body = str(data.get("body", "")).strip()
                kind = str(data.get("kind", "text"))
                meta = data.get("meta") or {}
                reply_to = data.get("reply_to")

                if not body and kind == "text":
                    continue

                if kind not in {"text", "attachment"}:
                    kind = "text"

                if reply_to is not None:
                    try:
                        reply_to = int(reply_to)
                    except (TypeError, ValueError):
                        reply_to = None

                message = insert_message(
                    sender=user,
                    body=body[:4000],
                    kind=kind,
                    meta=meta if isinstance(meta, dict) else {},
                    reply_to=reply_to,
                )

                await manager.broadcast(
                    {
                        "type": "message",
                        "message": message,
                    }
                )

            elif message_type == "typing":
                await manager.broadcast(
                    {
                        "type": "typing",
                        "from": user,
                        "active": bool(data.get("active")),
                    },
                    exclude=websocket,
                )

            elif message_type == "reaction":
                try:
                    message_id = int(data.get("message_id"))
                except (TypeError, ValueError):
                    continue

                updated = toggle_reaction(
                    message_id,
                    user,
                    str(data.get("reaction", "")),
                )

                if updated:
                    await manager.broadcast(
                        {
                            "type": "message_updated",
                            "message": updated,
                        }
                    )

            elif message_type == "edit":
                try:
                    message_id = int(data.get("message_id"))
                except (TypeError, ValueError):
                    continue

                updated = edit_message(
                    message_id,
                    user,
                    str(data.get("body", "")).strip(),
                )

                if updated:
                    await manager.broadcast(
                        {
                            "type": "message_updated",
                            "message": updated,
                        }
                    )

            elif message_type == "delete":
                try:
                    message_id = int(data.get("message_id"))
                except (TypeError, ValueError):
                    continue

                updated = delete_message(message_id, user)

                if updated:
                    await manager.broadcast(
                        {
                            "type": "message_updated",
                            "message": updated,
                        }
                    )

            elif message_type == "read":
                await manager.broadcast(
                    {
                        "type": "read",
                        "from": user,
                        "message_id": data.get("message_id"),
                    },
                    exclude=websocket,
                )

            elif message_type in {
                "call-invite",
                "call-accepted",
                "call-rejected",
                "call-offer",
                "call-answer",
                "ice-candidate",
                "call-ended",
            }:
                await manager.broadcast(
                    {
                        "type": message_type,
                        "from": user,
                        "payload": data.get("payload"),
                    },
                    exclude=websocket,
                )

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)

        await manager.broadcast(
            {
                "type": "presence",
                "online": manager.online_names(),
            }
        )


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Twofold Private Chat</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        :root {
            --ink: #20252b;
            --muted: #89929c;
            --line: rgba(32, 37, 43, .11);
            --paper: #f5f1ea;
            --paper-2: #fffdf9;
            --coral: #e66b50;
            --coral-dark: #bd4c37;
            --mint: #b8d8cb;
            --blue: #c8d8e8;
            --yellow: #f3ce73;
            --shadow: 0 24px 80px rgba(50, 42, 34, .12);
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            color: var(--ink);
            background:
                radial-gradient(circle at 12% 14%, rgba(230, 107, 80, .22), transparent 28%),
                radial-gradient(circle at 92% 85%, rgba(184, 216, 203, .42), transparent 30%),
                linear-gradient(135deg, #f8f4ee, #e9e3da);
            font-family: "DM Sans", sans-serif;
        }

        button,
        input,
        textarea {
            font: inherit;
        }

        button {
            border: 0;
            cursor: pointer;
        }

        .hidden {
            display: none !important;
        }

        .gate {
            display: grid;
            place-items: center;
            min-height: 100vh;
            padding: 24px;
        }

        .gate-card {
            width: min(460px, 100%);
            padding: 42px;
            border: 1px solid rgba(255,255,255,.72);
            border-radius: 32px;
            background: rgba(255,253,249,.78);
            box-shadow: var(--shadow);
            backdrop-filter: blur(20px);
        }

        .eyebrow {
            color: var(--coral-dark);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: .19em;
            text-transform: uppercase;
        }

        h1,
        h2,
        h3,
        p {
            margin-top: 0;
        }

        .gate-card h1 {
            margin: 16px 0 12px;
            font-family: "Space Grotesk", sans-serif;
            font-size: clamp(34px, 7vw, 56px);
            line-height: .95;
            letter-spacing: -.07em;
        }

        .gate-card p {
            color: var(--muted);
            line-height: 1.6;
        }

        .field {
            display: grid;
            gap: 8px;
            margin-top: 18px;
        }

        .field label {
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: .08em;
            text-transform: uppercase;
        }

        .field input,
        .field textarea,
        .search {
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 14px;
            outline: none;
            background: rgba(255,255,255,.7);
            color: var(--ink);
            padding: 13px 14px;
            transition: border-color .2s, box-shadow .2s;
        }

        .field input:focus,
        .field textarea:focus,
        .search:focus {
            border-color: var(--coral);
            box-shadow: 0 0 0 4px rgba(230,107,80,.12);
        }

        .primary {
            width: 100%;
            margin-top: 22px;
            border-radius: 14px;
            background: var(--ink);
            color: white;
            padding: 14px 18px;
            font-weight: 700;
            transition: transform .2s, background .2s;
        }

        .primary:hover {
            background: var(--coral-dark);
            transform: translateY(-2px);
        }

        .error {
            min-height: 20px;
            margin-top: 12px;
            color: var(--coral-dark);
            font-size: 13px;
        }

        .app {
            min-height: 100vh;
            padding: 18px;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            width: min(1480px, 100%);
            margin: 0 auto 16px;
            padding: 4px 6px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-mark {
            display: grid;
            place-items: center;
            width: 38px;
            height: 38px;
            border-radius: 14px;
            background: var(--coral);
            color: white;
            font-family: "Space Grotesk", sans-serif;
            font-weight: 700;
            transform: rotate(-6deg);
        }

        .brand-name {
            font-family: "Space Grotesk", sans-serif;
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -.04em;
        }

        .brand-subtitle {
            color: var(--muted);
            font-size: 12px;
        }

        .top-actions {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pill,
        .ghost,
        .danger {
            border: 1px solid var(--line);
            border-radius: 999px;
            background: rgba(255,255,255,.62);
            color: var(--ink);
            padding: 9px 13px;
            font-size: 12px;
            font-weight: 700;
        }

        .pill.active {
            border-color: var(--coral);
            background: var(--coral);
            color: white;
        }

        .ghost:hover {
            border-color: var(--coral);
        }

        .danger {
            color: var(--coral-dark);
        }

        .workspace {
            display: grid;
            grid-template-columns: 230px minmax(0, 1fr) 275px;
            width: min(1480px, 100%);
            min-height: calc(100vh - 92px);
            margin: 0 auto;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,.74);
            border-radius: 28px;
            background: rgba(255,253,249,.74);
            box-shadow: var(--shadow);
            backdrop-filter: blur(18px);
        }

        .side-panel {
            padding: 24px 18px;
            background: rgba(237,232,224,.46);
        }

        .left-panel {
            border-right: 1px solid var(--line);
        }

        .right-panel {
            border-left: 1px solid var(--line);
        }

        .side-title {
            margin: 0 0 22px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: .14em;
            text-transform: uppercase;
        }

        .room-card {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding: 12px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: rgba(255,255,255,.62);
        }

        .avatar {
            display: grid;
            flex: 0 0 auto;
            place-items: center;
            width: 42px;
            height: 42px;
            border-radius: 15px;
            background: var(--mint);
            font-family: "Space Grotesk", sans-serif;
            font-weight: 700;
        }

        .room-card strong {
            display: block;
            font-size: 14px;
        }

        .room-card small {
            color: var(--muted);
            font-size: 11px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            margin: 4px 0;
            border-radius: 12px;
            background: transparent;
            color: var(--ink);
            padding: 11px 12px;
            text-align: left;
            font-size: 13px;
        }

        .nav-item.active,
        .nav-item:hover {
            background: rgba(230,107,80,.12);
            color: var(--coral-dark);
        }

        .focus-card {
            margin-top: 32px;
            padding: 16px;
            border-radius: 19px;
            background: var(--ink);
            color: white;
        }

        .focus-card h3 {
            margin-bottom: 8px;
            font-family: "Space Grotesk", sans-serif;
            font-size: 17px;
        }

        .focus-card p {
            color: rgba(255,255,255,.65);
            font-size: 12px;
            line-height: 1.5;
        }

        .focus-card button {
            width: 100%;
            border-radius: 10px;
            background: var(--yellow);
            color: var(--ink);
            padding: 10px;
            font-size: 12px;
            font-weight: 700;
        }

        .chat-panel {
            display: flex;
            min-width: 0;
            flex-direction: column;
            background: rgba(255,253,249,.72);
        }

        .chat-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 24px 28px 18px;
            border-bottom: 1px solid var(--line);
        }

        .chat-header h1 {
            margin: 0;
            font-family: "Space Grotesk", sans-serif;
            font-size: 28px;
            letter-spacing: -.06em;
        }

        .presence {
            display: flex;
            align-items: center;
            gap: 7px;
            margin-top: 5px;
            color: var(--muted);
            font-size: 12px;
        }

        .presence-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--coral);
        }

        .presence-dot.online {
            background: #54a97e;
        }

        .header-buttons {
            display: flex;
            gap: 8px;
        }

        .icon-button {
            display: grid;
            place-items: center;
            width: 42px;
            height: 42px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: white;
            color: var(--ink);
            font-size: 18px;
        }

        .icon-button:hover {
            border-color: var(--coral);
            color: var(--coral-dark);
        }

        .search-wrap {
            padding: 14px 28px 0;
        }

        .messages {
            display: flex;
            flex: 1;
            min-height: 300px;
            flex-direction: column;
            gap: 14px;
            overflow-y: auto;
            padding: 24px 28px;
        }

        .empty {
            display: grid;
            flex: 1;
            place-items: center;
            min-height: 280px;
            color: var(--muted);
            text-align: center;
        }

        .empty strong {
            display: block;
            margin-bottom: 7px;
            color: var(--ink);
            font-family: "Space Grotesk", sans-serif;
            font-size: 24px;
        }

        .message {
            position: relative;
            max-width: min(74%, 580px);
            animation: rise .22s ease-out;
        }

        .message.mine {
            align-self: flex-end;
        }

        .message.theirs {
            align-self: flex-start;
        }

        .message-author {
            margin: 0 0 5px 4px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 700;
        }

        .message.mine .message-author {
            text-align: right;
            margin-right: 4px;
        }

        .bubble {
            padding: 13px 15px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: white;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .message.mine .bubble {
            border-color: transparent;
            border-bottom-right-radius: 5px;
            background: var(--ink);
            color: white;
        }

        .message.theirs .bubble {
            border-bottom-left-radius: 5px;
        }

        .reply-preview {
            margin-bottom: 8px;
            border-left: 3px solid var(--coral);
            color: var(--muted);
            padding-left: 9px;
            font-size: 11px;
        }

        .message.mine .reply-preview {
            color: rgba(255,255,255,.65);
        }

        .attachment-image {
            display: block;
            width: min(320px, 100%);
            border-radius: 12px;
        }

        .attachment-link {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            color: inherit;
            font-weight: 700;
        }

        .message-meta {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 7px;
            margin-top: 5px;
            color: var(--muted);
            font-size: 10px;
        }

        .message-tools {
            display: flex;
            gap: 4px;
            margin-top: 6px;
            opacity: 0;
            pointer-events: none;
            transition: opacity .2s;
        }

        .message:hover .message-tools,
        .message:focus-within .message-tools {
            opacity: 1;
            pointer-events: auto;
        }

        .message.mine .message-tools {
            justify-content: flex-end;
        }

        .message-tool {
            border: 1px solid var(--line);
            border-radius: 8px;
            background: white;
            color: var(--muted);
            padding: 5px 7px;
            font-size: 10px;
        }

        .message-tool:hover {
            color: var(--coral-dark);
        }

        .reactions {
            display: flex;
            gap: 4px;
            margin-top: 6px;
        }

        .reaction {
            border: 1px solid var(--line);
            border-radius: 999px;
            background: rgba(255,255,255,.8);
            color: var(--muted);
            padding: 4px 7px;
            font-size: 10px;
        }

        .composer-wrap {
            padding: 15px 28px 24px;
            border-top: 1px solid var(--line);
        }

        .replying {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 9px;
            border-radius: 10px;
            background: rgba(230,107,80,.09);
            color: var(--coral-dark);
            padding: 9px 11px;
            font-size: 12px;
        }

        .compose {
            display: flex;
            align-items: flex-end;
            gap: 9px;
        }

        .compose textarea {
            flex: 1;
            min-height: 48px;
            max-height: 140px;
            resize: vertical;
            border: 1px solid var(--line);
            border-radius: 15px;
            outline: none;
            background: white;
            color: var(--ink);
            padding: 14px;
        }

        .compose textarea:focus {
            border-color: var(--coral);
        }

        .compose-button {
            display: grid;
            place-items: center;
            width: 48px;
            height: 48px;
            border-radius: 15px;
            background: var(--coral);
            color: white;
            font-weight: 700;
        }

        .compose-button:hover {
            background: var(--coral-dark);
        }

        .composer-tools {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-top: 8px;
        }

        .composer-tools button,
        .composer-tools label {
            border: 1px solid var(--line);
            border-radius: 9px;
            background: rgba(255,255,255,.7);
            color: var(--muted);
            padding: 6px 9px;
            font-size: 11px;
            cursor: pointer;
        }

        .file-name {
            overflow: hidden;
            color: var(--coral-dark);
            font-size: 11px;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .right-panel h2 {
            margin-bottom: 6px;
            font-family: "Space Grotesk", sans-serif;
            font-size: 22px;
            letter-spacing: -.04em;
        }

        .right-panel > p {
            color: var(--muted);
            font-size: 12px;
            line-height: 1.6;
        }

        .intention-card {
            margin-top: 24px;
            padding: 15px;
            border-radius: 18px;
            background: var(--blue);
        }

        .intention-card label {
            display: block;
            margin-bottom: 9px;
            color: var(--ink);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: .08em;
            text-transform: uppercase;
        }

        .intention-card textarea {
            min-height: 80px;
            background: rgba(255,255,255,.55);
        }

        .small-button {
            margin-top: 8px;
            border-radius: 9px;
            background: var(--ink);
            color: white;
            padding: 8px 10px;
            font-size: 11px;
            font-weight: 700;
        }

        .status-card {
            display: grid;
            gap: 11px;
            margin-top: 16px;
            padding: 15px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: rgba(255,255,255,.55);
        }

        .status-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            font-size: 12px;
        }

        .status-row span {
            color: var(--muted);
        }

        .call-panel {
            position: fixed;
            right: 28px;
            bottom: 28px;
            z-index: 10;
            width: min(440px, calc(100vw - 30px));
            overflow: hidden;
            border: 1px solid rgba(255,255,255,.78);
            border-radius: 23px;
            background: #171b20;
            box-shadow: 0 25px 90px rgba(0,0,0,.28);
        }

        .call-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 16px;
            color: white;
        }

        .call-status {
            color: rgba(255,255,255,.58);
            font-size: 11px;
        }

        .video-stage {
            position: relative;
            aspect-ratio: 16 / 10;
            overflow: hidden;
            background: #0f1114;
        }

        #remote-video {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        #local-video {
            position: absolute;
            right: 12px;
            bottom: 12px;
            width: 120px;
            aspect-ratio: 4 / 3;
            border: 2px solid rgba(255,255,255,.85);
            border-radius: 12px;
            background: #2b3037;
            object-fit: cover;
        }

        .call-actions {
            display: flex;
            justify-content: center;
            gap: 8px;
            padding: 13px;
        }

        .call-actions button {
            min-width: 78px;
            border-radius: 10px;
            background: #2d343d;
            color: white;
            padding: 9px 11px;
            font-size: 11px;
        }

        .call-actions button:hover {
            background: #46515d;
        }

        .call-actions .hangup {
            background: var(--coral-dark);
        }

        .incoming {
            position: fixed;
            top: 24px;
            right: 24px;
            z-index: 20;
            width: min(340px, calc(100vw - 30px));
            padding: 17px;
            border-radius: 18px;
            background: var(--ink);
            color: white;
            box-shadow: var(--shadow);
        }

        .incoming strong {
            display: block;
            margin-bottom: 5px;
            font-family: "Space Grotesk", sans-serif;
        }

        .incoming p {
            margin-bottom: 13px;
            color: rgba(255,255,255,.65);
            font-size: 12px;
        }

        .incoming-actions {
            display: flex;
            gap: 8px;
        }

        .incoming-actions button {
            flex: 1;
            border-radius: 9px;
            padding: 9px;
            font-size: 12px;
            font-weight: 700;
        }

        .accept {
            background: var(--mint);
            color: var(--ink);
        }

        .reject {
            background: rgba(255,255,255,.12);
            color: white;
        }

        .toast {
            position: fixed;
            left: 50%;
            bottom: 25px;
            z-index: 30;
            transform: translate(-50%, 20px);
            border-radius: 999px;
            background: var(--ink);
            color: white;
            padding: 11px 16px;
            opacity: 0;
            pointer-events: none;
            transition: opacity .2s, transform .2s;
            font-size: 12px;
        }

        .toast.visible {
            opacity: 1;
            transform: translate(-50%, 0);
        }

        .focus-mode .left-panel,
        .focus-mode .right-panel {
            display: none;
        }

        .focus-mode .workspace {
            grid-template-columns: minmax(0, 1fr);
        }

        @keyframes rise {
            from {
                opacity: 0;
                transform: translateY(7px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @media (max-width: 1050px) {
            .workspace {
                grid-template-columns: 190px minmax(0, 1fr);
            }

            .right-panel {
                display: none;
            }
        }

        @media (max-width: 720px) {
            .app {
                padding: 8px;
            }

            .topbar {
                margin-bottom: 9px;
            }

            .brand-subtitle,
            .top-actions .ghost {
                display: none;
            }

            .workspace {
                grid-template-columns: minmax(0, 1fr);
                min-height: calc(100vh - 75px);
                border-radius: 20px;
            }

            .left-panel {
                display: none;
            }

            .chat-header,
            .search-wrap,
            .messages,
            .composer-wrap {
                padding-left: 16px;
                padding-right: 16px;
            }

            .chat-header h1 {
                font-size: 24px;
            }

            .message {
                max-width: 88%;
            }

            .message-tools {
                opacity: 1;
                pointer-events: auto;
            }

            .gate-card {
                padding: 28px;
                border-radius: 24px;
            }

            .call-panel {
                right: 15px;
                bottom: 15px;
            }
        }
    </style>
</head>
<body>
    <section id="gate" class="gate">
        <div class="gate-card">
            <div class="eyebrow">Private room / no feed</div>
            <h1>Just us,<br>without the scroll.</h1>
            <p>
                A quiet private space for messages, memories, focus sessions,
                and calls. No reels. No recommendations. No distraction loop.
            </p>

            <form id="login-form">
                <div class="field">
                    <label for="name">Your name</label>
                    <input id="name" name="name" maxlength="32" placeholder="Your name" required>
                </div>

                <div class="field">
                    <label for="password">Room password</label>
                    <input id="password" name="password" type="password" placeholder="Enter password" required>
                </div>

                <button class="primary" type="submit">Enter our room</button>
                <div id="login-error" class="error"></div>
            </form>
        </div>
    </section>

    <section id="app" class="app hidden">
        <header class="topbar">
            <div class="brand">
                <div class="brand-mark">2</div>
                <div>
                    <div class="brand-name">Twofold</div>
                    <div class="brand-subtitle">A private room for two</div>
                </div>
            </div>

            <div class="top-actions">
                <button id="focus-toggle" class="pill">Focus mode</button>
                <button id="logout" class="ghost">Leave room</button>
            </div>
        </header>

        <main class="workspace">
            <aside class="side-panel left-panel">
                <div class="side-title">Room</div>

                <div class="room-card">
                    <div class="avatar">U</div>
                    <div>
                        <strong id="sidebar-name">You</strong>
                        <small>Private access</small>
                    </div>
                </div>

                <button class="nav-item active">
                    <span>Conversation</span>
                    <span>01</span>
                </button>

                <button id="prompt-button" class="nav-item">
                    <span>Send a prompt</span>
                    <span>+</span>
                </button>

                <button id="call-sidebar-button" class="nav-item">
                    <span>Start video call</span>
                    <span>></span>
                </button>

                <div class="focus-card">
                    <h3>Focus lane</h3>
                    <p>
                        Start a quiet 25-minute session. Your girlfriend can see
                        that you are working, without needing to interrupt.
                    </p>
                    <button id="focus-start">Start 25 minutes</button>
                </div>
            </aside>

            <section class="chat-panel">
                <div class="chat-header">
                    <div>
                        <h1>Our conversation</h1>
                        <div class="presence">
                            <span id="presence-dot" class="presence-dot"></span>
                            <span id="presence-text">Connecting...</span>
                        </div>
                    </div>

                    <div class="header-buttons">
                        <button id="call-button" class="icon-button" title="Video call">Call</button>
                    </div>
                </div>

                <div class="search-wrap">
                    <input id="search" class="search" placeholder="Search our messages">
                </div>

                <div id="messages" class="messages">
                    <div class="empty">
                        <div>
                            <strong>Make this room yours.</strong>
                            Send the first message.
                        </div>
                    </div>
                </div>

                <div class="composer-wrap">
                    <div id="replying" class="replying hidden">
                        <span id="replying-text"></span>
                        <button id="cancel-reply" class="ghost">Cancel</button>
                    </div>

                    <form id="compose-form">
                        <div class="compose">
                            <textarea id="message-input" rows="1" maxlength="4000" placeholder="Write something real..."></textarea>
                            <button class="compose-button" type="submit">Send</button>
                        </div>

                        <div class="composer-tools">
                            <label for="file-input">Attach</label>
                            <input id="file-input" type="file" hidden accept="image/*,audio/*,video/*,.pdf,.txt,.zip">
                            <span id="file-name" class="file-name"></span>
                            <button id="heart-button" type="button">Add heart</button>
                        </div>
                    </form>
                </div>
            </section>

            <aside class="side-panel right-panel">
                <div class="side-title">Shared space</div>
                <h2>Keep the important things here.</h2>
                <p>
                    Use this room for messages and intentions, not endless
                    scrolling. The design intentionally has no public feed.
                </p>

                <div class="intention-card">
                    <label for="intention">Today's shared intention</label>
                    <textarea id="intention" maxlength="500" placeholder="What are we protecting time for today?"></textarea>
                    <button id="save-intention" class="small-button">Save intention</button>
                </div>

                <div class="status-card">
                    <div class="status-row">
                        <span>Connection</span>
                        <strong id="connection-status">Offline</strong>
                    </div>
                    <div class="status-row">
                        <span>Focus status</span>
                        <strong id="shared-focus-status">Open</strong>
                    </div>
                    <div class="status-row">
                        <span>Room type</span>
                        <strong>Private</strong>
                    </div>
                </div>
            </aside>
        </main>
    </section>

    <section id="incoming-call" class="incoming hidden">
        <strong id="incoming-name">Incoming call</strong>
        <p>There is a video call waiting in your private room.</p>
        <div class="incoming-actions">
            <button id="accept-call" class="accept">Accept</button>
            <button id="reject-call" class="reject">Decline</button>
        </div>
    </section>

    <section id="call-panel" class="call-panel hidden">
        <div class="call-header">
            <div>
                <strong>Private video call</strong>
                <div id="call-status" class="call-status">Connecting...</div>
            </div>
            <button id="close-call" class="ghost">Close</button>
        </div>

        <div class="video-stage">
            <video id="remote-video" autoplay playsinline></video>
            <video id="local-video" autoplay muted playsinline></video>
        </div>

        <div class="call-actions">
            <button id="mute-call">Mute</button>
            <button id="camera-call">Camera</button>
            <button id="screen-call">Share screen</button>
            <button id="hangup-call" class="hangup">Hang up</button>
        </div>
    </section>

    <div id="toast" class="toast"></div>

    <script>
        const state = {
            me: "",
            socket: null,
            messages: [],
            iceServers: [],
            replyingTo: null,
            pendingFile: null,
            peer: null,
            localStream: null,
            pendingOffer: null,
            pendingCandidates: [],
            acceptedCall: false,
            callActive: false,
            reconnectTimer: null,
            focusUntil: null
        };

        const $ = (selector) => document.querySelector(selector);

        function showToast(message) {
            const toast = $("#toast");
            toast.textContent = message;
            toast.classList.add("visible");

            window.clearTimeout(showToast.timer);
            showToast.timer = window.setTimeout(() => {
                toast.classList.remove("visible");
            }, 2600);
        }

        async function api(url, options = {}) {
            const response = await fetch(url, {
                credentials: "same-origin",
                ...options
            });

            let data = {};
            try {
                data = await response.json();
            } catch {
                data = {};
            }

            if (!response.ok) {
                throw new Error(data.detail || "Request failed");
            }

            return data;
        }

        function sendSocket(payload) {
            if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
                showToast("The room is reconnecting.");
                return false;
            }

            state.socket.send(JSON.stringify(payload));
            return true;
        }

        function formatTime(value) {
            return new Date(value).toLocaleTimeString([], {
                hour: "numeric",
                minute: "2-digit"
            });
        }

        function findMessage(id) {
            return state.messages.find((message) => message.id === id);
        }

        function renderMessage(message) {
            const article = document.createElement("article");
            const mine = message.sender === state.me;

            article.className = `message ${mine ? "mine" : "theirs"}`;
            article.dataset.id = message.id;

            const author = document.createElement("div");
            author.className = "message-author";
            author.textContent = mine ? "You" : message.sender;

            const bubble = document.createElement("div");
            bubble.className = "bubble";

            if (message.reply_to) {
                const replied = findMessage(message.reply_to);

                if (replied) {
                    const reply = document.createElement("div");
                    reply.className = "reply-preview";
                    reply.textContent = `Replying to ${replied.sender}: ${replied.body.slice(0, 90)}`;
                    bubble.appendChild(reply);
                }
            }

            if (message.deleted) {
                const deleted = document.createElement("em");
                deleted.textContent = "Message deleted";
                bubble.appendChild(deleted);
            } else if (message.kind === "attachment") {
                const meta = message.meta || {};

                if ((meta.content_type || "").startsWith("image/")) {
                    const image = document.createElement("img");
                    image.className = "attachment-image";
                    image.src = meta.url;
                    image.alt = meta.name || "Attached image";
                    bubble.appendChild(image);
                } else {
                    const link = document.createElement("a");
                    link.className = "attachment-link";
                    link.href = meta.url;
                    link.target = "_blank";
                    link.rel = "noopener";
                    link.textContent = `Open ${meta.name || "attachment"}`;
                    bubble.appendChild(link);
                }

                if (message.body) {
                    const caption = document.createElement("div");
                    caption.style.marginTop = "9px";
                    caption.textContent = message.body;
                    bubble.appendChild(caption);
                }
            } else {
                const text = document.createElement("div");
                text.textContent = message.body;
                bubble.appendChild(text);
            }

            const meta = document.createElement("div");
            meta.className = "message-meta";
            meta.textContent = `${formatTime(message.created_at)}${message.edited ? " · edited" : ""}`;

            const tools = document.createElement("div");
            tools.className = "message-tools";

            const replyButton = document.createElement("button");
            replyButton.className = "message-tool";
            replyButton.dataset.action = "reply";
            replyButton.textContent = "Reply";
            tools.appendChild(replyButton);

            if (mine && !message.deleted) {
                const editButton = document.createElement("button");
                editButton.className = "message-tool";
                editButton.dataset.action = "edit";
                editButton.textContent = "Edit";
                tools.appendChild(editButton);

                const deleteButton = document.createElement("button");
                deleteButton.className = "message-tool";
                deleteButton.dataset.action = "delete";
                deleteButton.textContent = "Delete";
                tools.appendChild(deleteButton);
            }

            const reactionButtons = document.createElement("div");
            reactionButtons.className = "message-tools";

            for (const reaction of ["heart", "smile", "fire"]) {
                const reactionButton = document.createElement("button");
                reactionButton.className = "message-tool";
                reactionButton.dataset.action = "react";
                reactionButton.dataset.reaction = reaction;
                reactionButton.textContent = reaction;
                reactionButtons.appendChild(reactionButton);
            }

            const reactions = document.createElement("div");
            reactions.className = "reactions";

            for (const [reaction, users] of Object.entries(message.reactions || {})) {
                if (!users.length) continue;

                const reactionBadge = document.createElement("span");
                reactionBadge.className = "reaction";
                reactionBadge.textContent = `${reaction} ${users.length}`;
                reactions.appendChild(reactionBadge);
            }

            article.appendChild(author);
            article.appendChild(bubble);
            article.appendChild(meta);

            if (reactions.children.length) {
                article.appendChild(reactions);
            }

            article.appendChild(tools);
            article.appendChild(reactionButtons);

            return article;
        }

        function renderMessages(scrollToBottom = false) {
            const container = $("#messages");
            const query = $("#search").value.trim().toLowerCase();

            container.innerHTML = "";

            const filtered = state.messages.filter((message) => {
                if (!query) return true;

                const body = `${message.body} ${message.sender}`.toLowerCase();
                return body.includes(query);
            });

            if (!filtered.length) {
                const empty = document.createElement("div");
                empty.className = "empty";

                const inner = document.createElement("div");
                const title = document.createElement("strong");
                title.textContent = query ? "Nothing found." : "Make this room yours.";

                inner.appendChild(title);
                inner.appendChild(
                    document.createTextNode(
                        query ? "Try another search." : "Send the first message."
                    )
                );

                empty.appendChild(inner);
                container.appendChild(empty);
                return;
            }

            for (const message of filtered) {
                container.appendChild(renderMessage(message));
            }

            if (scrollToBottom) {
                container.scrollTop = container.scrollHeight;
            }
        }

        function upsertMessage(message) {
            const index = state.messages.findIndex(
                (item) => item.id === message.id
            );

            if (index === -1) {
                state.messages.push(message);
            } else {
                state.messages[index] = message;
            }

            renderMessages(true);
        }

        function setReply(message) {
            state.replyingTo = message;
            $("#replying-text").textContent =
                `Replying to ${message.sender}: ${message.body.slice(0, 100)}`;
            $("#replying").classList.remove("hidden");
            $("#message-input").focus();
        }

        function clearReply() {
            state.replyingTo = null;
            $("#replying").classList.add("hidden");
        }

        function applySharedState(sharedState) {
            if (Object.prototype.hasOwnProperty.call(sharedState, "intention")) {
                $("#intention").value = sharedState.intention;
            }

            if (sharedState.focus_until) {
                const date = new Date(sharedState.focus_until);

                if (date > new Date()) {
                    state.focusUntil = date;
                    $("#shared-focus-status").textContent = "Focus active";
                } else {
                    $("#shared-focus-status").textContent = "Open";
                }
            }
        }

        function updatePresence(online) {
            const names = online || [];
            const otherOnline = names.some((name) => name !== state.me);

            $("#presence-dot").classList.toggle("online", otherOnline);
            $("#presence-text").textContent = otherOnline
                ? "Online now"
                : "Waiting for your person";

            $("#connection-status").textContent = state.socket?.readyState === WebSocket.OPEN
                ? "Connected"
                : "Offline";
        }

        function connectSocket() {
            if (state.socket && state.socket.readyState === WebSocket.OPEN) {
                return;
            }

            const protocol = location.protocol === "https:" ? "wss" : "ws";
            state.socket = new WebSocket(`${protocol}://${location.host}/ws`);

            state.socket.addEventListener("open", () => {
                $("#connection-status").textContent = "Connected";
                showToast("Private room connected.");
            });

            state.socket.addEventListener("close", () => {
                $("#connection-status").textContent = "Offline";
                $("#presence-text").textContent = "Reconnecting...";

                window.clearTimeout(state.reconnectTimer);
                state.reconnectTimer = window.setTimeout(connectSocket, 2500);
            });

            state.socket.addEventListener("message", async (event) => {
                const data = JSON.parse(event.data);

                if (data.type === "ready") {
                    state.me = data.me;
                    state.messages = data.messages || [];
                    applySharedState(data.state || {});
                    renderMessages(true);
                    updatePresence(data.online || []);
                    return;
                }

                if (data.type === "message") {
                    upsertMessage(data.message);
                    return;
                }

                if (data.type === "message_updated") {
                    upsertMessage(data.message);
                    return;
                }

                if (data.type === "presence") {
                    updatePresence(data.online || []);
                    return;
                }

                if (data.type === "typing") {
                    const typing = data.active
                        ? `${data.from} is writing...`
                        : "Connected";

                    $("#presence-text").textContent = typing;
                    return;
                }

                if (data.type === "shared_state") {
                    applySharedState(data.state || {});
                    return;
                }

                if (data.type === "call-invite") {
                    $("#incoming-name").textContent = `${data.from} is calling`;
                    $("#incoming-call").classList.remove("hidden");
                    return;
                }

                if (data.type === "call-accepted") {
                    $("#call-status").textContent = "Waiting for video...";
                    return;
                }

                if (data.type === "call-rejected") {
                    showToast(`${data.from} declined the call.`);
                    endCall(false);
                    return;
                }

                if (data.type === "call-offer") {
                    state.pendingOffer = data.payload;

                    if (state.acceptedCall) {
                        await applyPendingOffer();
                    }

                    return;
                }

                if (data.type === "call-answer") {
                    if (!state.peer) return;

                    await state.peer.setRemoteDescription(
                        new RTCSessionDescription(data.payload)
                    );

                    await flushCandidates();
                    $("#call-status").textContent = "Call connected";
                    return;
                }

                if (data.type === "ice-candidate") {
                    if (!data.payload) return;

                    if (!state.peer || !state.peer.remoteDescription) {
                        state.pendingCandidates.push(data.payload);
                    } else {
                        await state.peer.addIceCandidate(
                            new RTCIceCandidate(data.payload)
                        );
                    }

                    return;
                }

                if (data.type === "call-ended") {
                    showToast(`${data.from} ended the call.`);
                    endCall(false);
                }
            });
        }

        async function boot() {
            const me = await api("/api/me");

            if (!me.authenticated) {
                $("#gate").classList.remove("hidden");
                $("#app").classList.add("hidden");
                return;
            }

            state.me = me.name;
            $("#sidebar-name").textContent = me.name;
            $("#gate").classList.add("hidden");
            $("#app").classList.remove("hidden");

            try {
                const rtc = await api("/api/rtc-config");
                state.iceServers = rtc.iceServers || [];
            } catch {
                state.iceServers = [];
            }

            connectSocket();
        }

        async function sendMessage(event) {
            event.preventDefault();

            const input = $("#message-input");
            const text = input.value.trim();
            const file = state.pendingFile;

            if (!text && !file) {
                return;
            }

            let kind = "text";
            let body = text;
            let meta = {};

            try {
                if (file) {
                    const form = new FormData();
                    form.append("file", file);

                    const uploaded = await api("/api/upload", {
                        method: "POST",
                        body: form
                    });

                    kind = "attachment";
                    body = text || uploaded.name;
                    meta = uploaded;
                }

                sendSocket({
                    type: "message",
                    body,
                    kind,
                    meta,
                    reply_to: state.replyingTo?.id || null
                });

                input.value = "";
                state.pendingFile = null;
                $("#file-input").value = "";
                $("#file-name").textContent = "";
                clearReply();
            } catch (error) {
                showToast(error.message);
            }
        }

        async function saveIntention() {
            try {
                await api("/api/state", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        key: "intention",
                        value: $("#intention").value.trim()
                    })
                });

                showToast("Shared intention saved.");
            } catch (error) {
                showToast(error.message);
            }
        }

        function startFocus() {
            const until = new Date(Date.now() + 25 * 60 * 1000);
            state.focusUntil = until;

            document.body.classList.add("focus-mode");
            $("#focus-toggle").classList.add("active");
            $("#focus-toggle").textContent = "Exit focus";
            $("#shared-focus-status").textContent = "Focus active";

            sendSocket({
                type: "shared_state",
                state: {
                    focus_until: until.toISOString()
                }
            });

            api("/api/state", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    key: "focus_until",
                    value: until.toISOString()
                })
            }).catch(() => {});

            showToast("Focus mode started for 25 minutes.");
        }

        function toggleFocus() {
            const active = document.body.classList.toggle("focus-mode");
            $("#focus-toggle").classList.toggle("active", active);
            $("#focus-toggle").textContent = active ? "Exit focus" : "Focus mode";
        }

        async function ensureMedia() {
            if (!navigator.mediaDevices?.getUserMedia) {
                throw new Error("Video calls require HTTPS or localhost.");
            }

            if (!state.localStream) {
                state.localStream = await navigator.mediaDevices.getUserMedia({
                    video: true,
                    audio: true
                });
            }

            $("#local-video").srcObject = state.localStream;
        }

        function createPeer() {
            if (state.peer) {
                return state.peer;
            }

            state.peer = new RTCPeerConnection({
                iceServers: state.iceServers
            });

            for (const track of state.localStream.getTracks()) {
                state.peer.addTrack(track, state.localStream);
            }

            state.peer.addEventListener("icecandidate", (event) => {
                if (event.candidate) {
                    sendSocket({
                        type: "ice-candidate",
                        payload: event.candidate
                    });
                }
            });

            state.peer.addEventListener("track", (event) => {
                if (event.streams[0]) {
                    $("#remote-video").srcObject = event.streams[0];
                    $("#call-status").textContent = "Call connected";
                }
            });

            state.peer.addEventListener("connectionstatechange", () => {
                const connectionState = state.peer?.connectionState;

                if (connectionState === "connected") {
                    $("#call-status").textContent = "Call connected";
                }

                if (["failed", "disconnected", "closed"].includes(connectionState)) {
                    $("#call-status").textContent = "Connection ended";
                }
            });

            return state.peer;
        }

        async function flushCandidates() {
            if (!state.peer?.remoteDescription) {
                return;
            }

            const candidates = [...state.pendingCandidates];
            state.pendingCandidates = [];

            for (const candidate of candidates) {
                await state.peer.addIceCandidate(
                    new RTCIceCandidate(candidate)
                );
            }
        }

        function showCallPanel() {
            state.callActive = true;
            $("#call-panel").classList.remove("hidden");
        }

        async function startCall() {
            try {
                await ensureMedia();

                state.acceptedCall = true;
                createPeer();
                showCallPanel();

                sendSocket({
                    type: "call-invite"
                });

                const offer = await state.peer.createOffer();
                await state.peer.setLocalDescription(offer);

                sendSocket({
                    type: "call-offer",
                    payload: state.peer.localDescription
                });

                $("#call-status").textContent = "Calling...";
            } catch (error) {
                showToast(error.message);
                endCall(false);
            }
        }

        async function acceptCall() {
            try {
                state.acceptedCall = true;
                $("#incoming-call").classList.add("hidden");

                await ensureMedia();
                createPeer();
                showCallPanel();

                sendSocket({
                    type: "call-accepted"
                });

                if (state.pendingOffer) {
                    await applyPendingOffer();
                }
            } catch (error) {
                showToast(error.message);
                endCall(false);
            }
        }

        function rejectCall() {
            sendSocket({
                type: "call-rejected"
            });

            $("#incoming-call").classList.add("hidden");
        }

        async function applyPendingOffer() {
            if (!state.pendingOffer || !state.peer) {
                return;
            }

            await state.peer.setRemoteDescription(
                new RTCSessionDescription(state.pendingOffer)
            );

            state.pendingOffer = null;
            await flushCandidates();

            const answer = await state.peer.createAnswer();
            await state.peer.setLocalDescription(answer);

            sendSocket({
                type: "call-answer",
                payload: state.peer.localDescription
            });

            $("#call-status").textContent = "Joining call...";
        }

        function endCall(sendSignal = true) {
            if (sendSignal) {
                sendSocket({
                    type: "call-ended"
                });
            }

            if (state.peer) {
                state.peer.close();
            }

            if (state.localStream) {
                for (const track of state.localStream.getTracks()) {
                    track.stop();
                }
            }

            state.peer = null;
            state.localStream = null;
            state.pendingOffer = null;
            state.pendingCandidates = [];
            state.acceptedCall = false;
            state.callActive = false;

            $("#remote-video").srcObject = null;
            $("#local-video").srcObject = null;
            $("#call-panel").classList.add("hidden");
            $("#incoming-call").classList.add("hidden");
        }

        async function shareScreen() {
            if (!state.peer) {
                showToast("Start a call first.");
                return;
            }

            try {
                const displayStream =
                    await navigator.mediaDevices.getDisplayMedia({
                        video: true
                    });

                const screenTrack = displayStream.getVideoTracks()[0];
                const sender = state.peer
                    .getSenders()
                    .find((item) => item.track?.kind === "video");

                if (sender) {
                    await sender.replaceTrack(screenTrack);
                }

                screenTrack.addEventListener("ended", async () => {
                    const cameraTrack = state.localStream?.getVideoTracks()[0];

                    if (cameraTrack && sender) {
                        await sender.replaceTrack(cameraTrack);
                    }
                });
            } catch {
                showToast("Screen sharing was cancelled.");
            }
        }

        $("#login-form").addEventListener("submit", async (event) => {
            event.preventDefault();

            $("#login-error").textContent = "";

            try {
                await api("/api/login", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        name: $("#name").value,
                        password: $("#password").value
                    })
                });

                await boot();
            } catch (error) {
                $("#login-error").textContent = error.message;
            }
        });

        $("#logout").addEventListener("click", async () => {
            await api("/api/logout", { method: "POST" });
            location.reload();
        });

        $("#compose-form").addEventListener("submit", sendMessage);

        $("#message-input").addEventListener("input", () => {
            sendSocket({
                type: "typing",
                active: true
            });

            window.clearTimeout($("#message-input").typingTimer);
            $("#message-input").typingTimer = window.setTimeout(() => {
                sendSocket({
                    type: "typing",
                    active: false
                });
            }, 800);
        });

        $("#search").addEventListener("input", () => renderMessages(false));

        $("#file-input").addEventListener("change", () => {
            state.pendingFile = $("#file-input").files[0] || null;
            $("#file-name").textContent = state.pendingFile
                ? state.pendingFile.name
                : "";
        });

        $("#heart-button").addEventListener("click", () => {
            const input = $("#message-input");
            input.value += " <3";
            input.focus();
        });

        $("#messages").addEventListener("click", (event) => {
            const button = event.target.closest("[data-action]");

            if (!button) {
                return;
            }

            const article = button.closest(".message");
            const message = findMessage(Number(article.dataset.id));

            if (!message) {
                return;
            }

            const action = button.dataset.action;

            if (action === "reply") {
                setReply(message);
            }

            if (action === "react") {
                sendSocket({
                    type: "reaction",
                    message_id: message.id,
                    reaction: button.dataset.reaction
                });
            }

            if (action === "edit") {
                const nextBody = window.prompt("Edit message", message.body);

                if (nextBody?.trim()) {
                    sendSocket({
                        type: "edit",
                        message_id: message.id,
                        body: nextBody.trim()
                    });
                }
            }

            if (action === "delete") {
                if (window.confirm("Delete this message?")) {
                    sendSocket({
                        type: "delete",
                        message_id: message.id
                    });
                }
            }
        });

        $("#cancel-reply").addEventListener("click", clearReply);
        $("#save-intention").addEventListener("click", saveIntention);
        $("#focus-start").addEventListener("click", startFocus);
        $("#focus-toggle").addEventListener("click", toggleFocus);

        $("#call-button").addEventListener("click", startCall);
        $("#call-sidebar-button").addEventListener("click", startCall);
        $("#accept-call").addEventListener("click", acceptCall);
        $("#reject-call").addEventListener("click", rejectCall);
        $("#close-call").addEventListener("click", () => endCall(true));
        $("#hangup-call").addEventListener("click", () => endCall(true));
        $("#screen-call").addEventListener("click", shareScreen);

        $("#mute-call").addEventListener("click", () => {
            const track = state.localStream?.getAudioTracks()[0];

            if (!track) return;

            track.enabled = !track.enabled;
            $("#mute-call").textContent = track.enabled ? "Mute" : "Unmute";
        });

        $("#camera-call").addEventListener("click", () => {
            const track = state.localStream?.getVideoTracks()[0];

            if (!track) return;

            track.enabled = !track.enabled;
            $("#camera-call").textContent = track.enabled ? "Camera" : "Show camera";
        });

        $("#prompt-button").addEventListener("click", () => {
            $("#message-input").value =
                "What was one good thing about today?";
            $("#message-input").focus();
        });

        window.setInterval(() => {
            if (!state.focusUntil) return;

            if (state.focusUntil <= new Date()) {
                state.focusUntil = null;
                $("#shared-focus-status").textContent = "Open";
                document.body.classList.remove("focus-mode");
                $("#focus-toggle").classList.remove("active");
                $("#focus-toggle").textContent = "Focus mode";
            }
        }, 1000);

        boot().catch(() => {
            $("#gate").classList.remove("hidden");
        });
    </script>
</body>
</html>



