"""SQLite glabātuve lietotājiem un sesijām (CR-4 prototips)."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

SESSION_LIFETIME = timedelta(hours=8)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL
);
"""


class EmailTaken(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _hash_token(token: str) -> str:
    # Datu bāzē glabā tikai marķiera jaucējvērtību, ne pašu marķieri.
    return hashlib.sha256(token.encode()).hexdigest()


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def create_user(self, email: str, password_hash: str) -> sqlite3.Row:
        created_at = _now().isoformat()
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (email, password_hash, created_at),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise EmailTaken from exc
        return self.get_user(user_id)

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def get_user_by_email(self, email: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        expires_at = (_now() + SESSION_LIFETIME).isoformat()
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_now().isoformat(),))
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (_hash_token(token), user_id, expires_at),
            )
        return token

    def get_session_user(self, token: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
                "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
                (_hash_token(token), _now().isoformat()),
            ).fetchone()

    def delete_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
