#!/usr/bin/env python3
"""Persistência SQLite para histórico e relatórios do scanner."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'scanner.db')
_db_lock = threading.Lock()


def _db_path() -> str:
    return os.path.abspath(os.getenv('SCANNER_DB_PATH', _DEFAULT_DB))


def init_db() -> None:
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _db_lock, sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                total INTEGER NOT NULL DEFAULT 0,
                ts REAL NOT NULL,
                checks_json TEXT,
                by_type_json TEXT,
                severity_json TEXT,
                report_json TEXT NOT NULL
            )
            """
        )
        conn.execute('CREATE INDEX IF NOT EXISTS idx_scans_url_ts ON scans(url, ts DESC)')
        conn.commit()


def save_scan(
    url: str,
    total: int,
    findings: list[dict[str, Any]],
    *,
    checks: list[str] | None = None,
    by_type: dict[str, int] | None = None,
    severity_breakdown: dict[str, int] | None = None,
    meta: dict[str, Any] | None = None,
) -> int:
    path = _db_path()
    payload = {
        'url': url,
        'findings': findings,
        'total': total,
        'ts': time.time(),
        'by_type': by_type or {},
        'severity_breakdown': severity_breakdown or {},
        'meta': meta or {},
    }
    with _db_lock, sqlite3.connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (url, total, ts, checks_json, by_type_json, severity_json, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                total,
                payload['ts'],
                json.dumps(checks or [], ensure_ascii=False),
                json.dumps(by_type or {}, ensure_ascii=False),
                json.dumps(severity_breakdown or {}, ensure_ascii=False),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_history(limit: int = 50) -> list[dict[str, Any]]:
    path = _db_path()
    if not os.path.isfile(path):
        return []
    with _db_lock, sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT url, total, ts, by_type_json, severity_json FROM scans ORDER BY ts DESC LIMIT ?',
            (max(1, int(limit)),),
        ).fetchall()
    out = []
    for row in rows:
        out.append({
            'url': row['url'],
            'total': row['total'],
            'ts': row['ts'],
            'by_type': json.loads(row['by_type_json'] or '{}'),
            'severity_breakdown': json.loads(row['severity_json'] or '{}'),
        })
    return out


def get_last_report() -> dict[str, Any] | None:
    path = _db_path()
    if not os.path.isfile(path):
        return None
    with _db_lock, sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            'SELECT report_json FROM scans ORDER BY ts DESC LIMIT 1'
        ).fetchone()
    if not row:
        return None
    return json.loads(row['report_json'])


def prune_old(max_rows: int = 200) -> None:
    path = _db_path()
    if not os.path.isfile(path):
        return
    with _db_lock, sqlite3.connect(path) as conn:
        conn.execute(
            """
            DELETE FROM scans WHERE id NOT IN (
                SELECT id FROM scans ORDER BY ts DESC LIMIT ?
            )
            """,
            (max(10, int(max_rows)),),
        )
        conn.commit()
