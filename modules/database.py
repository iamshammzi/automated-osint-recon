import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = "osint_recon.db"


def init_db(db_path=DB_PATH):
    """Initializes the local SQLite database table for OSINT scan history."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_label TEXT NOT NULL,
            username TEXT,
            domain TEXT,
            accounts_found INTEGER DEFAULT 0,
            platforms_checked INTEGER DEFAULT 0,
            exposure_level TEXT,
            exposure_score INTEGER DEFAULT 0,
            json_path TEXT,
            txt_path TEXT,
            html_path TEXT,
            payload_json TEXT,
            created_utc TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def insert_scan(payload, paths, db_path=DB_PATH):
    """Stores an aggregated OSINT scan record into the SQLite database."""
    init_db(db_path)
    u_data = payload.get("username_recon") or {}
    d_data = payload.get("domain_recon") or {}
    exp = payload.get("exposure_summary") or {}

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (
            target_label, username, domain, accounts_found, platforms_checked,
            exposure_level, exposure_score, json_path, txt_path, html_path,
            payload_json, created_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.get("target_label", "unknown"),
            u_data.get("target_username"),
            d_data.get("target_domain"),
            u_data.get("accounts_found", 0),
            u_data.get("platforms_checked", 0),
            exp.get("exposure_level", "LOW"),
            exp.get("exposure_score", 0),
            paths.get("json"),
            paths.get("txt"),
            paths.get("html"),
            json.dumps(payload, ensure_ascii=False),
            payload.get(
                "generated_utc",
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ),
        ),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit=25, db_path=DB_PATH):
    """Retrieves recent scan summaries from the SQLite database."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, target_label, username, domain, accounts_found,
               platforms_checked, exposure_level, exposure_score,
               json_path, txt_path, html_path, created_utc
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_scan_by_id(scan_id, db_path=DB_PATH):
    """Retrieves a full scan record (including JSON payload) by ID from SQLite."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    try:
        data["payload"] = json.loads(data.get("payload_json") or "{}")
    except Exception:
        data["payload"] = {}
    return data
