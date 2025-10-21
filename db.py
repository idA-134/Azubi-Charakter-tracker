# Einfacher SQLite Helper für Metadaten
import sqlite3
import os
from datetime import datetime
import json
import config

DB_PATH = config.DB_PATH

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS characters (
        id TEXT PRIMARY KEY,
        name TEXT,
        lehrjahr INTEGER,
        klasse TEXT,
        path TEXT,
        xp INTEGER,
        level INTEGER,
        created_at TEXT,
        updated_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def upsert_character(metadata: dict):
    """
    metadata expects keys: id, name, lehrjahr, klasse, path, xp, level, created_at, updated_at
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO characters (id, name, lehrjahr, klasse, path, xp, level, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      lehrjahr=excluded.lehrjahr,
      klasse=excluded.klasse,
      path=excluded.path,
      xp=excluded.xp,
      level=excluded.level,
      updated_at=excluded.updated_at
    """, (
        metadata.get('id'),
        metadata.get('name'),
        metadata.get('lehrjahr'),
        metadata.get('klasse'),
        metadata.get('path'),
        metadata.get('xp', 0),
        metadata.get('level', 1),
        metadata.get('created_at'),
        metadata.get('updated_at')
    ))
    conn.commit()
    conn.close()

def list_characters():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM characters ORDER BY updated_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]