#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="azubi-character-tracker"
ZIP_NAME="azubi-character-tracker.zip"

if [ -d "$PROJECT_DIR" ]; then
  echo "Verzeichnis $PROJECT_DIR existiert bereits. Lösche oder benenne es um und starte erneut."
  exit 1
fi

mkdir -p "$PROJECT_DIR"

# app.py
cat > "$PROJECT_DIR/app.py" <<'PY'
# Haupt-App (erweitert, ersetzt vorherige Version)
from flask import Flask, request, render_template, redirect, url_for, flash, send_file, jsonify, session
from werkzeug.utils import secure_filename
import os
import json
import io
import zipfile
from datetime import datetime
from validator import validate_character
from storage import save_character_file, list_backups_for, export_character_json_path, quarantine_raw_bytes, restore_character_from_backup
from level_utils import ensure_level_consistent
import config
import logging_config
import db

logging_config.setup_logging()
import logging
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

DATA_DIR = config.DATA_DIR
CATALOG_PATH = os.path.join(os.path.dirname(__file__), 'skills_catalog.json')
ALLOWED_EXTENSIONS = {'json', 'zip'}

def allowed_filename(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_catalog():
    if not os.path.exists(CATALOG_PATH):
        with open(CATALOG_PATH, 'w', encoding='utf-8') as f:
            json.dump({"skills": [], "items": [], "badges": [], "titles": [], "config": {}}, f, ensure_ascii=False, indent=2)
    with open(CATALOG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_catalog(catalog):
    with open(CATALOG_PATH, 'w', encoding='utf-8') as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    return True

@app.before_first_request
def startup():
    logger.info("Initialisiere DB und notwendige Ordner")
    db.init_db()
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
    os.makedirs(config.ASSETS_DIR, exist_ok=True)

@app.route('/')
def index():
    catalog = load_catalog()
    return render_template('index.html', catalog=catalog)

@app.route('/create', methods=['GET','POST'])
def create_character():
    if request.method == 'GET':
        catalog = load_catalog()
        return render_template('create_character.html', catalog=catalog)
    # POST -> build JSON from form
    try:
        payload = {
            'id': request.form.get('id') or _sanitize(request.form.get('name','')).lower(),
            'name': request.form.get('name'),
            'lehrjahr': int(request.form.get('lehrjahr') or 1),
            'klasse': request.form.get('klasse') or '',
            'bio': request.form.get('bio') or '',
            'avatarPfad': request.form.get('avatarPfad') or '',
            'stats': {},
            'skills': [],
            'inventar': [],
            'xp': int(request.form.get('xp') or 0),
            'achievements': [],
            'titles': [],
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }
        # stats
        for s in ['technik','teamwork','kommunikation','problemlösung','kreativität','zeitmanagement']:
            val = int(request.form.get(s) or 0)
            payload['stats'][s] = val
        # skills as repeated fields "skill_name[]" and "skill_level[]"
        skill_names = request.form.getlist('skill_name[]')
        skill_levels = request.form.getlist('skill_level[]')
        for n,l in zip(skill_names, skill_levels):
            if n.strip() == '':
                continue
            payload['skills'].append({'name': n.strip(), 'level': int(l)})
        valid, errors = validate_character(payload)
        if not valid:
            flash('Validierungsfehler: ' + '; '.join(errors), 'danger')
            return redirect(url_for('create_character'))
        ensure_level_consistent(payload)
        path = save_character_file(payload)
        flash(f'Charakter erstellt und gespeichert: {path}', 'success')
        return redirect(url_for('view_character', char_id=payload['id']))
    except Exception as e:
        logger.exception("Fehler beim Erstellen des Charakters")
        flash(f'Fehler beim Erstellen: {e}', 'danger')
        return redirect(url_for('create_character'))

@app.route('/upload', methods=['POST'])
def upload():
    uploaded = request.files.get('file')
    if not uploaded or not allowed_filename(uploaded.filename):
        flash('Keine gültige Datei ausgewählt (JSON oder ZIP erwartet).', 'danger')
        return redirect(url_for('index'))
    filename = secure_filename(uploaded.filename)
    ext = filename.rsplit('.',1)[1].lower()
    raw_bytes = uploaded.read()
    try:
        if ext == 'json':
            raw = raw_bytes.decode('utf-8')
            data = json.loads(raw)
            valid, errors = validate_character(data)
            if not valid:
                # quarantine raw upload
                qpath = quarantine_raw_bytes(raw_bytes, filename)
                logger.warning("Upload quarantined: %s; errors: %s", qpath, errors)
                flash('Validierungsfehler: Datei in Quarantäne verschoben.', 'danger')
                return redirect(url_for('index'))
            ensure_level_consistent(data)
            saved_path = save_character_file(data)
            flash(f'Datei erfolgreich geladen und gespeichert: {saved_path}', 'success')
            return redirect(url_for('view_character', char_id=data.get('id')))
        elif ext == 'zip':
            mem = io.BytesIO(raw_bytes)
            with zipfile.ZipFile(mem) as zf:
                json_names = [n for n in zf.namelist() if n.lower().endswith('.json')]
                if not json_names:
                    qpath = quarantine_raw_bytes(raw_bytes, filename)
                    flash('Keine JSON-Datei in ZIP gefunden. ZIP in Quarantäne gespeichert.', 'danger')
                    logger.warning("ZIP quarantined: %s", qpath)
                    return redirect(url_for('index'))
                json_raw = zf.read(json_names[0]).decode('utf-8')
                data = json.loads(json_raw)
                valid, errors = validate_character(data)
                if not valid:
                    qpath = quarantine_raw_bytes(raw_bytes, filename)
                    logger.warning("ZIP quarantined: %s; errors: %s", qpath, errors)
                    flash('Validierungsfehler: ZIP in Quarantäne verschoben.', 'danger')
                    return redirect(url_for('index'))
                ensure_level_consistent(data)
                saved_path = save_character_file(data)
                # extract avatar if present in zip
                try:
                    avatar = data.get('avatarPfad')
                    if avatar and avatar in zf.namelist():
                        assets_dir = os.path.join(os.getcwd(), 'assets')
                        os.makedirs(assets_dir, exist_ok=True)
                        zf.extract(avatar, path=assets_dir)
                except Exception:
                    logger.exception("Fehler beim Extrahieren von Assets")
                flash(f'ZIP importiert und gespeichert: {saved_path}', 'success')
                return redirect(url_for('view_character', char_id=data.get('id')))
    except Exception as e:
        qpath = quarantine_raw_bytes(raw_bytes, filename)
        logger.exception("Fehler beim Verarbeiten der Datei, in Quarantäne: %s", qpath)
        flash('Fehler beim Verarbeiten der Datei. Datei in Quarantäne gespeichert.', 'danger')
        return redirect(url_for('index'))

@app.route('/character/<char_id>')
def view_character(char_id):
    path = export_character_json_path(char_id)
    if not path:
        flash('Charakter nicht gefunden', 'warning')
        return redirect(url_for('index'))
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    ensure_level_consistent(data)
    backups = list_backups_for(path)
    return render_template('character_view.html', character=data, backups=backups)

@app.route('/export/json/<char_id>')
def export_json(char_id):
    path = export_character_json_path(char_id)
    if not path:
        return "Nicht gefunden", 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))

@app.route('/export/zip/<char_id>')
def export_zip(char_id):
    path = export_character_json_path(char_id)
    if not path:
        return "Nicht gefunden", 404
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, mode='w') as zf:
        zf.write(path, arcname=os.path.basename(path))
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            avatar = data.get('avatarPfad')
            if avatar and os.path.exists(avatar):
                zf.write(avatar, arcname=os.path.basename(avatar))
        except Exception:
            pass
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f'{char_id}.zip', mimetype='application/zip')

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if pwd == config.ADMIN_PASSWORD:
            session['admin'] = True
            flash('Admin angemeldet', 'success')
            return redirect(url_for('admin_index'))
        else:
            flash('Falsches Passwort', 'danger')
    return render_template('admin_login.html')

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            flash('Admin-Berechtigung erforderlich', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin')
@admin_required
def admin_index():
    # list characters from DB for convenience
    chars = db.list_characters()
    # for each char, compute backups
    char_entries = []
    for c in chars:
        path = c.get('path')
        backups = list_backups_for(path) if path and os.path.exists(path) else []
        char_entries.append({'meta': c, 'backups': backups})
    return render_template('admin_index.html', characters=char_entries)

@app.route('/admin/catalog_editor')
@admin_required
def admin_catalog_editor():
    catalog = load_catalog()
    return render_template('admin_catalog_editor.html', catalog_json=json.dumps(catalog, ensure_ascii=False, indent=2))

@app.route('/admin/catalog', methods=['GET','POST'])
@admin_required
def admin_catalog():
    if request.method == 'POST':
        try:
            incoming = request.get_json(force=True)
            save_catalog(incoming)
            return jsonify({"ok": True, "msg": "Catalog gespeichert."})
        except Exception as e:
            logger.exception("Fehler beim Speichern des Katalogs")
            return jsonify({"ok": False, "error": str(e)}), 400
    else:
        catalog = load_catalog()
        return jsonify(catalog)

@app.route('/admin/restore', methods=['POST'])
@admin_required
def admin_restore():
    data = request.get_json(force=True)
    backup_path = data.get('backup_path')
    if not backup_path:
        return jsonify({"ok": False, "error": "backup_path fehlt"}), 400
    try:
        new_path = restore_character_from_backup(backup_path)
        return jsonify({"ok": True, "path": new_path})
    except Exception as e:
        logger.exception("Fehler beim Wiederherstellen")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin abgemeldet', 'info')
    return redirect(url_for('index'))

@app.route('/import', methods=['POST'])
def import_file():
    return upload()

# small helper used in create route
def _sanitize(name):
    if not name:
        return 'unknown'
    return ''.join(c for c in name if c.isalnum() or c in ('_', '.')).strip()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
PY

# validator.py
cat > "$PROJECT_DIR/validator.py" <<'PY'
import json
from jsonschema import validate, ValidationError
from jsonschema import Draft7Validator
import os
from datetime import datetime

# load schema file (should be placed next to this file)
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'character_schema.json')
with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
    SCHEMA = json.load(f)

def validate_character(data):
    """
    Returns (valid: bool, errors: list[str])
    Performs JSON Schema validation + project specific checks:
      - Stats each 0-10 (schema enforces)
      - Sum of stats <= maxStatSum (from x-constraints)
      - Max start skills (if created recently) <= configured value
    """
    errors = []

    # Basic JSON Schema validation
    v = Draft7Validator(SCHEMA)
    schema_errors = sorted(v.iter_errors(data), key=lambda e: e.path)
    for e in schema_errors:
        errors.append(f"{'/'.join(map(str, e.path))}: {e.message}")

    # Project constraints from x-constraints
    constraints = SCHEMA.get('x-constraints', {})
    max_stat_sum = constraints.get('maxStatSum', 30)
    max_start_skills = constraints.get('maxStartSkills', 5)

    # Stats sum check
    stats = data.get('stats', {})
    if isinstance(stats, dict):
        total = sum([int(v) for v in stats.values() if isinstance(v, int) or (isinstance(v, str) and v.isdigit())])
        if total > max_stat_sum:
            errors.append(f"Summe der Stats ist {total} (max {max_stat_sum})")

    # Skills count check (if created recently consider start check)
    skills = data.get('skills', [])
    if isinstance(skills, list) and len(skills) > 0:
        if len(skills) > 50:
            errors.append("Zu viele skills (max 50)")
        # enforce individual skill levels within 1-5 (schema enforces)
        if len(skills) > max_start_skills:
            # allow, but report warning as error for MVP (per settings: reject)
            errors.append(f"Anzahl Skills {len(skills)} > maxStartSkills {max_start_skills}")

    # Required fields: handled by schema, but ensure present
    required = SCHEMA.get('required', [])
    for r in required:
        if r not in data:
            errors.append(f"Pflichtfeld fehlt: {r}")

    valid = len(errors) == 0
    return valid, errors
PY

# storage.py
cat > "$PROJECT_DIR/storage.py" <<'PY'
import os
import json
from datetime import datetime
import shutil
import glob
import pathlib

from config import DATA_DIR, BACKUPS_TO_KEEP, QUARANTINE_DIR, ASSETS_DIR
import db

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)

def _username_from_id(char_id):
    return char_id.replace(' ', '_').lower()

def save_character_file(data):
    """
    Saves character to /data/characters/{lehrjahr}/{username}_{timestamp}.json
    Also updates SQLite metadata via db.upsert_character.
    Returns saved path.
    """
    lehrjahr = str(data.get('lehrjahr', 'unknown'))
    char_id = data.get('id', _username_from_id(data.get('name','unknown')))
    username = _username_from_id(char_id)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    base_dir = os.path.join(DATA_DIR, 'characters', lehrjahr)
    safe_mkdir(base_dir)
    filename = f"{username}_{ts}.json"
    path = os.path.join(base_dir, filename)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # maintain backups: keep latest BACKUPS_TO_KEEP files with same username prefix
    pattern = os.path.join(base_dir, f"{username}_*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    for old in files[BACKUPS_TO_KEEP:]:
        try:
            os.remove(old)
        except Exception:
            pass

    # update metadata DB
    meta = {
        'id': char_id,
        'name': data.get('name'),
        'lehrjahr': data.get('lehrjahr'),
        'klasse': data.get('klasse'),
        'path': path,
        'xp': data.get('xp', 0),
        'level': data.get('level', 1),
        'created_at': data.get('created_at'),
        'updated_at': data.get('updated_at') or datetime.utcnow().isoformat() + 'Z'
    }
    db.upsert_character(meta)
    return path

def quarantine_raw_bytes(raw_bytes: bytes, orig_filename='upload'):
    safe_mkdir(QUARANTINE_DIR)
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = f"{os.path.splitext(orig_filename)[0]}_{ts}.dat"
    path = os.path.join(QUARANTINE_DIR, fname)
    with open(path, 'wb') as f:
        f.write(raw_bytes)
    return path

def list_backups_for(json_path):
    p = pathlib.Path(json_path)
    base_dir = p.parent
    prefix = p.name.split('_')[0]
    matches = sorted(base_dir.glob(f"{prefix}_*.json"), reverse=True)
    return [str(m) for m in matches]

def export_character_json_path(char_id):
    base = os.path.join(DATA_DIR, 'characters')
    username = _username_from_id(char_id)
    matches = []
    for root, dirs, files in os.walk(base):
        for fn in files:
            if fn.startswith(username + '_') and fn.endswith('.json'):
                matches.append(os.path.join(root, fn))
    if not matches:
        for root, dirs, files in os.walk(base):
            for fn in files:
                if username in fn and fn.endswith('.json'):
                    matches.append(os.path.join(root, fn))
    if not matches:
        return None
    matches = sorted(matches, reverse=True)
    return matches[0]

def restore_character_from_backup(backup_path):
    """
    Restores a backup by copying it to a new timestamped file (thus creating a new current version).
    Returns new file path or raises.
    """
    if not os.path.exists(backup_path):
        raise FileNotFoundError("Backup nicht gefunden")
    # read data
    with open(backup_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return save_character_file(data)
PY

# db.py
cat > "$PROJECT_DIR/db.py" <<'PY'
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
PY

# level_utils.py
cat > "$PROJECT_DIR/level_utils.py" <<'PY'
"""
Level / XP Hilfsfunktionen
"""

import math

def xp_to_level(xp: int) -> int:
    """
    Standard-Formel:
      level = floor(sqrt(xp / 100)) + 1

    Beispiele:
      0  -> 1
      100 -> 2
      400 -> 3
      900 -> 4
    """
    try:
        xp_val = int(xp)
    except Exception:
        xp_val = 0
    level = math.floor(math.sqrt(xp_val / 100)) + 1
    return max(1, level)

def ensure_level_consistent(character: dict) -> dict:
    """
    Setzt oder korrigiert das level-Feld anhand von xp.
    Gibt das geänderte character dict zurück (in-memory).
    """
    xp = character.get('xp', 0)
    computed = xp_to_level(xp)
    character['level'] = computed
    return character
PY

# logging_config.py
cat > "$PROJECT_DIR/logging_config.py" <<'PY'
# Simple logging setup used by app
import logging
from logging.handlers import RotatingFileHandler
import os
import config

def setup_logging():
    os.makedirs(config.LOG_DIR, exist_ok=True)
    log_path = os.path.join(config.LOG_DIR, 'app.log')
    handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    # also have console output in debug
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)
PY

# config.py
cat > "$PROJECT_DIR/config.py" <<'PY'
# Konfiguration für das MVP (erweitert)
import os

SECRET_KEY = os.environ.get('AZUBI_SECRET_KEY', 'change-me-in-production')
DATA_DIR = os.environ.get('AZUBI_DATA_DIR', os.path.join(os.getcwd(), 'data'))
ADMIN_PASSWORD = os.environ.get('AZUBI_ADMIN_PW', 'adminpass')
BACKUPS_TO_KEEP = int(os.environ.get('AZUBI_BACKUPS_KEEP', '10'))

# Zusätzliche Pfade / Einstellungen
LOG_DIR = os.environ.get('AZUBI_LOG_DIR', os.path.join(os.getcwd(), 'logs'))
DB_PATH = os.environ.get('AZUBI_DB_PATH', os.path.join(os.getcwd(), 'azubi.db'))
QUARANTINE_DIR = os.environ.get('AZUBI_QUARANTINE_DIR', os.path.join(os.getcwd(), 'quarantine'))
ASSETS_DIR = os.environ.get('AZUBI_ASSETS_DIR', os.path.join(os.getcwd(), 'assets'))
PY

# requirements.txt
cat > "$PROJECT_DIR/requirements.txt" <<'PY'
Flask>=2.0
jsonschema>=3.2.0
python-dotenv>=1.0.0
PY

# Dockerfile
cat > "$PROJECT_DIR/Dockerfile" <<'PY'
# Einfaches Dockerfile zum lokalen Betrieb (MVP)
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# App-Dateien kopieren
COPY . /app

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "app.py"]
PY

# .env.example
cat > "$PROJECT_DIR/.env.example" <<'PY'
# Beispiel Umgebungsvariablen (lokal)
AZUBI_SECRET_KEY=change-me
AZUBI_DATA_DIR=/app/data
AZUBI_ADMIN_PW=adminpass
AZUBI_BACKUPS_KEEP=10
PY

# .gitignore
cat > "$PROJECT_DIR/.gitignore" <<'PY'
venv/
__pycache__/
data/
*.pyc
.env
logs/
quarantine/
azubi.db
PY

# character_schema.json
cat > "$PROJECT_DIR/character_schema.json" <<'PY'
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Azubi Character Schema",
  "description": "Schema für Azubi-Charaktere (JSON). Admins können zusätzliche Felder hinzufügen (additionalProperties=true).",
  "type": "object",
  "additionalProperties": true,
  "properties": {
    "id": { "type": "string" },
    "name": { "type": "string" },
    "lehrjahr": { "type": "integer", "minimum": 1, "maximum": 3 },
    "klasse": { "type": "string" },
    "bio": { "type": "string" },
    "avatarPfad": { "type": "string" },
    "stats": {
      "type": "object",
      "properties": {
        "technik": { "type": "integer", "minimum": 0, "maximum": 10 },
        "teamwork": { "type": "integer", "minimum": 0, "maximum": 10 },
        "kommunikation": { "type": "integer", "minimum": 0, "maximum": 10 },
        "problemlösung": { "type": "integer", "minimum": 0, "maximum": 10 },
        "kreativität": { "type": "integer", "minimum": 0, "maximum": 10 },
        "zeitmanagement": { "type": "integer", "minimum": 0, "maximum": 10 }
      },
      "required": ["technik","teamwork","kommunikation","problemlösung","kreativität","zeitmanagement"],
      "additionalProperties": false
    },
    "skills": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "level": { "type": "integer", "minimum": 1, "maximum": 5 }
        },
        "required": ["name","level"],
        "additionalProperties": false
      }
    },
    "inventar": { "type": "array", "items": { "type": "string" } },
    "xp": { "type": "integer", "minimum": 0 },
    "level": { "type": "integer", "minimum": 1 },
    "achievements": { "type": "array", "items": { "type": "string" } },
    "titles": { "type": "array", "items": { "type": "string" } },
    "created_at": { "type": "string", "format": "date-time" },
    "updated_at": { "type": "string", "format": "date-time" },
    "personality_traits": { "type": "array", "items": { "type": "string" } }
  },
  "required": ["id","name","lehrjahr","klasse","stats","xp"],
  "x-constraints": {
    "maxStatSum": 30,
    "maxStartSkills": 5,
    "skillMaxLevel": 5,
    "levelAutoFormula": "level = floor(sqrt(xp / 100)) + 1"
  }
}
PY

# skills_catalog.json
cat > "$PROJECT_DIR/skills_catalog.json" <<'PY'
{
  "description": "Vorkonfigurierter Katalog von Skills, Items, Badges und Titeln. Admins können diese Datei bearbeiten/erweitern.",
  "skills": [
    "Git",
    "Linux",
    "Python",
    "JavaScript",
    "SQL",
    "Docker",
    "Kubernetes",
    "Networking",
    "Java",
    "C#",
    "Testing",
    "CI/CD",
    "Security",
    "Cloud (AWS/Azure)",
    "DevOps",
    "Kommunikation",
    "Teamwork",
    "Problemlösung",
    "Zeitmanagement",
    "Präsentation",
    "HTML/CSS",
    "React",
    "REST"
  ],
  "items": [
    { "id": "usb_01", "name": "USB-Stick", "description": "Praktisches Werkzeug" },
    { "id": "book_python", "name": "Python-Handbuch", "description": "Lernressource" },
    { "id": "cert_tutorial", "name": "Tutorial-Zertifikat", "description": "Abschluss eines internen Tutorials" }
  ],
  "badges": [
    { "id": "git_master", "name": "Git Master", "criteria": "Skill Git Level >= 5" },
    { "id": "fast_learner", "name": "Schnelllerner", "criteria": "XP >= 1000" },
    { "id": "team_player", "name": "Teamplayer", "criteria": "teamwork >= 8" }
  ],
  "titles": [
    { "id": "junior_webdev", "name": "Junior Webdev", "criteria": "Level >= 2 and skills contains JavaScript" },
    { "id": "sys_admin_in_training", "name": "SysAdmin in Training", "criteria": "skills contains Linux and Networking" }
  ],
  "config": {
    "maxStatSum": 30,
    "maxStartSkills": 5,
    "skillMaxLevel": 5,
    "level_formula": "level = floor(sqrt(xp / 100)) + 1"
  }
}
PY

# max.mustermann_character.json
cat > "$PROJECT_DIR/max.mustermann_character.json" <<'PY'
{
  "id": "max.mustermann",
  "name": "Max Mustermann",
  "lehrjahr": 1,
  "klasse": "Frontend",
  "bio": "Azubi im ersten Lehrjahr, interessiert an Webentwicklung und Versionierung.",
  "avatarPfad": "assets/avatars/avatar1.svg",
  "stats": {
    "technik": 8,
    "teamwork": 6,
    "kommunikation": 4,
    "problemlösung": 7,
    "kreativität": 3,
    "zeitmanagement": 2
  },
  "skills": [
    { "name": "Git", "level": 2 },
    { "name": "HTML/CSS", "level": 3 },
    { "name": "JavaScript", "level": 2 }
  ],
  "inventar": [
    "Tutorial-Zertifikat",
    "USB-Stick"
  ],
  "xp": 450,
  "level": 3,
  "achievements": [
    "first-commit",
    "passed-quiz-1"
  ],
  "titles": [
    "Junior Webdev"
  ],
  "created_at": "2025-10-21T12:00:00Z",
  "updated_at": "2025-10-21T12:30:00Z",
  "personality_traits": [
    "analytisch",
    "neugierig"
  ]
}
PY

# README.md
cat > "$PROJECT_DIR/README.md" <<'PY'
# Azubi Character Tracker - Erweiterungen (Admin Editor, Create Form, Quarantine, Logging, Restore, DB)

Dieses Projekt ist ein lokales MVP zur Verwaltung von "Azubi"-Charakteren als JSON‑Daten. Funktionen im Paket:

- Flask Backend mit Upload/Import/Export (JSON, ZIP) und Admin‑UI
- JSON Schema (character_schema.json) + Validator
- Timestamped Storage unter data/characters/{lehrjahr}/{username}_{timestamp}.json
- Backup‑Retention (konfigurierbar)
- Quarantäne für fehlerhafte Uploads (quarantine/)
- Logging (logs/app.log) mit RotatingFileHandler
- SQLite Metadaten (azubi.db) für schnelle Übersicht
- Admin Catalog Editor (Bearbeitung von skills_catalog.json)
- Interaktives Create‑Formular (Web)
- Beispiel‑Avatare unter assets/avatars/

Schnellstart:
1. Python 3.8+ installieren
2. venv anlegen:
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\\Scripts\\activate   # Windows
3. Abhängigkeiten:
   pip install -r requirements.txt
4. App starten:
   python app.py
5. Öffne im Browser: http://localhost:5000

Admin:
- Passwort in config.py (oder Umgebungsvariable AZUBI_ADMIN_PW)
- Admin Login: /admin/login
- Catalog Editor: /admin/catalog_editor
PY

# templates
mkdir -p "$PROJECT_DIR/templates"

# templates/index.html
cat > "$PROJECT_DIR/templates/index.html" <<'PY'
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Azubi Character Tracker - Upload / Erstellen</title>
  <link href="/static/styles.css" rel="stylesheet">
</head>
<body>
  <h1>Azubi Character Tracker</h1>

  <section>
    <h2>Charakter hochladen (JSON oder ZIP)</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="file" accept=".json,.zip" required>
      <button type="submit">Hochladen</button>
    </form>
  </section>

  <section>
    <h2>Charakter erstellen (interaktiv)</h2>
    <p><a href="/create">Neuen Charakter erstellen</a></p>
  </section>

  <section>
    <h2>Kurze Anleitung</h2>
    <ul>
      <li>Dateiname: {username}_character.json</li>
      <li>Format: JSON — Schema wird geprüft.</li>
      <li>Admins: <a href="/admin/login">Admin Login</a></li>
    </ul>
  </section>

  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      <ul class="flashes">
      {% for category, message in messages %}
        <li class="{{ category }}">{{ message }}</li>
      {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}
</body>
</html>
PY

# templates/create_character.html
cat > "$PROJECT_DIR/templates/create_character.html" <<'PY'
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Charakter erstellen</title>
  <link href="/static/styles.css" rel="stylesheet">
  <script>
    function addSkillRow() {
      const container = document.getElementById('skills-container');
      const div = document.createElement('div');
      div.innerHTML = '<input name="skill_name[]" placeholder="Skill-Name"> <select name="skill_level[]"><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option></select>';
      container.appendChild(div);
    }
  </script>
</head>
<body>
  <h1>Charakter erstellen</h1>
  <form method="post" action="/create">
    <label>Name: <input name="name" required></label><br>
    <label>ID (optional): <input name="id"></label><br>
    <label>Lehrjahr: <input name="lehrjahr" type="number" min="1" max="3" value="1"></label><br>
    <label>Klasse: <input name="klasse"></label><br>
    <label>Bio: <textarea name="bio"></textarea></label><br>
    <label>XP: <input name="xp" type="number" min="0" value="0"></label><br>

    <h3>Stats (0-10)</h3>
    <label>Technik: <input name="technik" type="number" min="0" max="10" value="0"></label><br>
    <label>Teamwork: <input name="teamwork" type="number" min="0" max="10" value="0"></label><br>
    <label>Kommunikation: <input name="kommunikation" type="number" min="0" max="10" value="0"></label><br>
    <label>Problemlösung: <input name="problemlösung" type="number" min="0" max="10" value="0"></label><br>
    <label>Kreativität: <input name="kreativität" type="number" min="0" max="10" value="0"></label><br>
    <label>Zeitmanagement: <input name="zeitmanagement" type="number" min="0" max="10" value="0"></label><br>

    <h3>Skills (aus Katalog)</h3>
    <div id="skills-container"></div>
    <button type="button" onclick="addSkillRow()">Skill hinzufügen</button>
    <p>Du kannst die Skills aus dem Katalog kopieren: <code id="catalog-sample"></code></p>

    <br><button type="submit">Erstellen</button>
  </form>

  <script>
    // fill catalog sample
    fetch('/admin/catalog').then(r=>r.json()).then(c=>{
      const sample = c.skills && c.skills.slice(0,10).join(', ');
      document.getElementById('catalog-sample').textContent = sample || 'kein katalog';
    });
  </script>

  <p><a href="/">Zurück</a></p>
</body>
</html>
PY

# templates/character_view.html
cat > "$PROJECT_DIR/templates/character_view.html" <<'PY'
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Charakter: {{ character.name }}</title>
  <link href="/static/styles.css" rel="stylesheet">
</head>
<body>
  <h1>{{ character.name }} (Level {{ character.level }})</h1>
  <p>Lehrjahr: {{ character.lehrjahr }} — Klasse: {{ character.klasse }}</p>

  <h2>Stats</h2>
  <ul>
    {% for k,v in character.stats.items() %}
      <li>{{ k }}: {{ v }}</li>
    {% endfor %}
  </ul>

  <h2>Skills</h2>
  <ul>
    {% for s in character.skills %}
      <li>{{ s.name }} (Level {{ s.level }})</li>
    {% endfor %}
  </ul>

  <h2>Items</h2>
  <ul>
    {% for it in character.inventar %}
      <li>{{ it }}</li>
    {% endfor %}
  </ul>

  <p>
    <a href="/export/json/{{ character.id }}">Export JSON</a> |
    <a href="/export/zip/{{ character.id }}">Export ZIP (inkl. Avatar)</a>
  </p>

  <h3>Backups</h3>
  <ul>
    {% for b in backups %}
      <li>{{ b }}</li>
    {% endfor %}
  </ul>

  <p><a href="/">Zurück</a></p>
</body>
</html>
PY

# templates/admin_login.html
cat > "$PROJECT_DIR/templates/admin_login.html" <<'PY'
<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Admin Login</title></head>
<body>
  <h1>Admin Login</h1>
  <form method="post" action="/admin/login">
    <label>Passwort: <input type="password" name="password" required></label>
    <button type="submit">Anmelden</button>
  </form>
  <p><a href="/">Zurück</a></p>
</body>
</html>
PY

# templates/admin_index.html
cat > "$PROJECT_DIR/templates/admin_index.html" <<'PY'
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Admin Dashboard</title>
  <link href="/static/styles.css" rel="stylesheet">
</head>
<body>
  <h1>Admin Dashboard</h1>
  <p><a href="/admin/catalog_editor">Catalog Editor</a> | <a href="/admin/logout">Logout</a></p>

  <h2>Charaktere (DB)</h2>
  <ul>
    {% for entry in characters %}
      <li>
        <strong>{{ entry.meta.name }}</strong> ({{ entry.meta.id }}) — Lehrjahr: {{ entry.meta.lehrjahr }} — Klasse: {{ entry.meta.klasse }} — Level: {{ entry.meta.level }} — XP: {{ entry.meta.xp }}
        <div>
          Datei: {{ entry.meta.path }} —
          <a href="/character/{{ entry.meta.id }}">Ansehen</a>
        </div>
        <div>
          Backups:
          <ul>
            {% for b in entry.backups %}
              <li>
                {{ b }} 
                <button onclick="restoreBackup('{{ b }}')">Wiederherstellen</button>
              </li>
            {% endfor %}
            {% if not entry.backups %}
              <li>Keine Backups</li>
            {% endif %}
          </ul>
        </div>
      </li>
    {% endfor %}
  </ul>

  <script>
    function restoreBackup(path) {
      if (!confirm('Wirklich wiederherstellen?')) return;
      fetch('/admin/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({backup_path: path})})
        .then(r=>r.json()).then(j=>{
          alert(JSON.stringify(j));
          if (j.ok) location.reload();
        }).catch(e=>alert(e));
    }
  </script>
</body>
</html>
PY

# templates/admin_catalog_editor.html
cat > "$PROJECT_DIR/templates/admin_catalog_editor.html" <<'PY'
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Catalog Editor</title>
  <link href="/static/styles.css" rel="stylesheet">
</head>
<body>
  <h1>Catalog Editor</h1>
  <p>Bearbeite den Skills/Items/Bages/Titles-Katalog als JSON und speichere.</p>
  <textarea id="catalog" style="width:100%;height:400px;">{{ catalog_json }}</textarea><br>
  <button id="save">Speichern</button>
  <div id="result"></div>
  <p><a href="/admin">Zurück zum Admin</a></p>

  <script>
    document.getElementById('save').addEventListener('click', function(){
      let txt = document.getElementById('catalog').value;
      try {
        let parsed = JSON.parse(txt);
        fetch('/admin/catalog', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(parsed)})
          .then(r=>r.json()).then(j=>{ document.getElementById('result').textContent = JSON.stringify(j); })
          .catch(e=>{ document.getElementById('result').textContent = e; });
      } catch(e) {
        alert('Ungültiges JSON: ' + e);
      }
    });
  </script>
</body>
</html>
PY

# static
mkdir -p "$PROJECT_DIR/static"
cat > "$PROJECT_DIR/static/styles.css" <<'PY'
body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }
h1 { color: #2c3e50; }
.flashes li { margin: .5rem 0; padding: .5rem; list-style: none; border-radius: 4px; }
.flashes .success { background: #e6ffed; color: #034d1a; border: 1px solid #b6f0c7; }
.flashes .danger { background: #ffdede; color: #5c0505; border: 1px solid #f1a2a2; }
PY

# assets
mkdir -p "$PROJECT_DIR/assets/avatars"
cat > "$PROJECT_DIR/assets/avatars/avatar1.svg" <<'PY'
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <rect width="100%" height="100%" fill="#f0f4f8"/>
  <circle cx="128" cy="96" r="48" fill="#6c8ebf"/>
  <rect x="64" y="160" width="128" height="56" rx="8" fill="#9bb1d6"/>
  <text x="50%" y="240" font-size="14" text-anchor="middle" fill="#334155">Avatar 1</text>
</svg>
PY

cat > "$PROJECT_DIR/assets/avatars/avatar2.svg" <<'PY'
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <rect width="100%" height="100%" fill="#fff7ed"/>
  <circle cx="128" cy="88" r="46" fill="#f6ad55"/>
  <rect x="56" y="156" width="144" height="60" rx="10" fill="#fbd38d"/>
  <text x="50%" y="240" font-size="14" text-anchor="middle" fill="#92400e">Avatar 2</text>
</svg>
PY

# create zip archive
echo "Erzeuge ZIP-Archiv $ZIP_NAME ..."
(cd "$PROJECT_DIR" && zip -r "../$ZIP_NAME" . >/dev/null)

echo "Fertig. ZIP: $ZIP_NAME"
echo "Projektverzeichnis: $PROJECT_DIR"