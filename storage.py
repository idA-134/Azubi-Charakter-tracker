import os
import json
from datetime import datetime
import shutil
import glob
import pathlib
import re

from config import DATA_DIR, BACKUPS_TO_KEEP, QUARANTINE_DIR, ASSETS_DIR
import db

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)

def _sanitize_filename(s: str, max_len: int = 64) -> str:
    """
    Erzeugt aus einem beliebigen Namen einen sicheren Dateinamen-Teil:
    - ersetzt Leerzeichen durch Unterstriche
    - entfernt unerlaubte Zeichen
    - kürzt auf max_len
    """
    if not s:
        return 'unknown'
    # normalize whitespace, replace with underscore
    s = re.sub(r'\s+', '_', s.strip())
    # keep letters, numbers, dash, underscore, dot
    s = re.sub(r'[^A-Za-z0-9_\-\.]', '', s)
    s = s[:max_len]
    # avoid empty result
    return s or 'unknown'

def save_character_file(data):
    """
    Saves character to /data/characters/{lehrjahr}/{sanitized_name}_{timestamp}.json
    Also updates SQLite metadata via db.upsert_character.
    Returns saved path.
    """
    lehrjahr = str(data.get('lehrjahr', 'unknown'))
    char_id = data.get('id') or _sanitize_filename(data.get('name', 'unknown')).lower()
    # Use the human-readable name for filename (sanitized), fallback to id if no name
    name_for_file = data.get('name') or char_id
    username = _sanitize_filename(name_for_file).lower()
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
    # prefix is the portion before the first underscore in filename
    prefix = p.name.split('_')[0]
    matches = sorted(base_dir.glob(f"{prefix}_*.json"), reverse=True)
    return [str(m) for m in matches]

def export_character_json_path(char_id):
    """
    Find the most recent JSON file whose content has data['id'] == char_id.
    This is robust if filenames are based on character name.
    Returns path or None.
    """
    base = os.path.join(DATA_DIR, 'characters')
    matches = []
    # Walk all JSON files under data/characters
    for root, dirs, files in os.walk(base):
        for fn in files:
            if not fn.lower().endswith('.json'):
                continue
            full = os.path.join(root, fn)
            try:
                with open(full, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if data.get('id') == char_id:
                    # use file modification time for sorting
                    mtime = os.path.getmtime(full)
                    matches.append((mtime, full))
            except Exception:
                # skip files that can't be read/parsed
                continue
    if not matches:
        return None
    # return the most recently modified file
    matches.sort(reverse=True)
    return matches[0][1]

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