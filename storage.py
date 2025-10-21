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