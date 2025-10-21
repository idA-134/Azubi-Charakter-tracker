# Haupt-App (robustere Version, mit Admin-Endpoints zum Hinzufügen von XP / Titles / Items)
from flask import Flask, request, render_template, redirect, url_for, flash, send_file, jsonify, session
from werkzeug.utils import secure_filename
import os
import json
import io
import zipfile
from datetime import datetime
import random
import logging

from validator import validate_character
from storage import save_character_file, list_backups_for, export_character_json_path, quarantine_raw_bytes, restore_character_from_backup
from level_utils import ensure_level_consistent
import config
import logging_config
import db

# Logging initialisieren
logging_config.setup_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Konstanten / Pfade
DATA_DIR = config.DATA_DIR
CATALOG_PATH = os.path.join(os.path.dirname(__file__), 'skills_catalog.json')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'character_schema.json')
ALLOWED_EXTENSIONS = {'json', 'zip'}

# stat keys used across templates and storage
STAT_KEYS = ['technik', 'teamwork', 'kommunikation', 'problemlösung', 'kreativität', 'zeitmanagement']


def allowed_filename(filename):
    return filename and '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_catalog():
    """Lädt den Katalog; legt eine minimale Struktur an, falls Datei fehlt oder fehlerhaft ist."""
    default = {"skills": [], "items": [], "badges": [], "titles": [], "config": {}, "classes": []}
    try:
        if not os.path.exists(CATALOG_PATH):
            with open(CATALOG_PATH, 'w', encoding='utf-8') as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
            return default
        with open(CATALOG_PATH, 'r', encoding='utf-8') as f:
            c = json.load(f)
            # ensure keys exist
            for k in default:
                if k not in c:
                    c[k] = default[k]
            return c
    except Exception:
        logger.exception("Fehler beim Laden des Katalogs; verwende Fallback")
        return default


def save_catalog(catalog):
    try:
        with open(CATALOG_PATH, 'w', encoding='utf-8') as f:
            json.dump(catalog, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        logger.exception("Fehler beim Speichern des Katalogs")
        return False


def load_schema_constraints():
    """Lädt optionale x-constraints aus dem Schema, mit Fallbacks."""
    try:
        if not os.path.exists(SCHEMA_PATH):
            return {"maxStatSum": 30, "maxStartSkills": 5}
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            schema = json.load(f)
        return schema.get('x-constraints', {"maxStatSum": 30, "maxStartSkills": 5})
    except Exception:
        logger.exception("Fehler beim Laden des Schemas; nutze Default-Constraints")
        return {"maxStatSum": 30, "maxStartSkills": 5}


def generate_random_stats(max_sum=30):
    """
    Erzeugt zufällige Werte für STAT_KEYS (0-10), so dass die Summe <= max_sum.
    Vermeidet Endlosloops und ist deterministisch genug für UI-Vorbefüllung.
    """
    keys = STAT_KEYS
    stats = {k: 0 for k in keys}
    remaining = min(max_sum, 10 * len(keys))

    # initial small distribution
    for k in keys:
        give = random.randint(0, min(2, remaining))
        stats[k] = give
        remaining -= give

    # distribute remaining points, respecting max 10 per stat
    attempts = 0
    while remaining > 0 and attempts < 1000:
        k = random.choice(keys)
        if stats[k] < 10:
            stats[k] += 1
            remaining -= 1
        attempts += 1

    # final safety: clamp values and ensure sum <= max_sum
    total = sum(stats.values())
    if total > max_sum:
        # reduce proportionally
        over = total - max_sum
        for k in keys:
            if over <= 0:
                break
            dec = min(stats[k], over)
            stats[k] -= dec
            over -= dec

    return stats


@app.route('/')
def index():
    catalog = load_catalog()
    return render_template('index.html', catalog=catalog)


@app.route('/catalog', methods=['GET'])
def public_catalog():
    """
    Öffentlicher Endpunkt, damit Create-Formulare den Katalog abrufen können
    (ohne Admin-Login). Liefert skills/items/titles/classes etc.
    """
    catalog = load_catalog()
    return jsonify(catalog)


@app.route('/create', methods=['GET', 'POST'])
def create_character():
    catalog = load_catalog()
    constraints = load_schema_constraints()
    max_stat_sum = constraints.get('maxStatSum', 30)
    classes = catalog.get('classes', []) or ["Frontend", "Backend", "IT"]

    if request.method == 'GET':
        # Vorbefüllung der Stats (zufällig)
        stats = generate_random_stats(max_sum=max_stat_sum)
        return render_template('create_character.html', catalog=catalog, stats=stats, classes=classes)

    # POST: Charakter anlegen — XP-Eingabe ist nicht erlaubt; neuer Charakter erhält xp=0 und level=1
    try:
        name = (request.form.get('name') or '').strip()
        if not name:
            flash('Name ist erforderlich', 'danger')
            return redirect(url_for('create_character'))

        payload = {
            'id': request.form.get('id') or _sanitize(name).lower(),
            'name': name,
            'lehrjahr': int(request.form.get('lehrjahr') or 1),
            'klasse': request.form.get('klasse') or (classes[0] if classes else ''),
            'bio': request.form.get('bio') or '',
            'avatarPfad': request.form.get('avatarPfad') or '',
            'stats': {},
            'skills': [],
            'inventar': [],
            'xp': 0,
            'level': 1,
            'achievements': [],
            'titles': [],
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'updated_at': datetime.utcnow().isoformat() + 'Z'
        }

        # Stats: entweder aus Formular übernehmen oder aus generierten Defaults
        for s in STAT_KEYS:
            val = request.form.get(s)
            if val is None or val == '':
                # use a fresh random stat set as fallback (pick single stat value)
                fallback = generate_random_stats(max_sum=max_stat_sum)
                payload['stats'][s] = int(fallback.get(s, 0))
            else:
                try:
                    payload['stats'][s] = int(val)
                except Exception:
                    payload['stats'][s] = 0

        # Skills: wiederholbare Felder
        skill_names = request.form.getlist('skill_name[]')
        skill_levels = request.form.getlist('skill_level[]')
        for n, l in zip(skill_names, skill_levels):
            if not n or not n.strip():
                continue
            try:
                lvl = int(l)
            except Exception:
                lvl = 1
            payload['skills'].append({'name': n.strip(), 'level': max(1, min(5, lvl))})

        # Validierung
        valid, errors = validate_character(payload)
        if not valid:
            logger.info("Validierungsfehler beim Erstellen: %s", errors)
            flash('Validierungsfehler: ' + '; '.join(errors), 'danger')
            return redirect(url_for('create_character'))

        # Stelle sicher, dass level konsistent ist (aber zwinge neuen Charakter auf Level 1)
        ensure_level_consistent(payload)
        payload['level'] = 1
        payload['xp'] = 0

        saved_path = save_character_file(payload)
        flash(f'Charakter erstellt und gespeichert: {os.path.basename(saved_path)}', 'success')
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
    ext = filename.rsplit('.', 1)[1].lower()
    raw_bytes = uploaded.read()
    try:
        if ext == 'json':
            raw = raw_bytes.decode('utf-8')
            data = json.loads(raw)
            valid, errors = validate_character(data)
            if not valid:
                qpath = quarantine_raw_bytes(raw_bytes, filename)
                logger.warning("Upload quarantined: %s; errors: %s", qpath, errors)
                flash('Validierungsfehler: Datei in Quarantäne verschoben.', 'danger')
                return redirect(url_for('index'))
            ensure_level_consistent(data)
            saved_path = save_character_file(data)
            flash(f'Datei erfolgreich geladen und gespeichert: {os.path.basename(saved_path)}', 'success')
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
                        target_dir = os.path.join(os.getcwd(), os.path.dirname(avatar) or '')
                        os.makedirs(target_dir, exist_ok=True)
                        zf.extract(avatar, path=os.getcwd())
                except Exception:
                    logger.exception("Fehler beim Extrahieren von Assets")
                flash(f'ZIP importiert und gespeichert: {os.path.basename(saved_path)}', 'success')
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
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        flash('Fehler beim Laden des Charakters', 'danger')
        return redirect(url_for('index'))
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
            logger.exception("Fehler beim Erstellen des ZIP-Exports")
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f'{char_id}.zip', mimetype='application/zip')


@app.route('/admin/login', methods=['GET', 'POST'])
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
    chars = db.list_characters()
    char_entries = []
    for c in chars:
        path = c.get('path')
        backups = list_backups_for(path) if path and os.path.exists(path) else []
        char_entries.append({'meta': c, 'backups': backups})
    return render_template('admin_index.html', characters=char_entries)


# -------------------------
# Neue Admin-API Endpoints
# -------------------------
@app.route('/admin/add_xp', methods=['POST'])
@admin_required
def admin_add_xp():
    """
    JSON expected: { "id": "<char_id>", "amount": 100 }
    Adds amount (can be negative) to character.xp, ensures >=0, recalculates level, saves new file.
    """
    try:
        data = request.get_json(force=True)
        char_id = data.get('id') or data.get('char_id')
        if not char_id:
            return jsonify({"ok": False, "error": "char id fehlt"}), 400
        try:
            amount = int(data.get('amount', 0))
        except Exception:
            return jsonify({"ok": False, "error": "amount muss ein Integer sein"}), 400

        path = export_character_json_path(char_id)
        if not path:
            return jsonify({"ok": False, "error": "Charakter nicht gefunden"}), 404

        with open(path, 'r', encoding='utf-8') as f:
            character = json.load(f)

        xp_before = int(character.get('xp', 0))
        new_xp = max(0, xp_before + amount)
        character['xp'] = new_xp
        ensure_level_consistent(character)

        new_path = save_character_file(character)
        return jsonify({"ok": True, "path": new_path, "xp": character['xp'], "level": character.get('level', 1)})

    except Exception as e:
        logger.exception("Fehler in admin_add_xp")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/admin/add_title', methods=['POST'])
@admin_required
def admin_add_title():
    """
    JSON expected: { "id": "<char_id>", "title": "Neuer Titel" }
    Adds a title to character.titles (no duplicates) and saves.
    """
    try:
        data = request.get_json(force=True)
        char_id = data.get('id') or data.get('char_id')
        title = (data.get('title') or '').strip()
        if not char_id or not title:
            return jsonify({"ok": False, "error": "char id oder title fehlt"}), 400

        path = export_character_json_path(char_id)
        if not path:
            return jsonify({"ok": False, "error": "Charakter nicht gefunden"}), 404

        with open(path, 'r', encoding='utf-8') as f:
            character = json.load(f)

        titles = character.get('titles', [])
        if title not in titles:
            titles.append(title)
        character['titles'] = titles
        character['updated_at'] = datetime.utcnow().isoformat() + 'Z'

        new_path = save_character_file(character)
        return jsonify({"ok": True, "path": new_path, "titles": character['titles']})

    except Exception as e:
        logger.exception("Fehler in admin_add_title")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/admin/add_item', methods=['POST'])
@admin_required
def admin_add_item():
    """
    JSON expected: { "id": "<char_id>", "item": "Item Name" }
    Adds an item to character.inventar (no duplicates) and saves.
    """
    try:
        data = request.get_json(force=True)
        char_id = data.get('id') or data.get('char_id')
        item = (data.get('item') or '').strip()
        if not char_id or not item:
            return jsonify({"ok": False, "error": "char id oder item fehlt"}), 400

        path = export_character_json_path(char_id)
        if not path:
            return jsonify({"ok": False, "error": "Charakter nicht gefunden"}), 404

        with open(path, 'r', encoding='utf-8') as f:
            character = json.load(f)

        inv = character.get('inventar', [])
        if item not in inv:
            inv.append(item)
        character['inventar'] = inv
        character['updated_at'] = datetime.utcnow().isoformat() + 'Z'

        new_path = save_character_file(character)
        return jsonify({"ok": True, "path": new_path, "inventar": character['inventar']})

    except Exception as e:
        logger.exception("Fehler in admin_add_item")
        return jsonify({"ok": False, "error": str(e)}), 500
# -------------------------
# Ende Admin-API Endpoints
# -------------------------


@app.route('/admin/catalog_editor')
@admin_required
def admin_catalog_editor():
    catalog = load_catalog()
    return render_template('admin_catalog_editor.html', catalog_json=json.dumps(catalog, ensure_ascii=False, indent=2))


@app.route('/admin/classes', methods=['POST'])
@admin_required
def admin_add_class():
    try:
        if request.is_json:
            body = request.get_json(force=True)
            name = body.get('name') or body.get('classname')
        else:
            name = request.form.get('classname') or request.form.get('name')
        if not name or not isinstance(name, str) or name.strip() == '':
            return jsonify({"ok": False, "error": "Kein Klassenname übergeben"}), 400
        name = name.strip()
        catalog = load_catalog()
        classes = catalog.get('classes', [])
        if name in classes:
            return jsonify({"ok": False, "error": "Klasse existiert bereits"}), 400
        classes.append(name)
        catalog['classes'] = classes
        save_catalog(catalog)
        return jsonify({"ok": True, "classes": classes})
    except Exception as e:
        logger.exception("Fehler beim Hinzufügen einer Klasse")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/admin/catalog', methods=['GET', 'POST'])
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


# Hilfsfunktionen
def _sanitize(name):
    if not name:
        return 'unknown'
    return ''.join(c for c in name if c.isalnum() or c in ('_', '.')).strip()


def _ensure_startup_dirs_and_db():
    """Initialisierung, ausgeführt vor app.run() - kompatibel mit allen Flask-Versionen"""
    try:
        logger.info("Initialisiere DB und notwendige Ordner")
        db.init_db()
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
        os.makedirs(config.ASSETS_DIR, exist_ok=True)
    except Exception:
        logger.exception("Fehler bei der Initialisierung von Ordnern/DB")


if __name__ == '__main__':
    _ensure_startup_dirs_and_db()
    app.run(host='0.0.0.0', port=5000, debug=True)