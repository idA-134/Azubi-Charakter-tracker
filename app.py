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