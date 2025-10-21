```markdown
# Azubi Character Tracker - Erweiterungen (Admin Editor, Create Form, Quarantine, Logging, Restore, DB)

Dieses Update enthält die folgenden Ergänzungen:
- Admin Catalog Editor (HTML/AJAX) -> /admin/catalog_editor
- Interaktives Create‑Formular -> /create
- Quarantäne für fehlerhafte Uploads -> /quarantine
- Logging: /logs/app.log (RotatingFileHandler)
- Restore UI/Endpoint im Admin Dashboard
- SQLite Metadaten (azubi.db) mit Tabelle `characters`
- Beispiel Avatare (SVG) unter assets/avatars/

Wichtige Hinweise
- Lege alle Dateien im Projektordner ab (templates/, static/, assets/, app.py, storage.py, db.py, config.py, validator.py, level_utils.py, logging_config.py).
- Starte wie bisher mit: python -m venv venv; source venv/bin/activate; pip install -r requirements.txt; python app.py
- Admin Login: Passwort in config.ADMIN_PASSWORD (oder ENV AZUBI_ADMIN_PW)
- Änderungen am Katalog: Admin -> Catalog Editor -> Speichern (überschreibt skills_catalog.json)
- Quarantäne: Defekte Uploads landen im quarantine‑Ordner (config.QUARANTINE_DIR)
- DB: azubi.db erstellt automatisch; list_characters() im Admin zeigt gespeicherte Charaktere
```