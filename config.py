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