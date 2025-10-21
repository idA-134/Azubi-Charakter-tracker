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