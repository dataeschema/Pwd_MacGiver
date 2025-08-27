import os
import sys

DB_FILENAME = "vault.db"

def get_db_path() -> str:
    """Devuelve la ruta del archivo vault.db junto al ejecutable o script."""
    if getattr(sys, 'frozen', False):  # ejecutándose como .exe con PyInstaller
        base_path = os.path.dirname(sys.executable)
    else:
        # Sube un nivel porque este script está en el directorio 'app'
        base_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    return os.path.join(base_path, DB_FILENAME)
