"""
Password Manager GUI for Windows (Python 3.11, PySide6)
- SQLite storage for config and services
- Master password (first run asks to create one; later runs require it)
- Sensitive fields encrypted with key derived from master password (PBKDF2 + Fernet)
- Modern, elegant UI with custom icon
- Table listing services; double-click any cell copies value to clipboard and shows a temporary banner
- CRUD (Add / Edit / Delete) for services
- Settings dialog to set initial window size (width/height), persisted in DB

Dependencies: pip install PySide6 cryptography
"""
from __future__ import annotations

import base64
import os
import sqlite3
import sys
import typing as t
from dataclasses import dataclass

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

# ==========================
#  App Assets
# ==========================
# The application icon is loaded from icon.png within the MainWindow class.
# It is bundled into the executable using PyInstaller's --add-data flag.

DB_FILENAME = "vault.db"

# ==========================
# Crypto helper
# ==========================
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken


class CryptoManager:
    def __init__(self, key: bytes):
        # Fernet expects a 32-byte urlsafe base64 key
        self._fernet = Fernet(key)

    @staticmethod
    def derive_key(master_password: str, salt: bytes, iterations: int = 200_000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        raw = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw)

    def encrypt(self, plaintext: str | None) -> bytes | None:
        if plaintext is None:
            return None
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, token: bytes | None) -> str | None:
        if token is None:
            return None
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken:
            raise


# ==========================
# Database layer
# ==========================

SCHEMA = r"""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS entornos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL UNIQUE,
    color TEXT,
    orden INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    username BLOB,
    password BLOB,
    server BLOB,
    database BLOB,
    entorno_id INTEGER,
    FOREIGN KEY (entorno_id) REFERENCES entornos (id) ON DELETE SET NULL
);
"""

META_SALT_KEY = "kdf_salt"
META_VERIFIER_KEY = "key_verifier"


class Database:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # --- meta helpers ---
    def get_meta(self, key: str) -> bytes | None:
        cur = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: bytes) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    # --- config helpers ---
    def get_config(self, key: str, default: str | None = None) -> str | None:
        cur = self.conn.execute("SELECT value FROM config WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else default

    def set_config(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO config(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    # --- service CRUD ---
    @dataclass
    class Entorno:
        id: int | None
        nombre: str
        color: str | None
        orden: int

    @dataclass
    class Service:
        id: int | None
        service_name: str
        username: bytes | None
        password: bytes | None
        server: bytes | None
        database: bytes | None
        entorno_id: int | None
        entorno_color: str | None

    def list_entornos(self) -> list[Entorno]:
        cur = self.conn.execute("SELECT id, nombre, color, orden FROM entornos ORDER BY orden, nombre")
        return [
            Database.Entorno(
                id=row["id"],
                nombre=row["nombre"],
                color=row["color"],
                orden=row["orden"],
            )
            for row in cur.fetchall()
        ]

    def insert_entorno(self, nombre: str, color: str, orden: int) -> int:
        cur = self.conn.execute(
            "INSERT INTO entornos (nombre, color, orden) VALUES (?, ?, ?)", (nombre, color, orden)
        )
        self.conn.commit()
        return cur.lastrowid

    def update_entorno(self, id: int, nombre: str, color: str, orden: int) -> None:
        self.conn.execute(
            "UPDATE entornos SET nombre=?, color=?, orden=? WHERE id=?", (nombre, color, orden, id)
        )
        self.conn.commit()

    def delete_entorno(self, id: int) -> None:
        self.conn.execute("DELETE FROM entornos WHERE id=?", (id,))
        self.conn.commit()

    def is_entorno_in_use(self, id: int) -> bool:
        cur = self.conn.execute("SELECT 1 FROM services WHERE entorno_id=?", (id,))
        return cur.fetchone() is not None

    def list_services(self) -> list[Service]:
        cur = self.conn.execute(
            """
            SELECT s.id, s.service_name, s.username, s.password, s.server, s.database, s.entorno_id, e.color as entorno_color
              FROM services s
              LEFT JOIN entornos e ON s.entorno_id = e.id
             ORDER BY e.orden, s.service_name
            """
        )
        return [
            Database.Service(
                id=row["id"],
                service_name=row["service_name"],
                username=row["username"],
                password=row["password"],
                server=row["server"],
                database=row["database"],
                entorno_id=row["entorno_id"],
                entorno_color=row["entorno_color"],
            )
            for row in cur.fetchall()
        ]

    def insert_service(self, svc: Service) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO services(service_name, username, password, server, database, entorno_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                svc.service_name,
                svc.username,
                svc.password,
                svc.server,
                svc.database,
                svc.entorno_id,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_service(self, svc: Service) -> None:
        assert svc.id is not None
        self.conn.execute(
            """
            UPDATE services
               SET service_name=?, username=?, password=?, server=?, database=?, entorno_id=?
             WHERE id=?
            """,
            (
                svc.service_name,
                svc.username,
                svc.password,
                svc.server,
                svc.database,
                svc.entorno_id,
                svc.id,
            ),
        )
        self.conn.commit()

    def delete_service(self, service_id: int) -> None:
        self.conn.execute("DELETE FROM services WHERE id=?", (service_id,))
        self.conn.commit()


# ==========================
# Dialogs
# ==========================

class LoginDialog(QtWidgets.QDialog):
    def __init__(self, db: Database, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Acceso - Contraseña maestra")
        self.setModal(True)
        self.db = db
        self._build_ui()
        self.crypto: CryptoManager | None = None

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        lbl = QtWidgets.QLabel("Introduce la contraseña maestra")
        self.edit = QtWidgets.QLineEdit()
        self.edit.setEchoMode(QtWidgets.QLineEdit.Password)

        self.info = QtWidgets.QLabel()
        self.info.setWordWrap(True)
        self.info.setStyleSheet("color:#aaa; font-size:12px;")

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout.addWidget(lbl)
        layout.addWidget(self.edit)
        layout.addWidget(self.info)
        layout.addWidget(btns)

        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet(
            """
            QDialog { background: #0f172a; color: #e2e8f0; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            QLabel { color:#e5e7eb; }
            """
        )

    def _ensure_salt_and_verifier(self, master: str) -> CryptoManager:
        salt = self.db.get_meta(META_SALT_KEY)
        if salt is None:
            # First run: create salt + verifier
            salt = os.urandom(16)
            key = CryptoManager.derive_key(master, salt)
            verifier = QtCore.QCryptographicHash.hash(key, QtCore.QCryptographicHash.Sha256)
            self.db.set_meta(META_SALT_KEY, salt)
            self.db.set_meta(META_VERIFIER_KEY, verifier)
            return CryptoManager(key)
        else:
            key = CryptoManager.derive_key(master, salt)
            verifier_stored = self.db.get_meta(META_VERIFIER_KEY)
            verifier_now = QtCore.QCryptographicHash.hash(key, QtCore.QCryptographicHash.Sha256)
            if verifier_stored != verifier_now:
                raise ValueError("Contraseña maestra incorrecta")
            return CryptoManager(key)

    @staticmethod
    def get_crypto(db: Database, parent: QtWidgets.QWidget | None = None) -> CryptoManager | None:
        dlg = LoginDialog(db, parent)
        # Show helper text depending on first run
        if db.get_meta(META_SALT_KEY) is None:
            dlg.setWindowTitle("Crear contraseña maestra")
            dlg.info.setText(
                "Es la primera vez. Crea una contraseña maestra. Guárdala bien: sin ella no podrás descifrar tus datos."
            )
        else:
            dlg.info.setText("Introduce tu contraseña maestra para desbloquear el almacén.")

        while True:
            if dlg.exec() == QtWidgets.QDialog.Accepted:
                master = dlg.edit.text()
                if not master:
                    QtWidgets.QMessageBox.warning(dlg, "Aviso", "La contraseña no puede estar vacía")
                    continue
                try:
                    crypto = dlg._ensure_salt_and_verifier(master)
                    return crypto
                except ValueError:
                    QtWidgets.QMessageBox.critical(dlg, "Error", "Contraseña maestra incorrecta")
                    continue
            else:
                return None


class ServiceDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, *, title: str, service_name: str = "", username: str = "", password: str = "", server: str = "", database: str = "", entorno_id: int | None = None, entornos: list[Database.Entorno]):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(500)
        self.name_edit = QtWidgets.QLineEdit(service_name)
        self.user_edit = QtWidgets.QLineEdit(username)
        self.pass_edit = QtWidgets.QLineEdit(password)
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.server_edit = QtWidgets.QLineEdit(server)
        self.db_edit = QtWidgets.QLineEdit(database)

        self.entorno_combo = QtWidgets.QComboBox()
        self.entorno_combo.addItem("", None)  # No environment
        for entorno in entornos:
            self.entorno_combo.addItem(entorno.nombre, entorno.id)
            if entorno.id == entorno_id:
                self.entorno_combo.setCurrentText(entorno.nombre)

        self._build_ui()

    def _build_ui(self):
        form = QtWidgets.QFormLayout()
        form.addRow("Servicio:", self.name_edit)
        form.addRow("Usuario:", self.user_edit)
        form.addRow("Contraseña:", self.pass_edit)
        form.addRow("Servidor:", self.server_edit)
        form.addRow("BBDD:", self.db_edit)
        form.addRow("Entorno:", self.entorno_combo)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(btns)

        self.setStyleSheet(
            """
            QDialog { background:#0f172a; color:#e2e8f0; }
            QLineEdit, QComboBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #111827; border: 1px solid #334155; color: #e2e8f0; }
            QFormLayout > QLabel { color:#e5e7eb; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            """
        )

    def get_values(self) -> tuple[str, str, str, str, str, int | None]:
        return (
            self.name_edit.text().strip(),
            self.user_edit.text().strip(),
            self.pass_edit.text(),
            self.server_edit.text().strip(),
            self.db_edit.text().strip(),
            self.entorno_combo.currentData(),
        )


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuración")
        self.setModal(True)
        self.db = db
        w = int(self.db.get_config("win_width", "1000"))
        h = int(self.db.get_config("win_height", "600"))
        self.width_spin = QtWidgets.QSpinBox()
        self.width_spin.setRange(640, 3840)
        self.width_spin.setValue(w)
        self.height_spin = QtWidgets.QSpinBox()
        self.height_spin.setRange(480, 2160)
        self.height_spin.setValue(h)
        self._build_ui()

    def _build_ui(self):
        form = QtWidgets.QFormLayout()
        form.addRow("Ancho inicial (px):", self.width_spin)
        form.addRow("Alto inicial (px):", self.height_spin)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self._save)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(btns)

        self.setStyleSheet(
            """
            QDialog { background:#0f172a; color:#e2e8f0; }
            QSpinBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            """
        )

    def _save(self):
        self.db.set_config("win_width", str(self.width_spin.value()))
        self.db.set_config("win_height", str(self.height_spin.value()))
        self.accept()


class EntornoEditDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, *, nombre: str = "", color: str = "#FFFFFF", orden: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Editar Entorno")
        self.setModal(True)

        self.nombre_edit = QtWidgets.QLineEdit(nombre)
        self.orden_spin = QtWidgets.QSpinBox()
        self.orden_spin.setRange(0, 999)
        self.orden_spin.setValue(orden)

        self.color_button = QtWidgets.QPushButton()
        self.color_dialog = QtWidgets.QColorDialog(self)
        self._set_color(color)
        self.color_button.clicked.connect(self._pick_color)

        self._build_ui()

    def _build_ui(self):
        form = QtWidgets.QFormLayout()
        form.addRow("Nombre:", self.nombre_edit)
        form.addRow("Color:", self.color_button)
        form.addRow("Orden:", self.orden_spin)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(btns)
        self.setStyleSheet(
            """
            QDialog { background:#0f172a; color:#e2e8f0; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QSpinBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            """
        )

    def _pick_color(self):
        if self.color_dialog.exec():
            self._set_color(self.color_dialog.selectedColor().name())

    def _set_color(self, color_hex: str):
        self.color = QtGui.QColor(color_hex)
        self.color_button.setStyleSheet(f"background-color: {color_hex}; color: black; padding: 5px; border-radius: 5px;")
        self.color_button.setText(color_hex)

    def get_values(self) -> tuple[str, str, int]:
        return self.nombre_edit.text().strip(), self.color.name(), self.orden_spin.value()


class EntornosDialog(QtWidgets.QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("Gestionar Entornos")
        self.setMinimumSize(500, 400)
        self.setModal(True)
        self._build_ui()
        self._refresh_table()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Nombre", "Color", "Orden"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_add = QtWidgets.QPushButton("Añadir")
        btn_edit = QtWidgets.QPushButton("Modificar")
        btn_del = QtWidgets.QPushButton("Eliminar")
        btn_add.clicked.connect(self._add_entorno)
        btn_edit.clicked.connect(self._edit_entorno)
        btn_del.clicked.connect(self._del_entorno)

        btn_layout.addWidget(btn_add)
        btn_layout.addWidget(btn_edit)
        btn_layout.addWidget(btn_del)

        layout.addWidget(self.table)
        layout.addLayout(btn_layout)
        self.setStyleSheet(
            """
            QDialog { background:#0f172a; color:#e2e8f0; }
            QTableView { background:#0f172a; alternate-background-color:#0c1222; gridline-color:#1f2937; }
            QHeaderView::section { background:#111827; color:#e5e7eb; border:0; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            """
        )

    def _refresh_table(self):
        self.table.setRowCount(0)
        self._entornos_cache = self.db.list_entornos()
        for entorno in self._entornos_cache:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(entorno.nombre))
            color_item = QtWidgets.QTableWidgetItem(entorno.color)
            if entorno.color:
                color_item.setBackground(QtGui.QColor(entorno.color))
            self.table.setItem(row, 1, color_item)
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(entorno.orden)))
            self.table.item(row, 0).setData(Qt.UserRole, entorno.id)

    def _add_entorno(self):
        dlg = EntornoEditDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            nombre, color, orden = dlg.get_values()
            if not nombre:
                QtWidgets.QMessageBox.warning(self, "Aviso", "El nombre del entorno es obligatorio.")
                return
            try:
                self.db.insert_entorno(nombre, color, orden)
                self._refresh_table()
            except sqlite3.IntegrityError:
                QtWidgets.QMessageBox.warning(self, "Error", "Ya existe un entorno con ese nombre.")

    def _edit_entorno(self):
        sel = self.table.selectedItems()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Editar", "Selecciona un entorno de la lista.")
            return

        entorno_id = sel[0].data(Qt.UserRole)
        entorno = next((e for e in self._entornos_cache if e.id == entorno_id), None)
        if not entorno:
            return

        dlg = EntornoEditDialog(self, nombre=entorno.nombre, color=entorno.color, orden=entorno.orden)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            nombre, color, orden = dlg.get_values()
            if not nombre:
                QtWidgets.QMessageBox.warning(self, "Aviso", "El nombre del entorno es obligatorio.")
                return
            try:
                self.db.update_entorno(entorno_id, nombre, color, orden)
                self._refresh_table()
            except sqlite3.IntegrityError:
                QtWidgets.QMessageBox.warning(self, "Error", "Ya existe un entorno con ese nombre.")

    def _del_entorno(self):
        sel = self.table.selectedItems()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Eliminar", "Selecciona un entorno de la lista.")
            return

        entorno_id = sel[0].data(Qt.UserRole)
        if self.db.is_entorno_in_use(entorno_id):
            QtWidgets.QMessageBox.warning(self, "Error", "No se puede eliminar un entorno que está asignado a uno o más servicios.")
            return

        if QtWidgets.QMessageBox.question(self, "Confirmar", "¿Eliminar el entorno seleccionado?") == QtWidgets.QMessageBox.Yes:
            self.db.delete_entorno(entorno_id)
            self._refresh_table()


# ==========================
# Main Window
# ==========================

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, db: Database, crypto: CryptoManager):
        super().__init__()
        self.db = db
        self.crypto = crypto
        self.setWindowTitle("Pwd MacGiver")

        # Timer for debouncing column width saves
        self.column_resize_timer = QtCore.QTimer(self)
        self.column_resize_timer.setSingleShot(True)
        self.column_resize_timer.timeout.connect(self._save_column_widths)

        self._set_icon()
        self._build_ui()
        self._refresh_table()
        self._apply_initial_size()

    def _set_icon(self):
        try:
            if getattr(sys, 'frozen', False):
                # Path for PyInstaller bundle
                base_path = sys._MEIPASS
            else:
                # Path for running from source
                base_path = os.path.abspath(os.path.dirname(__file__))
            
            icon_path = os.path.join(base_path, "icon.png")

            if os.path.exists(icon_path):
                self.setWindowIcon(QtGui.QIcon(icon_path))
            else:
                icon = self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogInfoView)
                self.setWindowIcon(icon)
        except Exception:
            icon = self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogInfoView)
            self.setWindowIcon(icon)

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        vbox = QtWidgets.QVBoxLayout(central)

        # Top bar
        top = QtWidgets.QHBoxLayout()
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Buscar servicio...")
        self.search_edit.textChanged.connect(self._filter_table)
        btn_add = QtWidgets.QPushButton("Añadir")
        btn_edit = QtWidgets.QPushButton("Modificar")
        btn_del = QtWidgets.QPushButton("Eliminar")
        btn_clone = QtWidgets.QPushButton("Duplicar")
        btn_entornos = QtWidgets.QPushButton("Entornos")
        btn_settings = QtWidgets.QPushButton("Configuración")

        btn_add.clicked.connect(self._add_service)
        btn_edit.clicked.connect(self._edit_selected)
        btn_del.clicked.connect(self._delete_selected)
        btn_clone.clicked.connect(self._clone_selected)
        btn_entornos.clicked.connect(self._open_entornos)
        btn_settings.clicked.connect(self._open_settings)

        top.addWidget(self.search_edit, 1)
        top.addWidget(btn_add)
        top.addWidget(btn_edit)
        top.addWidget(btn_del)
        top.addWidget(btn_clone)
        top.addWidget(btn_entornos)
        top.addWidget(btn_settings)

        # Table
        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Servicio", "Usuario", "Contraseña", "Servidor", "BBDD"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._copy_cell)
        self.table.horizontalHeader().sectionResized.connect(self._on_column_resized)
        self.table.setStyleSheet("""
            QTableView {
                font-size: 12pt;
                font-family: 'Lucida Console';
            }
            """
        )
        # Copy banner
        self.banner = QtWidgets.QLabel("")
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setVisible(False)
        self.banner.setStyleSheet(
            "background:#065f46; color:#ecfdf5; padding:8px; border-radius:10px; font-weight:600;"
        )

        vbox.addLayout(top)
        vbox.addWidget(self.table, 1)
        vbox.addWidget(self.banner)

        # Footer
        foot = QtWidgets.QHBoxLayout()
        foot.addStretch(1)
        self.count_label = QtWidgets.QLabel("")
        foot.addWidget(self.count_label)
        vbox.addLayout(foot)

        # Style
        self.setStyleSheet(
            """
            QMainWindow { background: #0b1220; }
            QWidget { color: #e5e7eb; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:10px; padding:8px 10px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:10px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            QTableView { background:#0f172a; alternate-background-color:#0c1222; gridline-color:#1f2937; }
            QHeaderView::section { background:#111827; color:#e5e7eb; border:0; padding:6px; }
            """
        )

    def _apply_initial_size(self):
        try:
            w = int(self.db.get_config("win_width", "1000"))
            h = int(self.db.get_config("win_height", "600"))
        except Exception:
            w, h = 1000, 600
        self.resize(w, h)

    def _apply_column_widths(self):
        widths_str = self.db.get_config("table_col_widths")
        if widths_str:
            try:
                widths = [int(w) for w in widths_str.split(",")]
                if len(widths) == self.table.columnCount():
                    for i, width in enumerate(widths):
                        self.table.setColumnWidth(i, width)
                else:
                    self.table.horizontalHeader().setStretchLastSection(True)
            except (ValueError, IndexError):
                self.table.horizontalHeader().setStretchLastSection(True)
        else:
            self.table.horizontalHeader().setStretchLastSection(True)

    def _on_column_resized(self, logicalIndex: int, oldSize: int, newSize: int):
        self.column_resize_timer.start(500)

    def _save_column_widths(self):
        widths = [str(self.table.columnWidth(i)) for i in range(self.table.columnCount())]
        self.db.set_config("table_col_widths", ",".join(widths))

    # ------- Data loading & filtering -------
    def _refresh_table(self):
        self._services_cache = self.db.list_services()
        self._populate_table(self._services_cache)

    def _populate_table(self, services: list[Database.Service]):
        self.table.setRowCount(0)
        for svc in services:
            row = self.table.rowCount()
            self.table.insertRow(row)
            # Decrypt
            username = self._safe_decrypt(svc.username)
            password = self._safe_decrypt(svc.password)
            server = self._safe_decrypt(svc.server)
            database = self._safe_decrypt(svc.database)

            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(svc.service_name))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(username or ""))
            # Mask the password visually
            masked = "•" * min(len(password or ""), 10)
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(masked))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(server or ""))
            self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(database or ""))
            # Store the real decrypted values as data for easy copying
            self.table.item(row, 1).setData(Qt.UserRole, username or "")
            self.table.item(row, 2).setData(Qt.UserRole, password or "")
            self.table.item(row, 3).setData(Qt.UserRole, server or "")
            self.table.item(row, 4).setData(Qt.UserRole, database or "")
            # Keep service id in row for edit/delete
            self.table.item(row, 0).setData(Qt.UserRole + 1, svc.id)

            if svc.entorno_color:
                color = QtGui.QColor(svc.entorno_color)
                for i in range(self.table.columnCount()):
                    self.table.item(row, i).setBackground(color)

        self.count_label.setText(f"{self.table.rowCount()} servicios")
        self._apply_column_widths()

    def _safe_decrypt(self, blob: bytes | None) -> str | None:
        if blob is None:
            return None
        try:
            return self.crypto.decrypt(blob)
        except InvalidToken:
            return "<ERROR>"

    def _filter_table(self, text: str):
        text_low = text.lower().strip()
        if not text_low:
            self._populate_table(self._services_cache)
            return
        filtered: list[Database.Service] = []
        for s in self._services_cache:
            # decrypt minimal fields for filtering
            try:
                u = (self.crypto.decrypt(s.username) if s.username else "") or ""
                srv = (self.crypto.decrypt(s.server) if s.server else "") or ""
                dbn = (self.crypto.decrypt(s.database) if s.database else "") or ""
            except InvalidToken:
                u, srv, dbn = "", "", ""
            if (
                text_low in s.service_name.lower()
                or text_low in u.lower()
                or text_low in srv.lower()
                or text_low in dbn.lower()
            ):
                filtered.append(s)
        self._populate_table(filtered)

    # ------- Copy behavior -------
    def _copy_cell(self, index: QtCore.QModelIndex):
        row = index.row()
        col = index.column()
        item = self.table.item(row, col)
        if item is None:
            return
        # Only copy non-empty
        itemservicio = self.table.item(row, 0)
        servicio = itemservicio.text() if itemservicio else ""

        data = item.data(Qt.UserRole)
        if data is None:
            # for service name (col 0), copy its text
            data = item.text() if col == 0 else ""
        if not data:
            return
        QtGui.QGuiApplication.clipboard().setText(data)
        if col == 0:
            msg = f"Servicio {data} copiado"
        elif col == 1:
            msg = f"Usuario {data} copiado"
        elif col == 2:
            msg = f"Contraseña {servicio} copiada"
        elif col == 3:
            msg = f"Servidor {data} copiado"
        else:
            msg = f"BBDD {data} copiada"
        self._show_banner(msg)

    def _show_banner(self, text: str):
        self.banner.setText(text)
        self.banner.setVisible(True)
        QtCore.QTimer.singleShot(1500, lambda: self.banner.setVisible(False))

    # ------- CRUD -------
    def _add_service(self):
        entornos = self.db.list_entornos()
        dlg = ServiceDialog(self, title="Añadir servicio", entornos=entornos)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            name, user, pwd, srv, dbn, entorno_id = dlg.get_values()
            if not name:
                QtWidgets.QMessageBox.warning(self, "Aviso", "El nombre del servicio es obligatorio")
                return
            svc = Database.Service(
                id=None,
                service_name=name,
                username=self.crypto.encrypt(user) if user else None,
                password=self.crypto.encrypt(pwd) if pwd else None,
                server=self.crypto.encrypt(srv) if srv else None,
                database=self.crypto.encrypt(dbn) if dbn else None,
                entorno_id=entorno_id,
                entorno_color=None,  # Not needed for insert
            )
            self.db.insert_service(svc)
            self._refresh_table()

    def _get_selected_service_id(self) -> int | None:
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return None
        row = sel[0].row()
        it = self.table.item(row, 0)
        return it.data(Qt.UserRole + 1) if it else None

    def _edit_selected(self):
        sid = self._get_selected_service_id()
        if sid is None:
            QtWidgets.QMessageBox.information(self, "Editar", "Selecciona una fila primero")
            return
        svc = next((s for s in self._services_cache if s.id == sid), None)
        if not svc:
            return

        # Decrypt fields for editing
        user = self._safe_decrypt(svc.username) or ""
        pwd = self._safe_decrypt(svc.password) or ""
        srv = self._safe_decrypt(svc.server) or ""
        dbn = self._safe_decrypt(svc.database) or ""

        entornos = self.db.list_entornos()
        dlg = ServiceDialog(
            self,
            title="Modificar servicio",
            service_name=svc.service_name,
            username=user,
            password=pwd,
            server=srv,
            database=dbn,
            entorno_id=svc.entorno_id,
            entornos=entornos,
        )
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            name, user, pwd, srv, dbn, entorno_id = dlg.get_values()
            if not name:
                QtWidgets.QMessageBox.warning(self, "Aviso", "El nombre del servicio es obligatorio")
                return
            svc.service_name = name
            svc.username = self.crypto.encrypt(user) if user else None
            svc.password = self.crypto.encrypt(pwd) if pwd else None
            svc.server = self.crypto.encrypt(srv) if srv else None
            svc.database = self.crypto.encrypt(dbn) if dbn else None
            svc.entorno_id = entorno_id
            self.db.update_service(svc)
            self._refresh_table()

    def _delete_selected(self):
        sid = self._get_selected_service_id()
        if sid is None:
            QtWidgets.QMessageBox.information(self, "Eliminar", "Selecciona una fila primero")
            return
        if QtWidgets.QMessageBox.question(
            self,
            "Confirmar",
            "¿Eliminar el servicio seleccionado?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        ) == QtWidgets.QMessageBox.Yes:
            self.db.delete_service(sid)
            self._refresh_table()

    def _clone_selected(self):
        sid = self._get_selected_service_id()
        if sid is None:
            QtWidgets.QMessageBox.information(self, "Duplicar", "Selecciona una fila primero")
            return
        svc = next((s for s in self._services_cache if s.id == sid), None)
        if not svc:
            return

        # Decrypt fields for editing
        user = self._safe_decrypt(svc.username) or ""
        pwd = self._safe_decrypt(svc.password) or ""
        srv = self._safe_decrypt(svc.server) or ""
        dbn = self._safe_decrypt(svc.database) or ""

        entornos = self.db.list_entornos()
        dlg = ServiceDialog(
            self,
            title="Duplicar servicio",
            service_name=f"{svc.service_name} - Copia",
            username=user,
            password=pwd,
            server=srv,
            database=dbn,
            entorno_id=svc.entorno_id,
            entornos=entornos,
        )
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            name, user, pwd, srv, dbn, entorno_id = dlg.get_values()
            if not name:
                QtWidgets.QMessageBox.warning(self, "Aviso", "El nombre del servicio es obligatorio")
                return
            new_svc = Database.Service(
                id=None,
                service_name=name,
                username=self.crypto.encrypt(user) if user else None,
                password=self.crypto.encrypt(pwd) if pwd else None,
                server=self.crypto.encrypt(srv) if srv else None,
                database=self.crypto.encrypt(dbn) if dbn else None,
                entorno_id=entorno_id,
                entorno_color=None,  # Not needed for insert
            )
            self.db.insert_service(new_svc)
            self._refresh_table()

    # ------- Settings -------
    def _open_settings(self):
        dlg = SettingsDialog(self.db, self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            self._apply_initial_size()

    def _open_entornos(self):
        dlg = EntornosDialog(self.db, self)
        dlg.exec()
        self._refresh_table()


# ==========================
# Utility: locate DB file in working directory (simple) or AppData
# ==========================

def get_db_path() -> str:
    """Devuelve la ruta del archivo vault.db junto al ejecutable o script."""
    if getattr(sys, 'frozen', False):  # ejecutándose como .exe con PyInstaller
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, DB_FILENAME)


# ==========================
# App entry
# ==========================

def main():
    app = QtWidgets.QApplication(sys.argv)

    # Set high-DPI attributes for sharper UI on Windows
    QtCore.QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QtCore.QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    db = Database(get_db_path())

    crypto = LoginDialog.get_crypto(db)
    if crypto is None:
        sys.exit(0)

    win = MainWindow(db, crypto)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
