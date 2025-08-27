import os
import sqlite3
import typing as t

from PySide6 import QtCore, QtGui, QtWidgets

from .crypto import CryptoManager
from .database import Database, META_SALT_KEY, META_VERIFIER_KEY


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
            '''
            QDialog { background: #0f172a; color: #e2e8f0; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            QLabel { color:#e5e7eb; }
            '''
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
        self.entorno_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        self.entorno_combo.setMinimumWidth(100)
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
            '''
            QDialog { background:#0f172a; color:#e2e8f0; }
            QLineEdit, QComboBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView { background-color: #111827; border: 1px solid #334155; color: #e2e8f0; }
            QFormLayout > QLabel { color:#e5e7eb; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            '''
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
            '''
            QDialog { background:#0f172a; color:#e2e8f0; }
            QSpinBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            '''
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
            '''
            QDialog { background:#0f172a; color:#e2e8f0; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QSpinBox { background:#111827; border:1px solid #334155; border-radius:8px; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            '''
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
        btn_close = QtWidgets.QPushButton("Cerrar")

        btn_add.clicked.connect(self._add_entorno)
        btn_edit.clicked.connect(self._edit_entorno)
        btn_del.clicked.connect(self._del_entorno)
        btn_close.clicked.connect(self.accept)

        btn_layout.addWidget(btn_add)
        btn_layout.addWidget(btn_edit)
        btn_layout.addWidget(btn_del)
        btn_layout.addStretch(1)
        btn_layout.addWidget(btn_close)

        layout.addWidget(self.table)
        layout.addLayout(btn_layout)
        self.setStyleSheet(
            '''
            QDialog { background:#0f172a; color:#e2e8f0; }
            QTableView { background:#0f172a; alternate-background-color:#0c1222; gridline-color:#1f2937; }
            QHeaderView::section { background:#111827; color:#e5e7eb; border:0; padding:6px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            '''
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
            self.table.item(row, 0).setData(QtCore.Qt.UserRole, entorno.id)

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

        entorno_id = sel[0].data(QtCore.Qt.UserRole)
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

        entorno_id = sel[0].data(QtCore.Qt.UserRole)
        if self.db.is_entorno_in_use(entorno_id):
            QtWidgets.QMessageBox.warning(self, "Error", "No se puede eliminar un entorno que está asignado a uno o más servicios.")
            return

        if QtWidgets.QMessageBox.question(self, "Confirmar", "¿Eliminar el entorno seleccionado?") == QtWidgets.QMessageBox.Yes:
            self.db.delete_entorno(entorno_id)
            self._refresh_table()


class ChangePasswordDialog(QtWidgets.QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("Cambiar Contraseña Maestra")
        self.setModal(True)
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()

        self.old_pass_edit = QtWidgets.QLineEdit()
        self.old_pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.new_pass_edit = QtWidgets.QLineEdit()
        self.new_pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_pass_edit = QtWidgets.QLineEdit()
        self.confirm_pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)

        form.addRow("Contraseña actual:", self.old_pass_edit)
        form.addRow("Nueva contraseña:", self.new_pass_edit)
        form.addRow("Confirmar nueva:", self.confirm_pass_edit)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        layout.addLayout(form)
        layout.addWidget(btns)

        self.setStyleSheet(
            '''
            QDialog { background:#0f172a; color:#e2e8f0; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:8px; padding:8px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:8px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            '''
        )

    def get_passwords(self) -> tuple[str, str, str]:
        return self.old_pass_edit.text(), self.new_pass_edit.text(), self.confirm_pass_edit.text()
