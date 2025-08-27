import json
import os
import sys
import typing as t

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from .crypto import CryptoManager, InvalidToken
from .database import Database
from .dialogs import (
    ChangePasswordDialog, EntornosDialog, ServiceDialog, SettingsDialog
)


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
                base_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
            
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
        btn_add = QtWidgets.QPushButton("➕ Añadir")
        btn_edit = QtWidgets.QPushButton("✏️ Modificar")
        btn_del = QtWidgets.QPushButton("🗑️ Eliminar")
        btn_clone = QtWidgets.QPushButton("📋 Duplicar")
        btn_import = QtWidgets.QPushButton("📥 Importar")
        btn_export = QtWidgets.QPushButton("📤 Exportar")
        btn_entornos = QtWidgets.QPushButton("🌐 Entornos")
        btn_settings = QtWidgets.QPushButton("⚙️ Configuración")
        btn_change_pass = QtWidgets.QPushButton("🔑 Cambiar Contraseña")

        btn_add.clicked.connect(self._add_service)
        btn_edit.clicked.connect(self._edit_selected)
        btn_del.clicked.connect(self._delete_selected)
        btn_clone.clicked.connect(self._clone_selected)
        btn_import.clicked.connect(self._import_services)
        btn_export.clicked.connect(self._export_services)
        btn_entornos.clicked.connect(self._open_entornos)
        btn_settings.clicked.connect(self._open_settings)
        btn_change_pass.clicked.connect(self._change_master_password)

        top.addWidget(self.search_edit, 1)
        top.addWidget(btn_add)
        top.addWidget(btn_edit)
        top.addWidget(btn_del)
        top.addWidget(btn_clone)
        top.addWidget(btn_import)
        top.addWidget(btn_export)
        top.addWidget(btn_entornos)
        top.addWidget(btn_settings)
        top.addWidget(btn_change_pass)

        # Table
        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Servicio", "Usuario", "Contraseña", "Servidor", "BBDD"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._copy_cell)
        self.table.horizontalHeader().sectionResized.connect(self._on_column_resized)
        self.table.setStyleSheet(
            '''
            QTableView {
                font-size: 12pt;
                font-family: 'Lucida Console';
            }
            '''
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
            '''
            QMainWindow { background: #0b1220; }
            QWidget { color: #e5e7eb; }
            QLineEdit { background:#111827; border:1px solid #334155; border-radius:10px; padding:8px 10px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:10px; padding:8px 14px; }
            QPushButton:hover { background:#374151; }
            QPushButton:pressed { background:#111827; }
            QTableView { background:#0f172a; alternate-background-color:#0c1222; gridline-color:#1f2937; }
            QHeaderView::section { background:#111827; color:#e5e7eb; border:0; padding:6px; }
            '''
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

    def _import_services(self):
        # Get file to import
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo para importar", "", "Archivos cifrados (*.json.enc);;Todos los archivos (*)"
        )
        if not filepath:
            return

        # Get password for decryption
        password, ok = QtWidgets.QInputDialog.getText(
            self, "Contraseña de importación", "Introduce la contraseña del archivo a importar:",
            echo= QtWidgets.QLineEdit.Password
        )
        if not ok or not password:
            QtWidgets.QMessageBox.warning(self, "Aviso", "La importación ha sido cancelada. Se requiere una contraseña.")
            return

        try:
            # Read and decrypt file
            with open(filepath, "rb") as f:
                salt = f.read(16)
                encrypted_data = f.read()

            file_key = CryptoManager.derive_key(password, salt)
            file_crypto = CryptoManager(file_key)
            
            try:
                decrypted_json = file_crypto.decrypt(encrypted_data)
                if decrypted_json is None:
                    raise InvalidToken
                import_data = json.loads(decrypted_json)
            except InvalidToken:
                QtWidgets.QMessageBox.critical(self, "Error", "Contraseña incorrecta o archivo corrupto.")
                return
            except (json.JSONDecodeError, UnicodeDecodeError):
                QtWidgets.QMessageBox.critical(self, "Error", "El archivo no tiene un formato JSON válido o está corrupto.")
                return

            # --- Process data ---
            self.db.conn.execute("BEGIN")

            # 1. Process Entornos
            existing_entornos = {e.nombre: e for e in self.db.list_entornos()}
            if "entornos" in import_data:
                for entorno_data in import_data["entornos"]:
                    if entorno_data.get("nombre") and entorno_data["nombre"] not in existing_entornos:
                        self.db.insert_entorno(
                            nombre=entorno_data["nombre"],
                            color=entorno_data.get("color", "#FFFFFF"),
                            orden=entorno_data.get("orden", 0)
                        )
            
            # Refresh entornos list to get new IDs
            all_entornos = {e.nombre: e for e in self.db.list_entornos()}
            entorno_name_to_id = {name: e.id for name, e in all_entornos.items()}

            # 2. Process Services (with duplicate check)
            services_added_count = 0
            services_skipped_count = 0
            existing_services_set = {(s.service_name, s.entorno_id) for s in self.db.list_services()}

            if "services" in import_data:
                for svc_data in import_data["services"]:
                    service_name = svc_data.get("service_name")
                    entorno_id = entorno_name_to_id.get(svc_data.get("entorno_nombre"))

                    if not service_name:
                        services_skipped_count += 1
                        continue

                    if (service_name, entorno_id) in existing_services_set:
                        services_skipped_count += 1
                        continue
                    
                    user = svc_data.get("username")
                    pwd = svc_data.get("password")
                    srv = svc_data.get("server")
                    dbn = svc_data.get("database")

                    new_svc = Database.Service(
                        id=None,
                        service_name=service_name,
                        username=self.crypto.encrypt(user) if user else None,
                        password=self.crypto.encrypt(pwd) if pwd else None,
                        server=self.crypto.encrypt(srv) if srv else None,
                        database=self.crypto.encrypt(dbn) if dbn else None,
                        entorno_id=entorno_id,
                        entorno_color=None,
                    )
                    self.db.insert_service(new_svc)
                    services_added_count += 1
            
            self.db.conn.commit()
            
            summary_message = f"{services_added_count} servicio(s) importado(s) correctamente."
            if services_skipped_count > 0:
                summary_message += f"\n{services_skipped_count} servicio(s) duplicado(s) fueron omitido(s)."

            QtWidgets.QMessageBox.information(self, "Éxito", summary_message)
            self._refresh_table()

        except Exception as e:
            if self.db.conn:
                self.db.conn.rollback()
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo importar el archivo: {e}")

    def _export_services(self):
        sel_rows = self.table.selectionModel().selectedRows()
        if not sel_rows:
            QtWidgets.QMessageBox.information(self, "Exportar", "Selecciona al menos un servicio para exportar.")
            return

        sids = {self.table.item(idx.row(), 0).data(Qt.UserRole + 1) for idx in sel_rows}
        services_to_export = [s for s in self._services_cache if s.id in sids]

        if not services_to_export:
            return

        # Get password for encryption
        password, ok = QtWidgets.QInputDialog.getText(
            self, "Contraseña de exportación", "Crea una contraseña para cifrar el archivo:",
            echo= QtWidgets.QLineEdit.Password
        )
        if not ok or not password:
            QtWidgets.QMessageBox.warning(self, "Aviso", "La exportación ha sido cancelada. Se requiere una contraseña.")
            return

        # Get destination file
        default_filename = "pwd-macgiver-export.json.enc"
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar exportación", default_filename, "Archivos cifrados (*.json.enc);;Todos los archivos (*)"
        )
        if not filepath:
            return

        # Gather data
        entorno_ids = {s.entorno_id for s in services_to_export if s.entorno_id is not None}
        all_entornos = self.db.list_entornos()
        entornos_to_export = [e for e in all_entornos if e.id in entorno_ids]

        export_data = {
            "entornos": [
                {"nombre": e.nombre, "color": e.color, "orden": e.orden}
                for e in entornos_to_export
            ],
            "services": [
                {
                    "service_name": s.service_name,
                    "username": self._safe_decrypt(s.username),
                    "password": self._safe_decrypt(s.password),
                    "server": self._safe_decrypt(s.server),
                    "database": self._safe_decrypt(s.database),
                    "entorno_nombre": next((e.nombre for e in all_entornos if e.id == s.entorno_id), None),
                }
                for s in services_to_export
            ]
        }

        # Encrypt and write
        try:
            salt = os.urandom(16)
            key = CryptoManager.derive_key(password, salt)
            crypto = CryptoManager(key)
            json_data = json.dumps(export_data, indent=2).encode("utf-8")
            encrypted_data = crypto.encrypt(json_data.decode("utf-8"))

            with open(filepath, "wb") as f:
                f.write(salt)
                f.write(encrypted_data)

            QtWidgets.QMessageBox.information(self, "Éxito", f"{len(services_to_export)} servicio(s) exportado(s) con éxito a:\n{filepath}")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo exportar el archivo: {e}")

    # ------- Settings ------- 
    def _open_settings(self):
        dlg = SettingsDialog(self.db, self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            self._apply_initial_size()

    def _open_entornos(self):
        dlg = EntornosDialog(self.db, self)
        dlg.exec()
        self._refresh_table()

    def _change_master_password(self):
        dlg = ChangePasswordDialog(self.db, self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            old_pass, new_pass, confirm_pass = dlg.get_passwords()

            if not all([old_pass, new_pass, confirm_pass]):
                QtWidgets.QMessageBox.warning(self, "Error", "Todos los campos son obligatorios.")
                return

            if new_pass != confirm_pass:
                QtWidgets.QMessageBox.warning(self, "Error", "Las nuevas contraseñas no coinciden.")
                return

            # Verify old password
            try:
                salt = self.db.get_meta(META_SALT_KEY)
                key = CryptoManager.derive_key(old_pass, salt)
                verifier_stored = self.db.get_meta(META_VERIFIER_KEY)
                verifier_now = QtCore.QCryptographicHash.hash(key, QtCore.QCryptographicHash.Sha256)
                if verifier_stored != verifier_now:
                    QtWidgets.QMessageBox.critical(self, "Error", "La contraseña maestra actual es incorrecta.")
                    return
            except Exception:
                QtWidgets.QMessageBox.critical(self, "Error", "Error al verificar la contraseña anterior.")
                return

            # Rekey the database
            try:
                new_crypto = self.db.rekey_database(self.crypto, new_pass)
                self.crypto = new_crypto
                self._refresh_table()
                QtWidgets.QMessageBox.information(self, "Éxito", "La contraseña maestra se ha cambiado correctamente.")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo cambiar la contraseña: {e}")
