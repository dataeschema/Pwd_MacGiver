import os
import sqlite3
from dataclasses import dataclass

from PySide6 import QtCore

from .crypto import CryptoManager

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

        # --- Schema migration for entorno_id ---
        cur = self.conn.execute("PRAGMA table_info(services)")
        columns = [row["name"] for row in cur.fetchall()]
        if "entorno_id" not in columns:
            self.conn.execute("ALTER TABLE services ADD COLUMN entorno_id INTEGER REFERENCES entornos(id) ON DELETE SET NULL")

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
            '''
            SELECT s.id, s.service_name, s.username, s.password, s.server, s.database, s.entorno_id, e.color as entorno_color
              FROM services s
              LEFT JOIN entornos e ON s.entorno_id = e.id
             ORDER BY e.orden, s.service_name
            '''
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
            '''
            INSERT INTO services(service_name, username, password, server, database, entorno_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
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
            '''
            UPDATE services
               SET service_name=?, username=?, password=?, server=?, database=?, entorno_id=?
             WHERE id=?
            ''',
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

    def rekey_database(self, old_crypto: CryptoManager, new_master_password: str) -> CryptoManager:
        services = self.list_services()
        decrypted_services = []
        for s in services:
            decrypted_services.append(
                {
                    "id": s.id,
                    "service_name": s.service_name,
                    "username": old_crypto.decrypt(s.username),
                    "password": old_crypto.decrypt(s.password),
                    "server": old_crypto.decrypt(s.server),
                    "database": old_crypto.decrypt(s.database),
                    "entorno_id": s.entorno_id,
                }
            )

        new_salt = os.urandom(16)
        new_key = CryptoManager.derive_key(new_master_password, new_salt)
        new_crypto = CryptoManager(new_key)

        try:
            self.conn.execute("BEGIN")
            for s_dec in decrypted_services:
                self.conn.execute(
                    '''
                    UPDATE services
                       SET username=?, password=?, server=?, database=?
                     WHERE id=?
                    ''',
                    (
                        new_crypto.encrypt(s_dec["username"]),
                        new_crypto.encrypt(s_dec["password"]),
                        new_crypto.encrypt(s_dec["server"]),
                        new_crypto.encrypt(s_dec["database"]),
                        s_dec["id"],
                    ),
                )
            # Update salt and verifier
            new_verifier = QtCore.QCryptographicHash.hash(new_key, QtCore.QCryptographicHash.Sha256)
            self.set_meta(META_SALT_KEY, new_salt)
            self.set_meta(META_VERIFIER_KEY, new_verifier)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return new_crypto
