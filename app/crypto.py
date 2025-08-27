import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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
