from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils
from base64 import b64decode

class Base64(Decryption):
    def __init__(self):
        super().__init__("Base64")
        self.description = "Base64"
        self.version = "1.0"

    def decrypt(self, raw):
        data = DecryptionUtils.normalize_bytes(raw)
        cleaned = data.replace(b"\r", b"").replace(b"\n", b"").strip()
        # Fix padding when truncated inputs arrive from IDA strings
        if len(cleaned) % 4:
            cleaned += b"=" * (4 - (len(cleaned) % 4))
        try:
            decoded = b64decode(cleaned, validate=False)
        except Exception as exc:
            print(f"Base64 decrypt failed: {exc}")
            return raw
        return DecryptionUtils.to_preview_string(decoded)