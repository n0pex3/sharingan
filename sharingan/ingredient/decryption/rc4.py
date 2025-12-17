from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption

class Rc4(Decryption):
    """RC4 stream cipher decryption."""

    def __init__(self):
        super().__init__("RC4")
        self.description = "RC4 stream"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key bytes (e.g., 0x112233 or key)")

        form = QFormLayout()
        form.addRow("Key", self.key_input)
        self.layout_body.addLayout(form)

    def decrypt(self, raw):
        data = self.normalize_bytes(raw)
        key = self.parse_byte_sequence(self.key_input.text(), fallback=b"\x00")
        if not key:
            key = b"\x00"
        return self.to_preview_string(self._rc4(key, data))

    @staticmethod
    def _rc4(key: bytes, data: bytes) -> bytes:
        s = list(range(256))
        j = 0
        key_len = len(key)
        if key_len == 0:
            key = b"\x00"
            key_len = 1
        for i in range(256):
            j = (j + s[i] + key[i % key_len]) & 0xFF
            s[i], s[j] = s[j], s[i]
        i = j = 0
        out = bytearray()
        for byte in data:
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) & 0xFF]
            out.append(byte ^ k)
        return bytes(out)

