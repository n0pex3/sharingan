from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils

class Xorstr(Decryption):
    """XOR with repeating multi-byte key."""

    def __init__(self):
        super().__init__("XorStr")
        self.description = "XOR string key"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key bytes (e.g., 0x414243 or ABC)")

        form = QFormLayout()
        form.addRow("Key", self.key_input)
        self.layout_body.addLayout(form)

    def decrypt(self, raw):
        data = bytearray(DecryptionUtils.normalize_bytes(raw))
        key_bytes = DecryptionUtils.parse_byte_sequence(self.key_input.text(), fallback=b"\x00")
        if not key_bytes:
            key_bytes = b"\x00"
        klen = len(key_bytes)
        for idx, value in enumerate(data):
            data[idx] = value ^ key_bytes[idx % klen]
        return DecryptionUtils.to_preview_string(bytes(data))

