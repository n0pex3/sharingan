from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils

class Xor(Decryption):
    def __init__(self):
        super().__init__("Xor")
        self.description = "Xor"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key (e.g., 0xFF)")
        form = QFormLayout()
        form.addRow("Key", self.key_input)
        self.layout_body.addLayout(form)

    def decrypt(self, raw):
        data = DecryptionUtils.normalize_bytes(raw)
        key = DecryptionUtils.clamp_key(DecryptionUtils.parse_key(self.key_input.text(), default=0))
        out = bytearray()
        for byte_val in data:
            out.append(byte_val ^ key)
        return DecryptionUtils.to_preview_string(out)