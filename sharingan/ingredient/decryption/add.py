from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils

class Add(Decryption):
    """Additive byte-wise decryption (cipher - key)."""

    def __init__(self):
        super().__init__("Add")
        self.description = "Byte addition"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key (e.g., 0x13)")

        form = QFormLayout()
        form.addRow("Key", self.key_input)
        self.layout_body.addLayout(form)

    def decrypt(self, raw):
        data = bytearray(DecryptionUtils.normalize_bytes(raw))
        key = DecryptionUtils.clamp_key(DecryptionUtils.parse_key(self.key_input.text(), default=0))
        for idx, value in enumerate(data):
            data[idx] = (value + key) & 0xFF
        return DecryptionUtils.to_preview_string(bytes(data))

