from PySide6.QtWidgets import QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption

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
        data = bytearray(self.normalize_bytes(raw))
        key = self.clamp_key(self.parse_key(self.key_input.text(), default=0))
        for idx, value in enumerate(data):
            data[idx] = (value + key) & 0xFF
        return self.to_preview_string(bytes(data))

