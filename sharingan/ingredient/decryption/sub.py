from PySide6.QtWidgets import QFormLayout, QLineEdit

from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils


class Sub(Decryption):
    """Subtractive byte-wise decryption (key - cipher)."""

    def __init__(self):
        super().__init__("Sub")
        self.description = "Key minus cipher"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key (e.g., 0x41)")

        form = QFormLayout()
        form.addRow("Key", self.key_input)
        self.layout_body.addLayout(form)

    def decrypt(self, raw):
        data = bytearray(DecryptionUtils.normalize_bytes(raw))
        key = DecryptionUtils.clamp_key(DecryptionUtils.parse_key(self.key_input.text(), default=0))
        for idx, value in enumerate(data):
            data[idx] = (key - value) & 0xFF
        return DecryptionUtils.to_preview_string(bytes(data))

