from PySide6.QtWidgets import QFormLayout, QSpinBox
from sharingan.base.ingredient import Decryption

class Rol(Decryption):
    """Rotate each byte left by N bits."""

    def __init__(self):
        super().__init__("Rol")
        self.description = "Rotate left"
        self.version = "1.0"

        self.shift_spin = QSpinBox()
        self.shift_spin.setRange(0, 31)
        self.shift_spin.setValue(1)

        form = QFormLayout()
        form.addRow("Shift (bits)", self.shift_spin)
        self.layout_body.addLayout(form)

    @staticmethod
    def _rotl(value: int, shift: int, width: int = 8) -> int:
        if width <= 0:
            return value
        shift %= width
        mask = (1 << width) - 1
        return ((value << shift) | (value >> (width - shift))) & mask

    def decrypt(self, raw):
        data = bytearray(self.normalize_bytes(raw))
        shift = self.shift_spin.value() % 8
        if not data or shift == 0:
            return self.to_preview_string(bytes(data))
        for idx, value in enumerate(data):
            data[idx] = self._rotl(value, shift, 8)
        return self.to_preview_string(bytes(data))
