from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption

try:
    from Crypto.Cipher import DES as _DES  # type: ignore
except ImportError:
    try:
        from Cryptodome.Cipher import DES as _DES  # type: ignore
    except ImportError:
        _DES = None

class Des(Decryption):
    """DES block cipher (ECB / CBC)."""

    def __init__(self):
        super().__init__("DES")
        self.description = "DES decrypt"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key bytes (8 bytes)")
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText("IV for CBC (8 bytes)")

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CBC"])
        self.mode_combo.currentTextChanged.connect(self._toggle_iv)

        form = QFormLayout()
        form.addRow("Mode", self.mode_combo)
        form.addRow("Key", self.key_input)
        form.addRow("IV", self.iv_input)
        self.layout_body.addLayout(form)
        self._toggle_iv(self.mode_combo.currentText())

    def _toggle_iv(self, mode_name: str):
        need_iv = mode_name.upper() == "CBC"
        self.iv_input.setEnabled(need_iv)

    def decrypt(self, raw):
        if _DES is None:
            raise RuntimeError("PyCryptodome DES cipher is not available.")

        data = self.normalize_bytes(raw)
        key = self._normalize_key(self.parse_byte_sequence(self.key_input.text(), fallback=b""))
        mode = self.mode_combo.currentText().upper()

        if mode == "CBC":
            iv = self.parse_byte_sequence(self.iv_input.text(), fallback=b"")
            if len(iv) not in (0, 8):
                iv = iv.ljust(8, b"\x00")[:8]
            elif len(iv) == 0:
                iv = b"\x00" * 8
            cipher = _DES.new(key, _DES.MODE_CBC, iv=iv)
        else:
            cipher = _DES.new(key, _DES.MODE_ECB)

        block_size = _DES.block_size
        aligned = self.ensure_block_multiple(data, block_size)
        decrypted = cipher.decrypt(aligned)
        return self.to_preview_string(decrypted)

    @staticmethod
    def _normalize_key(key: bytes) -> bytes:
        if not key:
            return b"\x00" * 8
        if len(key) < 8:
            return key.ljust(8, b"\x00")
        return key[:8]

