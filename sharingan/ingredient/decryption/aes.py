from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit
from sharingan.base.ingredient import Decryption
from sharingan.core.utils import DecryptionUtils

try:
    from Crypto.Cipher import AES as _AES  # type: ignore
except ImportError:
    try:
        from Cryptodome.Cipher import AES as _AES  # type: ignore
    except ImportError:
        _AES = None

class Aes(Decryption):
    """AES block cipher (ECB / CBC)."""

    def __init__(self):
        super().__init__("AES")
        self.description = "AES decrypt"
        self.version = "1.0"

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Key bytes (hex or ASCII)")
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText("IV for CBC (hex or ASCII)")

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
        if _AES is None:
            raise RuntimeError("PyCryptodome AES cipher is not available.")

        data = DecryptionUtils.normalize_bytes(raw)
        key = self._normalize_aes_key(DecryptionUtils.parse_byte_sequence(self.key_input.text(), fallback=b""))
        mode = self.mode_combo.currentText().upper()

        if mode == "CBC":
            iv = DecryptionUtils.parse_byte_sequence(self.iv_input.text(), fallback=b"")
            if len(iv) not in (0, 16):
                iv = iv.ljust(16, b"\x00")[:16]
            elif len(iv) == 0:
                iv = b"\x00" * 16
            cipher = _AES.new(key, _AES.MODE_CBC, iv=iv)
        else:
            cipher = _AES.new(key, _AES.MODE_ECB)

        block_size = _AES.block_size
        aligned = DecryptionUtils.ensure_block_multiple(data, block_size)
        decrypted = cipher.decrypt(aligned)
        return DecryptionUtils.to_preview_string(decrypted)

    @staticmethod
    def _normalize_aes_key(key: bytes) -> bytes:
        if not key:
            return b"\x00" * 16
        for size in (16, 24, 32):
            if len(key) <= size:
                return key.ljust(size, b"\x00")
        return key[:32]

