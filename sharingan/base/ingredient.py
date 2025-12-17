from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QCheckBox, QHBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from abc import abstractmethod
import string
from sharingan.core.stylesmanager import ManageStyleSheet
from sharingan.base.obfuscatedregion import ListObfuscatedRegion


class Ingredient(QWidget):
    def __init__(self, label: str = "UnnamedModule"):
        super().__init__()
        self.name = label
        self.description = "Description"
        self.version = "1.0"

        self.setup_ui()

    # define all things relative ui in setup_ui
    def setup_ui(self):
        self.lbl_name = QLabel(self.name)
        self.lbl_name.setObjectName('header_ingredient_recipe')
        self.chk_active = QCheckBox()
        self.chk_active.toggled.connect(self.active_ingredient)
        self.layout_header = QHBoxLayout()
        self.layout_header.addWidget(self.lbl_name)
        self.layout_header.addStretch()
        self.layout_header.addWidget(self.chk_active)
        self.layout_body = QVBoxLayout()

        self.layout = QVBoxLayout()
        self.layout.addLayout(self.layout_header)
        self.layout.addLayout(self.layout_body)
        self.setLayout(self.layout)

    # active/disable ingredient in recipe when check/uncheck
    def active_ingredient(self, checked):
        if checked:
            self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
            self.setStyleSheet("""
                QListWidget#list_recipe * {
                    background-color: rgb(189, 189, 189);
                }
            """)
        else:
            self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
            self.setStyleSheet(ManageStyleSheet.get_stylesheet())

        for child in self.findChildren(QWidget):
            if child is not self.chk_active:
                child.setEnabled(not checked)
        self.chk_active.setEnabled(True)


class Deobfuscator(Ingredient):
    def __init__(self, label):
        super().__init__(label)
        self.possible_obfuscation_regions = ListObfuscatedRegion()

    @abstractmethod
    def scan(self, start_ea: int, end_ea: int) -> ListObfuscatedRegion:
        raise NotImplementedError('Must be implement method scan')


class Decryption(Ingredient):
    def __init__(self, label):
        super().__init__(label)

    @staticmethod
    def clamp_key(key: int, item_size: int = 1):
        bits = max(1, item_size) * 8
        mask = (1 << bits) - 1
        return key & mask

    @staticmethod
    def normalize_bytes(value):
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("latin-1", errors="ignore")
        return bytes(value)

    @staticmethod
    def parse_key(text: str, default: int = 0):
        if not text:
            return default
        try:
            return int(text, 0)
        except Exception:
            return default

    @staticmethod
    def parse_byte_sequence(text: str, fallback: bytes = b"") -> bytes:
        if not text:
            return fallback
        value = text.strip()
        if not value:
            return fallback
        normalized = value.replace(" ", "").replace("_", "")
        try:
            if normalized.lower().startswith("0x"):
                normalized = normalized[2:]
            if normalized and all(ch in string.hexdigits for ch in normalized):
                if len(normalized) % 2:
                    normalized = "0" + normalized
                return bytes.fromhex(normalized)
        except ValueError:
            pass
        return value.encode("latin-1", errors="ignore")

    @staticmethod
    def ensure_block_multiple(data: bytes, block_size: int) -> bytes:
        if block_size <= 0:
            return data
        remainder = len(data) % block_size
        if remainder == 0:
            return data
        padding = b"\x00" * (block_size - remainder)
        return data + padding

    @staticmethod
    def to_preview_string(data: bytes):
        if not data:
            return data
        idx = data.find(b"\x00")
        cleaned = data if idx == -1 else data[:idx]
        try:
            return cleaned.decode("utf-8")
        except UnicodeDecodeError:
            return cleaned.decode("latin-1", errors="replace")
    
    @abstractmethod
    def decrypt(self, raw):
        raise NotImplementedError('Must be implement method decrypt')
