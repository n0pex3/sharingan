from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QCheckBox, QHBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from abc import abstractmethod
from sharingan.core.utils import DecryptionUtils, ManageStyleSheet
from sharingan.base.obfuscatedregion import ListObfuscatedRegion


# parent class for deobfuscation and decryption
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
        self.lbl_name.setObjectName("header_ingredient_recipe")
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


# base class for deobfuscation, new class must be inherit from it
class Deobfuscator(Ingredient):
    def __init__(self, label):
        super().__init__(label)
        self.possible_obfuscation_regions = ListObfuscatedRegion()

    @abstractmethod
    def scan(self, start_ea: int, end_ea: int) -> ListObfuscatedRegion:
        raise NotImplementedError('Must be implement method scan')


# base class for decrypotion, new class must be inherit from it
class Decryption(Ingredient):
    def __init__(self, label):
        super().__init__(label)

    @abstractmethod
    def decrypt(self, raw):
        raise NotImplementedError('Must be implement method decrypt')
