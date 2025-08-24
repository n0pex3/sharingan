from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout
from abc import ABC, abstractmethod
from sharingan.module import StylesManager

class CustomItemBase(QWidget):
    def __init__(self, parent=None):
        super(CustomItemBase, self).__init__(parent)
        self.lbl_text = QLabel('DefaultBase')
        self.lbl_text.setObjectName('item_recipe')
        self.lbl_text.setStyleSheet(StylesManager.get_stylesheet())

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.lbl_text)
        self.setLayout(self.layout)

    def set_label_text(self, text):
        self.lbl_text.setText(text)

    @abstractmethod
    def deobf(self, addr):
        pass

    @abstractmethod
    def scan_internal(self):
        pass
