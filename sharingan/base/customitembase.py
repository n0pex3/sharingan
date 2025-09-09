from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout
from abc import abstractmethod
from sharingan.core import stylesmanager


class CustomItemBase(QWidget):
    def __init__(self, parent=None):
        super(CustomItemBase, self).__init__(parent)
        self.lbl_text = QLabel('DefaultBase')
        self.lbl_text.setObjectName('item_recipe')
        self.lbl_text.setStyleSheet(stylesmanager.get_stylesheet())

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.lbl_text)
        self.setLayout(self.layout)

    def set_label_text(self, text):
        self.lbl_text.setText(text)

    @abstractmethod
    def deobfuscate(self, start_ea=None, end_ea=None):
        pass

    @abstractmethod
    def detect(self, start_ea=None, end_ea=None):
        pass
