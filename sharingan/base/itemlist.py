from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout
from abc import abstractmethod
from sharingan.core import stylesmanager
from sharingan.base.listrangeaddr import RangeAddr, ListRangeAddr


class ItemList(QWidget):
    def __init__(self, parent=None):
        super(ItemList, self).__init__(parent)
        self.list_possible_obfus = ListRangeAddr(RangeAddr)

        self.lbl_name = QLabel('DefaultBase')
        self.lbl_name.setObjectName('item_recipe')
        self.lbl_name.setProperty('theme', stylesmanager.get_theme())
        self.lbl_name.setStyleSheet(stylesmanager.get_stylesheet())

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.lbl_name)
        self.setLayout(self.layout)

    def set_label_text(self, text):
        self.lbl_name.setText(text)

    @abstractmethod
    def deobfuscate(self, start_ea=None, end_ea=None):
        pass

    @abstractmethod
    def detect(self, start_ea=None, end_ea=None):
        pass
