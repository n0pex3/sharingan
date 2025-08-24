from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class Irrelevant(CustomItemBase):
    def __init__(self, parent=None):
        super(Irrelevant, self).__init__(parent)
        self.set_label_text('Irrelevant')

    def deob(self, addr):
        print('Deobf Irrelevant', addr)

    def scan_internal(self):
        print('Scan Internal')