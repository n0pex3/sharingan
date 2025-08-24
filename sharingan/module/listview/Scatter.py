from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class Scatter(CustomItemBase):
    def __init__(self, parent=None):
        super(Scatter, self).__init__(parent)
        self.set_label_text('Scatter')

    def deob(self, addr):
        print('Deobf Scatter', addr) 

    def scan_internal(self):
        print('Scan Internal')