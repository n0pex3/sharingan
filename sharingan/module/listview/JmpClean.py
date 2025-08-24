from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class JmpClean(CustomItemBase):
    def __init__(self, parent=None):
        super(JmpClean, self).__init__(parent)
        self.set_label_text('JmpClean')

    def deob(self, addr):
        print('Deobf JmpClean', addr)

    def scan_internal(self):
        print('Scan Internal')