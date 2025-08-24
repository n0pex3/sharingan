from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class DeadCode(CustomItemBase):
    def __init__(self, parent=None):
        super(DeadCode, self).__init__(parent)
        self.set_label_text('DeadCode')

    def deob(self, addr):
        print('Deobf DeadCode', addr)

    def scan_internal(self):
        print('Scan Internal')