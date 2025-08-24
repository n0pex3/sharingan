from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class DeadLoop(CustomItemBase):
    def __init__(self, parent=None):
        super(DeadLoop, self).__init__(parent)
        self.set_label_text('DeadLoop')

    def deob(self, addr):
        print('Deobf DeadLoop', addr)

    def scan_internal(self):
        print('Scan Internal')