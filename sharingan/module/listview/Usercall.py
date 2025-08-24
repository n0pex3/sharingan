from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QLabel, QVBoxLayout
from  sharingan.module import StylesManager

class Usercall(CustomItemBase):
    def __init__(self, parent=None):
        super(Usercall, self).__init__(parent)
        self.set_label_text('Usercall')

    def deob(self, addr):
        print('Deobf Usercall', addr)

    def scan_internal(self):
        print('Scan Internal')