from sharingan.module.listview.CustomItemBase import CustomItemBase
from PyQt5.QtWidgets import QPushButton

class Substitutions(CustomItemBase):
    def __init__(self, parent=None):
        super(Substitutions, self).__init__(parent)
        self.set_label_text('Substitutions')

    def deob(self, addr):
        print('Deobf Substitutions', addr)

    def scan_internal(self):
        print('Scan Internal')