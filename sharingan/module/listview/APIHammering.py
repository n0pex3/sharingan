from sharingan.module.listview.CustomItemBase import CustomItemBase
from  sharingan.module import StylesManager

class APIHammering(CustomItemBase):
    def __init__(self, parent=None):
        super(APIHammering, self).__init__(parent)
        self.set_label_text('APIHammering')

    def deob(self, addr):
        print('Deobf APIHammering', addr)

    def scan_internal(self):
        print('Scan Internal')