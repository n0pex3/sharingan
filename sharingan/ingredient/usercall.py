from sharingan.base.itemlist import ItemList

class Usercall(ItemList):
    def __init__(self, parent=None):
        super(Usercall, self).__init__(parent)
        self.set_label_text('Usercall')

    def deobfuscate(self, start_ea, end_ea):
        print('Deobf Usercall')

    def detect(self, start_ea, end_ea):
        print('Scan Internal')