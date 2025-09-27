from sharingan.base.itemlist import ItemList

class DeadCode(ItemList):
    def __init__(self, parent=None):
        super(DeadCode, self).__init__(parent)
        self.set_label_text('DeadCode')

    def deobfuscate(self, start_ea, end_ea):
        print('Deobf DeadCode')

    def detect(self, start_ea, end_ea):
        print('Scan Internal')