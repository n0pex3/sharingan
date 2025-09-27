from sharingan.base.itemlist import ItemList

class DeadLoop(ItemList):
    def __init__(self, parent=None):
        super(DeadLoop, self).__init__(parent)
        self.set_label_text('DeadLoop')

    def deobfuscate(self, start_ea, end_ea):
        print('Deobf DeadLoop')

    def detect(self, start_ea, end_ea):
        print('Scan Internal')