from sharingan.base.itemlist import ItemList

class Scatter(ItemList):
    def __init__(self, parent=None):
        super(Scatter, self).__init__(parent)
        self.set_label_text('Scatter')

    def deobfuscate(self, start_ea, end_ea):
        print('Deobf Scatter') 

    def detect(self, start_ea, end_ea):
        print('Scan Internal')