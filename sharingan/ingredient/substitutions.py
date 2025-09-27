from sharingan.base.itemlist import ItemList

class Substitutions(ItemList):
    def __init__(self, parent=None):
        super(Substitutions, self).__init__(parent)
        self.set_label_text('Substitutions')

    def deobfuscate(self, start_ea, end_ea):
        print('Deobf Substitutions')

    def detect(self, start_ea, end_ea):
        print('Scan Internal')