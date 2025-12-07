from sharingan.base.ingredient import Decryption


class Add(Decryption):
    def __init__(self):
        super().__init__('Add')
        self.description = 'Add'
        self.version = '1.0'

    def preview(self):
        print('Add')