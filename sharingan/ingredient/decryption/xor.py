from sharingan.base.ingredient import Decryption


class Xor(Decryption):
    def __init__(self):
        super().__init__('Xor')
        self.description = 'Xor'
        self.version = '1.0'

    def preview(self):
        print('Xor')