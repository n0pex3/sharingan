from sharingan.base.ingredient import Decryption


class Sub(Decryption):
    def __init__(self):
        super().__init__('Sub')
        self.description = 'Sub'
        self.version = '1.0'

    def preview(self):
        print('Sub')