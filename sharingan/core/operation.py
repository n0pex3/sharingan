from PySide6.QtWidgets import QWidget, QListWidgetItem, QVBoxLayout, QAbstractItemView, QListWidget, QCheckBox, QSizePolicy, QStackedWidget, QComboBox
from sharingan.core.stylesmanager import ManageStyleSheet
import idaapi
import sys, os
            

class Operation(QWidget):
    def __init__(self, parent=None, recipe=None):
        super().__init__(parent)
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.recipe = recipe

        self.setup_ui()
        self.list_deobfuscator.setStyleSheet(ManageStyleSheet.get_stylesheet())
        self.list_decryption.setStyleSheet(ManageStyleSheet.get_stylesheet())

        # load module into list 
        deobf_items = self.get_ingredients('deobfuscator')
        self.list_deobfuscator.addItems(deobf_items)
        decrypt_items = self.get_ingredients('decryption')
        self.list_decryption.addItems(decrypt_items)

    def setup_ui(self):
        self.list_deobfuscator = QListWidget()
        self.list_deobfuscator.setAcceptDrops(False)
        self.list_deobfuscator.setDragEnabled(True)
        self.list_deobfuscator.setDragDropMode(QAbstractItemView.DragDropMode.DragOnly)
        self.list_deobfuscator.setObjectName('list_operation')

        self.list_decryption = QListWidget()
        self.list_decryption.setAcceptDrops(False)
        self.list_decryption.setDragEnabled(True)
        self.list_decryption.setDragDropMode(QAbstractItemView.DragDropMode.DragOnly)
        self.list_decryption.setObjectName('list_operation')

        self.cmb_mode = QComboBox()
        self.cmb_mode.addItems(['Deobfuscator', 'Decryption'])
        self.cmb_mode.currentIndexChanged.connect(self.change_mode)

        self.layout_stack = QStackedWidget()
        self.layout_stack.addWidget(self.list_deobfuscator)
        self.layout_stack.addWidget(self.list_decryption)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.cmb_mode)
        self.layout.addWidget(self.layout_stack)
        self.setLayout(self.layout)

    def change_mode(self, index):
        self.layout_stack.setCurrentIndex(1 if index else 0 )
        self.recipe.list_recipe.mode = 'decryption' if index else 'deobfuscator'

    # get name module in folder
    def get_ingredients(self, folder_module) -> list:
        path_plugin = idaapi.get_ida_subdirs('plugins')
        target_subpath = os.path.join('sharingan', 'ingredient', folder_module)
        for path in path_plugin:
            module_dir = os.path.join(path, target_subpath)
            if os.path.isdir(module_dir):
                sys.path.append(module_dir)
                list_module = os.listdir(module_dir)
                ingredient = []
                for module in list_module:
                    filename, ext = os.path.splitext(module)
                    if ext == '.py':
                        ingredient.append(filename.lower().capitalize())
                return ingredient
        return []


