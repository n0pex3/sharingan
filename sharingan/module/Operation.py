from PyQt5.QtWidgets import QWidget, QListWidgetItem, QVBoxLayout, QAbstractItemView, QListWidget
from  sharingan.module import StylesManager
import idaapi, os
            
def init_list() -> list:
    path_plugin = idaapi.get_ida_subdirs("plugins")
    for path in path_plugin:
        path_module = os.path.join(path, 'sharingan', 'module', 'listview')
        if os.path.isdir(path_module):
            list_module = os.listdir(path_module)
            ingrediet = []
            for module in list_module:
                filename, ext = os.path.splitext(module)
                if filename == 'CustomDragDropRecipe' or filename == 'CustomItemBase':
                    continue
                elif ext == '.py':
                    ingrediet.append(filename)
            return ingrediet

class Operation(QWidget):
    def __init__(self, parent=None):
        super(Operation, self).__init__(parent)

        self.list_operation = QListWidget(self)
        self.list_operation.setAcceptDrops(False)
        self.list_operation.setDragEnabled(True)
        self.list_operation.setDragDropMode(QAbstractItemView.DragDropMode.DragOnly)
        self.list_operation.setObjectName('list_operation')
        self.list_operation.setStyleSheet(StylesManager.get_stylesheet())
        
        self.list_algorithm = init_list()
        for operation in self.list_algorithm:
            QListWidgetItem(operation, self.list_operation)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.list_operation)
        self.setLayout(self.layout)
