from PySide6.QtCore import QDataStream, Qt
from PySide6.QtGui import QDrag
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QAbstractItemView, QListView
from sharingan.base.ingredient import Ingredient, Decryption, Deobfuscator
import importlib, inspect, os
import idaapi


class DragDropRecipe(QListWidget):
    def __init__(self):
        super().__init__()
        self.setDragDropMode(QAbstractItemView.DragDrop)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setSelectionMode(QListView.ExtendedSelection)

        # cache store loaded class Ingredient, prevent loading many time
        self._class_cache = {}
        self.mode = 'deobfuscator'

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasText() or mime.hasFormat('application/x-qabstractitemmodeldatalist'):
            event.acceptProposedAction()
        else:
            event.ignore()

    def mimeData(self, items):
        # get default mime data
        mime = super().mimeData(items)
        if items:
            item = items[0]  # Handle single item for simplicity
            label = item.text()  # Assuming the item's text is the id_algorithm
            mime.setText(label)
            # Optionally, add custom data to ensure id_algorithm is included
            mime.setData('application/x-id-algorithm', label.encode('utf-8'))
        return mime

    def startDrag(self, supportedActions):
        item = self.currentItem()
        if item is None:
            return
        
        row = self.row(item)
        mime = self.mimeData([item])
        drag = QDrag(self)
        drag.setMimeData(mime)
        # normal drag
        drop_action = drag.exec(Qt.MoveAction)
        # drop outside to remove
        if drop_action != Qt.MoveAction:
            self.takeItem(row)
            print(f"Removed ingredient at row {row} (dropped outside)")

    def dropEvent(self, event):
        # internal drag drop (reorder), itself processing   
        if event.source() == self:
            super().dropEvent(event)
            event.acceptProposedAction()
            return

        id_algorithm = None
        mime = event.mimeData()
        # Check for custom MIME type first
        if mime.hasFormat('application/x-id-algorithm'):
            data = mime.data('application/x-id-algorithm')
            if not data.isEmpty():
                id_algorithm = bytes(data).decode('utf-8')
        # Fallback to standard MIME type
        elif mime.hasFormat('application/x-qabstractitemmodeldatalist'):
            stream = QDataStream(mime.data('application/x-qabstractitemmodeldatalist'))
            while not stream.atEnd():
                _ = stream.readInt32() # row
                _ = stream.readInt32() # col
                map_items = stream.readInt32()
                # item_data = {}
                for _ in range(map_items):  # Number of data entries
                    role = stream.readInt32()
                    value = stream.readQVariant()
                    # item_data[role] = value
                    if role == Qt.DisplayRole:
                        id_algorithm = value
                        break
                if id_algorithm:
                    break
        else:
            event.ignore()
            return

        # Insert item to list widget
        if id_algorithm:
            obj_algorithm = self.classify_algorithm(id_algorithm)
            if obj_algorithm:
                self.insert_ingredient_recipe(obj_algorithm, event)
        else:
            # Handle reordering
            if event:
                event.ignore()

    def insert_ingredient_recipe(self, obj_algorithm, event):
        if isinstance(obj_algorithm, Deobfuscator) or isinstance(obj_algorithm, Decryption):
            list_adapter_item = QListWidgetItem()
            list_adapter_item.setSizeHint(obj_algorithm.sizeHint())
            to_index = self.count()
            if event:
                ix = self.indexAt(event.pos())
                if ix.isValid():
                    to_index = ix.row()
            self.insertItem(to_index, list_adapter_item)
            self.setItemWidget(list_adapter_item, obj_algorithm)
            if event:
                event.acceptProposedAction()

    # find module to import
    def classify_algorithm(self, algorithm_name):
        algorithm_key = algorithm_name.lower()

        if algorithm_key in self._class_cache:
            return self._class_cache[algorithm_key]()

        path_plugin = idaapi.get_ida_subdirs('plugins')
        if self.mode == 'deobfuscator':
            target_module_name = f'sharingan.ingredient.deobfuscator.{algorithm_key}'
            target_filename = os.path.join('sharingan', 'ingredient', 'deobfuscator', f'{algorithm_key}.py')
        elif self.mode == 'decryption':
            target_module_name = f'sharingan.ingredient.decryption.{algorithm_key}'
            target_filename = os.path.join('sharingan', 'ingredient', 'decryption', f'{algorithm_key}.py')
        found_class = None

        for path in path_plugin:
            path_module = os.path.join(path, target_filename)
            if os.path.isfile(path_module):
                try:
                    module = importlib.import_module(target_module_name)
                    for _, classs in inspect.getmembers(module, inspect.isclass):
                        # find module inherit parent, exclude parent
                        if issubclass(classs, Ingredient) and classs is not Ingredient and classs.__module__ == module.__name__:
                            found_class = classs
                            break
                    if found_class:
                        break
                except Exception as e:
                    print(f"Error loading module {algorithm_key}: {path_module} {e}")
        
        # cache module
        if found_class:
            self._class_cache[algorithm_key] = found_class
            return found_class()
        
        return None