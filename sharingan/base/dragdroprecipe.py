from PySide6.QtCore import QDataStream, Qt
from PySide6.QtGui import QDrag
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QAbstractItemView, QListView
from sharingan.base.itemlist import ItemList
import importlib, inspect, os
import idaapi


class DragDropRecipe(QListWidget):
    def __init__(self, parent=None):
        super(DragDropRecipe, self).__init__(parent)
        self.setDragDropMode(QAbstractItemView.DragDrop)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setSelectionMode(QListView.ExtendedSelection)

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasText() or mime.hasFormat('application/x-qabstractitemmodeldatalist'):
            event.acceptProposedAction()
        else:
            event.ignore()

    def mimeData(self, items):
        """Override mimeData to ensure proper serialization of item data."""
        mime = super(DragDropRecipe, self).mimeData(items)
        if items:
            item = items[0]  # Handle single item for simplicity
            text = item.text()  # Assuming the item's text is the id_algorithm
            mime.setText(text)
            # Optionally, add custom data to ensure id_algorithm is included
            mime.setData('application/x-id-algorithm', text.encode('utf-8'))
        return mime

    def startDrag(self, supportedActions):
        """Initiate the drag operation."""
        item = self.currentItem()
        if item is None:
            return
        row = self.row(item)
        mime = self.mimeData([item])
        drag = QDrag(self)
        drag.setMimeData(mime)
        drop_action = drag.exec(Qt.MoveAction)
        if drop_action == Qt.MoveAction:
            self.takeItem(row)  # Remove item after successful move
            print(f"Removed item at row {row}")

    def dropEvent(self, event):
        """Handle drop event and extract id_algorithm."""
        mime = event.mimeData()
        
        # Check for custom MIME type first
        if mime.hasFormat('application/x-id-algorithm'):
            id_algorithm = mime.data('application/x-id-algorithm').decode('utf-8')
            # print(f"Custom MIME data: id_algorithm={id_algorithm}")
        elif mime.hasFormat('application/x-qabstractitemmodeldatalist'):
            # Fallback to standard MIME type
            id_algorithm = None
            stream = QDataStream(mime.data('application/x-qabstractitemmodeldatalist'))
            while not stream.atEnd():
                row = stream.readInt32()  # Use Int32 instead of Int8 for row/col
                col = stream.readInt32()
                item_data = {}
                for _ in range(stream.readInt32()):  # Number of data entries
                    role = stream.readInt32()
                    value = stream.readQVariant()
                    item_data[role] = value
                    if role == Qt.DisplayRole:
                        id_algorithm = value
                        print(f"Stream data: id_algorithm={id_algorithm}")
            # print(f"Parsed item data: {item_data}")
        else:
            event.ignore()
            return

        # Insert item to list widget
        if id_algorithm:
            obj_algorithm = self.classify_algorithm(id_algorithm)
            if isinstance(obj_algorithm, ItemList):
                list_adapter_item = QListWidgetItem()
                list_adapter_item.setSizeHint(obj_algorithm.sizeHint())
                to_index = self.count()
                ix = self.indexAt(event.pos())
                if ix.isValid():
                    to_index = ix.row()
                self.insertItem(to_index, list_adapter_item)
                self.setItemWidget(list_adapter_item, obj_algorithm)
            event.acceptProposedAction()
        else:
            # Handle reordering
            if self.row(self.itemAt(event.pos())) == self.currentRow() + 1:
                event.ignore()
            else:
                super(DragDropRecipe, self).dropEvent(event)

    def classify_algorithm(self, algorithm):
        """Load and classify the algorithm from a module."""
        path_plugin = idaapi.get_ida_subdirs("plugins")
        for path in path_plugin:
            path_module = os.path.join(path, 'sharingan', 'ingredient', f'{algorithm}.py')
            if os.path.isfile(path_module):
                try:
                    module = importlib.import_module(f"sharingan.ingredient.{algorithm}")
                    for name_class, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, ItemList) and obj != ItemList:
                            return obj()
                except Exception as e:
                    print(f"Error loading module {algorithm}: {e}")
        return None