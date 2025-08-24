from PyQt5.QtCore import QDataStream, Qt
from PyQt5.QtGui import QDrag
from PyQt5.QtWidgets import (QListWidget, QListWidgetItem, QAbstractItemView, QListView)
from sharingan.module.listview.Substitutions import Substitutions
from sharingan.module.listview.APIHammering import APIHammering
from sharingan.module.listview.Scatter import Scatter
from sharingan.module.listview.DeadCode import DeadCode
from sharingan.module.listview.DeadLoop import DeadLoop
from sharingan.module.listview.Irrelevant import Irrelevant
from sharingan.module.listview.JmpClean import JmpClean
from sharingan.module.listview.Usercall import Usercall


class CustomDragDropRecipe(QListWidget):
    def __init__(self, parent=None):
        super(CustomDragDropRecipe, self).__init__(parent)
        self.setDragDropMode(QAbstractItemView.DragDrop)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setSelectionMode(QListView.ExtendedSelection)


    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if (mime.hasText() or mime.hasFormat('application/x-qabstractitemmodeldatalist')):
            event.accept()
        else:
            event.ignore()

    def startDrag(self, event):
            item = self.currentItem()
            if item is None:
                return
            row = self.row(item)
            mime = self.mimeData([item])
            mime.setText(str(row))
            drag = QDrag(self)
            drag.setMimeData(mime)
            drop_action = drag.exec(Qt.MoveAction)
            if drop_action != Qt.MoveAction:
                self.takeItem(row)
                # print(f"Remove {row}")

    def dropEvent(self, event):
        mime = event.mimeData()
        if mime.hasFormat('application/x-qabstractitemmodeldatalist'):
            id_algorithm = None
            stream = QDataStream(mime.data('application/x-qabstractitemmodeldatalist'))
            while not stream.atEnd():
                # Don't use row and col but must implement
                row = stream.readInt()
                col = stream.readInt()
                for data_size in range(stream.readInt()):
                    role, value = stream.readInt(), stream.readQVariant()
                    if role == Qt.DisplayRole:
                        id_algorithm = value
            # Insert item to list widget
            if id_algorithm:
                obj_algorithm = self.classify_algorithm(id_algorithm)
                list_adapter_item = QListWidgetItem()
                list_adapter_item.setSizeHint(obj_algorithm.sizeHint())
                # Get index of recipe list to insert
                # from_index = self.currentRow()
                to_index = self.count()
                ix = self.indexAt(event.pos())
                if ix.isValid():
                    to_index = ix.row()
                self.insertItem(to_index, list_adapter_item)
                self.setItemWidget(list_adapter_item, obj_algorithm)
            # Reorder by drag and drop
            else:
                if (self.row(self.itemAt(event.pos())) == self.currentRow() + 1):
                    event.ignore()
                else:
                    super(CustomDragDropRecipe, self).dropEvent(event)

    def classify_algorithm(self, algorithm):
        switcher = {
            'Substitutions': Substitutions(),
            'APIHammering': APIHammering(),
            'Scatter': Scatter(),
            'DeadCode': DeadCode(),
            'DeadLoop': DeadLoop(),
            'Irrelevant': Irrelevant(),
            'JmpClean': JmpClean(),
            'Usercall': Usercall()
        }
        return switcher.get(algorithm, 'nothing')
