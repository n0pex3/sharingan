from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QSplitter
from PySide6.QtCore import Qt
from sharingan.core import stylesmanager
from sharingan.core.operation import Operation
from sharingan.core.recipe import Recipe
from sharingan.core.disassembler import Disassembler


class MainWindow(QMainWindow):
    def __init__(self, objEP, parent=None):
        super(MainWindow, self).__init__(parent)

        self.operation = Operation()
        self.disassembler = Disassembler()
        self.recipe = Recipe(disassembler=self.disassembler)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.operation)
        self.splitter.addWidget(self.recipe)
        self.splitter.addWidget(self.disassembler)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setStretchFactor(2, 3)
        self.splitter.setStyleSheet(stylesmanager.get_stylesheet())
        self.splitter.setChildrenCollapsible(False)
        operation_width = self.operation.list_operation.sizeHint().width()
        self.splitter.setSizes([operation_width, 2 * operation_width, 4 * operation_width])

        self.layout_panel = QHBoxLayout()
        self.layout_panel.addWidget(self.splitter)
        objEP.parent.setLayout(self.layout_panel)

