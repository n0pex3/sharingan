from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QSplitter
from PySide6.QtCore import Qt
from sharingan.core.utils import ManageStyleSheet
from sharingan.core.operation import Operation
from sharingan.core.recipe import Recipe
from sharingan.core.disassembler import Disassembler


class MainWindow(QMainWindow):
    def __init__(self, objEP):
        super().__init__()

        self.disassembler = Disassembler()
        self.recipe = Recipe(disassembler=self.disassembler)
        self.operation = Operation(recipe=self.recipe)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.operation)
        self.splitter.addWidget(self.recipe)
        self.splitter.addWidget(self.disassembler)

        self.splitter.setCollapsible(0, False)
        self.splitter.setCollapsible(1, False)
        self.splitter.setCollapsible(2, True)

        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setStretchFactor(2, 3)
        self.splitter.setStyleSheet(ManageStyleSheet.get_stylesheet())

        self.recipe.chk_compact.stateChanged.connect(self.toggle_compact)
        self.splitter.setChildrenCollapsible(False)
        operation_width = self.operation.list_decryption.sizeHint().width()
        self.splitter.setSizes([operation_width, 1.5 * operation_width, 4 * operation_width])

        self.layout_panel = QHBoxLayout()
        self.layout_panel.addWidget(self.splitter)
        objEP.parent.setLayout(self.layout_panel)

    # this mode for side by side another view of IDA (Disassembler/Decompiler)
    def toggle_compact(self):
        if self.recipe.chk_compact.isChecked():
            self.disassembler.hide()
            sizes = self.splitter.sizes()
            if len(sizes) > 2:
                sizes[2] = 0
                self.splitter.setSizes(sizes)
        else:
            self.disassembler.show()
            operation_width = self.operation.list_decryption.sizeHint().width()
            self.splitter.setSizes([operation_width, 1.5 * operation_width, 4 * operation_width])
