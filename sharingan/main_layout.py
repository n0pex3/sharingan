from PyQt5.QtWidgets import QHBoxLayout, QMainWindow, QSplitter
from PyQt5.QtCore import Qt

from sharingan.module import StylesManager
from sharingan.module.Operation import Operation
from sharingan.module.Recipe import Recipe
from sharingan.module.Disassembler import Disassembler


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
        self.splitter.setStyleSheet(StylesManager.get_stylesheet())
        self.splitter.setChildrenCollapsible(False)
        self.layout_panel = QHBoxLayout()
        self.layout_panel.addWidget(self.splitter)

        objEP.parent.setLayout(self.layout_panel)
