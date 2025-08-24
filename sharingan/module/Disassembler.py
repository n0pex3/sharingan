from PyQt5.QtWidgets import QTabWidget, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QHBoxLayout
from sharingan.module import StylesManager
import idaapi, idc

class Disassembler(QTabWidget):
    def __init__(self, parent=None):
        super(Disassembler, self).__init__(parent)
        self.setTabsClosable(True) 
        self.setMovable(True)
        self.setObjectName('disassembler')
        self.setStyleSheet(StylesManager.get_stylesheet())
        self.tabCloseRequested.connect(self.close_tab)
        self.tabBar().tabMoved.connect(self.on_tab_moved)
        self.tab_line_edits = []

        self.add_new_tab()

    def add_new_tab(self):
        tab_content = QWidget()
        layout = QVBoxLayout(tab_content)
        
        lbl_address = QLabel('Address')
        edt_address = QLineEdit()
        edt_address.setPlaceholderText('Input function')
        btn_choose = QPushButton('Choose')
        btn_choose.clicked.connect(lambda: self.choose_function(tab_content))
        btn_add_tab = QPushButton('+')
        btn_add_tab.clicked.connect(self.add_new_tab)
        layout_toolbar = QHBoxLayout()
        layout_toolbar.setContentsMargins(10, 10, 10, 0)
        layout_toolbar.addWidget(lbl_address)
        layout_toolbar.addWidget(edt_address)
        layout_toolbar.addWidget(btn_choose)
        layout_toolbar.addWidget(btn_add_tab)
        layout.addLayout(layout_toolbar, stretch=1)
        lbl_dis = QLabel('Disassembler')
        lbl_dis.setObjectName('disassembler')
        edt_address.editingFinished.connect(lambda: self.edit_address(tab_content))
        layout.addWidget(lbl_dis, stretch=10)

        self.addTab(tab_content, f"Tab {self.count() + 1}")
        self.tab_line_edits.append(edt_address)
    
    def choose_function(self, tab_content):
        func = idaapi.choose_func("Choose function to deobfuscate", idc.get_screen_ea())
        if func is None:
            return
        
        start_func = func.start_ea
        current_index = self.indexOf(tab_content)
        if current_index != -1 and current_index < len(self.tab_line_edits):
            self.tab_line_edits[current_index].setText(hex(start_func))
            func_name = idc.get_func_name(start_func)
            tab_title = func_name if func_name else hex(start_func)
            self.setTabText(current_index, tab_title)
            lbl_dis = tab_content.findChild(QLabel, 'disassembler')
            lbl_dis.setText(str(hex(start_func)))

    def edit_address(self, tab_content):
        current_index = self.indexOf(tab_content)
        if current_index != -1 and current_index < len(self.tab_line_edits):
            addr_obfus = int(self.tab_line_edits[current_index].text(), 16)
            func_name = idc.get_func_name(addr_obfus)
            tab_title = func_name if func_name else hex(addr_obfus)
            self.setTabText(current_index, tab_title)
            lbl_dis = tab_content.findChild(QLabel, 'disassembler')
            lbl_dis.setText(str(hex(addr_obfus)))

    def close_tab(self, index):
        self.removeTab(index)
        if index < len(self.tab_line_edits):
            del self.tab_line_edits[index]

    def on_tab_moved(self, from_index, to_index):
        if from_index < len(self.tab_line_edits) and to_index < len(self.tab_line_edits):
            line_edit = self.tab_line_edits.pop(from_index)
            self.tab_line_edits.insert(to_index, line_edit)