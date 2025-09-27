from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox
from PySide6.QtCore import Qt
import PySide6.QtWidgets as QtWidgets
from sharingan.base.dragdroprecipe import DragDropRecipe
from sharingan.core import stylesmanager
import ida_segment, ida_bytes, ida_auto, ida_idaapi, idaapi, idc


class Recipe(QWidget):
    def __init__(self, disassembler=None):
        super(Recipe, self).__init__()
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        self.disassembler = disassembler
        self.list_revert_addr = set()
        self.refresh_list_revert_addr()
        self.list_recipe = DragDropRecipe(self)
        self.list_recipe.setObjectName('list_recipe')
        self.list_recipe.setProperty('theme', stylesmanager.get_theme())
        self.list_recipe.setStyleSheet(stylesmanager.get_stylesheet())

        self.btn_delete = QPushButton('Delete')
        self.btn_delete.clicked.connect(self.delete)
        self.btn_cook = QPushButton('Cook')
        self.btn_cook.clicked.connect(self.cook)
        self.btn_apply = QPushButton('Apply')
        self.btn_apply.clicked.connect(self.apply)
        self.cmb_todo = QComboBox(self)
        self.cmb_todo.activated.connect(self.change_addr_to)
        self.cmb_todo.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.btn_resolve = QPushButton('Resolve', self)
        self.btn_resolve.clicked.connect(self.resolve)

        self.layout_button = QHBoxLayout()
        self.layout_button.addWidget(self.cmb_todo)
        self.layout_button.addWidget(self.btn_resolve)
        self.layout_button.addWidget(self.btn_delete)
        self.layout_button.addWidget(self.btn_apply)
        self.layout_button.setAlignment(Qt.AlignRight)

        self.start_ea = 0x0
        self.end_ea = 0x0

        self.layout = QVBoxLayout()
        self.layout.addLayout(self.layout_button)
        self.layout.addWidget(self.list_recipe)
        self.layout.addWidget(self.btn_cook)
        self.setLayout(self.layout)

    def delete(self):
        list_indexes = self.list_recipe.selectedIndexes()
        if list_indexes:
            for index in list_indexes:
                item = self.list_recipe.itemFromIndex(index)
                self.list_recipe.removeItemWidget(item)
                self.list_recipe.takeItem(index.row())
        else:
            for i in range(self.list_recipe.count()):
                item = self.list_recipe.item(i)
                self.list_recipe.removeItemWidget(item)
            self.list_recipe.clear()

    def apply(self):
        self.apply_or_scan(True)
        self.refresh_list_revert_addr()
        ida_auto.auto_mark_range(self.start_ea, self.end_ea, ida_auto.AU_CODE)
        ida_auto.plan_and_wait(self.start_ea, self.end_ea, True)

    def scan(self):
        self.apply_or_scan(False)

    def cook(self):
        if self.list_recipe.count() != 0:
            for i in range(self.list_recipe.count()):
                item = self.list_recipe.item(i)
                ingredient = self.list_recipe.itemWidget(item)
                if ingredient and hasattr(ingredient, 'deobfuscate'):
                    segment = ida_segment.get_first_seg()
                    while segment is not None:
                        if segment.perm & ida_segment.SEGPERM_EXEC:
                            self.start_ea = segment.start_ea
                            self.end_ea = segment.end_ea
                            ingredient.deobfuscate(self.start_ea, self.end_ea)
                        segment = ida_segment.get_next_seg(segment.start_ea)
            ida_auto.auto_mark_range(self.start_ea, self.end_ea, ida_auto.AU_CODE)
            ida_auto.plan_and_wait(self.start_ea, self.end_ea, True)
        self.refresh_list_revert_addr()

    def apply_or_scan(self, is_apply):
        active_index = self.disassembler.currentIndex()
        input_start, input_end = self.disassembler.get_tab_line_edit_texts(active_index)
        self.disassembler.clear_tab_addr_highlight(active_index)
        self.start_ea = int(input_start, 16)
        self.end_ea = int(input_end, 16)
        if self.list_recipe.count() != 0:
            for i in range(self.list_recipe.count()):
                item = self.list_recipe.item(i)
                ingredient = self.list_recipe.itemWidget(item)
                if is_apply and ingredient and hasattr(ingredient, 'deobfuscate'):
                    ingredient.deobfuscate(self.start_ea, self.end_ea)
                elif ingredient and hasattr(ingredient, 'detect'):
                    ingredient.detect(self.start_ea, self.end_ea)

    def resolve(self):
        index = self.cmb_todo.currentIndex()
        if index != -1:
            self.cmb_todo.removeItem(index)

    def append_addr_combobox(self, ea_hint):
        self.cmb_todo.addItem(ea_hint)

    def exclude_fp(self, ea):
        is_revert = True
        for i in range(self.cmb_todo):
            possible_obfus = self.cmb_todo.itemText(i)
            start_obfus = int(possible_obfus.split(' - ')[0], 0)
            end_obfus = int(possible_obfus.split(' - ')[1], 0)
            cursor = idaapi.get_screen_ea()
            if cursor >= start_obfus and cursor <= end_obfus:
                self.cmb_todo.removeItem(i)
                idc.set_cmt(self.start_ea, '')
                next_ea = start_obfus
                is_revert = False
                while next_ea <= end_obfus:
                    idaapi.set_item_color(next_ea, idc.DEFCOLOR)
                    next_ea = idc.next_head(next_ea)
                break
        if is_revert:
            for addr_revert in self.list_revert_addr:
                ida_bytes.revert_byte(addr_revert)
            ida_auto.auto_mark_range(self.start_ea, self.end_ea, ida_auto.AU_CODE)
            ida_auto.plan_and_wait(self.start_ea, self.end_ea, True)

    def change_addr_to(self):
        todo = self.cmb_todo.currentText()
        start_ea = todo.split(' - ')[0]
        start_ea = int(start_ea, 0)
        end_ea = todo.split(' - ')[1]
        end_ea = int(end_ea, 0)
        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_ea, end_ea)

    def refresh_list_revert_addr(self):
        def visitor(ea, fpos, original_bytes, patched_bytes):
            print(hex(ea), hex(fpos))
            self.list_revert_addr.add(ea)
            return 0
        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)
