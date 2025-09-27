from PySide6.QtWidgets import QTabWidget, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton
import PySide6.QtWidgets as QtWidgets
from PySide6.QtCore import Qt
from sharingan.core import stylesmanager
import idaapi, idc, ida_bytes, ida_kernwin, ida_lines, ida_name, ida_idp, ida_auto, ida_idaapi
import threading, platform


class PatchedBytesVistor(object):
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea

    def __call__(self, ea, fpos, original_bytes, patch_bytes, cnt=()):
        if fpos != -1 and ea >= self.start_ea and ea <= self.end_ea:
            for i in fpos:
                ida_bytes.revert_byte(ea)
            ida_auto.auto_mark_range(ea, ea + fpos, ida_auto.AU_CODE)
            ida_auto.plan_and_wait(ea, ea + fpos, True)
        return 0


class DBHooks(ida_idp.IDB_Hooks):
    def __init__(self, asmview, name_windows):
        super().__init__()
        self.asmview = asmview
        self.name = name_windows

    def byte_patched(self, ea, old_value):
        self.asmview.addr_highlight.add(ea)
        if self.name == 'after':
            start_ea = self.asmview.start_ea
            end_ea = self.asmview.end_ea
            self.asmview.disassemble(start_ea, end_ea)
        if self.name == 'before':
            self.asmview.Refresh()

    def item_color_changed(self, ea, color):
        # print(hex(ea), hex(color))
        pass


class ASMLine:
    def __init__(self, ea):
        self.colored_instruction = ida_lines.generate_disasm_line(ea).split(';')[0]
        assert self.colored_instruction, f'Bad address... {hex(ea)}'
        self.label = ida_name.get_short_name(ea)
        self.address = ea
        self.padding = ' ' * 2

    @property
    def colored_address(self):
        return ida_lines.COLSTR('%08X' % self.address, ida_lines.SCOLOR_PREFIX)
    
    @property
    def colored_label(self):
        if not self.label:
            return None
        pretty_name = ida_lines.COLSTR(self.label, ida_lines.SCOLOR_CNAME) + ':'
        return ' '.join(['', self.colored_address, self.padding, pretty_name])
    
    @property
    def colored_blank(self):
        return ' '.join(['', self.colored_address])

    @property
    def colored_asmline(self):
        return ' '.join(['', self.colored_address, self.padding, self.colored_instruction])
    

class UIHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        pass

    def get_lines_rendering_info(self, out, widget, rin):
        pass

    def populating_widget_popup(self, widget, popup, ctx):
        pass


class ASMView(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.ui_hooks = UIHooks()
        self.start_ea = 0
        self.end_ea = 0
        self.addr_highlight = set()

    def Create(self, name_windows):
        if not super().Create(name_windows):
            return False
        self._twidget = self.GetWidget()
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)
        self.ui_hooks.hook()
        self.db_hooks = DBHooks(self, name_windows)
        self.db_hooks.hook()
        return True
    
    def OnClose(self):
        self.ui_hooks.unhook()
        self.db_hooks.unhook()
    
    def disassemble(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        next_addr = start_ea
        self.ClearLines()
        while next_addr <= end_ea:
            line = ASMLine(next_addr)
            if line.label:
                self.AddLine(line.colored_blank)
                self.AddLine(line.colored_label)
            self.AddLine(line.colored_asmline)
            next_addr = idc.next_head(next_addr)
        self.Refresh()
    
    def get_lines_rendering_info(self, out, widget, rin):
        if widget != self._twidget:
            return
        for _, line in enumerate(rin.sections_lines[0]):
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            line_info = self.GetLine(splace.n)
            if not line_info:
                continue
            colored_text, _, _ = line_info
            line_input = ida_lines.tag_remove(colored_text)
            address = int(line_input.split()[0], 16)
            if address in self.addr_highlight:
                if ida_bytes.is_code(ida_bytes.get_flags(address)):
                    color = ida_kernwin.CK_EXTRA1
                    e = ida_kernwin.line_rendering_output_entry_t(line)
                    e.bg_color = color
                    e.flags = ida_kernwin.LROEF_FULL_LINE
                    out.entries.push_back(e)


class DisassembleTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        main_tab = self
        while type(main_tab).__name__ != "Disassembler":
            main_tab = main_tab.parent()
        self.main_tab = main_tab
        self.cached_start_ea = None
        self.cached_end_ea = None
        self.mutex = threading.Lock()

        self.lbl_start_ea = QLabel('Start EA')
        self.lbl_end_ea = QLabel('End EA')
        self.ldt_start_ea = QLineEdit()
        self.ldt_end_ea = QLineEdit()
        self.ldt_start_ea.setPlaceholderText('Start')
        self.ldt_end_ea.setPlaceholderText('End')
        self.ldt_start_ea.editingFinished.connect(self.disassemble)
        self.ldt_end_ea.editingFinished.connect(self.disassemble)
        self.btn_choose = QPushButton('Choose', parent=self)
        self.btn_choose.clicked.connect(self.choose_function)
        self.btn_revert = QPushButton('Revert', self)
        self.btn_revert.clicked.connect(self.revert)

        self.asm_before = ASMView()
        self.asm_after = ASMView()
        assert self.asm_before.Create('before'), 'Fail loading ASMView before'
        assert self.asm_after.Create('after'), 'Fail loading ASMView after'

        layout_toolbar = QHBoxLayout()
        layout_toolbar.addWidget(self.lbl_start_ea)
        layout_toolbar.addWidget(self.ldt_start_ea)
        layout_toolbar.addWidget(self.lbl_end_ea)
        layout_toolbar.addWidget(self.ldt_end_ea)
        layout_toolbar.addWidget(self.btn_choose)
        layout_toolbar.addWidget(self.btn_revert)
        layout_asm = QHBoxLayout()
        layout_asm.addWidget(self.asm_before.widget)
        layout_asm.addWidget(self.asm_after.widget)
        layout = QVBoxLayout(self)
        layout.addLayout(layout_toolbar, stretch=1)
        layout.addLayout(layout_asm, stretch=10)

    def revert(self):
        visitor = PatchedBytesVistor(self.lbl_start_ea.text(), self.lbl_end_ea.text())
        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)

    def get_line_edit_texts(self):
        return [self.ldt_start_ea.text(), self.ldt_end_ea.text()]

    def set_line_edit_texts(self, start_ea, end_ea):
        if start_ea != end_ea:
            self.ldt_start_ea.setText(hex(start_ea))
            self.ldt_end_ea.setText(hex(end_ea))
        else:
            self.ldt_start_ea.setText(hex(start_ea))
            dst_addr = start_ea
            for i in range(60):
                dst_addr = idc.next_head(dst_addr)
            self.ldt_end_ea.setText(hex(dst_addr))
        self.disassemble()

    def choose_function(self):
        func = idaapi.choose_func("Choose function to deobfuscate", idc.get_screen_ea())
        if func is None:
            return
        
        start_func = func.start_ea
        end_func = func.end_ea
        func_name = idc.get_func_name(start_func)
        tab_title = func_name if func_name else hex(start_func)
        self.main_tab.setTabText(self.main_tab.indexOf(self), tab_title)
        self.ldt_start_ea.clear()
        self.ldt_end_ea.clear()
        self.ldt_start_ea.setText(hex(start_func))
        self.ldt_start_ea.editingFinished.emit()
        self.ldt_end_ea.setText(hex(end_func))
        self.ldt_end_ea.editingFinished.emit()

    def disassemble(self):
        self.mutex.acquire()
        try:
            start_ea_txt = self.ldt_start_ea.text()
            end_ea_txt = self.ldt_end_ea.text()
            if start_ea_txt == "" or end_ea_txt == "": 
                self.mutex.release()
                return

            if start_ea_txt[:2].lower() == "0x":
                start_ea = int(start_ea_txt, 16)
            else:
                start_ea = int(start_ea_txt)
            if end_ea_txt[:2].lower() == "0x":
                end_ea = int(end_ea_txt, 16)
            else:
                end_ea = int(end_ea_txt)
            assert(end_ea > start_ea)
            if self.cached_start_ea == start_ea and self.cached_end_ea == end_ea: 
                self.mutex.release()
                return
            self.cached_start_ea = start_ea
            self.cached_end_ea = end_ea
            assert(start_ea != None and end_ea != None)
        except:
            print("Error parsing address")
            self.mutex.release()
            return
        self.mutex.release()

        self.clear_addr_highlight()
        self.asm_before.disassemble(start_ea, end_ea)
        # self.asm_after.disassemble(start_ea, end_ea)

    def clear_addr_highlight(self):
        self.asm_before.addr_highlight.clear()
        self.asm_after.addr_highlight.clear()


class Disassembler(QTabWidget):
    def __init__(self, parent=None):
        super(Disassembler, self).__init__(parent)
        self.setTabsClosable(True) 
        self.setMovable(True)
        self.setObjectName('disassembler')
        self.tabCloseRequested.connect(self.close_tab)
        self.btn_add_tab = QPushButton(' + ')
        self.btn_add_tab.setObjectName('new_tab')
        self.btn_add_tab.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        self.btn_add_tab.clicked.connect(self.add_new_tab)
        self.setCornerWidget(self.btn_add_tab, Qt.TopRightCorner)
        if platform.system().lower() == 'windows':
            self.setProperty('applyWindows', 'true')
            self.setStyleSheet(stylesmanager.get_stylesheet())
        self.tab_contents = []
        self.add_new_tab()

    def add_new_tab(self):
        tab_content = DisassembleTab(self)
        self.addTab(tab_content, f"Tab {self.count() + 1}")
        self.tab_contents.append(tab_content)

    def close_tab(self, index):
        if self.count() > 1:
            self.removeTab(index)
            self.tab_contents.pop(index)

    def get_tab_line_edit_texts(self, index):
        tab_content = self.tab_contents[index]
        if tab_content:
            return tab_content.get_line_edit_texts()
        return []

    def clear_tab_addr_highlight(self, index):
        tab_content = self.tab_contents[index]
        tab_content.clear_addr_highlight()

    def set_tab_line_edit_texts(self, index, start_ea, end_ea):
        tab_content = self.tab_contents[index]
        tab_content.set_line_edit_texts(start_ea, end_ea)
        