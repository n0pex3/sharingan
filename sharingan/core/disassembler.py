from PySide6.QtWidgets import QTabWidget, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QSizePolicy, QComboBox, QTableWidget, QTableWidgetItem, QStackedWidget, QHeaderView
from PySide6.QtCore import Qt
from sharingan.core.stylesmanager import ManageStyleSheet
import idaapi, ida_bytes, ida_hexrays
import threading, platform, difflib
from sharingan.core.utils import DeobfuscateUtils


FILTER = 'sharingan:filter'


# color asm line
class ASMLine:
    def __init__(self, ea):
        self.label = idaapi.get_short_name(ea)
        self.address = ea
        self.padding = ' ' * 2

        flags = idaapi.get_flags(ea)

        if idaapi.is_head(flags):
            self.colored_instruction = idaapi.generate_disasm_line(ea, 0)
            if not self.colored_instruction:
                self.colored_instruction = idaapi.COLSTR("??", idaapi.SCOLOR_ERROR)
        else:
            byte_val = idaapi.get_wide_byte(ea)
            s_val = f"{byte_val:02X}h"
            
            self.colored_instruction = (
                idaapi.COLSTR("db", idaapi.SCOLOR_KEYWORD) + " " + 
                idaapi.COLSTR(s_val, idaapi.SCOLOR_DNUM)
            )
        # self.colored_instruction = idaapi.generate_disasm_line(ea)
        # assert self.colored_instruction, f'Bad address... {hex(ea)}'

    @property
    def colored_address(self):
        return idaapi.COLSTR(f'{self.address:08X}', idaapi.SCOLOR_PREFIX)
    
    @property
    def colored_label(self):
        if not self.label:
            return None
        pretty_name = idaapi.COLSTR(self.label, idaapi.SCOLOR_CNAME) + ':'
        return f' {self.colored_address} {self.padding} {pretty_name}'
    
    @property
    def colored_blank(self):
        return f' {self.colored_address}'

    @property
    def colored_asmline(self):
        return f' {self.colored_address} {self.padding} {self.colored_instruction}'
    

# option right click filter region like this
class Filter(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def set_signal_filter(self, signal_filter):
        self.signal_filter = signal_filter
    
    def activate(self, ctx):
        if ctx.cur_flags & idaapi.ACF_HAS_SELECTION:
            start_splace = idaapi.place_t_as_simpleline_place_t(ctx.cur_sel._from.at)
            end_splace = idaapi.place_t_as_simpleline_place_t(ctx.cur_sel.to.at)
            start_colorize_line = start_splace.generate(idaapi.get_viewer_user_data(ctx.widget), 1)[0][0]
            end_colorize_line = end_splace.generate(idaapi.get_viewer_user_data(ctx.widget), 1)[0][0]
            raw_start_line = idaapi.tag_remove(start_colorize_line)
            raw_end_line = idaapi.tag_remove(end_colorize_line)
            start_ea = int(raw_start_line.split()[0], 16)
            end_ea = int(raw_end_line.split()[0], 16)
            end_ea = idaapi.next_head(end_ea, idaapi.BADADDR)
            self.signal_filter.filter_.emit(start_ea, end_ea)
        else:
            colorize_line = idaapi.get_custom_viewer_curline(ctx.widget, False)
            raw_line = idaapi.tag_remove(colorize_line)
            start_ea = end_ea = int(raw_line.split()[0], 16)
            self.signal_filter.filter_.emit(start_ea, end_ea)
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# override get_lines_rendering_info to highlight
class UIHooks(idaapi.UI_Hooks):
    def get_lines_rendering_info(self, out, widget, info):
        pass

    def finish_populating_widget_popup(self, widget, popup, ctx):
        pass


# mini disassembler
class ASMView(idaapi.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.ui_hooks = UIHooks()
        self.ui_hooks.get_lines_rendering_info = self.highlight_lines_disassm
        self.ui_hooks.finish_populating_widget_popup = self.popup_option_filter

        self.start_ea = 0x0
        self.end_ea = 0x0

        self.pseudocode = []

    def Create(self, name_windows, mode):
        if not super().Create(name_windows):
            return False
        self.mode = mode
        self.filter = Filter()
        idaapi.unregister_action(FILTER)
        action_filter = idaapi.action_desc_t(FILTER, 'Filter', self.filter, None, None)
        assert idaapi.register_action(action_filter), ' Action filter registration failed'
        self._twidget = self.GetWidget()
        self.widget = idaapi.PluginForm.TWidgetToPyQtWidget(self._twidget)
        self.ui_hooks.hook()
        return True
    
    def OnClose(self):
        self.ui_hooks.unhook()
        idaapi.unregister_action(FILTER)
    
    def disassemble(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.ClearLines()
        next_addr = start_ea
        while next_addr < end_ea:
            line = ASMLine(next_addr)
            if line.label:
                self.AddLine(line.colored_blank)
                self.AddLine(line.colored_label)
            self.AddLine(line.colored_asmline)

            flags = idaapi.get_flags(next_addr)
            if idaapi.is_head(flags):
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
            else:
                next_addr += 1
        self.Refresh()

    def decompile(self, start_ea, end_ea, is_diff=False):
        self.start_ea = start_ea
        self.end_ea = end_ea
        if not ida_hexrays.init_hexrays_plugin():
            print('Fail init decompiler')
            return
        func = idaapi.get_func(start_ea)
        if func is None:
            print("Please provid address within a function")
            return
        cfunc = ida_hexrays.decompile(func)
        if cfunc is None:
            print("Failed to decompile!")
            return
        pseudocode = cfunc.get_pseudocode()
        self.ClearLines()
        for i, sline in enumerate(pseudocode):
            if not is_diff:
                self.AddLine(sline.line)
            self.pseudocode.append(idaapi.tag_remove(sline.line))
        self.Refresh()

    def set_signal_filter(self, signal_filter):
        self.filter.set_signal_filter(signal_filter)

    def popup_option_filter(self, widget, popup, ctx):
        if self.mode == 'disassembler':
           idaapi.attach_action_to_popup(widget, popup, FILTER, None, 0) 

    def highlight_lines_disassm(self, out, widget, info):
        pass
    
    def diff_code(self, obfuscated_regions):
        if self.mode == 'decompiler':
            lines_pseudocode_before = []
            for i in range(self.Count()):
                line_content = self.GetLine(i)[0]
                lines_pseudocode_before.append(line_content)
            lines_pseudocode_before_raw = self.pseudocode

            if not ida_hexrays.init_hexrays_plugin():
                print('Fail init decompiler')
                return
            func = idaapi.get_func(self.start_ea)
            if func is None:
                print("Please provid address within a function")
                return
            cfunc = ida_hexrays.decompile(func)
            if cfunc is None:
                print("Failed to decompile!")
                return
            pseudocode = cfunc.get_pseudocode()
            lines_pseudocode_after_raw = []
            lines_pseudocode_after = []
            for i, sline in enumerate(pseudocode):
                lines_pseudocode_after.append(sline.line)
                lines_pseudocode_after_raw.append(idaapi.tag_remove(sline.line))

            self.ClearLines()
            comparasion = difflib.SequenceMatcher(None, lines_pseudocode_before_raw, lines_pseudocode_after_raw, autojunk=False)
            opcodes = comparasion.get_opcodes()
            for index, (tag, i1, i2, j1, j2) in enumerate(opcodes):
                if tag == 'equal':
                    for i in range(i2 - i1):
                        self.AddLine(f'{lines_pseudocode_before[i1 + i]}')
                elif tag == 'delete':
                    for i in range(i2 - i1):
                        self.AddLine(f'- {lines_pseudocode_before[i1 + i]}')
                elif tag == 'insert':
                    for i in range(j2 - j1):
                        self.AddLine(f'+ {lines_pseudocode_after[j1 + i]}')
                elif tag == 'replace':
                    num_before = i2 - i1
                    num_after = j2 - j1
                    max_lines = max(num_before, num_after)
                    for i in range(max_lines):
                        if i < num_before:
                            self.AddLine(f'- {lines_pseudocode_before[i1 + i]}')
                        if i < num_after:
                            self.AddLine(f'{lines_pseudocode_after[j1 + i]}')
            self.Refresh()

        elif self.mode == 'disassembler':
            current_asm_lines = []
            for i in range(self.Count()):
                line_content = self.GetLine(i)[0]
                raw_line = idaapi.tag_remove(line_content)
                address = raw_line.split()[0]
                current_asm_lines.append({
                    'addr': address,
                    'content': line_content
                })
            
            intervals = []
            for i, list_regions in enumerate(obfuscated_regions):
                for j, r in enumerate(list_regions):
                    for k in range(len(r.regions)):
                        start = r.regions[k].start_ea
                        end = r.regions[k].end_ea
                        intervals.append((start, end))
            intervals.sort(key=lambda x: (x[0], x[1]))

            self.ClearLines()
            is_diff = False
            idx = 0

            for item in current_asm_lines:
                current_addr = int(item['addr'], 16)
                if idx < len(intervals):
                    start, end = intervals[idx]
                else:
                    start, end = -1, -1

                # CASE 1: print code in obfuscated region (before)
                if start != -1 and start <= current_addr < end:
                    self.AddLine(f'- {item['content']}')
                    is_diff = True
                
                # CASE 2: print current code (after)
                elif is_diff and (start == -1 or current_addr >= end):
                    is_diff = False
                    
                    # print deobfuscated code
                    prev_start, prev_end = intervals[idx]
                    current_ea = prev_start
                    while current_ea < prev_end:
                        line = ASMLine(current_ea)
                        self.AddLine(f'+ {line.colored_asmline}')
                        current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)
                    
                    idx += 1
                    if idx < len(intervals):
                        next_start, next_end = intervals[idx]
                    else:
                        next_start, next_end = -1, -1

                    # check two patched sequence region, prevent missing
                    if next_start != -1 and next_start <= current_addr < next_end:
                         self.AddLine(f'- {item['content']}')
                         is_diff = True
                    else:
                        # print normal code
                        self.AddLine(item['content'])

                # CASE 3: equal
                else:
                    self.AddLine(item['content'])
            
            self.Refresh()


# class handle each tab disassembler
class DisassembleTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        main_tab = self
        while type(main_tab).__name__ != "Disassembler":
            main_tab = main_tab.parent()
        self.main_tab = main_tab
        self.cached_start_ea = None
        self.cached_end_ea = None
        self.mutex = threading.Lock()
        self.mode = 'disassembler'

        self.lbl_start_ea = QLabel('Start EA')
        self.lbl_end_ea = QLabel('End EA')
        self.ldt_start_ea = QLineEdit()
        self.ldt_end_ea = QLineEdit()
        self.ldt_start_ea.setPlaceholderText('Start')
        self.ldt_end_ea.setPlaceholderText('End')
        self.ldt_start_ea.editingFinished.connect(self.switch_mode_display)
        self.ldt_end_ea.editingFinished.connect(self.switch_mode_display)
        self.btn_choose = QPushButton('Choose', parent=self)
        self.btn_choose.clicked.connect(self.choose_function)
        self.cmb_mode = QComboBox(self)
        self.cmb_mode.addItem('Disassembler')
        self.cmb_mode.addItem('Decompiler')
        self.cmb_mode.addItem('String')
        self.cmb_mode.currentIndexChanged.connect(self.change_mode_code_string)

        self.asm_view = ASMView()
        assert self.asm_view.Create('asm_view', self.mode), 'Fail loading ASMView'

        # table string
        self.tbl_string = QTableWidget()
        self.tbl_string.setRowCount(100)
        self.tbl_string.setColumnCount(4)
        self.tbl_string.setHorizontalHeaderLabels(['Address', 'Raw', 'Cooking', 'Hint'])
        for i in range(100):
            for j in range(4):
                self.tbl_string.setItem(i, j, QTableWidgetItem(str(i * j)))
        self.tbl_string.horizontalHeader().setStretchLastSection(True)
        self.tbl_string.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout_toolbar = QHBoxLayout()
        layout_toolbar.addWidget(self.lbl_start_ea, stretch=1)
        layout_toolbar.addWidget(self.ldt_start_ea, stretch=3)
        layout_toolbar.addWidget(self.lbl_end_ea, stretch=1)
        layout_toolbar.addWidget(self.ldt_end_ea, stretch=3)
        layout_toolbar.addWidget(self.cmb_mode, stretch=2)
        layout_toolbar.addWidget(self.btn_choose, stretch=1)
        page_asm = QWidget()
        layout_asm = QHBoxLayout(page_asm)
        layout_asm.addWidget(self.asm_view.widget)
        self.layout_stack = QStackedWidget()
        self.layout_stack.addWidget(page_asm)
        self.layout_stack.addWidget(self.tbl_string)
        layout = QVBoxLayout(self)
        layout.addLayout(layout_toolbar, stretch=1)
        layout.addWidget(self.layout_stack, stretch=10)

    def __del__(self):
        self.db_hooks.unhook()

    def change_mode_code_string(self, index):
        mode = self.cmb_mode.itemText(index)
        self.layout_stack.setCurrentIndex(1 if mode.lower() == 'string' else 0)
        self.mode = mode.lower()
        self.asm_view.mode = self.mode

    def get_line_edit_texts(self):
        return self.ldt_start_ea.text(), self.ldt_end_ea.text()

    def set_line_edit_texts(self, start_ea, end_ea, is_all_binary=False):
        if start_ea == end_ea:
            end_ea = start_ea
            for _ in range(256):
                end_ea = idaapi.next_head(end_ea, idaapi.BADADDR)
        self.ldt_start_ea.setText(hex(start_ea))
        self.ldt_end_ea.setText(hex(end_ea))
        if not is_all_binary:
            self.switch_mode_display()

    def choose_function(self):
        func = idaapi.choose_func("Choose function to deobfuscate", idaapi.get_screen_ea())
        if func is None:
            return
        
        start_func = func.start_ea
        end_func = func.end_ea
        func_name = idaapi.get_func_name(start_func)
        tab_title = func_name if func_name else hex(start_func)
        self.main_tab.setTabText(self.main_tab.indexOf(self), tab_title)
        self.ldt_start_ea.setText(hex(start_func))
        self.ldt_start_ea.editingFinished.emit()
        self.ldt_end_ea.setText(hex(end_func))
        self.ldt_end_ea.editingFinished.emit()

    def switch_mode_display(self):
        self.mutex.acquire()
        try:
            start_ea_txt = self.ldt_start_ea.text()
            end_ea_txt = self.ldt_end_ea.text()
            if start_ea_txt == "" or end_ea_txt == "": 
                self.mutex.release()
                print('Empty address')
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
                print('Same previous range')
                return

            self.cached_start_ea = start_ea
            self.cached_end_ea = end_ea
            assert(start_ea != None and end_ea != None)
        except:
            print("Error parsing address")
            self.mutex.release()
            return

        self.mutex.release()

        mode = self.cmb_mode.currentText()
        if mode.lower() == 'disassembler':
            self.mode = 'disassembler'
            self.asm_view.disassemble(start_ea, end_ea)
        elif mode.lower() == 'decompiler':
            self.mode = 'decompiler'
            self.asm_view.decompile(start_ea, end_ea)

    def wrapper_diff_code(self, obfuscated_regions=None):
        self.asm_view.diff_code(obfuscated_regions)

    def set_signal_filter(self, signal_filter):
        self.asm_view.set_signal_filter(signal_filter)

    def clear_asmview(self):
        self.asm_view.ClearLines()

    def refresh_asm_view(self):
        start_ea = self.asm_view.start_ea
        end_ea = self.asm_view.end_ea
        self.asm_view.disassemble(start_ea, end_ea)
    

# class handle list tab disassembler
class Disassembler(QTabWidget):
    def __init__(self, parent=None):
        super(Disassembler, self).__init__(parent)
        self.setTabsClosable(True) 
        self.setMovable(True)
        self.setObjectName('disassembler')
        self.tabCloseRequested.connect(self.close_tab)
        self.btn_add_tab = QPushButton(' + ')
        self.btn_add_tab.setObjectName('new_tab')
        self.btn_add_tab.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        self.btn_add_tab.clicked.connect(self.add_new_tab)
        self.setCornerWidget(self.btn_add_tab, Qt.TopRightCorner)
        if platform.system().lower() == 'windows':
            self.setProperty('applyWindows', 'true')
            self.setStyleSheet(ManageStyleSheet.get_stylesheet())
        self.tab_contents = []
        self.signal_filter = None
        self.add_new_tab()

    def set_tab_signal_filter(self, signal_filter):
        self.signal_filter = signal_filter
        self.tab_contents[self.currentIndex()].set_signal_filter(self.signal_filter)

    def add_new_tab(self):
        tab_content = DisassembleTab(self)
        self.addTab(tab_content, f"Tab {self.count() + 1}")
        self.tab_contents.append(tab_content)
        if self.signal_filter:
            self.tab_contents[self.currentIndex()].set_signal_filter(self.signal_filter)
        
    def close_tab(self, index):
        if self.count() > 1:
            self.removeTab(index)
            self.tab_contents.pop(index)

    def get_tab_line_edit_texts(self, index):
        return self.tab_contents[index].get_line_edit_texts() if self.tab_contents[index] else []

    def clear_tab_asmview(self, index):
        self.tab_contents[index].clear_asmview()

    def set_tab_line_edit_texts(self, index, start_ea, end_ea, is_all_binary=False):
        self.tab_contents[index].set_line_edit_texts(start_ea, end_ea, is_all_binary)

    def compare_tab_code(self, index, obfuscated_regions=None):
        self.tab_contents[index].wrapper_diff_code(obfuscated_regions)

    def refresh_tab_asm_view(self, index):
        self.tab_contents[index].refresh_asm_view()
