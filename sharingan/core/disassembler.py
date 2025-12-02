from PySide6.QtWidgets import QTabWidget, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QSizePolicy, QComboBox, QTableWidget, QTableWidgetItem, QStackedWidget, QHeaderView, QAbstractItemView, QCheckBox, QToolButton
from PySide6.QtCore import Qt, QTimer
from sharingan.core.stylesmanager import ManageStyleSheet
import idaapi, ida_bytes, ida_hexrays, ida_kernwin
import threading, platform, difflib, os
from sharingan.core.utils import DeobfuscateUtils
from sharingan.core.StrFinder.string_finder import StringFinder


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
                    self.AddLine(f"- {item['content']}")
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
        self.string_results = []
        self.string_row_checkboxes = []
        self.ignore_file_path = self._resolve_ignore_file_path()
        try:
            self.string_finder = StringFinder()
        except Exception as exc:
            self.string_finder = None
            idaapi.msg(f"[Sharingan] Failed to initialize StringFinder: {exc}\n")

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
        self.string_workspace = self._initialize_string_workspace()

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
        self.layout_stack.addWidget(self.string_workspace)
        layout = QVBoxLayout(self)
        layout.addLayout(layout_toolbar, stretch=1)
        layout.addWidget(self.layout_stack, stretch=10)

    def __del__(self):
        self.db_hooks.unhook()

    def _initialize_string_workspace(self):
        workspace = QWidget()
        layout = QVBoxLayout(workspace)
        layout.setContentsMargins(0, 0, 0, 0)

        self.btn_scan_code = QPushButton('Scan code', self)
        self.btn_scan_code.clicked.connect(self.scan_code_strings)
        self.btn_ignore_strings = QPushButton('Ignore', self)
        self.btn_ignore_strings.clicked.connect(self.ignore_selected_strings)
        self.btn_export_report = QPushButton('Apply', self)
        self.btn_export_report.clicked.connect(self.apply_strings_decrypt)

        button_bar = QHBoxLayout()
        button_bar.addWidget(self.btn_scan_code)
        button_bar.addWidget(self.btn_ignore_strings)
        button_bar.addWidget(self.btn_export_report)
        button_bar.addStretch()
        layout.addLayout(button_bar)

        self.tbl_string = QTableWidget()
        self.tbl_string.setColumnCount(6)
        self.tbl_string.setHorizontalHeaderLabels(['', '#', 'Raw', 'Address', 'Preview', 'Xref'])
        self.tbl_string.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_string.setSelectionMode(QAbstractItemView.NoSelection)
        self.tbl_string.setAlternatingRowColors(True)
        self.tbl_string.verticalHeader().setVisible(False)
        self.tbl_string.horizontalHeader().setStretchLastSection(False)
        self.tbl_string.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_string.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_string.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_string.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_string.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tbl_string.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)

        self.checkbox_header_index = 0
        header = self.tbl_string.horizontalHeader()
        self.checkbox_header_button = QToolButton(header)
        self.checkbox_header_button.setText('Select all')
        self.checkbox_header_button.setAutoRaise(True)
        self.checkbox_header_button.setCursor(Qt.PointingHandCursor)
        self.checkbox_header_button.setStyleSheet(
            "QToolButton { border: none; font-size: 9px; padding: 0px 2px; }"
        )
        self.checkbox_header_button.clicked.connect(self._handle_header_checkbox_button)
        header.sectionResized.connect(self._position_checkbox_header_button)
        header.sectionMoved.connect(self._position_checkbox_header_button)
        header.geometriesChanged.connect(self._position_checkbox_header_button)
        self.tbl_string.horizontalScrollBar().valueChanged.connect(self._position_checkbox_header_button)

        layout.addWidget(self.tbl_string)
        self._initialize_string_table_placeholders()
        self._update_checkbox_header_label()        
        QTimer.singleShot(0, self._position_checkbox_header_button)
        return workspace        

    def _initialize_string_table_placeholders(self):
        self.tbl_string.setRowCount(1)
        self.tbl_string.clearContents()
        self.string_row_checkboxes.clear()
        for col in range(1, 6):
            align = Qt.AlignCenter if col in (1, 3) else None
            tooltip = '0' if col == 2 else None
            self.tbl_string.setItem(0, col, self._make_table_item('0', align=align, tooltip=tooltip))
        self._add_checkbox_to_row(0, enabled=False, track=False)

    def _make_table_item(self, text: str, align: Qt.Alignment | None = None, tooltip: str | None = None):
        item = QTableWidgetItem(text)
        flags = item.flags()
        item.setFlags(flags & ~Qt.ItemIsEditable)
        if align is not None:
            item.setTextAlignment(align)
        if tooltip:
            item.setToolTip(tooltip)
        return item

    def _add_checkbox_to_row(self, row: int, enabled: bool = True, track: bool = True):
        checkbox = QCheckBox(self.tbl_string)
        checkbox.setEnabled(enabled)
        if enabled:
            checkbox.stateChanged.connect(self._on_row_checkbox_state_changed)
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignCenter)
        layout.addWidget(checkbox)
        self.tbl_string.setCellWidget(row, self.checkbox_header_index, container)
        if enabled and track:
            self.string_row_checkboxes.append(checkbox)

    def _on_row_checkbox_state_changed(self, _state):
        self._update_checkbox_header_label()

    def _update_checkbox_header_label(self):
        if not hasattr(self, 'checkbox_header_button'):
            return
        if self._are_all_rows_checked():
            self.checkbox_header_button.setText('Deselect all')
        else:
            self.checkbox_header_button.setText('Select all')

    def _are_all_rows_checked(self) -> bool:
        return bool(self.string_row_checkboxes) and all(cb.isChecked() for cb in self.string_row_checkboxes)

    def _set_all_row_checkboxes(self, state: bool):
        for cb in self.string_row_checkboxes:
            cb.blockSignals(True)
            cb.setChecked(state)
            cb.blockSignals(False)
        self._update_checkbox_header_label()

    def _position_checkbox_header_button(self, *args):
        if not hasattr(self, 'checkbox_header_button') or not self.checkbox_header_button:
            return
        header = self.tbl_string.horizontalHeader()
        if self.checkbox_header_index >= header.count():
            return
        x = header.sectionViewportPosition(self.checkbox_header_index)
        width = header.sectionSize(self.checkbox_header_index)
        self.checkbox_header_button.setGeometry(x, 0, width, header.height())
        self.checkbox_header_button.show()

    def _handle_header_checkbox_button(self):
        select_all = not self._are_all_rows_checked()
        self._set_all_row_checkboxes(select_all)

    def _resolve_ignore_file_path(self):
        try:
            plugin_dirs = idaapi.get_ida_subdirs("plugins")
        except Exception:
            plugin_dirs = []
        for path in plugin_dirs:
            candidate = os.path.join(path, 'sharingan', 'core', 'StrFinder', 'ignore_string')
            if os.path.exists(candidate):
                return candidate
        return os.path.join(os.path.dirname(__file__), 'StrFinder', 'ignore_string')

    def _get_selected_string_rows(self):
        selected_rows = []
        for idx, checkbox in enumerate(self.string_row_checkboxes):
            if checkbox.isEnabled() and checkbox.isChecked():
                selected_rows.append(idx)
        return selected_rows

    def _iter_ignore_file_paths(self):
        paths = []
        seen = set()

        def add_path(p):
            if p and p not in seen:
                seen.add(p)
                paths.append(p)

        add_path(self.ignore_file_path)
        user_ida_dir = None
        try:
            user_ida_dir = idaapi.get_user_idadir()
        except Exception:
            user_ida_dir = None
        if user_ida_dir:
            add_path(os.path.join(user_ida_dir, 'plugins', 'sharingan', 'core', 'StrFinder', 'ignore_string'))
        add_path(os.path.join(os.path.expanduser('~'), '.sharingan', 'ignore_string'))
        return paths

    def _try_append_ignore_strings(self, path, strings):
        directory = os.path.dirname(path)
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
        except OSError:
            return False, False
        existing = set()
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    existing = {line.rstrip('\n') for line in f}
            except OSError:
                return False, False
        new_strings = [s for s in strings if s and s not in existing]
        if not new_strings:
            return True, False
        try:
            with open(path, 'a', encoding='utf-8') as f:
                for s in new_strings:
                    f.write(f'{s}\n')
        except OSError:
            return False, False
        return True, True

    def _append_ignore_strings(self, strings):
        strings = [s for s in strings if s]
        if not strings:
            return False
        primary_path = os.path.join(os.path.dirname(__file__), 'StrFinder', 'ignore_string')
        ok, wrote = self._try_append_ignore_strings(primary_path, strings)
        if ok:
            if primary_path != self.ignore_file_path:
                self.ignore_file_path = primary_path
            if not wrote:
                idaapi.msg('[Sharingan] Selected strings already ignored.\n')
            return True
        fallback_paths = []
        plugin_dirs = []
        try:
            plugin_dirs = idaapi.get_ida_subdirs("plugins")
        except Exception:
            plugin_dirs = []
        for path in plugin_dirs:
            fallback_paths.append(os.path.join(path, 'sharingan', 'core', 'StrFinder', 'ignore_string'))
        user_ida_dir = None
        try:
            user_ida_dir = idaapi.get_user_idadir()
        except Exception:
            user_ida_dir = None
        if user_ida_dir:
            fallback_paths.append(os.path.join(user_ida_dir, 'plugins', 'sharingan', 'core', 'StrFinder', 'ignore_string'))
        fallback_paths.append(os.path.join(os.path.expanduser('~'), '.sharingan', 'ignore_string'))
        for candidate in fallback_paths:
            ok, wrote = self._try_append_ignore_strings(candidate, strings)
            if ok:
                if candidate != self.ignore_file_path:
                    self.ignore_file_path = candidate
                    idaapi.msg(f'[Sharingan] Using ignore list at {candidate}\n')
                if not wrote:
                    idaapi.msg('[Sharingan] Selected strings already ignored.\n')
                return True
        idaapi.msg('[Sharingan] Failed to update ignore list: no writable location available.\n')
        return False

    def scan_code_strings(self):
        if self.string_finder is None:
            idaapi.msg('[Sharingan] String Finder modules unavailable.\n')
            return
        if hasattr(self.string_finder, 'load_init_exclude'):
            try:
                self.string_finder.load_init_exclude()
            except Exception as exc:
                idaapi.msg(f'[Sharingan] Failed to reload ignore list: {exc}\n')
        self.btn_scan_code.setEnabled(False)
        self.btn_scan_code.setText('Scanning...')
        ida_kernwin.execute_sync(self._run_scan_code_strings, ida_kernwin.MFF_WRITE)

    def _run_scan_code_strings(self):
        results = []
        try:
            results = self.string_finder.find_all_encrypted_strings()
        except Exception as exc:
            idaapi.msg(f'[Sharingan] String scan failed: {exc}\n')
        self.btn_scan_code.setEnabled(True)
        self.btn_scan_code.setText('Scan code')
        self.populate_string_table(results)

    def populate_string_table(self, strings: list):
        self.string_results = strings or []
        self.tbl_string.setUpdatesEnabled(False)
        self.tbl_string.clearContents()
        for row in range(self.tbl_string.rowCount()):
            self.tbl_string.setCellWidget(row, self.checkbox_header_index, None)
        if not self.string_results:
            self._initialize_string_table_placeholders()
            self.tbl_string.setUpdatesEnabled(True)
            self._position_checkbox_header_button()
            return

        self.tbl_string.setRowCount(len(self.string_results))
        self.string_row_checkboxes.clear()
        for row, item in enumerate(self.string_results):
            idx_item = self._make_table_item(str(row + 1), align=Qt.AlignCenter)
            raw_value = item.get('value', '')
            address = item.get('address', 0)
            preview_value = item.get('preview') or item.get('decrypted') or raw_value
            xref_list = item.get('xrefs') or []
            xref_text = '\n'.join(f'0x{ea:08X}' for ea in xref_list) if xref_list else '0'

            self.tbl_string.setItem(row, 1, idx_item)
            self.tbl_string.setItem(row, 2, self._make_table_item(raw_value, tooltip=raw_value))
            self.tbl_string.setItem(row, 3, self._make_table_item(f'0x{address:08X}', align=Qt.AlignCenter))
            self.tbl_string.setItem(row, 4, self._make_table_item(preview_value))
            self.tbl_string.setItem(row, 5, self._make_table_item(xref_text))
            self._add_checkbox_to_row(row)

        self.tbl_string.setUpdatesEnabled(True)
        self._update_checkbox_header_label()
        self._position_checkbox_header_button()

    def ignore_selected_strings(self):
        if not self.string_results:
            idaapi.msg('[Sharingan] No strings available to ignore.\n')
            return
        selected_rows = self._get_selected_string_rows()
        if not selected_rows:
            idaapi.msg('[Sharingan] Please select at least one string to ignore.\n')
            return
        values_to_ignore = []
        for row in selected_rows:
            item = self.tbl_string.item(row, 2)
            if item:
                values_to_ignore.append(item.text())
        if not values_to_ignore:
            idaapi.msg('[Sharingan] Unable to determine selected string values.\n')
            return
        if not self._append_ignore_strings(values_to_ignore):
            return
        selected_set = set(selected_rows)
        remaining_results = [entry for idx, entry in enumerate(self.string_results) if idx not in selected_set]
        self.populate_string_table(remaining_results)
        idaapi.msg(f'[Sharingan] Ignored {len(values_to_ignore)} string(s).\n')

    def apply_strings_decrypt(self):
        print('[Sharingan] Export report is not implemented yet.')

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
