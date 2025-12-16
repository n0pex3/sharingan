from PySide6.QtWidgets import QApplication, QTabWidget, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QSizePolicy, QComboBox, QTableWidget, QTableWidgetItem, QStackedWidget, QHeaderView, QAbstractItemView, QCheckBox, QToolButton
from PySide6.QtCore import Qt, QTimer
from sharingan.core.stylesmanager import ManageStyleSheet
import idaapi, ida_bytes, ida_hexrays, ida_kernwin
import threading, platform, difflib, os
from sharingan.core.utils import DeobfuscateUtils
from sharingan.core.StrFinder.string_finder import StringFinder


FILTER_ACTION_NAME = 'sharingan:filter'


class DBHook(idaapi.IDB_Hooks):
    def __init__(self, asm_view):
        super().__init__()
        self.asm_view = asm_view

    def byte_patched(self, ea, old_value):
        pass

    # highlight hint in asmview
    def item_color_changed(self, ea, color):
        if ea in self.asm_view.addr_asm_highlight:
            self.asm_view.addr_asm_highlight.remove(ea)
        else:
            self.asm_view.addr_asm_highlight.append(ea)


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

    @property
    def colored_address(self):
        return idaapi.COLSTR(f"{self.address:08X}", idaapi.SCOLOR_PREFIX)

    @property
    def colored_label(self):
        if not self.label:
            return None
        pretty_name = idaapi.COLSTR(self.label, idaapi.SCOLOR_CNAME) + ':'
        return f" {self.colored_address} {self.padding} {pretty_name}"

    @property
    def colored_blank(self):
        return f" {self.colored_address}"

    @property
    def colored_asmline(self):
        return f" {self.colored_address} {self.padding} {self.colored_instruction}"


# option right click filter region like this
class Filter(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def set_signal_filter(self, signal_filter):
        self.signal_filter = signal_filter

    def activate(self, ctx):
        if not self.signal_filter:
            return 0

        start_ea = idaapi.BADADDR
        end_ea = idaapi.BADADDR

        if ctx.cur_flags & idaapi.ACF_HAS_SELECTION:
            # handle selection
            viewer = idaapi.get_viewer_user_data(ctx.widget)

            # generate line at selection
            start_place = idaapi.place_t_as_simpleline_place_t(ctx.cur_sel._from.at)
            start_line = start_place.generate(viewer, 1)[0][0]
            end_place = idaapi.place_t_as_simpleline_place_t(ctx.cur_sel.to.at)
            end_line = end_place.generate(viewer, 1)[0][0]

            # parse start ea
            raw_start = idaapi.tag_remove(start_line).split()
            if raw_start:
                start_ea = int(raw_start[0], 16)
            # parse end ea
            raw_end = idaapi.tag_remove(end_line).split()
            if raw_end:
                end_ea = int(raw_end[0], 16)
                end_ea = idaapi.next_head(end_ea, idaapi.BADADDR)
        else:
            # handle single line
            colored_line = idaapi.get_custom_viewer_curline(ctx.widget, False)
            raw_line = idaapi.tag_remove(colored_line).split()
            if raw_line:
                start_ea = int(raw_line[0], 16)
                end_ea = start_ea

        if start_ea != idaapi.BADADDR:
            self.signal_filter.filter_.emit(start_ea, end_ea)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# override get_lines_rendering_info to highlight
# override finish_populating_widget_popup to insert option filter
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
        self.ui_hooks.get_lines_rendering_info = self.highlight_diff_lines
        self.ui_hooks.finish_populating_widget_popup = self.popup_option_filter

        self.start_ea = 0x0
        self.end_ea = 0x0
        self.lines_pseudocode_before = []
        self.lines_pseudocode_before_raw = []
        self.lines_asm_before = []
        self.addr_asm_highlight = []

        self.db_hook = DBHook(self)
        self.db_hook.hook()

    def Create(self, name_windows, mode):
        if not super().Create(name_windows):
            return False
        self.mode = mode
        self.filter = Filter()

        # re-register action to prevent duplicate option
        idaapi.unregister_action(FILTER_ACTION_NAME)
        action_filter = idaapi.action_desc_t(FILTER_ACTION_NAME, 'Filter', self.filter, None, None)
        assert idaapi.register_action(action_filter), ' Action filter registration failed'

        self._twidget = self.GetWidget()
        self.widget = idaapi.PluginForm.TWidgetToPyQtWidget(self._twidget)
        self.ui_hooks.hook()
        return True

    def OnClose(self):
        self.ui_hooks.unhook()
        idaapi.unregister_action(FILTER_ACTION_NAME)

    def disassemble(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.lines_asm_before.clear()
        self.ClearLines()

        next_addr = start_ea
        while next_addr < end_ea:
            line = ASMLine(next_addr)
            if line.label:
                self.AddLine(line.colored_blank)
                self.AddLine(line.colored_label)
                # backup to diff
                self.lines_asm_before.append({
                    'addr': next_addr,
                    'content': line.colored_blank
                })
                self.lines_asm_before.append({
                    'addr': next_addr,
                    'content': line.colored_label
                })
            self.AddLine(line.colored_asmline)
            self.lines_asm_before.append({
                'addr': next_addr,
                'content': line.colored_asmline
            })
            # add data if found
            flags = idaapi.get_flags(next_addr)
            if idaapi.is_head(flags):
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
            else:
                next_addr += 1
        self.Refresh()

    def decompile(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.lines_pseudocode_before.clear()
        self.lines_pseudocode_before_raw.clear()

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
        for sline in pseudocode:
            self.AddLine(sline.line)
            # backup to diff
            self.lines_pseudocode_before.append(sline.line)
            self.lines_pseudocode_before_raw.append(idaapi.tag_remove(sline.line))
        self.Refresh()

    def set_signal_filter(self, signal_filter):
        self.filter.set_signal_filter(signal_filter)

    def popup_option_filter(self, widget, popup, ctx):
        if self.mode == 'disassembler':
           idaapi.attach_action_to_popup(widget, popup, FILTER_ACTION_NAME, None, 0)

    def highlight_diff_lines(self, out, widget, info):
        if widget != self._twidget:
            return
        for _, line in enumerate(info.sections_lines[0]):
            splace = idaapi.place_t_as_simpleline_place_t(line.at)
            line_info = self.GetLine(splace.n)
            if not line_info:
                continue
            colored_line, _, _ = line_info
            if colored_line.startswith('-'):
                color = idaapi.CK_EXTRA11
            elif colored_line.startswith('+'):
                color = idaapi.CK_EXTRA1
            else:
                raw_line = idaapi.tag_remove(colored_line)
                address = int(raw_line.split()[0], 16)
                if address in self.addr_asm_highlight:
                    color = idaapi.CK_EXTRA6
                else:
                    continue
            e = idaapi.line_rendering_output_entry_t(line)
            e.bg_color = color
            e.flags = idaapi.LROEF_FULL_LINE
            out.entries.push_back(e)

    def split_header_body(self, raw_lines, colored_lines):
        sep_index = -1
        for i, line in enumerate(raw_lines):
            # find empty line, border header and content
            if not line.strip():
                sep_index = i
                break

        # return parts header, body of color and raw line
        if sep_index != -1:
            return (colored_lines[:sep_index+1], colored_lines[sep_index+1:],
                    raw_lines[:sep_index+1], raw_lines[sep_index+1:])
        else:
            # not found empty line, return all
            return [], colored_lines, [], raw_lines

    def diff_decompiler(self):
        if not ida_hexrays.init_hexrays_plugin():
            return

        func = idaapi.get_func(self.start_ea)
        if not func:
            return

        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            return

        pseudocode_obj = cfunc.get_pseudocode()
        lines_pseudocode_after = []
        lines_pseudocode_after_raw = []
        # capture after state
        for sline in pseudocode_obj:
            lines_pseudocode_after.append(sline.line)
            lines_pseudocode_after_raw.append(idaapi.tag_remove(sline.line))

        self.pseudocode = lines_pseudocode_after_raw
        self.ClearLines()

        # split parts
        _, body_before, _, body_before_raw = self.split_header_body(self.lines_pseudocode_before_raw, self.lines_pseudocode_before)
        header_after, body_after, _, body_after_raw = self.split_header_body(lines_pseudocode_after_raw, lines_pseudocode_after)

        # print header after
        for line in header_after:
            self.AddLine(line)

        # diff
        matcher = difflib.SequenceMatcher(None, body_before_raw, body_after_raw, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for i in range(i1, i2):
                    self.AddLine(body_before[i])
            elif tag == 'delete':
                for i in range(i1, i2):
                    self.AddLine(f"- {body_before[i]}")
            elif tag == 'insert':
                for i in range(j1, j2):
                    self.AddLine(f"+ {body_after[i]}")
            elif tag == 'replace':
                for i in range(i1, i2):
                    self.AddLine(f"- {body_before[i]}")
                for i in range(j1, j2):
                    self.AddLine(f"+ {body_after[i]}")

        self.Refresh()

    def diff_disassembler(self, obfuscated_regions):
        # flatten
        intervals = []
        for list_regions in obfuscated_regions:
            for r in list_regions:
                for region_part in r.regions:
                    intervals.append((region_part.start_ea, region_part.end_ea))
        intervals.sort(key=lambda x: (x[0], x[1]))

        self.ClearLines()
        is_diff = False
        idx = 0

        for item in self.lines_asm_before:
            # current_addr = int(item['addr'], 16)
            current_addr = item['addr']

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
                        self.AddLine("+ {line.colored_asmline}")
                        current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)

                    idx += 1
                    if idx < len(intervals):
                        next_start, next_end = intervals[idx]
                    else:
                        next_start, next_end = -1, -1
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
                    self.AddLine(f"+ {line.colored_asmline}")
                    current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)

                idx += 1
                if idx < len(intervals):
                    next_start, next_end = intervals[idx]
                else:
                    next_start, next_end = -1, -1

                # check two patched sequence region, prevent missing
                if next_start != -1 and next_start <= current_addr < next_end:
                        self.AddLine("- {item['content']}")
                        is_diff = True
                else:
                    # print normal code
                    self.AddLine(item['content'])
            # CASE 3: equal
            else:
                self.AddLine(item['content'])
        self.Refresh()

    def diff_code(self, obfuscated_regions):
        if self.mode == 'decompiler':
            self.diff_decompiler()
        elif self.mode == 'disassembler':
            self.diff_disassembler(obfuscated_regions)


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
        self._last_checkbox_row = None
        self.decryption_runner = None
        try:
            self.string_finder = StringFinder()
        except Exception as exc:
            self.string_finder = None
            idaapi.msg(f"[Sharingan] Failed to initialize StringFinder: {exc}\n")

        self.setup_ui()

    def setup_ui(self):
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
        self.cmb_mode = QComboBox()
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

        button_bar = QHBoxLayout()
        button_bar.addWidget(self.btn_scan_code)
        button_bar.addWidget(self.btn_ignore_strings)
        button_bar.addStretch()
        layout.addLayout(button_bar)

        self.tbl_string = QTableWidget()
        self.tbl_string.setColumnCount(6)
        self.tbl_string.setHorizontalHeaderLabels(['', '#', 'Raw', 'Address', 'Preview', 'Xref'])
        self.tbl_string.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_string.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl_string.setSelectionBehavior(QAbstractItemView.SelectRows)
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
        self.checkbox_header_container = QWidget(header)
        container_layout = QHBoxLayout(self.checkbox_header_container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setAlignment(Qt.AlignCenter)
        self.checkbox_header_button = QToolButton(self.checkbox_header_container)
        self.checkbox_header_button.setAutoRaise(True)
        self.checkbox_header_button.setCursor(Qt.PointingHandCursor)
        self.checkbox_header_button.setToolTip('Toggle all selections')
        self.checkbox_header_button.clicked.connect(self._handle_header_checkbox_button)
        container_layout.addWidget(self.checkbox_header_button)
        header.sectionResized.connect(self._position_checkbox_header_button)
        header.sectionMoved.connect(self._position_checkbox_header_button)
        header.geometriesChanged.connect(self._position_checkbox_header_button)
        self.tbl_string.horizontalScrollBar().valueChanged.connect(self._position_checkbox_header_button)
        self.tbl_string.cellClicked.connect(self._handle_cell_clicked)

        layout.addWidget(self.tbl_string)
        self._initialize_string_table_placeholders()
        self._update_checkbox_header_label()
        QTimer.singleShot(0, self._position_checkbox_header_button)
        return workspace

    def _initialize_string_table_placeholders(self):
        self.tbl_string.setRowCount(1)
        self.tbl_string.clearContents()
        self.string_row_checkboxes.clear()
        self._last_checkbox_row = None
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
            checkbox.clicked.connect(lambda checked, r=row: self._handle_row_checkbox_clicked(r, checked))
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

    def _handle_row_checkbox_clicked(self, row: int, checked: bool):
        self._select_row_from_checkbox(row)
        modifiers = QApplication.keyboardModifiers()
        if modifiers & Qt.ShiftModifier and self._last_checkbox_row is not None:
            self._set_checkbox_range_state(self._last_checkbox_row, row, checked)
        self._last_checkbox_row = row

    def _set_checkbox_range_state(self, start_row: int, end_row: int, state: bool):
        if not self.string_row_checkboxes:
            return
        lower = max(0, min(start_row, end_row))
        upper = min(len(self.string_row_checkboxes) - 1, max(start_row, end_row))
        for idx in range(lower, upper + 1):
            checkbox = self.string_row_checkboxes[idx]
            checkbox.blockSignals(True)
            checkbox.setChecked(state)
            checkbox.blockSignals(False)
        self._update_checkbox_header_label()

    def _select_row_from_checkbox(self, row: int):
        if 0 <= row < self.tbl_string.rowCount():
            self.tbl_string.selectRow(row)

    def _handle_cell_clicked(self, row: int, column: int):
        self.tbl_string.selectRow(row)
        if column == 5:
            self._print_xrefs_for_row(row)

    def _print_xrefs_for_row(self, row: int):
        if not (0 <= row < len(self.string_results)):
            idaapi.msg("[Sharingan] No xref data for this row.\n")
            return
        entry = self.string_results[row]
        if not isinstance(entry, dict):
            idaapi.msg("[Sharingan] No xref data for this row.\n")
            return

        def _normalize_ea(value):
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 16) if value.lower().startswith("0x") else int(value)
                except ValueError:
                    return None
            return None

        raw_xrefs = entry.get('xrefs') or []
        normalized = [ea for ea in (_normalize_ea(x) for x in raw_xrefs) if ea is not None]
        if not normalized:
            idaapi.msg("[Sharingan] No xrefs recorded for the selected string.\n")
            return

        formatted = ', '.join(f"0x{ea:08X}" for ea in normalized)
        idaapi.msg(f"[Sharingan] Xrefs for row {row + 1}: {formatted}\n")

    def _update_checkbox_header_label(self):
        if not hasattr(self, 'checkbox_header_button'):
            return
        self.checkbox_header_button.setText('\u2611' if self._are_all_rows_checked() else '\u2610')

    def _are_all_rows_checked(self) -> bool:
        return bool(self.string_row_checkboxes) and all(cb.isChecked() for cb in self.string_row_checkboxes)

    def _set_all_row_checkboxes(self, state: bool):
        for cb in self.string_row_checkboxes:
            cb.blockSignals(True)
            cb.setChecked(state)
            cb.blockSignals(False)
        self._last_checkbox_row = None
        self._update_checkbox_header_label()

    def _handle_header_checkbox_button(self):
        select_all = not self._are_all_rows_checked()
        self._set_all_row_checkboxes(select_all)

    def _position_checkbox_header_button(self, *args):
        if not hasattr(self, 'checkbox_header_container') or not self.checkbox_header_container:
            return
        header = self.tbl_string.horizontalHeader()
        if self.checkbox_header_index >= header.count():
            return
        x = header.sectionViewportPosition(self.checkbox_header_index)
        width = header.sectionSize(self.checkbox_header_index)
        self.checkbox_header_container.setGeometry(x, 0, width, header.height())
        self.checkbox_header_container.show()

    def get_selected_string_rows(self):
        selected_rows = []
        for idx, checkbox in enumerate(self.string_row_checkboxes):
            if checkbox.isEnabled() and checkbox.isChecked():
                selected_rows.append(idx)
        return selected_rows

    def get_string_table_snapshot(self):
        if not self.string_results:
            return []
        snapshot = []
        for item in self.string_results:
            if isinstance(item, dict):
                snapshot.append((item.get('value', ''), item.get('address')))
            else:
                snapshot.append((item, None))
        return snapshot

    def _apply_preview_to_row(self, row: int, preview_value) -> bool:
        if not (0 <= row < len(self.string_results)):
            return False
        entry = self.string_results[row]
        if isinstance(entry, dict):
            entry['preview'] = preview_value
        text = str(preview_value)
        table_item = self.tbl_string.item(row, 4)
        if table_item:
            table_item.setText(text)
            table_item.setToolTip(text)
        else:
            self.tbl_string.setItem(row, 4, self._make_table_item(text, tooltip=text))
        return True

    def update_preview_at_location(self, ea, preview_value):
        if ea is None or not self.string_results:
            return False

        def _normalize_address(value):
            if value is None:
                return None
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 16) if value.lower().startswith('0x') else int(value)
                except ValueError:
                    return None
            return None

        target = _normalize_address(ea)
        if target is None:
            return False

        updated = False
        for row, entry in enumerate(self.string_results):
            current = _normalize_address(entry.get('address') if isinstance(entry, dict) else None)
            if current != target:
                continue
            if self._apply_preview_to_row(row, preview_value):
                updated = True
        return updated

    def update_preview_row(self, row_index: int, preview_value):
        return self._apply_preview_to_row(row_index, preview_value)

    def scan_code_strings(self):
        if self.string_finder is None:
            idaapi.msg('[Sharingan] String Finder modules unavailable.\n')
            return
        self.btn_scan_code.setEnabled(False)
        self.btn_scan_code.setText('Scanning...')
        ida_kernwin.execute_sync(self._run_scan_code_strings, ida_kernwin.MFF_WRITE)

    def _run_scan_code_strings(self):
        results = []
        try:
            results = self.string_finder.find_all_encrypted_strings()
        except Exception as exc:
            idaapi.msg(f"[Sharingan] String scan failed: {exc}\n")
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
        self._last_checkbox_row = None
        for row, item in enumerate(self.string_results):
            idx_item = self._make_table_item(str(row + 1), align=Qt.AlignCenter)
            raw_value = item.get('value', '')
            address = item.get('address', 0)
            preview_value = item.get('preview') or raw_value
            xref_list = item.get('xrefs') or []
            xref_text = '\n'.join(f"0x{ea:08X}" for ea in xref_list) if xref_list else '0'

            self.tbl_string.setItem(row, 1, idx_item)
            self.tbl_string.setItem(row, 2, self._make_table_item(raw_value, tooltip=raw_value))
            self.tbl_string.setItem(row, 3, self._make_table_item(f"0x{address:08X}", align=Qt.AlignCenter))
            self.tbl_string.setItem(row, 4, self._make_table_item(preview_value, tooltip=preview_value))
            self.tbl_string.setItem(row, 5, self._make_table_item(xref_text, tooltip=xref_text))
            self._add_checkbox_to_row(row)

        self.tbl_string.setUpdatesEnabled(True)
        self._update_checkbox_header_label()
        self._position_checkbox_header_button()

    def ignore_selected_strings(self):
        if not self.string_results:
            idaapi.msg('[Sharingan] No strings available to ignore.\n')
            return
        selected_rows = self.get_selected_string_rows()
        if not selected_rows:
            idaapi.msg('[Sharingan] Please select at least one string to ignore.\n')
            return
        values_to_ignore = []
        for row in selected_rows:
            item = self.tbl_string.item(row, 2)
            if item and item.text():
                values_to_ignore.append(item.text())
        if not values_to_ignore:
            idaapi.msg('[Sharingan] Unable to determine selected string values.\n')
            return
        if not self._append_ignore_strings(values_to_ignore):
            return
        selected_set = set(selected_rows)
        remaining_results = [entry for idx, entry in enumerate(self.string_results) if idx not in selected_set]
        self.populate_string_table(remaining_results)
        idaapi.msg(f"[Sharingan] Ignored {len(values_to_ignore)} string(s).\n")

    def _append_ignore_strings(self, strings):
        store = getattr(self.string_finder, 'ignore_store', None)
        if not store or not store.user_path:
            idaapi.msg('[Sharingan] Ignore store is unavailable.\n')
            return False
        new_literals = store.append_literals(strings)
        if not new_literals:
            idaapi.msg('[Sharingan] Selected strings already ignored.\n')
            return False
        self.string_finder.result_filter.ignore_literals.update(new_literals)
        return True

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
        self.switch_mode_display()

    def switch_mode_display(self):
        with self.mutex:
            try:
                s_txt = self.ldt_start_ea.text().strip()
                e_txt = self.ldt_end_ea.text().strip()

                if not s_txt or not e_txt:
                    print('Empty address')
                    return

                start_ea = int(s_txt, 16) if s_txt.lower().startswith("0x") else int(s_txt)
                end_ea = int(e_txt, 16) if e_txt.lower().startswith("0x") else int(e_txt)

                if end_ea <= start_ea:
                    # Logic cũ dùng assert nhưng trong GUI không nên crash app, chỉ return
                    print("End EA must be greater than Start EA")
                    return

                if self.cached_start_ea == start_ea and self.cached_end_ea == end_ea:
                    print('Same previous range')
                    return

                self.cached_start_ea = start_ea
                self.cached_end_ea = end_ea

            except ValueError:
                print("Error parsing address")
                return

        if self.mode == 'disassembler':
            self.asm_view.disassemble(start_ea, end_ea)
        elif self.mode == 'decompiler':
            self.asm_view.decompile(start_ea, end_ea)

    def wrapper_diff_code(self, obfuscated_regions=None):
        self.asm_view.diff_code(obfuscated_regions)

    def set_signal_filter(self, signal_filter):
        self.asm_view.set_signal_filter(signal_filter)

    def set_decryption_runner(self, runner):
        self.decryption_runner = runner

    def clear_asmview(self):
        self.asm_view.ClearLines()

    def refresh_asmview(self):
        start_ea = self.asm_view.start_ea
        end_ea = self.asm_view.end_ea
        if self.mode == 'disassembler':
            self.asm_view.disassemble(start_ea, end_ea)
        elif self.mode == 'decompiler':
            self.asm_view.decompile(start_ea, end_ea)


# class handle list tab disassembler
class Disassembler(QTabWidget):
    def __init__(self, ):
        super().__init__()
        self.setTabsClosable(True)
        self.setMovable(True)
        self.setObjectName('disassembler')
        self.tabCloseRequested.connect(self.close_tab)
        self.setup_ui()
        if platform.system().lower() == 'windows':
            self.setProperty('applyWindows', 'true')
        self.setStyleSheet(ManageStyleSheet.get_stylesheet())
        self.tab_contents = []
        self.signal_filter = None
        self.decryption_runner = None
        self.add_new_tab()

    def setup_ui(self):
        self.btn_add_tab = QPushButton(' + ')
        self.btn_add_tab.setObjectName('new_tab')
        self.btn_add_tab.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        self.btn_add_tab.clicked.connect(self.add_new_tab)
        self.setCornerWidget(self.btn_add_tab, Qt.TopRightCorner)

    def _current_tab(self):
        idx = self.currentIndex()
        if 0 <= idx < len(self.tab_contents):
            return self.tab_contents[idx]
        return None

    @property
    def tbl_string(self):
        tab = self._current_tab()
        return tab.get_string_table_snapshot() if tab else []

    def update_preview_for_row(self, row_idx, preview_value):
        tab = self._current_tab()
        return tab.update_preview_row(row_idx, preview_value) if tab else False

    def set_tab_signal_filter(self, signal_filter):
        self.signal_filter = signal_filter
        self.tab_contents[self.currentIndex()].set_signal_filter(self.signal_filter)

    def set_tab_decryption_runner(self, runner):
        self.decryption_runner = runner
        self.tab_contents[self.currentIndex()].set_decryption_runner(runner)

    def add_new_tab(self):
        tab_content = DisassembleTab(self)
        self.addTab(tab_content, f"Tab {self.count() + 1}")
        self.tab_contents.append(tab_content)
        if self.signal_filter:
            tab_content.set_signal_filter(self.signal_filter)
        if self.decryption_runner:
            tab_content.set_decryption_runner(self.decryption_runner)

    def close_tab(self, index):
        if self.count() > 1:
            self.removeTab(index)
            self.tab_contents.pop(index)

    def get_selected_string_indices(self):
        tab = self._current_tab()
        return tab.get_selected_string_rows() if tab else []

    def update_preview_at_location(self, ea, preview_value):
        tab = self._current_tab()
        if not tab:
            return False
        return tab.update_preview_at_location(ea, preview_value)

    def get_tab_line_edit_texts(self, index):
        return self.tab_contents[index].get_line_edit_texts() if self.tab_contents[index] else []

    def clear_tab_asmview(self, index):
        self.tab_contents[index].clear_asmview()

    def set_tab_line_edit_texts(self, index, start_ea, end_ea, is_all_binary=False):
        self.tab_contents[index].set_line_edit_texts(start_ea, end_ea, is_all_binary)

    # display diff
    def compare_tab_code(self, index, obfuscated_regions=None):
        self.tab_contents[index].wrapper_diff_code(obfuscated_regions)

    # only refresh, no display diff
    def refresh_tab_asmview(self, index):
        self.tab_contents[index].refresh_asmview()
