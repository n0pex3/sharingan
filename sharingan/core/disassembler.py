import difflib
import os
import platform
import threading

import ida_bytes
import ida_hexrays
import ida_kernwin
import idaapi
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sharingan.core.StrFinder.string_finder import StringFinder
from sharingan.core.stringfindertable import StringFinderTable
from sharingan.core.stylesmanager import ManageStyleSheet
from sharingan.core.utils import Color, DeobfuscateUtils

FILTER_ACTION_NAME = "sharingan:filter"


class DBHook(idaapi.IDB_Hooks):
    def __init__(self, asm_view):
        super().__init__()
        self.asm_view = asm_view

    def byte_patched(self, ea, old_value):
        pass

    # highlight hint in asm_view
    def item_color_changed(self, ea, color):
        idx_line = set()
        if self.asm_view.mode == "decompiler":
            if ea in self.asm_view.eamap:
                items = self.asm_view.eamap[ea]
                for item in items:
                    if item.ea == ea:
                        coords = self.asm_view.cfunc.find_item_coords(item)
                        if coords:
                            _, y = coords
                            idx_line.add(y)

        if ea in self.asm_view.addr_asm_highlight:
            self.asm_view.addr_asm_highlight.discard(ea)
            self.asm_view.addr_pseudo_highlight ^= idx_line
            self.asm_view.addr_asm_overlap.discard(ea)
        elif color != Color.BG_BOOKMARK and color != Color.DEFCOLOR:
            if color == Color.BG_HINT:
                self.asm_view.addr_asm_highlight.add(ea)
                self.asm_view.addr_pseudo_highlight |= idx_line
            elif color == Color.BG_OVERLAPPING:
                self.asm_view.addr_asm_overlap.add(ea)


# color asm line
class ASMLine:
    def __init__(self, ea):
        self.label = idaapi.get_short_name(ea)
        self.address = ea
        self.padding = " " * 2

        # flags = idaapi.get_flags(ea)
        flags = ida_bytes.get_full_flags(ea)

        # if idaapi.is_head(flags):
        if ida_bytes.is_code(flags):
            self.colored_instruction = idaapi.generate_disasm_line(ea, 0)
            if not self.colored_instruction:
                self.colored_instruction = idaapi.COLSTR("??", idaapi.SCOLOR_ERROR)
        else:
            byte_val = idaapi.get_wide_byte(ea)
            s_val = f"{byte_val:02X}h"

            self.colored_instruction = (
                idaapi.COLSTR("db", idaapi.SCOLOR_KEYWORD)
                + " "
                + idaapi.COLSTR(s_val, idaapi.SCOLOR_DNUM)
            )

    @property
    def colored_address(self):
        return idaapi.COLSTR(f"{self.address:08X}", idaapi.SCOLOR_PREFIX)

    @property
    def colored_label(self):
        if not self.label:
            return None
        pretty_name = idaapi.COLSTR(self.label, idaapi.SCOLOR_CNAME) + ":"
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
        self.addr_asm_highlight = set()
        self.addr_asm_overlap = set()
        self.addr_pseudo_highlight = set()

        self.cfunc = None
        self.eamap = None

        self.idx_bookmark = 0
        self.count_manual_bookmark = 0

        self.db_hook = DBHook(self)
        self.db_hook.hook()

    def Create(self, name_windows, mode):
        if not super().Create(name_windows):
            return False
        self.mode = mode
        self.filter = Filter()

        # re-register action to prevent duplicate option
        idaapi.unregister_action(FILTER_ACTION_NAME)
        action_filter = idaapi.action_desc_t(
            FILTER_ACTION_NAME, "Filter", self.filter, None, None
        )
        assert idaapi.register_action(action_filter), (
            " Action filter registration failed"
        )

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
        self.clear_lines()

        last_item_type = None
        next_addr = start_ea
        last_was_nop = False

        while next_addr < end_ea:
            flags = idaapi.get_full_flags(next_addr)
            is_code = idaapi.is_code(flags)
            current_type = "code" if is_code else "junk"

            current_is_nop = False
            if is_code:
                current_is_nop = DeobfuscateUtils.is_nop(next_addr)

            if is_code and current_is_nop and last_was_nop:
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
                continue

            if last_item_type is not None and last_item_type != current_type:
                separator = idaapi.COLSTR(f" {next_addr:08X} " + ";" + "-" * 30, idaapi.SCOLOR_AUTOCMT)
                self.AddLine(separator)

            line = ASMLine(next_addr)

            if is_code and current_is_nop:
                line.colored_instruction = idaapi.COLSTR("NOP NOP NOP ...", idaapi.SCOLOR_INSN)

            if line.label:
                self.AddLine(line.colored_blank)
                self.AddLine(line.colored_label)
                self.lines_asm_before.append({"addr": next_addr, "content": line.colored_blank})
                self.lines_asm_before.append({"addr": next_addr, "content": line.colored_label})
            self.AddLine(line.colored_asmline)
            self.lines_asm_before.append({"addr": next_addr, "content": line.colored_asmline})
            # add data if found
            if current_type == 'code':
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
                last_was_nop = current_is_nop
            else:
                next_addr += 1
                last_was_nop = False
            last_item_type = current_type
        self.Refresh()


    def decompile(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.lines_pseudocode_before.clear()
        self.lines_pseudocode_before_raw.clear()

        if not ida_hexrays.init_hexrays_plugin():
            print("Fail init decompiler")
            return
        func = idaapi.get_func(start_ea)
        if func is None:
            print("Please provid address within a function")
            return
        self.cfunc = ida_hexrays.decompile(func_ea)
        self.eamap = self.cfunc.get_eamap()
        if self.cfunc is None:
            print("Failed to decompile!")
            return
        pseudocode = self.cfunc.get_pseudocode()
        self.clear_lines()
        for sline in pseudocode:
            self.AddLine(sline.line)
            # backup to diff
            self.lines_pseudocode_before.append(sline.line)
            self.lines_pseudocode_before_raw.append(idaapi.tag_remove(sline.line))
        self.Refresh()

    def set_signal_filter(self, signal_filter):
        self.filter.set_signal_filter(signal_filter)

    def popup_option_filter(self, widget, popup, ctx):
        if self.mode == "disassembler" and ida_kernwin.get_widget_title(widget) == 'asm_view':
            idaapi.attach_action_to_popup(widget, popup, FILTER_ACTION_NAME, None, 0)

    def highlight_diff_lines(self, out, widget, info):
        if widget != self._twidget:
            return
        for _, line in enumerate(info.sections_lines[0]):
            color = None
            splace = idaapi.place_t_as_simpleline_place_t(line.at)
            abs_line_idx = splace.n
            line_info = self.GetLine(splace.n)
            if not line_info:
                continue
            colored_line, _, _ = line_info

            if self.mode == 'disassembler':
                if colored_line.startswith("-"):
                    color = idaapi.CK_EXTRA11
                elif colored_line.startswith("+"):
                    color = idaapi.CK_EXTRA1
                else:
                    raw_line = idaapi.tag_remove(colored_line)
                    address = int(raw_line.split()[0], 16)
                    if address in self.addr_asm_highlight and self.idx_bookmark <= self.count_manual_bookmark:
                        color = idaapi.CK_EXTRA6
                    elif address in self.addr_asm_overlap and self.idx_bookmark <= self.count_manual_bookmark:
                        color = idaapi.CK_EXTRA4
                    else:
                        continue
            elif self.mode == 'decompiler':
                if colored_line.startswith("-"):
                    color = idaapi.CK_EXTRA11
                elif colored_line.startswith("+"):
                    color = idaapi.CK_EXTRA1
                elif abs_line_idx in self.addr_pseudo_highlight and self.idx_bookmark <= self.count_manual_bookmark:
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
            return (
                colored_lines[: sep_index + 1],
                colored_lines[sep_index + 1 :],
                raw_lines[: sep_index + 1],
                raw_lines[sep_index + 1 :],
            )
        else:
            # not found empty line, return all
            return [], colored_lines, [], raw_lines

    def diff_decompiler(self):
        if not ida_hexrays.init_hexrays_plugin():
            return

        func = idaapi.get_func(self.start_ea)
        if not func:
            return

        cfunc = ida_hexrays.decompile(func_ea)
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
        self.clear_lines()

        # split parts
        _, body_before, _, body_before_raw = self.split_header_body(
            self.lines_pseudocode_before_raw, self.lines_pseudocode_before
        )
        header_after, body_after, _, body_after_raw = self.split_header_body(
            lines_pseudocode_after_raw, lines_pseudocode_after
        )

        # print header after
        for line in header_after:
            self.AddLine(line)

        # diff
        matcher = difflib.SequenceMatcher(
            None, body_before_raw, body_after_raw, autojunk=False
        )
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for i in range(i1, i2):
                    self.AddLine(body_before[i])
            elif tag == "delete":
                for i in range(i1, i2):
                    self.AddLine(f"- {body_before[i]}")
            elif tag == "insert":
                for i in range(j1, j2):
                    self.AddLine(f"+ {body_after[i]}")
            elif tag == "replace":
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

        self.clear_lines()
        is_diff = False
        idx = 0
        last_was_nop = False

        for item in self.lines_asm_before:
            current_addr = item["addr"]

            if idx < len(intervals):
                start, end = intervals[idx]
            else:
                start, end = -1, -1

            # CASE 1: print code in obfuscated region (before)
            if start != -1 and start <= current_addr < end:
                self.AddLine(f"- {item['content']}")
                is_diff = True
                last_was_nop = False

            # CASE 2: print current code (after)
            elif is_diff and (start == -1 or current_addr >= end):
                is_diff = False

                # print deobfuscated code
                prev_start, prev_end = intervals[idx]
                current_ea = prev_start
                while current_ea < prev_end:
                    current_is_nop = DeobfuscateUtils.is_nop(current_ea)
                    if not (current_is_nop and last_was_nop):
                        line = ASMLine(current_ea)
                        if current_is_nop:
                            line.colored_instruction = idaapi.COLSTR("NOP NOP NOP ...", idaapi.SCOLOR_INSN)
                        self.AddLine(f"+ {line.colored_asmline}")

                    last_was_nop = current_is_nop
                    current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)

                idx += 1
                if idx < len(intervals):
                    next_start, next_end = intervals[idx]
                else:
                    next_start, next_end = -1, -1

                # check two patched sequence region, prevent missing
                if next_start != -1 and next_start <= current_addr < next_end:
                    self.AddLine(f"- {item['content']}")
                    is_diff = True
                    last_was_nop = False
                else:
                    # print normal code
                    self.AddLine(item["content"])
            # CASE 3: equal
            else:
                self.AddLine(item["content"])

        if is_diff and idx < len(intervals):
            is_diff = False
            prev_start, prev_end = intervals[idx]
            current_ea = prev_start
            while current_ea < prev_end:
                line = ASMLine(current_ea)
                self.AddLine(f"+ {line.colored_asmline}")
                current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)

        self.Refresh()

    def diff_code(self, obfuscated_regions):
        if self.mode == "decompiler":
            self.diff_decompiler()
        elif self.mode == "disassembler":
            self.diff_disassembler(obfuscated_regions)

    def clear_lines(self):
        self.ClearLines()
        self.Refresh()
        self.Jump(0, 0)


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

        self.cached_start_ea = 0
        self.cached_end_ea = 0
        self.mutex = threading.Lock()
        self.cached_mode = None
        self.mode = "disassembler"
        self.decryption_runner = None
        try:
            self.string_finder = StringFinder()
        except Exception as exc:
            self.string_finder = None
            idaapi.msg(f"[Sharingan] Failed to initialize StringFinder: {exc}\n")

        self.setup_ui()

    def setup_ui(self):
        self.lbl_start_ea = QLabel("Start EA")
        self.lbl_end_ea = QLabel("End EA")
        self.ldt_start_ea = QLineEdit()
        self.ldt_end_ea = QLineEdit()
        self.ldt_start_ea.setPlaceholderText("Start")
        self.ldt_end_ea.setPlaceholderText("End")
        self.ldt_start_ea.editingFinished.connect(self.switch_mode_display)
        self.ldt_end_ea.editingFinished.connect(self.switch_mode_display)
        self.btn_choose = QPushButton("Choose", parent=self)
        self.btn_choose.clicked.connect(self.choose_function)
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItem("Disassembler")
        self.cmb_mode.addItem("Decompiler")
        self.cmb_mode.addItem("String")
        self.cmb_mode.currentIndexChanged.connect(self.change_mode_code_string)

        self.asm_view = ASMView()
        assert self.asm_view.Create("asm_view", self.mode), "Fail loading ASMView"
        self.string_table = StringFinderTable(self.string_finder)

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
        self.layout_stack.addWidget(self.string_table)
        layout = QVBoxLayout(self)
        layout.addLayout(layout_toolbar, stretch=1)
        layout.addWidget(self.layout_stack, stretch=10)

    def __del__(self):
        self.db_hooks.unhook()

    def get_selected_string_rows(self):
        return self.string_table.get_selected_string_rows()

    def get_string_table_snapshot(self):
        return self.string_table.get_string_table_snapshot()

    def update_preview_at_location(self, ea, preview_value):
        return self.string_table.update_preview_at_location(ea, preview_value)

    def update_preview_row(self, row_index: int, preview_value):
        return self.string_table.update_preview_row(row_index, preview_value)

    def scan_code_strings(self):
        self.string_table.scan_code_strings()

    def populate_string_table(self, strings: list):
        self.string_table.populate_string_table(strings)

    def ignore_selected_strings(self):
        self.string_table.ignore_selected_strings()

    def change_mode_code_string(self, index):
        mode = self.cmb_mode.itemText(index)

        if mode.lower() == "string":
            self.layout_stack.setCurrentIndex(1)
            self.ldt_start_ea.setEnabled(False)
            self.ldt_end_ea.setEnabled(False)
        else:
            self.layout_stack.setCurrentIndex(0)
            self.ldt_start_ea.setEnabled(True)
            self.ldt_end_ea.setEnabled(True)
            self.asm_view.idx_bookmark = 0
            self.asm_view.count_manual_bookmark = 0

            self.mode = mode.lower()
            self.asm_view.mode = self.mode
            self.switch_mode_display()

    def get_line_edit_texts(self):
        return self.ldt_start_ea.text(), self.ldt_end_ea.text()

    def set_line_edit_texts(self, start_ea, end_ea, idx_bookmark, count_manual_bookmark, is_all_binary=False):
        if start_ea == end_ea:
            end_ea = start_ea
            for _ in range(256):
                end_ea = idaapi.next_head(end_ea, idaapi.BADADDR)
        self.ldt_start_ea.setText(hex(start_ea))
        self.ldt_end_ea.setText(hex(end_ea))
        self.asm_view.idx_bookmark = idx_bookmark
        self.asm_view.count_manual_bookmark = count_manual_bookmark
        if not is_all_binary:
            self.switch_mode_display()

    def choose_function(self):
        func = idaapi.choose_func(
            "Choose function to deobfuscate", idaapi.get_screen_ea()
        )
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
                    print("Empty address")
                    return

                start_ea = (
                    int(s_txt, 16) if s_txt.lower().startswith("0x") else int(s_txt)
                )
                end_ea = (
                    int(e_txt, 16) if e_txt.lower().startswith("0x") else int(e_txt)
                )

                if end_ea <= start_ea:
                    # Logic cũ dùng assert nhưng trong GUI không nên crash app, chỉ return
                    print("End EA must be greater than Start EA")
                    return

                if self.cached_start_ea == start_ea and self.cached_end_ea == end_ea and self.cached_mode == self.mode:
                    print("Same current range")
                    return

                self.cached_start_ea = start_ea
                self.cached_end_ea = end_ea
                self.cached_mode = self.mode

            except ValueError:
                print("Error parsing address")
                return

        if self.mode == "disassembler":
            self.asm_view.disassemble(start_ea, end_ea)
        elif self.mode == "decompiler":
            self.asm_view.decompile(start_ea, end_ea)

    def wrapper_diff_code(self, obfuscated_regions=None):
        self.asm_view.diff_code(obfuscated_regions)

    def set_signal_filter(self, signal_filter):
        self.asm_view.set_signal_filter(signal_filter)

    def set_decryption_runner(self, runner):
        self.decryption_runner = runner

    def clear_asmview(self):
        self.asm_view.clear_lines()

    def clear_input_address(self):
        self.ldt_start_ea.clear()
        self.ldt_end_ea.clear()

    def clear_cache_address(self):
        self.cached_start_ea = 0
        self.cached_end_ea = 0
        self.cached_mode = None

    def refresh_asmview(self):
        start_ea = self.asm_view.start_ea
        end_ea = self.asm_view.end_ea
        if self.mode == "disassembler":
            self.asm_view.disassemble(start_ea, end_ea)
        elif self.mode == "decompiler":
            self.asm_view.decompile(start_ea, end_ea)


# class handle list tab disassembler
class Disassembler(QTabWidget):
    def __init__(
        self,
    ):
        super().__init__()
        self.setTabsClosable(True)
        self.setUsesScrollButtons(True)
        self.setMovable(True)
        self.setObjectName("disassembler")
        self.tabCloseRequested.connect(self.close_tab)
        self.setup_ui()
        if platform.system().lower() == "windows":
            self.setProperty("applyWindows", "true")
        self.setStyleSheet(ManageStyleSheet.get_stylesheet())
        self.tab_contents = []
        self.signal_filter = None
        self.decryption_runner = None
        self.add_new_tab()

    def setup_ui(self):
        self.btn_add_tab = QPushButton(" + ")
        self.btn_add_tab.setObjectName("new_tab")
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
        return (
            self.tab_contents[index].get_line_edit_texts()
            if self.tab_contents[index]
            else []
        )

    def clear_tab_asmview(self, index):
        self.tab_contents[index].clear_asmview()
        self.tab_contents[index].clear_input_address()
        self.tab_contents[index].clear_cache_address()

    def set_tab_line_edit_texts(self, index, start_ea, end_ea, idx_bookmark, count_manual_bookmark, is_all_binary=False):
        self.tab_contents[index].set_line_edit_texts(start_ea, end_ea, idx_bookmark, count_manual_bookmark, is_all_binary)

    # display diff
    def compare_tab_code(self, index, obfuscated_regions=None):
        self.tab_contents[index].wrapper_diff_code(obfuscated_regions)

    # only refresh, no display diff
    def refresh_tab_asmview(self, index):
        self.tab_contents[index].refresh_asmview()

    def clear_highlight(self, index):
        self.tab_contents[index].asm_view.addr_asm_highlight.clear()
        self.tab_contents[index].asm_view.addr_pseudo_highlight.clear()
        self.tab_contents[index].asm_view.addr_asm_overlap.clear()
