from typing import Any
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, QSizePolicy, QCheckBox
from PySide6.QtCore import Qt, Signal, QObject, Slot
from sharingan.base.dragdroprecipe import DragDropRecipe
from sharingan.core.utils import (
    DeobfuscateUtils,
    DecryptionUtils,
    Color,
    ManageStyleSheet,
    OperatorMode,
)
from sharingan.core.region_registry import Region, RegionKind, RegionRegistry, RegionRenderer
from sharingan.base.ingredient import Decryption, Deobfuscator
from sharingan.base.obfuscatedregion import Action, ListObfuscatedRegion
import ida_bytes, idaapi, idc


# display raw instruction via hint
class HintRawInsn(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.hooked = False
        self.dict_hints = dict()

    def hook(self):
        if not self.hooked:
            super().hook()
            self.hooked = True
            print("[Sharingan] Hint hook installed.")

    def unhook(self):
        if self.hooked:
            super().unhook()
            self.hooked = False
            print("[Sharingan] Hint hook removed.")

    def insert_hint(self, ea, hint):
        self.dict_hints[ea] = hint

    def remove_hint(self, ea):
        print('[Sharingan] Remove hint', hex(ea))
        self.dict_hints.pop(ea)

    # override to custom return hint
    def get_custom_viewer_hint(self, viewer, place):
        if place:
            ea = place.toea()
            if hint := self.dict_hints.get(ea):
                return hint, len(hint.split('\n'))
        return None


# handle revert bytes (option exclusion right click)
class PatchedBytesVistor(object):
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea

    def __call__(self, ea, fpos, original_bytes, patch_bytes, cnt=()):
        if  self.start_ea <= ea < self.end_ea:
            ida_bytes.revert_byte(ea)
        return 0


# signal for filter action in asm_view or disassembler ida
class FilterSignal(QObject):
    filter_ = Signal(object, object)


class Recipe(QWidget):
    def __init__(self, disassembler=None):
        super().__init__()
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.obfuscated_regions = []
        self.overlapping_regions = set()
        self.count_manual_bookmark = 0
        self.start_ea = 0x0
        self.end_ea = 0x0

        self.hint_hook = HintRawInsn()
        self.hint_hook.hook()

        # registry holds typed regions; renderer paints them on disassembler
        self.registry = RegionRegistry()
        self.renderer = RegionRenderer(self.registry)
        if not self.renderer.hook():
            print('[Sharingan] RegionRenderer hook failed')

        self.disassembler = disassembler

        self.signal_filter = FilterSignal()
        self.disassembler.set_tab_signal_filter(self.signal_filter)
        self.signal_filter.filter_.connect(self.add_ingredient_substitute)

        if hasattr(self.disassembler, 'set_tab_decryption_runner'):
            self.disassembler.set_tab_decryption_runner(self.run_decryption)

        self.setup_ui()
        self.list_recipe.setStyleSheet(ManageStyleSheet.get_stylesheet())
        # when append or delete bookmark (manual), it auto save. So when lost tab or exit ida, it can load previous bookmark
        self.load_bookmarks()
        self.load_patched_regions()

    def setup_ui(self):
        self.list_recipe = DragDropRecipe()
        self.list_recipe.setObjectName('list_recipe')
        self.btn_delete = QPushButton('Delete')
        self.btn_delete.clicked.connect(self.delete_ingredient)
        self.btn_cook = QPushButton('Cook')
        self.btn_cook.clicked.connect(self.cook)
        self.btn_preview = QPushButton('Preview')
        self.btn_preview.clicked.connect(self.preview)
        self.btn_clear_bookmark = QPushButton('Reset')
        self.btn_clear_bookmark.clicked.connect(self.reset)
        self.cmb_bookmark = QComboBox()
        self.cmb_bookmark.activated.connect(self.disassemble_range_addr)
        self.cmb_bookmark.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.cmb_bookmark.addItem('Manual')
        self.cmb_bookmark.model().item(0).setEnabled(False)
        self.cmb_bookmark.addItem('Scanning')
        self.cmb_bookmark.model().item(1).setEnabled(False)
        self.btn_resolve = QPushButton('Resolve')
        self.btn_resolve.clicked.connect(self.resolve)

        self.chk_compact = QCheckBox(text='Compact')
        self.chk_auto_patch = QCheckBox(text='Auto patch')
        self.chk_all_binary = QCheckBox(text='All binary')
        self.chk_all_binary.stateChanged.connect(self.replace_start_end_by_all)

        self.layout_checkbox = QHBoxLayout()
        self.layout_checkbox.addWidget(self.chk_compact)
        self.layout_checkbox.addWidget(self.chk_auto_patch)
        self.layout_checkbox.addWidget(self.chk_all_binary)
        self.layout_checkbox.setAlignment(Qt.AlignJustify)

        self.layout_button = QHBoxLayout()
        self.layout_button.addWidget(self.btn_resolve)
        self.layout_button.addWidget(self.btn_delete)
        self.layout_button.addWidget(self.btn_preview)
        self.layout_button.addWidget(self.btn_clear_bookmark)
        self.layout_button.setAlignment(Qt.AlignJustify)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.cmb_bookmark)
        self.layout.addLayout(self.layout_checkbox)
        self.layout.addLayout(self.layout_button)
        self.layout.addWidget(self.list_recipe)
        self.layout.addWidget(self.btn_cook)
        self.setLayout(self.layout)

    # explicit teardown so plugin close path doesn't rely on GC for unhooking
    def cleanup(self):
        try:
            self.hint_hook.unhook()
        except Exception:
            pass
        try:
            self.renderer.unhook()
        except Exception:
            pass

    def __del__(self):
        self.cleanup()

    # check if bookmark is saved to restore
    def get_bookmark_node(self):
        NODE_NAME = "$sharingan_bookmarks"
        node = idaapi.netnode(NODE_NAME)

        if node.index() == idaapi.BADADDR:
            node.create(NODE_NAME)
        return node

    def get_patched_node(self):
        NODE_NAME = "$sharingan_patched"
        node = idaapi.netnode(NODE_NAME)
        if node.index() == idaapi.BADADDR:
            node.create(NODE_NAME)
        return node

    # persist PATCHED entries so the visual marker survives IDA restart
    def save_patched_regions(self):
        node = self.get_patched_node()
        node.supdel_all(idaapi.stag)
        patched = self.registry.all([RegionKind.PATCHED])
        node.altset(0, len(patched))
        for i, r in enumerate(patched):
            text = f"{r.start_ea}|{r.end_ea}|{r.hint}"
            node.supset(i, text.encode('utf-8'))

    def load_patched_regions(self):
        node = self.get_patched_node()
        if node.index() == idaapi.BADADDR:
            return
        count = node.altval(0)
        if count <= 0:
            return
        for i in range(count):
            val = node.supstr(i)
            if not val:
                continue
            parts = val.split('|', 2)
            if len(parts) < 2:
                continue
            try:
                s = int(parts[0])
                e = int(parts[1])
            except ValueError:
                continue
            hint = parts[2] if len(parts) == 3 else ''
            self.registry.add(Region(s, e, RegionKind.PATCHED, hint))
        idaapi.refresh_idaview_anyway()

    # mirror current combobox bookmarks into registry; HINT/OVERLAP/PATCHED untouched
    def sync_bookmarks_to_registry(self):
        self.registry.clear([RegionKind.MANUAL_BM, RegionKind.SCAN_BM])
        scan_label_idx = self.count_manual_bookmark + 1
        for i in range(1, self.cmb_bookmark.count()):
            if i == scan_label_idx:
                continue
            s, e = self.parse_start_end_region(i)
            if not s and not e:
                continue
            parts = self.cmb_bookmark.itemText(i).split(' - ', 2)
            hint = parts[2] if len(parts) == 3 else ''
            kind = RegionKind.MANUAL_BM if i <= self.count_manual_bookmark else RegionKind.SCAN_BM
            self.registry.add(Region(s, e, kind, hint))

    # push HINT/OVERLAP intervals to every tab so highlights survive tab switches
    def push_highlights_to_view(self):
        hint_iv = [(r.start_ea, r.end_ea) for r in self.registry.all([RegionKind.HINT])]
        overlap_iv = [(r.start_ea, r.end_ea) for r in self.registry.all([RegionKind.OVERLAP])]
        for idx in range(self.disassembler.count()):
            self.disassembler.update_tab_highlights(idx, hint_iv, overlap_iv)
        idaapi.refresh_idaview_anyway()

    # cmb_bookmark is saved into database ida
    def save_bookmarks(self):
        node = self.get_bookmark_node()
        node.supdel_all(idaapi.stag)

        node.altset(0, self.count_manual_bookmark)
        total_count = self.cmb_bookmark.count()
        node.altset(1, total_count)

        for i in range(total_count):
            text = self.cmb_bookmark.itemText(i)
            node.supset(i, text.encode('utf-8'))

        print(f"[Sharingan] Saved {total_count} items. Manual count marker: {self.count_manual_bookmark}")

    # restore bookmark and load into QComboBox
    def load_bookmarks(self):
        node = self.get_bookmark_node()
        if node.index() == idaapi.BADADDR:
            return

        total_count = node.altval(1)
        if total_count <= 0:
            return

        # block signal to prevent asm_view load
        self.cmb_bookmark.blockSignals(True)
        self.cmb_bookmark.clear()

        self.count_manual_bookmark = node.altval(0)

        for i in range(total_count):
            val = node.supstr(i)
            if val:
                self.cmb_bookmark.addItem(val)

        if self.cmb_bookmark.count() > 0:
            self.cmb_bookmark.model().item(0).setEnabled(False)

        scanning_label_idx = self.count_manual_bookmark + 1
        if self.cmb_bookmark.count() > scanning_label_idx:
            self.cmb_bookmark.model().item(scanning_label_idx).setEnabled(False)

        self.cmb_bookmark.blockSignals(False)
        self.sync_bookmarks_to_registry()
        idaapi.refresh_idaview_anyway()
        print(f"[Sharingan] Restored bookmarks.")

    # value in QComboBox is text and seperated by dash. Splitting start and end region via dash
    def parse_start_end_region(self, index):
        selection = self.cmb_bookmark.itemText(index)
        if selection in ('Scanning', 'Manual'):
            return 0, 0
        parts = selection.split(' - ')
        if len(parts) == 3:
            return int(parts[0], 0), int(parts[1], 0)
        return 0, 0

    # clear all scanning regions in cmb_bookmark and all content of asm_view
    # if preview running, keep content asm_view, only delete scanning regions
    def reset(self, is_preview=False):
        start_index = self.count_manual_bookmark + 1
        end_index = self.cmb_bookmark.count() - 1
        for index in range(end_index, start_index, -1):
            start_region, end_region = self.parse_start_end_region(index)
            DeobfuscateUtils.reset(start_region, end_region)
            self.cmb_bookmark.removeItem(index)

        self.obfuscated_regions.clear()
        # PATCHED + MANUAL_BM survive reset; scanning state is wiped
        self.registry.clear([RegionKind.SCAN_BM, RegionKind.HINT, RegionKind.OVERLAP])

        active_index = self.disassembler.currentIndex()
        self.disassembler.clear_highlight(active_index)
        if not is_preview:
            self.disassembler.clear_tab_asmview(active_index)
        self.save_bookmarks()
        idaapi.refresh_idaview_anyway()
        print('[Sharingan] Reset all')

    # delete item in list recipe
    def delete_ingredient(self):
        list_selection = self.list_recipe.selectedIndexes()
        # delete selection
        if list_selection:
            # reverse sorted list to delete
            sorted_list_selection = sorted(list_selection, key=lambda x: x.row(), reverse=True)
            for index in sorted_list_selection:
                item = self.list_recipe.itemFromIndex(index)
                self.list_recipe.removeItemWidget(item)
                self.list_recipe.takeItem(index.row())
        else:
            # clear all
            for i in range(self.list_recipe.count()):
                item = self.list_recipe.item(i)
                self.list_recipe.removeItemWidget(item)
            self.list_recipe.clear()

    # add ingredient substitute into recipe (column2) via option filter (asm_view/disassembler)
    @Slot(object, object)
    def add_ingredient_substitute(self, start_ea, end_ea):
        obj_substitute = self.list_recipe.classify_algorithm('substitute')
        if obj_substitute:
            obj_substitute.set_obfuscated_start_end_ea(start_ea, end_ea)
            self.list_recipe.insert_ingredient_recipe(obj_substitute, None)

    # if checkbox "all binary" turn on, start and end disassemble will be replace by start of first segment and end of last segment
    def replace_start_end_by_all(self):
        if not self.chk_all_binary.isChecked():
            return

        start_binary = idaapi.get_imagebase()
        end_binary = idaapi.get_last_seg().end_ea if idaapi.get_last_seg() else idaapi.BADADDR

        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_binary, end_binary, 0, self.count_manual_bookmark, True)

    # scan to find list region => add to bookmark and patch
    def preview_deobfuscator(self):
        self.obfuscated_regions.clear()
        self.overlapping_regions.clear()

        # clear scanning regions
        self.reset(True)

        active_tab = self.disassembler.currentIndex()
        input_start, input_end = self.disassembler.get_tab_line_edit_texts(active_tab)
        try:
            self.start_ea = int(input_start, 16)
            self.end_ea = int(input_end, 16)
        except:
            print('[Sharingan] Invalid start or end address (or empty input)')
            return

        # Iterate each ingredient to find obfuscated region
        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            ingredient = self.list_recipe.itemWidget(item)

            # skip disable
            if ingredient.chk_active.isChecked():
                print('[Sharingan]', ingredient.name, 'disable')
                continue

            # check mode, all ingredients must be same
            if not isinstance(ingredient, Deobfuscator):
                print('[Sharingan]', ingredient.name, 'wrong mode')
                return

            found_regions = ingredient.scan(self.start_ea, self.end_ea)
            if not found_regions:
                continue
            # check return type, must be ListObfuscatedRegion
            elif type(found_regions) is not ListObfuscatedRegion:
                print(f"[Sharingan] Module {ingredient.name} return invalid type ListObfuscatedRegion")
                return
            print('[Sharingan] Done', ingredient.description)

            is_clear_bookmark = False
            self.obfuscated_regions.append(found_regions)
            for r in found_regions:
                hint = ingredient.description
                # check found obfuscated region outside current disassembler
                for reg in r.regions:
                    # last addr may equal end address obfuscated region, use below equal
                    is_start_in = self.start_ea <= reg.start_ea < self.end_ea
                    is_end_in = self.start_ea <= reg.end_ea <= self.end_ea
                    if not is_start_in or not is_end_in:
                        print(f"[Sharingan] Obfuscated region {hex(reg.start_ea)} - {hex(reg.end_ea)} outside current view")
                    # reset region to prepare highlight
                    if is_start_in and is_end_in and not is_clear_bookmark:
                        is_clear_bookmark = True
                        DeobfuscateUtils.reset(self.start_ea, self.end_ea)
                # check len found region to add bookmark
                # sequence instruction
                if len(r.regions) == 1:
                    self.append_bookmark(r.regions[0].start_ea, r.regions[0].end_ea, hint, is_scan=True)
                # rambling instruction
                elif len(r.regions) > 1:
                    min_start = min(reg.start_ea for reg in r.regions)
                    max_end = max(reg.end_ea for reg in r.regions)
                    self.append_bookmark(min_start, max_end, hint, is_scan=True)

        self.sync_bookmarks_to_registry()
        self.save_bookmarks()
        #highlight and check overlap
        self.check_overlapping_regions()
        self.highlight_region()
        print('[Sharingan] Done scanning!!!')

        # if some ingredient change atribute data/insn => refresh (not patching)
        active_index = self.disassembler.currentIndex()
        self.disassembler.refresh_tab_asmview(active_index)
        self.push_highlights_to_view()

        # if auto patch is checked, it will be cook
        if self.chk_auto_patch.isChecked():
            self.cook()

    # manip data in table of string mode in module disassembler
    def preview_decryption(self):
        pipeline = self.get_active_decryption_pipeline()
        if not pipeline:
            print("[Sharingan] No active decryption ingredients.")
            return None

        selected_indices = self.disassembler.get_checked_box_rows()
        if not selected_indices:
            print("[Sharingan] No selected strings to decrypt.")
            return None

        selection = []
        raw_values = []
        for idx in selected_indices:
            entry = self.disassembler.get_string_entry(idx)
            raw_values.append(entry.get("value"))
            selection.append(idx)

        if not raw_values:
            print("[Sharingan] No valid strings selected for preview.")
            return None

        decrypted_values = self.run_decryption(raw_values, pipeline=pipeline) or raw_values

        for row_idx, preview_value in zip(selection, decrypted_values):
            self.disassembler.update_preview(row_idx, preview_value)

        return selection, decrypted_values

    def get_active_decryption_pipeline(self):
        pipeline = []
        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            if not item:
                continue
            widget = self.list_recipe.itemWidget(item)
            if not isinstance(widget, Decryption):
                print('[Sharingan] Wrong mode')
                return
            if isinstance(widget, Decryption) and not widget.chk_active.isChecked():
                pipeline.append(widget)
        return pipeline

    def run_decryption(self, raw_values, pipeline=None):
        if not raw_values:
            return []
        if not pipeline:
            return raw_values
        results = []
        for raw in raw_values:
            for step in pipeline:
                raw = step.decrypt(raw)
            if isinstance(raw, (bytes, bytearray)):
                raw = DecryptionUtils.to_preview_string(bytes(raw))
            results.append(raw)
        return results

    def preview(self):
        if self.list_recipe.mode == OperatorMode.DEOBFUSCATION:
            self.preview_deobfuscator()
        elif self.list_recipe.mode == OperatorMode.DECRYPTION:
            self.preview_decryption()

    # delete selected item cmb_bookmark
    def resolve(self, exclude_addr=0):
        index = -1
        selection = str()
        if not exclude_addr:
            index = self.cmb_bookmark.currentIndex()
            selection = self.cmb_bookmark.itemText(index)
        else:
            end_index = self.cmb_bookmark.count()
            for i in range(end_index, 0, -1):
                start_region, end_region = self.parse_start_end_region(i)
                if not start_region and not end_region:
                    continue
                if start_region <= exclude_addr <= end_region:
                    index = i
                    selection = self.cmb_bookmark.itemText(index)
                    break

        # not delete two label in cmb_bookmark
        if index == -1 or selection in ('Scanning', 'Manual'):
            return

        # restore that region to normal
        start_region, end_region = self.parse_start_end_region(index)
        self.cmb_bookmark.removeItem(index)
        active_tab = self.disassembler.currentIndex()
        self.disassembler.clear_tab_asmview(active_tab)
        DeobfuscateUtils.reset(start_region, end_region)

        is_manual = 0 < index <= self.count_manual_bookmark
        if is_manual:
            self.count_manual_bookmark -= 1
        else:
            # drop matching scanning region from obfuscated_regions so cook won't re-patch it
            for i in range(len(self.obfuscated_regions) - 1, -1, -1):
                list_regions = self.obfuscated_regions[i]
                for j in range(len(list_regions) - 1, -1, -1):
                    r = list_regions[j]
                    if any(p.start_ea == start_region and p.end_ea == end_region for p in r.regions):
                        bnd_s = min(p.start_ea for p in r.regions)
                        bnd_e = max(p.end_ea for p in r.regions)
                        DeobfuscateUtils.reset(bnd_s, bnd_e)
                        print(f"[Sharingan] Exclude region: {hex(bnd_s)} {hex(bnd_e)}")
                        list_regions.pop(j)
                        break

        # drop HINT/OVERLAP entries covered by the resolved range
        self.registry.remove_where(
            lambda x: x.kind in (RegionKind.HINT, RegionKind.OVERLAP)
            and x.start_ea >= start_region and x.end_ea <= end_region
        )
        self.sync_bookmarks_to_registry()
        self.save_bookmarks()
        self.push_highlights_to_view()

    # check overlap with any bookmark in given index range; returns matching index or False
    # uses half-open interval semantics [start, end) — overlap iff a.start < b.end and b.start < a.end
    def check_exist_bookmark(self, start_index_bookmark, end_index_bookmark, start_ea, end_ea):
        for index in range(start_index_bookmark, end_index_bookmark):
            start_region, end_region = self.parse_start_end_region(index)
            # skip label rows ("Manual" / "Scanning") which parse to (0, 0)
            if start_region == 0 and end_region == 0:
                continue
            if start_ea < end_region and start_region < end_ea:
                return index
        return False

    # add region to bookmark
    def append_bookmark(self, start_ea, end_ea, hint, is_scan=False):
        ea_hint = f"{hex(start_ea)} - {hex(end_ea)} - {hint}"
        # check overlap only within the same section (manual or scanning); the two are independent
        if is_scan:
            start_idx, end_idx = self.count_manual_bookmark + 2, self.cmb_bookmark.count()
        else:
            start_idx, end_idx = 1, self.count_manual_bookmark + 1
        if self.check_exist_bookmark(start_idx, end_idx, start_ea, end_ea):
            msg = "Duplicate region" if is_scan else "Already bookmark"
            print(f"[Sharingan] {msg} - {hex(start_ea)} - {hex(end_ea)}")
            return

        if is_scan:
            self.cmb_bookmark.addItem(ea_hint)
        else:
            self.count_manual_bookmark += 1
            self.cmb_bookmark.insertItem(self.count_manual_bookmark, ea_hint)
            self.sync_bookmarks_to_registry()
            self.save_bookmarks()
            idaapi.refresh_idaview_anyway()

    # this method is called when selecting from cmb_bookmark
    def disassemble_range_addr(self, index):
        start_region, end_region = self.parse_start_end_region(self.cmb_bookmark.currentIndex())
        if start_region == 0 or end_region == 0:
            return

        if self.chk_compact.isChecked():
            idc.jumpto(start_region)
        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_region, end_region, index, self.count_manual_bookmark)

    # check found scanning regions are overlapped or not from ingredient
    def check_overlapping_regions(self):
        intervals = []
        for i, list_regions in enumerate(self.obfuscated_regions):
            for j, r in enumerate(list_regions):
                for k, region_part in enumerate(r.regions):
                    intervals.append({
                        'start': region_part.start_ea,
                        'end': region_part.end_ea,
                        'name': r.name,
                        'id': (i, j, k)
                    })

        if not intervals:
            return False

        # sort to compare if start of following region is greater than end of previous region, it overlap
        intervals.sort(key=lambda x: (x['start'], x['end']))

        self.overlapping_regions.clear()
        has_overlap = False

        for i in range(len(intervals)):
            for j in range(i + 1, len(intervals)):
                if intervals[j]['start'] >= intervals[i]['end']:
                    break

                inter_start = intervals[j]['start']
                inter_end = min(intervals[i]['end'], intervals[j]['end'])

                if inter_start < inter_end:
                    self.overlapping_regions.add((inter_start, inter_end))
                    print(f"[Sharingan] Overlap detected: {hex(inter_start)} - {hex(inter_end)} "
                            f"between '{intervals[i]['name']}' and '{intervals[j]['name']}'")
                    has_overlap = True

        return has_overlap

    # register overlap intervals; renderer paints them
    def highlight_overlapping(self):
        for start_ea, end_ea in self.overlapping_regions:
            self.registry.add(Region(start_ea, end_ea, RegionKind.OVERLAP))

    # register obfuscated sub-regions as hint; renderer paints them
    def highlight_hint(self):
        for list_regions in self.obfuscated_regions:
            for r in list_regions:
                for reg in r.regions:
                    self.registry.add(Region(reg.start_ea, reg.end_ea, RegionKind.HINT, r.name))

    def highlight_region(self):
        self.highlight_hint()
        self.highlight_overlapping()

    # cook decryption for string mode
    def cook_strings(self):
        result = self.preview_decryption()
        if not result:
            return

        selection, decrypted_values = result
        if not decrypted_values:
            print("[Sharingan] No valid strings selected for cooking.")
            return

        for idx, preview_value in zip(selection, decrypted_values):
            entry = self.disassembler.get_string_entry(idx)

            targets = set()
            targets.add(entry.get("address"))
            for x in entry.get("xrefs") or []:
                targets.add(x)

            if not targets:
                continue

            for addr in targets:
                ida_bytes.set_cmt(addr, str(preview_value), 0)

        print("[Sharingan] Done string cooking.")

    # patch/cook
    def cook(self):
        if self.list_recipe.mode == OperatorMode.DECRYPTION and getattr(self.disassembler, "is_current_tab_string_mode", lambda: False)():
            self.cook_strings()
            return

        if self.check_overlapping_regions():
            print('[Sharingan] Please resolve all overlapping region!')
            return

        for list_regions in self.obfuscated_regions:
            for r in list_regions:
                for reg in r.regions:
                    if reg.action == Action.CMT:
                        start_ea = reg.start_ea
                        end_ea = reg.end_ea
                        start_index_bookmark = self.count_manual_bookmark + 2
                        end_index_bookmark = self.cmb_bookmark.count()
                        index_bookmark = self.check_exist_bookmark(start_index_bookmark, end_index_bookmark, start_ea, end_ea)
                        if index_bookmark:
                            self.cmb_bookmark.removeItem(index_bookmark)

                        idaapi.set_cmt(reg.start_ea, reg.comment, 0)
                    elif reg.action == Action.PATCH:
                        start_ea = reg.start_ea
                        end_ea = reg.end_ea
                        start_index_bookmark = self.count_manual_bookmark + 2
                        end_index_bookmark = self.cmb_bookmark.count()
                        index_bookmark = self.check_exist_bookmark(start_index_bookmark, end_index_bookmark, start_ea, end_ea)
                        if index_bookmark:
                            self.cmb_bookmark.removeItem(index_bookmark)

                        # patching
                        patch_bytes = bytes(reg.patch_bytes)
                        DeobfuscateUtils.del_items(start_ea, reg.obfus_size)
                        DeobfuscateUtils.patch_bytes(start_ea, patch_bytes)
                        DeobfuscateUtils.del_items(start_ea, reg.obfus_size)
                        DeobfuscateUtils.mark_as_code(start_ea, end_ea)

                        # registry paints the patched range; hidden range still drives folding for NOP holes
                        self.registry.add(Region(start_ea, end_ea, RegionKind.PATCHED, reg.comment))

                        if DeobfuscateUtils.is_all_nop(patch_bytes):
                            idaapi.add_hidden_range(start_ea, end_ea, reg.comment, '', '', Color.BG_PATCH_HIDDEN)
                        else:
                            curr_ea = start_ea
                            while curr_ea < end_ea:
                                if DeobfuscateUtils.is_nop(curr_ea):
                                    nop_block_start = curr_ea
                                    while curr_ea < end_ea and DeobfuscateUtils.is_nop(curr_ea):
                                        next_ea = idaapi.next_head(curr_ea, end_ea)
                                        if next_ea == idaapi.BADADDR or next_ea >= end_ea:
                                            curr_ea = end_ea
                                            break
                                        curr_ea = next_ea
                                    idaapi.add_hidden_range(nop_block_start, curr_ea, 'NOP NOP NOP ...', '', '', Color.BG_PATCH_HIDDEN)
                                else:
                                    next_ea = idaapi.next_head(curr_ea, end_ea)
                                    curr_ea = end_ea if next_ea == idaapi.BADADDR or next_ea >= end_ea else next_ea

                            self.hint_hook.insert_hint(start_ea, reg.comment)

        DeobfuscateUtils.refresh_view()
        active_index = self.disassembler.currentIndex()
        self.disassembler.compare_tab_code(active_index, self.obfuscated_regions)
        self.sync_bookmarks_to_registry()
        self.save_bookmarks()
        self.save_patched_regions()
        idaapi.refresh_idaview_anyway()
        print('[Sharingan] Done cooking!!!')

    # when selecting option exclusion, decide action by registry kind at cursor (no color reads)
    def exclude_patch_false_positive(self, cursor):
        patched = self.registry.find_at(cursor, [RegionKind.PATCHED])
        if patched:
            # registry holds bounds; obfuscated_regions is consulted only for same-session cleanup
            target = patched[0]
            start_ea, end_ea = target.start_ea, target.end_ea

            if start_ea in self.hint_hook.dict_hints:
                self.hint_hook.remove_hint(start_ea)

            visitor = PatchedBytesVistor(start_ea, end_ea)
            ida_bytes.visit_patched_bytes(start_ea, end_ea, visitor)
            idaapi.auto_wait()
            DeobfuscateUtils.reset(start_ea, end_ea)

            self.registry.remove_where(
                lambda x: x.kind == RegionKind.PATCHED
                and x.start_ea == start_ea and x.end_ea == end_ea
            )
            self.save_patched_regions()

            # drop matching ObfuscatedRegion from same-session metadata if present
            for i in range(len(self.obfuscated_regions) - 1, -1, -1):
                list_regions = self.obfuscated_regions[i]
                for j in range(len(list_regions) - 1, -1, -1):
                    r = list_regions[j]
                    if any(p.start_ea <= cursor < p.end_ea for p in r.regions):
                        list_regions.pop(j)
                        break

            active_index = self.disassembler.currentIndex()
            self.disassembler.compare_tab_code(active_index, self.obfuscated_regions)
            idaapi.refresh_idaview_anyway()
            print(f"[Sharingan] Revert region: {hex(start_ea)} {hex(end_ea)}")
            return

        kinds = {r.kind for r in self.registry.find_at(cursor)}
        if kinds & {RegionKind.HINT, RegionKind.MANUAL_BM, RegionKind.SCAN_BM}:
            self.resolve(cursor)
