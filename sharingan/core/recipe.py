from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, QSizePolicy, QCheckBox
from PySide6.QtCore import Qt, Signal, QObject
from sharingan.base.dragdroprecipe import DragDropRecipe
from sharingan.core.stylesmanager import ManageStyleSheet
import ida_bytes, idaapi, idc
from sharingan.base.obfuscatedregion import ListObfuscatedRegion
from sharingan.core.utils import DeobfuscateUtils


class HintRawInsn(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.hooked = False
        self.dict_hints = dict()

    def hook(self):
        if not self.hooked:
            super(HintRawInsn, self).hook()
            self.hooked = True
            print("Hint hook installed.")

    def unhook(self):
        if self.hooked:
            super(HintRawInsn, self).unhook()
            self.hooked = False
            print("Hint hook removed.")

    def update_hints(self, ea, hint):
        self.dict_hints[ea] = hint

    def get_custom_viewer_hint(self, viewer, place):
        if place is None:
            return None
        ea = place.toea()
        if ea in self.dict_hints.keys():
            hint = self.dict_hints[ea]
            return hint, len(hint.split('\n'))
        return None


class PatchedBytesVistor(object):
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea

    def __call__(self, ea, fpos, original_bytes, patch_bytes, cnt=()):
        if  self.start_ea <= ea < self.end_ea:
            ida_bytes.revert_byte(ea)
        return 0


# singal for checkbox disable ingredient
class ToggleSignal(QObject):
    toggle = Signal()


# signal for filter action in asmview
class FilterSignal(QObject):
    filter_ = Signal(int, int)


class Recipe(QWidget):
    def __init__(self, disassembler=None):
        super(Recipe, self).__init__()
        self.setMinimumSize(50, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.DEFCOLOR = 0xFFFFFFFF                  # remove color
        self.BG_HINT = 0x8bab53                     # green: hint
        self.BG_OVERLAPPING = 0x4a6afb              # red: overlap
        self.BG_PATCH_HIDDEN = 0xbd8231             # blue: patch/hidden range
    
        self.obfuscated_regions = []
        self.overlapping_regions = set()
        self.count_manual_bookmark = 0

        self.hint_hook = HintRawInsn()
        self.hint_hook.hook()

        self.signal_toggle = ToggleSignal()
        self.signal_toggle.toggle.connect(self.disable_obfuscated_region)
        self.list_recipe = DragDropRecipe(self)
        self.list_recipe.set_signal_toggle(self.signal_toggle)
        self.list_recipe.setObjectName('list_recipe')

        self.disassembler = disassembler
        self.signal_filter = FilterSignal()
        self.disassembler.set_tab_signal_filter(self.signal_filter)
        self.signal_filter.filter_.connect(self.add_ingredient_substitute)

        self.btn_delete = QPushButton('Delete')
        self.btn_delete.clicked.connect(self.delete_ingredient)
        self.btn_cook = QPushButton('Cook')
        self.btn_cook.clicked.connect(self.cook)
        self.btn_scan = QPushButton('Scan')
        self.btn_scan.clicked.connect(self.scan)
        self.cmb_bookmark = QComboBox(self)
        self.cmb_bookmark.activated.connect(self.disassemble_range_addr)
        self.cmb_bookmark.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.cmb_bookmark.addItem('Manual')
        self.cmb_bookmark.model().item(0).setEnabled(False)
        self.cmb_bookmark.addItem('Scanning')
        self.cmb_bookmark.model().item(1).setEnabled(False)
        self.btn_resolve = QPushButton('Resolve', self)
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
        self.layout_button.addWidget(self.btn_scan)
        self.layout_button.setAlignment(Qt.AlignJustify)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.cmb_bookmark)
        self.layout.addLayout(self.layout_checkbox)
        self.layout.addLayout(self.layout_button)
        self.layout.addWidget(self.list_recipe)
        self.layout.addWidget(self.btn_cook)
        self.setLayout(self.layout)

        self.list_recipe.setStyleSheet(ManageStyleSheet.get_stylesheet())

        self.start_ea = 0x0
        self.end_ea = 0x0

    def __del__(self):
        self.hint_hook.unhook()

    # delete item in list recipe
    def delete_ingredient(self):
        list_selection = self.list_recipe.selectedIndexes()
        if list_selection:
            for index in list_selection:
                item = self.list_recipe.itemFromIndex(index)
                self.list_recipe.removeItemWidget(item)
                self.list_recipe.takeItem(index.row())
        else:
            for i in range(self.list_recipe.count()):
                item = self.list_recipe.item(i)
                self.list_recipe.removeItemWidget(item)
            self.list_recipe.clear()

    def add_ingredient_substitute(self, start_ea, end_ea):
        obj_substitute = self.list_recipe.classify_algorithm('substitute')
        obj_substitute.set_obfuscated_start_end_ea(start_ea, end_ea)
        self.list_recipe.insert_ingredient_recipe(obj_substitute, None)

    # if checkbox all binary turn on, start and end disassemble will be replace all binary
    def replace_start_end_by_all(self):
        if not self.chk_all_binary.isChecked():
            return

        start_binary = idaapi.get_imagebase()
        end_binary = idaapi.get_last_seg().end_ea if idaapi.get_last_seg() else idaapi.BADADDR

        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_binary, end_binary, True)

    # scan to find list => add to bookmark and patch
    def scan(self):
        self.obfuscated_regions.clear()
        self.overlapping_regions.clear()

        active_tab = self.disassembler.currentIndex()
        input_start, input_end = self.disassembler.get_tab_line_edit_texts(active_tab)
        self.start_ea = int(input_start, 16)
        self.end_ea = int(input_end, 16)

        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            ingredient = self.list_recipe.itemWidget(item)
            print('Done', ingredient.description)
            if ingredient.chk_active.isChecked():
                continue

            possible_obfuscation_regions = ingredient.scan(self.start_ea, self.end_ea)
            if not possible_obfuscation_regions:
                continue

            self.obfuscated_regions.append(possible_obfuscation_regions)
            for r in possible_obfuscation_regions:
                hint = ingredient.description
                # check found obfuscated region outside current disassembler
                for i in range(len(r.regions)):
                    # last addr may equal end address obfuscated region, use below equal
                    if not (self.start_ea <= r.regions[i].start_ea < self.end_ea) or not (self.start_ea <= r.regions[i].end_ea <= self.end_ea):
                        print(f'Obfuscated region {hex(r.regions[i].start_ea)} - {hex(r.regions[i].end_ea)} outside current view')
                # check len found region to add bookmark
                if len(r.regions) == 1:
                    self.append_bookmark(r.regions[0].start_ea, r.regions[0].end_ea, hint, is_scan=True)
                elif len(r.regions) > 1:
                    arr_start_ea = [item.start_ea for i, item in enumerate(r.regions)]
                    arr_end_ea = [item.end_ea for i, item in enumerate(r.regions)]
                    self.append_bookmark(min(arr_start_ea), max(arr_end_ea), hint, is_scan=True)
        #highlight and check overlap
        self.check_overlapping_regions()
        self.highlight_region()
        print('Done scanning!!!')

        active_index = self.disassembler.currentIndex()
        self.disassembler.refresh_tab_asm_view(active_index)

        # if auto patch is checked, it will be cook
        if self.chk_auto_patch.isChecked():
            self.cook()

    # delete selected item combobox
    def resolve(self):
        index = self.cmb_bookmark.currentIndex()
        selection = self.cmb_bookmark.itemText(index)
        if index != -1 and selection != 'Scanning' and selection != 'Manual':
            selection = self.cmb_bookmark.itemText(index)
            tmp_start_ea = selection.split(' - ')[0]
            tmp_end_ea = selection.split(' - ')[1]
            tmp_start_ea = int(tmp_start_ea, 0)
            tmp_end_ea = int(tmp_end_ea, 0)

            self.cmb_bookmark.removeItem(index)
            active_tab = self.disassembler.currentIndex()
            self.disassembler.clear_tab_asmview(active_tab)

            if 0 < index < self.count_manual_bookmark:
                self.count_manual_bookmark -= 1
            else:
                DeobfuscateUtils.reset(tmp_start_ea, tmp_end_ea)
                for i, list_regions in enumerate(self.obfuscated_regions):
                    for j, r in enumerate(list_regions):
                        for k in range(len(r.regions)):
                            start = r.regions[k].start_ea
                            end = r.regions[k].end_ea
                            if start == tmp_start_ea and tmp_end_ea == end:
                                start_ea = min([item.start_ea for i, item in enumerate(r.regions)])
                                end_ea = max([item.end_ea for i, item in enumerate(r.regions)])
                                DeobfuscateUtils.reset(start_ea, end_ea)
                                print(f'Revert region: {hex(start_ea)} {hex(end_ea)}')
                                list_regions.pop(j)

    def check_exist_bookmark(self, start_index_bookmark, end_index_bookmark, start_ea, end_ea):
        for i in range(start_index_bookmark, end_index_bookmark):
            selection = self.cmb_bookmark.itemText(i)
            tmp_start_ea = selection.split(' - ')[0]
            tmp_end_ea = selection.split(' - ')[1]
            tmp_start_ea = int(tmp_start_ea, 0)
            tmp_end_ea = int(tmp_end_ea, 0)
            if tmp_start_ea <= start_ea <= tmp_end_ea and tmp_start_ea <= end_ea <= tmp_end_ea:
                return i
        return False

    # classify bookmark scan or right click
    def append_bookmark(self, start_ea, end_ea, hint, is_scan=False):
        ea_hint = f'{hex(start_ea)} - {hex(end_ea)} - {hint}'
        if is_scan:
            # plus two label header
            start_index_bookmark = self.count_manual_bookmark + 2
            end_index_bookmark = self.cmb_bookmark.count()
            if self.check_exist_bookmark(start_index_bookmark, end_index_bookmark, start_ea, end_ea):
                print(f'Duplicate region - {hex(start_ea)} - {hex(end_ea)}')
                return
            self.cmb_bookmark.addItem(ea_hint)
        else:
            if self.check_exist_bookmark(1, self.count_manual_bookmark + 1, start_ea, end_ea):
                print(f'Already bookmark - {hex(start_ea)} - {hex(end_ea)}')
                return
            self.cmb_bookmark.insertItem(self.count_manual_bookmark + 1, ea_hint)
            self.count_manual_bookmark += 1

    def disassemble_range_addr(self):
        bookmark = self.cmb_bookmark.currentText()
        start_ea = bookmark.split(' - ')[0]
        start_ea = int(start_ea, 0)
        end_ea = bookmark.split(' - ')[1]
        end_ea = int(end_ea, 0)
        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_ea, end_ea)

    # Flatten all sub-regions with their locations
    def check_overlapping_regions(self):
        intervals = []
        for i, list_regions in enumerate(self.obfuscated_regions):
            for j, r in enumerate(list_regions):
                for k in range(len(r.regions)):
                    start = r.regions[k].start_ea
                    end = r.regions[k].end_ea
                    name = r.name
                    active = r.active
                    intervals.append((start, end, i, j, k, name, active))
        if not intervals:
            return
        # Sort by start, then by end
        intervals.sort(key=lambda x: (x[0], x[1]))
        # Collect regions to alert

        self.overlapping_regions.clear()
        curr_end = intervals[0][1]
        for index in range(1, len(intervals)):
            start, end, i, j, k, current_name, active = intervals[index]
            # after sort, if end_region larger than previous start region => overlap
            if start < curr_end and active:
                previous_name = intervals[index - 1][5]
                self.overlapping_regions.add((i, j, k, current_name, previous_name))
            else:
                curr_end = end
        
        if len(self.overlapping_regions) > 0:
            for region in self.overlapping_regions:
                i, j, k, current_name, previous_name = region
                start_overlapping = self.obfuscated_regions[i][j].regions[k].start_ea
                end_overlapping = self.obfuscated_regions[i][j].regions[k].end_ea
                print(f'Overlap: {hex(start_overlapping)} - {hex(end_overlapping)} - {current_name} - {previous_name}')
            return True
        return False

    # highlight background overlapping region by red
    def highlight_overlapping(self):
        for region in self.overlapping_regions:
            i, j, k, current_name, previous_name = region
            start_overlapping = self.obfuscated_regions[i][j].regions[k].start_ea
            end_overlapping = self.obfuscated_regions[i][j].regions[k].end_ea
            while start_overlapping < end_overlapping:
                idc.set_color(start_overlapping, idc.CIC_ITEM, self.BG_OVERLAPPING)
                start_overlapping = idaapi.next_head(start_overlapping, idaapi.BADADDR)

    #highlight background obfuscated region by green
    def highlight_hint(self):
        for i, list_regions in enumerate(self.obfuscated_regions):
            for j, r in enumerate(list_regions):
                for k in range(len(r.regions)):
                    start = r.regions[k].start_ea
                    end = r.regions[k].end_ea
                    if r.active:
                        while start < end:
                            idc.set_color(start, idc.CIC_ITEM, self.BG_HINT)
                            start = idaapi.next_head(start, idaapi.BADADDR)
                    else:
                        while start < end:
                            idc.set_color(start, idc.CIC_ITEM, self.DEFCOLOR)
                            start = idaapi.next_head(start, idaapi.BADADDR)

    def highlight_region(self, is_refresh=False):
        if not is_refresh:
            self.highlight_hint()
            self.highlight_overlapping()
        else:
            self.highlight_hint()

    def is_all_nop(self, ba):
        return all(b == 0x90 for b in ba)

    # patch
    def cook(self):
        if self.check_overlapping_regions():
            print('Please resolve all overlapping region!')
            return

        for i, list_regions in enumerate(self.obfuscated_regions):
            for j, r in enumerate(list_regions):
                if not r.active:
                    continue
                for k in range(len(r.regions)):
                    start_ea = r.regions[k].start_ea
                    end_ea = r.regions[k].end_ea
                    start_index_cmb = self.count_manual_bookmark + 2
                    end_index_cmb = self.cmb_bookmark.count()
                    index_bookmark = self.check_exist_bookmark(start_index_cmb, end_index_cmb, start_ea, end_ea)
                    if index_bookmark:
                        self.cmb_bookmark.removeItem(index_bookmark)
                    size_obfus = r.regions[k].obfus_size
                    patch_bytes = bytes(r.regions[k].patch_bytes)
                    comment = r.regions[k].comment
                    # len patch_bytes must same as size_obfus
                    DeobfuscateUtils.del_items(start_ea, size_obfus)
                    DeobfuscateUtils.patch_bytes(start_ea, patch_bytes)
                    DeobfuscateUtils.mark_as_code(start_ea, end_ea)
                    if self.is_all_nop(patch_bytes):
                        idaapi.del_item_color(start_ea)
                        idaapi.add_hidden_range(start_ea, end_ea, comment, '', '', self.BG_PATCH_HIDDEN)
                    else:
                        nop_ea = start_ea
                        while nop_ea < end_ea:
                            if DeobfuscateUtils.is_nop(nop_ea):
                                break
                            else:
                                idc.set_color(nop_ea, idc.CIC_ITEM, self.BG_PATCH_HIDDEN)
                                nop_ea = idaapi.next_head(nop_ea, idaapi.BADADDR)
                        DeobfuscateUtils.mark_as_code(start_ea, end_ea)
                        idaapi.del_item_color(nop_ea)
                        idaapi.add_hidden_range(nop_ea, end_ea, 'NOP', '', '', self.BG_PATCH_HIDDEN)
                        self.hint_hook.update_hints(start_ea, comment)
        DeobfuscateUtils.refresh_view()
        active_index = self.disassembler.currentIndex()
        self.disassembler.compare_tab_code(active_index, self.obfuscated_regions)
        print('Done cooking!!!')

    # method disable ingredient in list recipe (column 2) via sinal checkbox
    def disable_obfuscated_region(self):
        if len(self.obfuscated_regions) != self.list_recipe.count():
            print('Please run cooking before disable')
            return
    
        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            ingredient = self.list_recipe.itemWidget(item)
            state_ingredient = ingredient.chk_active.isChecked()
            obfuscated_region = self.obfuscated_regions[i]
            for r in obfuscated_region:
                r.active = not state_ingredient

        self.highlight_region(is_refresh=True)

    def exclude_patch_false_positive(self, cursor):
        color_insn = idc.get_color(cursor, idc.CIC_ITEM)
        if color_insn == self.DEFCOLOR:
            color_insn = idaapi.get_hidden_range(cursor).color
        # remove hidden range or patching
        if color_insn == self.BG_PATCH_HIDDEN:
            obfuscated_region = None
            found = False
            for i, list_regions in enumerate(self.obfuscated_regions):
                for j, r in enumerate(list_regions):
                    for k in range(len(r.regions)):
                        start = r.regions[k].start_ea
                        end = r.regions[k].end_ea
                        if start <= cursor < end:
                            start_ea = min([item.start_ea for i, item in enumerate(r.regions)])
                            end_ea = max([item.end_ea for i, item in enumerate(r.regions)])
                            visitor = PatchedBytesVistor(start_ea, end_ea)
                            ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, visitor)
                            DeobfuscateUtils.reset(start_ea, end_ea)
                            print(f'Revert region: {hex(start_ea)} {hex(end_ea)}')
                            list_regions.pop(j)
                            return
        # remove hint
        elif color_insn == self.BG_HINT:
            start_index = self.count_manual_bookmark + 2
            end_index = self.cmb_bookmark.count()
            for i in range(start_index, end_index):
                possible_obfus = self.cmb_bookmark.itemText(i)
                if possible_obfus == 'Scanning' or possible_obfus == 'Manual':
                    continue
                start_obfus = int(possible_obfus.split(' - ')[0], 0)
                end_obfus = int(possible_obfus.split(' - ')[1], 0)
                if start_obfus <= cursor < end_obfus:
                    self.cmb_bookmark.removeItem(i)
                    next_ea = start_obfus
                    while next_ea < end_obfus:
                        idaapi.set_item_color(next_ea, self.DEFCOLOR)
                        next_ea = idaapi.next_head(next_ea, idaapi.BADADDR)
                    DeobfuscateUtils.mark_as_code(start_obfus, end_obfus)
                    return