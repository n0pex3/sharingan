from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, QSizePolicy, QCheckBox
from PySide6.QtCore import Qt, Signal, QObject
from sharingan.base.dragdroprecipe import DragDropRecipe
from sharingan.core.stylesmanager import ManageStyleSheet
from sharingan.core.utils import DeobfuscateUtils
from sharingan.base.ingredient import Decryption, Deobfuscator
import ida_bytes, idaapi, idc


class HintRawInsn(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.hooked = False
        self.dict_hints = dict()

    def hook(self):
        if not self.hooked:
            super().hook()
            self.hooked = True
            print("Hint hook installed.")

    def unhook(self):
        if self.hooked:
            super().unhook()
            self.hooked = False
            print("Hint hook removed.")

    def insert_hint(self, ea, hint):
        self.dict_hints[ea] = hint

    def remove_hint(self, ea):
        print('Remove hint', hex(ea))
        self.dict_hints.pop(ea)

    def get_custom_viewer_hint(self, viewer, place):
        if place is None:
            return None
        ea = place.toea()
        hint = self.dict_hints.get(ea)
        if hint:
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


# signal for filter action in asmview
class FilterSignal(QObject):
    filter_ = Signal(int, int)


class Color:
    DEFCOLOR = 0xFFFFFFFF                  # remove color
    BG_HINT = 0x8bab53                     # green: hint
    BG_OVERLAPPING = 0x4a6afb              # red: overlap
    BG_PATCH_HIDDEN = 0xbd8231             # blue: patch/hidden range


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

        self.disassembler = disassembler
        self.signal_filter = FilterSignal()
        self.disassembler.set_tab_signal_filter(self.signal_filter)
        self.signal_filter.filter_.connect(self.add_ingredient_substitute)

        self.setup_ui()
        self.list_recipe.setStyleSheet(ManageStyleSheet.get_stylesheet())

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

    def __del__(self):
        self.hint_hook.unhook()                                                                                                     

    def parse_start_end_region(self, index):
        selection = self.cmb_bookmark.itemText(index)
        parts = selection.split(' - ')
        if len(parts) == 3:
            return int(parts[0], 0), int(parts[1], 0)
        return 0, 0

    def reset(self):
        start_index = self.count_manual_bookmark + 1
        end_index = self.cmb_bookmark.count() - 1
        for index in range(end_index, start_index, -1):
            start_region, end_region = self.parse_start_end_region(index)
            DeobfuscateUtils.reset(start_region, end_region)
            self.cmb_bookmark.removeItem(index)
        self.obfuscated_regions.clear()
        print('Reset all')

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

    def add_ingredient_substitute(self, start_ea, end_ea):
        obj_substitute = self.list_recipe.classify_algorithm('substitute')
        if obj_substitute:
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
    def preview_deobfuscator(self):
        self.obfuscated_regions.clear()
        self.overlapping_regions.clear()

        active_tab = self.disassembler.currentIndex()
        input_start, input_end = self.disassembler.get_tab_line_edit_texts(active_tab)
        self.start_ea = int(input_start, 16)
        self.end_ea = int(input_end, 16)

        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            ingredient = self.list_recipe.itemWidget(item)

            # skip disable
            if ingredient.chk_active.isChecked():
                print(ingredient.name, 'disable')
                continue
            
            # check mode
            if not isinstance(ingredient, Deobfuscator):
                print(ingredient.name, 'wrong mode')
                return

            print('Done', ingredient.description)
            found_regions = ingredient.scan(self.start_ea, self.end_ea)
            if not found_regions:
                continue

            self.obfuscated_regions.append(found_regions)
            for r in found_regions:
                hint = ingredient.description
                # check found obfuscated region outside current disassembler
                for reg in r.regions:
                    # last addr may equal end address obfuscated region, use below equal
                    is_start_in = self.start_ea <= reg.start_ea < self.end_ea
                    is_end_in = self.start_ea <= reg.end_ea <= self.end_ea
                    if not is_start_in or not is_end_in:
                        print(f'Obfuscated region {hex(reg.start_ea)} - {hex(reg.end_ea)} outside current view')
                # check len found region to add bookmark
                if len(r.regions) == 1:
                    self.append_bookmark(r.regions[0].start_ea, r.regions[0].end_ea, hint, is_scan=True)
                elif len(r.regions) > 1:
                    min_start = min(reg.start_ea for reg in r.regions)
                    max_end = max(reg.end_ea for reg in r.regions)
                    self.append_bookmark(min_start, max_end, hint, is_scan=True)
        
        #highlight and check overlap
        self.check_overlapping_regions()
        self.highlight_region()
        print('Done scanning!!!')

        # if some ingredient change atribute data/insn => refresh (not patching)
        active_index = self.disassembler.currentIndex()
        self.disassembler.refresh_tab_asmview(active_index)

        # if auto patch is checked, it will be cook
        if self.chk_auto_patch.isChecked():
            self.cook()

    # manip data in table of string mode in module disassembler
    def preview_decryption(self):
        for i in range(self.list_recipe.count()):
            item = self.list_recipe.item(i)
            ingredient = self.list_recipe.itemWidget(item)

            # skip disable
            if ingredient.chk_active.isChecked():
                print(ingredient.name, 'disable')
                continue
            
            # check mode
            if not isinstance(ingredient, Decryption):
                print(ingredient.name, 'wrong mode')
                return

            print('Done', ingredient.description)
            ingredient.preview()

    def preview(self):
        if self.list_recipe.mode == 'deobfuscator':
            self.preview_deobfuscator()
        elif self.list_recipe.mode == 'decryption':
            self.preview_decryption()

    # delete selected item combobox
    def resolve(self):
        index = self.cmb_bookmark.currentIndex()
        selection = self.cmb_bookmark.itemText(index)

        if index == -1 or selection in ('Scanning', 'Manual'):
            return
        
        start_region, end_region = self.parse_start_end_region(index)
        self.cmb_bookmark.removeItem(index)
        active_tab = self.disassembler.currentIndex()
        self.disassembler.clear_tab_asmview(active_tab)

        if 0 < index < self.count_manual_bookmark:
            self.count_manual_bookmark -= 1
        else:
            DeobfuscateUtils.reset(start_region, end_region)
            # Iterate backwards to safely pop from list
            for i in range(len(self.obfuscated_regions) - 1, -1, -1):
                list_regions = self.obfuscated_regions[i]
                for j in range(len(list_regions) - 1, -1, -1):
                    r = list_regions[j]
                    # Check match logic (matches any sub-region boundary logic from original code)
                    matched = False
                    for k in range(len(r.regions)):
                        if r.regions[k].start_ea == start_region and r.regions[k].end_ea == end_region:
                            matched = True
                            break
                    
                    if matched:
                        # Calculate total bounds for this group to reset
                        total_start = min(reg.start_ea for reg in r.regions)
                        total_end = max(reg.end_ea for reg in r.regions)
                        DeobfuscateUtils.reset(total_start, total_end)
                        print(f'Exclude region: {hex(total_start)} {hex(total_end)}')
                        list_regions.pop(j)
                        return

    def check_exist_bookmark(self, start_index_bookmark, end_index_bookmark, start_ea, end_ea):
        for index in range(start_index_bookmark, end_index_bookmark):
            start_region, end_region = self.parse_start_end_region(index)
            if start_region <= start_ea <= end_region and start_region <= end_ea <= end_region:
                return index
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
        start_region, end_region = self.parse_start_end_region(self.cmb_bookmark.currentIndex())
        if start_region == 0 or end_region == 0:
            return

        active_index = self.disassembler.currentIndex()
        self.disassembler.set_tab_line_edit_texts(active_index, start_region, end_region)

    # Flatten all sub-regions with their locations
    def check_overlapping_regions(self):
        intervals = []
        for i, list_regions in enumerate(self.obfuscated_regions):
            for j, r in enumerate(list_regions):
                for k, region_part in enumerate(r.regions):
                    intervals.append((region_part.start_ea, region_part.end_ea, i, j, k, r.name))
        
        if not intervals:
            return False
        
        # Sort by start, then by end
        intervals.sort(key=lambda x: (x[0], x[1]))

        # Collect regions to alert
        self.overlapping_regions.clear()
        curr_end = intervals[0][1]
        for index in range(1, len(intervals)):
            start, end, i, j, k, current_name = intervals[index]
            # after sort, if end_region larger than previous start region => overlap
            if start < curr_end:
                previous_name = intervals[index - 1][5]
                self.overlapping_regions.add((i, j, k, current_name, previous_name))
            else:
                curr_end = end
        
        if self.overlapping_regions:
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
            i, j, k, _, _ = region
            item = self.obfuscated_regions[i][j].regions[k]
            DeobfuscateUtils.color_range(item.start_ea, item.end_ea, Color.BG_OVERLAPPING)

    #highlight background obfuscated region by green
    def highlight_hint(self):
        for list_regions in self.obfuscated_regions:
            for r in list_regions:
                for reg in r.regions:
                    DeobfuscateUtils.color_range(reg.start_ea, reg.end_ea, Color.BG_HINT)

    def highlight_region(self):
        self.highlight_hint()
        self.highlight_overlapping()

    # patch
    def cook(self):
        if self.check_overlapping_regions():
            print('Please resolve all overlapping region!')
            return

        for list_regions in self.obfuscated_regions:
            for r in list_regions:
                for reg in r.regions:
                    start_ea = reg.start_ea
                    end_ea = reg.end_ea
                    start_index_bookmark = self.count_manual_bookmark + 2
                    end_index_bookmark = self.cmb_bookmark.count()
                    # remove bookmark
                    index_bookmark = self.check_exist_bookmark(start_index_bookmark, end_index_bookmark, start_ea, end_ea)
                    if index_bookmark:
                        self.cmb_bookmark.removeItem(index_bookmark)
                    
                    # patching
                    patch_bytes = bytes(reg.patch_bytes)
                    DeobfuscateUtils.del_items(start_ea, reg.obfus_size)
                    DeobfuscateUtils.patch_bytes(start_ea, patch_bytes)
                    DeobfuscateUtils.mark_as_code(start_ea, end_ea)

                    # color region
                    # raw insn equal 1 insn
                    if DeobfuscateUtils.is_all_nop(patch_bytes):
                        idaapi.del_item_color(start_ea)
                        idaapi.add_hidden_range(start_ea, end_ea, reg.comment, '', '', Color.BG_PATCH_HIDDEN)
                    # greater than 1 insn
                    else:
                        nop_ea = start_ea
                        while nop_ea < end_ea:
                            if DeobfuscateUtils.is_nop(nop_ea):
                                break
                            idc.set_color(nop_ea, idc.CIC_ITEM, Color.BG_PATCH_HIDDEN)
                            nop_ea = idaapi.next_head(nop_ea, idaapi.BADADDR)

                        DeobfuscateUtils.mark_as_code(start_ea, end_ea)
                        idaapi.del_item_color(nop_ea)
                        idaapi.add_hidden_range(nop_ea, end_ea, 'NOP', '', '', Color.BG_PATCH_HIDDEN)
                        self.hint_hook.insert_hint(start_ea, reg.comment)

        DeobfuscateUtils.refresh_view()
        active_index = self.disassembler.currentIndex()
        self.disassembler.compare_tab_code(active_index, self.obfuscated_regions)
        print('Done cooking!!!')

    def exclude_patch_false_positive(self, cursor):
        color_insn = idc.get_color(cursor, idc.CIC_ITEM)
        if color_insn == Color.DEFCOLOR:
            hidden_region = idaapi.get_hidden_range(cursor)
            if hidden_region:
                color_insn = idaapi.get_hidden_range(cursor).color
        
        # remove hidden range or patching
        if color_insn == Color.BG_PATCH_HIDDEN:
            found = False
            for i, list_regions in enumerate(self.obfuscated_regions):
                for j, r in enumerate(list_regions):
                    for k, reg in enumerate(r.regions):
                        if reg.start_ea <= cursor < reg.end_ea:
                            start_ea = min([x.start_ea for x in r.regions])
                            end_ea = max([x.end_ea for x in r.regions])

                            #remove hint raw insn
                            self.hint_hook.remove_hint(start_ea)

                            # revert region menu right click
                            visitor = PatchedBytesVistor(start_ea, end_ea)
                            ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, visitor)
                            DeobfuscateUtils.reset(start_ea, end_ea)

                            # remove from bookmark
                            print(f'Revert region: {hex(start_ea)} {hex(end_ea)}')
                            list_regions.pop(j)

                            # refresh asmview
                            active_index = self.disassembler.currentIndex()
                            self.disassembler.compare_tab_code(active_index, self.obfuscated_regions)
                            return
        # remove hint
        elif color_insn == Color.BG_HINT:
            start_index = self.count_manual_bookmark + 2
            end_index = self.cmb_bookmark.count()

            for i in range(start_index, end_index):
                possible_obfus = self.cmb_bookmark.itemText(i)
                if possible_obfus in ('Scanning', 'Manual'):
                    continue
                
                # parse address start and end
                try:
                    parts = txt.split(' - ')
                    start_obfus = int(parts[0], 0)
                    end_obfus = int(parts[1], 0)
                except (ValueError, IndexError):
                    continue

                # remove from bookmark and reset color
                if start_obfus <= cursor < end_obfus:
                    self.cmb_bookmark.removeItem(i)
                    DeobfuscateUtils.color_range(start_obfus, end_obfus, Color.DEFCOLOR)
                    DeobfuscateUtils.mark_as_code(start_obfus, end_obfus)
                    return