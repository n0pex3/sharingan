import idaapi, ida_bytes
from sharingan.base.ingredient import Deobfuscator
from PySide6.QtWidgets import QTextEdit, QLineEdit, QHBoxLayout
from sharingan.core.utils import DeobfuscateUtils
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action


class Substitute(Deobfuscator):
    def __init__(self):
        super().__init__('Substitute')
        self.description = 'Substitute'
        self.version = '1.0'

    def setup_ui(self):
        super().setup_ui()

        self.ldt_start_ea = QLineEdit()
        self.ldt_start_ea.setPlaceholderText('Start EA')
        self.ldt_end_ea = QLineEdit()
        self.ldt_end_ea.setPlaceholderText('End EA')
        self.layout_addr = QHBoxLayout()
        self.layout_addr.addWidget(self.ldt_start_ea)
        self.layout_addr.addWidget(self.ldt_end_ea)
        self.tet_patching_instruction = QTextEdit()
        self.layout_body.addLayout(self.layout_addr)
        self.layout_body.addWidget(self.tet_patching_instruction)

    def set_obfuscated_start_end_ea(self, start_ea, end_ea):
        self.ldt_start_ea.setText(hex(start_ea))
        self.ldt_end_ea.setText(hex(end_ea))

    def scan(self, start_ea, end_ea):
        # address start and end of obfuscated instruction
        try:
            start_obfu_addr = int(self.ldt_start_ea.text(), 0)
            end_obfu_addr = int(self.ldt_end_ea.text(), 0)
        except:
            print('Invalid hex number')
            return

        if start_obfu_addr >= end_obfu_addr or idaapi.get_imagebase() > start_obfu_addr or idaapi.get_imagebase() > end_obfu_addr:
            print('Invalid address')
            return

        arr_patching_assem = self.tet_patching_instruction.toPlainText().split('\n')
        bytes_pattern_find_str = ''
        comment = []
        is_32bit = idaapi.inf_is_32bit_exactly()

        # get full hex bytes string of instruction and data between start_obfu_addr and end_obfu_addr to search and comment
        while start_obfu_addr < end_obfu_addr and start_obfu_addr != idaapi.BADADDR:
            if ida_bytes.is_code(ida_bytes.get_full_flags(start_obfu_addr)):
                instr_size = idaapi.get_item_size(start_obfu_addr)
                bytes_pattern_find_str += f"{DeobfuscateUtils.get_bytes_as_hex_string(start_obfu_addr, instr_size)} "
                line_asm = idaapi.generate_disasm_line(start_obfu_addr, 0)
                comment.append(line_asm)
            # if being data, convert to NOP
            else:
                len_data = idaapi.next_head(start_obfu_addr, idaapi.BADADDR) - start_obfu_addr
                bytes_pattern_find_str += '?? ' * len_data
                comment.append(DeobfuscateUtils.get_bytes_as_hex_string(start_obfu_addr, len_data))
            start_obfu_addr = idaapi.next_head(start_obfu_addr, idaapi.BADADDR)

        # convert input user to hex byte
        arr_replace_bytes = bytearray()
        total_bytes_patching = 0
        for line in arr_patching_assem:
            try:
                mod_bytes = idaapi.AssembleLine(0, 0, 0, is_32bit, line)
                arr_replace_bytes.extend(mod_bytes)
                total_bytes_patching += len(mod_bytes)
            except:
                print('Invalid assembly')
                return

        #check enough space to patch and fill nop
        flag_patching = True
        len_bytes_pattern_find_str = len(bytes_pattern_find_str.split())
        if len_bytes_pattern_find_str < total_bytes_patching:
            print('Not enough space to patch')
            flag_patching = False
            return
        else:
            # if not same length, fill nop
            remain = len_bytes_pattern_find_str - total_bytes_patching
            if remain > 0:
                nop_bytes = b'\x90' * remain
                arr_replace_bytes.extend(nop_bytes)

        # search pattern hex
        self.possible_obfuscation_regions.clear()
        pos_replaced_instr = current_addr = start_ea
        compiled_pattern = DeobfuscateUtils.compile_pattern_search(bytes_pattern_find_str)
        while current_addr < end_ea and pos_replaced_instr != idaapi.BADADDR and flag_patching:
            pos_replaced_instr = ida_bytes.bin_search(current_addr, end_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)[0]
            current_addr = pos_replaced_instr + len_bytes_pattern_find_str
            if pos_replaced_instr != idaapi.BADADDR:
                cmt = '\n'.join(comment)
                possible_region = ObfuscatedRegion(start_ea = pos_replaced_instr, end_ea = pos_replaced_instr + len_bytes_pattern_find_str,
                                                    obfus_size = len_bytes_pattern_find_str, comment = cmt, patch_bytes = arr_replace_bytes,
                                                    name = 'substitution', action = Action.PATCH)
                self.possible_obfuscation_regions.append(possible_region)

        return self.possible_obfuscation_regions
