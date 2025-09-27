import idaapi, ida_bytes, ida_ida, idc
from sharingan.base.itemlist import ItemList
from PySide6.QtWidgets import QTextEdit, QLineEdit, QHBoxLayout


class Irrelevant(ItemList):
    def __init__(self, parent=None):
        super(Irrelevant, self).__init__(parent)
        self.set_label_text('Irrelevant')

        self.ldt_start_ea = QLineEdit()
        self.ldt_start_ea.setPlaceholderText('Start EA')
        self.ldt_end_ea = QLineEdit()
        self.ldt_end_ea.setPlaceholderText('End EA')
        self.layout_addr = QHBoxLayout()
        self.layout_addr.addWidget(self.ldt_start_ea)
        self.layout_addr.addWidget(self.ldt_end_ea)
        self.tet_patching_instruction = QTextEdit()
        self.layout.addLayout(self.layout_addr)
        self.layout.addWidget(self.tet_patching_instruction)
        
    def deobfuscate(self, start_ea, end_ea):
        # address start and end of obfuscated instruction
        start_obfu_addr = int(self.ldt_start_ea.text(), 0)
        end_obfu_addr = int(self.ldt_start_ea.text(), 0)
        # previous address for determining instruction or data
        previous_addr = 0
        # maybe segment or function
        end_ea = 0
        flag_patching = True
        patching_assem = self.tet_patching_instruction.toPlainText()
        arr_patching_assem = patching_assem.split('\n')
        # hex bytes in string
        seqstr = ''
        comment = ''
        is_32bit = ida_ida.inf_is_32bit_exactly()
        # get full bytes of instruction and data between start_obfu_addr and end_obfu_addr
        while start_obfu_addr <= end_obfu_addr and start_obfu_addr != idaapi.BADADDR:
            instr = idaapi.insn_t()
            if ida_bytes.is_code(ida_bytes.get_full_flags(start_obfu_addr)):
                idaapi.decode_insn(instr, start_obfu_addr)
                len_instr = instr.size
                hex_bytes = ida_bytes.get_bytes(start_obfu_addr, len_instr)
                hex_bytes_str = ' '.join([f"{b:02x}" for b in hex_bytes]) + ' '
                seqstr += hex_bytes_str
                count_space = len_instr - 1
                # adjust space to align
                comment += f'{idc.generate_disasm_line(start_obfu_addr, 0)}\n'
            # if being data, convert to NOP
            elif ida_bytes.is_code(ida_bytes.get_full_flags(previous_addr)) is False:
                len_data = start_obfu_addr - previous_addr
                seqstr += '?? ' * len_data
                seq_nop = '90 ' * len_data
                comment += '\n'
            previous_addr = start_obfu_addr
            start_obfu_addr = idc.next_head(start_obfu_addr)
        # find end_ea is segment or function
        comment += '#Instructions Substitution'
        image_base = idaapi.get_imagebase()
        pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(pattern, image_base, seqstr, 16)
        # function = idaapi.get_func(start_obfu_addr)
        # if function is not None:
        #     current_ea = function.start_ea
        #     end_ea = function.end_ea
        # else:
        #     segment = idaapi.getseg(start_obfu_addr)
        #     current_ea = segment.start_ea
        #     end_ea = segment.end_ea

        # check enough space to patch
        count_patching_byte = 0
        for line in arr_patching_assem:
            count_patching_byte += len(idaapi.AssembleLine(0, 0, 0, is_32bit, line))
        if len(seqstr.split()) < count_patching_byte:
            print('Not enough space to patch')
            flag_patching = False

        # patching
        current_addr = start_ea
        end_addr = end_ea
        while current_addr < end_ea and current_addr != idaapi.BADADDR and flag_patching:
            pos_replaced_instr = ida_bytes.bin_search(current_addr, end_ea, pattern,
                                                    ida_bytes.BIN_SEARCH_FORWARD)[0]
            current_addr = pos_replaced_instr + len(seqstr)
            if ida_bytes.is_code(ida_bytes.get_full_flags(pos_replaced_instr)):
                ida_bytes.del_items(pos_replaced_instr, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_SIMPLE, len(seqstr))
                # save original instruction
                ida_bytes.set_cmt(pos_replaced_instr, comment, False)
                pos_patching = pos_replaced_instr
                count_patching_byte = 0
                # patch replaced instruction firstly
                for line in arr_patching_assem:
                    idaapi.assemble(pos_patching, 0, pos_patching, is_32bit, line)
                    instr = idaapi.insn_t()
                    idaapi.decode_insn(instr, pos_patching)
                    count_patching_byte += instr.size
                    pos_patching += instr.size
                remain = len(seqstr.split()) - count_patching_byte
                start_nop = pos_patching
                # if remain space, fill nop
                if remain > 0:
                    nop = b'\x90' * remain
                    ida_bytes.patch_bytes(pos_patching, nop)
                end_nop = pos_patching + remain
                idc.create_insn(pos_replaced_instr)
                if start_nop != end_nop:
                    idc.add_hidden_range(start_nop, end_nop - 1, 'NOP', '', '', 0xFFFFFF)
                    idc.del_hidden_range(start_nop)

    def detect(self, start_ea, end_ea):
        print('Irrelevant - Nothing')



