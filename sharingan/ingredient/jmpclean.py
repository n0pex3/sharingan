from sharingan.base.itemlist import ItemList

class JmpClean(ItemList):
    def __init__(self, parent=None):
        super(JmpClean, self).__init__(parent)
        self.set_label_text('JmpClean')
        self.conditional_jump = {
            'jz_jnz_je_jne': ['74 ?? 75 ??', '75 ?? 74 ??', '0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??', '0F 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??'],
            'jc_jnc': ['72 ?? 73 ??', '73 ?? 72 ??', '0F 82 ?? ?? ?? ?? 0F 83 ?? ?? ?? ??', '0F 83 ?? ?? ?? ?? 0F 82 ?? ?? ?? ??'],
            'jo_jno': ['70 ?? 71 ??', '71 ?? 70 ??', '0F 80 ?? ?? ?? ?? 0F 81 ?? ?? ?? ??', '0F 81 ?? ?? ?? ?? 0F 80 ?? ?? ?? ??'],
            'js_jns': ['78 ?? 79 ??', '79 ?? 78 ??', '0F 88 ?? ?? ?? ?? 0F 89 ?? ?? ?? ??', '0F 89 ?? ?? ?? ?? 0F 88 ?? ?? ?? ??'],
            'jp_jnp_jpe_jpo': ['7A ?? 7B ??', '7B ?? 7A ??', '0F 8A ?? ?? ?? ?? 0F 8B ?? ?? ?? ??', '0F 8B ?? ?? ?? ?? 0F 8A ?? ?? ?? ??'],
            'ja_jbe_jnbe_jna': ['77 ?? 76 ??', '76 ?? 77 ??', '0F 86 ?? ?? ?? ?? 0F 87 ?? ?? ?? ??', '0F 87 ?? ?? ?? ?? 0F 86 ?? ?? ?? ??'],
            'jae_jb_jnb_jnae': ['73 ?? 72 ??', '72 ?? 73 ??', '0F 83 ?? ?? ?? ?? 0F 82 ?? ?? ?? ??', '0F 82 ?? ?? ?? ?? 0F 83 ?? ?? ?? ??'],
            'jg_jle_jnle_jng': ['7F ?? 7E ??', '7E ?? 7F ??', '0F 8E ?? ?? ?? ?? 0F 8F ?? ?? ?? ??', '0F 8F ?? ?? ?? ?? 0F 8E ?? ?? ?? ??'],
            'jge_jl_jnl_jnge': ['7D ?? 7C ??', '7C ?? 7D ??', '0F 8D ?? ?? ?? ?? 0F 8C ?? ?? ?? ??', '0F 8C ?? ?? ?? ?? 0F 8D ?? ?? ?? ??'],
        }
        self.count_patched_instr = 1
        self.key_conditional_jump = list(self.conditional_jump.keys())

    def deobfuscate(self, start_ea, end_ea):
        # loop all segment that has got EXEC permission
        current_segm = idaapi.get_first_seg()
        while current_segm.start_ea != idaapi.BADADDR:
            if current_segm.perm & idaapi.SEGPERM_EXEC:
                find_patch_jump_same_target(current_segm)
            current_segm = idaapi.get_next_seg(current_segm.start_ea)
            if current_segm is None:
                break

    def make_instr(self, addr):
        idc.create_insn(addr)
        idaapi.auto_wait()    

    def cmt_patch(self, start_obfu_addr, len_obfu, count_patched_instr, segm):
        current_ea = start_obfu_addr
        cmt = ''
        start_ea = 0x0
        dest_jump = 0x0
        while current_ea < start_obfu_addr + len_obfu:
            # delete obfu jump to make instruction and get cmt
            ida_bytes.del_items(current_ea, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_SIMPLE, len_obfu // 2)
            # create instruction obfu instruction
            self.make_instr(current_ea)
            instr = idaapi.insn_t()
            idaapi.decode_insn(instr, current_ea)
            # validate destination jump belong to segment, prevent invalid instruction
            if idc.get_operand_value(current_ea, 0) < segm.start_ea or idc.get_operand_value(current_ea, 0) > segm.end_ea:
                return
            cmt += idc.generate_disasm_line(current_ea, 0)
            if count_patched_instr > 0:
                # jump short 1 byte
                if instr.size == 2:
                    ida_bytes.patch_bytes(current_ea, b'\xEB')
                # jump short 4 byte
                elif instr.size == 6:
                    ida_bytes.patch_bytes(current_ea, b'\x90')
                    ida_bytes.patch_bytes(current_ea + 1, b'\xE9')
                count_patched_instr -= 1
            else:
                # patch other instruction to nop
                seq_nop = b'\x90' * instr.size
                ida_bytes.patch_bytes(current_ea, seq_nop)
                start_ea = current_ea
            current_ea += instr.size
        # patch instruction that make ida analyze fail jump
        ida_bytes.patch_bytes(current_ea, b'\x90')
        # create instruction at start address obfu
        self.make_instr(start_obfu_addr)
        # get valid destination jump after deob to create valid instruction at that address
        if len_obfu == 12:
            dest_jump = idc.get_operand_value(start_obfu_addr + 1, 0)
        elif len_obfu == 4:
            dest_jump = idc.get_operand_value(start_obfu_addr, 0)
        ida_bytes.del_items(dest_jump, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_SIMPLE, len_obfu)
        self.make_instr(dest_jump)
        # hide nop
        if len_obfu == 12:
            idc.add_hidden_range(start_ea, current_ea + 1, cmt, '', '', 0xFFA500)
        elif len_obfu == 4:
            idc.add_hidden_range(start_ea, current_ea + 1, cmt, '', '', 0xFFA500)
        ida_kernwin.request_refresh(0xFFFFFFFF)
        idaapi.auto_wait()

    def find_patch_jump_same_target(self, segm):
        found_obfu = segm.start_ea
        index_pair = 0
        # loop every key in hex pattern, if found it will return to begin to prevent not detecting previous hex pattern
        while index_pair < len(key_conditional_jump):
        #for jump in conditional_jump:
            index_pattern = 0
            while index_pattern < len(conditional_jump[key_conditional_jump[index_pair]]):
                seqstr = conditional_jump[key_conditional_jump[index_pair]][index_pattern]
                image_base = idaapi.get_imagebase()
                pattern = ida_bytes.compiled_binpat_vec_t()
                ida_bytes.parse_binpat_str(pattern, image_base, seqstr, 16)
                found_obfu = ida_bytes.bin_search(found_obfu, segm.end_ea, pattern, ida_bytes.BIN_SEARCH_FORWARD)[0]
                # if idaapi.print_insn_mnem(found_obfu) in arr_opcode_jmp:
                if found_obfu == idaapi.BADADDR:
                    index_pattern += 1
                    found_obfu = segm.start_ea
                    continue
                else:
                    self.cmt_patch(found_obfu, len(seqstr.split()), self.count_patched_instr, segm)
                    index_pair = 0
                found_obfu += len(seqstr.split())
            index_pair += 1

    def detect(self, start_ea, end_ea):
        print('Scan Internal')