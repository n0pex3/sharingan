import idaapi
import ida_bytes
import idc


class DeobfuscateUtils:
    @staticmethod
    def get_bytes_as_hex_string(addr, size):
        bytes_data = ida_bytes.get_bytes(addr, size)
        return ' '.join([f"{b:02x}" for b in bytes_data])

    @staticmethod
    def mark_as_code(start_addr, end_addr):
        idaapi.auto_mark_range(start_addr, end_addr, idaapi.AU_CODE)
        idaapi.plan_and_wait(start_addr, end_addr, True)

    @staticmethod
    def refresh_view():
        idaapi.request_refresh(0xFFFFFFFF)
        idaapi.auto_wait()

    @staticmethod
    def patch_bytes(addr, arr_byte):
        ida_bytes.patch_bytes(addr, arr_byte)
        idaapi.auto_wait()

    @staticmethod
    def del_items(addr, length, is_expand=False):
        if not is_expand:
            ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, length)
        else:
            ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE | ida_bytes.DELIT_EXPAND, length)
        idaapi.auto_wait()

    @staticmethod
    def compile_pattern_search(bytes_pattern_str):
        image_base = idaapi.get_imagebase()
        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled_pattern, image_base, bytes_pattern_str, 16)
        return compiled_pattern

    @staticmethod
    def is_call(addr):
        call_insn = set((idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni))
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype in call_insn or idaapi.is_call_insn(instr)

    @staticmethod
    def is_push(addr) :
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype == idaapi.NN_push

    @staticmethod
    def is_mov(addr) :
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype == idaapi.NN_mov

    @staticmethod
    def is_nop(addr) :
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype == idaapi.NN_nop

    @staticmethod
    def reset(start_addr, end_addr):
        current_ea = start_addr
        while current_ea < end_addr:
            idaapi.del_hidden_range(current_ea)
            idc.set_color(current_ea, idc.CIC_ITEM, 0xFFFFFFFF)
            current_ea = idaapi.next_head(current_ea, idaapi.BADADDR)
        DeobfuscateUtils.mark_as_code(start_addr, end_addr)

    @staticmethod
    def color_range(start_addr, end_addr, color):
        curr = start_addr
        while curr < end_addr:
            idc.set_color(curr, idc.CIC_ITEM, color)
            curr = idaapi.next_head(curr, idaapi.BADADDR)

    @staticmethod
    def is_all_nop(ba):
        return all(b == 0x90 for b in ba)