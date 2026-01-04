from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, ida_bytes, idc
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action


class DBJmp(Deobfuscator):
    def __init__(self):
        super().__init__('DBJmp')
        self.description = 'ObfuscatedJump'
        self.version = '1.0'

    def check_same_target(self, first_jmp, second_jmp):
        first_target = idc.get_operand_value(first_jmp, 0)
        second_target = idc.get_operand_value(second_jmp, 0)
        return True if first_target == second_target else False

    def get_bytes_jmp(self, first_jmp, second_jmp):
        first_size = idc.get_item_size(first_jmp)
        second_size = idc.get_item_size(second_jmp)
        first_raw = ida_bytes.get_bytes(first_jmp, first_size)
        second_raw = ida_bytes.get_bytes(second_jmp, second_size)
        return first_raw + second_raw

    def patch_bytes(self, bytes_jmp):
        len_bytes_jmp = len(bytes_jmp)
        mod_bytes = bytearray(bytes_jmp)
        if len_bytes_jmp == 4:
            mod_bytes[0] = 0xEB
            for i in range(2, 4):
                mod_bytes[i] = 0x90
        elif len_bytes_jmp == 12:
            mod_bytes[0] = 0x90
            mod_bytes[1] = 0xE9
            for i in range(6, 12):
                mod_bytes[i] = 0x90

        return mod_bytes

    def fix_overlapping(self, obfus_jmp):
        insn = idaapi.generate_disasm_line(obfus_jmp, 0)
        insn = idaapi.tag_remove(insn)
        dest_addr = idc.get_operand_value(obfus_jmp, 0)
        if '+' in insn:
            overlapping_size_str = insn.split('+')[1]
            overlapping_size = int(overlapping_size_str, 0)
            invalid_addr = dest_addr - overlapping_size
            DeobfuscateUtils.del_items(invalid_addr, overlapping_size, True)
            DeobfuscateUtils.mark_as_code(dest_addr, idaapi.BADADDR)
            return invalid_addr, dest_addr
        return None, None

    def scan(self, start_addr, end_addr):
        self.possible_obfuscation_regions.clear()
        next_addr = start_addr
        while next_addr < end_addr:
            if DeobfuscateUtils.is_jmp(next_addr):
                below_addr_jmp = idaapi.next_head(next_addr, idaapi.BADADDR)
                if DeobfuscateUtils.is_jmp(below_addr_jmp):
                    if not self.check_same_target(next_addr, below_addr_jmp):
                        next_addr = below_addr_jmp
                        continue
                    comment = f"{idaapi.generate_disasm_line(next_addr, 0)}\n"
                    comment += f"{idaapi.generate_disasm_line(below_addr_jmp, 0)}"
                    bytes_jmp = self.get_bytes_jmp(next_addr, below_addr_jmp)
                    patched_bytes_jmp = self.patch_bytes(bytes_jmp)
                    len_bytes_jmp = len(bytes_jmp)
                    possible_region = ObfuscatedRegion(start_ea = next_addr, end_ea = next_addr + len_bytes_jmp, obfus_size = len_bytes_jmp, comment = comment,
                                                        patch_bytes = patched_bytes_jmp, name = 'dbjmp', action = Action.PATCH)
                    start_invalid, end_invalid = self.fix_overlapping(next_addr)
                    if start_invalid and end_invalid:
                        size_invalid = end_invalid - start_invalid
                        possible_region.append_obfu(start_ea = start_invalid, end_ea = end_invalid, obfus_size = size_invalid, comment = 'NOP',
                                                    patch_bytes = size_invalid * b'\x90', action = Action.PATCH)
                    self.possible_obfuscation_regions.append(possible_region)

            next_addr = idaapi.next_head(next_addr, idaapi.BADADDR)

        return self.possible_obfuscation_regions
