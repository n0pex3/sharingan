from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, ida_bytes, idc
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action


class JmpClean(Deobfuscator):
    def __init__(self):
        super().__init__('JmpClean')
        self.description = 'ObfuscatedJump'
        self.version = '1.0'

        self.conditional_jump_patterns = {
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
        self.pattern_keys = list(self.conditional_jump_patterns.keys())

    def scan(self, start_addr, end_addr):
        self.possible_obfuscation_regions.clear()
        current_addr = start_addr
        key_index = 0
        # loop every key in hex pattern, if found it will return to begin to prevent not detecting previous hex pattern
        while key_index < len(self.pattern_keys) and current_addr < end_addr:
            pattern_index = 0
            # loop all values in each key
            while pattern_index < len(self.conditional_jump_patterns[self.pattern_keys[key_index]]):
                pattern_str = self.conditional_jump_patterns[self.pattern_keys[key_index]][pattern_index]
                compiled_pattern = DeobfuscateUtils.compile_pattern_search(pattern_str)
                found_addr = ida_bytes.bin_search(current_addr, end_addr, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)[0]
                if found_addr == idaapi.BADADDR:
                    pattern_index += 1
                    current_addr = start_addr
                    continue
                else:
                    current_addr = found_addr
                    len_obfu_jump = len(pattern_str.split())
                    comment = ''
                    is_valid_jmp = True
                    start_binary = idaapi.get_imagebase()
                    end_binary = idaapi.get_last_seg().end_ea if idaapi.get_last_seg() else idaapi.BADADDR
                    # check valid dest jump
                    while current_addr < found_addr + len_obfu_jump:
                        if not (start_binary < idc.get_operand_value(current_addr, 0) < end_binary):
                            print(f"Invalid jmp {current_addr}")
                            is_valid_jmp = False
                            continue
                        comment += "{idaapi.tag_remove(idaapi.generate_disasm_line(current_addr, 0))}\n"
                        current_addr += len_obfu_jump // 2

                    if is_valid_jmp:
                        # create valid instruction, convert invalid opcode to data
                        dest_jmp = idc.get_operand_value(found_addr, 0)
                        addr_obfus_jmp = idaapi.get_item_head(dest_jmp)
                        size_insn_obfus_jmp = idaapi.get_item_size(addr_obfus_jmp)
                        DeobfuscateUtils.del_items(addr_obfus_jmp, size_insn_obfus_jmp, True)
                        next_addr_obfus_jmp = idaapi.next_head(dest_jmp, idaapi.BADADDR)
                        DeobfuscateUtils.mark_as_code(dest_jmp, next_addr_obfus_jmp)
                        size_invalid_opcode = dest_jmp - addr_obfus_jmp

                        if len_obfu_jump == 4:
                            mod_bytes = bytearray(ida_bytes.get_bytes(found_addr, len_obfu_jump))
                            mod_bytes[0] = 0xEB
                            for i in range(2, 4):
                                mod_bytes[i] = 0x90
                        elif len_obfu_jump == 12:
                            mod_bytes = bytearray(ida_bytes.get_bytes(found_addr, len_obfu_jump))
                            mod_bytes[0] = 0x90
                            mod_bytes[1] = 0xE9
                            for i in range(6, 12):
                                mod_bytes[i] = 0x90
                        # region jump
                        possible_region = ObfuscatedRegion(start_ea = found_addr, end_ea = found_addr + len_obfu_jump, obfus_size = len_obfu_jump, comment = comment,
                                                            patch_bytes = mod_bytes, name = 'jumpclean', action = Action.PATCH)
                        # region invalid opcode
                        possible_region.append_obfu(start_ea = addr_obfus_jmp, end_ea = dest_jmp, obfus_size = size_invalid_opcode, comment = 'NOP',
                                                    patch_bytes = size_invalid_opcode * b'\x90', action = Action.PATCH)
                        self.possible_obfuscation_regions.append(possible_region)

                    key_index = 0
                current_addr = found_addr + len_obfu_jump
            key_index += 1

        return self.possible_obfuscation_regions
