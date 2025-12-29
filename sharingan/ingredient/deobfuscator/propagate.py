from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action

import idaapi, idc

from unicorn import *
from unicorn.x86_const import *


class Propagate(Deobfuscator):
    def __init__(self):
        super().__init__('Propagate')
        self.description = 'Propagate'
        self.version = '1.0'

        self.start_ea = 0x0
        self.end_ea = 0x0
        self.is_error = False

        self.text_segm = idaapi.get_segm_by_name(".text")
        self.data_segm = idaapi.get_segm_by_name(".data")
        self.imagebase = idaapi.get_imagebase()

        self.stack_addr = 0x70000000
        self.stack_size = 0x10000
        self.stack_top = self.stack_addr + self.stack_size - 0x1000

        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.mu.mem_map(self.stack_addr, self.stack_size)
        self.hook_insn = None

        if self.text_segm:
            self.text_map_size = self.text_segm.end_ea - self.text_segm.start_ea
            self.text_map_base = self.text_segm.start_ea
            self.mu.mem_map(self.text_map_base, self.text_map_size)

        if self.data_segm:
            self.data_content = idaapi.get_bytes(self.data_segm.start_ea, self.data_segm.end_ea - self.data_segm.start_ea)
            self.data_map_size = self.data_segm.end_ea - self.data_segm.start_ea
            self.data_map_base = self.data_segm.start_ea
            self.mu.mem_map(self.data_map_base, self.data_map_size)
            self.mu.mem_write(self.data_map_base, self.data_content)

        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_invalid)

    # when access invalid memory like unmap region => log and continue
    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)

        print(f"\n[!] CRASH DETECTED!")
        print(f"    - RIP: {hex(rip)}")
        print(f"    - Access (Memory): {hex(address)}")

        try:
            insn = idc.GetDisasm(rip)
            print(f"    -> Skipping instruction: {insn} (length: {size})")
            # return true to continue
            return True
        except Exception as e:
            print(f"    -> Cannot skip: {e}")
            # if cannot disassemble instruction => return false to exit
            return False

    # extract bytes to emulate
    def prepare_emulation(self, addr_obfus):
        start_emu = addr_obfus
        while True:
            # loop previous insn to extract bytes
            start_emu = idaapi.prev_head(start_emu, self.imagebase)
            if start_emu < self.start_ea:
                start_emu = self.start_ea
                break
            elif start_emu == idaapi.BADADDR:
                start_emu = self.imagebase
                break
            elif DeobfuscateUtils.is_jmp(start_emu) or DeobfuscateUtils.is_call(start_emu):
                start_emu = idaapi.next_head(start_emu, idaapi.BADADDR)
                break

        len_bytes = addr_obfus - start_emu
        if len_bytes:
            bytes_emulation = idaapi.get_bytes(start_emu, len_bytes)
            return bytes_emulation, start_emu

        return None, None

    # use unicorn to emulate code
    def emulate_code(self, hex_code, start_emu, addr_obfus):
        # check boundary and skip insn call/jmp to prevent emulate outside
        def skip_insn_hook(uc, address, size, user_data):
            if address < self.start_ea or address > self.end_ea or address == idaapi.BADADDR:
                print(f"Outside boundary {hex(self.start_ea)} {hex(self.end_ea)}")
                self.is_error = True
                uc.emu_stop()
            elif DeobfuscateUtils.is_call(address) or DeobfuscateUtils.is_jmp(address):
                uc.reg_write(UC_X86_REG_RIP, address + size)

        # reset register rsp, rbp, rax
        def reset_registers():
            self.mu.reg_write(UC_X86_REG_RSP, self.stack_top)
            self.mu.reg_write(UC_X86_REG_RBP, self.stack_top)
            self.mu.reg_write(UC_X86_REG_RAX, 0)

        self.mu.mem_write(start_emu, hex_code)
        reset_registers()

        # if emulating some insns failure, skip those insn and log
        start_emu_bak = start_emu
        len_emu = len(hex_code) - (start_emu - start_emu_bak)
        rax = 0
        # flag control emulation success
        self.is_error = False
        # add hook to check
        self.hook_insn = self.mu.hook_add(UC_HOOK_CODE, skip_insn_hook)
        while not self.is_error:
            try:
                self.mu.emu_start(start_emu, start_emu + len_emu)
                rax = self.mu.reg_read(UC_X86_REG_RAX)
                self.is_error = True
            # if emulation fails, skip those insn
            except UcError as e:
                print(f"Error at {hex(start_emu)}: {e}")
                reset_registers()
                start_emu = idaapi.next_head(start_emu, idaapi.BADADDR)
                if start_emu < self.start_ea or start_emu > self.end_ea or start_emu == idaapi.BADADDR or start_emu > addr_obfus:
                    print(f"Cannot emulate this region {hex(self.start_ea)} {hex(self.end_ea)}")
                    self.is_error = True
                    rax = 0

        # delete hook after emulation success
        self.mu.hook_del(self.hook_insn)
        if self.text_segm.start_ea <= rax < self.text_segm.end_ea:
            return rax
        else:
            print(f"Invalid jmp {hex(addr_obfus)}")
            return 0

    def scan(self, start_addr, end_addr):
        self.start_ea = start_addr
        self.end_ea = end_addr
        self.possible_obfuscation_regions.clear()

        next_addr = start_addr
        while next_addr < end_addr:
            next_addr = idaapi.next_head(next_addr, idaapi.BADADDR)
            if not idaapi.is_code(idaapi.get_full_flags(next_addr)):
                continue
            insn = idaapi.insn_t()
            len_insn = idaapi.decode_insn(insn, next_addr)
            if len_insn == 0:
                continue
            # find jmp abd call insn to emulate
            if insn.itype == idaapi.NN_jmpni or insn.itype == idaapi.NN_callni:
                op_reg = insn.ops[0]
                if op_reg.type != idaapi.o_reg or op_reg.reg != 0:
                    continue
                bytes_emulation, start_emu = self.prepare_emulation(next_addr)
                addr_deob = self.emulate_code(bytes_emulation, start_emu, next_addr)
                if addr_deob:
                    possible_region = ObfuscatedRegion(start_ea = next_addr, end_ea = idaapi.next_head(next_addr, idaapi.BADADDR), comment = hex(addr_deob), name = 'propagate', action = Action.CMT)
                    self.possible_obfuscation_regions.append(possible_region)

        return self.possible_obfuscation_regions
