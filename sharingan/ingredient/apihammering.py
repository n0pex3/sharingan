from sharingan.base.itemlist import ItemList
from PySide6.QtWidgets import QLineEdit, QCheckBox, QHBoxLayout

class APIHammering(ItemList):
    def __init__(self, parent=None):
        super(APIHammering, self).__init__(parent)
        self.set_label_text('APIHammering')
        self.ldt_winapi = QLineEdit()
        self.ldt_winapi.setPlaceholderText('WinAPI')
        self.chk_pointer = QCheckBox('Pointer')
        self.layout_input = QHBoxLayout()
        self.layout_input.addWidget(self.ldt_winapi)
        self.layout_input.addWidget(self.chk_pointer)
        self.layout.addLayout(self.layout_input)

    def deobfuscate(self, start_ea, end_ea):
        if self.chk_pointer.isChecked():
            enumerate_xref_patch(pointer, None, None)
        else:
            count_import = idaapi.get_import_module_qty()
            for i in range(0, count_import):
                name_module = idaapi.get_import_module_name(i)
                if not name_module:
                    print('Failed to get module {i}')
                    continue
                idaapi.enum_import_names(i, self.w_enumerate_xref_patch)

    def count_param_api(self, ea_api):
        prototype = idc.get_type(ea_api)
        # ([^)]*) => matches any character except a closing parenthesis )
        params = re.findall(r'\(([^)]*)\)', prototype)
        if len(params) > 0:
            param_list = params[1].split(',')
            if len(param_list) > 0 and param_list[0] != '':
                param_count = len(param_list)
                return param_count
        return 0

    def gen_comment(self, start_obfu_addr, len_instr):
        hex_bytes = ida_bytes.get_bytes(start_obfu_addr, len_instr)
        hex_bytes_str = ' '.join([f"{b:02x}" for b in hex_bytes]) + ' '
        count_space = len_instr - 1
        return f'{hex_bytes_str.ljust(20 - len_instr + count_space)} % {idc.generate_disasm_line(start_obfu_addr, 0)}'

    def patch_nop(self, addr, start_ea, end_ea, info_func):
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        cmt = idc.generate_disasm_line(addr, 0)
        seq_nop = b'\x90' * instr.size
        ida_bytes.del_items(addr, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_SIMPLE, instr.size)
        ida_bytes.patch_bytes(addr, seq_nop)
        idc.create_insn(addr)
        end_nop = addr + instr.size
        idc.add_hidden_range(addr, end_nop, cmt, '', '', 0xFFA500)
        ida_kernwin.request_refresh(0xFFFFFFFF)
        idaapi.auto_wait()
        # set end function after patching to make function
        if info_func is not None:
            ida_funcs.set_func_end(start_ea, end_ea)
            idaapi.auto_wait()

    def enumerate_xref_patch(self, ea_api, name_api, ord_api):
        # ida auto regconize calling register is calling api via calculating 
        code_refs = list(idautils.CodeRefsTo(ea_api, 0))
        # directly call from data segment
        data_refs = list(idautils.DataRefsTo(ea_api))
        xrefs = code_refs + data_refs
        for addr_call in xrefs:
            # exclude mov register, pointer_api
            if idc.print_insn_mnem(addr_call) == 'call':
                info_func = ida_funcs.get_func(addr_call)
                start_ea = None
                end_ea = None
                if info_func is not None:
                    start_ea = ida_funcs.get_func(addr_call).start_ea
                    end_ea = ida_funcs.get_func(addr_call).end_ea
                else:
                    start_ea = idaapi.getseg(addr_call).start_ea
                    end_ea = idaapi.getseg(addr_call).end_ea
                param_count = self.count_param_api(ea_api)
                patch_nop(addr_call, start_ea, end_ea, info_func)
                if param_count > 0:
                    prev_instr = addr_call
                    # find push or mov instruction init param of api via sp
                    while prev_instr > start_ea and prev_instr < end_ea and param_count > 0:
                        prev_instr = idc.prev_head(prev_instr)
                        if idc.print_insn_mnem(prev_instr) == 'push':
                            patch_nop(prev_instr, start_ea, end_ea, info_func)
                            idaapi.auto_wait()
                            param_count -= 1
                        elif idc.print_insn_mnem(prev_instr) == 'call':
                            idc.set_cmt(addr_call, 'Manually patch push instruction',0)
                            break
                        elif idc.print_insn_mnem(prev_instr) == 'mov':
                            pass
                            # 1. get bytes of this instruction
                            # 2. decode its via keystone to get raw instruction
                            # 3. get first operand and compare sp + offset 

    def w_enumerate_xref_patch(self, ea_api, name_api, ord_api):
        if name_api.lower() == self.ldt_winapi.text().trim().lower():
            self.enumerate_xref_patch(ea_api, name_api, ord_api)
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True

    def detect(self, start_ea, end_ea):
        print('API Hammering - Nothing')