from sharingan.base.ingredient import Deobfuscator
from PySide6.QtWidgets import QLineEdit, QCheckBox, QHBoxLayout
import idaapi, ida_bytes, idautils, idc
import re
from sharingan.core.utils import DeobfuscateUtils
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action


class APIHammering(Deobfuscator):
    def __init__(self):
        super().__init__('APIHammering')
        self.description = 'APIHammering'
        self.version = '1.0'

        self.range_start = 0x0
        self.range_end = 0x0

    def setup_ui(self):
        super().setup_ui()

        self.ldt_winapi = QLineEdit()
        self.ldt_winapi.setPlaceholderText('WinAPI')
        self.chk_pointer = QCheckBox('Pointer')
        self.layout_input = QHBoxLayout()
        self.layout_input.addWidget(self.ldt_winapi)
        self.layout_input.addWidget(self.chk_pointer)
        self.layout_body.addLayout(self.layout_input)

    def scan(self, start_ea, end_ea):
        is_32bit = idaapi.inf_is_32bit_exactly()
        if not is_32bit:
            print('Only support 32 bit')
            return

        self.range_start = start_ea
        self.range_end = end_ea
        if self.chk_pointer.isChecked():
            self.enumerate_xref(int(self.ldt_winapi.text().strip().lower(), 16), None, None)
        else:
            count_import = idaapi.get_import_module_qty()
            for i in range(0, count_import):
                name_module = idaapi.get_import_module_name(i)
                if not name_module:
                    print('Failed to get module {i}')
                    continue
                idaapi.enum_import_names(i, self.callback_enumerate_xref)
        return self.possible_obfuscation_regions

    def get_arg_count(self, api_addr):
        prototype = idc.get_type(api_addr)
        if prototype is None:
            return -1

        # ([^)]*) => matches any character except a closing parenthesis )
        params_match = re.findall(r'\(([^)]*)\)', prototype)
        if len(params_match) > 0:
            param_list = params_match[1].split(',')
            if len(param_list) > 0 and param_list[0] != '':
                return len(param_list)
        return -1

    def enumerate_xref(self, api_addr, name_api, ord_api):
        self.possible_obfuscation_regions.clear()
        # ida auto regconize calling register is calling api via calculating
        code_refs = list(idautils.CodeRefsTo(api_addr, 0))
        # directly call from data segment
        data_refs = list(idautils.DataRefsTo(api_addr))
        all_xrefs = code_refs + data_refs
        for addr_call in all_xrefs:
            # exclude mov register, pointer_api
            if not DeobfuscateUtils.is_call(addr_call) or not (self.range_start <= addr_call < self.range_end):
                continue

            info_func = idaapi.get_func(addr_call)
            func_start = idaapi.get_func(addr_call).start_ea if info_func else idaapi.getseg(addr_call).start_ea
            func_end = idaapi.get_func(addr_call).end_ea if info_func else idaapi.getseg(addr_call).end_ea
            param_count = self.get_arg_count(api_addr)
            if param_count >= 0:
                # collect call
                len_call = idaapi.get_item_size(addr_call)
                possible_region = ObfuscatedRegion(start_ea = addr_call, end_ea = addr_call + len_call, obfus_size = len_call,
                                                    comment = idaapi.tag_remove(idaapi.generate_disasm_line(addr_call, 0)),
                                                    patch_bytes = len_call * b'\x90', name = 'apihammering', action = Action.PATCH)
                prev_addr = addr_call
                # find push or mov instruction init param of api via sp
                while func_start <= prev_addr < func_end and param_count > 0:
                    prev_addr = idaapi.prev_head(prev_addr, 0)
                    if DeobfuscateUtils.is_push(prev_addr):
                        len_push = idaapi.get_item_size(prev_addr)
                        possible_region.append_obfu(start_ea = prev_addr, end_ea = prev_addr + len_push, obfus_size = len_push,
                                                    comment = idaapi.tag_remove(idaapi.generate_disasm_line(prev_addr, 0)),
                                                    patch_bytes = len_push * b'\x90', action = Action.PATCH)
                        param_count -= 1
                    elif DeobfuscateUtils.is_call(prev_addr):
                        idaapi.set_cmt(addr_call, 'Manually patch push instruction',0)
                        break
                    elif DeobfuscateUtils.is_mov(prev_addr):
                        print(f"Maybe push {hex(prev_addr)}")
                        pass
                self.possible_obfuscation_regions.append(possible_region)
            else:
                print('Please define prototype API')
                return

    def callback_enumerate_xref(self, api_addr, name_api, ord_api):
        if name_api.lower() == self.ldt_winapi.text().strip().lower():
            self.enumerate_xref(api_addr, name_api, ord_api)
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
