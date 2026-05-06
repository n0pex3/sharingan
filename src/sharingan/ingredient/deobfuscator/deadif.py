from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, ida_bytes, idc, ida_hexrays
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action
from PySide6.QtWidgets import QLineEdit, QComboBox, QHBoxLayout, QLabel, QSizePolicy


# for best result, remove the inside out
class FinderCondition(ida_hexrays.ctree_visitor_t):
    def __init__(self, func, obfus_region, equation, user_val):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.flowchart = idaapi.FlowChart(func)
        self.obfus_region = obfus_region
        self.equation = equation
        self.user_val = int(user_val, 0)

        self.op_map = {
            '==': [22],                     # cot_eq
            '>':  [28, 29],                 # cot_sgt, cot_ugt
            '>=': [24, 25],                 # cot_sge, cot_uge
            '<':  [30, 31],                 # cot_slt, cot_ult
            '<=': [26, 27]                  # cot_sle, cot_ule
        }
        self.COT_NUM = 61                   # cot_num

    def check_numeric_logic(self, expr):
        if not expr:
            return False

        if expr.op in [ida_hexrays.cot_land, ida_hexrays.cot_lor]:
            return self.check_numeric_logic(expr.x) or self.check_numeric_logic(expr.y)

        target_ops = self.op_map.get(self.equation, [])
        if expr.op not in target_ops:
            return False
        if expr.y.op == self.COT_NUM:
            code_val = expr.y.n._value
            if self.equation in ['>', '>=']:
                return self.user_val >= code_val
            elif self.equation in ['<', '<=']:
                return self.user_val <= code_val
            elif self.equation == '==':
                return self.user_val == code_val
        return False

    def get_boundary_block(self, ea):
        for block in self.flowchart:
            if block.start_ea <= ea < block.end_ea:
                return block.start_ea, block.end_ea
        return None, None

    def get_expr_string(self, expr):
        if not expr:
            return False
        return idaapi.tag_remove(expr.print1(None))

    def is_break_statement(self, insn):
        if not insn:
            return False

        if insn.op == ida_hexrays.cit_break:
            return True

        if insn.op == ida_hexrays.cit_block:
            if insn.cblock.size() == 1:
                first_insn = insn.cblock.front()
                if first_insn.op == ida_hexrays.cit_break:
                    return True
        return False

    # please update instruction before jump condition if not found
    def is_cmp_test(self, addr):
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype in [idaapi.NN_cmp, idaapi.NN_test, idaapi.NN_and]

    def is_jmp(self, addr):
        return idc.print_insn_mnem(addr).startswith("j")

    def find_cmp_test(self, ea):
        start_blk, end_blk = self.get_boundary_block(ea)
        if start_blk and end_blk:
            while ea != idaapi.BADADDR:
                if self.is_cmp_test(ea):
                    return ea
                ea = idaapi.prev_head(ea, start_blk)
        return idaapi.BADADDR

    def get_start_block(self, insn):
        if not insn:
            return idaapi.BADADDR

        if insn.ea != idaapi.BADADDR:
            start_blk, _ = self.get_boundary_block(insn.ea)
            return start_blk

        if insn.op is ida_hexrays.cit_block and not insn.cblock.empty():
            return self.get_start_block(insn.cblock.front())

        return idaapi.BADADDR

    def get_end_block(self, insn):
        if not insn:
            return idaapi.BADADDR

        if insn.op is idaapi.cit_block:
            if insn.cblock.empty():
                return self.get_start_block(insn)
            return self.get_end_block(insn.cblock.back())

        if insn.ea != idaapi.BADADDR:
            _, end_blk = self.get_boundary_block(insn.ea)
            return end_blk
        return idaapi.BADADDR

    def find_and_or_condition(self, expr, result):
        if not expr:
            return

        if expr.op in [ida_hexrays.cot_land, ida_hexrays.cot_lor]:
            self.find_and_or_condition(expr.x, result)
            self.find_and_or_condition(expr.y, result)
        else:
            op_ea = expr.ea
            if op_ea != idaapi.BADADDR:
                # can use recursive to get min and max address to get ea of cmp and jmp but compiler can insert some insn between them
                # so cannot filter exactly
                jmp_ea = self.find_jmp(op_ea)
                cmp_ea = self.find_cmp_test(jmp_ea)
                result.append({
                    'cond': self.get_expr_string(expr),
                    'cmp': cmp_ea,
                    'jmp': jmp_ea
                })

    def find_jmp(self, jmp_ea):
        while not self.is_jmp(jmp_ea):
            jmp_ea = idaapi.next_head(jmp_ea, idaapi.BADADDR)
        return jmp_ea

    def visit_insn(self, insn):
        if insn.op == ida_hexrays.cit_if:
            # check condition expression if is junk code or not base on input of user
            if self.check_numeric_logic(insn.cif.expr):
                print(f"[Sharingan] --- [IF] at {hex(insn.ea)} ---")
                cond = self.get_expr_string(insn.cif.expr)
                print(f"[Sharingan]    Condition: {cond}")

                # 1. find pair cmp/jmp instruction and/or
                sub_conditions = []
                self.find_and_or_condition(insn.cif.expr, sub_conditions)

                if not sub_conditions:
                    return 0

                # 2. always init possible_region from first pair cmp/jmp to prevent missing if break in loop
                first_item = sub_conditions[0]
                size_cmp = idaapi.get_item_size(first_item["cmp"])

                possible_region = ObfuscatedRegion(
                    start_ea=first_item["cmp"],
                    end_ea=idaapi.next_head(first_item["cmp"], idaapi.BADADDR),
                    obfus_size=size_cmp,
                    comment='DeadIf CMP',
                    patch_bytes=size_cmp * b'\x90',
                    name='DeadIf',
                    action=Action.PATCH
                )

                size_jmp = idaapi.get_item_size(first_item["jmp"])
                possible_region.append_obfu(
                    start_ea=first_item["jmp"],
                    end_ea=idaapi.next_head(first_item["jmp"], idaapi.BADADDR),
                    obfus_size=size_jmp,
                    comment='DeadIf JMP',
                    patch_bytes=size_jmp * b'\x90',
                    action=Action.PATCH
                )

                # add other pairs expression
                for i in range(1, len(sub_conditions)):
                    item = sub_conditions[i]
                    s_cmp = idaapi.get_item_size(item["cmp"])
                    possible_region.append_obfu(item["cmp"], idaapi.next_head(item["cmp"], idaapi.BADADDR), s_cmp, 'DeadIf CMP', s_cmp * b'\x90', Action.PATCH)
                    s_jmp = idaapi.get_item_size(item["jmp"])
                    possible_region.append_obfu(item["jmp"], idaapi.next_head(item["jmp"], idaapi.BADADDR), s_jmp, 'DeadIf JMP', s_jmp * b'\x90', Action.PATCH)

                # 3. find block then/else
                jmp_ea = self.find_jmp(insn.ea)
                start_then = end_then = start_else = end_else = idaapi.BADADDR

                # find block then
                if not insn.cif.ielse and not self.is_break_statement(insn.cif.ithen):
                    start_then = idaapi.next_head(jmp_ea, idaapi.BADADDR)
                    end_then = self.get_end_block(insn.cif.ithen)
                else:
                    # find block then/else
                    if not self.is_break_statement(insn.cif.ithen):
                        start_then = self.get_start_block(insn.cif.ithen)
                        end_then = self.get_end_block(insn.cif.ithen)
                    if not self.is_break_statement(insn.cif.ielse):
                        start_else = self.get_start_block(insn.cif.ielse)
                        end_else = self.get_end_block(insn.cif.ielse)

                if start_then != idaapi.BADADDR and end_then != idaapi.BADADDR:
                    size_obfus = end_then - start_then
                    possible_region.append_obfu(start_ea=start_then, end_ea=end_then, obfus_size=size_obfus, comment='DeadIf Then', patch_bytes=size_obfus * b'\x90', action=Action.PATCH)

                if start_else != idaapi.BADADDR and end_else != idaapi.BADADDR:
                    size_obfus = end_else - start_else
                    possible_region.append_obfu(start_ea=start_else, end_ea=end_else, obfus_size=size_obfus, comment='DeadIf Else', patch_bytes=size_obfus * b'\x90', action=Action.PATCH)

                self.obfus_region.append(possible_region)

        return 0

class DeadIf(Deobfuscator):
    def __init__(self):
        super().__init__('DeadIf')
        self.description = 'Deadcode Condition'
        self.version = '1.0'

    def setup_ui(self):
        super().setup_ui()

        self.cmb_equation = QComboBox()
        self.cmb_equation.addItems(['>=', '>', '<', '<=', '=='])
        self.cmb_equation.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.ldt_condition = QLineEdit()
        self.layout_input = QHBoxLayout()
        self.layout_input.addWidget(self.cmb_equation)
        self.layout_input.addWidget(self.ldt_condition)
        self.layout_body.addLayout(self.layout_input)

    def scan(self, start_addr, end_addr):
        self.possible_obfuscation_regions.clear()

        equation = self.cmb_equation.currentText()
        condition = self.ldt_condition.text()

        if not ida_hexrays.init_hexrays_plugin():
            print("[Sharingan] Hex-Rays decompiler not available.")
            exit()
        f = idaapi.get_func(start_addr)
        if not f:
            print("[Sharingan] Please select a function.")
            exit()
        cfunc = ida_hexrays.decompile(f)
        if cfunc:
            print(f"\n[Sharingan] [v] ANALYSIS LOG FOR: {idaapi.get_func_name(f.start_ea)}")
            visitor = FinderCondition(f, self.possible_obfuscation_regions, equation, condition)
            visitor.apply_to(cfunc.body, None)
            print("[Sharingan] [v] Analysis Finished.")

        return self.possible_obfuscation_regions
