from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, ida_bytes, idc, ida_hexrays
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action
from PySide6.QtWidgets import QLineEdit, QComboBox, QHBoxLayout, QLabel, QSizePolicy


class RangeScanner(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.eas = set()

    def visit_insn(self, i):
        if i.ea != idaapi.BADADDR: self.eas.add(i.ea)
        return 0

    def visit_expr(self, e):
        if e.ea != idaapi.BADADDR: self.eas.add(e.ea)
        return 0

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
        self.COT_NUM = 61  # cot_num

    def check_numeric_logic(self, expr):
        target_ops = self.op_map.get(self.equation, [])
        if expr.op not in target_ops:
            return False
        if expr.y.op == self.COT_NUM:
            code_val = expr.y.n._value
            if self.equation in ['>', '>=']:
                return code_val >= self.user_val
            elif self.equation in ['<', '<=']:
                return code_val <= self.user_val
            elif self.equation == '==':
                return code_val == self.user_val
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

    def visit_insn(self, insn):
        loop_insn = None
        if insn.op == ida_hexrays.cit_for:
            loop_insn = insn.cfor
            print(f'--- [FOR] at {hex(insn.ea)} ---')
        elif insn.op == ida_hexrays.cit_while:
            loop_insn = insn.cwhile
            print(f'--- [WHILE] at {hex(insn.ea)} ---')
        elif insn.op == ida_hexrays.cit_do:
            loop_insn = insn.cdo
            print(f'--- [DO_WHILE] at {hex(insn.ea)} ---')

        if loop_insn:
            if self.check_numeric_logic(loop_insn.expr):
            # if self.equation in cond and self.condition in cond:
                cond = self.get_expr_string(loop_insn.expr)
                print(f'   Condition: {cond}')

                start_loop_recursion = self.get_start_block(loop_insn.body)
                end_loop_recursion = self.get_end_block(loop_insn.body)

                scanner = RangeScanner()
                scanner.apply_to(loop_insn.body, None)
                start_loop_ctree = min(scanner.eas)
                end_loop_ctree = idc.get_item_end(max(scanner.eas))

                start_loop = min(start_loop_ctree, start_loop_recursion)
                end_loop = max(end_loop_ctree, end_loop_recursion)
                size_obfus = end_loop - start_loop
                possible_region = ObfuscatedRegion(start_ea = start_loop, end_ea = end_loop, obfus_size = size_obfus, comment = 'Expr Body', patch_bytes = size_obfus * b'\x90', name = 'DeadLoop', action = Action.PATCH)

                start_expr = self.get_start_block(loop_insn.expr)
                end_expr = self.get_end_block(loop_insn.expr)
                if not (start_loop <= start_expr < end_loop):
                    size_expr = end_expr - start_expr
                    possible_region.append_obfu(start_ea = start_expr, end_ea = end_expr, obfus_size = size_expr, comment = 'Expr Loop', patch_bytes = size_expr * b'\x90', action = Action.PATCH)

                self.obfus_region.append(possible_region)

        return 0

class DeadLoop(Deobfuscator):
    def __init__(self):
        super().__init__('DeadLoop')
        self.description = 'Deadcode Loop'
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
            print("Hex-Rays decompiler not available.")
            exit()

        f = idaapi.get_func(start_addr)
        if not f:
            print("Please select a function.")
            exit()
        cfunc = ida_hexrays.decompile(f)
        if cfunc:
            print(f"\n[v] ANALYSIS LOG FOR: {idaapi.get_func_name(f.start_ea)}")
            visitor = FinderCondition(f, self.possible_obfuscation_regions, equation, condition)
            visitor.apply_to(cfunc.body, None)
            print("[v] Analysis Finished.")

        return self.possible_obfuscation_regions
