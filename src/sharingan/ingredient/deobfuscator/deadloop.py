from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, ida_bytes, idc, ida_hexrays
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action
from PySide6.QtWidgets import QLineEdit, QComboBox, QHBoxLayout, QLabel, QSizePolicy


# only support remove body loop, experiement currently
# for best result, remove the inside out
class BlockScanner(ida_hexrays.ctree_visitor_t):
    def __init__(self, flowchart):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.flowchart = flowchart
        self.matched_blocks = set()

    def add_block_from_ea(self, ea):
        if ea == idaapi.BADADDR:
            return
        for block in self.flowchart:
            if block.start_ea <= ea < block.end_ea:
                self.matched_blocks.add((block.start_ea, block.end_ea))
                break

    def visit_insn(self, i):
        if i.ea != idaapi.BADADDR:
            self.add_block_from_ea(i.ea)
        return 0

    def visit_expr(self, e):
        if e.ea != idaapi.BADADDR:
            self.add_block_from_ea(e.ea)
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
            loop_expr = loop_body = None

            if insn.op == ida_hexrays.cit_for:
                loop_expr = insn.cfor.expr
                loop_body = insn.cfor.body
            elif insn.op == ida_hexrays.cit_while:
                loop_expr = insn.cwhile.expr
                loop_body = insn.cwhile.body
            elif insn.op == ida_hexrays.cit_do:
                loop_expr = insn.cdo.expr
                loop_body = insn.cdo.body

            if loop_expr and loop_body:
                if self.check_numeric_logic(loop_expr):
                    print(f"[Sharingan] --- [DEAD LOOP] detected at {hex(insn.ea)} ---")

                    scanner = BlockScanner(self.flowchart)
                    scanner.apply_to(loop_body, None)

                    if not scanner.matched_blocks:
                        return 0

                    blocks = sorted(list(scanner.matched_blocks))
                    first_start, first_end = blocks[0]
                    size_first = first_end - first_start

                    possible_region = ObfuscatedRegion(
                        start_ea=first_start,
                        end_ea=first_end,
                        obfus_size=size_first,
                        comment='DeadLoop Block',
                        patch_bytes=size_first * b'\x90',
                        name='DeadLoop',
                        action=Action.PATCH
                    )

                    for i in range(1, len(blocks)):
                        b_start, b_end = blocks[i]
                        b_size = b_end - b_start
                        possible_region.append_obfu(
                            start_ea=b_start,
                            end_ea=b_end,
                            obfus_size=b_size,
                            comment='DeadLoop Block',
                            patch_bytes=b_size * b'\x90',
                            action=Action.PATCH
                        )

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
