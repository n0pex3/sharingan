from sharingan.base.ingredient import Deobfuscator
from sharingan.core.utils import DeobfuscateUtils
import idaapi, idc, ida_hexrays
from sharingan.base.obfuscatedregion import ObfuscatedRegion, Action
from PySide6.QtWidgets import QLineEdit, QComboBox, QHBoxLayout, QSizePolicy


# scan basic blocks containing the addresses visited within a ctree subtree
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


# detect for / while / do-while loops, optionally filtered by a numeric condition,
# then NOP only the loop control flow (header condition + back-edge) and keep the body
class FinderCondition(ida_hexrays.ctree_visitor_t):
    def __init__(self, func, obfus_region, equation, user_val):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.flowchart = idaapi.FlowChart(func)
        self.obfus_region = obfus_region
        self.equation = equation
        # empty input => no filter, accept any loop
        self.user_val = None if user_val in (None, '') else int(user_val, 0)

        self.op_map = {
            '==': [22],                     # cot_eq
            '!=': [23],                     # cot_ne
            '>':  [28, 29],                 # cot_sgt, cot_ugt
            '>=': [24, 25],                 # cot_sge, cot_uge
            '<':  [30, 31],                 # cot_slt, cot_ult
            '<=': [26, 27]                  # cot_sle, cot_ule
        }
        self.COT_NUM = 61  # cot_num

    def check_numeric_logic(self, expr):
        # no filter -> match every loop
        if self.user_val is None:
            return True

        if not expr:
            return False

        # compound condition: recurse into both sides, match if either sub-condition matches
        if expr.op in [ida_hexrays.cot_land, ida_hexrays.cot_lor]:
            return self.check_numeric_logic(expr.x) or self.check_numeric_logic(expr.y)

        target_ops = self.op_map.get(self.equation, [])
        if expr.op not in target_ops:
            return False

        # constant on the right: var OP const  (normal form)
        if expr.y is not None and expr.y.op == self.COT_NUM:
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

    # find unconditional jmp at end of each body block that targets the loop header
    def find_back_edges(self, loop_body, header_start):
        body_scanner = BlockScanner(self.flowchart)
        body_scanner.apply_to(loop_body, None)

        back_edges = []
        for blk_start, blk_end in body_scanner.matched_blocks:
            last_ea = idaapi.prev_head(blk_end, blk_start)
            if last_ea == idaapi.BADADDR:
                continue
            if idc.print_insn_mnem(last_ea).lower() != 'jmp':
                continue
            target = idc.get_operand_value(last_ea, 0)
            if target == header_start:
                length = idaapi.get_item_size(last_ea)
                back_edges.append((last_ea, last_ea + length))
        return back_edges

    def collect_patch_ranges(self, insn, loop_expr, loop_body):
        if loop_expr is None or loop_expr.ea == idaapi.BADADDR:
            return []
        header_start, header_end = self.get_boundary_block(loop_expr.ea)
        if header_start is None:
            return []

        patches = []
        if insn.op in (ida_hexrays.cit_while, ida_hexrays.cit_for):
            # NOP entire header block (cmp + jcc-out-of-loop)
            patches.append((header_start, header_end))
            # NOP unconditional back-edge inside body
            patches.extend(self.find_back_edges(loop_body, header_start))
        elif insn.op == ida_hexrays.cit_do:
            # do-while: condition (cmp + jcc back) lives at the bottom of body block
            # NOP from cmp through end of its block -> body falls through
            patches.append((loop_expr.ea, header_end))
        return sorted(set(patches))

    def emit_region(self, patches, anchor_ea):
        first_start, first_end = patches[0]
        size_first = first_end - first_start
        region = ObfuscatedRegion(
            start_ea=first_start, end_ea=first_end, obfus_size=size_first,
            comment='DeadLoop Condition', patch_bytes=size_first * b'\x90',
            name='DeadLoop', action=Action.PATCH
        )
        for s, e in patches[1:]:
            sz = e - s
            region.append_obfu(
                start_ea=s, end_ea=e, obfus_size=sz,
                comment='DeadLoop Condition', patch_bytes=sz * b'\x90',
                action=Action.PATCH
            )
        self.obfus_region.append(region)
        print(f"[Sharingan] --- [DEAD LOOP] flatten at {hex(anchor_ea)} ---")

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
        else:
            return 0

        if loop_body is None:
            return 0
        if not self.check_numeric_logic(loop_expr):
            return 0

        patches = self.collect_patch_ranges(insn, loop_expr, loop_body)
        if not patches:
            return 0

        self.emit_region(patches, insn.ea)
        return 0


class DeadLoop(Deobfuscator):
    def __init__(self):
        super().__init__('DeadLoop')
        self.description = 'Deadcode Loop'
        self.version = '1.0'

    def setup_ui(self):
        super().setup_ui()

        self.cmb_equation = QComboBox()
        self.cmb_equation.addItems(['>=', '>', '<', '<=', '==', '!='])
        self.cmb_equation.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.ldt_condition = QLineEdit()
        self.ldt_condition.setPlaceholderText('Empty = all loops')
        self.layout_input = QHBoxLayout()
        self.layout_input.addWidget(self.cmb_equation)
        self.layout_input.addWidget(self.ldt_condition)
        self.layout_body.addLayout(self.layout_input)

    def scan(self, start_addr, end_addr):
        self.possible_obfuscation_regions.clear()

        equation = self.cmb_equation.currentText()
        condition = self.ldt_condition.text().strip()

        if not ida_hexrays.init_hexrays_plugin():
            print("[Sharingan] Hex-Rays decompiler not available.")
            return

        f = idaapi.get_func(start_addr)
        if not f:
            print("[Sharingan] Please select a function.")
            return

        cfunc = ida_hexrays.decompile(f)
        if cfunc:
            label = f"filter {equation} {condition}" if condition else "all loops"
            print(f"\n[Sharingan] [v] ANALYSIS LOG FOR: {idaapi.get_func_name(f.start_ea)} ({label})")
            visitor = FinderCondition(f, self.possible_obfuscation_regions, equation, condition or None)
            visitor.apply_to(cfunc.body, None)
            print("[Sharingan] [v] Analysis Finished.")

        return self.possible_obfuscation_regions
