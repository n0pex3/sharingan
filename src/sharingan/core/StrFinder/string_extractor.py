"""FLOSS String Extractor (IDA 9.2)

FLOSS-inspired comprehensive string extraction system.
Extracts strings missed by IDA's built-in detector through:
1. Static strings: Raw segment scanning for ASCII/Unicode runs
2. Stack strings: Monitor-based emulation tracking stack MOVs
3. Tight strings: Tight-loop emulation with pre-context filtering

Strictly uses modern ida_* APIs (no legacy idc calls).

References: 
    https://github.com/mandiant/flare-floss/blob/master/floss/stackstrings.py
    https://github.com/mandiant/flare-floss/blob/master/floss/tightstrings.py
"""

from typing import Any, List, Dict, Set, Optional, Iterator
from dataclasses import dataclass
import re
import os
import struct
import idaapi
import idautils
import ida_segment
import ida_bytes
import ida_funcs
import ida_ua
import ida_ida
import ida_nalt

try:
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_X86,
        UC_MODE_32,
        UC_MODE_64,
        UC_PROT_ALL,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
    )
    from unicorn.x86_const import (
        UC_X86_REG_ESP, 
        UC_X86_REG_EBP, 
        UC_X86_REG_EIP, 
        UC_X86_REG_RSP, 
        UC_X86_REG_RBP, 
        UC_X86_REG_RIP
    )
except Exception as e:
    print(f"[Sharingan] Unicorn not available: {e}")
    Uc = None
    UcError = Exception  # type: ignore

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

REPEATS = ["A", "\x00", "\xfe", "\xff", " ", "j"]
PRINTABLE_BYTES = {0x09, 0x0A, 0x0D} | set(range(0x20, 0x7F))
PUSH_PRINTABLE = set(range(0x20, 0x7F))
FUZZY_MAX_NONPRINTABLE = int(os.getenv('ESF_FUZZY_MAX_BAD', '2'))
FUZZY_MIN_RATIO = float(os.getenv('ESF_FUZZY_MIN_RATIO', '0.75'))

MIN_LENGTH = 4
MAX_LENGTH = 2048
MAX_STACK_SIZE = 0x10000
MIN_NUMBER_OF_MOVS = 5  # FLOSS heuristic
EMU_STACK_BASE = 0x70000000
EMU_STACK_SIZE = 0x10000
EMU_MAX_INSNS = int(os.getenv('ESF_EMU_MAX_INSNS', '5000'))
TIGHT_LOOP_MAX_SPAN = int(os.getenv('ESF_TIGHT_LOOP_MAX_SPAN', '512'))
TIGHT_LOOP_MAX_INSN = int(os.getenv('ESF_TIGHT_LOOP_MAX_INSN', '64'))
DEBUG_EMU = os.getenv('DEBUG_ESF_EMU', '0') == '1'


@dataclass
class CallContext:
    """FLOSS-style context snapshot for string extraction."""
    pc: int
    sp: int
    init_sp: int
    stack_memory: bytes
    pre_ctx_strings: Optional[Set[str]] = None


class FLOSSStringExtractor:
    """Comprehensive string extraction beyond IDA's default detection."""
    def __init__(self, min_length: int = MIN_LENGTH):
        self.min_length = min_length
        self.stack_reg_names = {'sp', 'esp', 'rsp', 'bp', 'ebp', 'rbp'}
        
    # ------------------------------------------------------------------
    # Static String Extraction (raw segment scan)
    # ------------------------------------------------------------------
    def extract_static_strings(self) -> Iterator[Dict]:
        """Scan ALL segments"""
        seen_addrs: Set[int] = set()

        for s in idautils.Strings():
            val = str(s)
            if not self._is_no_loop(val): 
                continue
            if s.ea in seen_addrs: 
                continue

            seen_addrs.add(s.ea)
            xrefs = list(idautils.DataRefsTo(s.ea))
            yield {
                'value': val,
                'address': s.ea,
                'type': 'static',
                'xrefs': xrefs,
                'xref_count': len(xrefs)
            }
        
        rsrc_seg = None
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg: 
                continue
            name = ida_segment.get_segm_name(seg) or f"SEG_{seg.start_ea:08X}"
            if name == '.rsrc':
                rsrc_seg = seg
            yield from self._scan_segment(seg, name, seen_addrs)

        if not rsrc_seg:
            for item in self._extract_other_seg('.rsrc', seen_addrs):
                addr = item['address']
                if addr in seen_addrs:
                    continue
                seen_addrs.add(addr)
                yield item

    def _scan_segment(self, seg, name: str, seen_addrs: Set[int]) -> Iterator[Dict]:
        """Raw scan a mapped segment for ASCII/Unicode strings."""
        start, end = seg.start_ea, seg.end_ea
        size = end - start
        if size <= 0:
            return
        try:
            data = ida_bytes.get_bytes(start, size)
        except Exception:
            return
        yield from self.extract_ascii_unicode(data, start, name, seen_addrs, type_prefix='static')
    
    def _extract_other_seg(self, seg: str, seen_addrs: Set[int]) -> Iterator[Dict]:
        """Parse PE section table from original file to strings."""
        try:
            path = ida_nalt.get_input_file_path()
            if not path or not os.path.exists(path):
                return
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) < 0x100:
                return
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            if e_lfanew + 0x100 > len(data):
                return
            if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return
            file_hdr_off = e_lfanew + 4
            num_sections = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
            size_opt_hdr = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
            opt_hdr_off = file_hdr_off + 20
            sect_tbl_off = opt_hdr_off + size_opt_hdr
            seg_raw = None
            seg_va = 0
            for i in range(num_sections):
                sh_off = sect_tbl_off + i * 40
                if sh_off + 40 > len(data):
                    break
                name = data[sh_off:sh_off+8].rstrip(b'\x00')
                virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, sh_off + 8)
                if name == seg.encode():
                    if raw_ptr + raw_size <= len(data):
                        seg_raw = data[raw_ptr:raw_ptr+raw_size]
                        seg_va = virt_addr
                    break
            if not seg_raw:
                return
            
            # Extract ASCII and Unicode strings
            yield from self.extract_ascii_unicode(seg_raw, seg_va, seg, seen_addrs, type_prefix='static')

        except Exception as e:
            print(f"[Sharingan] Disk .rsrc parse failed: {e}")

    # ------------------------------------------------------------------
    # Stack String Extraction
    # ------------------------------------------------------------------
    def extract_stack_strings(self) -> Iterator[Dict]:
        """Extract stack strings."""
        if Uc is None:
            print("[Sharingan] Unicorn not available; skipping stack strings.")
            return

        bb_ends = self._get_basic_block_ends()
        for f_ea in idautils.Functions():
            func_ea = ida_funcs.get_func(f_ea)
            if not func_ea:
                continue
            func_name = ida_funcs.get_func_name(f_ea)
            seen: Set[str] = set()
            for ctx in self._extract_call_contexts(func_ea, bb_ends):
                for val, encoding in self.extract_strings_from_stack(ctx.stack_memory, seen):
                    frame_offset = (ctx.init_sp - ctx.sp) - len(val)
                    yield {
                        'address': ctx.pc,
                        'value': val,
                        'type': 'stack-string',
                        'encoding': encoding,
                        'function': func_name,
                        'function_ea': f_ea,
                        'stack_pointer': ctx.sp,
                        'original_stack_pointer': ctx.init_sp,
                        'frame_offset': frame_offset,
                        'xrefs': [f_ea],
                        'xref_count': 1,
                    }
                    seen.add(val)

    def _get_basic_block_ends(self) -> Set[int]:
        """Return set of VAs that are last instructions of basic blocks."""
        index = set()
        for func_ea in idautils.Functions():
            try:
                flow = idautils.FlowChart(ida_funcs.get_func(func_ea))
                for bb in flow:
                    if bb.start_ea < bb.end_ea:
                        last_ea = ida_bytes.prev_head(bb.end_ea, bb.start_ea)
                        if last_ea != idaapi.BADADDR:
                            index.add(last_ea)
            except Exception:
                continue
        return index

    def _extract_call_contexts(self, func_ea, bb_ends: Set[int]) -> Iterator[CallContext]:
        """Emulate function and capture contexts at call sites and BB ends with stack MOVs."""
        ctxs: List[CallContext] = []
        is_64 = ida_ida.inf_is_64bit()
        
        try:
            mu = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
            stack_top = EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000
            mu.mem_map(EMU_STACK_BASE, EMU_STACK_SIZE, UC_PROT_ALL)
            if is_64:
                mu.reg_write(UC_X86_REG_RSP, stack_top)
                mu.reg_write(UC_X86_REG_RBP, stack_top)
                sp_reg = UC_X86_REG_RSP
                ip_reg = UC_X86_REG_RIP
            else:
                mu.reg_write(UC_X86_REG_ESP, stack_top)
                mu.reg_write(UC_X86_REG_EBP, stack_top)
                sp_reg = UC_X86_REG_ESP
                ip_reg = UC_X86_REG_EIP
            init_sp = stack_top
        except Exception as exc:
            print(f"[Sharingan] Unicorn setup failed for function {hex(func_ea.start_ea)}: {exc}")
            return

        # Map segments
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            seg_start, seg_end = self._align_down(seg.start_ea), self._align_up(seg.end_ea)
            seg_size = seg_end - seg_start
            if seg_size <= 0:
                continue
            try:
                bytes_seg = ida_bytes.get_bytes(seg_start, seg_size) or b""
                try:
                    mu.mem_map(seg_start, seg_size, UC_PROT_ALL)
                except UcError:
                    try:
                        mu.mem_protect(seg_start, seg_size, UC_PROT_ALL)
                    except Exception:
                        continue
                if bytes_seg:
                    try:
                        mu.mem_write(seg_start, bytes_seg)
                    except Exception:
                        pass
            except Exception:
                continue

        # Monitor state
        mov_count = 0
        insn_budget = EMU_MAX_INSNS

        def get_context(pc: int) -> Optional[CallContext]:
            try:
                sp = mu.reg_read(sp_reg)
                stack_size = init_sp - sp
                if stack_size <= 0 or stack_size > MAX_STACK_SIZE:
                    return None
                stack_buf = mu.mem_read(sp, stack_size)
                return CallContext(pc, sp, init_sp, stack_buf)
            except Exception:
                return None

        def hook_code(uc, address, size, user_data):
            nonlocal mov_count, insn_budget
            insn_budget -= 1
            if insn_budget <= 0:
                uc.emu_stop()
                return
            
            try:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, address) <= 0:
                    return
                mnem = insn.get_canon_mnem().lower()
                
                # Skip calls/jumps
                if mnem.startswith("call") or mnem.startswith("jmp"):
                    uc.reg_write(ip_reg, address + size)
                    # Capture context at call site
                    ctx = get_context(address)
                    if ctx:
                        ctxs.append(ctx)
                    return
                
                # Count stack MOVs
                if mnem.startswith("mov") and self._is_stack_mov(insn):
                    mov_count += 1
                
                # Capture at BB end if enough MOVs
                if address in bb_ends and mov_count >= MIN_NUMBER_OF_MOVS:
                    ctx = get_context(address)
                    if ctx:
                        ctxs.append(ctx)
                    mov_count = 0
                elif address in bb_ends:
                    mov_count = 0
            except Exception:
                return

        def hook_unmapped(uc, access, address, size, value, user_data):
            # Stop gracefully on unmapped memory access
            if DEBUG_EMU:
                access_type = "read" if access == 16 else "write" if access == 17 else "fetch"
                print(f"[ESF] Unmapped {access_type} at {hex(address)} in {hex(func_ea.start_ea)}")
            uc.emu_stop()
            return False

        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

        try:
            mu.emu_start(func_ea.start_ea, func_ea.end_ea, count=EMU_MAX_INSNS)
        except UcError as exc:
            if DEBUG_EMU:
                print(f"[ESF] Emulation ended for {hex(func_ea.start_ea)}: {exc}")

        yield from ctxs

    def _is_stack_mov(self, insn) -> bool:
        """Check if instruction is MOV to stack."""
        ops = insn.ops
        if not ops or ops[0].type not in (ida_ua.o_displ, ida_ua.o_phrase):
            return False
        base_reg = getattr(ops[0], 'reg', -1)
        if base_reg == -1:
            return False
        reg_name = ida_ua.get_reg_name(base_reg, insn.get_canon_feature()).lower()
        return reg_name in self.stack_reg_names

    # ------------------------------------------------------------------
    # Tight String Extraction
    # ------------------------------------------------------------------
    def extract_tight_strings(self) -> Iterator[Dict]:
        """Extract tight strings using FLOSS tight-loop pattern."""
        if Uc is None:
            print("[Sharingan] Unicorn not available; tight strings limited to push-immediate detection.")
            # push-immediate collection only
            for f_ea in idautils.Functions():
                func_ea = ida_funcs.get_func(f_ea)
                if not func_ea:
                    continue
                func_name = ida_funcs.get_func_name(f_ea)
                for ea, text in self._collect_push_strings(func_ea):
                    if not self._is_no_loop(text):
                        continue
                    yield {
                        'address': ea,
                        'value': text,
                        'type': 'tight-string-push',
                        'encoding': 'push-immediate',
                        'function': func_name,
                        'function_ea': f_ea,
                        'xrefs': [f_ea],
                        'xref_count': 1,
                    }
            return

        # Full FLOSS tight-loop emulation
        tightloop_functions = self._identify_tightloop_functions()
        for func_ea, tloops in tightloop_functions.items():
            func_name = ida_funcs.get_func_name(func_ea)
            for tloop in tloops:
                for ctx in self._extract_tightstring_contexts(func_ea, tloop):
                    for val, encoding in self.extract_strings_from_stack(ctx.stack_memory, ctx.pre_ctx_strings or set()):
                        frame_offset = (ctx.init_sp - ctx.sp) - len(val)
                        yield {
                            'address': ctx.pc,
                            'value': val,
                            'type': 'tight-string',
                            'encoding': encoding,
                            'function': func_name,
                            'function_ea': func_ea,
                            'stack_pointer': ctx.sp,
                            'original_stack_pointer': ctx.init_sp,
                            'frame_offset': frame_offset,
                            'loop_start': tloop['start'],
                            'loop_end': tloop['end'],
                            'xrefs': [func_ea],
                            'xref_count': 1,
                        }

    def _identify_tightloop_functions(self) -> Dict[int, List[Dict]]:
        """Identify functions containing tight loops (backward branches)."""
        tightloop_funcs: Dict[int, List[Dict]] = {}
        for f_ea in idautils.Functions():
            func_ea = ida_funcs.get_func(f_ea)
            if not func_ea:
                continue
            loops = []
            for head in idautils.FuncItems(f_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                    continue
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) <= 0:
                    continue
                mnem = insn.get_canon_mnem().lower()
                if not (mnem.startswith('j') or mnem in ('loop', 'loope', 'loopne')):
                    continue
                target = self._get_branch_target(insn)
                if target == idaapi.BADADDR or target >= head:
                    continue
                if target < func_ea.start_ea or target >= func_ea.end_ea:
                    continue
                span = head - target
                if span <= 0 or span > TIGHT_LOOP_MAX_SPAN:
                    continue
                insn_count = self._count_instructions_between(target, head)
                if insn_count == 0 or insn_count > TIGHT_LOOP_MAX_INSN:
                    continue
                loops.append({
                    'start': target,
                    'end': head,
                    'span': span,
                    'insn_count': insn_count,
                })
            if loops:
                tightloop_funcs[f_ea] = loops
        return tightloop_funcs

    def _extract_tightstring_contexts(self, func_ea: int, tloop: Dict) -> Iterator[CallContext]:
        """Emulate to loop start, capture pre-context, then emulate through loop."""
        is_64 = ida_ida.inf_is_64bit()
        try:
            mu = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
            stack_top = EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000
            mu.mem_map(EMU_STACK_BASE, EMU_STACK_SIZE, UC_PROT_ALL)
            if is_64:
                mu.reg_write(UC_X86_REG_RSP, stack_top)
                mu.reg_write(UC_X86_REG_RBP, stack_top)
                sp_reg = UC_X86_REG_RSP
                ip_reg = UC_X86_REG_RIP
            else:
                mu.reg_write(UC_X86_REG_ESP, stack_top)
                mu.reg_write(UC_X86_REG_EBP, stack_top)
                sp_reg = UC_X86_REG_ESP
                ip_reg = UC_X86_REG_EIP
            init_sp = stack_top
        except Exception:
            return

        # Map segments
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            seg_start, seg_end = self._align_down(seg.start_ea), self._align_up(seg.end_ea)
            seg_size = seg_end - seg_start
            if seg_size <= 0:
                continue
            try:
                bytes_seg = ida_bytes.get_bytes(seg_start, seg_size) or b""
                try:
                    mu.mem_map(seg_start, seg_size, UC_PROT_ALL)
                except UcError:
                    try:
                        mu.mem_protect(seg_start, seg_size, UC_PROT_ALL)
                    except Exception:
                        continue
                if bytes_seg:
                    try:
                        mu.mem_write(seg_start, bytes_seg)
                    except Exception:
                        pass
            except Exception:
                continue

        insn_budget = EMU_MAX_INSNS

        def hook_code(uc, address, size, user_data):
            nonlocal insn_budget
            insn_budget -= 1
            if insn_budget <= 0:
                uc.emu_stop()
                return
            try:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, address) > 0:
                    mnem = insn.get_canon_mnem().lower()
                    if mnem.startswith("call") or mnem.startswith("jmp"):
                        uc.reg_write(ip_reg, address + size)
            except Exception:
                return

        def hook_unmapped(uc, access, address, size, value, user_data):
            # Stop gracefully on unmapped memory
            uc.emu_stop()
            return False

        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

        # Step 1: Emulate to loop start and capture pre-context
        try:
            mu.emu_start(func_ea, tloop['start'], count=EMU_MAX_INSNS // 2)
        except UcError:
            pass

        pre_ctx_strings: Set[str] = set()
        try:
            sp = mu.reg_read(sp_reg)
            stack_size = init_sp - sp
            if 0 < stack_size <= MAX_STACK_SIZE:
                stack_buf = mu.mem_read(sp, stack_size)
                for val, _ in self.extract_strings_from_stack(stack_buf, set()):
                    pre_ctx_strings.add(val)
        except Exception:
            pass

        # Step 2: Emulate through tight loop
        insn_budget = EMU_MAX_INSNS // 2
        try:
            mu.emu_start(tloop['start'], tloop['end'] + 16, count=EMU_MAX_INSNS // 2)
        except UcError:
            pass

        # Step 3: Capture final context
        try:
            sp = mu.reg_read(sp_reg)
            stack_size = init_sp - sp
            if 0 < stack_size <= MAX_STACK_SIZE:
                stack_buf = mu.mem_read(sp, stack_size)
                yield CallContext(tloop['start'], sp, init_sp, stack_buf, pre_ctx_strings)
        except Exception:
            pass

    def _collect_push_strings(self, func_ea) -> Iterator[tuple]:
        """Collect push-immediate string sequences (non-emulated fallback)."""
        current: List[int] = []
        seq_start = None
        last_ea = None

        def flush():
            nonlocal current, seq_start
            if seq_start is None:
                current.clear()
                return None
            if len(current) >= self.min_length:
                try:
                    text = bytes(current).decode("ascii", errors="ignore")
                except Exception:
                    text = ""
                if text:
                    result = (seq_start, text)
                    current = []
                    seq_start = None
                    return result
            current = []
            seq_start = None
            return None

        for head in idautils.FuncItems(func_ea.start_ea):
            if head < func_ea.start_ea or head >= func_ea.end_ea:
                continue
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) <= 0:
                result = flush()
                if result:
                    yield result
                continue
            if ida_ua.print_insn_mnem(head).lower() != "push":
                result = flush()
                if result:
                    yield result
                continue
            op = insn.ops[0]
            if op.type != ida_ua.o_imm:
                result = flush()
                if result:
                    yield result
                continue
            width = self._op_width(op)
            try:
                raw = (op.value & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
            except Exception:
                result = flush()
                if result:
                    yield result
                continue

            chunk: List[int] = []
            for b in raw:
                if b == 0:
                    break
                if b not in PUSH_PRINTABLE:
                    chunk = []
                    break
                chunk.append(b)
            if not chunk:
                result = flush()
                if result:
                    yield result
                continue

            if seq_start is None:
                seq_start = head
            if last_ea is not None and head - last_ea > 16:
                result = flush()
                if result:
                    yield result
                seq_start = head
            current.extend(chunk)
            last_ea = head

        result = flush()
        if result:
            yield result

    def _count_instructions_between(self, start_ea: int, end_ea: int) -> int:
        """Count code instructions between two addresses."""
        count = 0
        for head in idautils.Heads(start_ea, end_ea + 1):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                count += 1
                if count > TIGHT_LOOP_MAX_INSN:
                    break
        return count

    def _get_branch_target(self, insn) -> int:
        """Best-effort branch target resolution."""
        for op in insn.ops:
            if op.type in (ida_ua.o_near, ida_ua.o_far):
                return op.addr
        return idaapi.BADADDR

    # ------------------------------------------------------------------
    # ASCII and Unicode String Extraction
    # ------------------------------------------------------------------
    def extract_ascii_unicode(self, data: bytes, base_addr: int, name: str, seen_addrs: Set[int], type_prefix: str) -> Iterator[Dict]:
        """ 
        Extract ASCII and Unicode strings from raw byte data using pattern matching.
        Args:
            data: Raw bytes to search
            base_addr: Base address offset for calculating absolute addresses
            name: Context name (e.g., segment name, 'rsrc', 'disk')
            seen_addrs: Set of already-seen addresses to avoid duplicates
            type_prefix: Prefix for the 'type' field (e.g., 'static', 'rsrc')
        Returns:
            Iterator of string dictionaries with metadata
        """
        ascii_pat = re.compile(rb'([%s]{%d,})' % (ASCII_BYTE, self.min_length))
        unicode_pat = re.compile(rb'((?:[%s]\x00){%d,})' % (ASCII_BYTE, self.min_length))
        
        # Extract ASCII strings
        for match in ascii_pat.finditer(data):
            addr = base_addr + match.start()
            if addr in seen_addrs: 
                continue
            try:
                val = match.group().decode('ascii')
            except Exception:
                continue
            if not self._is_no_loop(val):
                continue

            seen_addrs.add(addr)
            xrefs = list(idautils.DataRefsTo(addr))
            yield {
                'address': addr,
                'value': val,
                'type': f"ascii-{type_prefix}",
                'segment': name,
                'encoding': 'ascii',
                'xrefs': xrefs,
                'xref_count': len(xrefs)
            }
        
        # Extract Unicode strings
        for match in unicode_pat.finditer(data):
            addr = base_addr + match.start()
            if addr in seen_addrs:
                continue
            try:
                val = match.group().decode('utf-16le')
            except Exception:
                continue
            if not self._is_no_loop(val):
                continue

            seen_addrs.add(addr)
            xrefs = list(idautils.DataRefsTo(addr))
            yield {
                'address': addr,
                'value': val,
                'type': f"unicode-{type_prefix}",
                'segment': name,
                'encoding': 'utf-16le',
                'xrefs': xrefs,
                'xref_count': len(xrefs)
            }

    def _is_no_loop(self, s: str) -> bool:
        """Filter garbage strings"""
        if not s or len(s) > MAX_LENGTH: 
            return False
        if any(s == c * len(s) for c in REPEATS):
            return False
        
        printable = sum(1 for c in s if c.isprintable())
        ratio = printable / len(s)
        if ratio < 0.7:
            return False
        
        alnum = sum(1 for c in s if c.isalnum())
        if alnum < min(3, len(s) // 2):
            return False
        
        return True

    def extract_strings_from_stack(self, stack_buf: bytes, exclude: Set[str]) -> Iterator[tuple]:
        """Extract strings from stack buffer, excluding already-seen strings."""
        ascii_pat = re.compile(rb'([%s]{%d,})' % (ASCII_BYTE, self.min_length))
        uni_pat = re.compile(rb'((?:[%s]\x00){%d,})' % (ASCII_BYTE, self.min_length))
        
        for m in ascii_pat.finditer(stack_buf):
            try:
                val = m.group().decode('ascii')
            except Exception:
                continue
            if val and self._is_no_loop(val) and val not in exclude:
                yield (val, 'ascii')
        
        for m in uni_pat.finditer(stack_buf):
            try:
                val = m.group().decode('utf-16le')
            except Exception:
                continue
            if val and self._is_no_loop(val) and val not in exclude:
                yield (val, 'utf-16le')

    @staticmethod
    def _op_width(op) -> int:
        dt = getattr(op, "dtype", getattr(op, "dtyp", None))
        width = ida_ua.get_dtype_size(dt) if dt is not None else 0
        if width <= 0:
            width = 8 if ida_ida.inf_is_64bit() else 4
        return width

    @staticmethod
    def _align_down(value: int, alignment: int = 0x1000) -> int:
        return value & ~(alignment - 1)

    @staticmethod
    def _align_up(value: int, alignment: int = 0x1000) -> int:
        return (value + alignment - 1) & ~(alignment - 1)
