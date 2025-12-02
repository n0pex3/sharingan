"""FLOSS String Extractor (IDA 9.2)

FLOSS-inspired comprehensive string extraction system.
Extracts strings missed by IDA's built-in detector through:
1. Static strings: Raw segment scanning for ASCII/Unicode runs
2. Stack strings: Functions building strings via stack operations
3. Tight strings: Sequences of immediate byte pushes forming ASCII

Strictly uses modern ida_* APIs (no legacy idc calls).

References: 
    https://github.com/mandiant/flare-floss/blob/master/floss/strings.py
"""

from typing import List, Dict, Set, Optional
from collections import Counter
import re
import os
import struct
import idautils
import ida_segment
import ida_bytes
import ida_funcs
import ida_ua
import ida_idaapi
import ida_nalt
import contextlib

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
REPEATS = ["A", "\x00", "\xfe", "\xff", " "]
PRINTABLE_BYTES = {0x09, 0x0A, 0x0D} | set(range(0x20, 0x7F))
FUZZY_MAX_NONPRINTABLE = int(os.getenv('ESF_FUZZY_MAX_BAD', '2'))
FUZZY_MIN_RATIO = float(os.getenv('ESF_FUZZY_MIN_RATIO', '0.75'))

MIN_LENGTH = 4
MAX_LENGTH = 2048
SLICE_SIZE = 4096
TIGHT_LOOP_MAX_SPAN = int(os.getenv('ESF_TIGHT_LOOP_MAX_SPAN', '512'))
TIGHT_LOOP_MAX_INSN = int(os.getenv('ESF_TIGHT_LOOP_MAX_INSN', '64'))
TIGHT_LOOP_PRELUDE_BYTES = int(os.getenv('ESF_TIGHT_LOOP_PRELUDE', '64'))
TIGHT_LOOP_MAX_GAP = int(os.getenv('ESF_TIGHT_LOOP_MAX_GAP', '16'))

class FLOSSStringExtractor:
    """Comprehensive string extraction beyond IDA's default detection."""
    def __init__(self, min_length: int = MIN_LENGTH):
        self.min_length = min_length
        self._stack_reg_names = {'sp', 'esp', 'rsp', 'bp', 'ebp', 'rbp'}
        self._debug_stack = os.getenv('DEBUG_ESF_STACK', '0') == '1'
        
    # ------------------------------------------------------------------
    # Static String Extraction (raw segment scan)
    # ------------------------------------------------------------------
    def extract_static_strings(self) -> List[Dict]:
        """Scan ALL segments for ASCII/Unicode strings IDA didn't recognize.
        
        Returns list of dicts: {'address': int, 'value': str, 'type': str, 'encoding': str}
        """
        ret: List[Dict] = []
        seen_addrs: Set[int] = set()

        # Enumerate mapped segments
        segments: List[tuple] = []
        rsrc_seg = None
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            name = ida_segment.get_segm_name(seg) or f"SEG_{seg.start_ea:08X}"
            segments.append((seg, name))
            if name.lower().strip('.') == 'rsrc':
                rsrc_seg = seg

        # for seg, name in segments:
        #     ret.extend(self._scan_segment_for_strings(seg, name, seen_addrs))
            # ret.extend(self._scan_fuzzy_ascii_sequences(seg, name, seen_addrs))

        # Disk-based .rsrc fallback if not mapped
        if not rsrc_seg:
            disk_rsrc = self.extract_rsrc_from_disk()
            if disk_rsrc:
                for item in disk_rsrc:
                    addr = item['address']
                    if addr in seen_addrs:
                        continue
                    seen_addrs.add(addr)
                    ret.append(item)

        # Add IDA-recognized strings themselves
        for s in idautils.Strings():
            val = str(s)
            if self._is_no_loop(val):
                if s.ea in seen_addrs:
                    continue
                seen_addrs.add(s.ea)
                # Get where this string is used
                xrefs = self._collect_xrefs(s.ea)
                ret.append({
                    'value': val,
                    'address': s.ea,
                    'type': 'static',
                    'xrefs': xrefs,
                    'xref_count': len(xrefs)
                })

        return ret

    def _scan_segment_for_strings(self, seg, name: str, seen_addrs: Set[int]) -> List[Dict]:
        """Raw scan a mapped segment for ASCII/Unicode strings."""
        results: List[Dict] = []
        start = seg.start_ea
        end = seg.end_ea
        size = end - start
        if size <= 0:
            return results
        try:
            data = ida_bytes.get_bytes(start, size)
        except Exception:
            data = None
        if not data:
            return results

        seg_type = 'segment'
        
        ascii_pat = re.compile(rb'([%s]{%d,})' % (ASCII_BYTE, self.min_length,))
        for match in ascii_pat.finditer(data):
            addr = start + match.start()
            if addr in seen_addrs:
                continue
            try:
                val = match.group().decode('ascii')
            except Exception:
                continue
            if not self._is_no_loop(val):
                continue
            seen_addrs.add(addr)
            xrefs = self._collect_xrefs(addr)
            results.append({
                'address': addr,
                'value': val,
                'type': f'{seg_type}-ascii',
                'segment': name,
                'encoding': 'ascii',
                'xrefs': xrefs,
                'xref_count': len(xrefs)
            })

        unicode_pat = re.compile(rb'((?:[%s]\x00){%d,})' % (ASCII_BYTE, self.min_length))
        for match in unicode_pat.finditer(data):
            addr = start + match.start()
            if addr in seen_addrs:
                continue
            try:
                val = match.group().decode('utf-16le')
            except Exception:
                continue
            if not self._is_no_loop(val):
                continue
            seen_addrs.add(addr)
            xrefs = self._collect_xrefs(addr)
            results.append({
                'address': addr,
                'value': val,
                'type': f'{seg_type}-unicode',
                'segment': name,
                'encoding': 'utf-16le',
                'xrefs': xrefs,
                'xref_count': len(xrefs)
            })

        return results

    def _scan_fuzzy_ascii_sequences(self, seg, name: str, seen_addrs: Set[int]) -> List[Dict]:
        """Detect mostly printable sequences that contain a few junk bytes."""
        results: List[Dict] = []
        if FUZZY_MAX_NONPRINTABLE <= 0:
            return results
        start = seg.start_ea
        end = seg.end_ea
        size = end - start
        if size <= 0:
            return results
        try:
            data = ida_bytes.get_bytes(start, size)
        except Exception:
            return results
        if not data:
            return results

        idx = 0
        limit = len(data)
        while idx < limit:
            if data[idx] not in PRINTABLE_BYTES:
                idx += 1
                continue
            run_start = idx
            run = bytearray()
            non_printables = 0
            while idx < limit:
                byte = data[idx]
                if byte in PRINTABLE_BYTES:
                    run.append(byte)
                    idx += 1
                    continue
                if non_printables < FUZZY_MAX_NONPRINTABLE and byte not in (0x00,):
                    run.append(byte)
                    non_printables += 1
                    idx += 1
                    continue
                break
            if len(run) >= self.min_length:
                printable = sum(1 for b in run if b in PRINTABLE_BYTES)
                ratio = printable / len(run)
                if non_printables > 0 and ratio >= FUZZY_MIN_RATIO:
                    addr = start + run_start
                    if addr not in seen_addrs:
                        value = run.decode('latin-1', errors='ignore')
                        if self._is_no_loop(value):
                            seen_addrs.add(addr)
                            xrefs = self._collect_xrefs(addr)
                            results.append({
                                'address': addr,
                                'value': value,
                                'raw_bytes': run.hex(),
                                'type': 'segment-hybrid-ascii',
                                'segment': name,
                                'encoding': 'mixed',
                                'xrefs': xrefs,
                                'xref_count': len(xrefs)
                            })
            idx = run_start + 1
        return results

    def _collect_xrefs(self, ea: int) -> List[int]:
        try:
            return list(idautils.DataRefsTo(ea))
        except Exception:
            return []

    def extract_rsrc_from_disk(self) -> List[Dict]:
        """Fallback: parse PE section table from original file to harvest .rsrc strings.

        Only used if IDA did not map .rsrc. Performs lightweight PE header walk:
        - DOS header: e_lfanew at 0x3C
        - NT headers: signature + FILE header + OPTIONAL header
        - Section table: iterate names, locate '.rsrc'
        Extract raw section data and apply loose ASCII / UTF-16LE scans.
        Addresses use BADADDR because section is not mapped; consumers should treat 'type' field to differentiate origin.
        """
        ret = []
        try:
            path = ida_nalt.get_input_file_path()
            if not path or not os.path.exists(path):
                return ret
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) < 0x100:
                return ret
            # DOS header
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            if e_lfanew + 0x100 > len(data):
                return ret
            # PE signature
            if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return ret
            # File header
            file_hdr_off = e_lfanew + 4
            num_sections = struct.unpack_from('<H', data, file_hdr_off + 2)[0]
            size_opt_hdr = struct.unpack_from('<H', data, file_hdr_off + 16)[0]
            opt_hdr_off = file_hdr_off + 20
            sect_tbl_off = opt_hdr_off + size_opt_hdr
            # Iterate section headers (40 bytes each)
            rsrc_raw = None
            rsrc_va = 0
            for i in range(num_sections):
                sh_off = sect_tbl_off + i * 40
                if sh_off + 40 > len(data):
                    break
                name = data[sh_off:sh_off+8].rstrip(b'\x00')
                virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, sh_off + 8)
                if name == b'.rsrc':
                    if raw_ptr + raw_size <= len(data):
                        rsrc_raw = data[raw_ptr:raw_ptr+raw_size]
                        rsrc_va = virt_addr
                    break
            if not rsrc_raw:
                return ret
            
            # Scan .rsrc
            ascii_pat = re.compile(rb'([%s]{%d,})' % (ASCII_BYTE, self.min_length))
            uni_pat = re.compile(rb'((?:[%s]\x00){%d,})' % (ASCII_BYTE, self.min_length))
            for m in ascii_pat.finditer(rsrc_raw):
                try:
                    val = m.group().decode('ascii')
                    if self._is_no_loop(val):
                        ret.append({
                            'address': rsrc_va + m.start(), 
                            'value': val, 
                            'type': 'rsrc-ascii',
                            'encoding': 'ascii', 
                            'xrefs': [], 
                            'xref_count': 0
                        })
                except Exception:
                    pass
            for m in uni_pat.finditer(rsrc_raw):
                try:
                    val = m.group().decode('utf-16le')
                    if self._is_no_loop(val):
                        ret.append({
                            'address': rsrc_va + m.start(), 
                            'value': val, 
                            'type': 'rsrc-unicode',
                            'encoding': 'utf-16le',
                            'xrefs': [], 
                            'xref_count': 0
                        })
                except Exception:
                    pass
        except Exception as e:
            if os.getenv('DEBUG_ESF_SEGMENTS'):
                print(f"[ESF] Disk .rsrc parse failed: {e}")
        return ret

    def _is_no_loop(self, s: str) -> bool:
        """Filter out garbage strings (too many nulls, control chars, etc.)."""
        if not s or len(s) > MAX_LENGTH:
            return False
        
        # Filter out repetitive strings (e.g., "AAAA...", "\x00\x00...")
        if any(s == c * len(s) for c in REPEATS):
            return False
        
        # Count printable vs non-printable
        printable = sum(1 for c in s if c.isprintable())
        ratio = printable / len(s)
        
        # Must be mostly printable
        if ratio < 0.7:
            return False
        
        # Must have some alphanumeric content
        alnum = sum(1 for c in s if c.isalnum())
        if alnum < min(3, len(s) // 2):
            return False
        
        return True
    
    # ------------------------------------------------------------------
    # Upgraded: FLOSS-style Stack String Extraction via Snapshots
    # ------------------------------------------------------------------
    def extract_stack_strings(self) -> List[Dict]:
        """
        Upgraded snapshot-based stack string detection per function, inspired by FLOSS.
        At basic block end (if enough stack writes) or CALL, snapshot stack as bytearray, scan ASCII/Unicode.
        Deduplicate, filter, and report with metadata.
        """
        MOV_THRESH = int(os.getenv('ESF_MIN_MOVS') or 5)
        FRAME_LIMIT = 0x10000
        results = []

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            results.extend(self._simulate_function_for_stack(func_ea, MOV_THRESH, FRAME_LIMIT))
        return results

    def _get_basic_block_end_addrs(self, func_ea: int) -> Set[int]:
        """Return set of instruction EA that are last in a basic block for func."""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return set()
        try:
            flow = idautils.FlowChart(func)
            return {bb.end_ea - ida_ua.get_item_size(bb.end_ea - 1) for bb in flow}
        except Exception:
            return set()

    def _simulate_function_for_stack(self, func_ea: int, mov_threshold: int, frame_limit: int) -> List[Dict]:
        """
        Advanced: Also support bulk/SIMD memory writes for robust string/buffer catching.
        Returns: list[dict] (with metadata)
        """
        ascii_pat = re.compile(rb'([%s]{%d,})' % (ASCII_BYTE, self.min_length,))
        uni_pat = re.compile(rb'((?:[%s]\x00){%d,})' % (ASCII_BYTE, self.min_length,))
        results = []
        seen = set()  # (value,function_ea)
        bb_end_eas = self._get_basic_block_end_addrs(func_ea)

        frame_map = dict()    # offset -> (byte, inst_ea)
        xmm_state = {}        # reg idx -> bytes currently in given xmm (only from immediate/mem moves w/ clear content)
        register_state = {}   # reg idx -> bytes (little-endian order)
        movs_in_bb = 0
        orig_sp = 0
        sp = orig_sp
        func_items = list(idautils.FuncItems(func_ea))

        for idx, ea in enumerate(func_items):
            try:
                insn = ida_ua.insn_t()
                inslen = ida_ua.decode_insn(insn, ea)
                mnem = insn.get_canon_mnem().lower()

                # MOV [stack], imm
                if mnem == 'mov':
                    op_dst = insn.ops[0]
                    op_src = insn.ops[1]
                    # mem write from immediate
                    print('0', ida_ua.decode_insn(insn, ea), hex(ea), op_dst.type, hex(op_dst.addr),  op_src.type, hex(op_src.value))
                    # ida_ua.o_displ == 4: displacement - Memory Ref (Base + Index + Disp) - mov dword ptr [esi+24h], 0Fh
                    # ida_ua.o_phrase == 3: phrase - Memory Ref (Base + Index) - mov dword ptr [esi], offset unk_401020
                    if op_dst.type in (ida_ua.o_displ, ida_ua.o_phrase) and op_src.type == ida_ua.o_imm:
                        print('==> stack, imm', 'op_dst.type', op_dst.type, ida_ua.o_displ, ida_ua.o_phrase)
                        #print('stack, imm', ida_ua.decode_insn(insn, ea), hex(ea), hex(op_dst.addr), hex(op_src.value))
                        base_off = self._resolve_stack_offset(op_dst, insn)
                        if base_off is None:
                            continue
                        width = self._dtype_size(op_dst.dtyp, default=1)
                        data = self._int_to_little_bytes(op_src.value, width)
                        if data:
                            self._write_stack_bytes(frame_map, base_off, data, ea, frame_limit)
                            movs_in_bb += 1
                        continue
                    
                    # mem write from known register
                    if op_dst.type in (ida_ua.o_displ, ida_ua.o_phrase) and op_src.type == ida_ua.o_reg:
                        base_off = self._resolve_stack_offset(op_dst, insn)
                        if base_off is None:
                            continue
                        reg_bytes = register_state.get(op_src.reg)
                        if not reg_bytes:
                            continue
                        width = self._dtype_size(op_dst.dtyp, default=len(reg_bytes))
                        data = reg_bytes[:width]
                        if data:
                            self._write_stack_bytes(frame_map, base_off, data, ea, frame_limit)
                            movs_in_bb += 1
                        continue
                    
                    # Track register assignments
                    if op_dst.type == ida_ua.o_reg:
                        if op_src.type == ida_ua.o_imm:
                            width = self._dtype_size(op_dst.dtyp, default=ida_idaapi.get_inf_structure().ptrsize)
                            buf = self._int_to_little_bytes(op_src.value, width)
                            if buf:
                                register_state[op_dst.reg] = buf
                                continue
                        elif op_src.type == ida_ua.o_reg:
                            buf = register_state.get(op_src.reg)
                            if buf:
                                register_state[op_dst.reg] = buf
                            else:
                                register_state.pop(op_dst.reg, None)
                            continue
                        else:
                            register_state.pop(op_dst.reg, None)
                        continue
                    
                    if op_dst.type == ida_ua.o_mem and self._debug_stack:
                        print('[ESF stack] skipping absolute mem write',
                              ida_ua.decode_insn(insn, ea), hex(ea))

                # SIMD: MOVAPS/MOVUPS/MOVDQA/MOVDQU [mem], XMMx   or   MOVAPS/MOVUPS/MOVDQA/MOVDQU XMMx, [mem]
                # Intel, usually Arg 0: dst,  Arg 1: src
                if mnem in ('movaps','movups','movdqa','movdqu'):
                    d0 = insn.ops[0]
                    d1 = insn.ops[1]
                    # Write FROM xmm to MEM
                    print('1', ida_ua.decode_insn(insn, ea), hex(ea), hex(d0.addr), hex(d1.reg))
                    if (d0.type in (ida_ua.o_displ, ida_ua.o_phrase)) and d1.type == ida_ua.o_reg and d1.reg >= ida_ua.XMM0 and d1.reg <= ida_ua.XMM15:
                        reg_name = ida_ua.get_reg_name(d1.reg, insn.get_canon_feature())
                        buf = xmm_state.get(d1.reg)
                        # Only simulate if our reg has a known value
                        if isinstance(buf, (bytes, bytearray)):
                            base_off = self._resolve_stack_offset(d0, insn)
                            if base_off is None:
                                continue
                            for i in range(min(len(buf), 16)):
                                this_off = base_off + i
                                if abs(this_off) >= frame_limit:
                                    continue
                                frame_map[this_off] = (buf[i], ea)
                            movs_in_bb += 1
                        continue

                    # Read TO xmm from MEM (simulate only if from const memory)
                    if d0.type == ida_ua.o_reg and d0.reg >= ida_ua.XMM0 and d0.reg <= ida_ua.XMM15 and (d1.type == ida_ua.o_mem or d1.type == ida_ua.o_displ):
                        # Try static memory dump
                        print('2', ida_ua.decode_insn(insn, ea), hex(ea), hex(d0.reg), hex(d1.addr))
                        memea = d1.addr
                        width = 16 # XMM is always 16 bytes
                        if self._debug_stack:
                            print('[ESF stack] SIMD load',
                                  ida_ua.decode_insn(insn, ea), hex(ea), hex(memea),
                                  ida_ua.get_reg_name(d0.reg, insn.get_canon_feature()))
                        try:
                            buf = ida_bytes.get_bytes(memea, width)
                        except Exception:
                            buf = None
                        if buf and len(buf) == 16:
                            xmm_state[d0.reg] = buf
                        else:
                            xmm_state[d0.reg] = None
                        continue

            except Exception:
                continue

            # Triggers as before
            triggers_snapshot = False
            if ea in bb_end_eas and movs_in_bb >= mov_threshold:
                triggers_snapshot = True
            elif mnem == 'call':
                triggers_snapshot = True

            if triggers_snapshot:
                if not frame_map:
                    movs_in_bb = 0
                    continue
                min_o = min(frame_map.keys())
                max_o = max(frame_map.keys()) + 1
                arr = bytearray([frame_map[o][0] if o in frame_map else 0 for o in range(min_o, max_o)])
                byte_to_off = [o for o in range(min_o, max_o)]

                for m in ascii_pat.finditer(arr):
                    s = m.group().decode('ascii', errors='ignore')
                    if not self._is_no_loop(s): continue
                    start = m.start(); off = byte_to_off[start]
                    meta = frame_map.get(off)
                    meta_ea = meta[1] if meta else None
                    valsig = (s, func_ea)
                    if valsig in seen: continue
                    seen.add(valsig)
                    results.append({
                        'function_ea': func_ea,
                        'pc': meta_ea,
                        'stack_pointer': sp,
                        'original_stack_pointer': orig_sp,
                        'offset': off,
                        'frame_offset': off,
                        'encoding': 'ascii',
                        'value': s,
                        'type': 'stack-string',
                        'function': ida_funcs.get_func_name(func_ea),
                    })
                for m in uni_pat.finditer(arr):
                    try:
                        s = m.group().decode('utf-16le', errors='ignore')
                    except Exception:
                        continue
                    if not self._is_no_loop(s): continue
                    start = m.start(); off = byte_to_off[start]
                    meta = frame_map.get(off)
                    meta_ea = meta[1] if meta else None
                    valsig = (s, func_ea)
                    if valsig in seen: continue
                    seen.add(valsig)
                    results.append({
                        'function_ea': func_ea,
                        'pc': meta_ea,
                        'stack_pointer': sp,
                        'original_stack_pointer': orig_sp,
                        'offset': off,
                        'frame_offset': off,
                        'encoding': 'utf-16le',
                        'value': s,
                        'type': 'stack-string',
                        'function': ida_funcs.get_func_name(func_ea),
                    })
                movs_in_bb = 0

        return results
    
    def _resolve_stack_offset(self, op, insn) -> Optional[int]:
        """Return stack frame offset for operand if it references stack memory."""
        base_reg = getattr(op, 'reg', -1)
        if base_reg == -1:
            return None
        reg_name = ida_ua.get_reg_name(base_reg, insn.get_canon_feature()).lower()
        if reg_name not in self._stack_reg_names:
            return None

        # Reject complex addressing with index registers to avoid false offsets
        if getattr(op, 'specflag1', 0):
            idx = getattr(op, 'index', -1)
            if idx != -1:
                return None

        displacement = getattr(op, 'addr', 0)
        return displacement
    
    # ------------------------------------------------------------------
    # Tight String Extraction
    # ------------------------------------------------------------------
    def extract_tight_strings(self) -> List[Dict]:
        """Detect push-immediate based tight strings near tight loops.

        This mirrors the FLOSS philosophy:
        - locate compact backward branches ("tight loops")
        - capture sequences of push immediates that seed stack buffers
        - keep sequences that originate inside or immediately before those loops
        """
        results: List[Dict] = []
        seen: Set[tuple] = set()
        
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue
            loops = self._locate_tight_loops(func_ea)
            if not loops:
                continue
            sequences = self._collect_push_sequences(func_ea, loops)
            if not sequences:
                continue
            func_name = ida_funcs.get_func_name(func_ea)
            for seq in sequences:
                key = (seq['start'], seq['value'])
                if key in seen:
                    continue
                seen.add(key)
                loop_meta = seq['loop']
                results.append({
                    'address': seq['start'],
                    'end_address': seq['end'],
                    'value': seq['value'],
                    'length': len(seq['value']),
                    'type': 'tight-string',
                    'encoding': 'push-immediate',
                    'function': func_name,
                    'function_ea': func_ea,
                    'loop_start': loop_meta['start'],
                    'loop_end': loop_meta['end'],
                    'loop_span': loop_meta['span'],
                    'loop_relation': loop_meta['relation'],
                    'loop_insn_count': loop_meta['insn_count'],
                    'xrefs': [func_ea],
                })
        return results
    
    def _collect_push_sequences(self, func_ea: int, loops: List[Dict]) -> List[Dict]:
        """Collect sequences of push immediates aligned with tight loops."""
        sequences: List[Dict] = []
        current_bytes: List[int] = []
        seq_start = None
        seq_end = None
        last_ea = None
        loop_hits: List[tuple] = []
        
        def flush():
            nonlocal current_bytes, seq_start, seq_end, loop_hits, last_ea
            if current_bytes and len(current_bytes) >= self.min_length:
                try:
                    value = bytes(current_bytes).decode('ascii', errors='ignore')
                except Exception:
                    value = ''
                if value and self._is_no_loop(value):
                    loop_choice = self._select_loop(loop_hits, loops)
                    if loop_choice:
                        loop_meta, relation = loop_choice
                        sequences.append({
                            'start': seq_start,
                            'end': seq_end,
                            'value': value,
                            'loop': {
                                'start': loop_meta['start'],
                                'end': loop_meta['end'],
                                'span': loop_meta['span'],
                                'insn_count': loop_meta['insn_count'],
                                'relation': relation,
                            }
                        })
            current_bytes = []
            seq_start = None
            seq_end = None
            loop_hits = []
            last_ea = None
        
        for head in idautils.FuncItems(func_ea):
            try:
                if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                    continue
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) <= 0:
                    continue
                chunk = self._extract_push_bytes(insn)
                if chunk:
                    if seq_start is None:
                        seq_start = head
                    if last_ea is not None and head - last_ea > TIGHT_LOOP_MAX_GAP:
                        flush()
                        seq_start = head
                    current_bytes.extend(chunk)
                    seq_end = head
                    last_ea = head
                    hit = self._match_loop_region(head, loops)
                    if hit:
                        loop_hits.append(hit)
                    continue
                flush()
            except Exception:
                flush()
        flush()
        return sequences
    
    def _locate_tight_loops(self, func_ea: int) -> List[Dict]:
        """Return metadata about backward branches that look like tight loops."""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return []
        loops: List[Dict] = []
        for head in idautils.FuncItems(func_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                continue
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) <= 0:
                continue
            mnem = insn.get_canon_mnem().lower()
            if not (mnem.startswith('j') or mnem in ('loop', 'loope', 'loopne')):
                continue
            target = self._get_branch_target(insn)
            if target == ida_idaapi.BADADDR:
                continue
            if target >= head or target < func.start_ea or target >= func.end_ea:
                continue
            span = head - target
            if span <= 0 or span > TIGHT_LOOP_MAX_SPAN:
                continue
            insn_count = self._count_instructions_between(target, head)
            if insn_count == 0 or insn_count > TIGHT_LOOP_MAX_INSN:
                continue
            loops.append({
                'id': len(loops),
                'start': target,
                'end': head,
                'branch': head,
                'span': span,
                'insn_count': insn_count,
                'prelude_start': max(func.start_ea, target - TIGHT_LOOP_PRELUDE_BYTES),
            })
        return loops
    
    def _count_instructions_between(self, start_ea: int, end_ea: int) -> int:
        """Count code instructions between two addresses (inclusive)."""
        count = 0
        for head in idautils.Heads(start_ea, end_ea + 1):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                count += 1
                if count > TIGHT_LOOP_MAX_INSN:
                    break
        return count
    
    def _match_loop_region(self, ea: int, loops: List[Dict]) -> Optional[tuple]:
        """Return (loop_id, relation) if EA is inside or near a loop."""
        for loop in loops:
            if loop['start'] <= ea <= loop['end']:
                return (loop['id'], 'inside')
            if loop['prelude_start'] <= ea < loop['start']:
                return (loop['id'], 'prelude')
        return None
    
    def _select_loop(self, hits: List[tuple], loops: List[Dict]) -> Optional[tuple]:
        """Pick the dominant loop for a sequence."""
        if not hits:
            return None
        score = Counter()
        relation_count = Counter()
        for loop_id, relation in hits:
            weight = 2 if relation == 'inside' else 1
            score[loop_id] += weight
            relation_count[(loop_id, relation)] += 1
        loop_id, _ = score.most_common(1)[0]
        inside_votes = relation_count.get((loop_id, 'inside'), 0)
        prelude_votes = relation_count.get((loop_id, 'prelude'), 0)
        relation = 'inside' if inside_votes >= prelude_votes else 'prelude'
        return loops[loop_id], relation
    
    def _extract_push_bytes(self, insn) -> Optional[List[int]]:
        """Return printable bytes pushed by this instruction, if any."""
        if insn.get_canon_mnem().lower() != 'push':
            return None
        op = insn.ops[0]
        if op.type != ida_ua.o_imm:
            return None
        width = ida_ua.get_dtype_size(op.dtyp)
        if width <= 0:
            width = ida_idaapi.get_inf_structure().ptrsize
        mask = (1 << (width * 8)) - 1
        val = op.value & mask
        try:
            raw = val.to_bytes(width, byteorder='little', signed=False)
        except OverflowError:
            return None
        chunk = []
        for b in raw:
            if b == 0:
                break
            if b < 0x20 or b > 0x7E:
                return None
            chunk.append(b)
        return chunk or None
    
    def _get_branch_target(self, insn) -> int:
        """Best-effort branch target resolution for conditional/backward jumps."""
        for op in insn.ops:
            if op.type in (ida_ua.o_near, ida_ua.o_far):
                return op.addr
        return ida_idaapi.BADADDR

    def _dtype_size(self, dtyp: int, default: int = 1) -> int:
        """Helper to get operand width with sane fallback."""
        size = ida_ua.get_dtype_size(dtyp)
        if size and size > 0:
            return size
        return default
    
    def _int_to_little_bytes(self, value: int, width: int) -> Optional[bytes]:
        """Convert an integer to little-endian bytes with width guard."""
        if width <= 0:
            return None
        mask = (1 << (width * 8)) - 1
        try:
            return (value & mask).to_bytes(width, byteorder='little', signed=False)
        except OverflowError:
            return None
    
    def _write_stack_bytes(self, frame_map: Dict[int, tuple], base_off: int,
                            data: bytes, ea: int, frame_limit: int) -> None:
        """Write byte buffer into simulated stack frame."""
        for idx, byte in enumerate(data):
            off = base_off + idx
            if abs(off) >= frame_limit:
                continue
            frame_map[off] = (byte, ea)
