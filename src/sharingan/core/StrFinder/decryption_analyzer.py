"""DecryptionFunctionAnalyzer (IDA 9.2)

Identify potential decryption functions by correlating functions that reference
multiple encrypted strings, and map all strings they access (direct & indirect).

Strictly uses modern ida_* APIs (no legacy idc calls).
"""

from typing import Dict, List, Set

import idautils
import ida_funcs
import ida_bytes
import ida_nalt
import ida_idaapi
import ida_ua


class DecryptionFunctionAnalyzer:
    """Analyzes functions that reference multiple encrypted strings to identify
    potential decryption routines, then finds all other strings they use.
    """

    def __init__(self, encrypted_strings: List[Dict]):
        """Args:
        - encrypted_strings: list of dicts from StringFinder
          Each: {'address': int, 'value': str, 'xrefs': List[int], 'xref_count': int, 'type': str}
        """
        self.encrypted_strings = encrypted_strings or []
        self.decryption_candidates: List[Dict] = []

    # ------------------------------------------------------------------
    def analyze(self, min_encrypted_refs: int = 3) -> List[Dict]:
        """Main analysis: find functions referencing multiple encrypted strings,
        then map all strings they access.

        Returns list of candidate dicts.
        """
        print(f"\n[Sharingan] === DECRYPTION FUNCTION ANALYSIS ===")
        print(f"[Sharingan] Threshold: Functions referencing >= {min_encrypted_refs} encrypted strings\n")

        func_to_encrypted = self._build_function_mapping()
        candidates = {
            f: refs for f, refs in func_to_encrypted.items() if len(refs) >= min_encrypted_refs
        }

        if not candidates:
            print(f"[Sharingan] No functions found with >= {min_encrypted_refs} encrypted string references")
            return []

        print(f"[Sharingan] Found {len(candidates)} potential decryption functions\n")

        results: List[Dict] = []
        for func_ea in sorted(candidates.keys()):
            result = self._analyze_function(func_ea, candidates[func_ea])
            if result:
                results.append(result)
                self._print_function_analysis(result)

        self.decryption_candidates = results
        return results

    # ------------------------------------------------------------------
    def _build_function_mapping(self) -> Dict[int, List[Dict]]:
        """Build mapping: function_address -> list of encrypted string refs it makes."""
        func_to_encrypted: Dict[int, List[Dict]] = {}
        for enc in self.encrypted_strings:
            for xref_ea in enc.get('xrefs', []) or []:
                func_ea = ida_funcs.get_func(xref_ea)
                if not func_ea:
                    continue
                func_start_ea = func_ea.start_ea
                if func_start_ea not in func_to_encrypted:
                    func_to_encrypted[func_start_ea] = []
                func_to_encrypted[func_start_ea].append({
                    'string_addr': enc['address'],
                    'string_value': enc.get('value', ''),
                    'xref_location': xref_ea,
                })
        return func_to_encrypted

    # ------------------------------------------------------------------
    def _analyze_function(self, func_ea: int, encrypted_refs: List[Dict]) -> Dict:
        name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:08X}"
        all_strings = self._find_all_string_refs(func_ea)
        enc_addrs: Set[int] = {e['string_addr'] for e in encrypted_refs}
        other_strings = [s for s in all_strings if s['address'] not in enc_addrs]

        return {
            'function_address': func_ea,
            'function_name': name,
            'encrypted_string_count': len(encrypted_refs),
            'encrypted_strings': encrypted_refs,
            'other_string_count': len(other_strings),
            'other_strings': other_strings,
            'total_string_refs': len(all_strings),
            'characteristics': self._identify_characteristics(func_ea),
        }

    # ------------------------------------------------------------------
    def _is_strlit(self, ea: int) -> bool:
        try:
            return ida_bytes.is_strlit(ida_bytes.get_full_flags(ea))
        except Exception:
            return False

    def _get_str_content(self, ea: int) -> str:
        try:
            t = 0
            try:
                t = ida_bytes.get_str_type(ea)
            except Exception:
                t = 0
            size = ida_bytes.get_item_size(ea)
            if size <= 0:
                size = 0x400
            b = ida_bytes.get_strlit_contents(ea, size, t)
            if b is None:
                return ''
            if isinstance(b, bytes):
                return b.decode('utf-8', errors='ignore')
            return str(b)
        except Exception:
            return ''

    def _ptr_at(self, ea: int) -> int:
        try:
            inf = ida_nalt.get_inf_structure()
            if inf.is_64bit():
                val = ida_bytes.get_qword(ea)
            else:
                val = ida_bytes.get_dword(ea)
            return val if val != ida_idaapi.BADADDR else ida_idaapi.BADADDR
        except Exception:
            return ida_idaapi.BADADDR

    def _find_all_string_refs(self, func_ea: int) -> List[Dict]:
        strings: List[Dict] = []
        seen: Set[int] = set()

        func = ida_funcs.get_func(func_ea)
        if not func:
            return strings

        for head in idautils.FuncItems(func_ea):
            # Direct data refs from instruction
            for dref in idautils.DataRefsFrom(head):
                if self._is_strlit(dref):
                    if dref not in seen:
                        seen.add(dref)
                        val = self._get_str_content(dref)
                        if val:
                            strings.append({
                                'address': dref,
                                'value': val,
                                'ref_location': head,
                                'ref_type': 'direct',
                            })
                else:
                    # Indirect via global: load from a global pointer to a string
                    ptr = self._ptr_at(dref)
                    if ptr and ptr != ida_idaapi.BADADDR and self._is_strlit(ptr):
                        if ptr not in seen:
                            seen.add(ptr)
                            val = self._get_str_content(ptr)
                            if val:
                                strings.append({
                                    'address': ptr,
                                    'value': val,
                                    'ref_location': head,
                                    'ref_type': 'indirect_via_global',
                                    'global_var': dref,
                                })
        return strings

    # ------------------------------------------------------------------
    def _identify_characteristics(self, func_ea: int) -> Dict:
        chars = {
            'has_loops': False,
            'has_xor': False,
            'has_shifts': False,
            'instruction_count': 0,
            'call_count': 0,
        }

        xor_count = 0
        shift_count = 0

        for head in idautils.FuncItems(func_ea):
            chars['instruction_count'] += 1

            mnem = (ida_ua.print_insn_mnem(head) or '').lower()

            if mnem == 'xor':
                op0 = ida_ua.print_operand(head, 0)
                op1 = ida_ua.print_operand(head, 1)
                if op0 and op1 and op0 != op1:
                    xor_count += 1

            if mnem in ('shl', 'shr', 'sal', 'sar', 'rol', 'ror'):
                shift_count += 1

            if mnem == 'call':
                chars['call_count'] += 1

            # Very simple loop/back-edge check
            for tgt in idautils.CodeRefsFrom(head, 0):
                if tgt < head:
                    chars['has_loops'] = True

        if xor_count >= 2:
            chars['has_xor'] = True
        if shift_count >= 2:
            chars['has_shifts'] = True

        return chars

    # ------------------------------------------------------------------
    def _print_function_analysis(self, result: Dict) -> None:
        print(f"[Sharingan] {'='*80}")
        print(f"Function: {result['function_name']}")
        print(f"Address: 0x{result['function_address']:08X}")
        print(f"{'='*80}")

        print("\n[Sharingan] Summary:")
        print(f"  Encrypted strings referenced: {result['encrypted_string_count']}")
        print(f"  Other strings accessed: {result['other_string_count']}")
        print(f"  Total string references: {result['total_string_refs']}")

        chars = result['characteristics']
        check = '✓'
        cross = '✗'
        print("\n[Sharingan] Characteristics:")
        print(f"  Instructions: {chars['instruction_count']}")
        print(f"  Calls: {chars['call_count']}")
        print(f"  Has XOR operations: {check if chars['has_xor'] else cross}")
        print(f"  Has bit shifts: {check if chars['has_shifts'] else cross}")
        print(f"  Likely has loops: {check if chars['has_loops'] else cross}")

        print("\nEncrypted strings:")
        for i, enc in enumerate(result['encrypted_strings'], 1):
            sval = (enc.get('string_value') or '')[:60]
            print(f"  {i}. 0x{enc['string_addr']:08X} = '{sval}'")
            print(f"     Referenced at: 0x{enc['xref_location']:08X}")

        if result['other_strings']:
            print("\n[Sharingan] Other strings accessed:")
            for i, other in enumerate(result['other_strings'], 1):
                ref_type = other.get('ref_type', 'unknown')
                sval = (other.get('value') or '')[:60]
                print(f"  {i}. 0x{other['address']:08X} = '{sval}'")
                print(f"     Type: {ref_type}, Referenced at: 0x{other['ref_location']:08X}")
                if 'global_var' in other:
                    print(f"     Via global: 0x{other['global_var']:08X}")
        else:
            print("\n[Sharingan] No other strings found (only encrypted strings)")
        print()
