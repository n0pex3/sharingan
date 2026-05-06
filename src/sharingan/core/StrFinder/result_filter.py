import os
import re

import ida_diskio
import ida_funcs
import ida_nalt
import ida_typeinf
import idautils
from .ignore_store import IgnoreStringStore

# pVA, VA, 0VA, ..VA
FP_FILTER_PREFIX_1 = re.compile(r"^.{0,2}[0pP]?[]^\[_\\V]A")
# FP string ends
FP_FILTER_SUFFIX_1 = re.compile(r"[0pP]?[VWU][A@]$|Tp$")
# same printable ASCII char 4 or more consecutive times
FP_FILTER_REP_CHARS_1 = re.compile(r"([ -~])\1{3,}")
# same 4 printable ASCII chars 5 or more consecutive times
# /v7+/v7+/v7+/v7+
# ignore space and % for potential format strings, like %04d%02d%02d%02d%02d
FP_FILTER_REP_CHARS_2 = re.compile(r"([^% ]{4})\1{4,}")
# AaaAaAAaAAAaaAA-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
FP_FILTER_MINGW32 = re.compile(r"[aA]*-LIBGCCW32-.*-GTHR-MINGW32")
# aeriedjD#shasj
FP_FILTER_JUNK1 = re.compile(r"(aeriedjD#shasj)+")
# fatal error:
FP_FILTER_FATAL = re.compile(r".*fatal error: .*")
# lAll0Y
FP_FILTER_LALL = re.compile(r"^lAll")

MIN_LENGTH = 4

# API-like literal filter patterns
API_NAME_PATTERN = re.compile(r"^([A-Z][a-z0-9_]{1,63}){2,63}(Ex)?(W|A)?$")
API_PREFIXES = (
    "Global", "Local", "Display", "Find", "Heap", "Exit", "Process", "Path", "File", "Console", "Window", "Thread", "Process", "Thread", "Event", "Mutex", "Semaphore", "CriticalSection", "Timer", "Job",
    "Get", "Set", "Create", "Open", "Close", "Delete", "Enum", "Query", "Reg", "Crypt", "WinHttp", "Http", "Internet", "Url", "Shell", "SystemFunction", 
    "Char", "Str", "Rtl", "Ldr", "Nt", "Zw", "Tls", "Fls", "WSA", "Co", "Ole", "Device", "Virtual", "Map", "Unmap", "Read", "Write", "Duplicate",
    "MultiByte", "WideChar",
)

# be stricter removing FP strings for shorter strings
MAX_STRING_LENGTH_FILTER_STRICT = 6
# e.g. [ESC], [Alt], %d.dll
FP_FILTER_STRICT_INCLUDE = re.compile(r"^\[.*?]$|%[sd]")
# remove special characters
FP_FILTER_STRICT_SPECIAL_CHARS = re.compile(r"[^A-Za-z0-9.]")
FP_FILTER_STRICT_KNOWN_FP = re.compile(r"^O.*A$")

# ----------------------------------------------------------------------
# Filter Signature-based False Positives
# ----------------------------------------------------------------------
class SignatureFilter:
    def __init__(self) -> None:
        self._imports = set()
        self._lib_funcs = set()
        self._feed_symbols = set()
        self._feed_recognized = set()
        self._loader_patterns = []
        self.build_imports()
        self.build_library_functions()
        self.build_feed_symbols()
        self.build_feed_recognized()
        self.build_loader_context()

    def build_imports(self) -> None:
        try:
            qty = ida_nalt.get_import_module_qty()
            for i in range(qty):
                def _cb(ea, name, ordinal):
                    if name:
                        self._imports.add(name)
                        self._imports.add(name.lower())
                    return True
                ida_nalt.enum_import_names(i, _cb)
        except Exception as e:
            print(f"[Sharingan] Import enumeration failed: {e}")

    def build_library_functions(self) -> None:
        try:
            for f_ea in idautils.Functions():
                func = ida_funcs.get_func(f_ea)
                if not func:
                    continue
                if (func.flags & ida_funcs.FUNC_LIB) != 0:
                    name = ida_funcs.get_func_name(f_ea)
                    if name and len(name) >= 3:
                        self._lib_funcs.add(name)
                        self._lib_funcs.add(name.lower())
        except Exception as e:
            print(f"[Sharingan] Library function enumeration failed: {e}")

    def build_feed_symbols(self) -> None:
        verb_prefixes = (
            "Get", "Set", "Create", "Initialize", "Load", "Reg", "Crypt", "Find",
            "Open", "Close", "Delete", "Enum", "Query", "Fls", "WSA", "Tls",
            "Rtl", "Ldr", "Nt"
        )
        try:
            tils = []
            if hasattr(ida_typeinf, 'get_tils'):
                raw = ida_typeinf.get_tils()
                if raw:
                    tils.extend([t for t in raw if t])
            elif hasattr(ida_typeinf, 'get_til_qty') and hasattr(ida_typeinf, 'get_til'):
                qty = ida_typeinf.get_til_qty()
                for i in range(qty):
                    til = ida_typeinf.get_til(i)
                    if til:
                        tils.append(til)
            else:
                print("[Sharingan] Type library enumeration APIs not available; skipping Feeds symbols.")

            for til in tils:
                try:
                    if not hasattr(ida_typeinf, 'get_ordinal_qty') or not hasattr(ida_typeinf, 'get_ordinal_name'):
                        continue
                    ord_qty = ida_typeinf.get_ordinal_qty(til)
                    for ord in range(1, ord_qty + 1):
                        name = ida_typeinf.get_ordinal_name(til, ord)
                        if not name:
                            continue
                        if len(name) < 3 or len(name) > 64:
                            continue
                        if not any(name.startswith(p) for p in verb_prefixes):
                            continue
                        if name.lower() == name or name.upper() == name:
                            continue
                        self._feed_symbols.add(name)
                        self._feed_symbols.add(name.lower())
                except Exception:
                    continue
        except Exception as e:
            print(f"[Sharingan] Feed symbol enumeration fatal error: {e}")

        if not self._feed_symbols:
            synth_source = set()
            synth_source.update(self._imports)
            synth_source.update(self._lib_funcs)
            for name in synth_source:
                if not name or len(name) < 3 or len(name) > 64:
                    continue
                if name.lower() == name or name.upper() == name:
                    continue
                if not any(name.startswith(p) for p in verb_prefixes):
                    continue
                self._feed_symbols.add(name)
                self._feed_symbols.add(name.lower())
            if self._feed_symbols:
                print(f"[Sharingan] Feed fallback synthesized {len(self._feed_symbols)} symbols from imports/lib funcs.")

    def build_feed_recognized(self) -> None:
        try:
            for f_ea in idautils.Functions():
                fname = ida_funcs.get_func_name(f_ea)
                if not fname or len(fname) < 3:
                    continue
                low = fname.lower()
                if fname in self._feed_symbols or low in self._feed_symbols:
                    self._feed_recognized.add(fname)
                    self._feed_recognized.add(low)
        except Exception as e:
            print(f"[Sharingan] Feed recognized function collection failed: {e}")

    def build_loader_context(self) -> None:
        pattern_sources = [
            r"^LoadLibrary.*", r"^GetModuleHandle.*", r"^GetProcAddress.*", r"^MessageBox.*", r"^Fls.*",
            r"^(Add|Remove|Set)DllDirector.*", r"^FreeLibrary.*", r"^LoadPackagedLibrary$",
            r"^LoadLibraryShim$", r"^Rtl(GetProcAddress|PcToFileHeader).*$", r"^Ldr(GetDllHandle(ByName)?|GetProcedureAddress|LoadDll).*$",
            r"^lstr(cpy|cpyn|cmp|cmpi|cat|len)(W|A)$"
        ]
        compiled_patterns = [re.compile(p) for p in pattern_sources]
        try:
            self._loader_patterns = compiled_patterns
        except Exception:
            pass

    def is_known_function_literal(self, s: str) -> bool:
        if not s:
            return False
        ls = s.lower()
        if s in self._imports or ls in self._imports:
            return True
        if s in self._lib_funcs or ls in self._lib_funcs:
            return True
        if s in self._feed_symbols or ls in self._feed_symbols:
            return True
        if s in self._feed_recognized or ls in self._feed_recognized:
            return True
        if self.is_cxx_symbol_literal(s):
            return True
        return False

    def is_loader_api_literal(self, s: str) -> bool:
        if not s:
            return False
        for cp in self._loader_patterns:
            try:
                if cp.match(s):
                    return True
            except Exception:
                continue
        return False

    def _is_msvc_mangled(self, s: str) -> bool:
        return s.startswith('?') or s.startswith('??') or s.startswith('.?') or s.startswith('__')

    def _is_itanium_mangled(self, s: str) -> bool:
        return s.startswith('_Z')

    def _demangles(self, s: str) -> bool:
        try:
            dm = ida_typeinf.demangle_name(s, 0)
            return bool(dm)
        except Exception:
            return False

    def is_cxx_symbol_literal(self, s: str) -> bool:
        if not s:
            return False
        if self._is_msvc_mangled(s) or self._is_itanium_mangled(s):
            return True
        if self._demangles(s):
            return True
        if ('std::' in s) or ('operator' in s):
            return True
        ns_tokens = (
            'std::__cxx11::', 'std::__1::', 'std::__ndk1::', '__gnu_cxx::', 'std::pmr::'
        )
        if any(tok in s for tok in ns_tokens):
            return True
        keywords = (
            'string', 'wstring', 'u16string', 'u32string', 'string_view', 'basic_string',
            'istream', 'ostream', 'iostream', 'fstream', 'ifstream', 'ofstream',
            'stringstream', 'istringstream', 'ostringstream', 'basic_istream', 'basic_ostream', 'basic_iostream',
            'ios', 'ios_base', 'char_traits', 'codecvt',
            'vector', 'list', 'forward_list', 'deque', 'queue', 'priority_queue', 'stack',
            'map', 'multimap', 'set', 'multiset', 'unordered_map', 'unordered_set',
            'pair', 'tuple', 'optional', 'variant', 'any', 'bitset', 'span', 'valarray',
            'allocator', 'shared_ptr', 'unique_ptr', 'weak_ptr', 'enable_shared_from_this',
            'function', 'bind', 'placeholders', 'thread', 'jthread', 'mutex', 'recursive_mutex',
            'timed_mutex', 'shared_mutex', 'condition_variable', 'future', 'promise', 'packaged_task',
            'atomic', 'shared_lock', 'unique_lock', 'scoped_lock', 'barrier', 'latch',
            'counting_semaphore', 'binary_semaphore', 'stop_token', 'stop_source',
            'complex', 'random_device', 'mt19937', 'mt19937_64', 'uniform_int_distribution',
            'uniform_real_distribution', 'bernoulli_distribution', 'normal_distribution', 'chrono',
            'filesystem', 'path', 'locale', 'numpunct', 'num_put', 'num_get', 'ctype',
            'exception', 'bad_alloc', 'terminate', 'unexpected', 'type_info', 'typeinfo', 'type_index',
            'format', 'formatter', 'vformat', 'print', 'charconv', 'to_chars', 'from_chars',
            'ranges', 'views', 'mdspan', 'generator', 'coroutine', 'coroutine_handle',
            'suspend_always', 'suspend_never', 'source_location', 'expected'
        )
        if any(k in s for k in keywords):
            return True
        return False

class ResultFilter:
    def __init__(self):
        # Custom ignore list for known static tables
        self.ignore_file_path = ""
        self.ignore_literals = set()

        # Handle signature-based filtering
        self.sig_filter = SignatureFilter()
    
    def filter_results(self, strings_list, report):
        # If signature sources look empty on first call, rebuild after analysis
        try:
            if not (self.sig_filter._imports or self.sig_filter._lib_funcs or self.sig_filter._feed_symbols):
                self.sig_filter = SignatureFilter()
        except Exception:
            pass

        # Exclusion: skip known initialization / lookup tables
        report.log_message(f"Excluding known initialization / lookup tables, \n\t\tBefore: {len(strings_list)} strings")
        filtered = [s for s in strings_list if not self.is_init_exclude(s['value'])]
        report.log_message(f"\t\tAfter: {len(filtered)} strings")

        # Exclude FLOSS-style false positives (CRT errors, runtime messages, etc.)
        report.log_message(f"Excluding FLOSS-style false positives, \n\t\tBefore: {len(filtered)} strings")
        filtered = [s for s in filtered if not self.is_floss_fp(s['value'])]
        report.log_message(f"\t\tAfter: {len(filtered)} strings")
        
        # Exclude known function signature-like strings
        report.log_message(f"Excluding known function signature-like strings, \n\t\tBefore: {len(filtered)} strings")
        filtered = [s for s in filtered if not self.sig_filter.is_known_function_literal(s['value'])]
        report.log_message(f"\t\tAfter: {len(filtered)} strings")

        # Exclude dynamic loader API literals via direct name/pattern match
        report.log_message(f"Excluding dynamic loader API literals via direct name/pattern match, \n\t\tBefore: {len(filtered)} strings")
        filtered = [s for s in filtered if not self.sig_filter.is_loader_api_literal(s['value'])]
        report.log_message(f"\t\tAfter: {len(filtered)} strings")

        # Exclude API-like literals (WinAPI/RTL)
        report.log_message(f"Excluding API-like literals (WinAPI/RTL), \n\t\tBefore: {len(filtered)} strings")
        filtered = [s for s in filtered if not self.is_api_like_literal(s['value'])]
        report.log_message(f"\t\tAfter: {len(filtered)} strings")

        return filtered
    
    def is_floss_fp(self, s: str) -> bool:
        """Check if string matches FLOSS false positive patterns.
        
        Returns True if string should be filtered out as FP.
        """
        if not s:
            return False
        
        # Strip FP patterns and check if result is too short
        stripped = self.strip_string(s)
        if len(stripped) < MIN_LENGTH:
            return True
        
        # If stripped version is significantly shorter, it was mostly junk
        if len(stripped) < len(s) * 0.3:
            return True
        
        return False
    
    def strip_string(self, s: str) -> str:
        """Strip false positive pre/suffixes from string."""
        # Apply general FP pattern removal
        for fp in (
            FP_FILTER_PREFIX_1,
            FP_FILTER_SUFFIX_1,
            FP_FILTER_REP_CHARS_1,
            FP_FILTER_REP_CHARS_2,
            FP_FILTER_MINGW32,
            FP_FILTER_JUNK1,
            FP_FILTER_FATAL,
            FP_FILTER_LALL,
        ):
            ret = re.sub(fp, "", s)
        if len(ret) <= MAX_STRING_LENGTH_FILTER_STRICT:
            if not re.match(FP_FILTER_STRICT_INCLUDE, s):
                for fp in (FP_FILTER_STRICT_KNOWN_FP, FP_FILTER_STRICT_SPECIAL_CHARS):
                    ret = re.sub(fp, "", ret)
        return ret

    def is_init_exclude(self, s: str) -> bool:
        """idk, ignore some initial things"""
        if not s:
            return False

        # 1. Standard base64 tables
        base64_std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        if s == base64_std or s == base64_std + "=":
            return True

        # 2. Ignore list
        if s in self.ignore_literals:
            return True

        # 3. Monotonically increasing sequential ASCII (common init table pattern)
        if len(s) >= 32 and all(ord(s[i]) + 1 == ord(s[i+1]) for i in range(len(s) - 1)):
            return True

        # 4. Hex-only big-number constants (exclude if long and all hex chars)
        if len(s) in {20, 32, 48, 64, 128, 256} and all(c in '0123456789abcdefABCDEF' for c in s):
            return True
        
        # 5. Exclude .dll file names
        if s.lower().endswith('.dll') and all(c.isalnum() or c in ('_', '-') for c in s[:-4]):
            return True

        return False

    def is_api_like_literal(self, s: str) -> bool:
        """Heuristic filter for API-looking names to keep UI noise low."""
        if not s or len(s) < MIN_LENGTH or len(s) > 64:
            return False
        if any(s.startswith(pref) for pref in API_PREFIXES) and API_NAME_PATTERN.match(s):
            return True
        return False
