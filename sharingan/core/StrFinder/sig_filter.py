"""SignatureFilter (IDA 9.2)

Use IDA's own knowledge (FLIRT, imports, Feeds) instead of parsing .sig files.

This collects:
- Import table function names
- FLIRT-recognized library functions (FUNC_LIB)
- Type-library (Feeds) symbols filtered by API-like prefixes
- Functions whose names match feed symbols (recognized by type libraries)
- Dynamic loader API names/patterns (GetProcAddress/LoadLibrary/Ldr*/Rtl*) for direct literal exclusion.

APIs:
- is_known_function_literal(s: str) -> bool
- is_loader_api_literal(s: str) -> bool
"""

from typing import List  # retained for backward compat; may be removed later
import re
import ida_funcs
import ida_nalt
import ida_typeinf
import idautils


class SignatureFilter:
    def __init__(self) -> None:
        self._imports = set()
        self._lib_funcs = set()
        self._feed_symbols = set()
        self._feed_recognized = set()
        self._loader_patterns = []
        self._api_prefixes = (
            "Get", "Set", "Create", "Close", "Load", "Free", "Reg", "Crypt",
            "Http", "WinHttp", "Delete", "Find"
        )
        self._build_imports()
        self._build_library_functions()
        self._build_feed_symbols()
        self._build_feed_recognized()
        self._build_loader_context()

    # ------------------------------------------------------------------
    def _build_imports(self) -> None:
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

    def _build_library_functions(self) -> None:
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

    def _build_feed_symbols(self) -> None:
        # Include dynamic-loader-adjacent families to improve coverage
        verb_prefixes = (
            "Get", "Set", "Create", "Initialize", "Load", "Reg", "Crypt", "Find",
            "Open", "Close", "Delete", "Enum", "Query", "Fls", "WSA", "Tls",
            "Rtl", "Ldr", "Nt"
        )
        try:
            # older builds get_til_qty/get_til
            # newer builds get_tils()
            tils = []
            if hasattr(ida_typeinf, 'get_tils'):
                # get_tils() may return list/tuple of til objects
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

        # If no feed symbols gathered, synthesize from imports & lib funcs
        if not self._feed_symbols:
            synth_source = set()
            synth_source.update(self._imports)
            synth_source.update(self._lib_funcs)
            for name in synth_source:
                if not name or len(name) < 3 or len(name) > 64:
                    continue
                # Mixed case typical of APIs
                if name.lower() == name or name.upper() == name:
                    continue
                if not any(name.startswith(p) for p in verb_prefixes):
                    continue
                self._feed_symbols.add(name)
                self._feed_symbols.add(name.lower())
            if self._feed_symbols:
                print(f"[Sharingan] Feed fallback synthesized {len(self._feed_symbols)} symbols from imports/lib funcs.")

    def _build_feed_recognized(self) -> None:
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

    def _build_loader_context(self) -> None:
        """Build only loader API literal name/pattern sets for direct exclusion.
        Case-sensitive names to avoid over-filtering generic identifiers.
        """
        pattern_sources = [
            r"^LoadLibrary.*", r"^GetModuleHandle.*", r"^GetProcAddress.*", r"^MessageBox.*", r"^Fls.*", 
            r"^(Add|Remove|Set)DllDirector.*", r"^FreeLibrary.*", r"^LoadPackagedLibrary$",
            r"^LoadLibraryShim$", r"^Rtl(GetProcAddress|PcToFileHeader).*$", r"^Ldr(GetDllHandle(ByName)?|GetProcedureAddress|LoadDll).*$"
        ]
        compiled_patterns = [re.compile(p) for p in pattern_sources]
        try:
            self._loader_patterns = compiled_patterns
        except Exception:
            pass
        # Optional debug output (disabled):
        # print(f"[Sharingan] Loader APIs cached: {len(self._loader_names)}")

    # ------------------------------------------------------------------
    def is_known_function_literal(self, s: str) -> bool:
        """Exact case-insensitive test against imports, FLIRT libs, and Feeds."""
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
        # Optional: short API-like names that appear among imports via common prefixes
        if len(s) <= 32 and any(s.startswith(pref) for pref in self._api_prefixes):
            if s in self._imports or ls in self._imports:
                return True
        # C++ runtime/typeinfo/stdlib identifiers and mangled names (from sig/typelibs)
        if self.is_cxx_symbol_literal(s):
            return True
        return False

    def is_loader_api_literal(self, s: str) -> bool:
        """Return True if s explicitly matches a dynamic loader related API name or pattern.

        This is a direct exclusion mechanism independent of xrefs. Patterns mirror those used for expansion in _build_loader_context. Case-sensitive to avoid over-filtering.
        """
        if not s:
            return False
        for cp in self._loader_patterns:
            try:
                if cp.match(s):
                    return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------
    # C++ symbol (STL/RTTI/mangled)
    # ------------------------------------------------------------------
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
        """Heuristic for C++/STL/RTTI names likely covered by sig/typelibs.

        Matches if any:
        - Demangler accepts the name
        - Looks like MSVC or Itanium-mangled
        - Contains common stdlib identifiers (std::, basic_string, iostream, ios_base, char_traits, allocator, exception)
        - Contains 'operator' (demangled form)
        """
        if not s:
            return False
        if self._is_msvc_mangled(s) or self._is_itanium_mangled(s):
            return True
        if self._demangles(s):
            return True
        if ('std::' in s) or ('operator' in s):
            return True
        # Detect common namespace qualifiers from libstdc++/libc++/NDK/pmr/gnu extensions
        ns_tokens = (
            'std::__cxx11::', 'std::__1::', 'std::__ndk1::', '__gnu_cxx::', 'std::pmr::'
        )
        if any(tok in s for tok in ns_tokens):
            return True
        # Broad, but safe because this filter applies post-collection (base64/high-entropy only)
        keywords = (
            # Strings/streams
            'string', 'wstring', 'u16string', 'u32string', 'string_view', 'basic_string',
            'istream', 'ostream', 'iostream', 'fstream', 'ifstream', 'ofstream',
            'stringstream', 'istringstream', 'ostringstream', 'basic_istream', 'basic_ostream', 'basic_iostream',
            'ios', 'ios_base', 'char_traits', 'codecvt',
            # Containers/algorithms/utilities
            'vector', 'list', 'forward_list', 'deque', 'queue', 'priority_queue', 'stack',
            'map', 'multimap', 'set', 'multiset', 'unordered_map', 'unordered_set',
            'pair', 'tuple', 'optional', 'variant', 'any', 'bitset', 'span', 'valarray',
            # Memory/smart pointers
            'allocator', 'shared_ptr', 'unique_ptr', 'weak_ptr', 'enable_shared_from_this',
            # Functional/threading/atomic
            'function', 'bind', 'placeholders', 'thread', 'jthread', 'mutex', 'recursive_mutex',
            'timed_mutex', 'shared_mutex', 'condition_variable', 'future', 'promise', 'packaged_task',
            'atomic', 'shared_lock', 'unique_lock', 'scoped_lock', 'barrier', 'latch',
            'counting_semaphore', 'binary_semaphore', 'stop_token', 'stop_source',
            # Numerics/random/chrono
            'complex', 'random_device', 'mt19937', 'mt19937_64', 'uniform_int_distribution',
            'uniform_real_distribution', 'bernoulli_distribution', 'normal_distribution', 'chrono',
            # Filesystem/localization/exceptions/RTTI
            'filesystem', 'path', 'locale', 'numpunct', 'num_put', 'num_get', 'ctype',
            'exception', 'bad_alloc', 'terminate', 'unexpected', 'type_info', 'typeinfo', 'type_index',
            # Formatting/charconv
            'format', 'formatter', 'vformat', 'print', 'charconv', 'to_chars', 'from_chars',
            # Ranges/coroutines/utilities
            'ranges', 'views', 'mdspan', 'generator', 'coroutine', 'coroutine_handle',
            'suspend_always', 'suspend_never', 'source_location', 'expected'
        )
        if any(k in s for k in keywords):
            return True
        return False
