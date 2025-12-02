import os
import re
import ida_diskio
from .sig_filter import SignatureFilter

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

# be stricter removing FP strings for shorter strings
MAX_STRING_LENGTH_FILTER_STRICT = 6
# e.g. [ESC], [Alt], %d.dll
FP_FILTER_STRICT_INCLUDE = re.compile(r"^\[.*?]$|%[sd]")
# remove special characters
FP_FILTER_STRICT_SPECIAL_CHARS = re.compile(r"[^A-Za-z0-9.]")
FP_FILTER_STRICT_KNOWN_FP = re.compile(r"^O.*A$")

class ResultFilter:
    def __init__(self):
        # Custom ignore list for known static tables
        self.ignore_literals = set()
        self.load_init_exclude()

        # Handle signature-based filtering
        self.sig_filter = SignatureFilter()
        
    def load_init_exclude(self):
        """Load ignore strings from all available ignore files."""
        for path in self._candidate_ignore_files():
            self._load_ignore_file(path)

    def _load_ignore_file(self, path: str):
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.rstrip()
                    if not line:
                        continue
                    self.ignore_literals.add(line)
        except Exception as e:
            print(f"[ESF] Warning: could not load ignore list {path}: {e}")

    def _candidate_ignore_files(self):
        module_dir = os.path.dirname(os.path.abspath(__file__))
        yield os.path.join(module_dir, "ignore_string")
        user_dir = None
        try:
            user_dir = ida_diskio.get_user_idadir()
        except Exception:
            user_dir = None
        if user_dir:
            yield os.path.join(user_dir, "plugins", "sharingan", "core", "StrFinder", "ignore_string")
        yield os.path.join(os.path.expanduser("~"), ".sharingan", "ignore_string")
    
    def filter_results(self, strings_list):
        try:
            import ida_auto
            ida_auto.auto_wait()
        except Exception:
            pass

        # If signature sources look empty on first call, rebuild after analysis
        try:
            if not (self.sig_filter._imports or self.sig_filter._lib_funcs or self.sig_filter._feed_symbols):
                self.sig_filter = SignatureFilter()
        except Exception:
            pass

        # Exclusion: skip known initialization / lookup tables
        filtered = [s for s in strings_list if not self.is_init_exclude(s['value'])]

        # Exclude FLOSS-style false positives (CRT errors, runtime messages, etc.)
        filtered = [s for s in filtered if not self.is_floss_fp(s['value'])]
        
        # Exclude known function signature-like strings
        filtered = [s for s in filtered if not self.sig_filter.is_known_function_literal(s['value'])]

        # Exclude dynamic loader API literals via direct name/pattern match
        filtered = [s for s in filtered if not self.sig_filter.is_loader_api_literal(s['value'])]

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
