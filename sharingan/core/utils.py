import string

import ida_bytes
import idaapi
import idc


class Color:
    DEFCOLOR = 0xFFFFFFFF               # remove color
    BG_PATCH_HIDDEN = 0x8BAB53          # green: patch/hidden range
    BG_OVERLAPPING = 0x4A6AFB           # red: overlap
    BG_HINT = 0x736E37                  # blue: hint
    BG_BOOKMARK = 0x3059AD              # brown: bookmark


class DeobfuscateUtils:
    @staticmethod
    def get_bytes_as_hex_string(addr, size):
        bytes_data = ida_bytes.get_bytes(addr, size)
        return " ".join([f"{b:02x}" for b in bytes_data])

    @staticmethod
    def mark_as_code(start_addr, end_addr):
        idaapi.auto_mark_range(start_addr, end_addr, idaapi.AU_CODE)
        idaapi.plan_and_wait(start_addr, end_addr, True)

    @staticmethod
    def refresh_view():
        idaapi.request_refresh(0xFFFFFFFF)
        idaapi.auto_wait()

    @staticmethod
    def patch_bytes(addr, arr_byte):
        ida_bytes.patch_bytes(addr, arr_byte)
        idaapi.auto_wait()

    @staticmethod
    def del_items(addr, length, is_expand=False):
        if not is_expand:
            ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, length)
        else:
            ida_bytes.del_items(
                addr, ida_bytes.DELIT_SIMPLE | ida_bytes.DELIT_EXPAND, length
            )
        idaapi.auto_wait()

    @staticmethod
    def compile_pattern_search(bytes_pattern_str):
        image_base = idaapi.get_imagebase()
        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(
            compiled_pattern, image_base, bytes_pattern_str, 16
        )
        return compiled_pattern

    @staticmethod
    def is_jmp(addr):
        return idc.print_insn_mnem(addr).startswith("j")

    @staticmethod
    def is_call(addr):
        call_insn = set((idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni))
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype in call_insn or idaapi.is_call_insn(instr)

    @staticmethod
    def is_push(addr):
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype == idaapi.NN_push

    @staticmethod
    def is_mov(addr):
        instr = idaapi.insn_t()
        idaapi.decode_insn(instr, addr)
        return instr.itype == idaapi.NN_mov

    @staticmethod
    def is_nop(addr):
        if idaapi.get_wide_byte(addr) == 0x90:
            return True

        instr = idaapi.insn_t()
        insn_len = idaapi.decode_insn(instr, addr)

        if insn_len > 0:
            if instr.itype == idaapi.NN_nop:
                return True

        return False

    @staticmethod
    def reset(start_addr, end_addr):
        next_addr = start_addr
        while next_addr < end_addr:
            idc.set_color(next_addr, idc.CIC_ITEM, 0xFFFFFFFF)
            hr = idaapi.get_hidden_range(next_addr)
            if hr:
                ba = ida_bytes.get_bytes(hr.start_ea, hr.end_ea - hr.start_ea)
                if not DeobfuscateUtils.is_all_nop(ba):
                    idaapi.del_hidden_range(next_addr)
                next_addr = hr.end_ea
                continue
            flags = idaapi.get_flags(next_addr)
            if idaapi.is_code(flags):
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
            else:
                next_addr += 1
        DeobfuscateUtils.mark_as_code(start_addr, end_addr)

    @staticmethod
    def color_range(start_addr, end_addr, color):
        next_addr = start_addr
        while next_addr < end_addr:
            idc.set_color(next_addr, idc.CIC_ITEM, color)
            flags = idaapi.get_flags(next_addr)
            if idaapi.is_code(flags):
                size_item = idaapi.get_item_size(next_addr)
                next_addr += size_item if size_item > 0 else 1
            else:
                next_addr += 1

    @staticmethod
    def is_all_nop(ba):
        return all(b == 0x90 for b in ba)


class DecryptionUtils:
    @staticmethod
    def clamp_key(key: int, item_size: int = 1):
        bits = max(1, item_size) * 8
        mask = (1 << bits) - 1
        return key & mask

    @staticmethod
    def normalize_bytes(value):
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("latin-1", errors="ignore")
        return bytes(value)

    @staticmethod
    def parse_key(text: str, default: int = 0):
        if not text:
            return default
        try:
            return int(text, 0)
        except Exception:
            return default

    @staticmethod
    def parse_byte_sequence(text: str, fallback: bytes = b"") -> bytes:
        if not text:
            return fallback
        value = text.strip()
        if not value:
            return fallback
        normalized = value.replace(" ", "").replace("_", "")
        try:
            if normalized.lower().startswith("0x"):
                normalized = normalized[2:]
            if normalized and all(ch in string.hexdigits for ch in normalized):
                if len(normalized) % 2:
                    normalized = "0" + normalized
                return bytes.fromhex(normalized)
        except ValueError:
            pass
        return value.encode("latin-1", errors="ignore")

    @staticmethod
    def ensure_block_multiple(data: bytes, block_size: int) -> bytes:
        if block_size <= 0:
            return data
        remainder = len(data) % block_size
        if remainder == 0:
            return data
        padding = b"\x00" * (block_size - remainder)
        return data + padding

    @staticmethod
    def to_preview_string(data: bytes):
        if not data:
            return data
        idx = data.find(b"\x00")
        cleaned = data if idx == -1 else data[:idx]
        try:
            return cleaned.decode("utf-8")
        except UnicodeDecodeError:
            return cleaned.decode("latin-1", errors="replace")

    @staticmethod
    def rotl(value: int, shift: int, width: int = 8) -> int:
        if width <= 0:
            return value
        shift %= width
        mask = (1 << width) - 1
        return ((value << shift) | (value >> (width - shift))) & mask
