import os
from collections.abc import Iterable

import ida_diskio


class IgnoreStringStore:
    """Manage per-user ignore strings and synchronize with the bundled list."""

    def __init__(self):
        self.bundle_path = os.path.join(os.path.dirname(__file__), "ignore_string")
        self.user_path = self._ensure_user_store()

    def _ensure_user_store(self) -> str | None:
        user_dir = None
        try:
            user_root = ida_diskio.get_user_idadir()
            user_dir = os.path.join(user_root, "plugins", "sharingan", "core", "StrFinder")
            os.makedirs(user_dir, exist_ok=True)
        except Exception as exc:
            print(f"[Sharingan] Warning: cannot create user ignore dir {user_dir}: {exc}")
            return None

        user_file = os.path.join(user_dir, "ignore_string")
        if os.path.exists(user_file):
            existing_literals = self._read_literals(user_file)
            try:
                self._store_literals(user_file, existing_literals)
            except OSError as exc:
                print(f"[Sharingan] Warning: unable to normalize user ignore file {user_file}: {exc}")
            self._merge_bundle_into_user(user_file)
            return user_file

        initial_literals = self._read_literals(self.bundle_path)
        try:
            self._store_literals(user_file, initial_literals)
            return user_file
        except OSError as exc:
            print(f"[Sharingan] Warning: cannot seed user ignore file {user_file}: {exc}")
        return None

    def apply_to_result_filter(self, result_filter) -> None:
        if not result_filter or not self.user_path:
            return
        user_literals = self._load_literals(self.user_path)
        if user_literals:
            result_filter.ignore_literals.update(user_literals)
        result_filter.ignore_file_path = self.user_path

    def _read_literals(self, path: str) -> list[str]:
        literals: list[str] = []
        if not os.path.exists(path):
            return literals
        try:
            with open(path, "rb") as src:
                for line in src:
                    literal = self._decode_literal(line)
                    if literal:
                        literals.append(literal)
        except OSError as exc:
            print(f"[Sharingan] Warning: unable to read ignore list {path}: {exc}")
        return literals

    def _load_literals(self, path: str) -> set[str]:
        return set(self._read_literals(path))

    def _store_literals(self, path: str, literals: Iterable[str]) -> None:
        with open(path, "wb") as dst:
            for literal in literals:
                encoded = self._encode_literal(literal)
                dst.write(encoded + b"\n")

    def _merge_bundle_into_user(self, user_file: str) -> None:
        if not os.path.exists(self.bundle_path):
            return
        user_literals = self._load_literals(user_file)
        ordered_bundle = self._read_literals(self.bundle_path)
        missing = [literal for literal in ordered_bundle if literal not in user_literals]
        if not missing:
            return
        try:
            with open(user_file, "ab") as dst:
                for literal in missing:
                    dst.write(self._encode_literal(literal) + b"\n")
        except OSError as exc:
            print(f"[Sharingan] Warning: unable to merge bundle ignore literals: {exc}")

    @staticmethod
    def _encode_literal(value: str) -> bytes:
        return value.encode("unicode_escape")

    @staticmethod
    def _decode_literal(raw_line: bytes) -> str | None:
        literal = raw_line.rstrip(b"\r\n")
        if not literal:
            return None
        try:
            return literal.decode("unicode_escape")
        except UnicodeDecodeError:
            return literal.decode("utf-8", errors="ignore")

    def append_literals(self, literals: Iterable[str]) -> set[str]:
        if not self.user_path:
            return set()
        candidates = [literal for literal in literals if literal]
        if not candidates:
            return set()
        existing = self._load_literals(self.user_path)
        ordered_new: list[str] = []
        for literal in candidates:
            if literal in existing or literal in ordered_new:
                continue
            ordered_new.append(literal)
        if not ordered_new:
            return set()
        try:
            with open(self.user_path, "ab") as dst:
                for literal in ordered_new:
                    dst.write(self._encode_literal(literal) + b"\n")
        except OSError as exc:
            print(f"[Sharingan] Warning: failed to append ignore file {self.user_path}: {exc}")
            return set()
        return set(ordered_new)

    def flush_to_bundle(self) -> None:
        if not self.user_path:
            return
        user_literals = self._load_literals(self.user_path)
        if not user_literals:
            return
        bundle_literals = self._load_literals(self.bundle_path) if os.path.exists(self.bundle_path) else set()
        new_literals = sorted(user_literals - bundle_literals)
        if not new_literals:
            return
        try:
            with open(self.bundle_path, "ab") as dst:
                for item in new_literals:
                    dst.write(self._encode_literal(item) + b"\n")
        except OSError as exc:
            print(f"[Sharingan] Warning: failed to append bundle ignore file {self.bundle_path}: {exc}")


_ignore_store: IgnoreStringStore | None = None


def get_ignore_store(create: bool = True) -> IgnoreStringStore | None:
    global _ignore_store
    if _ignore_store is None and create:
        _ignore_store = IgnoreStringStore()
    return _ignore_store


def apply_ignore_store(result_filter) -> IgnoreStringStore | None:
    store = get_ignore_store()
    if store:
        store.apply_to_result_filter(result_filter)
    return store


def flush_user_ignore_to_bundle() -> None:
    store = get_ignore_store(create=False)
    if store:
        store.flush_to_bundle()

