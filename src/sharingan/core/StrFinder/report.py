"""Scan progress reporting for Sharingan String Finder.

Writes a human-readable log alongside the input binary/IDB so users can review
what was collected at each stage (static/stack/tight/merge/filter).
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Iterable

import ida_nalt    

class ScanReport:
    def __init__(self):
        in_path = ida_nalt.get_input_file_path()
        if in_path:
            base, _ = os.path.splitext(in_path)
        self.path = f"{base}_sharingan_strings.txt"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = [
            "\nSharingan String Finder Report",
            f"Generated: {timestamp}",
        ]
        if not os.path.exists(self.path):
            self.log_message('\n'.join(header), "w")
        else:
            self.log_message('\n'.join(header), "a")

    def log_message(self, mess: str, mode: str = "a") -> None:
        try:
            with open(self.path, mode, encoding="utf-8") as f:
                f.write(f"{mess}\n")
        except Exception:
            return