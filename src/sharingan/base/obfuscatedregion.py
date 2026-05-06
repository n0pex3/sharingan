from collections import namedtuple
from typing import List
from enum import Enum


RegionData = namedtuple('RegionData', ['start_ea', 'end_ea', 'obfus_size', 'comment', 'patch_bytes', 'action'])


class Action(Enum):
    PATCH = 1
    CMT = 2


# one ObfuscatedRegion may contain sequence instructions (len == 1) or rambling instructions (len > 1)
class ObfuscatedRegion:
    def __init__(self, start_ea: int = 0, end_ea: int = 0, obfus_size: int = 0, comment: str = '', patch_bytes: bytes = b'', name: str = '', action: Action = Action.PATCH):
        self.regions: List[RegionData] = [RegionData(start_ea, end_ea, obfus_size, comment, patch_bytes, action)]
        self.name = name

    # if rambling instruction, use append_obfu
    def append_obfu(self, start_ea: int, end_ea: int, obfus_size: int, comment: str, patch_bytes: bytes, action: Action) -> None:
        self.regions.append(RegionData(start_ea, end_ea, obfus_size, comment, patch_bytes, action))

    def __str__(self) -> str:
        lines = []
        for r in self.regions:
            lines.append(f"{hex(r.start_ea)} - {r.end_ea} - {r.comment} - {r.patch_bytes} - {r.action}")
        return '\n'.join(lines)


# ListObfuscatedRegion contain many ObfuscatedRegion => one ingredient may responde many ObfuscatedRegion
# [[[a, a][a, a][a, a]][[b, b][b, b][b, b]]]
# [[a, a][a, a][a, a]] is a ingredient, [a, a] is a region
class ListObfuscatedRegion(list):
    def __init__(self) -> None:
        super().__init__()
        self.allowed_type = ObfuscatedRegion

    def append(self, item: ObfuscatedRegion) -> None:
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        super().append(item)

    def insert(self, index: int, item: ObfuscatedRegion) -> None:
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        super().insert(index, item)

    def __setitem__(self, index: int, item: ObfuscatedRegion) -> None:
        if not isinstance(item, self.allowed_type):
            raise TypeError(f"Item must be of type {self.allowed_type.__name__}, got {type(item).__name__}")
        super().__setitem__(index, item)

    def __str__(self) -> str:
        return '\n\n'.join(str(item) for item in self)
