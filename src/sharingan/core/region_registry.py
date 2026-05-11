import ida_kernwin
import idaapi


class RegionKind:
    MANUAL_BM = 'manual_bm'
    SCAN_BM = 'scan_bm'
    PATCHED = 'patched'
    HINT = 'hint'
    OVERLAP = 'overlap'


# annotated interval; replaces per-byte color as source of truth
class Region:
    __slots__ = ('start_ea', 'end_ea', 'kind', 'hint')

    def __init__(self, start_ea, end_ea, kind, hint=''):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.kind = kind
        self.hint = hint


# single source of truth for region semantics; render is derived, never the other way
class RegionRegistry:
    def __init__(self):
        self._regions = []

    def add(self, region):
        self._regions.append(region)

    def remove_where(self, predicate):
        self._regions = [r for r in self._regions if not predicate(r)]

    def find_at(self, ea, kinds=None):
        return [r for r in self._regions
                if r.start_ea <= ea < r.end_ea
                and (kinds is None or r.kind in kinds)]

    def all(self, kinds=None):
        if kinds is None:
            return list(self._regions)
        return [r for r in self._regions if r.kind in kinds]

    def clear(self, kinds=None):
        if kinds is None:
            self._regions.clear()
        else:
            self._regions = [r for r in self._regions if r.kind not in kinds]


# highest kind painted on a line when several regions cover the same ea
_KIND_PRIORITY = (
    RegionKind.OVERLAP,
    RegionKind.PATCHED,
    RegionKind.HINT,
    RegionKind.MANUAL_BM,
    RegionKind.SCAN_BM,
)

# IDA's line_rendering bg_color expects CK_EXTRA* color keys, not raw BGR
_KIND_COLOR = {
    RegionKind.OVERLAP: ida_kernwin.CK_EXTRA4,
    RegionKind.PATCHED: ida_kernwin.CK_EXTRA3,
    RegionKind.HINT: ida_kernwin.CK_EXTRA6,
    RegionKind.MANUAL_BM: ida_kernwin.CK_EXTRA5,
    RegionKind.SCAN_BM: ida_kernwin.CK_EXTRA5,
}


# paints registry regions on the disassembler at draw time; never writes byte color
class RegionRenderer(ida_kernwin.UI_Hooks):
    def __init__(self, registry):
        ida_kernwin.UI_Hooks.__init__(self)
        self.registry = registry

    def get_lines_rendering_info(self, out, widget, rin):
        if not widget or idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            return
        for section_lines in rin.sections_lines:
            for line in section_lines:
                place = line.at
                if not place:
                    continue
                ea = place.toea()
                if ea == idaapi.BADADDR:
                    continue
                kinds = {r.kind for r in self.registry.find_at(ea)}
                if not kinds:
                    continue
                top = next((k for k in _KIND_PRIORITY if k in kinds), None)
                if top is None:
                    continue
                e = ida_kernwin.line_rendering_output_entry_t(line)
                e.bg_color = _KIND_COLOR[top]
                out.entries.push_back(e)
