from sharingan.base.customitembase import CustomItemBase
import idc, idaapi

class Irrelevant(CustomItemBase):
    def __init__(self, parent=None):
        super(Irrelevant, self).__init__(parent)
        self.set_label_text('Irrelevant')

    def deobfuscate(self, start_ea, end_ea):
        dst_addr = start_ea
        for i in range(3):
            dst_addr = idc.next_head(dst_addr)
        for i in range(5):
            idaapi.patch_byte(dst_addr, 0x90)
            dst_addr = idc.next_head(dst_addr)

    def detect(self, start_ea, end_ea):
        dst_addr = start_ea
        color_mint = 0x3EB489
        for i in range(3):
            dst_addr = idc.next_head(dst_addr)
        for i in range(5):
            if idaapi.is_code(idaapi.get_flags(dst_addr)):
                idaapi.set_item_color(dst_addr, color_mint)
                dst_addr = idc.next_head(dst_addr)