import idaapi
from sharingan.main_layout import MainWindow
from  sharingan.module import StylesManager


class PluginPanel(idaapi.PluginForm):
    def __init__(self):
        super().__init__()

    """Panel for the IDA GUI."""
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.main_layout = MainWindow(self)

class Sharingan(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = 'Assist and ease deobfuscation'
    wanted_name = 'Sharingan'
    wanted_hotkey = ''
    help = ''

    def init(self):
        """Init the IDA plugin."""
        idaapi.msg("Sharingan initialized!!!\n")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """Run the IDA plugin."""
        idaapi.msg('Running ' + self.wanted_name + '\n')
        self.sharingan_gui = PluginPanel()
        self.sharingan_gui.Show('Sharingan')
        StylesManager.load_stylesheet()
    
    def term(self):
        pass


def PLUGIN_ENTRY():
    return Sharingan()