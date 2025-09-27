import idaapi
from sharingan.mainwindow import MainWindow
from sharingan.core import stylesmanager
from sharingan.core.contextmenu import InitHookMenu


class PluginPanel(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        self.main_layout = None

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
        self.hook_menu = InitHookMenu()
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        """Run the IDA plugin."""
        idaapi.msg('Running ' + self.wanted_name + '\n')
        self.sharingan_gui = PluginPanel()
        self.sharingan_gui.Show('Sharingan')
        stylesmanager.load_stylesheet()
        recipe = self.sharingan_gui.main_layout.recipe
        self.hook_menu.register_recipe(recipe)
    
    def term(self):
        self.hook_menu.cleanup()


def PLUGIN_ENTRY():
    return Sharingan()