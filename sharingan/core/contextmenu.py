import idaapi, ida_kernwin
from PyQt5 import QtWidgets

TODO_LIST = 'sharingan:todo'
FIND_OBFU = 'sharingan:find_obfu'
REVERT = 'sharingan:revert'

class InputDialog(QtWidgets.QDialog):
    def __init__(self):
        super(InputDialog, self).__init__()
        self.setWindowTitle(f"Input hint")
        self.layout = QtWidgets.QVBoxLayout()
        
        self.textbox = QtWidgets.QLineEdit()
        self.layout.addWidget(QtWidgets.QLabel("Hint:"))
        self.layout.addWidget(self.textbox)
        
        self.buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)
        
        self.setLayout(self.layout)
    
    def get_value(self):
        return self.textbox.text()

class HookRightClick(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup, TODO_LIST, None, 0)
            ida_kernwin.attach_action_to_popup(widget, popup, FIND_OBFU, None, 0)
            ida_kernwin.attach_action_to_popup(widget, popup, REVERT, None, 0)
        return 0
    
class handler_add_todo(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
        self.recipe = None

    def add_recipe(self, recipe):
        self.recipe = recipe

    def activate(self, ctx):
        if self.recipe:
            cursor = idaapi.get_screen_ea()
            dialog = InputDialog()
            if dialog.exec_():
                hint = dialog.get_value()
                self.recipe.append_addr_combobox(f'{hex(cursor)} - {hint}')
        else:
            print('Please run plugin first')

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class handler_find_obfus(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
        self.recipe = None

    def add_recipe(self, recipe):
        self.recipe = recipe

    def activate(self, ctx):
        if self.recipe:
            self.recipe.scan()
        else:
            print('Please run plugin first')

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class handler_exclusion(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
        self.recipe = None

    def add_recipe(self, recipe):
        self.recipe = recipe

    def activate(self, ctx):
        if self.recipe:
            cursor = idaapi.get_screen_ea()
            self.recipe.exclude_fp(cursor)
        else:
            print('Please run plugin first')

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class InitHookMenu():
    def __init__(self):
        self.handler_todo = handler_add_todo()
        self.handler_find = handler_find_obfus()
        self.handler_exclusion = handler_exclusion()
        action_add_todo = idaapi.action_desc_t(TODO_LIST, 'Add todo list', self.handler_todo, None, None, -1)
        action_find_obfu = idaapi.action_desc_t(FIND_OBFU, 'Find obfuscated code', self.handler_find, None, None, -1)
        action_exclusion = idaapi.action_desc_t(REVERT, 'Exclude', self.handler_exclusion, None, None, -1)
        assert idaapi.register_action(action_add_todo), "Action registration failed"
        assert idaapi.register_action(action_find_obfu), "Action registration failed"
        assert idaapi.register_action(action_exclusion), "Action registration failed"
        self.hook_menu = HookRightClick()
        self.hook_menu.hook()

    def cleanup(self):
        self.hook_menu.unhook()
        idaapi.unregister_action(TODO_LIST)
        idaapi.unregister_action(FIND_OBFU)
        idaapi.unregister_action(REVERT)

    def register_recipe(self, recipe):
        self.handler_todo.add_recipe(recipe)
        self.handler_find.add_recipe(recipe)
        self.handler_exclusion.add_recipe(recipe)