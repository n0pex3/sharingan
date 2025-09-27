import idaapi, os

stylesheet = None
KEY = 'THEME_SHARINGAN'

def load_stylesheet():
    global stylesheet
    path_plugin = idaapi.get_ida_subdirs("plugins")
    for path in path_plugin:
        path_stylesheet = os.path.join(path, 'sharingan', 'core', 'styles.qss')
        if os.path.exists(path_stylesheet):
            with open(path_stylesheet, 'r') as file:
                stylesheet = file.read()
                break

def get_stylesheet():
    if not stylesheet:
        load_stylesheet()
    return stylesheet

def get_theme():
    return 'light' if os.environ.get(KEY) else 'dark'
                