import ida_idaapi
import ida_kernwin
import ida_loader
from idarest.idarest import *

MENU_PATH = 'Edit/Other'

def PLUGIN_ENTRY():
    globals()['instance'] = idarest_main()
    return globals()['instance']
