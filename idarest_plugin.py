import ida_idaapi
import ida_kernwin
import ida_loader
try:
    ida_idaapi.require('idarest.idarest')
    ida_idaapi.require('idarest.idarest_mixins')
    from idarest.idarest import *
except ModuleNotFoundError:
    ida_idaapi.require('idarest')
    ida_idaapi.require('idarest_mixins')
    from idarest import *

MENU_PATH = 'Edit/Other'

def PLUGIN_ENTRY():
    # from idarest import idarest_main
    globals()['instance'] = idarest_main()
    return globals()['instance']
