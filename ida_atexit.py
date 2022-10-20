import atexit
import idc
import ida_idaapi

class ida_atexit(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "atexit"
    help = "triggers atexit._run_exitfuncs() when ida halts plugins"
    wanted_hotkey = ""
    comment = "atexit"
    wanted_name = "atexit interop"
    wanted_hotkey = ""

    def init(self):
        super(ida_atexit, self).__init__()
        return ida_idaapi.PLUGIN_KEEP

    def run(*args):
        pass

    def term(self):
        idc.msg('[ida_atexit::term] calling atexit._run_exitfuncs()\n')
        atexit._run_exitfuncs()

def PLUGIN_ENTRY():
    globals()['instance'] = ida_atexit()
    return globals()['instance']
