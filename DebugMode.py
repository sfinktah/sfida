import idc

def SetDebugMode(n):
    global debug
    old_debug_mode = debug
    debug = n
    return old_debug_mode

class DebugMode(object):
    old_debug_mode = None
    new_debug_mode = None
    def __init__(self, new_debug_mode):
        self.new_debug_mode = new_debug_mode
        self.old_debug_mode = SetDebugMode(self.new_debug_mode)

    def __enter__(self):
        # self.old_debug_mode = SetDebugMode(self.new_debug_mode)
        return self.old_debug_mode

    def __exit__(self, exc_type, exc_value, traceback):
        if self.old_debug_mode is not None:
            SetDebugMode(self.old_debug_mode)

