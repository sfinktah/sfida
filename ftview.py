from __future__ import print_function
# -----------------------------------------------------------------------
# This is an example illustrating how to use customview in Python
# (c) Hex-Rays
#
import ida_kernwin
import ida_lines
from PyQt5.QtCore import QTimer
# -----------------------------------------------------------------------
from exectools import execfile, _import, make_refresh
refresh_ftview = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))



class ft_char:
    """colored character"""

    def __init__(self, char=' ', color=default_color, attributes=None, dirty=True):
        self.char  = char
        self.color = default_color
        self.attributes = {}
        if attributes is not None:
            _.extend(self.attributes, attributes)
        self.dirty = not not dirty

ft_screen = collections.defaultdict(dict)

class say_something_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, thing):
        ida_kernwin.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        print(self.thing)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    @staticmethod
    def compose_action_name(v):
        return "custview:say_%s" % v


# create actions
actions_variants = ["Hello", "World"]
for av in actions_variants:
    actname = say_something_handler_t.compose_action_name(av)
    if ida_kernwin.unregister_action(actname):
        print("Unregistered previously-registered action \"%s\"" % actname)

    desc = ida_kernwin.action_desc_t(actname, "Say %s" % av, say_something_handler_t(av))
    if ida_kernwin.register_action(desc):
        print("Registered action \"%s\"" % actname)



# -----------------------------------------------------------------------
class mycv_t(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        self.q = []
        self.buffer = []
    
    def draw_request(self):
        self.debounce.start()

    def debounced(self):
        if self.q:
            mycv.ClearLines()
            mycv.Draw()
        mycv.draw_request()

    def Draw(self):
        self.last_ea = idc.here()
        self.buffer.extend(self.q)
        self.q.clear()
        if len(self.buffer) > 10:
            self.buffer = self.buffer[:-10]
        #  func_tails(idc.here(), output=output)
        #  output.extend(["a", "b", "c"])
        for i in range(0, len(self.buffer)):
            prefix, bg = ida_lines.COLOR_DEFAULT, None
            # make every 10th line a bit special
            if i % 10 == 0:
                prefix = ida_lines.COLOR_DNAME   # i.e., dark yellow...
                # bg = 0xFFFF00                 # ...on cyan
            pfx = ida_lines.COLSTR("%3d" % i, ida_lines.SCOLOR_PREFIX)
            if self.use_colors:
                self.AddLine("%s: %s" % (pfx, self.buffer[i]), fgcolor=prefix) #  , bgcolor=bg)
            else:
                self.AddLine("%s: %s" % (pfx, self.buffer[i]))

    def Create(self, sn=None, use_colors=True):
        # Form the title
        title = "Simple custom view test"
        if sn:
            title += " %d" % sn
        self.use_colors = use_colors

        # Create the customviewer
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            print("failed to create")
            return False

        #  self.Draw()

        self.debounce = QTimer()
        self.debounce.setInterval(500)
        self.debounce.setSingleShot(True)
        self.debounce.timeout.connect(self.debounced)
        self.debounce.start()

        return True



    def OnClick(self, shift):
        """
        User clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnClick, shift=%d" % shift)
        return True

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        word = self.GetCurrentWord()
        if not word: word = "<None>"
        print("OnDblClick, shift=%d, current word=%s" % (shift, word))
        return True

    def OnCursorPosChanged(self):
        """
        Cursor position changed.
        @return: Nothing
        """
        print("OnCurposChanged")

    def OnClose(self):
        """
        The view is closing. Use this event to cleanup.
        @return: Nothing
        """
        print("OnClose " + self.title)

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnKeydown, vk=%d shift=%d" % (vkey, shift))
        # ESCAPE?
        if vkey == 27:
            self.Close()
        # VK_DELETE
        elif vkey == 46:
            n = self.GetLineNo()
            if n is not None:
                self.DelLine(n)
                self.Refresh()
                print("Deleted line %d" % n)
        # Goto?
        elif vkey == ord('G'):
            n = self.GetLineNo()
            if n is not None:
                v = ida_kernwin.ask_long(self.GetLineNo(), "Where to go?")
                if v:
                    self.Jump(v, 0, 5)
        elif vkey == ord('R'):
            print("refreshing....")
            self.Refresh()
        elif vkey == ord('C'):
            print("refreshing current line...")
            self.RefreshCurrent()
        elif vkey == ord('A'):
            s = ida_kernwin.ask_str("NewLine%d" % self.Count(), 0, "Append new line")
            self.AddLine(s)
            self.Refresh()
        elif vkey == ord('X'):
            print("Clearing all lines")
            self.ClearLines()
            self.Refresh()
        elif vkey == ord('I'):
            n = self.GetLineNo()
            s = ida_kernwin.ask_str("InsertedLine%d" % n, 0, "Insert new line")
            self.InsertLine(n, s)
            self.Refresh()
        elif vkey == ord('E'):
            l = self.GetCurrentLine(notags=1)
            if not l:
                return False
            n = self.GetLineNo()
            print("curline=<%s>" % l)
            l = l + ida_lines.COLSTR("*", ida_lines.SCOLOR_VOIDOP)
            self.EditLine(n, l)
            self.RefreshCurrent()
            print("Edited line %d" % n)
        else:
            return False
        return True

    def OnHint(self, lineno):
        """
        Hint requested for the given line number.
        @param lineno: The line number (zero based)
        @return:
            - tuple(number of important lines, hint string)
            - None: if no hint available
        """
        return (1, "OnHint, line=%d" % lineno)

    def Show(self, *args):
        ok = ida_kernwin.simplecustviewer_t.Show(self, *args)
        if ok:
            # permanently attach actions to this viewer's popup menu
            for av in actions_variants:
                actname = say_something_handler_t.compose_action_name(av)
                ida_kernwin.attach_action_to_popup(self.GetWidget(), None, actname)
        return ok

    def OnRefresh(self):
        """
        """
        print("OnRefresh ")


# -----------------------------------------------------------------------
try:
    # created already?
    mycv
    print("Already created, will close it...")
    mycv.Close()
    del mycv
except:
    pass

def show_win():
    x = mycv_t()
    if not x.Create():
        print("Failed to create!")
        return None
    x.Show()
    #  globals()['tcc'] = x.GetWidget()
    return x

mycv = show_win()
if not mycv:
    del mycv

def make_many(n):
    L = []
    for i in range(1, n+1):
        v = mycv_t()
        if not v.Create(i):
            break
        v.Show()
        L.append(v)
    return L
