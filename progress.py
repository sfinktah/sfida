# This Python file uses the following encoding: utf-8

"""
[░░░░░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███████████████████▒┅┅┅┅] 95%
"""

import ida_kernwin
from static_vars import static_vars
#  from exectools import _import, _from
#  _from('slowtrace_helpers import make_transpose_fn')
#  _from('hex import asList')

@static_vars(last_width=getglobal('_progress_console_width', None))
def _get_console_width():
    #  return screenwidth_process.width
    output_window_title = "Output window"
    tw = ida_kernwin.find_widget(output_window_title)
    if not tw:
        if _get_console_width.last_width:
            return _get_console_width.last_width
        raise Exception("Couldn't find widget '%s'" % output_window_title)

    # convert from a SWiG 'TWidget*' facade,
    # into an object that PyQt will understand
    if hasattr(ida_kernwin.PluginForm, 'TWidgetToPyQtWidget'):
        w = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw)
        scrollable = w.childAt(0, 0)
        char_width = int(scrollable.width() / 7.06)
        if char_width != _get_console_width.last_width:
            _get_console_width.last_width = char_width
            try:
                setglobal('_progress_console_width', _get_console_width.last_width)
            except:
                pass
        return char_width
    else:
        print('[progress] return default width of 100')
        return 100


_block = "█▒▓░"
_block_half = "▏▎▍▋▊█" # left-half-block: ▌  almost-full-block: ▉   right-half-block: ▐▌

class ProgressBar:
    """Show a progress bar"""

    def __init__(self, *maxvals, min=None):
        self.count = len(maxvals)
        self.compound = True
        self.transpose_fns = []
        self.percent_format = None
        self.maxval = 100
        self.min = min
        self.msg = None
        for v in maxvals:
            if v is not None and hasattr(v, '__len__') and len(v) > 1:
                _min, _max = v[0:2]
            else:
                _min = 0
                _max = v
            self.transpose_fns.append( make_transpose_fn( (_min, _max), (0.0, 100.0) ) )

        self.console_width = _get_console_width()
        self.blocks = [0] * self.count
        self.remainders = [0] * self.count
        self.value = [None] * self.count
        self.raw_value = [0] * self.count
        self.always_print = 0
        self.show_percentage = True
        self.last_blocks = [0] * self.count
        self.last_remainders = [0] * self.count
        self.onPrePrint = None
        if self.min is not None and _.first(maxvals) < self.min:
            self.hidden = True
        else:
            self.hidden = False

    def update(self, *values, msg=None):
        if msg is not None:
            self.msg = msg
        if self.hidden:
            return
        _should_print = 0
        for i, value in enumerate(values):
            if value is not None:
                self.raw_value[i] = value
                self.value[i] = self.transpose_fns[i](value)
                self.blocks[i], self.remainders[i] = self.calc_blocks(self.value[i])
                if self.blocks[i] != self.last_blocks[i] or self.remainders[i] != self.last_remainders[i]:
                    _should_print = 1
                    self.last_blocks[i] = self.blocks[i]
                    self.last_remainders[i] = self.remainders[i]
        if self.always_print:
            _should_print = 1
        if _should_print:
            self.print_blocks()

    def calc_blocks(self, value):
        done = self.console_width * value / self.maxval
        whole = int(done)
        remainder = int((done - whole) * len(_block_half))

        # dprint("[calc_blocks] value, done, whole, remainder")
        # print("[calc_blocks] value:{}, done:{}, whole:{}, remainder:{}".format(value, done, whole, remainder))
        
        return whole, remainder
        

    def print_blocks(self):
        #  # blocks = "▁▂▃▅▆▇░▒▓█"  ▐⣹⣹⣹
        #  blocks = b'\xe2\x96\x81\xe2\x96\x82\xe2\x96\x83\xe2\x96\x85\xe2\x96\x86\xe2\x96\x87\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x88'.decode('utf-8')
        #  blocks = b'\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x88'.decode('utf-8')

        drawn = 0
        max_drawn = 0
        blocks = [''] * len(self.blocks)
        for i, value in enumerate(self.blocks):
            actual_v = self.value[i]
            block_v = value // (len(self.blocks) if not self.compound else 1)
            drawn += block_v
            b = _block[i % len(_block)]
            bh = ''
            if i == 0:
                bh = b
                bh = _block_half[self.remainders[i]]
            if self.percent_format:
                pf = self.percent_format(self.raw_value[i], actual_v)
            else:
                pf = "{}%".format(int(actual_v))
            if block_v > len(pf) + 6: #  and len(self.blocks) > 1:
                p = pf # "{}%".format(int(actual_v))
                block_v -= len(p) + 2
                r = block_v // 2
                l = block_v - r
                lhs = b * l
                rhs = b * r
                s = "{}▌{}▐{}".format(lhs, p, rhs)
            else:
                s = b * block_v
            s += bh
            blocks[i] = s
        empty = self.console_width - drawn
        message = ''
        if self.msg:
            message = (" " * self.console_width).join(ascii_box(self.msg, render=False)) + " "
        if six.PY3:
            if self.show_percentage:
                pct = "{}%".format(int(sum(self.value) / (len(self.value) if not self.compound else 1)))
            else:
                pct = ' '.join([str(x) for x in self.raw_value])
            # printcr("{}{}      {}".format(''.join(blocks), ' ' * empty, pct))
            printcr("{}{}{}".format(message, ''.join(blocks), ' ' * empty))
            #  print("[{}{}{}{}{}] {}%".format("\u2591" * self.blocks_bad, "\u2593"* self.blocks_good, "\u2588" * done, decimal, "\u2505" * remain, 100 * self.value // self.maxval))
        else:
            printcr("{}{}%".format(message, int(sum(self.value) / (len(self.value) if not self.compound else 1))))

def progress_demo():

    # w = _get_console_width()
    w = 100
    p = ProgressBar(100, 100)
    # p.percent_format = lambda x, y: "{}".format(x)
    # p = ProgressBar(1000)
    p.always_print = True
    for r in range(w + (w >> 1)):
        p.update(r % w, (w - r) % w, msg=["The value of", "r is {}".format(r)])
        # p.update(r)
        if r % 22 == 0:
            print("Sample of interrupting output...")
        idc.qsleep(50)

    
    ctr_text = "░▒▓█▓▒░┅"
    ctr = 0
    ctr_len = len(ctr_text)
    ctr_interval = 1
    ctr_icount = 0
    ctr_interval_count = 0
    ctr_hpos = 0

def hpos():
    return len(ida_kernwin.msg_get_lines(1)[-1])

@static_vars(current='', last=None)
def printcr(s):
    printcr.current = s
    idc.msg(chr(13) + s)
    # clear cached line after 60 seconds
    if s.strip():
        _printcr_clear_debounced()

def _printcr_clear():
    printcr(' ')
    printcr.current = ''

# clear cached line after 60 seconds
_printcr_clear_debounced = _.debounce(_printcr_clear, 60 * 1000)

def print(*args, **kwargs):
    """
    print(value, ..., sep=' ', end='\n', file=sys.stdout, flush=False)

    Prints the values to a stream, or to sys.stdout by default.
    Optional keyword arguments:
    file:  a file-like object (stream); defaults to the current sys.stdout.
    sep:   string inserted between values, default a space.
    end:   string appended after the last value, default a newline.
    flush: whether to forcibly flush the stream.
    """
    if printcr.current:
        idc.msg(chr(13) + ' ')
        builtins.print(*args, **kwargs)
        idc.msg(printcr.current)
    else:
        builtins.print(*args, **kwargs)


def screenwidth_display_test(m):
    clear()
    idc.msg("\n")
    for x in range(m): idc.msg("# ")
    idc.msg("\n")

@static_vars(r=[], width=100, ratio=7.5)
def screenwidth_process(m, x, y):
    screenwidth_process.r.append((m, x, y))
    return y < 2

def screenwidth_calc():
    # screenwidth_process.width = _.last(_.filter(screenwidth_process.r, lambda v, *a: v[2] == 1))[1]
    screenwidth_process.width = [v[1] for v in screenwidth_process.r if v[2] == 1][-1]
    screenwidth_process.ratio = screenwidth_widget() / screenwidth_process.width
    print("screenwidth is {} characters, char-to-pixel ratio is {:3.5f}".format(screenwidth_process.width, screenwidth_process.ratio))
    progress_demo()

def screenwidth_widget():
    output_window_title = "Output window"
    tw = ida_kernwin.find_widget(output_window_title)
    if not tw:
        raise Exception("Couldn't find widget '%s'" % output_window_title)

    # convert from a SWiG 'TWidget*' facade,
    # into an object that PyQt will understand
    if hasattr(ida_kernwin.PluginForm, 'TWidgetToPyQtWidget'):
        w = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw)
        scrollable = w.childAt(0, 0)
        return scrollable.width()

cmds=[]
def nextcmd():
    if cmds: fake_cli(cmds.pop(0))

def screenwidth_get():
    screenwidth_process.r.clear()
    for x in range(400):
        cmds.append("screenwidth_display_test({}); nextcmd()".format(x))
        cmds.append("if screenwidth_process({}, *ida_kernwin.get_output_cursor()[1:]): nextcmd()".format(x))
    cmds.append("screenwidth_calc()")
    nextcmd()
    return

def binary_search(value, low, high, iterator):
    value = 1
    while low < high:
        mid = (low + high) >> 1
        if iterator(mid) < value:
            low = mid + 1
        else:
            high = mid
    return low

def ProgressEnumerate(iteratee, min=None, **kwargs):
    iteratee = list(iteratee)
    p = ProgressBar(len(iteratee), min=min)
    for k, v in kwargs.items():
        setattr(p, k, v)
    for i, val in enumerate(iteratee):
        p.update(i)
        yield val

    _printcr_clear()

# screenwidth_get()
#
ACS_ULCORNER = "┌" # (0xDA)	/* upper left corner */
ACS_LLCORNER = "└" # (0xC0)	/* lower left corner */
ACS_URCORNER = "┐" # (0xBF)	/* upper right corner */
ACS_LRCORNER = "┘" # (0xD9)	/* lower right corner */
ACS_HLINE    = "─" # (0xC4)	/* horizontal line */
ACS_VLINE    = "│" # (0xB3)	/* vertical line */
ACS_LTEE     = "├" # (acs_map['t'])	/* tee pointing right */
ACS_RTEE     = "┤" # (acs_map['u'])	/* tee pointing left */
ACS_BTEE     = "┴" # (acs_map['v'])	/* tee pointing up */
ACS_TTEE     = "┬" # (acs_map['w'])	/* tee pointing down */
ACS_PLUS     = "┼" # (acs_map['n'])	/* large plus or crossover */
ACS_S1       = "-" # (acs_map['o'])	/* scan line 1 */
ACS_S9       = "_" # (acs_map['s'])	/* scan line 9 */
ACS_DIAMOND  = "♦" # (acs_map['`'])	/* diamond */
ACS_CKBOARD  = "▒" # (acs_map['a'])	/* checker board (stipple) */
ACS_DEGREE   = "°" # (acs_map['f'])	/* degree symbol */
ACS_PLMINUS  = "±" # (acs_map['g'])	/* plus/minus */
ACS_BULLET   = "∙" # (acs_map['~'])	/* bullet */
ACS_LARROW   = "◄" # (acs_map[','])	/* arrow pointing left */
ACS_RARROW   = "◄" # (acs_map['+'])	/* arrow pointing right */
ACS_DARROW   = "▼" # (acs_map['.'])	/* arrow pointing down */
ACS_UARROW   = "▲" # (acs_map['-'])	/* arrow pointing up */
ACS_BOARD    = "░" # (acs_map['h'])	/* board of squares */
ACS_LANTERN  = "○" # (acs_map['i'])	/* lantern symbol */
ACS_BLOCK    = "█" # (acs_map['0'])	/* solid square block */

_color_names = [
            "BLACK", "RED", "GREEN", "BROWN", "BLUE", "MAGENTA", "CYAN", "LIGHTGRAY",
            "DARKGRAY", "LIGHTRED", "LIGHTGREEN", "YELLOW", "LIGHTBLUE", "LIGHTMAGENTA",
            "LIGHTCYAN", "WHITE"
] 
ansi_colors = SimpleAttrDict(_.invert(_color_names))

def splice(target, start, delete_count='', insert=''):
    """
    >>> splice('hello pizza world', 6, 5, 'pasta')
    ('hello pasta world', 'pizza')

    >>> s = 'hello pizza world'
    >>> s, food = splice(s, (6, 5), 'pasta')
    >>> s, food
    ('hello pasta world', 'pizza')
    """
    if isinstance(start, (list, tuple)):
        insert = delete_count
        start, delete_count = start
    delete_count += start
    return target[:start] + insert + target[delete_count:], target[start:delete_count]


def ascii_box(lines, width=0, selected=None, render=True, shadow=False): 
    ns = Namespace()
    ns.x = 0
    ns.y = 0
    nitems = len(lines)
    buffer = [] # ['' * width] * (nitems + 2)
    setglobal('buffer', buffer)
    width = max(width, max([len(line) for line in lines]))

    def ensure(columns, rows):
        rows += 1
        while len(buffer) < rows:
            buffer.append('')
        # buffer[:] = _.map(buffer, lambda v, *a: (v + ' ' * columns)[0:columns])
        for i in range(len(buffer)):
            if len(buffer[i]) < columns:
                buffer[i] += ' ' * (columns - len(buffer[i]))

    def gotoxy(x, y):
        ns.x, ns.y = x, y

    def _putch(s):
        length = len(s)
        ensure(ns.x + length, ns.y)
        buffer[ns.y], *a = splice(buffer[ns.y], ns.x, length, s)
        ns.x += length

    def textattr(*args):
        pass

    def _write_buffer():
        if render:
            for row in buffer:
                print(row.rstrip())
        else:
            return [row.rstrip() for row in buffer]

    x, y = 0, 0
    while True:
        textattr(ansi_colors.CYAN << 4 | ansi_colors.BLACK)
        gotoxy(x, y)

        _putch(ACS_ULCORNER)
        _putch(ACS_HLINE * (width + 2))
        _putch(ACS_URCORNER)

        for i in range(nitems):
            gotoxy(x, y + i + 1)
            _putch(ACS_VLINE)
            _putch(' ')
            if i == selected:
                textattr(ansi_colors.YELLOW)
            s = lines[i]
            _putch(s)
            textattr(ansi_colors.CYAN << 4 | ansi_colors.BLACK)
            gotoxy(x + width + 3, y + i + 1)
            _putch(ACS_VLINE)
            if shadow:
                gotoxy(x + width + 4, y + i + 2)
                _putch(' ' + ACS_BOARD  * 2)

        if shadow:
            gotoxy(x + width + 4, y + nitems + 2)
            _putch(' ' + ACS_BOARD  * 2)

        gotoxy(x, y + nitems + 1)
        _putch(ACS_LLCORNER)
        for i in range(width + 2):
            _putch(ACS_HLINE)
        _putch(ACS_LRCORNER)

        if shadow:
            gotoxy(x + 3, y + nitems + 2)
            _putch(ACS_BOARD * (width + 4))

        return _write_buffer()

