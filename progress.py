# This Python file uses the following encoding: utf-8

"""
[░░░░░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███████████████████▒┅┅┅┅] 95%
"""

import ida_kernwin

def _get_console_width():
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
    else:
        return 100


class ProgressBar:
    """Show a progress bar"""


    def __init__(self, *maxvals):
        self.count = len(maxvals)
        self.compound = True
        self.transpose_fns = []
        self.maxval = 100
        for v in maxvals:
            if v is not None and hasattr(v, '__len__') and len(v) > 1:
                _min, _max = v[0:2]
            else:
                _min = 0
                _max = v
            self.transpose_fns.append( make_transpose_fn( (_min, _max), (0.0, 100.0) ) )

        self.console_width = int(_get_console_width() * 0.10)
        self.blocks = [0] * self.count
        self.value = [None] * self.count
        self.always_print = 0
        self.last_blocks = [0] * self.count
        self.timer = timeit.default_timer
        self.start_time = self.timer()

    def update(self, *values):
        _should_print = 0
        for i, value in enumerate(values):
            if value is not None:
                self.value[i] = self.transpose_fns[i](value)
                self.blocks[i] = self.calc_blocks(self.value[i])
                if self.blocks[i] != self.last_blocks[i]:
                    _should_print = 1
                self.last_blocks[i] = self.blocks[i]
        if self.always_print:
            _should_print = 1
        if _should_print:
            self.print_blocks()

    def calc_blocks(self, value):
        done = self.console_width * value / self.maxval
        whole = int(done)
        return whole
        

    def print_blocks(self):
        #  # blocks = "▁▂▃▅▆▇░▒▓█"
        #  blocks = b'\xe2\x96\x81\xe2\x96\x82\xe2\x96\x83\xe2\x96\x85\xe2\x96\x86\xe2\x96\x87\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x88'.decode('utf-8')
        #  blocks = b'\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x91\xe2\x96\x92\xe2\x96\x93\xe2\x96\x88'.decode('utf-8')

        block = "█▒▓░"
        drawn = 0
        max_drawn = 0
        blocks = [''] * len(self.blocks)
        for i, value in enumerate(self.blocks):
            actual_v = self.value[i]
            block_v = value // (len(self.blocks) if not self.compound else 1)
            drawn += block_v
            b = block[i % len(block)]
            if block_v > 8 and len(self.blocks) > 1:
                p = "{}%".format(int(actual_v))
                block_v -= len(p)
                r = block_v // 2
                l = block_v - r
                lhs = b * l
                rhs = b * r
                s = "{}{}{}".format(lhs, p, rhs)
            else:
                s = b * block_v
            blocks[i] = s
        empty = self.console_width - drawn
        if six.PY3:
            print("[{}{}] {}%".format(''.join(blocks), ' ' * empty, int(sum(self.value) / (len(self.value) if not self.compound else 1))))
            #  print("[{}{}{}{}{}] {}%".format("\u2591" * self.blocks_bad, "\u2593"* self.blocks_good, "\u2588" * done, decimal, "\u2505" * remain, 100 * self.value // self.maxval))
        else:
            print("{}%".format(int(sum(self.value) / (len(self.value) if not self.compound else 1))))
