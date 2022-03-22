import textwrap
import html
from collections import defaultdict

def array(*args):    return defaultdict(array)
def array_keys(a):  return range(len(a)) if isinstance(a, list) else a.keys()
def array_shift(a): return a.pop(0)
def foreach(a):      return enumerate(a) if isinstance(a, list) else a.items()
def implode(by, a): return by.join(a)
def count(a):         return len(a)
def strlen(a):        return len(a)
def ahex(item):      return hex(item) if isinstance(item, int) and (item > 9 or item < 9) else str(item)
def A(o):              return o if isinstance(o, list) else [o]
def shorten(s, width, placeholder='[...]'):
    return s[:width] if len(s) <= width else s[:width-len(placeholder)] + placeholder

def indent(n1, n2, s, stripEmpty=True):
    if isinstance(s, str):
        s = s.replace('\r', '').split('\n')

    result = []
    count = -1
    for line in s:
        if isinstance(line, list):
            print("[indent] line: {}".format(line))
        if not stripEmpty or line.rstrip():
            count += 1
            if count == 0:
                n = n1
            else:
                n = n2
            if isinstance(n, str):
                result.append(n + line)
            elif isinstance(n, int):
                result.append("  " * n + line)

    return "\n".join(result)

def array_pad(a, length, value):
    len_a = len(a)
    if abs(length) <= len_a: return a
    if length < 0:
        amt = 0 - (len_a + length)
        return [value] * amt + a
    else:
        amt = length - len_a
        return a + [value] * amt

class MakeRows(object):
    def __init__(self, width=80):
        self.clear()
        self.width = width

    def clear(self):
        self.data = dict()
        self.numrows = dict()
        self.nameWidths = dict()
        self.valueWidths = dict()
        self.headerWidths = dict()

    def add(self, _name, _value):
        _value = str(_value)
        if _name in self.data:
            _name = _name + ' '
        self.data[_name] = _value;
        self.nameWidths[_name] = strlen(_name)
        self.valueWidths[_name] = strlen(_value)

    def addHeading(self, _value):
        _name = '#{}'.format(len(self.data.keys()))
        self.data[_name] = _value;
        self.headerWidths[_name] = strlen(_value)
        self.valueWidths[_name] = 0
        self.nameWidths[_name] = 0

    def addBreak(self):
        _name = '#{}'.format(len(self.data.keys()))
        _value = '-'
        self.data[_name] = _value;
        self.valueWidths[_name] = 0
        self.nameWidths[_name] = 0

    def __str__(self):
        #  import shutil
        #  size = shutil.get_terminal_size((80, 20))  # pass fallback
        #  columns = size.columns
        #  print("size: {}".format(size))
        #  os.terminal_size(columns=87, lines=23)  # returns a named-tuple
        columns = self.width

        headerWidth = max(self.headerWidths.values())
        nameWidth   = max(self.nameWidths.values())
        valueWidth  = max(self.valueWidths.values())

        if headerWidth + 4 > columns:
            #  columns = headerWidth + 4
            headerWidth = columns - 4

        if nameWidth + valueWidth + 7 > columns:
            valueWidth = columns - nameWidth - 7

        columns = valueWidth + nameWidth + 7

        headerLine = '+-' + '-' * nameWidth + '-+-' + '-' * valueWidth + '-+'

        _output = []
        _output.append(headerLine)
        for k, v in self.data.items():
            if k[0] == '#':
                if v != '-':
                    _output.append('| {} |'.format(shorten(v, width=headerWidth, placeholder='...').center(columns - 4)))
                _output.append(headerLine)
            else:
                _output.append(indent(
                    '| {} | '.format(k.ljust(nameWidth)), 
                    '| {} | '.format(''.ljust(nameWidth)),
                        [x.ljust(valueWidth) + ' |' for x in textwrap.wrap(v, valueWidth)]
                ))
        _output.append(headerLine)
        return implode("\n", _output) + "\n"

    def html_escape(self, s):
        return html.escape(s, True)

    def asDotTable(self):
        columns = self.width

        headerWidth = max(self.headerWidths.values())
        nameWidth   = max(self.nameWidths.values())
        valueWidth  = max(self.valueWidths.values())

        _output = ['']
        _output.append('<TABLE>')
        for k, v in self.data.items():
            _output.append('  <TR>')
            if k[0] == '#':
                if v != '-':
                    _output.append('    <TD COLSPAN="2">{}</TD>'.format(self.html_escape(v)))
                #  _output.append(headerLine)
            else:
                _output.append('      <TD>{}</TD>'.format(self.html_escape(k)))
                _output.append('      <TD>{}</TD>'.format(self.html_escape(v)))

            _output.append('  </TR>')
        #  _output.append(headerLine)
        _output.append('</TABLE>')
        return implode("\n", _output)
# vim: set ts=4 sts=4 sw=4 et:
