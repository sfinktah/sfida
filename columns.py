from collections import defaultdict

def array(*args):
   return defaultdict(array)
def array_keys(a):
   if isinstance(a, list):
      return range(len(a))
   return a.keys()
def array_shift(a):
   return a.pop(0)
def foreach(a):
   if isinstance(a, list):
      return enumerate(a)
   return a.items()
def implode(by, a):
   if isinstance(a, list):
      return by.join(a)
   raise TypeError('Not a list')
def count(a):
   return len(a)
def strwraplen(a):
   return max([len(x) for x in a.split('\n')])

def ahex(item):
    if isinstance(item, int):
        if item > 9 or item < 9:
            return hex(item) # & ~0xff00000000000000)
    return str(item)

def clamp(val, minval, maxval):
    if val < minval: return minval
    if val > maxval: return maxval
    return val

def genAsList(o):
  return [x for x in o]

def isgenerator(iterable):
  return hasattr(iterable,'__iter__') and not hasattr(iterable,'__len__')

def isflattenable(iterable):
  return hasattr(iterable,'__iter__') and not hasattr(iterable,'isalnum')

def flatten(t):
  l = []
  try:
      for item in t:
          if isflattenable(item):
              l.extend(flatten(item))
          else:
              l.append(item)
  except TypeError:
      l.append(t)
  return l

def A(o):
    if o is None:
        return []
    elif isinstance(o, list):
        return o
    elif isflattenable(o) and len(list(o)) > 1:
        return list(o)
    elif isflattenable(o):
        return genAsList(o)
    else:
        return [o]


def array_pad(a, length, value):
   len_a = len(a)
   if abs(length) <= len_a: return a
   if length < 0:
      amt = 0 - (len_a + length)
      return [value] * amt + a
   else:
      amt = length - len_a
      return a + [value] * amt



class MakeColumns(object):
   def __init__(self):
      self.clear()

   def clear(self):
      self.data = defaultdict(list)
      self.numrows = dict()
      self.skiprows = 0
      self.widest = array()

   def addSqlResult(self, _array, **kwargs):
      _data = array()
      for _rownum, _row in foreach(_array):
         for _key, _value in foreach(_row):
            _data[_key][_rownum] = _value
      for _key, _column in foreach(_data):
         self.addColumn(_column, _key, **kwargs)

   def addArray(self, _array, **kwargs):
      _fields = array()
      for _record in _array:
         for _key, _value in foreach(_record):
            _fields[_key] = _key

      for _rownum, _record in foreach(_array):
         for _key in _fields:
            _data[_key][_rownum] = _record[_key] or ''

      for _key, _column in foreach(_data):
         self.addColumn(_column, _key, **kwargs)

   def addRow(self, _row, **kwargs):
      for _key, _value in foreach(_row):
         self.addColumn(A(_value), _key, **kwargs)

   def addRows(self, _rows, **kwargs):
      for _row in _rows:
         for _key, _value in foreach(_row):
            self.addColumn(A(_value), _key, **kwargs)

   def addColumn(self, _data, _name = "", **kwargs):
      _data = [ahex(x) for x in _data]
      self.data[_name].extend(_data)
      self.widest[_name] = self.widest.get(_name, 0)
      self.numrows[_name] = self.numrows.get(_name, 0)
      self.numrows[_name] += count(_data)
      _width = strwraplen(_name) if isinstance(_name, str) else 0
      for _value in _data:
         _width = max(strwraplen(_value), _width)
      if 'max_width' in kwargs:
         _width = clamp(_width, 0, kwargs['max_width'])
      self.widest[_name] = max(self.widest[_name], _width)
      return _data

   def clearAll(self):
      _maxnumrows = max(self.numrows.values())
      for k, v in self.data.items():
          self.data[k] = array_pad(v, _maxnumrows, '')
          self.numrows[k] = len(self.data[k])


   def __str__(self):
      if not self.numrows:
         return ''
      _output = array()
      _skiprows = self.skiprows
      _maxnumrows = max(self.numrows.values())
      for k, v in self.data.items():
         self.data[k] = array_pad(v, _maxnumrows, '')
         self.numrows[k] = len(self.data[k])
      _maxnumrows = max(self.numrows.values())
      _minnumrows = min(self.numrows.values())
      _skiprows = _maxnumrows - _minnumrows
      _header = ""
      _header_underline = ""
      for _key, _data in foreach(self.data):
         _pad = _maxnumrows - self.numrows[_key]
         _output[_key] = array_pad(_data, 0-_pad, "0")
      _columns = array_keys(_output)
      _lines = list()
      _underline = ""

      #  for (_i = _skiprows - 1; _i < _maxnumrows; _i ++)
      for _i in range(_skiprows - 1, _maxnumrows):
         _underline = _line = ""
         for _c in _columns:
            _width = self.widest[_c]
            if _i == _skiprows - 1:
               _datum = _c
            else:
               _datum = array_shift(_output[_c])
            # _line += f"%-{_width}s " % _datum
            _line = _line + _datum.ljust(_width) + ' '
            #  _line += ("%-" + str(_width) + "s ") % _datum
            if not _header_underline:
               #  _underline += f"%-{_width}s " % ('-' * _width)
               _underline += ("%-" + str(_width) + "s ") % ('-' * _width)

         if _underline:
            _header_underline = _underline

         if _i == _skiprows - 1:
            _header = _line
            _lines.append(_header)
            _lines.append(_header_underline)
         else:
            if _line.strip():
               _lines.append(_line)
         if False and not (count(_lines) % 30) and _maxnumrows - _i > 10:
            _lines.append("")
            _lines.append(_header)
            _lines.append(_header_underline)

      return implode("\n", _lines) + "\n"

#  c = MakeColumns()
#  c.addColumn([1,2,3,4,5], "Numbers")
#  #  c.addColumn(array(1,2,3,4,5), "Numbers")
#  #  c.addColumn(array("Pink", "Yellow", "Green", "Turquiose", "Paisely"), "Colors")
#  c.addColumn(["Orange", "Marmalade", "Pink", "Yellow", "Green", "Turquiose", "Paisely"], "Colors")
#  c.addRow({'Numbers': 7, 'Colors': ['White', 'Red', 'Blue']})
#  print(str(c))
#  print(c.data)
#  
#  Numbers Colors    
#  ------- --------- 
#  0x1     Pink      
#  0x2     Yellow    
#  0x3     Green     
#  0x4     Turquiose 
#  0x5     Paisely   
#  0x7     White     
#  
