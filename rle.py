import itertools
from six.moves import collections_abc

def indexing_decorator(func):
    def decorated(self, index, *args):
        raise IndexError("Don't mess with the list")
        return func(self, index, *args)
    return decorated

class RunLengthList(collections_abc.MutableSequence):
    def __init__(self, counts=None, items=None):
        self.count = counts or list()
        self.items = items or list()

    def __len__(self):
        return len(self.items)

    @indexing_decorator
    def __delitem__(self, index):
        self.count.__delitem__(index)
        self.items.__delitem__(index)

    @indexing_decorator
    def insert(self, index, value):
        self.count.insert(index, value[0])
        self.items.insert(index, value[1])

    @indexing_decorator
    def __setitem__(self, index, value):
        self.count.__setitem__(index, value[0])
        self.items.__setitem__(index, value[1])

    def __getitem__(self, index):
        return self.items[index], self.count[index]

    def __iter__(self):
        return itertools.zip_longest(self.count, self.items)

    def index(self, value, start=0, stop=9223372036854775807):
        return self.items.index(value, start, stop)

    def copy(self):
        return RunLengthList(self.count[:], self.items[:])

    def append(self, value):
        if not self.items or value != self.items[-1]:
            self.count.append(1)
            self.items.append(value)
        else:
            self.count[-1] += 1

def test_RunLengthList():
    rle = RunLengthList()
    for i in [0, 20, 28, 80, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 0]:
        rle.append(i)
    print(len(rle))
    print(rle[-1])
    print([x for x in rle])
    print(max(rle))
    m = max(rle)
    print(rle.index(m[1]))
    return rle

"""
class list(object)
 |  list(iterable=(), /)
 |  
 |  Built-in mutable sequence.
 |  
 |  If no argument is given, the constructor creates a new empty list.
 |  The argument must be an iterable if specified.
 |  
 |  Methods defined here:
 |  
 |  __add__(self, value, /)
 |      Return self+value.
 |  
 |  __contains__(self, key, /)
 |      Return key in self.
 |  
 |  __delitem__(self, key, /)
 |      Delete self[key].
 |  
 |  __eq__(self, value, /)
 |      Return self==value.
 |  
 |  __ge__(self, value, /)
 |      Return self>=value.
 |  
 |  __getattribute__(self, name, /)
 |      Return getattr(self, name).
 |  
 |  __getitem__(...)
 |      x.__getitem__(y) <==> x[y]
 |  
 |  __gt__(self, value, /)
 |      Return self>value.
 |  
 |  __iadd__(self, value, /)
 |      Implement self+=value.
 |  
 |  __imul__(self, value, /)
 |      Implement self*=value.
 |  
 |  __init__(self, /, *args, **kwargs)
 |      Initialize self.  See help(type(self)) for accurate signature.
 |  
 |  __iter__(self, /)
 |      Implement iter(self).
 |  
 |  __le__(self, value, /)
 |      Return self<=value.
 |  
 |  __len__(self, /)
 |      Return len(self).
 |  
 |  __lt__(self, value, /)
 |      Return self<value.
 |  
 |  __mul__(self, value, /)
 |      Return self*value.
 |  
 |  __ne__(self, value, /)
 |      Return self!=value.
 |  
 |  __repr__(self, /)
 |      Return repr(self).
 |  
 |  __reversed__(self, /)
 |      Return a reverse iterator over the list.
 |  
 |  __rmul__(self, value, /)
 |      Return value*self.
 |  
 |  __setitem__(self, key, value, /)
 |      Set self[key] to value.
 |  
 |  __sizeof__(self, /)
 |      Return the size of the list in memory, in bytes.
 |  
 |  append(self, object, /)
 |      Append object to the end of the list.
 |  
 |  clear(self, /)
 |      Remove all items from list.
 |  
 |  copy(self, /)
 |      Return a shallow copy of the list.
 |  
 |  count(self, value, /)
 |      Return number of occurrences of value.
 |  
 |  extend(self, iterable, /)
 |      Extend list by appending elements from the iterable.
 |  
 |  index(self, value, start=0, stop=9223372036854775807, /)
 |      Return first index of value.
 |      
 |      Raises ValueError if the value is not present.
 |  
 |  insert(self, index, object, /)
 |      Insert object before index.
 |  
 |  pop(self, index=-1, /)
 |      Remove and return item at index (default last).
 |      
 |      Raises IndexError if list is empty or index is out of range.
 |  
 |  remove(self, value, /)
 |      Remove first occurrence of value.
 |      
 |      Raises ValueError if the value is not present.
 |  
 |  reverse(self, /)
 |      Reverse *IN PLACE*.
 |  
 |  sort(self, /, *, key=None, reverse=False)
 |      Stable sort *IN PLACE*.
 |  
 |  ----------------------------------------------------------------------
 |  Static methods defined here:
 |  
 |  __new__(*args, **kwargs) from builtins.type
 |      Create and return a new object.  See help(type) for accurate signature.
 |  
 |  ----------------------------------------------------------------------
 |  Data and other attributes defined here:
 |  
 |  __hash__ = None
"""
