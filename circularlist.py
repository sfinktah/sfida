import itertools
import re
from pprint import PrettyPrinter
from mypprint import MyPrettyPrinter
from collections import defaultdict
from execfile import execfile, _import
from attrdict1 import AttrDict
#  _import('from sfida.sf_string_between import *')
#  _import('from hotkey_utils import stutter_chunk')
# execfile('hotkey_utils')

class CircularList(object):
    """
    https://stackoverflow.com/questions/4151320/efficient-circular-buffer/40784706#40784706
    """

    def __init__(self, size, data=[]):
        """Initialization"""
        self.size = size
        self._data = list(data)[-size:]
        self.end = len(self._data) % self.size

    def clear(self):
        self.__init__(self.size, [])

    def extend(self, data):
        self._data.extend(data)
        self._data = self._data[-self.size:]
        self.end = len(self._data) % self.size

    def resize(self, size):
        self.__init__(size, self.as_list())

    def copy(self):
        return type(self)(self.size, self.as_list())
        
    def restart(self, size):
        self.__init__(self.size, self.as_list()[0:size])

    def pop(self, index=-1):
        """
        Remove and return item at index (default last).

        Raises IndexError if list is empty or index is out of range.
        """
        if not self._data:
            raise IndexError("pop from empty list")
        try:
            idx = (index + self.end) % len(self._data)
            result = self._data.pop(idx)
            self.size -= 1
            self.end -= 1
            return result

        except IndexError as ex:
            print(("Exception: ", ex))
            print(("index", index, "size", len(self._data)))
            raise IndexError(ex)

    def append(self, value):
        """Append an element"""
        if len(self._data) == self.size:
            self._data[self.end] = value
        else:
            self._data.append(value)
        self.end = (self.end + 1) % self.size

    def __iter__(self):
        for v in self.as_list():
            yield v

    def pattern_transform(self, pattern):
        return string_between('({', '}', pattern, inclusive=1, repl= \
                lambda v: '(?P<{}>'.format(string_between('({', '}', v)))

    def multimatch(self, pattern_list, flags=0):
        matches = []
        group_matches = dict()
        group_matches['default'] = matches
        last_pattern = self.pattern_transform(pattern_list[-1])
        if not re.search(last_pattern, self[-1], flags):
            return None
        pattern_iter = iter(stutter_chunk([self.pattern_transform(x) for x in pattern_list], 2, 1))
        pattern, peek = next(pattern_iter)
        pattern_count = 0
        buffer_count = len(self._data)
        repetitions = defaultdict(list)
        i = -1
        while i+1 < buffer_count:
            i += 1
            l = self[i]
            if pattern.endswith(('++', '**', '++?', '**?')):
                multi = True
                greedy = True
                if pattern.endswith('?'):
                    greedy = False
                    pattern = pattern[0:-1]

                if pattern.endswith('++'):
                    min = 1
                elif pattern.endswith('**'):
                    min = 0
                pattern = pattern[0:-2]
            else:
                multi = greedy = False
            #  if multi:
                # dprint("[multi] multi, min, pattern")
                #  print("[multi] multi:{}, min:{}, pattern:{}".format(multi, min, pattern))
                
            m = re.search(pattern, l, flags)
            if multi and not greedy and peek:
                mpeek = re.search(peek, l, flags)
            else: 
                mpeek = None
            if not m:
                if multi and len(repetitions[pattern_count]) >= min:
                    try:
                        pattern, peek = next(pattern_iter)
                        # dprint("[multi] pattern")
                        #  print("[multi] pattern:{}".format(pattern))
                        
                        pattern_count += 1
                    except StopIteration:
                        if i == buffer_count - 1:
                            if len(group_matches):
                                return AttrDict(group_matches)
                            return matches

            elif m and mpeek and multi and not greedy and len(repetitions[pattern_count]) >= min:
                m = mpeek
                pattern, peek = next(pattern_iter)
                # dprint("[multi-peek-advance] m")
                #  print("[multi-peek-advance] m:{}".format(m))
                
                pattern_count += 1
            if m:
                matches.append(m)
                # dprint("[multi] m")
                #  print("[either] m:{}".format(m))
                
                for k, v in m.groupdict().items():
                    if k not in group_matches:
                        group_matches[k] = []
                    group_matches[k].append(v)
                    # dprint("[multi] k, v")
                    #  print("[either] k:{}, v:{}".format(k, v))
                    
                if multi:
                    repetitions[pattern_count].append(m)
                    # dprint("[multi] repetitions[pattern_count]")
                    #  print("[multi] repetitions[pattern_count]:{}".format(repetitions[pattern_count]))
                    
                elif not multi:
                    try:
                        pattern, peek = next(pattern_iter)
                        #  print("[non-multi] pattern:{}".format(pattern))
                        pattern_count += 1
                    except StopIteration:
                        if i == buffer_count - 1:
                            if len(group_matches):
                                return AttrDict(group_matches)
                            return matches
                    # if debug: print("not matched as there are {} items remaining".format(buffer_count - i - 1))
        return None

    def as_list(self):
        return self._data[self.end:] + self._data[:self.end]

    def __len__(self):
        return len(self._data)

    def __getitem__(self, key):
        """Get element by end, relative to the current end"""
        try:
            if len(self._data) == self.size:
                idx = (key + self.end) % self.size
            else:
                idx = key % len(self._data)
            return self._data[idx]
            #  if len(self._data) == self.size:
                #  return self._data[(key + self.end) % self.size]
            #  else:
                #  return self._data[key]

        except IndexError as ex:
            print(("Exception: ", ex))
            print(("key", key, "size", len(self._data)))
            raise IndexError(ex)

    def __repr__(self):
        """Return string representation"""
        return 'Circular List: ' + self.as_list().__repr__() + ' (' + str(len(self._data)) + 'out of ' + str(
            self.size) + ' items)'

    # produce pprint compatible object, easy as pie!
    def __pprint_repr__(self):
        return { 'CircularList': self.as_list() }

    # to take total control (python 3)
    def __pprint__(self, object, stream, indent, allowance, context, level):
        stream.write('CircularList(\n')
        self._format(object._data, stream, indent, allowance + 1, context, level)
        stream.write(')')
        pass

