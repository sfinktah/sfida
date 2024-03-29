## The Generic Rangertte

import os
from exectools import make_refresh
from sortedcontainers import SortedList
refresh_ranger = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
""" 
note: length is (end + 1) -- its a bug^H^H^Hfeature
      so start of next instruction is (start + length) == (end + 1)
"""

class GenericRange(object):
    endash = '\u2013'
    formatter = None

    def __init__(self, start=None, trend=None, sacrificial=None, last=None, end=None, length=None, ctx=None):
        self._start = start
        self._last = None
        self._ctx = ctx
        args = {'sacrificial':sacrificial, 'last':last, 'trend':trend, 'end':end, 'length':length}
        argc = sum([x is not None for x in args.values()])
        if argc > 1 or end is not None or sacrificial is not None: # or (trend is None and length is None and last is None):
                    raise SyntaxError("GenericRange: please use GenericRange(start=x, last=y|trend=y+1|length=1+y-x")

        if last is not None:
            self._last = last
        elif trend is not None:
            self._last = trend - 1
        elif length is not None:
            self._last = self._start + length - 1
        else:
            if hasattr(start, 'start') or isinstance(start, tuple) and len(start) == 2:
                self._start = get_start(start)
                self._last = get_last(start)
            elif hasattr(start, '__iter__') and len(list(start)) > 1:
                l = list(start)
                self._start, self._last = l[0], l[-1]

        if self._start and self._last and self._start > self._last:
            if self._last < 0xffffffff and self._start > 0xffffffff:
                self._last += self._start
            else:
                self._start, self._last = self._last, self._start

    def __repr__(self):
        return "{:x}{}{:x}".format(self.start, self.endash, self.last) if self.last != self.start else "{:x}".format(self.start)

    def __getitem__(self, index):
        if index < 0:
            index += len(self)
        r = self.start + index
        if r > self.last:
            raise IndexError()
        return r

    def __iter__(self):
        i = self.start
        while i <= self.last:
            yield i
            i += 1 

    def chunk(self):
        return self.start, self.last + 1

    def issubset(self, other):
        return issubset(self, other)

    def issuperset(self, other):
        return issuperset(self, other)

    def asTuple(self):
        return (self.start, self.last + 1)

    def __key(self):
        return (self.start, self.last)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.__key() == other.__key()
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, type(self)):
            return self.start < other.start
        return NotImplemented

    def __len__(self):
        """ this will now return correct lengths (subtract 1 for old behaviour) """
        if self.start is None or self.last is None:
            return 0
        return self.trend - self.start

    @property
    def length(self):
        return self.__len__()

    @length.setter
    def length(self, value):
        diff = value - self.__len__()
        self._last += diff

    @property
    def length_sub_1(self):
        return self.__len__() - 1

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    @property
    def last(self):
        return self._last

    #  @property
    #  def stop(self):
        #  return self._last

    @last.setter
    def last(self, value):
        self._last = value


    @property
    def trend(self):
        return self._last + 1

    @property
    def stop(self):
        return self._last + 1

    @trend.setter
    def trend(self, value):
        self._last = value - 1






def GenericRanger(genericRange, sort, outsort=True, prefilter=None, iteratee=None, input_filter=None):

    def adjoins(r1, r2):
        """Does the range r1 adjoin or overlap the range r2?"""
        return get_last(r1) + 1 >= get_start(r2) and get_last(r2) + 1 >= get_start(r1)

    def union(r1, r2):
        try:
            return type(r1)([min(get_start(r1), get_start(r2)), max(get_last(r1), get_last(r2))])
        except TypeError:
            return type(r1)(min(get_start(r1), get_start(r2)), max(get_last(r1), get_last(r2)))


    def check_overlap(array, element):
        return [x for x in array if adjoins(x, element)]

    def append(result, group):
        group = lengthify(group)
        #  for item in check_overlap(result, group):
            #  result.remove(item)
            #  group = union(group, item)

        result.append(group)

    def asList(o):
        return list(o)

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

    def lengthify(group):
        if group.last is None:
            group.last = group.start
        if iteratee and callable(iteratee):
            print("Should this be group.last or group.trend?")
            result = iteratee(group.start, group.last)
            if result and isflattenable(result):
                r = GenericRange(result)
                group = r
        return group
        #  if not 'end' in group:
            #  group.end = group.start
        #  group.length = group.end - group.start + 1
        #  return iteratee(group.start, group.end) if iteratee else group


    if genericRange is None:
        return list()

    # convert ranges to `GenericRange`s
    if isinstance(genericRange, GenericRange):
        genericRange = list(range(genericRange.start, genericRange.trend))
    elif not input_filter:
        if not isinstance(genericRange, (list, set)):
            gr = GenericRange(genericRange)
            genericRange = list(range(gr.start, gr.trend))
        else:
            if _.all(genericRange, lambda v, *a: isinstance(v, tuple) and len(v) == 2):
                genericRange = [GenericRange(*x) for x in genericRange]

    if input_filter is None:
        genericRange = flatten(genericRange)
    else:
        genericRange = input_filter(genericRange)
    
    if len(genericRange) == 0:
        return list()

    end = None
    start = None
    result = []
    group = GenericRange()

    if prefilter is None:
        prefilter = lambda x: x

    ## We cannot trust fool users to pre-sort things
    if sort:
        genericRange.sort()

    #  genericRange = _.uniq(genericRange)

    for n in prefilter(genericRange):
        if n == end:
            continue

        if end is not None and n == end + 1:
            if start is None:
                start = end
            end = n
            continue

        if start is not None:
            if end > start:
                group.last = end
                start = None
            else:
                raise RuntimeError("This point never reached")

        if group.start is not None:
            append(result, group)

        group = GenericRange(start=n)
        
        end = n

    ## If we were counting out a range, then it's over now.
    if start:
        group.last = end

    append(result, group)

    #  result = [lengthify(g) for g in result]
    if outsort:
        result.sort(key=lambda x, *a: x.start)
    return result

def insn_filter(o):
    """
    Convert a list of Heads into consecutive addresses
    """
    result = []
    for k in o:
        for i in range(GetInsnLen(k)):
            result.append(k + i)

    return result

def patchmap_filter(o):
    result = []
    for k in o:
        for i in range(len(o[k])):
            result.append(k + i)
    return result

def GenericRangerHealer(genericRange, sort, outsort = True, iteratee = None, apply=0, show=0):
    expanded = {}
    print("expanding...")
    for k, v in genericRange.items():
        for i, b in enumerate(genAsList(v)):
            expanded[k + i] = b

    result = {}
    results = []
    print("ranging...")
    gr = GenericRanger(list(_.keys(expanded)), sort=sort, outsort=outsort, iteratee=iteratee)
    print("coagulating...")
    for r in gr:
        b = bytearray()
        #  print("r.start, r.end, diff: {}", hex(r.start), hex(r.end), r.end - r.start)
        
        if r.start > ida_ida.cvar.inf.min_ea:
            for i in range(r.start, r.trend):
                b.append(expanded[i])
                # dprint("[debug] b")
                #  print("[debug] b:{}".format(b))

            result[r.start] = b
                
            if False:
                results.append("PatchBytes(0x{:x}, '{}')".format(r.start, listAsHex(b)))
            if apply:
                PatchBytes(r.start, listAsHex(b))

            if show:
                fnName = GetFuncName(r.start)
                if fnName:
                    results.append("; func {}".format(fnName))
                    results.append("{}: ; {}".format(idc.get_name(r.start) or "loc_{:X}".format(r.start), hex(r.start)))
                for insn in diida(r.start, len(b), asBytes(b), iterate=1):
                    if insn.endswith(':'):
                        results.append(insn)
                    else:
                        results.append("    {}".format(insn))
                # print(diInsns(b, r.start))
                #  print("\n")
                #  result[r.start] = diInsns(b, r.start)[-1:]

    if show:
        return results
    return result

def get_start(r):
    return r.start if hasattr(r, 'start') else r[0]

def get_last(r):
    if hasattr(r, 'last'):
        return r.last
    if hasattr(r, 'stop'):
        return r.stop - 1
    return r[-1] - 1


class GenericRanges:
    """Collection of GenericRange(s)"""

    def __init__(self, genericRanges=None, cmp=adjoins):
        """
        describe_target

        @param cmp: comparison function (default: adjoins) see also: overlaps
        """

        # Be intentionally vague to allow "upgrading" of previous iterations of objects
        if type(genericRanges).__name__ == 'GenericRanges':
            self.cmp = genericRanges.cmp
            self.genericRanges = genericRanges.genericRanges.copy()
            self.optimize()
        else:
            self.cmp = cmp
            self.genericRanges = SortedList(key=lambda v: v[1])
            if genericRanges:
                self.genericRanges = SortedList([(get_start(x), get_last(x) + 1) for x in genericRanges])
                self.optimize()

    def __repr__(self):
        return 'GenericRanges([' + ', '.join([ahex(x) for x in self.genericRanges]).replace('[', '(').replace(']', ')') + '])'
        # return repr(ahex(list(self.genericRanges)))

    def __len__(self):
        return self.genericRanges.__len__()
    
    def __getitem__(self, key):
        return self.genericRanges.__getitem__(key)
    
    def __setitem__(self, key, value):
        self.genericRanges.__setitem__(key, value)
    
    def __delitem__(self, key):
        self.genericRanges.__delitem__(key)
    
    def __iter__(self):
        return self.genericRanges.__iter__()
    
    def __reversed__(self):
        return self.genericRanges.__reversed__()

    def __eq__(self, other):
        pass
    
    def __ne__(self, other):
        pass
    
    def __lt__(self, other):
        pass
    
    def __le__(self, other):
        pass
    
    def __gt__(self, other):
        pass
    
    def __ge__(self, other):
        pass
    
    def __cmp__(self, other):
        pass

    #  def __copy__(self):
        #  cls = self.__class__
        #  result = cls.__new__(cls)
        #  result.__dict__.update(self.__dict__)
        #  return result

    def copy(self):
        # newone = type(self)(self.genericRanges.copy(), cmp=self.cmp)
        newone = GenericRanges(self.genericRanges.copy(), cmp=self.cmp)
        return newone

    #  def __deepcopy__(self, memo):
        #  cls = self.__class__
        #  result = cls.__new__(cls)
        #  memo[id(self)] = result
        #  for k, v in self.__dict__.items():
            #  setattr(result, k, deepcopy(v, memo))
        #  return result
    
    def __indexOf__(self, item):
        if isinstance(item, int):
            right = self.genericRanges.bisect_left((item, item)) + 1
            left = right - 2
            right = min(right, len(self.genericRanges))
            left = max(0, left)
            for i in range(left, right):
                try:
                    r = self.genericRanges[i]
                except IndexError:
                    # dprint("[__indexOf__] i, left, right, len(self), len(self.genericRanges)")
                    print("[__indexOf__] i: {}, left: {}, right: {}, len(self): {}, len(self.genericRanges): {}".format(i, left, right, len(self), len(self.genericRanges)))
                    raise

                #  if get_start(r) <= item < get_last(r):
                #  if self.cmp(r, (item, item)):
                if overlaps(r, (item, item + 1)):
                    return i
        else:
            right = self.genericRanges.bisect_left((item)) + 1
            left = right - 2
            right = min(right, len(self))
            left = max(0, left)
            if left < 0:
                left = 0
            for i in range(left, right):
                try:
                    r = self.genericRanges[i]
                except IndexError:
                    # dprint("[__indexOf__] i, left, right, len(self), len(self.genericRanges)")
                    print("[__indexOf__] i: {}, left: {}, right: {}, len(self): {}, len(self.genericRanges): {}".format(i, left, right, len(self), len(self.genericRanges)))
                    raise
                if issubset(item, r):
                    return i
        return -1

    def find(self, item):
        found = self.__indexOf__(item)
        if ~found:
            return self[found]


    def __contains__(self, item):
        return ~self.__indexOf__(item)
    
    def append(self, object):
        #  if not IsValidEA(object):
            #  print("GenericRanges::append: InvalidEA({})".format(ahex(object)))
            #  return
        object = (get_start(object), get_last(object) + 1)
        if object[1] <= object[0]:
            raise ValueError("{} <= {}".format(ahex(object[1]), ahex(object[0])))
        if object[1] - object[0] > 65535:
            raise ValueError("{} - {} > 64k".format(ahex(object[1]), ahex(object[0])))

        if isinstance(self.genericRanges, list):
            idx = indexOfSet(self.genericRanges, object, self.cmp)
            if ~idx:
                    self.genericRanges[idx] = union(self.genericRanges[idx], object)
                    #
                    # XXX: the new range may join two existing ranges
                    if len(self.genericRanges) > idx and self.cmp(self.genericRanges[idx], self.genericRanges[idx+1]):
                        self.genericRanges[idx] = union(self.genericRanges[idx], self.genericRanges[idx+1])
                        self.genericRanges.pop(idx+1)
                    return
        else:
            left = self.genericRanges.bisect_left((get_start(object), get_start(object) + 1)) - 1
            right = self.genericRanges.bisect_left((get_last(object) + 1, get_last(object) + 2)) + 1
            right = min(right, len(self.genericRanges))
            left = max(0, left)
            overlapping = filterSet(self.genericRanges[left:right], object, self.cmp)
            if overlapping:
                new = object
                for r in overlapping:
                    new = union(r, object)
                    self.genericRanges.remove(r)
                self.genericRanges.add(new)
                return

        # self.genericRanges.append(object)
        self.genericRanges.add(object)
        # TODO: replace with lowerbounds insert
        self.sort()

    def intersection(self, object):
        left = self.genericRanges.bisect_left((get_start(object), get_start(object) + 1)) - 1
        right = self.genericRanges.bisect_left((get_last(object) + 1, get_last(object) + 2)) + 1
        right = min(right, len(self.genericRanges))
        left = max(0, left)
        overlapping = filterSet(self.genericRanges[left:right], object, overlaps)
        if overlapping:
            new = set()
            for r in overlapping:
                new.update([x for x in range(get_start(r), get_last(r) + 1)])
            # dprint("[debug] new, object")
            print("[debug] new: {}, object: {}".format(ahex(new), ahex(object)))
            
            return new.intersection([x for x in range(get_start(object), get_last(object) + 1)])


    def clear(self):
        self.genericRanges.clear()
    
    def copy(self):
        return (type(self))(self.genericRanges.copy())
    
    def count(self):
        return self.genericRanges.count()
    
    def extend(self, iterable):
        self.genericRanges += SortedList([(get_start(x), get_last(x) + 1) for x in iterable])
        self.optimize(quiet=True)

        # very slow
        #  for item in iterable:
            #  self.append(item)

    def __add__(self, iterable):
        tmp = self.copy()
        tmp.extend(iterable)
        return tmp

    update = extend
    add = append
    
    def index(self, value, start=0, stop=9223372036854775807):
        return self.genericRanges.index(value, start, stop)
    
    #  def insert(self):
        #  self.genericRanges.insert()
    
    def pop(self):
        self.genericRanges.pop()
    
    def remove(self):
        self.genericRanges.remove()
    
    def reverse(self):
        self.genericRanges.reverse()
    
    def sort(self):
        return
        self.genericRanges.sort()
    
    #  def insert(self, index, object):
        #  self.genericRanges.insert(index, object)
    
    def pop(self, index=-1):
        return self.genericRanges.pop(index)
    
    def remove(self, value):
        found = self.find(value)
        if found:
            self.genericRanges.remove(found)
            if found in self:
                print("remove failed for {}".format(ahex(found)))
                idx = self.__indexOf__(value)
                if ~idx:
                    del self[idx]
                    if found in self:
                        print("remove failed for {} (by index)".format(ahex(found)))
                    else:
                        print("remove succeeded for {} (by index)".format(ahex(found)))
    
    def asTuples(self):
        for r in self.genericRanges:
            yield r

    def optimize(self, quiet=False):
        self.sort()

        starting_len = len(self.genericRanges)

        def by(memo, r, i):
            if r[1] <= r[0]:
                return memo
            if r[1] - r[0] > 65535:
                return memo
            if memo:
                last = memo[-1]
                if self.cmp(last, r):
                    new = union(last, r)
                    # dprint("[by] last, r, new")
                    # print("[by-union] {} + {} = {}".format(ahex(last), ahex(r), ahex(new)))
                    
                    memo[-1] = new
                    return memo
            memo.append(r)
            return memo

        self.genericRanges = type(self.genericRanges)(_.reduce(self.genericRanges, by, []))
        final_len = len(self.genericRanges)
        if not quiet and (final_len != starting_len):
            print('self.optimize: reduced from {} to {} items'.format(starting_len, final_len))



def GenericRangesAsTuples(gr):
    for r in gr:
        yield r.start, r.trend

if hasglobal('PerfTimer'):
    PerfTimer.bindmethods(GenericRange)
    PerfTimer.bindmethods(GenericRanger)

"""
for addr in done2:
  if addr in done3: continue
  b = Block(addr)
  if b[0] in done3 and b[1] in done3: continue
  print("adding {}".format(ahex(b)))
  done3.add(b)
"""
