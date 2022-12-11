## The Generic Rangertte

import os
from exectools import make_refresh
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
    return r[1]

if hasglobal('PerfTimer'):
    PerfTimer.bindmethods(GenericRange)
    PerfTimer.bindmethods(GenericRanger)
