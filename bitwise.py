import os, re
import pprint
import itertools

from exectools import execfile, make_refresh
refresh_bitwise = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

def _listAsHex(l):
    try:
        return " ".join(map(lambda x: ("%02x" % x), _.flatten(list(l))))
    except TypeError as e:
        print("listasHex: TypeError: {}; l was {}".format(e, l))
        raise e


def binlist(n):    
    if isinstance(n, (int, )):
        return "{:08b}".format(int(n))
    if type(n) == list:
        return ' '.join(["{:08b}".format(int(x)) for x in n])

class BitwiseMask(object):
    _reserved = 0   # size of largest pattern
    _size = 0       # size of smallest pattern
    _set = list()
    _clear = list()
    _eval = list()

    def __init__(self, *args, **kwargs):
        self._options = kwargs
        self._store = []
        self.resize(0)
        if len(args):
            for value in args:
                if type(value) == type(self):
                    # maybe replace with a call to self.extend
                    self.extend([value])
                    #  self._set      = value._set[:]
                    #  self._clear    = value._clear[:]
                    #  self._eval     = value._eval[:]
                    #  self._size     = value._size
                    #  self._reserved = value._reserved
                    #  self._store    = value._store[:]
                elif isinstance(value, list):
                    [self.add_list(x) for x in value]
                elif value:
                    self.add_list(value)


    @staticmethod
    def _as_mask(_set, _clear):
        return 0xff & ~_clear ^ _set

    @staticmethod
    def _as_clear(_set, _mask):
        return 0xff & ~_mask ^ _set

    @property
    def mask(self):
        return [self._as_mask(self._set[i], self._clear[i]) for i in range(self._size)]

    @property
    def value(self):
        return [self._set[i] & 255 for i in range(self._size)]

    @property
    def clear(self):
        return [self._clear[i] & 255 for i in range(self._size)]

    @property
    def eval(self):
        return [x for x in self._eval if (isString(x) and x.strip()) or (not isString(x) and x)]   

    @property
    def tri(self):
        def make_tri(x):
            if x[0] == ' ': return x[0]
            return x[0] if x[1] == '1' else "."
        y = zip(binlist(self.value), binlist(self.mask))
        return "".join([make_tri(x) for x in y])

    @property
    def pattern(self):
        def make_pattern(v, c, m):
            if m == 0xff:
               return "{:02x}".format(v)
            return "{:02x}~{:02x}".format(v, c)
        y = zip(self.value, self.clear, self.mask)
        return " ".join([make_pattern(*x) for x in y])

    @property
    def ida_pattern(self):
        def make_pattern(v, c, m):
            if m == 0xff:
               return "{:02x}".format(v)
            return "??"
        y = zip(self.value, self.clear, self.mask)
        return " ".join([make_pattern(*x) for x in y])

    @property
    def masked_pattern(self):
        def make_pattern(v, c, m):
            if m == 0xff:
               return "{:02x}".format(v)
            return "{:02x}&{:02x}".format(v, m)
        y = zip(self.value, self.clear, self.mask)
        return " ".join([make_pattern(*x) for x in y])

    def bitset(self, position, value):
        byte = position // 8
        bit = 7 - (position % 8)
        self._set[byte] |= 1 << bit
        self._clear[byte] |= 1 << bit
        if not value:
            self._set[byte] ^= 1 << bit
            self._clear[byte] ^= 1 << bit

    def bitget(self, position):
        byte = position // 8
        bit = 7 - (position % 8)
        return self._set[byte] & (1 << bit) != 0

    def asBitset(self):
        result = []
        for position in range(len(self._set) * 8):
            result.append(self.bitget(position))
        return result

    def __getitem__(self, key):
        """get specific bit(s)"""

        # https://stackoverflow.com/questions/2936863/implementing-slicing-in-getitem
        if isinstance(key, slice):
            # Get the start, stop, and step from the slice
            return [self.bitget(i) for i in range(*key.indices(len(self._set)*8))]

        return self.bitget(key)

    def __setitem__(self, key, value):
        """set specific bit(s)"""

        # https://stackoverflow.com/questions/2936863/implementing-slicing-in-getitem
        if isinstance(key, slice):
            if isinstance(value, list):
                for i in range(*key.indices(len(self._set)*8)):
                    self.bitset(i, value[i]) 
            elif isinstance(value, int):
                lr = len(range(*key.indices(len(self._set)*8)))
                # pad value, incase it isn't large enough
                value = [False] * lr + [True if x == '1' else False for x in bin(value)[2:]]
                value = value[-lr:]
                
                for i in range(*key.indices(len(self._set)*8)):
                    self.bitset(i, value[i]) 
            return

        self.bitset(key, value)

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.tri == other.tri
    
    def __ne__(self, other):
        return self.tri != other.tri
    
    def __lt__(self, other):
        return self.tri < other.tri
    
    def __le__(self, other):
        return selt.tri <= other.tri
    
    def __gt__(self, other):
        return self.tri > other.tri
    
    def __ge__(self, other):
        return self.tri >= other.tri

    def __hash__(self):
        return hash(self.tri)
    
    def firstn(self, n):
        bm = self.clone()
        bm.resize(n)
        return bm

    def __repr__(self):
        return "%s" % self.tri

    def match_addresses(self, addr):
        if isinstance(addr, int):
            b = idc.get_bytes(addr, len(self))
            return self.match(b)

        if isinstance(addr, list):
            b = [idc.get_wide_byte(x) for x in addr[0:len(self)]]
            return self.match(b)

        # _.indexOf([bm1.match_addresses(ea) for ea in range(ms(), me())], True) + ms()

    def match(self, other):
        if type(other) == type(self):
            b = other.value
        elif isinstance(other, (bytes, bytearray, list)):
            b = other
            value = self.value
            mask = self.mask
            if len(b) < len(self):
                if obfu_debug:
                    print("len(b)<len(self)")
                return False
            for i in range(len(self)):
                if not b[i] & mask[i] == value[i]:
                    return False
        else:
            raise TypeError('other: {}'.format(type(other).__name__))

        # TODO: perform check similar to above before doing eval
        if self.eval:
            for stmt in self.eval:
                res = eval(stmt, globals(), {'x': self, 'y': b})
                if debug: printi("eval: {} -> {}".format(stmt, res))
                if not res:
                    return False

        return True

    def find_in_segments(self, segments=None, start=None, stop=None, limit=None, iteratee=None):
        def predicate(ea):
            return self.match(ida_bytes.get_bytes(ea, length))
        return FindInSegments(self.ida_pattern, segments=segments, start=start, stop=stop, limit=limit, predicate=predicate, iteratee=iteratee)

    def find_binary(self):
        return self.find_in_segments(segments='any')

    def dword(self, places=4):
        # Python>bm1.mask
        # [0xfb, 0xff, 0xc7]
        # Python>bm1.value
        # [0x48, 0x29, 0xc4]
        # if ida_bytes.get_dword(ea) & 0x00c7fffb == 0x00c42948:
        # (0xc7fffb, 0xc42948)
        _mask   = self.mask  
        _value  = self.value 
        __mask  = 0
        __value = 0
        for x in range(min(places, len(self)) -1, -1, -1):
            __mask  <<= 8
            __mask  |=  _mask[x]
            __value <<= 8
            __value |=  _value[x]
        return "v & {:#x} == {:#x}".format(__mask, __value)
        return __mask, __value

    def sub(self, b):
        value = self.value
        mask = self.mask
        clear = self.clear
        """
        x.setbit(18,y.getbit(5))
        x.setbit(19,y.getbit(6))
        x.setbit(20,y.getbit(7))
        x.setbit(21,y.getbit(26))
        x.setbit(22,y.getbit(27))
        x.setbit(23,y.getbit(28))
        """
        if not self.eval:
            size = min(len(b), self._size)
            r = []
            for i in range(size):
                r.append( (b[i] & clear[i]) | value[i] )
            return r
        
        # raise RuntimeError('need to test this')
        tmp = BitwiseMask()
        tmp.resize(len(b))
        for i, c in enumerate(b):
            tmp._add_byte(i, c)
        _before = self.tri
        for stmt in self.eval:
            if debug: printi("eval: {}".format(stmt))
            eval(stmt, globals(), {'x': self, 'y': tmp})
        _after = self.tri
        if debug: printi("[sub] source:  {}\n[sub] eval b4: {}\n[sub] after  : {}".format(tmp.tri, _before, _after))
        return self.value

    #  48&fe 83 c0&f8 f8     48~49 83 c0~c7 f8     0100100. 10000011 11000... 11111000
    #  48&fe 83 e8&f8 08     48~49 83 e8~ef 08     0100100. 10000011 11101... 00001000
    #                                              ........ ........ ..1.1... 0000....
    def diff(self, other):
        if self._reserved != other._reserved:
            self.resize(max(self._reserved, other._reserved))
            self.resize(max(self._reserved, other._reserved))
            #  return TypeError("Mismatched sizes")

        _diff = None
        if self._options.get('store', None) and other._options.get('store', None):
            _diff = []
            for lhs, rhs in zip(self._store, other._store):
                _diff.append(lhs.diff(rhs))

        _unset = []
        for i in range(self._size):
            # bits to be unset
            _unset.append((self.value[i] ^ other.value[i]) & self.value[i])

        _set = []
        for i in range(self._size):
            # bits to be set
            _set.append((self.value[i] ^ other.value[i]) & ~self.value[i])

        _clear = []
        for i in range(self._size):
            # convert to _clear
            # _clear.append((0xff & ~_set[i] ^ _unset[i]) | _set[i] )
            _clear.append(self._as_mask(_set[i], _unset[i]) | _set[i])


        # _mask  = 0xff & ~_clear ^ _set
        # _clear = ~_mask & 0xff ^ _set
        r = BitwiseMask(_set, _clear, [])

        if _diff:
            # dprint("[debug] len(self._store), len(other._store), len(_diff)")
            #  print("[debug] (self._store):{}, (other._store):{}, (_diff):{}".format((self._store[0]), (other._store[0]), (_diff[0])))
            
            
            for lhs, rhs, d in zip(self._store, other._store, _diff):
                print("{:6} {:32} {:32} {:32}".format(rhs == r.sub(lhs), _listAsHex(lhs), _listAsHex(r.sub(lhs)), _listAsHex(rhs)))
        return r


    def _add_byte(self, index, byte):
        if isinstance(byte, tuple):
            if len(byte)           == 2:
                self._set[index]   &= byte[0]
                self._clear[index] |= byte[1]
                if index >= self._size:
                    self._size = index + 1

        elif isinstance(byte, dict):
            e = byte.get('eval', None)
            if e:
                self._eval.append(e)

        else:
            if index >= self._size:
                self._size = index + 1
            if byte                == -1:
                self._set[index]    = 0
                self._clear[index] |= 0xff
            else:
                self._set[index]   &= byte
                self._clear[index] |= byte


    def add_string(self, pat):
        """ add_string("48 c1 00")
        """
        return self.add_list(self._hex_pattern(pat))

    def add_list(self, pat):
        """ add_list([0x48, 0xc1, 0]))
        """
        #  print("[add_list] pat: {}".format(pat))
        if isinstance(pat, str):
            return self.add_string(pat)
        if isinstance(pat, int):
            raise TypeError("bad arg {} ({})".format(pat, type(pat).__name__))
        if self._options.get('store', None):
            self._store.append(BitwiseMask(pat))
        if len(pat) > self._reserved:
            self.resize(len(pat))
        for index, byte in enumerate(pat):
            self._add_byte(index, byte)

    def add(self, pat):
        return self.add_list(pat)

    def invert_mask(self):
        bm1 = BitwiseMask(self)
        mask = []
        for i in range(bm1._size):
            mask.append(bm1.value[i] ^ bm1.clear[i])
        for i in range(bm1._size):
            bm1._set[i] = 0
            bm1._clear[i] = self._as_clear(bm1._set[i], mask[i])
        return bm1



    def extend(self, l):
        for bm in l:
            self.add_list(bm.masked_pattern)
            self._store.extend(bm._store)

    def clone(self):
        return BitwiseMask(self)

    def __enter__(self):
        self.resize(0)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def __len__(self):
        return self._size

    def _resize(self, l, size, pad):
        length = len(l)
        if size > length:
            l += [pad] * (size - length)
        elif size < length:
            l[:] = l[0:size]


    def resize(self, size):
        if size == 0:
            self._size = self._reserved = 0
            self._set = []
            self._clear = []
            self._eval = []

        self._resize(self._set, size, 0xff)
        self._resize(self._clear, size, 0)
        self._reserved = size

        if size < self._size:
            self._size = size

    def pretty(self):
        return pprint.pformat({ 'value': binlist(self.value), 'mask ': binlist(self.mask), 'set  ': binlist(self._set), 'clear': binlist(self._clear), 'trnry': self.tri})


    # helpers
    @classmethod
    def _hex_pattern(cls, hex_list):
        def _hex_byte(string):
            m = re.match(r'(?:0b)?([01._?-]{8})$', string)
            if m: # 0b0011....
                _set   = int(re.sub(r'[^01]', '0', m.group(1)), 2)
                _clear = int(re.sub(r'[^01]', '1', m.group(1)), 2)
                _mask  = cls._as_mask(_set, _clear)
                return _set, _clear

            m = re.match(r'([0-9a-fA-F]{2})[/&]([0-9a-fA-F]{2})$', string)
            if m: # 70/F8 or 70&F8
                _set   = int(m.group(1), 16)
                _mask  = int(m.group(2), 16)
                _clear = cls._as_clear(_set, _mask)
                return _set, _clear

            m = re.match(r'([0-9a-fA-F]{2})~([0-9a-fA-F]{2})$', string)
            if m: # 70~77
                _set    = int(m.group(1), 16)
                _clear  = int(m.group(2), 16)
                return _set, _clear

            m = re.match(r'.*r', string)
            if m:
                return {'eval': string[0:-1]}

            return -1 if '?' in string else int(string, 16)

        result = []
        # Convert a string into a list, just so we can process it
        if not isinstance(hex_list, list):
            hex_list = [hex_list]
        for l in hex_list:
            result.extend([_hex_byte(item) for item in l.split(" ")])
        return result

def BitwiseMasks(count, *args, **kwargs):
    r = []
    for x in range(count):
        r.append(BitwiseMask(*args, **kwargs))
    return r

if False and __name__ == "__main__":
    # Brute Force
    for i in range(256):
        if ((i - 91) & 0xDF) == 0:
            print(hex(i))

    # Optimal
    delta = 91
    mask = 0xDF
    match = 0
    max_match = ~mask & 0xFF
    while True:
        print(hex(delta + match))
        if match == max_match:
            break
        match = ((match | mask) + 1) & ~mask


    with BitwiseMask() as bm:
        #  for pattern in braceexpand('{70..77}'):
            #  bm.add_list(bm._hex_pattern(pattern))
        #  for pattern in braceexpand('{70..77} 01110... 0b01110... 70/f8'):
            #  bm.add_list(bm._hex_pattern(pattern))
        bm.add_list('70/F8 ?? C2/FE 20~10 ?? CC')
        print(bm.pretty())
        print("bm", bm)


#  def bit_pattern(pattern):
    #  result = []
    #  # Convert a string into a list, just so we can process it
    #  if not isinstance(pattern, list):
        #  pattern = [pattern]
    #  for i, l in enumerate(pattern):
        #  if i > 0:
            #  raise RuntimeError("bit_pattern can only handle 1 list item rn")
#  
        #  with BitwiseMask() as bm:
            #  bm.add_list(l)
            #  return bm

if False and __name__ == "__main__":
    for _set, _clear in itertools.product(range(256), range(256)):
        _mask = 0xff & ~_clear ^ _set
        __clear = ~_mask & 0xff ^ _set
        if __clear != _clear:
            print("fail: {:02x}~{:02x} == {:02x}&{:02x} != {:02x}~{:02x}" \
                    .format(_set, _clear, _set, _mask, _set, __clear))

    #  48&fe 83 c0&f8 f8     48~49 83 c0~c7 f8     0100100. 10000011 11000... 11111000
    #  48&fe 83 e8&f8 08     48~49 83 e8~ef 08     0100100. 10000011 11101... 00001000
                                                    #  ........ ........ ..1.1... 0000....
    # add reg, -8
    bm1 = BitwiseMask("48&fe 83 c0&f8 f8 ??")
    # sub reg, 8
    bm2 = BitwiseMask("48&fe 83 e8&f8 08 ??")

    print("*** PATTERN 1 ***")
    print("{:32} or {:32}".format(bm1.masked_pattern, bm1.pattern))     # '48&fe 83 c0&f8 f8'    '48~49 83 c0~c7 f8'
    print(bm1.tri)
    print("")

    print("*** PATTERN 2 ***")
    print("{:32} or {:32}".format(bm2.masked_pattern, bm2.pattern))
    print(bm2.tri)
    print("")

    print("*** DIFF ***")
    bm3 = bm1.diff(bm2)
    print("{:32} or {:32}".format(bm3.masked_pattern, bm3.pattern))
    print(bm3.tri)

    #  00&00 00&00 28&28 00&f0
    #  00~ff 00~ff 28~ff 00~0f
    #  ........ ........ ..1.1... 0000....

if False and __name__ == "__main__":
    r64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    _search = [
        [72, 139, 4, 36, 72, 141, 100, 36, 8]  ,
        [72, 139, 12, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 20, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 28, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 36, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 44, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 52, 36, 72, 141, 100, 36, 8] ,
        [72, 139, 60, 36, 72, 141, 100, 36, 8] ,
    ]
    _replace = [
        [88] ,
        [89] ,
        [90] ,
        [91] ,
        [92] ,
        [93] ,
        [94] ,
        [95] ,
    ]

    searches = ['push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; push {2}; pop rsp',
                'push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; mov rsp, {2}',
                'push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; push {2}; pop rsp',
                'push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; mov rsp, {2}',
                ]
    b1, b2 = _.grouper(BitwiseMasks(len(searches) * 2, store=1), len(searches))
    if 0:
        for x, y in zip(_search, _replace):
            b1.add(x)
            b2.add(y)
    else:
        for (dst, src, tmp) in (itertools.product(_.without(r64[0:8], 'rsp'), _.without(r64[0:8], 'rsp'), _.without(r64[0:8], 'rsp'))):
            if dst != src and dst != tmp:
                replace_asm = "mov {0}, {1}".format(dst, src)
                replace     = kassemble(replace_asm)

                for i, search_asm in enumerate(searches):
                    search     = kassemble(search_asm.format(dst, src, tmp))
                    b1[i].add_list(search)
                    b2[i].add_list(replace)

    ball1, ball2 = BitwiseMasks(2)
    ball1.extend([b1[0]])
    ball2.extend([b2[0]])

    
    #
    # dprint("[debug] bm1, bm2, bm3")
    # for i, tpl in enumerate(zip(b1, b2)):
    for i, tpl in enumerate(zip([ball1], [ball2])):
        print("[debug] \nb1[{}]:{}\nb1[{}]:{}\nb1[{}]:{}".format(i, b1[i].masked_pattern, i, b1[i].pattern, i, b1[i].tri))
        print("[debug] {}".format(re.sub(r'[01]', 'x', b1[i].tri)))
        print("[debug] {}".format(b1[i].invert_mask().masked_pattern))

        print("[debug] \nb2[{}]:{}\nb2[{}]:{}\nb2[{}]:{}".format(i, b2[i].masked_pattern, i, b2[i].pattern, i, b2[i].tri))
        print("[debug] {}".format(re.sub(r'[01]', 'x', b2[i].tri)))
        print("[debug] {}".format(b2[i].invert_mask().masked_pattern))

    bm1, bm2 = ball1, ball2
    #  bm1, bm2 = b1[0], b2[0]
    tri1 = bm1.tri.replace(' ', '')
    tri2 = bm2.tri.replace(' ', '')
    unk1 = list()
    unk2 = list()
    for i, c in enumerate(tri1):
        if c == '.':
            unk1.append(i)
    for i, c in enumerate(tri2):
        if c == '.':
            unk2.append(i)
    print("[tri1] {}, unk1: {}".format(tri1, unk1))
    print("[tri2] {}, unk2: {}".format(tri2, unk2))
    while len(unk1) < len(unk2):
        unk1.append(None)
    while len(unk2) < len(unk1):
        unk2.append(None)

    if len(unk1) == len(unk2):
        for perm in itertools.permutations(unk1, len(unk1)):
            bad = 0
            good = 0
            s1 = []
            s2 = []
            for l, r in zip(bm1._store, bm2._store):
                d = bm2.clone()
                for i, tpos in enumerate(unk2):
                    if tpos is not None:
                        d.bitset(tpos, l.bitget(perm[i]))
                s1.append(l.value)
                s2.append(d.value)
                if d.tri != r.tri:
                    bad += 1
                    break
                good += 1
            if not bad and good:
                print("possible solution: {} = {}".format(unk2, perm))
                print('\n'.join(['x.bitset({},y.bitget({}))'.format(x, y) for x, y in zip(unk2, perm)]))
                print('\n'.join(['x.bitset({},y.bitget({}))'.format(x, y) for x, y in zip(unk2, perm)]))
                print("""
        searches = [
            "{}"
        ]
        replace_eval = \\
            "{}r"
        
        replace = BitwiseMask(replace_eval)
        for i, search in enumerate(searches):
            obfu.append("", "",
                    BitwiseMask(search),
                    replace,
                    safe=1,
                    resume=1,
            )
                """.format(
                        '", "'.join([x.masked_pattern for x in b1]),
                        'r " + \\\n            "'.join(['x.bitset({},y.bitget({}))'.format(x, y) for x, y in zip(unk2, perm) if x is not None])
                    ))

                results = []
                for l, r in zip(s1, s2):
                    results.append("    {} == {}   {} == {}".format('; '.join(diInsnsPretty(l)), '; '.join(diInsnsPretty(r)), _listAsHex(l), _listAsHex(r)))
                print("\n".join(_.uniq(results)))
                break

    else:
        print("unequal lengths")


                
    if 0:
        with BitwiseMask() as bm:
            for r in r64: 
                if r == 'rsp':
                    continue
    
                # search      = hex_pattern([re.sub(r' de ad ff 08', ' f8 ff ff ff', _listAsHex(kassemble(search_asm)))])
                search_asm  = "lea rsp, [rsp-8]; mov [rsp], {0}".format(r)
                search      = nassemble(search_asm)
                bm.add_list(search)
    
            print(bm.pattern)

        movlealistpush = [
                # MOV [RSP-0x8], RAX; LEA RSP, [RSP-0x8]
                [["48 89 44 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 04 24 90"], "rax"],
                [["48 89 4c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 0c 24 90"], "rcx"],
                [["48 89 54 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 14 24 90"], "rdx"],
                [["48 89 5c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 1c 24 90"], "rbx"],
                [["48 89 64 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 24 24 90"], "rsp"],
                [["48 89 6c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 2c 24 90"], "rbp"],
                [["48 89 74 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 34 24 90"], "rsi"],
                [["48 89 7c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 3c 24 90"], "rdi"],
                [["4c 89 44 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 04 24 90"], "r8"],
                [["4c 89 4c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 0c 24 90"], "r9"],
                [["4c 89 54 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 14 24 90"], "r10"],
                [["4c 89 5c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 1c 24 90"], "r11"],
                [["4c 89 64 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 24 24 90"], "r12"],
                [["4c 89 6c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 2c 24 90"], "r13"],
                [["4c 89 74 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 34 24 90"], "r14"],
                [["4c 89 7c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 3c 24 90"], "r15"]
        ]
    #       def hex_byte_as_pattern_int(string):
    #           return -1 if '?' in string else int(string, 16)
    #   
    #       def hex_pattern(hexLists):
    #           result = [ ]
    #           # Convert a string into a list, just so we can process it
    #           if not isinstance(hexLists, list):
    #               hexLists = [hexLists]
    #           for l in hexLists:
    #               result.extend([hex_byte_as_pattern_int(item) for item in l.split(" ")])
    #           return result

    from underscoretest import _
    with BitwiseMask(store=1) as bm1:
        with BitwiseMask(store=1) as bm2:
            for x, y, z in movlealistpush:
                bm1.add_list(hex_pattern(x))
                bm2.add_list(hex_pattern(y))

            bm3 = bm1.diff(bm2)

            # dprint("[debug] bm1, bm2, bm3")
            print("[debug] \nbm1:{}, \nbm2:{}, \nbm3:{}".format(bm1.pattern, bm2.pattern, bm3.pattern))
                
    #  48~4c 89    44~7c 24    f8    48    8d    64    24    f8,
    #  48    8d    64    24    f8    48~4c 89    04~3c 24    90,
    #  00~ff 04~ff 20~ff 00~ff 00~ff 00~ff 00~fb 00~9f 00~ff 00~97

    #  48~4c 89    44~7c 24    f8    48    8d    64    24    f8,
    #  48~4c 89    04~3c 24    90    48    8d    64    24    f8,
    #  00~ff 00~ff 00~bf 00~ff 00~97 00~ff 00~ff 00~ff 00~ff 00~ff


    #  48 89 44 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 04 24 90
    #  48 89 4c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 0c 24 90
    #  48 89 54 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 14 24 90
    #  48 89 5c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 1c 24 90
    #  48 89 64 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 24 24 90
    #  48 89 6c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 2c 24 90
    #  48 89 74 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 34 24 90
    #  48 89 7c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 48 89 3c 24 90
    #  4c 89 44 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 04 24 90
    #  4c 89 4c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 0c 24 90
    #  4c 89 54 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 14 24 90
    #  4c 89 5c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 1c 24 90
    #  4c 89 64 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 24 24 90
    #  4c 89 6c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 2c 24 90
    #  4c 89 74 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 34 24 90
    #  4c 89 7c 24 f8 48 8d 64 24 f8        48 8d 64 24 f8 4c 89 3c 24 90
    #  

if False and __name__ == "__main__":
    movlealistpop2  = [
        [["48 8d 64 24 08", "48 8b 44 24 f8"], ["48 8b 04 24", "48 8d 64 24 08"], "rax"],
        [["48 8d 64 24 08", "48 8b 4c 24 f8"], ["48 8b 0c 24", "48 8d 64 24 08"], "rcx"],
        [["48 8d 64 24 08", "48 8b 54 24 f8"], ["48 8b 14 24", "48 8d 64 24 08"], "rdx"],
        [["48 8d 64 24 08", "48 8b 5c 24 f8"], ["48 8b 1c 24", "48 8d 64 24 08"], "rbx"],
        [["48 8d 64 24 08", "48 8b 64 24 f8"], ["48 8b 24 24", "48 8d 64 24 08"], "rsp"],
        [["48 8d 64 24 08", "48 8b 6c 24 f8"], ["48 8b 2c 24", "48 8d 64 24 08"], "rbp"],
        [["48 8d 64 24 08", "48 8b 74 24 f8"], ["48 8b 34 24", "48 8d 64 24 08"], "rsi"],
        [["48 8d 64 24 08", "48 8b 7c 24 f8"], ["48 8b 3c 24", "48 8d 64 24 08"], "rdi"],
        [["48 8d 64 24 08", "4c 8b 44 24 f8"], ["4c 8b 04 24", "48 8d 64 24 08"], "r8"],
        [["48 8d 64 24 08", "4c 8b 4c 24 f8"], ["4c 8b 0c 24", "48 8d 64 24 08"], "r9"],
        [["48 8d 64 24 08", "4c 8b 54 24 f8"], ["4c 8b 14 24", "48 8d 64 24 08"], "r10"],
        [["48 8d 64 24 08", "4c 8b 5c 24 f8"], ["4c 8b 1c 24", "48 8d 64 24 08"], "r11"],
        [["48 8d 64 24 08", "4c 8b 64 24 f8"], ["4c 8b 24 24", "48 8d 64 24 08"], "r12"],
        [["48 8d 64 24 08", "4c 8b 6c 24 f8"], ["4c 8b 2c 24", "48 8d 64 24 08"], "r13"],
        [["48 8d 64 24 08", "4c 8b 74 24 f8"], ["4c 8b 34 24", "48 8d 64 24 08"], "r14"],
        [["48 8d 64 24 08", "4c 8b 7c 24 f8"], ["4c 8b 3c 24", "48 8d 64 24 08"], "r15"]
    ]


    from underscoretest import _
    with BitwiseMask(store=1) as bm1:
        with BitwiseMask(store=1) as bm2:
            for x, y, z in movlealistpop2:
                # dprint("[] x, y, z")
                print("x:{}, y:{}, z:{}".format(x, y, z))
                
                bm1.add_string(x)
                bm2.add_string(y)

            bm3 = bm1.diff(bm2)

            # dprint("[debug] bm1, bm2, bm3")
            print("[debug] \nbm1:{}, \nbm2:{}, \nbm3:{}".format(bm1.pattern, bm2.pattern, bm3.pattern))
                

if False and __name__ == "__main__":
    # xmms = braceexpand('xmm{0..15}')
    r64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    bm1 = BitwiseMask([nassemble("sub rsp, {}".format(reg)) for reg in r64])
    bm2 = BitwiseMask([[x[0], x[1] + 2, x[2]] for x in [nassemble("sub {}, rsp".format(reg)) for reg in r64]])
    
    print("[tri] {}".format(bm1.tri))
    tri1 = bm1.tri.replace(' ', '')
    #  unk1 = list()
    #  unk2 = list()
    #  for i, c in enumerate(tri1):
        #  if c == '.':
            #  unk1.append(i)
    #  for i, c in enumerate(tri2):
        #  if c == '.':
            #  unk2.append(i)

    print("[tri1] {}".format(tri1))


                
# vim: set ts=4 sts=4 sw=4 et:
