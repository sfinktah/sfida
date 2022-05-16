"""
Speaking generally about Arxan -- most integrity and healing operates on other
Arxan functions.  You can identify which addresses are healed or checked by
monitoring memory reads/writes in flare-emu, and then (this is personal choice)
coloring the appropriate lines in IDA.  You can also store the information in
a database, or to disk, etc.  A lot of it will be checking or mutating binary
chunks that are inputs to other Arxan functions.

Some Arxan functions will operate on a "once in a blue moon" condition, which
may require your emulator to re-run the function until it works (this can be
measured by how many lines of code have been processed).

An alternative for checking what addresses a single Arxan function checks is to
find the pointer to what I call the "ArxanGuide", which is passed to a function
in each checker which I call `ArxanGetNextRange(uint8_t* guide, arxan_range *range)`.
`arxan_range` is just two uint32_t's.  The rest can be
figured from there.
"""

from exectools import make_refresh
refresh_checksummer = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

def _int(n):
    return MakeSigned(n, 32)

def _uint(n):
    return n & 0xffffffff

def _int32(n):
    return MakeSigned(n, 32)

def _uint32(n):
    return n & 0xffffffff


def _int8(n):
    return MakeSigned(n, 8)

def _uint8(n):
    return n & 0xff

def _intn(n, bits=None, signed=True):
    if bits is None:
        bits = _intn.bits
    result = n & ((1 << bits) - 1)
    if signed:
        result = MakeSigned(result, bits)
    return result

def _uintn(n, bits=None, signed=False):
    return _intn(n, bits, signed)

classmaker_info = idaapi.get_inf_structure()
if classmaker_info.is_64bit():
    _intn.bits = 64
elif classmaker_info.is_32bit():
    _intn.bits = 32
else:
    _intn.bits = 16


def hex_trailing_zero_to_space(n):
    s = "{:x}".format(n)
    z = string_between('0', '', s, inclusive=1)
    if z:
        l = len(z)
        s = s[0:len(s)-l] + ' ' * l
    return s

def ArxanMemset(dst, value, size):
    pass

def ArxanMemcpy(dst, src, size):
    pass


def ArxanGetNextRange(guide, range=None):
    """
        ArxanChecksumWorkerB_643
        ArxanGetNextRange(uint8_t **guide, arxan_range *range) {
            int32_t byte, accum = 0, shift = 0;

            do {
                accum += (**guide & 0x7F) << shift;
                shift += 7;
                byte = *(*guide)++;
            } while (byte >= 128);

            range->start += accum + range->len;

            if (range->start != -1) {
                shift = 0;
                do {
                    accum += (**guide & 0x7F) << shift;
                    shift += 7;
                    byte = *(*guide)++;
                } while (byte >= 128);
                range->len = accum;
            }
        }
                                                           
    """
    if isinstance(guide, (str, int)):
        guide = arxan_guide(guide)
    if range is None:
        range = arxan_range()

    if debug: 
        print("{:55}{:8x}   range.start".format('', range.start))
        print("{:55}{:8x}   range.len".format('', range.len))
        print("{:55}{}".format('', '-' * 8))

    accum = 0 # int32
    shift = 0 # int32
    for byte in guide.gen():
        #  if byte >= 128:
        accum = as_uint32(accum + ((byte & 0x7f) << shift))
        shift += 7;
        if debug: print("[phase-1] bt: {:02x}, 7bt {:02x} <<{:2}: accum: {:8x}"\
                .format(byte, byte & 0x7f, shift, accum))
        
    range.start += accum + range.len;
    if debug: print("{:55}{:8x} = new range.start".format('', range.start))

    if range.start != 0xFFFFFFFF:
        accum = shift = 0;
        for byte in guide.gen():
            accum = as_uint32(accum + ((byte & 0x7f) << shift))
            shift += 7;
            if debug: print("[phase-2] bt: {:02x}, 7bt {:02x} <<{:2}: accum: {:8x}"\
                    .format(byte, byte & 0x7f, shift,  accum))
        range.len = accum;
        # if debug: print("[-------] range.len:{}".format(range.len))
    if debug: 
        print("{:55}{:8x}   range.start".format('', range.start))
        print("{:55}{:8x}   range.len".format('', range.len))
        print("{:55}{}".format('', '-' * 8))

    return guide, range


def ArxanGetNextRangeGen(guide, range=None):
    if isinstance(guide, (str, int)):
        guide = arxan_guide(guide)
    if range is None:
        range = arxan_range()

    while True:
        ArxanGetNextRange(guide, range)
        if range.start == 0xffffffff:
            break
        yield 0x140000000 + range.start, range.len

def ArxanGetNextRangeGenChunked(guide, _range=None, step=4):
    _range = arxan_range()
    while True:
        ArxanGetNextRange(guide, _range)
        if _range.start == 0xffffffff:
            break
        for rs in range(_range.start, _range.end, step):
            yield 0x140000000 + rs, min(step, _range.end - rs)


def ArxanDwordSub(guide, src, dword):
    r = arxan_range()
    g = arxan_guide(guide)
    src = eax(src)
    dword = idc.get_wide_dword(eax(dword))

    for rs, rl in ArxanGetNextRangeGenChunked(guide, range, 4):
        # dprint("[debug] rs, rl")
        print("[debug] rs:{}, rl:{}".format(ahex(rs), ahex(rl)))
        print("reading dword from {:x}, writing {} bytes to {:x}".format(src, rl, rs))
        buf4 = _uint32(dword - idc.get_wide_dword(src))
        src += 4
        b = struct.pack('I', buf4)
        # idc.patch_bytes(rs, b[0:rl])
        PatchBytes(rs, b[0:rl], "ArxanDwordSub")


        
        





class arxan_guide(object):
    """arxan guide iter"""

    def __init__(self, ea):
        self._start = eax(ea)
        self.ea = eax(ea)

    def __iter__(self):
        return self

    def __next__(self):
        r = idc.get_wide_byte(self.ea)
        self.ea += 1
        return r

    def __get__(self, index):
        return idc.get_wide_byte(self.ea + index)

    def __len__(self):
        return self.ea - self._start

    def __str__(self):
        return "{:x} +{:x}".format(self.ea, self.__len__())

    def __repr__(self):
        return "<{} object with values {}>".format(string_between("'", "'", str(type(self))), str(self))

    def gen(self):
        while True:
            r = next(self)
            yield r
            if r & 0x80 == 0:
                break

    @property
    def value(self):
        return idc.get_wide_byte(self.ea)

    @value.setter
    def value(self, value):
        idc.patch_byte(self.ea, value)
        return value



class arxan_range:
    """arxan range"""
    base = ida_ida.cvar.inf.min_ea

    def __init__(self, start=0, len=0, rdx=None):
        self._start = start
        self._len = len
        if rdx is not None:
            self._start = rdx & (1 << 32) - 1 # 0xa1b2c3d4
            self._len = rdx >> 32             # 0x12345678

    def fromQword(self, qword):
        self._start, self._len = struct.unpack('II', intAsBytes(qword, 8))
        return self

    def asQword(self):
        return self._len << 32 | self._start

    @property
    def start(self):
        """
        returns self._start
        """
        return _uint32(self._start)

    @start.setter
    def start(self, value):
        """ New style classes requires setters for @property methods
        """
        self._start = _uint32(value)
        if self._start == _uint32(-1):
            print("[arxan_range] **** start == -1 ****")
        elif self._start > 0x5000000:
            print("[arxan_range] start {:08x}".format(0x140000000 + self._start))
        return self._start

    @property
    def len(self):
        """
        returns self._len
        """
        return _uint32(self._len)

    @len.setter
    def len(self, value):
        """ New style classes requires setters for @property methods
        """
        self._len = _uint32(value)
        return self._len

    @property
    def end(self):
        """
        returns self._len
        """
        return _uint32(self._start + self._len)


    def __str__(self):
        return "{:x}\u2013{:x}".format(self.base + self._start, self.base + self._start + self._len)

    def __repr__(self):
        return "<{} object with values {}>".format(string_between("'", "'", str(type(self))), str(self))


class arxan_boxed_number(object):
    """arxan boxed dword"""

    bits = 32
    signed = False

    def __init__(self, value=None, ea=None):
        if ea is None and isinstance(value, str):
            ea = value
            value = None
        if ea is not None:
            self._start = eax(ea)
            self.ea = eax(ea)
            self._value = getptr(self.ea, self.bits, self.signed)
        elif value is not None:
            self._value = value

    def __iter__(self):
        return self

    #  def __next__(self):
        #  r = idc.get_wide_byte(self.ea)
        #  self.ea += 1
        #  return r

    #  def __get__(self, index):
        #  return idc.get_wide_byte(self.ea + index)

    #  def __len__(self):
        #  return self.ea - self._start

    def __str__(self):
        return "0x{:08x}".format(self._value)

    def __repr__(self):
        return "<{} object with values {}>".format(string_between("'", "'", str(type(self))), str(self))

    @property
    def value(self):
        return _uintn(self._value, self.bits, signed=self.signed)

    @value.setter
    def value(self, value):
        self._value = _uintn(value, self.bits, signed=self.signed)
        return self._value

class arxan_boxed_int(arxan_boxed_number):
    bits = 32
    signed = True

class arxan_boxed_dword(arxan_boxed_number):
    bits = 32
    signed = False

class arxan_boxed_qword(arxan_boxed_number):
    bits = 64
    signed = False



def ArxanReadMemcpyRanges(
        base: arxan_boxed_qword, 
        guide: arxan_guide, 
        range: arxan_range, 
        begin: arxan_boxed_qword, 
        total_size, 
        skip: arxan_boxed_dword):
    """
    void ArxanReadMemcpyRanges(uint8_t* Base, uint8_t** guide, arxan_range* range, void* begin, uint total_size, int* skip)
    {
        _BYTE* src;            // [rsp+40h] [rbp+20h]
        _BYTE* dst;            // [rsp+48h] [rbp+28h]
        _BYTE* end;            // [rsp+50h] [rbp+30h]
        unsigned int size;     // [rsp+58h] [rbp+38h]
        unsigned int remains;  // [rsp+5Ch] [rbp+3Ch]

        dst = begin;
        end = (char*)begin + total_size;
        remains = total_size;
        if (begin != end) {
            do {
                size = range->len - *skip;
                src = &Base[range->start + *skip];
                if (remains >= size) {
                    if (remains == size) {
                        ArxanMemcpy(dst, src, size);
                        dst += size;
                        ArxanGetNextRange(guide, range);
                        if (range->start == -1)
                            return;
                        *skip = 0;
                    }
                    else {
                        ArxanMemcpy(dst, src, size);
                        dst += size;
                        *skip = 0;
                        ArxanGetNextRange(guide, range);
                        remains -= size;
                        if (range->start == -1) {
                            ArxanMemset(dst, 0, remains);
                            return;
                        }
                    }
                }
                else {
                    ArxanMemcpy(dst, src, remains);
                    dst += remains;
                    *skip += remains;
                }
            } while (dst != end);
        }
    }
    """
    dst = begin.value
    end = begin.value + total_size
    remains = total_size
    if (begin.value != end):
        while True:
            size = range.len - skip.value
            src = base.value + range.start + skip.value
            if remains >= size:
                if remains == size:
                    ArxanMemcpy(dst, src, size)
                    dst += size
                    ArxanGetNextRange(guide, range)
                    if range.start == 0xffffffff:
                        return
                    skip.value = 0
                else:
                    ArxanMemcpy(dst, src, size)
                    dst += size
                    skip.value = 0
                    ArxanGetNextRange(guide, range)
                    remains -= size
                    if range.start == 0xffffffff:
                        ArxanMemset(dst, 0, remains)
                        return
            else:
                ArxanMemcpy(dst, src, remains)
                dst += remains
                skip.value += remains

            if dst == end: 
                break

def ArxanSecond():
    #  guide1 = (uint8_t *)guide_140DB6F62;
    #  guide2 = (uint8_t *)guide_1416F9531;

    range1 = arxan_range()
    range2 = arxan_range()
    guide1 = arxan_guide('guide_140DB6F62')
    guide2 = arxan_guide('guide_1416F9531')

    #  ArxanGetNextRange2(&guide1, &range1);
    #  ArxanGetNextRange2(&guide2, &range2);

    ArxanGetNextRange(guide1, range1)
    ArxanGetNextRange(guide2, range2)

    #  ptr1 = (uint64_t *)&_ImageBase[range1.start];
    #  ptr2 = (uint64_t *)&_ImageBase[range2.start];

    ptr1 = 0x140000000 + range1.start
    ptr2 = 0x140000000 + range2.start

    #  len1 = range1.len;
    #  len2 = range2.len;

    len1 = range1.len
    len2 = range2.len

    #  for ( i = range1.start; range1.start != -1; i = range1.start ) {

    i = range1.start
    while range1.start != 0xffffffff:

        #  i = range2.start;
        i = range2.start
  
        #  if range2.start == -1 )
          #  break;
  
        if range2.start == 0xffffffff:
            break
  
        #  *ptr2++ = *ptr1++;
        #  len1 -= 8;
        #  len2 -= 8;
  
        print("writing to {:x} value {:016x} from {:x}".format(ptr2, idc.get_qword(ptr1), ptr1))
        #  idc.patch_qword(ptr2, idc.get_qword(ptr1))
        ptr1 += 8
        ptr2 += 8
        len1 -= 8
        len2 -= 8
  
        #  if ( !len1 || !len2 )
        #  {
          #  ArxanGetNextRange2(&guide1, &range1);
          #  ptr1 = (uint64_t *)&_ImageBase[range1.start];
          #  ArxanGetNextRange2(&guide2, &range2);
          #  ptr2 = (uint64_t *)&_ImageBase[range2.start];
          #  len1 = range1.len;
          #  len2 = range2.len;
        #  }
        #
  
        if not len1 or not len2:
            ArxanGetNextRange(guide1, range1)
            ArxanGetNextRange(guide2, range2)
            ptr1 = 0x140000000 + range1.start
            ptr2 = 0x140000000 + range2.start
            len1 = range1.len
            len2 = range2.len

        i = range1.start

    #  byte_1402A1B20 = 0;

def cs1(guide, range=arxan_range()):
    results = []
    base = ida_ida.cvar.inf.min_ea
    while True:
        ArxanGetNetRange(guide, range)
        if not range.start < 0xFFFFFFFF:
            break
        print("range: {}".format(range))
        results.append(GenericRange(base + range.start, last=base + range.start + range.len))
    #  arxan_range.start = arxan_range.len
    #  arxan_range.len = 0
    return results

def rol4():
    clear = b''
    rolling_code = 0xB39B78D0
    roll_amt = 0x10
    len = 0x3d30
    ciphered = 0x140de840c
    for i in range(0, len, 4):
        # first iteration, rolling code becomes 0x78d0b39b
        rolling_code = rotate_dword(rolling_code, roll_amt & 0x1f) & 0xffffffff
        print("rolling_code 0x{:x} roll_amt 0x{:x}".format(rolling_code, roll_amt))
        secret = idc.get_wide_dword(ciphered + i)
        buf4 = (secret - ((roll_amt * rolling_code) & 0xffffffff)) & 0xffffffff;

        clear += struct.pack('I', buf4)
        roll_amt ^= ~buf4

    return clear




if False:
    print("""
    Actual real life function scans in bytes from:
    0x14065e5f8 - 0x14065e695
    0x1412e1548 - 0x1412e164e
    0x1412e1650 - 0x1412e16dc
    0x1413e4c5c - 0x1413e4d77

    Our emulation shows:
    """)

#  arange = arxan_range()
#  guide = arxan_guide("loc_14351AEBE")
#  results = cs1(guide, arange)
# dprint("[cs1] guide, arange")


    guide = arxan_guide(0x142ce88c8)
    range = arxan_range()
    ArxanGetNextRange(guide, range)
    base = arxan_boxed_qword(0x140000000)
    skip = arxan_boxed_dword(0)
    rewritable_dword = arxan_boxed_dword(0)
    ArxanReadMemcpyRanges(base, guide, range, rewritable_dword, 4, skip)
