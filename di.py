import os
import re
import idc
import ida_ua, idaapi

try:
    import distorm3c as distorm3
except ModuleNotFoundError:
    import distorm3
# import distorm3 as distorm3
# from start import asBytesRaw
from string_between import string_between
from idc import *

try:
    from execfile import make_refresh, execfile, _import
    #  _import("from sfida.sf_common import asBytes, isInt")
    #  _import("from sftools import eax")
    #  _import("from sfida.sf_string_between import string_between")

    refresh_di = make_refresh(os.path.abspath(__file__))
    refresh = make_refresh(os.path.abspath(__file__))
except ModuleNotFoundError:
    pass


def get_ea_by_any(val, d=object):
    """
    returns the address of a val (and if address is
    a number, looks up the val first).

    an easy way to accept either address or val as input.
    """

    if isinstance(val, list):
        return [get_ea_by_any(x) for x in val]
    if isinstance(val, str):
        r = idaapi.str2ea(val)
        if r and r != idc.BADADDR:
            return r

        match = re.match(r'(sub|off|loc|byte|word|dword|qword|nullsub|locret)_([0-9A-F]+)$', val)
        if match:
            return int(match.group(2), 16)

        return 0 if d == object else d

    if isinstance(val, idaapi.vdui_t):
        val = val.cfunc

    if val is None:
        return idc.get_screen_ea() if d == object else d

    if isinstance(val, int):
        return val

    try:
        for attr_name in ['start_ea', 'ea', 'entry_ea', 'start', 'min_ea']:
            if hasattr(val, attr_name):
                return getattr(val, attr_name)
    except AttributeError:
        pass 

    raise ValueError("Don't know how to convert {} '{}' to address".format(type(val), val))

def eax(*args):
    return get_ea_by_any(*args)
def isInt(o):
    return isinstance(o, int)

def asBytes(o):
    if isinstance(o, bytearray):
        return bytes(o)
    return o if isBytes(o) else o.encode('utf-8')

def asString(o):
    return o if isString(o) else o.decode('utf-8')

def asBytesRaw(o):
    if isinstance(o, bytearray):
        return bytes(o)
    return o.encode('raw_unicode_escape') if isinstance(o, str) else o


def distorm_64_bit_flag():
    return distorm3.Decode64Bits 
    return distorm3.Decode64Bits if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT else distorm3.Decode32Bits

def MyGetMnem(ea):
    if idc.get_wide_word(ea) == 0x9066:
        return "nop"
    mnem = idc.print_insn_mnem(ea)
    return mnem

def GetMnemDi(ea=None):
    """
    Get Mnemonic using Distorm3

    @param ea: linear address
    """
    ea = eax(ea)
    d = de(ea)
    if not de:
        return ''
    d = d[0]
    m = d.mnemonic.lower().replace('ret', 'retn')
    return m

GetInsnMnem = MyGetMnem

def GetMnemForce(ea=None):
    """
    GetMnemForce

    @param ea: linear address
    """
    ea = eax(ea)
    return GetInsn(ea).get_canon_mnem()

def GetInsn(*args):
    if len(args) == 1:
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, args[0])
        return insn
    else:
        return ida_ua.decode_insn(*args)

# DOUNK_NOTRUNC
def MyGetInstructionLength(*args):
    lengths = []
    if len(args) == 1:
        if not isInt(args[0]):
            print("return_unless: isInt(args[0])")
            return 
        
        # ida method
        ea = args[0]
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        if inslen:
            lengths.append(inslen)

        # distorm method
        insn_de = de(ea, 16)
        if insn_de:
            insn_de = insn_de[0]
            if insn_de.rawFlags == 0xffff:
                return 0
            size = insn_de.size
            lengths.append(inslen)

        if len(lengths) == 2 and lengths[0] and lengths[1] and lengths[0] == lengths[1]:
            return size
        if not lengths[0] or not lengths[1]:
            return 0
        
        raise RuntimeError("[MyGetInstructionLength] {:x} differing insnlen: ida: {} distorm: {}".format(ea, inslen, size))
    else:
        return ida_ua.decode_insn(*args)

def getLength(ea):
    return MyGetInstructionLength(ea)

def GetInsLen(ea):
    return getLength(ea)

def getCode(ea=None, length=None):
    """
    get bytes comprising instruction
    (wrapper around idc.get_bytes)

    @param ea: linear address
    @param length: number of bytes
    """
    ea = eax(ea)
    length = length or MyGetInstructionLength(ea)
    if length > ea:
        length -= ea
    r = idc.get_bytes(ea, length)
    return r

def GetFuncCode(ea):
    ea = get_ea_by_any(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        result.extend([idc.get_wide_byte(x) for x in range(startea, endea)])
    return bytearray(result)

def GetFuncCodeNoJunk(ea):
    ba = bytearray()
    def add_insn(x):
        if x.mnem not in ('nop', 'jmp'):
            ba.extend(x.bytes)
        # {'result': (x.ea, x.ea + x.size)}
        # n = ll.node(x)

    r = AdvanceToMnemEx(ea, lambda x: not ida_funcs.is_same_func(x, ea), lambda x, *a: add_insn(x))
    return ba

def GetFuncCodeIndexNoJunk(ea):
    l = []
    def add_insn(x):
        if x.mnem not in ('nop', 'jmp'):
            l.extend([a for a in range(x.ea, x.ea + x.size)])
        # {'result': (x.ea, x.ea + x.size)}
        # n = ll.node(x)

    r = AdvanceToMnemEx(ea, lambda x: not ida_funcs.is_same_func(x, ea), lambda x, *a: add_insn(x))
    return l


def GetFuncCodeNoJunk_(ea):
    ea = get_ea_by_any(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            if insn.itype not in (ida_allins.NN_nop, ida_allins.NN_jmp):
                result.extend([idc.get_wide_byte(x) for x in range(insn.ea, insn.ea + insn.size)])
    return bytearray(result)

def GetFuncCodeIndexNoJunk_(ea):
    ea = get_ea_by_any(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            if insn.itype not in (ida_allins.NN_nop, ida_allins.NN_jmp):
                result.extend([x for x in range(insn.ea, insn.ea + insn.size)])
    return result

def GetFuncCodeIndexTest(ea):
    ea = get_ea_by_any(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            result.extend([x for x in range(insn.ea, insn.ea + insn.size)])
    return result

def GetFuncCodeIndex(ea):
    ea = get_ea_by_any(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        result.extend([x for x in range(startea, endea)])
    return result

def getCodeAsList(ea, length):
    return [ord(x) for x in idc.get_bytes(ea, length)]

def ripadd(group, rip):
    splut = re.split(r'([+-])', group, 1)
    if len(splut) == 3:
        return "rel 0x{:x}".format(rip + int(splut[1] + splut[2], 16))
    return "rel " + "".join(group)

def diInsn(code, offset = 0):
    if isinstance(code, list):
        code = bytearray(code)
    if isinstance(code, bytearray):
        #  code = code.decode('raw_unicode_escape')
        code = asBytesRaw(code)
    dt       = distorm_64_bit_flag()
    iterable = distorm3.DecodeGenerator(offset, code, dt)
    for (offset, size, instruction, hexdump) in iterable:
        return instruction.lower().replace('[cr4:', '[')

def diInsnsPretty(code, ea = None, dt=distorm_64_bit_flag()):
    iterable = diInsnsIter(asBytes(bytearray(code)), ea)
    for (offset, size, instruction, hexdump) in iterable:
        yield instruction.lower().replace('[cr4:', '[')

def diInsns(code, ea = None, dt=distorm_64_bit_flag()):
    iterable = diInsnsIter(asBytes(bytearray(code)), ea)
    return [x for x in iterable]


#  def diInsn(code, offset = 0):
    #  dt       = distorm_64_bit_flag()
    #  iterable = distorm3.DecodeGenerator(offset, code, dt)
    #  for (offset, size, instruction, hexdump) in iterable:
        #  return instruction

def diInsnsIter(code, ea = None, dt=distorm_64_bit_flag()):
    if ea is None:
        ea = idc.ScreenEA()
    if isinstance(code, list):
        code = bytearray(code)
    if isinstance(code, bytearray):
        #  try:
            #  code = code.decode('raw_unicode_escape')
        #  except UnicodeDecodeError as e:
            #  # b'\xe9\\uo\x03'
            #  globals()['code'] = code
            #  raise e
        code = asBytesRaw(code)
    return distorm3.DecodeGenerator(ea, code, dt)

def di_decode_insn(code_or_ea, length=16, dt=distorm_64_bit_flag()):
    if isInt(code_or_ea):
        ea = eax(code_or_ea)
        code = getCode(ea, length)
    elif isByteish(code_or_ea):
        code = asBytesRaw(code_or_ea)
        ea = 0

    for insn_de in deCodeIter(code, ea, dt=dt):
        return insn_de

def di_can_decode(code_or_ea, length=16, dt=distorm_64_bit_flag()):
    return di_decode_insn(code_or_ea, length, dt).rawFlags != 65535

def idafy(operand, ea, size):
    regex = r"\b(rip[+-]0x[0-9a-f]+)"
    operand = re.sub(regex, lambda m: ripadd(m.group(), ea + size), operand, 0, re.IGNORECASE)
    regex = r"\b(0x[0-9])\b"
    operand = re.sub(regex, lambda m: str(int(m.group(), 16)), operand, 0, re.IGNORECASE)
    regex = r"\b(0x[0-9a-f]{8,})\b"
    operand = re.sub(regex, lambda m: get_name_or_hex(int(m.group(), 16)), operand, 0, re.IGNORECASE)
    return operand

def diInsnsObjectIter(code, ea=None, dt=distorm_64_bit_flag()):
    for it in diInsnsIter(asBytes(bytearray(code)), ea):
        yield AttrDict({
            'ea': it[0],
            'size': it[1],
            'insn': idafy(it[2], it[0], it[1]),
            'bytes': bytearray().fromhex(it[3]),
            })



def diCode(code, offset = 0):
    dt       = distorm_64_bit_flag()
    iterable = distorm3.DecodeGenerator(offset, code, dt)
    for (offset, size, instruction, hexdump) in iterable:
        print("%.8x: %-32s %s" % (offset, hexdump, instruction))

    # It could also be used as a returned list:
    # l = distorm3.Decode(offset, code, options.dt)
    # for (offset, size, instruction, hexdump) in l:
    #     print("%.8x: %-32s %s" % (offset, hexdump, instruction))

def deCode(code, ea = 0, dt=distorm_64_bit_flag(), features = 0):
    return distorm3.Decompose(ea, code, dt, features)

def deCodeIter(code, ea = 0, dt=distorm_64_bit_flag(), features = 0):
    return distorm3.DecomposeGenerator(ea, code, dt, features)

def de(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = MyGetInstructionLength(ea)
    return deCode(getCode(ea, length), ea)

def derange(ea = None, length = None, dt=distorm_64_bit_flag(), features = 0):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = MyGetInstructionLength(ea)
    return deCodeIter(getCode(ea, length), ea)

def deranger(ea = None, length = None, dt=distorm_64_bit_flag(), features = 
        # distorm3.DF_STOP_ON_CALL       |
        # distorm3.DF_STOP_ON_UNC_BRANCH |
        # distorm3.DF_STOP_ON_INT        |
        distorm3.DF_STOP_ON_PRIVILEGED |
        # distorm3.DF_STOP_ON_RET        |
        distorm3.DF_STOP_ON_UNDECODEABLE):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    return deCodeIter(getCode(ea, length), ea, features = features)

def der(ea = None, length = None, features = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    if length > ea:
        length = length - ea
    if features is not None:
        gen = deranger(ea, length, features = features)
    else:
        gen = deranger(ea,length)
    return [x for x in gen] 

def destart2(ea=None, length=None):
    """
    [alpha] attempt to find start of function 

    @param ea: linear address
    @param length: how many preview bytes to check
    """
    if isinstance(ea, list):
        return [destart(x) for x in ea]

    ea = eax(ea)
    length = length or 300
    l = [der(ea - x, x) for x in range(1, length)]
    j = [len(x) for x in l]
    m = _.max(j)
    p = j.index(m) + 1
    q = l[p-1]
    setglobal('destart_debug', {'l': l, 'j': j, 'm': m, 'p': p, 'q': q})
    q.reverse()
    for i in range(1, len(q)):
        #  if q[i].flowControl != 'FC_NONE':
            #  q = q[0:i]
            #  break
        if IsRef(q[i].address):
            q = q[0:i+1]
            break
    print("not popping", q[-1])
    result = q[-1].address
    for ea in range(result, result + 16):
        #  print("ea: {:x} isref: {}".format(ea, IsRef(ea)))
        if IsRef(ea):
            return ea
    return result

def destart(ea=None, length=None):
    """
    [alpha] attempt to find start of function containing multiple 'PUSH'
    instructions by disassembling from `ea` backwards

    @param ea: linear address
    @param length: how many preview bytes to check
    """
    if isinstance(ea, list):
        return [destart(x) for x in ea]

    ea = eax(ea)
    length = length or 300
    l = [der(ea - x, x) for x in range(1, length)]
    j = [len(x) for x in l]
    m = _.max(j)
    p = j.index(m) + 1
    q = l[p-1]
    setglobal('destart_debug', {'l': l, 'j': j, 'm': m, 'p': p, 'q': q})
    q.reverse()
    for i in range(1, len(q)):
        if q[i].flowControl != 'FC_NONE':
            q = q[0:i]
            break
        if IsRef(q[i].address):
            q = q[0:i+1]
            break
    while q and not str(q[-1]).startswith('PUSH'):
        print("popping", q[-1])
        #  print("q: {}".format(pf(q)))
        q.pop();
    if not q:
        return None
    print("not popping {} at {:x}".format(q[-1], q[-1].address))
    result = q[-1].address
    for ea in range(result, result + 16):
        #  print("ea: {:x} isref: {}".format(ea, IsRef(ea)))
        if IsRef(ea):
            return ea
    return result

def label(addr, colon = 0): 
    l = get_name_by_any(addr)
    if not l:
        l = "loc_{:x}".format(addr)
    if colon:
        return "{:16}".format(l + ':')
    return "{:16}".format(l)

def _di_indent(insn):
    return "{:16}".format("")

def instruction(insn):
    s = str(insn)
    if insn.rawFlags & (1 << 7):
        # rip_relative
        opn = -1
        for i, o in enumerate(insn.operands):
            # must be a numeric/binary check for this
            if o.type == 'AbsoluteMemory': 
                target = o.disp + insn.address + insn.size
                opn = i
        if opn > -1:
            regex = r"(rip[+-]0[x0-9a-f]+)"
            s = re.sub(regex, hex(target), s, flags=re.IGNORECASE)
    return re.sub('0x(145[0-9a-fA-F]{6})', lambda m: label(int(m.group(1), 16)), s)

def deri(ea = None, length = None, features = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    if features is not None:
        d = der(ea, length, features = features)
    else:
        d = der(ea,length)
    targets = [distorm3._getRegularTarget(x) for x in d]
    targets = [x for x in targets if x and x > 0x145000000]
    for i in d:
        if i.address in targets:
            yield label(i.address, colon=1) + instruction(i)
        else:
            yield _di_indent(i) + instruction(i)
            
def derip(ea = None):
    if ea is None:
        ea = ScreenEA()
    g = deri(ea, 0x8000, features=distorm3.DF_STOP_ON_UNDECODEABLE)
    output = "{0}: ; {1:x}\n".format(idc.get_name(ea, GN_VISIBLE), ea)
    output += '\n'.join([x for x in g])
    output += '\n\n'
    return output

def deriploc():
    output = ''
    for f in FunctionsMatching('.*_RELOC_11'):
        output += derip(f)
    return output

def di(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = MyGetInstructionLength(ea)
    return diCode(getCode(ea, length), ea)

def dii(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None: # Default to 1 instruction
        length = MyGetInstructionLength(ea)
    return diInsn(getCode(ea, length), ea)

def log2(v):
    """
    http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
    """
    a = [0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9]
    n = ((v * 0x077CB531) & 0xffffffff) >> 27
    r = a[n];
    return r

name_addr_map = dict()
def get_name_or_hex(ea):
    global name_addr_map
    name_v = idc.get_name(ea, GN_VISIBLE)
    name = idc.get_name(ea)
    if name != name_v:
        return hex(ea)
        #  name_addr_map[name_v] = (name_v, name, ea)
        #  return name_v
    if not name:
        return hex(ea)
    return name

def get_operand_size_type(size):
    sizes = ['byte', 'word', 'dword', 'qword', 'dqword', 'tword']
    n = log2(size // 8);
    return sizes[n];

def diida(ea = None, length = None, mnemOnly = False, filter=None, iteratee=None, returnLength=False):
    if ea is None:
        ea = ScreenEA()
    if length is None: # Default to 1 instruction
        length = MyGetInstructionLength(ea) or 15
    if length > ea:
        length = length - ea
    start_ea = ea
    end = ea + length
    next_ea = ea
    result = []
    while next_ea < end and MyGetInstructionLength(next_ea):
        ea = next_ea
        length = MyGetInstructionLength(ea)
        next_ea = ea + length
        if next_ea > end:
            continue
        if callable(filter):
            if not filter(ea):
                continue
        insn = diInsn(getCode(ea, length), ea) # .lower()
        insn_de = deCode(getCode(ea, length), ea)
        if insn_de:
            insn_de = insn_de[0]
        else:
            result.append('** ERROR **')
            break

        def getMnem(asm):
            sp = asm.split(' ')
            return sp[0].lower().replace('ret', 'retn')

        mnem = getMnem(insn)
        if mnem == '' or mnem.startswith(('rep', 'repne', 'repe')):
            result.append(insn)
            continue

        if mnemOnly:
            result.append(mnem)
            continue

        opers = []
        opercount = len(insn_de.operands)
        operand_part = string_between(' ', '', insn)
        if not operand_part:
            result.append(mnem)
            continue

        operands = operand_part.split(',')
        operands = [s.strip() for s in operands]
        for i in range(len(insn_de.operands)): # , operand in enumerate(operands):
            operand = operands[i]
            # .text:0000000140016120 0B8 BA 5F 60 38 CE                          mov     edx, 0CE38605Fh
            # mov EDX, 0xffffffffeeaf512a

            # len(d.operands) == 2 and d.operands[1].type == 'Immediate' and d.operands[1].value < 0 and d.operands[1].size == 32: v = d.operands[1].value; hex(v & 0xffffffff)
            o = insn_de.operands[i]
            if o.value < 0 and o.size == 32 and o.type == 'Immediate':
                operand = "0x%x" % (o.value & 0xffffffff)

            post_colon = string_between('CR4:', ']', operand)
            if post_colon:
                size = insn_de.operands[i].size 
                if size:
                    dtyp_name = get_operand_size_type(size)
                    if dtyp_name != None:
                        operand = "{0} [{1}]".format(dtyp_name, post_colon)
                else:
                    operand = "[{0}]".format(post_colon)
            e = insn_de
            regex = r"\b(rip[+-]0x[0-9a-f]+)"
            operand = re.sub(regex, lambda m: ripadd(m.group(), e.address + e.size), operand, 0, re.IGNORECASE)
            regex = r"\b(0x[0-9])\b"
            operand = re.sub(regex, lambda m: str(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            regex = r"\b(0x[0-9a-f]{8,})\b"
            operand = re.sub(regex, lambda m: get_name_or_hex(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            opers.append(operand)

        asm = "{0} {1}".format(mnem, ", ".join(opers))
        result.append(asm)

    if returnLength:
        return next_ea - start_ea, '\n'.join(result)
    return '\n'.join(result)

def diidaIter(ea = None, length = None, code = None, mnemOnly = False, iterate = False, labels = True):
    output = []

    def label_line(addr):
        true_name = idc.get_name(addr)
        label = idc.get_name(addr, ida_name.GN_VISIBLE)
        return "{}:".format(label)

    def sub_header(addr):
        true_name = idc.get_name(addr)
        label = idc.get_name(addr, ida_name.GN_VISIBLE)
        tags = "" # get_tags(addr)
        return ("" + \
"; =============== S U B R O U T I N E =======================================" + \
"; public " + str(true_name) + " proc" + \
";" + \
"; 	tags: " + str(tags) + "" + \
";" + \
"" + str(label) + ":").split("\n")

    def chunk_start(addr):
        owners = GetChunkOwners(addr)
        fstart = GetFuncStart(addr)
        other_owners = [x for x in owners if x != fstart]
        owner_true_name = idc.get_name(fstart)
        other_owners_names = [idc.get_name(x) for x in other_owners]
        other_owner_lines = ''
        if other_owners:
            for owner, owner_name in zip(other_owners, other_owners_names):
                other_owner_lines += ";   additionally chunk " + str(ida_funcs.get_fchunk_num(owner, addr)) + " of " + str(owner_name) + "\n"

        label = idc.get_name(addr, ida_name.GN_VISIBLE)
        tags = [get_tags(x) for x in owners]
        return "" + \
"; --------------- C h u n k   S t a r t -------------------------------------" + \
"; chunk " + str(ida_funcs.get_fchunk_num(fstart, addr)) + " of " + str(owners_true_name) + "" + \
"" + str(other_owner_lines or ';') + "" + \
"; 	tags: " + str(", ".join(tags)) + "" + \
";" + \
"" + str(label) + ":".split("\n")

    def chunk_end(addr):
        return """
; --------------- C h u n k   E n d -----------------------------------------
""".split("\n")

    def out(line):
        for l in A(line):
            print(line)
            output.append(line)

    # dprint("[debug] ea, length, code")
    #  print("[debug] ea:{}, length:{}, code:{}".format(ea, length, code))
    
    if ea is None:
        ea = ScreenEA()
    if length is None: # Default to 1 instruction
        length = MyGetInstructionLength(ea)
    insn_iter = diInsnsIter(getCode(ea, length) if not code else code, ea) # .lower()
    insn_de_iter = deCodeIter(getCode(ea, length) if not code else code, ea)
    # dprint("[debug] insn_iter, insn_de_iter")
    #  print("[debug] insn_iter:{}, insn_de_iter:{}".format(insn_iter, insn_de_iter))

    def getMnem(asm):
        mnem = asm.split(' ', 1)
        if mnem == '' or mnem in ('rep', 'repne', 'repe'):
            return insn.lower()
        return mnem[0].lower().replace('ret', 'retn')

    for insn_di, insn_de in zip(insn_iter, insn_de_iter):
        # dprint("[debug] insn_di, insn_de")
        #  print("[debug] insn_di:{}, insn_de:{}".format(insn_di, insn_de))
            
        addr, insn_len, insn, _hex = insn_di
        insn = insn.lower()

        if labels and idc.get_name(addr):
            if IsChunkEnd(addr):
                out(chunk_end(addr))
            if IsFuncHead(addr):
                out(sub_header(addr))
            elif IsChunkStart(addr):
                out(chunk_start(addr))
            else:
                out(label_line(addr))

        mnem = getMnem(insn)
        if mnem == '' or mnem.startswith('rep'):
            out(insn)
            continue
        if mnemOnly:
            out(mnem)
            continue

        mnem = insn_de.mnemonic.lower().replace('ret', 'retn').replace('int ', 'int')

        opers = []
        operand_part = string_between(' ', '', insn)
        if not operand_part:
            out(mnem)
            continue

        operands = operand_part.split(',')
        opercount_de = len(insn_de.operands)
        opercount_di = len(operands)
        if opercount_de != opercount_di:
            out(mnem)
            continue
        operands = [s.strip() for s in operands]
        for i in range(opercount_di): # , operand in enumerate(operands):
            try:
                operand = operands[i]
            except IndexError:
                print("[error] IndexError, operand[{}]. {} at {:x}. opercount_de: {} opercount_di: {}".format(i, mnem, ea, opercount_de, opercount_di))
                # generate really bad exception
                a = fuckamup
            # .text:0000000140016120 0B8 BA 5F 60 38 CE                          mov     edx, 0CE38605Fh
            # mov EDX, 0xffffffffeeaf512a

            # len(d.operands) == 2 and d.operands[1].type == 'Immediate' and d.operands[1].value < 0 and d.operands[1].size == 32: v = d.operands[1].value; hex(v & 0xffffffff)
            #
            # pp({'insn_de.operands': insn_de.operands, 'insn_di.operands': operands})
            o = insn_de.operands[i]
            if o.value < 0 and o.size == 32 and o.type == 'Immediate':
                operand = "0x%x" % (o.value & 0xffffffff)

            #  post_colon = string_between('CR4:', ']', operand)
            #  if post_colon:
                #  size = insn_de.operands[i].size 
                #  if size:
                    #  dtyp_name = get_operand_size_type(size)
                    #  if dtyp_name != None:
                        #  operand = "{0} [{1}]".format(dtyp_name, post_colon)
                #  else:
                    #  operand = "[{0}]".format(post_colon)
            e = insn_de
            regex = r"\b(rip[+-]0x[0-9a-f]+)"
            operand = re.sub(regex, lambda m: ripadd(m.group(), e.address + e.size), operand, 0, re.IGNORECASE)
            regex = r"\b(0x[0-9])\b"
            operand = re.sub(regex, lambda m: str(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            regex = r"\b(0x[0-9a-f]{9,})\b"
            operand = re.sub(regex, lambda m: get_name_or_hex(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            opers.append(operand)

        asm = "{0} {1}".format(mnem, ", ".join(opers))
        if iterate: 
            yield asm
        #  else: return asm

def idii(ea = None, length = None):
    if ea is None:
        ea = idc.get_screen_ea()
    insn = idc.GetDisasm(ea)

    def getMnem(asm):
        mnem = asm.split(' ', 1)
        if mnem == '' or mnem in ('rep', 'repne', 'repe'):
            return insn.lower().replace('ret', 'retn')
        return mnem[0].lower().replace('ret', 'retn')

    mnem = getMnem(insn)
    if mnem == '' or mnem.startswith('rep'):
        return insn
    # mnem = insn_de.mnemonic.lower().replace('ret', 'retn').replace('int ', 'int')

    opers = []
    operand_part = string_between(' ', '', insn)
    if not operand_part:
        return mnem

    operands = operand_part.split(',')
    opercount = len(operands)
    operands = [s.strip() for s in operands]
    for i in range(opercount): # , operand in enumerate(operands):
        operand = operands[i]

        # any processing can happen here
        opers.append(operand)

    asm = "{0} {1}".format(mnem, ", ".join(opers))
    return asm

def mov_reg_reg():
    ba = bytearray()
    for b in range(0x00, 0x100):
        for c in range(0x00, 0x100):
            i = diInsn(ba.fromhex("{:02x}{:02x}".format(b, c)), 3)
            if i.startswith('mov '):
                print("{:08b} {:08b}\t{}".format(b, c, i))

def find_movs():
    ba = bytearray(b'000')
    for rex in range(0x40, 0x50):
        for a in range(0x0, 0x100):
            for b in range(0x00, 0x100):
                ba[0] = rex
                ba[1] = a
                ba[2] = b
                r = diInsn(ba, 3)
                if r.startswith(("mov ", "lea ")) and "0x" not in r:
                    print("{} : {:02x} {:02x} {:02x}".format(r, rex, a, b))


def transmute_mov(hex_string):
    """ transform various mov variants, lea and push/pop equiv. to standard sig

        @param hex_string pattern for single mov, lea, or combined push+pop
        @returns normalised pattern in the form, '8b c0' or '48 8b c0' or similar
    """
    def retsig(pk):
        return ' '.join(["{:02x}".format(x) for x in pk if x])

    for x in hex_string.split(" "):
        if len(x) > 2 or "?" in x:
            return hex_string

    rex = 0
    bt = bytearray().fromhex(hex_string)
    # remove leading rex (0x48) byte
    if len(bt) > 2:
        if bt[0] & 0xf0 == 0x40:
            rex = bt[0]
            bt = bt[1:]

    # check for 4 byte lea reg, [reg]  48 8d 04 24
    if len(bt) == 3:
        (a, z) = struct.unpack(">HB", bt)
        # reverse
        if rex and a & 0b1000110100000100 == 0b1000110100000100 and z == 0x24:
            b = a ^ 0b010011000000
            t1 =  (a & 0b00111000) >> 3                  
            t2 =  (a & 0b00000111) << 3                  
            b =  (b & ~0b00111111) | t1 | t2 
            return retsig(struct.pack(">BH", rex, b))

        if 0:
            if rex and a & 0b1000110100000100 == 0b1000110100000100 and z == 0x24:
                b = a ^ 0b011011000000
                return retsig(struct.pack(">BH", rex, b))

    if len(bt) == 2:
        (a, ) = struct.unpack(">H", bt)
        
        # [reverse] check for 3 byte lea reg, [reg] 48 8b c4
        if rex and a & 0b1000110100000100 == 0b1000110100000000:
            b = a ^        0b010011000000
            t1 =  (a & 0b00111000) >> 3                  
            t2 =  (a & 0b00000111) << 3                  
            b =  (b & ~0b00111111) | t1 | t2 
            return retsig(struct.pack(">BH", rex, b))
        
        # check for 3 byte lea reg, [reg] 48 8b c4
        if 0:
            if rex and a & 0b1000110100000100 == 0b1000110100000000:
                b = a ^ 0b011011000000
                return retsig(struct.pack(">BH", rex, b))

        # [reverse] check for push reg; pop reg
        if a & 0b1111100011111000 == 0b0101000001011000:
            t1 = (a & 0b0000011100000000) >> 8 
            t2 = (a & 0b0000000000000111) << 3
            b = 0x89c0 | t1 | t2
            rex = 0x48
            return retsig(struct.pack(">BH", rex, b))

        # check for push reg; pop reg
        if 0:
            if a & 0b1111100011111000 == 0b0101000001011000:
                t1 = (a & 0b0000011100000000) >> 5 
                t2 = (a & 0b0000000000000111)      
                b  = 0x8bc0 | t1 | t2   
                rex = 0x48
                return retsig(struct.pack(">BH", rex, b))

        # [reverse] check for mov reg, reg of the [48] 8d c0 form (returned as [48] 89 c0 form)
        if a & 0b1111101011000000 == \
               0b1000101011000000:
            t1 =  (a & 0b00111000) >> 3                  
            t2 =  (a & 0b00000111) << 3                  
            b =(a & ~0b1000111111) | t1 | t2 
            return retsig(struct.pack(">BH", rex, b))
        
        # check for mov reg, reg of the [48] 89 c0 form (returned as [48] 8d c0 form)
        if 0:
            if a & 0b1111100011000000 == \
                   0b1000100011000000:
                t1 =  (a & 0b00111000) >> 3                  
                t2 =  (a & 0b00000111) << 3                  
                b  = (a & ~0b00111111) | (1 << 9) | t1 | t2 
                return retsig(struct.pack(">BH", rex, b))
        

    return hex_string

def diStrip(ea1=None, ea2=None):
    """
    diStrip

    @param ea1: linear address
    """
    ea1 = GetChunkStart(ea1)
    if ea2 is None:
        ea2 = GetChunkEnd(ea1)
        
    if IsValidEA(ea1, ea2):
        # dprint("[xx] ea1, ea2")
        print("[xx] ea1:{}, ea2:{}".format(ea1, ea2))
        
        for head in idautils.Heads(ea1, ea2):
            if IsRef(head) and head != ea1:
                print("[diStrip] aborting, reference to {:x}".format(head))
                return 0
        r = nassemble(ea1, diida(ea1, ea2 - ea1, filter=lambda x, *a: not isNop(x)))
        if len(r) < ea2 - ea1:
            PatchBytes(ea1, r, "diStrip")
            new_end = ea1 + len(r)
            SetFuncEnd(ea1, new_end)
            PatchNops(new_end, ea2 - new_end)
            return ea2 - new_end

    return 0


def shr(dest, count=1, bits=64):
    return (dest & (1 << bits) - 1) >> count

def sar(dest, count=1, bits=64):
    return (dest >> count) & (1 << bits) - 1

def rol(value, count=1, nbits=64):
    offset = 0
    return idc.rotate_left(value & (1 << bits) - 1, count, nbits, offset) & (1 << bits) - 1

def ror(dest, count=1, bits=64):
    return rol(dest, -count)

def imul(subject, by, bits=64):
    r = (subject & (1 << bits) - 1) * by
    return ( r >> bits, r & (1 << bits) - 1 )

def shv86():
    shvScriptSize = 0x68
    shvScripts_first = 0x180164FF8
    shvScripts_size = 31
    shvScripts_last = shvScripts_first + shvScripts_size * shvScriptSize
    #  inc     ebx
    #  mov     rcx, cs:shvScripts.last
    rcx = shvScripts_last
    #  mov     r8, cs:shvScripts.first
    r8 = shvScripts_first
    #  sub     rcx, r8
    rcx -= r8
    #  mov     rax, rdi        ; 0x4EC4EC4EC4EC4EC5
    rax = 0x4EC4EC4EC4EC4EC5
    #  imul    rcx             ; RDX:RAX ← RAX ∗ r/m64.
                            #  ; rcx /= 13
    print("imul input:  {:x}, {:x}".format(rcx, rax))
    rdx, rax = imul(rcx, rax)
    print("imul result: {:x}, {:x}".format(rdx, rax))
    #  sar     rdx, 5          ; 0x220 -> 17
    rdx = sar(rdx, 5)
    #  mov     rax, rdx
    rax = rdx
    #  shr     rax, 3Fh
    #  dealing with carry? neg number?
    rax = shr(rax, 0x3f)
    #  add     rdx, rax
    rdx += rax
    #  mov     eax, ebx
    # ???
    #  cmp     rdx, rax
    return dict({
        'rax': rax,
        'rcx': rcx,
        'rdx': rdx,
    })
