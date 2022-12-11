import os
import re
import idc
import ida_ua, idaapi

#  try:
    #  import icstorm3c as icstorm3
#  except ModuleNotFoundError:
from iced_x86 import *

# This example produces the following output:
# 00007FFAC46ACDA4 48895C2410           mov       [rsp+10h],rbx
# 00007FFAC46ACDA9 4889742418           mov       [rsp+18h],rsi
# 00007FFAC46ACDAE 55                   push      rbp
# 00007FFAC46ACDAF 57                   push      rdi
# 00007FFAC46ACDB0 4156                 push      r14
# 00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]
# 00007FFAC46ACDBA 4881EC00020000       sub       rsp,200h
# 00007FFAC46ACDC1 488B0518570A00       mov       rax,[rel 7FFA`C475`24E0h]
# 00007FFAC46ACDC8 4833C4               xor       rax,rsp
# 00007FFAC46ACDCB 488985F0000000       mov       [rbp+0F0h],rax
# 00007FFAC46ACDD2 4C8B052F240A00       mov       r8,[rel 7FFA`C474`F208h]
# 00007FFAC46ACDD9 488D05787C0400       lea       rax,[rel 7FFA`C46F`4A58h]
# 00007FFAC46ACDE0 33FF                 xor       edi,edi
#
# Format specifiers example:
# xchg [rdx+rsi+16h],ah
# xchg %ah,0x16(%rdx,%rsi)
# xchg [rdx+rsi+16h],ah
# xchg ah,[rdx+rsi+16h]
# xchg ah,[rdx+rsi+16h]
# xchgb %ah, %ds:0x16(%rdx,%rsi)

def iccode(code, ea=None):
    """
    ictest

    @param code: binary blob
    @param ea: linear address
    """

    ea = eax(ea)

    EXAMPLE_CODE_BITNESS = 64
    EXAMPLE_CODE_RIP = ea
    EXAMPLE_CODE = code

    # Create the decoder and initialize RIP
    decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

    # Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
    # There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
    # speed is more important than being able to re-assemble formatted
    # instructions.
    #    formatter = FastFormatter()
    formatter = Formatter(FormatterSyntax.NASM)
    formatter.space_after_operand_separator = True
    formatter.show_branch_size = False
    formatter.hex_prefix = "0x"
    formatter.hex_suffix = ""



    # Change some options, there are many more
    #  formatter.digit_separator = "`"
    #  formatter.first_operand_char_index = 10

    # You can also call decoder.can_decode + decoder.decode()/decode_out(instr)
    # but the iterator is faster
    for instr in decoder:
        icsasm = formatter.format(instr)
        # You can also get only the mnemonic string, or only one or more of the operands:
        #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        #   op0_str = formatter.format_operand(instr, 0)
        #   operands_str = formatter.format_all_operands(instr)

        #  start_index = instr.ip - EXAMPLE_CODE_RIP
        #  bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
        #  # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        #  print(f"{instr.ip:016X} {bytes_str:20} {icsasm}")
        print(icsasm)


def ictest(ea=None, length=None):
    """
    ictest

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [ictest(x) for x in ea]

    ea = eax(ea)

    EXAMPLE_CODE_BITNESS = 64
    EXAMPLE_CODE_RIP = ea
    EXAMPLE_CODE = getCode(ea, length=length)

    # Create the decoder and initialize RIP
    decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

    # Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
    # There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
    # speed is more important than being able to re-assemble formatted
    # instructions.
    #    formatter = FastFormatter()
    formatter = Formatter(FormatterSyntax.NASM)
    formatter.space_after_operand_separator = True
    formatter.show_branch_size = False
    formatter.hex_prefix = "0x"
    formatter.hex_suffix = ""



    # Change some options, there are many more
    #  formatter.digit_separator = "`"
    #  formatter.first_operand_char_index = 10

    # You can also call decoder.can_decode + decoder.decode()/decode_out(instr)
    # but the iterator is faster
    for instr in decoder:
        icsasm = formatter.format(instr)
        # You can also get only the mnemonic string, or only one or more of the operands:
        #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        #   op0_str = formatter.format_operand(instr, 0)
        #   operands_str = formatter.format_all_operands(instr)

        #  start_index = instr.ip - EXAMPLE_CODE_RIP
        #  bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
        #  # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        #  print(f"{instr.ip:016X} {bytes_str:20} {icsasm}")
        print(icsasm)

    # Instruction also supports format specifiers, see the table below
    #  decoder = Decoder(64, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)
    #  instr = decoder.decode()
#  
    #  print()
    #  print("Format specifiers example:")
    #  print(f"{instr:f}")
    #  print(f"{instr:g}")
    #  print(f"{instr:i}")
    #  print(f"{instr:m}")
    #  print(f"{instr:n}")
    #  print(f"{instr:gG_xSs}")
    #  print(f"{instr:nxsB}")

    # ====== =============================================================================
    # F-Spec Description
    # ====== =============================================================================
    # f      Fast formatter (masm-like syntax)
    # g      GNU Assembler formatter
    # i      Intel (XED) formatter
    # m      masm formatter
    # n      nasm formatter
    # X      Uppercase hex numbers with ``0x`` prefix
    # x      Lowercase hex numbers with ``0x`` prefix
    # H      Uppercase hex numbers with ``h`` suffix
    # h      Lowercase hex numbers with ``h`` suffix
    # r      RIP-relative memory operands use RIP register instead of abs addr (``[rip+123h]`` vs ``[123456789ABCDEF0h]``)
    # U      Uppercase everything except numbers and hex prefixes/suffixes (ignored by fast fmt)
    # s      Add a space after the operand separator
    # S      Always show the segment register (memory operands)
    # B      Don't show the branch size (``SHORT`` or ``NEAR PTR``) (ignored by fast fmt)
    # G      (GNU Assembler): Add mnemonic size suffix (eg. ``movl`` vs ``mov``)
    # M      Always show the memory size (eg. ``BYTE PTR``) even when not needed
    # _      Use digit separators (eg. ``0x12345678`` vs ``0x1234_5678``) (ignored by fast fmt)
    # ====== =============================================================================

from string_between import string_between
from idc import *

try:
    from exectools import make_refresh, execfile, _import
    #  _import("from sfida.sf_common import asBytes, isInt")
    #  _import("from sftools import eax")
    #  _import("from sfida.sf_string_between import string_between")

    refresh_iced = make_refresh(os.path.abspath(__file__))
    refresh = make_refresh(os.path.abspath(__file__))
except ModuleNotFoundError:
    pass

def icstorm_64_bit_flag():
    return 64

def IdaGetMnem(ea):
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

GetInsnMnem = IdaGetMnem

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
        insnlen = ida_ua.decode_insn(insn, args[0])
        return insn
    else:
        return ida_ua.decode_insn(*args)

# DELIT_NOTRUNC
def IdaGetInsnLen(*args):
    lengths = []
    if len(args) == 1:
        if not isInt(args[0]):
            print("return_unless: isInt(args[0])")
            return 
        
        # ida method
        ea = args[0]
        insn = ida_ua.insn_t()
        insnlen = ida_ua.decode_insn(insn, ea)
        return insnlen

        if insnlen:
            lengths.append(insnlen)

        # icstorm method
        if False:
            insn_de = de(ea, 16)
            if insn_de:
                insn_de = insn_de[0]
                if insn_de.rawFlags == 0xffff:
                    return 0
                size = insn_de.size
                lengths.append(insnlen)

            if len(lengths) == 2 and lengths[0] and lengths[1] and lengths[0] == lengths[1]:
                return size
            if not lengths[0] or not lengths[1]:
                return 0
            
            raise RuntimeError("[IdaGetInsnLen] {:x} icffering insnlen: ida: {} icstorm: {}".format(ea, insnlen, size))
    else:
        return ida_ua.decode_insn(*args)

def getLength(ea):
    return IdaGetInsnLen(ea)

def GetInsLen(ea):
    return getLength(ea)

def GetFuncCode(ea):
    ea = eax(ea) or idc.here()
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
    ea = eax(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            if insn.itype not in (ida_allins.NN_nop, ida_allins.NN_jmp):
                result.extend([idc.get_wide_byte(x) for x in range(insn.ea, insn.ea + insn.size)])
    return bytearray(result)

def GetFuncCodeIndexNoJunk_(ea):
    ea = eax(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            if insn.itype not in (ida_allins.NN_nop, ida_allins.NN_jmp):
                result.extend([x for x in range(insn.ea, insn.ea + insn.size)])
    return result

def GetFuncCodeIndexTest(ea):
    ea = eax(ea) or idc.here()
    result = []
    for (startea, endea) in idautils.Chunks(ea):
        for head in idautils.Heads(startea, endea):
            insn = GetInsn(head)
            result.extend([x for x in range(insn.ea, insn.ea + insn.size)])
    return result

def GetFuncCodeIndex(ea):
    ea = eax(ea) or idc.here()
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

def icInsn(code, offset = 0):
    if isinstance(code, list):
        code = bytearray(code)
    if isinstance(code, bytearray):
        #  code = code.decode('raw_unicode_escape')
        code = asBytesRaw(code)
    decoder = Decoder(icstorm_64_bit_flag(), code, ip=offset)

    # Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
    # There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
    # speed is more important than being able to re-assemble formatted
    # instructions.
    #    formatter = FastFormatter()
    formatter = Formatter(FormatterSyntax.NASM)
    formatter.space_after_operand_separator = True
    formatter.show_branch_size = False
    formatter.hex_prefix = "0x"
    formatter.hex_suffix = ""

    decoder = Decoder(icstorm_64_bit_flag(), code, ip=offset)
    instr = decoder.decode()                                 
    return f"{instr:nxsB}"

def icInsnsPretty(code, ea = None, dt=icstorm_64_bit_flag()):
    iterable = icInsnsIter(asBytes(bytearray(code)), ea)
    for (offset, size, instruction, hexdump) in iterable:
        yield instruction.lower().replace('[cr4:', '[')

def icInsns(code, ea = None, dt=icstorm_64_bit_flag()):
    iterable = icInsnsIter(asBytes(bytearray(code)), ea)
    return [x for x in iterable]


#  def icInsn(code, offset = 0):
    #  dt       = icstorm_64_bit_flag()
    #  iterable = icstorm3.DecodeGenerator(offset, code, dt)
    #  for (offset, size, instruction, hexdump) in iterable:
        #  return instruction

def icInsnsIter(code, ea = None, dt=icstorm_64_bit_flag()):
    if ea is None:
        ea = idc.get_screen_ea()
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
    return icstorm3.DecodeGenerator(ea, code, dt)

def idafy(operand, ea, size):
    regex = r"\b(rip[+-]0x[0-9a-f]+)"
    operand = re.sub(regex, lambda m: ripadd(m.group(), ea + size), operand, 0, re.IGNORECASE)
    regex = r"\b(0x[0-9])\b"
    operand = re.sub(regex, lambda m: str(int(m.group(), 16)), operand, 0, re.IGNORECASE)
    regex = r"\b(0x[0-9a-f]{8,})\b"
    operand = re.sub(regex, lambda m: get_name_or_hex(int(m.group(), 16)), operand, 0, re.IGNORECASE)
    return operand

def icInsnsObjectIter(code, ea=None, dt=icstorm_64_bit_flag()):
    for it in icInsnsIter(asBytes(bytearray(code)), ea):
        yield SimpleAttrDict({
            'ea': it[0],
            'size': it[1],
            'insn': idafy(it[2], it[0], it[1]),
            'bytes': bytearray().fromhex(it[3]),
            })



def icCode(code, offset = 0):
    dt       = icstorm_64_bit_flag()
    iterable = icstorm3.DecodeGenerator(offset, code, dt)
    for (offset, size, instruction, hexdump) in iterable:
        print("%.8x: %-32s %s" % (offset, hexdump, instruction))

    # It could also be used as a returned list:
    # l = icstorm3.Decode(offset, code, options.dt)
    # for (offset, size, instruction, hexdump) in l:
    #     print("%.8x: %-32s %s" % (offset, hexdump, instruction))

def icdCode(code, ea = 0, dt=icstorm_64_bit_flag(), features = 0):
    return icstorm3.Decompose(ea, code, dt, features)

def icdCodeIter(code, ea = 0, dt=icstorm_64_bit_flag(), features = 0):
    return icstorm3.DecomposeGenerator(ea, code, dt, features)

def icd(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = IdaGetInsnLen(ea)
    return icdCode(getCode(ea, length), ea)

def icdrange(ea = None, length = None, dt=icstorm_64_bit_flag(), features = 0):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = IdaGetInsnLen(ea)
    return icdCodeIter(getCode(ea, length), ea)

def icdranger(ea = None, length = None, dt=icstorm_64_bit_flag(), features = 0):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    return icdCodeIter(getCode(ea, length), ea, features = features)

def icdr(ea = None, length = None, features = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    if length > ea:
        length = length - ea
    if features is not None:
        gen = icdranger(ea, length, features = features)
    else:
        gen = icdranger(ea,length)
    return [x for x in gen] 

def icdstart2(ea=None, length=None):
    """
    [alpha] attempt to find start of function 

    @param ea: linear address
    @param length: how many preview bytes to check
    """
    if isinstance(ea, list):
        return [icdstart(x) for x in ea]

    ea = eax(ea)
    length = length or 300
    l = [icdr(ea - x, x) for x in range(1, length)]
    j = [len(x) for x in l]
    m = _.max(j)
    p = j.index(m) + 1
    q = l[p-1]
    setglobal('icdstart_debug', {'l': l, 'j': j, 'm': m, 'p': p, 'q': q})
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

def icdstart(ea=None, length=None):
    """
    [alpha] attempt to find start of function containing multiple 'PUSH'
    instructions by icsassembling from `ea` backwards

    @param ea: linear address
    @param length: how many preview bytes to check
    """
    if isinstance(ea, list):
        return [icdstart(x) for x in ea]

    ea = eax(ea)
    length = length or 300
    l = [icdr(ea - x, x) for x in range(1, length)]
    j = [len(x) for x in l]
    m = _.max(j)
    p = j.index(m) + 1
    q = l[p-1]
    setglobal('icdstart_debug', {'l': l, 'j': j, 'm': m, 'p': p, 'q': q})
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

def icdri(ea = None, length = None, features = None):
    def instruction(insn):
        s = str(insn)
        if insn.rawFlags & (1 << 7):
            # rip_relative
            opn = -1
            for i, o in enumerate(insn.operands):
                # must be a numeric/binary check for this
                if o.type == 'AbsoluteMemory': 
                    target = o.icsp + insn.address + insn.size
                    opn = i
            if opn > -1:
                regex = r"(rip[+-]0[x0-9a-f]+)"
                s = re.sub(regex, hex(target), s, flags=re.IGNORECASE)
        return re.sub('0x(145[0-9a-fA-F]{6})', lambda m: label(int(m.group(1), 16)), s)

    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = 1024
    if features is not None:
        d = icdr(ea, length, features = features)
    else:
        d = icdr(ea,length)
    targets = [icstorm3._getRegularTarget(x) for x in d]
    targets = [x for x in targets if x and x > 0x145000000]
    for i in d:
        if i.address in targets:
            yield label(i.address, colon=1) + instruction(i)
        else:
            yield _di_indent(i) + instruction(i)
            
def icdrip(ea = None):
    if ea is None:
        ea = ScreenEA()
    g = icdri(ea, 0x8000, features=icstorm3.DF_STOP_ON_UNDECODEABLE)
    output = "{0}: ; {1:x}\n".format(idc.get_name(ea, GN_VISIBLE), ea)
    output += '\n'.join([x for x in g])
    output += '\n\n'
    return output

def icdriploc():
    output = ''
    for f in FunctionsMatching('.*_RELOC_11'):
        output += icdrip(f)
    return output

def ic(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None:
        length = IdaGetInsnLen(ea)
    return icCode(getCode(ea, length), ea)

def ici(ea = None, length = None):
    if ea is None:
        ea = ScreenEA()
    if length is None: # Default to 1 instruction
        length = IdaGetInsnLen(ea)
    return icInsn(getCode(ea, length), ea)

def log2(v):
    """
    http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
    """
    a = [0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9]
    n = ((v * 0x077CB531) & 0xffffffff) >> 27
    r = a[n];
    return r

def ic_get_operand_size_type(size):
    sizes = ['byte', 'word', 'dword', 'qword', 'dqword', 'tword']
    n = log2(size // 8);
    return sizes[n];

def icida(ea=None, length=None, mnemOnly=False, filter=None, iteratee=None, returnLength=False, labels=False):
    if isinstance(ea, list):
        return [icida(x) for x in ea]
    ea = eax(ea)
    if length is None: # Default to 1 instruction
        length = IdaGetInsnLen(ea) or 15
    if length > ea:
        length = length - ea
    start_ea = ea
    end = ea + length
    next_ea = ea
    result = []
    while next_ea < end and IdaGetInsnLen(next_ea):
        ea = next_ea
        length = IdaGetInsnLen(ea)
        next_ea = ea + length
        if next_ea > end:
            continue
        if callable(filter):
            if not filter(ea):
                continue
        insn = icInsn(getCode(ea, length), ea) # .lower()
        insn_label = idc.get_name(ea, ida_name.GN_VISIBLE)

        def getMnem(asm, _insn_de=None):
            if asm.startswith('rep'):
                return asm
            mnem = asm.split(' ')
            return mnem[0].lower().replace('ret', 'retn')

        mnem = getMnem(insn)
        if mnem == '' or mnem.startswith(('rep', 'repne', 'repe')):
            result.append(insn)
            continue

        if mnemOnly:
            result.append(mnem)
            continue

        opers = []
        operand_part = string_between(' ', '', insn)
        if not operand_part:
            result.append(mnem)
            # result.append(string_between('', ' ', insn, repl=mnem))
            continue

        operands = operand_part.split(',')
        operands = [s.strip() for s in operands]
        for i in range(len(operands)): # , operand in enumerate(operands):
            operand = operands[i]
            # .text:0000000140016120 0B8 BA 5F 60 38 CE                          mov     edx, 0CE38605Fh
            # mov EDX, 0xffffffffeeaf512a

            # len(d.operands) == 2 and d.operands[1].type == 'Immediate' and d.operands[1].value < 0 and d.operands[1].size == 32: v = d.operands[1].value; hex(v & 0xffffffff)
            #  o = insn_de.operands[i]
            #  if o.value < 0 and o.size == 32 and o.type == 'Immediate':
                #  operand = "0x%x" % (o.value & 0xffffffff)

            #  post_colon = string_between('CR4:', ']', operand)
            #  if post_colon:
                #  size = insn_de.operands[i].size 
                #  if size:
                    #  dtyp_name = ic_get_operand_size_type(size)
                    #  if dtyp_name != None:
                        #  operand = "{0} [{1}]".format(dtyp_name, post_colon)
                #  else:
                    #  operand = "[{0}]".format(post_colon)
            #  e = insn_de
            #  regex = r"\b(rip[+-]0x[0-9a-f]+)"
            #  operand = re.sub(regex, lambda m: ripadd(m.group(), e.address + e.size), operand, 0, re.IGNORECASE)
            #  regex = r"\b(0x[0-9])\b"
            #  operand = re.sub(regex, lambda m: str(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            regex = r"\b(0x[0-9a-f]{8,})\b"
            operand = re.sub(regex, lambda m: get_name_or_hex(int(m.group(), 16)), operand, 0, re.IGNORECASE)
            opers.append(operand)

        asm = ""
        if labels:
            if insn_label:
                asm = insn_label + ":\n"
            asm += "    "

        asm += "{0} {1}".format(mnem, ", ".join(opers))
        result.append(asm.rstrip())

    if returnLength:
        return next_ea - start_ea, '\n'.join(result)
    return '\n'.join(result)

def icidaIter(ea = None, length = None, code = None, mnemOnly = False, iterate = False, labels = True):
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

    # dprint("[icdbug] ea, length, code")
    #  print("[icdbug] ea:{}, length:{}, code:{}".format(ea, length, code))
    
    if ea is None:
        ea = ScreenEA()
    if length is None: # Default to 1 instruction
        length = IdaGetInsnLen(ea)
    insn_iter = icInsnsIter(getCode(ea, length) if not code else code, ea) # .lower()
    insn_de_iter = icdCodeIter(getCode(ea, length) if not code else code, ea)
    # dprint("[icdbug] insn_iter, insn_de_iter")
    #  print("[icdbug] insn_iter:{}, insn_de_iter:{}".format(insn_iter, insn_de_iter))

    def getMnem(asm, _insn_de=None):
        if _insn_de:
            mnem = _insn_de.mnemonic.lower()
            return mnem.replace('ret', 'retn')
        else:
            mnem = asm.split(' ', 1)
        if mnem == '' or mnem in ('rep', 'repne', 'repe'):
            return insn.lower()
        return mnem[0].lower().replace('ret', 'retn')

    for insn_di, insn_de in zip(insn_iter, insn_de_iter):
        # dprint("[icdbug] insn_di, insn_de")
        #  print("[icdbug] insn_di:{}, insn_de:{}".format(insn_di, insn_de))
            
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

        mnem = getMnem(insn, insn_de)
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
                    #  dtyp_name = ic_get_operand_size_type(size)
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

def icii(ea = None, length = None):
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

def icStrip(ea1=None, ea2=None):
    """
    icStrip

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
                print("[icStrip] aborting, reference to {:x}".format(head))
                return 0
        r = nassemble(ea1, icida(ea1, ea2 - ea1, filter=lambda x, *a: not isNop(x)))
        if len(r) < ea2 - ea1:
            PatchBytes(ea1, r, "icStrip")
            new_end = ea1 + len(r)
            SetFuncEnd(ea1, new_end)
            PatchNops(new_end, ea2 - new_end)
            return ea2 - new_end

    return 0
