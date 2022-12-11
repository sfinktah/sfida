# hotkey_utils.py - bNull
#
# Some useful shortcuts for binding to hotkeys. Current output/hotkeys:
#
# [+] Bound make_dwords to Ctrl-Alt-D
# [+] Bound make_cstrings to Ctrl-Alt-A
# [+] Bound make_offset to Ctrl-Alt-O

# &
# &.update_file(__file__, __version_hash__, __version_info__)
from binascii import unhexlify
import ida_idaapi
from idautils import Heads, Chunks
import idaapi
import idc
import inspect
import time
import os
import ida_auto
from itertools import islice
from idc import *
from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets
delayed_exec_timer = QtCore.QTimer()

import ida_kernwin

if not idc:
    # from classmaker import sanitizedName, make_vfunc_struct_sig
    from commenter import Commenter
    # from di import *
    # from helpers import unpatch
    from is_flags import HasUserName, IsCode_
    from membrick import FindInSegments
    from obfu_helpers import MakeSigned, PatchNops
    from sfcommon import GetFuncStart
    from slowtrace_helpers import GetNumChunks
    from start import *
    from string_between import string_between, string_between

from exectools import make_refresh
refresh_hotkey_utils = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

if not 'searches' in globals():
    searches = dict()

class MyHotkey(object):

    """Docstring for MyHotkey. """

    def __init__(self, shortcut, func, ctx=None, active=False):
        """TODO: to be defined1.

        :shortcut: TODO
        :func: TODO

        """
        self.shortcut = shortcut
        self.func = func
        self.ctx = None
        self.active = False

    def funcname(self):
        return string_between('function ', ' at ', str(self.func))

class MyHotkeys(object):
    """Collection of MyHotkey instances"""

    def __init__(self, items=None):
        """@todo: to be defined """
        self.hotkeys = []
        for hotkey in A(items):
            self.append(hotkey)

    def __len__(self):
        return self.hotkeys.__len__()
    
    def __getitem__(self, key):
        return self.hotkeys.__getitem__(key)
    
    def __setitem__(self, key, value):
        self.hotkeys.__setitem__(key, value)
    
    def __delitem__(self, key):
        self.hotkeys.__delitem__(key)
    
    def __iter__(self):
        return self.hotkeys.__iter__()
    
    def __reversed__(self):
        return self.hotkeys.__reversed__()
    
    def __contains__(self, item):
        return self.hotkeys.__containers__(item)

    def _remove(self, hotkey):
        func_name = hotkey.funcname()
        ctx       = hotkey.ctx
        shortcut  = hotkey.shortcut
        #  print("[helpers::load_hotkeys] shortcut:{}, 'func_name':{}, ctx:{}".format(hotkey.shortcut, 'func_name', not not ctx))
        if ctx:
            if ida_kernwin.del_hotkey(ctx):
                # print("[+] Removed previous binding: %s to %s" % (func_name, shortcut))
                pass
            else:
                print("[-] Couldn't remove previous binding: %s to %s" % (func_name, shortcut))
                pass

            hotkey.ctx = None
            hotkey.active = False

    def _add(self, hotkey):
        func_name = hotkey.funcname()
        shortcut  = hotkey.shortcut
        func      = hotkey.func
        #  print("[helpers::load_hotkeys] shortcut:{}, 'func_name':{}, ctx:{}".format(hotkey.shortcut, 'func_name', not not ctx))
        self._remove(hotkey)
        new_ctx = ida_kernwin.add_hotkey(shortcut, func)
        if new_ctx:
            # print("[+] Bound %s to %s" % (func_name, shortcut))
            hotkey.ctx = new_ctx
            hotkey.active = True
        else:
            print("[-] Error: Unable to bind %s to %s" % ('func_name', shortcut))

    def find(self, match_object):
        found = None
        for hotkey in self.hotkeys:
            for key, value in match_object.items():
                if getattr(hotkey, key, {}) == value:
                    found = hotkey
                else:
                    found = None
                    break
            if found:
                break
        return found

    def append(self, hotkey):
        existing = self.find(_.pick(hotkey, 'shortcut'))
        if existing:
            self.remove(existing)

        self._add(hotkey)
        self.hotkeys.append(hotkey)
    
    def clear(self):
        for hotkey in self.hotkeys[:]:
            # print("removing hotkey '{}'".format(hotkey.shortcut))
            self._remove(hotkey)
            self.hotkeys.remove(hotkey)
    
    def copy(self):
        return (type(self))(self.hotkeys.copy())
    
    def count(self):
        return self.hotkeys.count()
    
    def extend(self, iterable):
        for item in iterable:
            self.append(item)
    
    def index(self, value, start=0, stop=9223372036854775807):
        self.hotkeys.index(value, start, stop)
    
    def remove(self, value):
        self._remove(value)
        self.hotkeys.remove(value)
    
    #  def reverse(self):
        #  self.hotkeys.reverse()
    #  
    #  def sort(self):
        #  self.hotkeys.sort()
    #  
    #  def insert(self, index, object):
        #  self.hotkeys.insert(index, object)
    #  
    #  def pop(self, index=-1):
        #  return self.hotkeys.pop(index)
    
    
def mark(ea, comment):
    c = Commenter(ea, 'func')
    if not c.exists(comment):
        c.add(comment)


def remove(ea, comment):
    c = Commenter(ea, 'func')
    return c.remove(comment)


def comment_sig(ea, pattern, _type='SHORTEST'):
    version = idc.get_input_file_path().split('\\')[2]
    mark(ea, "[PATTERN;%s:%s;VERSION:%s] %s" % (_type, idc.get_name(ea), version, pattern))
    mark(ea, "[ADDRESS;NORMALISED:0x%x;VERSION:%s]" % (ea, version))


def selection_is_valid(selection, ea):
    """If the cursor is not at the beginning or the end of our selection, assume that
    something bad has gone wrong and bail out instead of turning a lot of important
    things into dwords.
    """
    if not (ea == selection[1] or ea == selection[2] - 1):
        print("%012x: Selection[1]" % selection[1])
        print("%012x: Selection[2]" % selection[2])
        print("%012x: ScreenEA    " % ea)
        return False
    else:
        return True


def get_selected_bytes():
    """Highlight a range and turn it into dwords

    NOTE: read_selection appears to be a fickle bitch. You absolutely have to
    select more than one line at a time in order for it to work as expected.
    """

    selected = idaapi.read_selection()
    curr_ea = idc.get_screen_ea()
    print("[+] Processing range: %x - %x" % (selected[1], selected[2]))

    # refer to selection_is_valid comments regarding the need for this check

    if (selection_is_valid(selected, curr_ea)):
        return selected
    else:
        return None


# It may be useful to know how many arguments the target function will take.
# import inspect
# inspect.getargspec(fn)
# Python>inspect.getargspec(slowtrace2)
# ArgSpec(args=['ea', 'max_depth'], varargs=None, keywords=None, defaults=(None, 4))
class Selection(object):
    """Perform a single command on a selection of addresses"""

    def __init__(self, fn, step=None):
        """Take the function to excute as the constructor's argument

        :fn: a user-defined or built-in function or method, or a class object

        """
        self._fn = fn
        self._selected = get_selected_bytes()
        if step is None:
            self._step = NextNotTail
        else:
            self._step = step

    def increment(self, inc):
        """increments value by number or function

        :inc: pre-increment value
        :returns: TODO

        """
        if callable(self._step):
            return self._step(inc)
        return inc + self._step

    def apply(self, *_args):
        """Apply arguments (if any) to function specified in constructor

        :args: varargs
        :returns: list of results

        """
        results = []
        ea = self._selected[1]
        while ea < self._selected[2]:  # maybe '<='
            args = [ea]
            args += (list(_args))
            print("Calling fn with args %s" % (", ".join(map(lambda x: str(x), args))))
            results.append(self._fn(*args))
            ea = self.increment(ea)
        return results


def make_offset():
    """Resolve an offset to a pointer

    For some reason, it seems as though IDA will not auto-define a pointer DWORD. Ex:

       .rodata:08E30000                 dd 8271234h

    In the case that 0x8271234 is actually a function, resolving the offset will
    result in:

       .rodata:08E30000                 dd offset _ZN29ClassAD1Ev ; ClassA::~ClassA()
    """
    idc.OpOffset(idc.get_screen_ea(), 0)


def div3(n):
    return (n + 1) // 3


def round3(n):
    return 3 * div3(n)


def get_bytes_():
    byteList = list();
    for ea in range(idc.SelStart(), idc.SelEnd()):
        byteList.append(idc.get_wide_byte(ea))
    return " ".join(map(lambda x: "%02x" % x, byteList))


def bytes_as_hex(bytes):
    return " ".join(map(lambda x: "%02x" % x, bytes))


def bytes_as_hex_no_spaces(bytes):
    return "".join(map(lambda x: "%02x" % x, bytes))


def get_bytes_chunked_from_comb(addresses):
    byteList = list()
    for ea, count in addresses:
        bytes = [idc.get_wide_byte(ea + i) for i in range(count)]
        byteList.append(bytes)
    return [bytes_as_hex(x) for x in byteList]


def get_bytes_chunked(start=0, end=0, maxlen=65535):
    byteList = list()
    ea = start if start else idc.SelStart()
    end = end if end else idc.SelEnd()
    inslen = 1
    count = 0
    while ea < end and inslen and count < maxlen:
        inslen = IdaGetInsnLen(ea)
        count += inslen
        bytes = [idc.get_wide_byte(ea + i) for i in range(inslen)]
        byteList.append(bytes)
        ea += inslen
    return [bytes_as_hex(x) for x in byteList]


def get_data_ref(frm, var, _globals=None):
    _globals = A(_globals)
    from JsonStoredList import JsonStoredDict
    with JsonStoredDict('datarefs.json') as __data_ref_cache:
        fullvar = idaapi.get_name(GetFuncStart(frm)) + "." + var
        if fullvar in __data_ref_cache:
            return __data_ref_cache[fullvar]
        ea = idc.get_name_ea_simple(var)
        inslen = IdaGetInsnLen(frm)
        for offset in range(inslen - 4, 1, -1):
            if MakeSigned(idc.get_wide_dword(frm + offset), 32) + frm + inslen == ea:
                insOffset = frm - GetFuncStart(frm)
                # print(" %% Found reference at offset %i (%i) of instruction offset %i of %s" % (offset, inslen - offset, insOffset, idc.get_func_name(frm)))
                #  pattern = sig_maker_ex(GetFuncStart(frm), GetFuncEnd(frm), offset = insOffset + offset, rip = inslen - offset, MyGetType(ea), name=var)
                pattern = "mem(LocByName('{}')).chain().add({}).rip({}).type('{}').name('{}')".format(
                    idc.get_name(GetFuncStart(frm)), insOffset + offset, inslen - offset, MyGetType(ea), var)
                #  idc.apply_type(EA(), byteify(unbyteify(idc.get_tinfo(EA()))))
                if isinstance(pattern, str) and len(pattern) > 0:
                    __data_ref_cache[fullvar] = pattern
                    _globals.append(pattern)
                    return pattern
                else:
                    print(" %% couldn't get unique pattern for function")


def get_instructions_chunked(start=0, end=0, addresses=None, maxlen=65535, _globals=None):
    _globals = A(_globals)
    byteList = list()
    if isinstance(addresses, list):
        for ea, count in addresses:
            inslen = IdaGetInsnLen(ea)
            if inslen:
                count += inslen
                disasm = idc.GetDisasm(ea).split(';')[0]
                var = string_between('cs:', '', disasm)
                if var and not ~var.find(' '):
                    addr = idc.get_name_ea_simple(var)
                    if addr < idc.BADADDR and HasUserName(addr):
                        loc = get_data_ref(ea, var, _globals)
                        print(" %% global: 0x{:x} {} {}: {}".format(addr, MyGetType(addr), var, loc))
                        Commenter(addr).add('[DATA-PATTERN: {}]'.format(loc))

                byteList.append(disasm)
            else:
                byteList.append('invalid')
                break
        return byteList

    ea = start if start else idc.SelStart()
    end = end if end else idc.SelEnd()
    inslen = 1
    count = 0
    while ea < end and inslen and count < maxlen:
        if IsCode_(ea):
            inslen = IdaGetInsnLen(ea)
            if inslen:
                count += inslen
                disasm = idc.GetDisasm(ea).split(';')[0]
                var = string_between('cs:', '', disasm)
                if var and not ~var.find(' '):
                    addr = get_name_ea_simple(var)
                    if addr < BADADDR and HasUserName(addr):
                        loc = get_data_ref(ea, var, _globals)
                        print(" %% global: 0x{:x} {} {}: {}".format(addr, MyGetType(addr), var, loc))
                        Commenter(addr).add('[DATA-PATTERN: {}]'.format(loc))

                byteList.append(disasm)
                ea += inslen
        else:
            byteList.append('invalid')
            break
    return byteList


# 48 83 EC 28                                sub     rsp, 28h
# 33 C0                                      xor     eax, eax
# 38 05 F5 65 C9 01                          cmp     cs:_bIsOnline, al
# 74 0A                                      jz      short loc_7FF742F24438
# 83 F9 1F                                   cmp     ecx, 1Fh
# 77 05                                      ja      short loc_7FF742F24438
# E8 6C 02 59 00                             call    playerIndexAsNetGamePlayer
# 0F 85 A8 00 00 00                          jnz     xxx

# (80 A1 C1 01 00 00 BF)
#  80 a1 c1 ?? ?? ?? ??     and     byte ptr [rcx+1C1h], 0BFh; self->byte_01c1 &= 0xBFu;  // b 1011 1111 
#  8a c2                    mov     al, dl                   ; result = b1 << 6;          // b 0100 1111 
#  24 01                    and     al, 1                    ; self->byte_01c1 |= result;                                   
#  c0 e0 06                 shl     al, 6
#  08 81 c1 01 00 00        or      [rcx+1C1h], al
#
# 80 a1 ?? 01 00 00 ?? 8a c2 24 01 c0 e0 ?? 08 81 ?? 01 00 00
# 80 a1 ?? ?? 00 00 ?? 8a c2 24 01 c0 e0 ?? 08 81 ?? ?? 00 00
#
#  80 a1 c1 ?? ?? ?? ??     and     byte ptr [rcx+1C1h], 0BFh; self->byte_01c1 &= 0xBFu;  // b 1011 1111 
#  8a c2                    mov     al, dl                   ; result = b1 << 6;          // b 0100 1111 
#  24 01                    and     al, 1                    ; self->byte_01c1 |= result;                                   
#  c0 e0 06                 shl     al, 6
#  08 81 c1 01 00 00        or      [rcx+1C1h], al

#  .text2:0000000144CC1145 028 0F BA B7 88 01 00 00 08                 btr     dword ptr [rdi+188h], 8
#  .text2:0000000144CC114D 028 83 E3 01                                and     ebx, 1
#  .text2:0000000144CC1150 028 C1 E3 08                                shl     ebx, 8
#  .text2:0000000144CC1153 028 09 9F 88 01 00 00                       or      [rdi+188h], ebx

#  0F BA B7 ?? ?? ?? 00 ??   btr     dword ptr [rdi+188h], 8
#  83 E3 01                  and     ebx, 1
#  C1 E3 ??                  shl     ebx, 8
#  09 9F ?? ?? ?? 00         or      [rdi+188h], ebx
#
#
#
# 0F BA B7 ?? ?? ?? 00 ?? 83 ?? 01 C1 ?? ?? 09 9F ?? ?? ?? 00


def make_sig_from_comb(_chunks, addresses, ripRelAsQuad=False, replValues=None):
    def addReplValue(_replValue):
        if isinstance(replValues, list):
            replValues.append(_replValue)

    _pe = idautils.peutils_t()
    _base = _pe.imagebase
    procSet = set([o_far, o_near, o_mem, o_phrase])
    newchunks = []
    chunks = list()
    chunks.extend(_chunks.lower())
    chunks.reverse()

    for ea, octets in addresses:
        chunk = chunks.pop()
        mnem = IdaGetMnem(ea)
        op0 = idc.get_operand_type(ea, 0)
        op1 = idc.get_operand_type(ea, 1)
        opSet = set([op0, op1])
        #  ['o_mem', 2, 'Direct Memory Reference  (DATA)', 'addr'],
        #  ['o_phrase', 3, 'Memory Ref [Base Reg + Index Reg]', 'phrase'],
        #  ['o_far', 6, 'Immediate Far Address  (CODE)', 'addr'],
        #  ['o_near', 7, 'Immediate Near Address (CODE)', 'addr'],
        # dprint("[debug] ea, chunks, opSet.isdisjoint(procSet)")
        if debug: print("[debug] ea:{:x}, chunks:{}, opSet.isdisjoint(procSet):{}".format(ea, chunks, opSet.isdisjoint(procSet)))
        
        changed = 0
        if not opSet.isdisjoint(procSet):
            opNum = -1
            for i in range(2):
                if idc.get_operand_type(ea, i) in procSet:
                    opNum = i
            
            if opNum > -1:
                _opValue = GetOperandValue(ea, opNum)
                _insnEnd = ea + GetInsnLen(ea)
                _tmp1 = str("{:08x}".format((_opValue - _insnEnd) & 0xffffffff))
                _tmp2 = [''.join(y) for y in [x for x in chunk_tuple(_tmp1, 2)]]
                _tmp2.reverse()
                _ripRelHex = ' '.join(_tmp2)
                _insnHex = ' '.join(["{:02x}".format(idc.get_wide_byte(ea + a)) for a in range(GetInsnLen(ea))])
                _offsetChars = _insnHex.find(_ripRelHex)
                # dprint("[debug] _ripRelHex, _insnHex, _offsetChars")
                if debug: print("[debug] _ripRelHex:{}, _insnHex:{}, _offsetChars:{}".format(_ripRelHex, _insnHex, _offsetChars))
                
                
                if ~_offsetChars:
                    _offsetBytes = div3(_offsetChars)
                    _replValue = "{:08x}".format(_opValue - _base)
                    if ripRelAsQuad:
                        _insn = idautils.DecodeInstruction(ea)
                        if _insn.itype in (idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni, idaapi.NN_jmpshort) or \
                           _insn.itype in (idaapi.NN_ja, idaapi.NN_jae,   idaapi.NN_jb,   idaapi.NN_jbe,  idaapi.NN_jc,  idaapi.NN_jcxz,
                                idaapi.NN_jecxz,     idaapi.NN_jrcxz, idaapi.NN_je,   idaapi.NN_jg,   idaapi.NN_jge, idaapi.NN_jl,   idaapi.NN_jle,
                                idaapi.NN_jna,       idaapi.NN_jnae,  idaapi.NN_jnb,  idaapi.NN_jnbe, idaapi.NN_jnc, idaapi.NN_jne,  idaapi.NN_jng,
                                idaapi.NN_jnge,      idaapi.NN_jnl,   idaapi.NN_jnle, idaapi.NN_jno,  idaapi.NN_jnp, idaapi.NN_jns,  idaapi.NN_jnz,
                                idaapi.NN_jo,        idaapi.NN_jp,    idaapi.NN_jpe,  idaapi.NN_jpo,  idaapi.NN_js,  idaapi.NN_jz) or \
                           _insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                               if IsFuncHead(_opValue) and HasUserName(_opValue) and not ~idc.get_func_name(_opValue).find('___') and not ~idc.get_func_name(_opValue).find('::_0x'):
                                   _replValue = "@{}".format(TagRemoveSubstring(idc.get_func_name(_opValue)))
                               elif (IsSameChunk(ea, _opValue)):
                                   _replValue = "+{:x}".format(_opValue - ea).replace("+-", "-")
                               elif (IsSameFunc(ea, _opValue)):
                                   _replValue = "~{:08x}".format(_opValue - _base)
                        elif _insn.itype in (idaapi.NN_lea, idaapi.NN_mov):
                            if idc.get_name(_opValue).startswith('??_7'):
                                _replValue = idc.get_name(_opValue, GN_DEMANGLED).replace('const ', '').replace('`', '').replace("'", '')
                                addReplValue(_replValue)
                            elif idc.get_name(_opValue).startswith('a'):
                                # st = idc.get_strlit_contents(_opValue, 256, idc.STRTYPE_C)
                                st = mb(_opValue).str()
                                if st and re.match(asBytes(r"""[-_a-zA-Z0-9./,'"]+$"""), st):
                                    _replValue = "'{}'".format(asString(st).replace("'", "\\'").replace('"', '\\"'))
                                    addReplValue(_replValue)
                            elif HasUserName(idc.get_item_head(_opValue)):
                                _replValue = "[{}]".format(TagRemoveSubstring(idc.get_name(idc.get_item_head(_opValue))))
                                addReplValue(_replValue)
                        chunk = "{}{}{}".format(_insnHex[0:_offsetChars], _replValue, _insnHex[_offsetChars+11:])
                        changed = 1
                    else:
                        chunk = "{}?? ?? ?? ??{}".format(_insnHex[0:_offsetChars], _insnHex[_offsetChars+11:])
                        changed = 1

        # mov     rax, [rcx+0E8h]  ; o_reg, o_displ
        if changed or (set([o_reg, o_displ]) <= opset):
            pass
        elif mnem == 'test': # octets == 7 and chunk[0:5] == '48 f7':
            print("Testing letting test go without wildcards: {}".format(idc.GetDisasm(ea)))
            pass
        elif octets == 7 and chunk[0:5] == 'c7 43':
            pass
        elif octets == 6 and chunk[0:2] == '41':
            pass
        # 48 81 ec 80 00 00 00                 sub     rsp, 80h
        elif octets == 7 and chunk[0:5] == '48 81':
            pass
        elif octets == 7 and chunk[0:5] == '80 a1':
            pass
        elif octets == 7 and chunk[0:5] == '81 a1':
            pass
        elif octets == 7 and chunk[0:5] == '83 a1':
            pass
        elif (mnem == 'cmp' or mnem == 'mov') and idc.get_operand_type(ea, 0) == o_reg and idc.get_operand_type(ea,
                                                                                                                1) == o_imm:
            print("Testing letting cmp/mov o_reg, o_imm go without wildcards: {}".format(idc.GetDisasm(ea)))
            pass
        elif octets == 7 and (mnem == 'cmp' or mnem == 'mov') and idc.get_operand_type(ea, 1) == o_imm:
            # chunk = '80 3D 64 C2 D1 01 00'
            #  ch = chunk.split(' ')
            #  l = len(ch)
            #  new = (ch[0:l-1-4] + ['??'] * 4 + [ch[l-1]])
            #  chunk = " ".join(new)
            #  # chunk = re.sub(r'(.*) ((?:[0-9A-F]{2} ){4})([0-9A-F]{2})$', r'\1 ?? ?? ?? ?? \3', chunk)
            chunk = chunk[0:5] + ' ??' * 4 + chunk[17:]
            # '80 3D ?? ?? ?? ?? 00'
        elif octets == 5:
            if chunk[0] == 'e' and chunk[1] in ['8', '9']:
                chunk = chunk[0:2] + ' ??' * 4
        elif octets == 6:
            # 38 05 F5 65 C9 01                          cmp     cs:_bIsOnline, al
            # 8B 15 AE BF 17 01                          mov     edx, cs:dword_141BA9DB8
            # 8B 1D 9C D0 AD 00                          mov     ebx, cs:seconds_60
            if (chunk[0] == '3' and chunk[1] in ['8', '9']) or (chunk[0:2] == '8b'):
                chunk = chunk[0:5] + ' ??' * 4
            # 0F 85 0B 01 00 00                          jnz     loc_1401BF0BF
            if chunk[0:4] == '0f 8':
                # leave jumps that are less that 0xff bytes forward
                if chunk[9:] != '00 00 00':
                    chunk = chunk[0:5] + ' ??' * 4
            elif mnem == 'mov':
                chunk = chunk[0:5] + ' ??' * 4
            elif idc.get_operand_type(ea, 0) == o_mem and idc.get_operand_type(ea, 1) != o_imm:
                chunk = chunk[0:5] + ' ??' * 4
        # F6 81 C0 DF 03 00 04  test    byte ptr [rcx+3DFC0h], 4
        elif octets == 7 and chunk[0:2] == 'f6':
            pass
        elif octets == 8:
            # 48 83 25 28 6E 5F 01 00                    and     cs:null_1427EB5E0, 0
            if chunk[0:5] == '48 83':
                # chunk[9:21] = ' ??' * 4
                chunk = chunk[0:8] + ' ??' * 4 + chunk[20:23]
        elif octets == 10:
            chunk = chunk[0:5] + ' ??' * 8
        elif octets > 6:
            chunk = chunk[0:len(chunk) - (4 * 3)] + ' ??' * 4

        newchunks.append(chunk)

    globals()['lastSig'] = newchunks
    return newchunks


#  def sig_subs(ea=None, sig='', offset=0, filter=None):
    #  sent = set()
    #  if ea is None:
        #  ea = idc.get_screen_ea()
    #  ea = GetFuncStart(ea)
    #  results = []
    #  for (startea, endea) in Chunks(ea):
        #  for head in Heads(startea, endea):
            #  d = de(head)
            #  if d and isinstance(d, list):
                #  d = d[0]
                #  if d.mnemonic in ('JMP', 'CALL') and d.usedRegistersMask == 0:
                    #  sub = d.operands[0].value
                    #  if HasUserName(sub):
                        #  name = idc.get_name(sub)
                        #  if filter and not filter(sub, name):
                            #  continue
                        #  if name.startswith('?'):
                            #  continue
                        #  if sub not in sent:
                            #  sent.add(sub)
                            #  if sig:
                                #  print(sig_protectscan(sig, head - ea + 1 + offset, 4, sig_type_fn(sub), idc.get_name(sub), func=1))
                            #  results.append( \
                                    #  { 'ea': sub,
                                      #  'name': TagRemoveSubstring(idc.get_name(sub)),
                                      #  'path': [('offset', head - ea + 1 + offset), ('is_mnem', IdaGetMnem(head)), ('rip', 4), ('name', TagRemoveSubstring(idc.get_name(sub))), ('type', MyGetType(sub))],
                                      #  'sub' : True,
                                      #  'type': MyGetType(sub) })
    #  return results


def sig_globals(ea=None, sig='', sig_offset=0, fullFuncTypes=False):
    sent = set()
    if ea is None:
        ea = idc.get_screen_ea()
    results = []
    ea = GetFuncStart(ea)
    # ProtectScan("48 83 fb 1f").add(-204)
    m = re.match(r"""Protect\w+\("([^"]+)"\)\.add\((-?\d+)\)""", sig)
    if m:
        sig_offset = int(m.group(2))
        sig = m.group(1)
    for (startea, endea) in Chunks(ea):
        for instruction_start in Heads(startea, endea):
            instruction_offset = instruction_start - ea
            d = idii(instruction_start)
            cs_arg = string_between('cs:', '', d) or string_between('g_', '', d, inclusive=1)

            s = ida_lines.generate_disasm_line(instruction_start, 1)
            #  print(s)
            #  ' \x01 \x05lea\x02\x05 \x01 ) \x01 !rcx\x02!\x02) \x01 \t,\x02\t \x01 *    \x01 \x06 \x01 (0000000141EE6738qword_141EE6738\x02\x06\x02*'
            #  ' \x01 \x05mov\x02\x05 \x01 ) \x01 !cs\x02!       \x01 \t:\x02\t           \x01 \x06 \x01 (0000000141EE6758dword_141EE6758\x02\x06\x02) \x01 \t,\x02\t \x01 * \x01 !ecx\x02!\x02*'
            # \x01\x06 - generated name
            # \x01\x07 - user defined name
            # \x01* _ (prefaced) - offset
            # \x01*\x01%\x01(0000000141501AECSYSTEM__WAIT\x02%\x02*'
            m = re.search(r'((?:\x01.)*)\x01(?:\x07|%)\x01\(([0-9A-F]{16})(\w+)\x02(?:\x07|%)', s)
            if m:
                #  pp(m.groups())
                m_prefix, m_loc, m_name = m.groups()
                found = 0
                global_name = m_name
                global_address = idc.get_name_ea_simple(global_name)
                if global_address not in sent:
                    if global_address == BADADDR:
                        global_name = get_name_by_any(eax(m_loc.lstrip('0')))
                        global_address = idc.get_name_ea_simple(global_name)
                    if global_address == BADADDR:
                        print("'{}' == BADADDR".format(global_name, global_address))

                    instruction_length = IdaGetInsnLen(instruction_start)
                    for offset in range(instruction_length - 4, 0, -1):
                        a = MakeSigned(idc.get_wide_dword(instruction_start + offset),
                                       32) + instruction_start + instruction_length
                        if a == global_address:
                            global_offset = global_address - ea
                            #  print(" %% Found reference at offset(%i).rip(%i) of instruction offset(%i) of %s" % (offset, instruction_length - offset, instruction_offset, idc.get_func_name(ea)))
                            _offset = sig_offset + instruction_offset + offset
                            _rip = instruction_length - offset
                            _type = str(MyGetType(global_address))
                            if isinstance(_type, str):
                                if fullFuncTypes:
                                    _type = _type.replace("__fastcall", "(*)").replace("__stdcall", "(*)").replace("None", "void*").replace("(*)", "(*) func")
                                else:
                                    _type = _type.replace("__fastcall", "(*)").replace("__stdcall", "(*)").replace("None", "void*")
                                # dprint("[sig_globals] _type")
                                if debug: print("[sig_globals] _type:{} fullFuncTypes:{}".format(_type, fullFuncTypes))
                                

                            sent.add(global_address)
                            if debug: print(
                                sig_protectscan(sig, _offset, _rip,
                                                _type, idc.get_name(global_address), func=IsFuncHead(global_address), fullFuncTypes=fullFuncTypes))
                            found += 1
                            results.append( \
                                    { 'ea': global_address,
                                      'name': global_name,
                                      'path': [('offset', _offset),
                                               ('is_mnem', IdaGetMnem(instruction_start)),
                                               ('rip', _rip),
                                               ('name', global_name),
                                               ('type', MyGetType(global_address))],
                                      'sub' : IsFuncHead(global_address),
                                      'type': _type })
                            #  pattern = sig_maker_ex(GetFuncStart(global_address), GetFuncEnd(global_address), offset = global_offset + offset, rip = instruction_length - offset, quick = 1) #, type = MyGetType(global_address))

                    if not found:
                        print(" %% Couldn't find solution for {} self {}".format(global_name, hex(global_address)))
    return results


def make_sig(chunks, start, ripRelAsQuad=False, replValues=None):
    def addReplValue(_replValue):
        if isinstance(replValues, list):
            replValues.append(_replValue)
    _pe = idautils.peutils_t()
    _base = _pe.imagebase
    newchunks = []
    procSet = set([o_far, o_near, o_mem, o_phrase])
    for chunk in chunks:
        chunk = chunk.lower()
        octets = div3(len(chunk))
        mnem = IdaGetMnem(start)
        op0 = idc.get_operand_type(start, 0)
        op1 = idc.get_operand_type(start, 1)
        opSet = set([op0, op1])
        #  ['o_mem', 2, 'Direct Memory Reference  (DATA)', 'addr'],
        #  ['o_phrase', 3, 'Memory Ref [Base Reg + Index Reg]', 'phrase'],
        #  ['o_far', 6, 'Immediate Far Address  (CODE)', 'addr'],
        #  ['o_near', 7, 'Immediate Near Address (CODE)', 'addr'],
        # dprint("[debug] start, chunks, opSet.isdisjoint(procSet)")
        if debug: print("[debug] start:{:x}, chunks:{}, opSet.isdisjoint(procSet):{}".format(start, chunks, opSet.isdisjoint(procSet)))
        
        changed = 0
        if not opSet.isdisjoint(procSet):
            opNum = -1
            for i in range(2):
                if idc.get_operand_type(start, i) in procSet:
                    opNum = i
            
            if opNum > -1:
                _opValue = GetOperandValue(start, opNum)
                _insnEnd = start + GetInsnLen(start)
                _tmp1 = str("{:08x}".format((_opValue - _insnEnd) & 0xffffffff))
                _tmp2 = [''.join(y) for y in [x for x in chunk_tuple(_tmp1, 2)]]
                _tmp2.reverse()
                _ripRelHex = ' '.join(_tmp2)
                _insnHex = ' '.join(["{:02x}".format(idc.get_wide_byte(start + a)) for a in range(GetInsnLen(start))])
                _offsetChars = _insnHex.find(_ripRelHex)
                if debug: print("[debug] _ripRelHex:{}, _insnHex:{}, _offsetChars:{}".format(_ripRelHex, _insnHex, _offsetChars))
                
                if ~_offsetChars:
                    _offsetBytes = div3(_offsetChars)
                    _replValue = "{:08x}".format(_opValue - _base)
                    if ripRelAsQuad:
                        _insn = idautils.DecodeInstruction(start)
                        if _insn.itype in (idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni, idaapi.NN_jmpshort) or \
                           _insn.itype in (idaapi.NN_ja, idaapi.NN_jae,   idaapi.NN_jb,   idaapi.NN_jbe,  idaapi.NN_jc,  idaapi.NN_jcxz,
                                idaapi.NN_jecxz,     idaapi.NN_jrcxz, idaapi.NN_je,   idaapi.NN_jg,   idaapi.NN_jge, idaapi.NN_jl,   idaapi.NN_jle,
                                idaapi.NN_jna,       idaapi.NN_jnae,  idaapi.NN_jnb,  idaapi.NN_jnbe, idaapi.NN_jnc, idaapi.NN_jne,  idaapi.NN_jng,
                                idaapi.NN_jnge,      idaapi.NN_jnl,   idaapi.NN_jnle, idaapi.NN_jno,  idaapi.NN_jnp, idaapi.NN_jns,  idaapi.NN_jnz,
                                idaapi.NN_jo,        idaapi.NN_jp,    idaapi.NN_jpe,  idaapi.NN_jpo,  idaapi.NN_js,  idaapi.NN_jz) or \
                           _insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                               if IsFuncHead(_opValue) and HasUserName(_opValue) and not ~idc.get_func_name(_opValue).find('___') and not ~idc.get_func_name(_opValue).find('::_0x'):
                                   _replValue = "[{}]".format(TagRemoveSubstring(idc.get_func_name(_opValue)))
                               elif (IsSameChunk(start, _opValue)):
                                   _replValue = "+{:x}".format(_opValue - start).replace("+-", "-")
                               elif (IsSameFunc(start, _opValue)):
                                   _replValue = "~{:08x}".format(_opValue - _base)
                        elif _insn.itype in (idaapi.NN_lea, idaapi.NN_mov):
                            if idc.get_name(_opValue).startswith('??_7'):
                                _replValue = idc.get_name(_opValue, GN_DEMANGLED).replace('const ', '').replace('`', '').replace("'", '')
                                addReplValue(_replValue)
                            elif idc.get_name(_opValue).startswith('a'):
                                # st = idc.get_strlit_contents(_opValue, 256, idc.STRTYPE_C)
                                st = mb(_opValue).str()
                                if st and re.match(asBytes(r"""[-_a-zA-Z0-9./,'"]+$"""), st):
                                    _replValue = "'{}'".format(asString(st).replace("'", "\\'").replace('"', '\\"'))
                                    addReplValue(_replValue)
                        chunk = "{}{}{}".format(_insnHex[0:_offsetChars], _replValue, _insnHex[_offsetChars+11:])
                        changed = 1
                    else:
                        chunk = "{}?? ?? ?? ??{}".format(_insnHex[0:_offsetChars], _insnHex[_offsetChars+11:])
                        changed = 1

        # mov     rax, [rcx+0E8h]  ; o_reg, o_displ
        if changed or (set([o_reg, o_displ]) <= opSet):
            pass
        elif mnem == 'test':
            pass
        elif octets == 7 and chunk[0:5] == '48 f7':
            pass
        elif octets == 7 and chunk[0:5] == 'c7 43':
            pass
        elif octets == 6 and chunk[0:2] == '41':
            pass
        # 48 81 EC 80 00 00 00                 sub     rsp, 80h
        elif octets == 7 and chunk[0:5] == '48 81':
            pass
        elif octets == 7 and chunk[0:5] == '80 A1':
            pass
        elif octets == 7 and chunk[0:5] == '81 A1':
            pass
        elif octets == 7 and chunk[0:5] == '83 A1':
            pass
        elif (mnem == 'cmp' or mnem == 'mov') and idc.get_operand_type(start, 0) == o_reg and idc.get_operand_type(
                start, 1) == o_imm:
            if debug: print("Testing letting cmp/mov o_reg, o_imm go without wildcards: {}".format(idc.GetDisasm(start)))
            pass
        elif octets == 7 and (mnem == 'cmp' or mnem == 'mov') and idc.get_operand_type(start, 1) == o_imm:
            # chunk = '80 3D 64 C2 D1 01 00'
            #  ch = chunk.split(' ')
            #  l = len(ch)
            #  new = (ch[0:l-1-4] + ['??'] * 4 + [ch[l-1]])
            #  chunk = " ".join(new)
            #  # chunk = re.sub(r'(.*) ((?:[0-9A-F]{2} ){4})([0-9A-F]{2})$', r'\1 ?? ?? ?? ?? \3', chunk)
            chunk = chunk[0:5] + ' ??' * 4 + chunk[17:]
            # '80 3D ?? ?? ?? ?? 00'
        elif octets == 5:
            if chunk[0] == 'e' and chunk[1] in ['8', '9']:
                chunk = chunk[0:2] + ' ??' * 4
        elif octets == 6:
            # 38 05 F5 65 C9 01                          cmp     cs:_bIsOnline, al
            # 8B 15 AE BF 17 01                          mov     edx, cs:dword_141BA9DB8
            # 8B 1D 9C D0 AD 00                          mov     ebx, cs:seconds_60
            if (chunk[0] == '3' and chunk[1] in ['8', '9']) or (chunk[0:2] == '8b'):
                chunk = chunk[0:5] + ' ??' * 4
            # 0F 85 0B 01 00 00                          jnz     loc_1401BF0BF
            if chunk[0:4] == '0f 8':
                # leave jumps that are less that 0xff bytes forward
                if chunk[9:] != '00 00 00':
                    chunk = chunk[0:5] + ' ??' * 4
            elif mnem == 'mov':
                chunk = chunk[0:5] + ' ??' * 4
            elif idc.get_operand_type(start, 0) == o_mem and idc.get_operand_type(start, 1) != o_imm:
                chunk = chunk[0:5] + ' ??' * 4
        # F6 81 C0 DF 03 00 04  test    byte ptr [rcx+3DFC0h], 4
        elif octets == 7 and chunk[0:2] == 'f6':
            pass
        elif octets == 8:
            # 48 83 25 28 6E 5F 01 00                    and     cs:null_1427EB5E0, 0
            if chunk[0:5] == '48 83':
                # chunk[9:21] = ' ??' * 4
                chunk = chunk[0:8] + ' ??' * 4 + chunk[20:23]
        elif octets == 10:
            chunk = chunk[0:5] + ' ??' * 8
        elif octets > 6:
            chunk = chunk[0:len(chunk) - (4 * 3)] + ' ??' * 4
        newchunks.append(chunk)
        start += octets
    globals()['lastSig'] = newchunks
    return newchunks


def sig_maker_chunked(ea=None):
    print("\n".join(make_sig(get_bytes_chunked(), ea or idc.SelStart())))


def sig_protectscan(pattern, add=0, rip=-1, type_="void*", name=None, rtg=True, func=False, fullFuncTypes=False):
    if add:
        while pattern[0:3] == "?? " and len(pattern):
            pattern = pattern[3:]
            add -= 1
        if 0:
            # seems slow
            while hotkey_find_pattern(pattern[3:]) == 1 and len(pattern):
                pattern = pattern[3:]
                add -= 1

    name_append = ''
    if 0:
        if name:
            name_append = '.name("{}")'.format(name)

    if add > 99 or add < 99:
        add_string = hex(add).replace('0x-', '-0x')
    else:
        add_string = add
    result = "ProtectScan(\"%s\").add(%i)" % (pattern, add)
    if rip > -1 or type_ != "void*":
        result = "ProtectScan(\"%s\").add(%s).rip(%i).type(%s)%s" % (pattern, add_string, rip, type_, name_append)
        if rtg:
            if func:
                result = "static auto  %s = ProtectScan(\"%s\").add(%s).rip(%i).as<%s>();" % (
                    name, pattern, add_string, rip, type_)
            else:
                result = "static auto& %s = ProtectScan(\"%s\").add(%s).rip(%i).as<%s&>();" % (
                    name, pattern, add_string, rip, type_)

    result = result.replace('.add(0)', '')
    result = result.replace('.rip(-1)', '')
    result = result.replace('.as<None>("None")', '')
    # dprint("[sig_protectscan] result")
    print("[sig_protectscan] result:{}".format(result))
    
    return result


def sig_maker_data(ea=None, wrt=None):
    patterns = []
    start = time.time()

    try:
        if type(ea) is str:
            ea = idc.get_name_ea_simple(ea)
        elif ea is None:
            ea = EA()
        f = idc.get_full_flags(ea)
        if idc.is_data(f) or idc.is_code(f):
            if idc.is_data(f):
                print(" %% isData")
            else:
                print(" %% isCode")

            if not ida_bytes.hasRef(f):
                print(" %% no references to data type")
                return None
            print(" %% ida_bytes.hasRef")
            found = 0
            lastFunc = BADADDR
            for ref in [x for x in idautils.XrefsTo(ea, flags=0) if
                        get_segm_name(x.frm) == '.text' and IsFunc_(x.frm) and not IsChunked(x.frm)]:
                if (time.time() - start) > 60:
                    break
                if wrt and found == 0:
                    ref.frm = wrt
                    found = 1
                if found > 5:
                    break
                print(" %% examining xref 0x%x - %s" % (ref.frm, GetFunctionName(ref.frm)))
                # {'to': 5415931184L, 'type': 1L, 'user': 0L, 'frm': 5391113029L, 'iscode': 0L}
                if ref.iscode == 0 or ref.iscode == 1:
                    frm = ref.frm
                    f = idc.get_full_flags(frm)
                    if IsFunc_(frm) and GetNumChunks(frm) == 1:  # and HasUserName(GetFuncStart(frm)):
                        if frm != lastFunc:
                            lastFunc = frm
                        else:
                            print(" %% same as lastFunc")
                            continue

                        print(" %% isfunc and is not chunked: 0x{:x}".format(frm), GetFunctionName(frm))
                        inslen = IdaGetInsnLen(frm)
                        for offset in range(inslen - 4, 0, -1):
                            if MakeSigned(idc.get_wide_dword(frm + offset), 32) + frm + inslen == ea:
                                insOffset = frm - GetFuncStart(frm)
                                print(" %% Found reference at offset %i (%i) of instruction offset %i of %s" % (
                                    offset, inslen - offset, insOffset, idc.get_func_name(frm)))
                                pattern = sig_maker_ex(GetFuncStart(frm), GetFuncEnd(frm), offset=insOffset + offset,
                                                       rip=inslen - offset, quick=1)  # , type = MyGetType(ea))
                                if isinstance(pattern, str) and len(pattern) > 0 and len(pattern) < 128:
                                    patterns.append(pattern)
                                    print("%x: %s" % (ea, pattern))
                                    found += 1
                                    break
                                else:
                                    print(" %% couldn't get unique pattern for function")
                                    deCode
                            else:
                                print("MakeSigned: 0x{:x}, ea: 0x{:x}".format(
                                    MakeSigned(idc.get_wide_dword(frm + offset), 32) + frm + inslen, ea))
                    else:
                        if not IsFunc_(frm):
                            print(" %% incompatible function (not function)")
                        #  elif not HasUserName(GetFuncStart(frm)):
                        #  print(" %% incompatible function (not named)")
                        elif GetNumChunks(frm) != 1:
                            print(" %% incompatible function (%i chunks)" % GetNumChunks(frm))
                        else:
                            print(" %% incompatible function (unknown reason)")
                else:
                    print(ref.__dict__)
    except KeyboardInterrupt:
        print("W: interrupt received, stopping")
        raise Exception('Keyboard');
        return patterns


def chunk_list(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def chunk_tuple(it, size):
    """Yield successive n-sized tuples from lst."""
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

def stutter_chunk(lst, size, overlap=0):
    for i in range(0, len(lst), size - overlap):
        r = lst[i:i + size]
        while len(r) < size:
            r.append(None)
        yield r


def chunk_addresses(it, min_chunk_len, start, skip=0):
    count = 0
    total_chunk_len = 0
    pos = 0
    chunk = []
    for address_chunk in it:
        this_chunk_len = div3(len(address_chunk))
        total_chunk_len += this_chunk_len
        if skip:
            if total_chunk_len < skip:
                continue
            skip = 0
            pos += total_chunk_len
            total_chunk_len = 0
            continue

        chunk.append(address_chunk)
        if total_chunk_len > min_chunk_len:
            count = 0
            yield (start + pos, chunk)
            pos += total_chunk_len
            total_chunk_len = 0
            chunk = []

    if total_chunk_len:
        yield (start + pos, chunk)


def stripArgNames(arg):
    # ('Not accepted: {}', 'void __fastcall CTrackedEventInfo__unsigned__int64__::m_8(CTrackedEventInfo<unsigned __int64>* self)')

    if isinstance(arg, list):
        return [stripArgNames(x) for x in arg if x]
    elif isinstance(arg, str):
        print("stripArgNames: {}".format(arg))
        lhs = string_between('', ' ', arg, inclusive=1, greedy=1)
        rhs = arg[len(lhs):]
        lhs = lhs.strip()
        while not str.isalnum(rhs[0]):
            lhs += rhs[0]
            rhs = rhs[1:]
        # return lhs + " " + rhs
        return lhs
    else:
        raise Exception("Unknown type: {}".format(type(arg)))


def make_declfn(decl, fnNameAlt=''):
    if decl:
        regex = r"(.*?) ?(__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge)? ?([^* ]*?)\((.*)\)"
        for (returnType, callType, fnName, fnArgs) in re.findall(regex, decl):
            # print('//{:12}|{:10}|{}|{}|{}'.format(returnType, callType, fnName, fnArgs, decl))
            if fnNameAlt: fnName = fnNameAlt
            args = fnArgs.split(", ")
            return make_vfunc_struct_sig(returnType, callType, fnName, stripArgNames(sanitizedName(args))).replace(
                '__fastcall ', '').strip(' ;')


def sig_type_fn(ea=None):
    if ea is None:
        ea = idc.get_screen_ea()
    fnLoc = ea
    # member_type = MyGetType(fnLoc)
    # we don't want the name
    member_type = idc.get_type(fnLoc)
    return make_declfn(member_type)


def sig_maker_chunk(funcea=None):
    """
    sig_maker_chunk

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return []
    else:
        funcea = func.start_ea
    rl = []
    for r in [24, 36, 48]:
        res = sig_maker_ex(funcea, chunk=r, quick=0, comment=1)
        if res:
            rl.extend(res)

    if rl:
        rl = _.sortBy(_.flatten(rl), lambda x: len(x) + 5 * x.count("??"))

        print(str(rl).replace("'", ''))

        sig_globals(funcea, rl[0])

    return rl

def sig_maker_ex(start=None, end=None, addresses=None, offset=0, rip=-1, type_=None, name=None, maxlen=256, show=False,
                 fullSig=False, noSig=False, quick=False, comment=False, chunk=False, extra=False, ripRelAsQuad=False, replValues=None):
    #  print(start, end, addresses, offset, rip, type_, name, maxlen, show, fullSig, noSig, quick)
    if start is None:
        start, end = get_selection_or_ea()
    final = ""
    insns = list()
    if start is None:
        start = GetFuncStart(EA())
    if not isInt(start):
        raise ValueError("Start is {}".format(start))
    if end is None:
        end = GetFuncEnd(start)
    elif end < start:
        if end < -1:
            end = GetFuncEnd(start) + end
        else:
            end = start + end

    if isinstance(addresses, list):
        full = get_bytes_chunked_from_comb(addresses)
        if not noSig:
            full = make_sig_from_comb(full, addresses, ripRelAsQuad=ripRelAsQuad, replValues=replValues)
        insns = get_instructions_chunked(addresses=addresses)
    elif noSig:
        full = get_bytes_chunked(start, end, maxlen)
    else:
        full = make_sig(get_bytes_chunked(start, end, maxlen), start, ripRelAsQuad=ripRelAsQuad, replValues=replValues)

    if show and fullSig:
        return " ".join(full)
        # might not be unique
        # final = sig_protectscan(full)
    _globals = []
    if len(insns) == 0:
        insns = get_instructions_chunked(start, end, _globals=_globals)
    if show:
        # dprint("[debug] len(full), len(insn)")
        if debug: print("[debug] len(full):{}, len(insns):{}".format(len(full), len(insns)))
        
        for i in range(len(full)):
            print("%-24s %s" % (full[i], insns[i]))
    if fullSig:
        #  if replValues:
            #  return full, replValues
        return full

    if show:
        return

    full = " ".join(full)
    final = sig_protectscan(full, offset, rip, type_, name=name)
    #  if type(full) is str:
    #  if type_:
    #  final = "Full: %s.add(%i).rip(4).as<%s>()" % (sig_protectscan(full).replace(".add(0)", ""), offset, type_)
    #  print(final)
    #  else:
    #  final = "Full: %s" % sig_protectscan(full)
    #  print(final)
    #  else:
    #  return final

    if chunk:
        addresses = get_bytes_chunked(start, end, maxlen)
        count = 0
        reduced_list = []

        for chunk_ea, chunk_pattern in chunk_addresses(addresses, chunk, start, skip=5):
            offset = chunk_ea - start
            full = make_sig(chunk_pattern, chunk_ea, ripRelAsQuad=ripRelAsQuad, replValues=replValues)
            extra_offset = 0
            reduced = sig_reducer(" ".join(full), quick=quick)
            print("reduced: {}".format(reduced))
            if isinstance(reduced, tuple):
                reduced, extra_offset = reduced
            if isinstance(reduced, list):
                raise Exception("Hmmm, double check this")
                reduced_list.append(sig_protectscan(" ".join(reduced), chunk_ea - start + offset + extra_offset))
            elif isinstance(reduced, str):
                #  raise Exception("Hmmm, double check this")
                reduced_list.append(sig_protectscan(reduced, -(offset + extra_offset)))

        for reduced in reduced_list:
            comment_sig(start, reduced, 'ALT')
        return reduced_list

    extra_offset = 0
    reduced = sig_reducer(full, quick=quick)
    if isinstance(reduced, tuple):
        reduced, extra_offset = reduced
    if isinstance(reduced, str):
        final = sig_protectscan(reduced, 0 + offset + extra_offset, rip, type_, name=name)
        #  comment_sig(start, final)
        #  return result

    advanced = full[30:30 + 3 * 24]
    advanced = sig_reducer(advanced)
    if isinstance(advanced, tuple):
        advanced, extra_offset = advanced
    if type(advanced) is str:
        final2 = sig_protectscan(advanced, -10 + offset + extra_offset, rip, type_, name=name)
        if type(final) != str or len(final2) < len(final):
            remove(start, final)
            comment_sig(start, final, 'PRIMARY')
            comment_sig(start, final2, 'SHORTEST')
            final = final2
        else:
            comment_sig(start, final)

    print("final: %s" % final)
    comment_sig(start, final, 'SHORTEST')
    return final
    #  # search for first `sub rsp, ` and start match from there
    #  needle = "48 83 ec "
    #  index = full.find(needle)
    #  if index > -1:
    #  postsub = full[index:index+3*24]
    #  reduced = sig_reducer(postsub)
    #  if type(reduced) is str:
    #  print("PostSubReduced: %s" % sig_protectscan(reduced, index / 3 + offset))


def sig_maker():
    if not idc.SelStart() - idc.SelEnd():
        return sig_maker_ex(EA(), idc.next_head(EA()))
    return sig_maker_ex(idc.SelStart(), idc.SelEnd())


def get_segment_range():
    ranges = list()
    for segment in idautils.Segments():
        # idc.jumpto(idc.get_segm_attr(segment, SEGATTR_START))
        segName = idc.get_segm_name(segment)
        #  print("Segment: %s" % segName)
        if segName == '.text':
            # Do find based patching first (very quick)
            # findAndPatch(idc.get_segm_attr(segment, SEGATTR_START), idc.get_segm_attr(segment, SEGATTR_END))
            # Then slog it out instruction by instruction for very little gain
            ranges.append([idc.get_segm_attr(segment, SEGATTR_START), idc.get_segm_attr(segment, SEGATTR_END)])
            break
    return ranges


def find_pattern_in_segment(pattern):
    count = 0
    ranges = get_segment_range()
    for r in ranges:
        this_count = hotkey_find_pattern(pattern, 2, r[0], r[1])
        if this_count == -2:
            return this_count
        count += this_count
        if count > 1:
            break
    #  print("%s: found %i times" % (pattern, count))
    return count


def hotkey_find_pattern(pattern, limit=2, start=0, end=BADADDR):
    global searches
    high = 0
    count = 0
    patternsFound = set()
    hints = set();
    for p in searches:
        addrList = searches[p]
        if pattern.find(p) == 0:
            hint = hints.union(addrList)
            #  if pattern == p:
            #  print("exact match on cache %s" % p)

    pat = list()
    mask = list()
    for o in range(0, div3(len(pattern)), 3):
        octet = pattern[o:o + 2]
        if octet == "??":
            mask.append(0)
            pat.append(0);
        else:
            mask.append(0xff)
            pat.append(ord(unhexlify(octet)))

    #  print("pattern: %s" % pat)
    #  print("mask   : %s" % mask)

    for ea in hints:
        if ea > high:
            high = ea
        mem = list()
        for o in range(len(pat)):
            mem.append(idc.get_wide_byte(ea + o))

        #  print("mem    : %s" % mem)

        for o in range(len(pat)):
            r = (mem[o] ^ pat[o]) & mask[o]
            if r:
                continue
        count += 1

    if count > 1:
        print("cache reports %i hits" % count)
        return count

    #  count = 0
    if start == 0:
        start = idaapi.cvar.inf.min_ea
        if high > start:
            start = high + 1
    pos = start
    while pos < end:
        # pos = FindBinary(pos + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 F8 48 89 2C 24 48 8D 2D ? ? ? ? 48 87 2C 24 48 8D 64 24 08 FF 64 24 F8")
        try:
            pos = idc.find_binary(pos + 1, SEARCH_DOWN | SEARCH_CASE, pattern)
            if pos == BADADDR:
                break
            patternsFound.add(pos)
            count += 1
            if count == limit:
                break
        except KeyboardInterrupt:
            print("W: interrupt received, stopping")
            raise KeyboardInterrupt

    #  print("%s: found %i times" % (pattern, count))
    searches[pattern] = patternsFound;
    return len(patternsFound)


def binary_search_pattern_len(pattern, quick=False):
    if debug: print(" %% checking entire pattern is unique %s (%i bytes)" % (pattern[0:72], len(pattern) / 3))
    count = len(FindInSegments(pattern, None, 2))
    if debug:
        if count > 1:
            print(" %% pattern was found %i times" % count)
        if count < 1:
            print(" %% pattern was not found")

    if count != 1:
        return count

    best = pattern
    best_size = len(pattern) / 3

    limit = 64 * 3
    if best_size > 99:
        if debug: print(" %% checking small pattern is unique %s (%i bytes)" % (pattern[0:24], limit // 3))
        count = len(FindInSegments(pattern[0:limit], None, 2))

        if count == 1:
            if debug: print(" %% it was")
            best = pattern = pattern[0:limit]

        else:
            if debug: print(" %% afraid not")

    if quick:
        return best;

    t = 1
    min = 0
    max = (len(pattern) + 1) // 3
    seq = range(0, max + 1)
    best_match = len(seq) - 2

    #  print("pattern ok: %s" % pattern)
    #  print("sequence: %s" % seq)

    while True:
        if max < min:
            return reduce_start(pattern[0:3 * seq[best_match] - 1])
        m = (min + max) // 2
        #  print("(%i, %i, %i)" % (min, m, max))
        r = len(FindInSegments(pattern[0:3 * seq[m] - 1], None, 2))
        #  print("(%i, %i, %i): %i" % (min, m, max, r))
        if r > t:
            min = m + 1
        else:
            if r == t:
                best_match = seq[m]
            max = m - 1

    return reduce_start(best)


def reduce_start(pattern):
    """ this is very stupid unless. we return offset start, eliffucks shit up """
    return pattern

    print("reduce_start", pattern)
    match = pattern
    last_match = match
    while len(FindInSegments(match, None, 2)) == 1:
        #  print("match: {}".format(match))
        last_match = match
        match = match[3:]

    #  print("best_match: {}".format(last_match))
    if len(pattern) == len(last_match):
        return pattern
    return (last_match, (len(last_match) - len(pattern)) // 3)


def sig_reducer(sig, quick=False):
    return binary_search_pattern_len(sig, quick=quick)


import bisect


class TinySig:
    def __init__(self, pattern):
        self.pattern = pattern

    def __getitem__(self, index):
        self.pattern.setshutter(index)
        im = cam.getframe()  # returns a numarray array
        return im.mean()


def auto_expose(pattern, target_mean=128):
    ms = bisect.bisect(TinySig(pattern), target_mean, 0, 1000)
    pattern.setshutter(ms)


def chunk_adder():
    chunkStart = idc.SelStart()
    chunkEnd = idc.SelEnd()
    print("idc.append_func_tail(0x%x, 0x%x, 0x%x)" % (ms() or fnLoc, chunkStart, chunkEnd))
    # result = idc.append_func_tail(ms() or fnLoc, chunkStart, chunkEnd)
    result = ShowAppendFchunk(ms() or fnLoc, chunkStart, chunkEnd, "hotkey")
    print(result)


def make_nops():
    chunkStart, chunkEnd = get_selection_or_ea()
    if chunkEnd > chunkStart and chunkEnd < BADADDR and chunkEnd - chunkStart < 1024:
        PatchNops(chunkStart, chunkEnd - chunkStart)
        ida_auto.plan_range(chunkStart, chunkEnd)

def get_selection_or_ea(asLength=False, expandEa=True, ea_iteratee=None, selection_iteratee=None):
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)
    if selection:
        if callable(selection_iteratee):
            return selection_iteratee(startaddr, endaddr)
        return startaddr, endaddr - startaddr if asLength else endaddr
    else:
        if callable(ea_iteratee):
            return ea_iteratee(EA())
        return idc.get_screen_ea(), idc.next_not_tail(idc.get_screen_ea()) if expandEa else idc.get_screen_ea()

def create_insns(ea1, ea2):
    ea = idc.get_item_head(ea1)
    n = True
    while ea < ea2 and n:
        n = idc.create_insn(ea)
        if not n:
            n = GetInsnLen(ea)
            if n:
                MyMakeUnknown(ea, n, DELIT_NOTRUNC)
                n = idc.create_insn(ea)
        ea += n

def hotkey_patch():
    obfu.combed.clear()
    chunkStart, chunkEnd = get_selection_or_ea()
    if chunkStart + IdaGetInsnLen(chunkStart) >= chunkEnd:
        print("single patch at {:x}".format(chunkStart))
        obfu._patch(chunkStart)
    elif chunkEnd > chunkStart and chunkEnd < BADADDR and chunkEnd - chunkStart < 8192:
        print("range patch")
        reflow = True
        while reflow:
            reflow = False
            print("reflow:")
            for ea in idautils.Heads(chunkStart, chunkEnd):
                print("for ea: {:x}".format(ea))
                r = True
                while r and not reflow:
                    r = False
                    r = obfu._patch(ea)
                    if r and isinstance(r, list):
                        print("result")
                        for p in r:
                            if deep_get(p, 'pat.options.reflow', '') == 'reflow':
                                print("reflowing")
                                reflow = True



def hotkey_edit_nasm():
    chunkStart, chunkEnd = get_selection_or_ea()
    _asm = ""
    if chunkStart + IdaGetInsnLen(chunkStart) >= chunkEnd:
        _asm = icida(chunkStart, labels=True)
    elif chunkEnd > chunkStart and chunkEnd < BADADDR and chunkEnd - chunkStart < 8192:
        _asm = icida(chunkStart, chunkEnd, labels=True)

    _new_asm = "start:\n" + _asm
    while True:
        _new_asm = idaapi.ask_text(0x10000, _new_asm, "Edit Disassembly")
        if _new_asm:
            if not nassemble(chunkStart, _new_asm, apply=True):
                continue
            ida_auto.plan_and_wait(chunkStart, chunkEnd)
        break

def hotkey_unpatch():
    chunkStart, chunkEnd = get_selection_or_ea()
    if GetFuncStart(chunkStart) == chunkStart and chunkEnd == idc.next_head(chunkStart):
        unpatch_func2(chunkStart)
    if chunkEnd > chunkStart and chunkEnd < BADADDR and chunkEnd - chunkStart < 8192:
        unpatch(chunkStart, chunkEnd)
        # ida_auto.plan_range(chunkStart, chunkEnd)
        try:
            EaseCode(chunkStart, chunkEnd, forceStart=1)
        except:
            pass
        return
        ea = idc.get_item_head(chunkStart)
        n = True
        while ea < chunkEnd and n:
            n = idc.create_insn(ea)
            if not n:
                n = GetInsnLen(ea)
                if n:
                    MyMakeUnknown(ea, n, DELIT_NOTRUNC)
                    n = idc.create_insn(ea)
            ea += n

def hotkey_skipjumps():
    chunkStart, chunkEnd = get_selection_or_ea()
    for ea in idautils.Heads(chunkStart, chunkEnd):
        SkipJumps(ea, skipNops=1, apply=1)

def hotkey_unchunk():
    def hotkey_unchunk_expand_ea(ea, *args):
        if IsChunk(ea):
            return GetChunkStart(ea), GetChunkEnd(ea)
        if IsFunc_(ea):
            return idc.get_item_head(ea), idc.get_item_end(ea)

    chunkStart, chunkEnd = get_selection_or_ea(ea_iteratee=hotkey_unchunk_expand_ea)

    if chunkStart == GetFuncStart(chunkStart):
        print("This shit crashes when used on function heads")
        idc.del_func(chunkStart)
        return 0

    if chunkEnd > chunkStart and chunkEnd < BADADDR and chunkEnd - chunkStart < 1024:
        return chunk_remove_range(chunkStart, chunkEnd)

def hotkey_join_to_parent():
    ea = idc.get_screen_ea()
    if IsFunc_(ea) and not IsFuncHead(ea):
        ea = GetFuncStart(ea)
    funcs = list()
    unowned = list()
    for ref in idautils.CodeRefsTo(ea, 1):
        if GetFuncStart(ref):
            if ref == idc.prev_head(ea):
                funcs.append(ref)
            else:
                funcs.insert(0, ref)
        else:
            unowned.append(ref)

    if len(funcs) == 1:
        for func in funcs:
            ShowAppendFunc(func, ea)
            return

    for ref in idautils.DataRefsTo(ea):
        if GetFuncStart(ref):
            if ref == idc.prev_head(ea):
                funcs.append(ref)
            else:
                funcs.insert(0, ref)
        else:
            unowned.append(ref)

    if len(funcs) == 1:
        for func in funcs:
            ShowAppendFunc(func, ea)
            return

def MakeJmpUnconditional(ea):
    # dprint("[MakeJmpUnconditional] ea")
    print("[MakeJmpUnconditional] ea:{:x}".format(ea))
    if isCall(ea):
        nassemble(ea, "jmp 0x{:x}".format(GetTarget(ea)), apply=1)
    elif not isAnyJmp(ea):
        raise IndexError("No jump at this location {:x}".format(ea))
    elif not isConditionalJmp(ea):
        raise IndexError("Jump already conditional at this location {:x}".format(ea))
    nassemble(ea, "jmp 0x{:x}".format(GetTarget(ea)), apply=1)

def RemoveConditionalJmp(ea):
    # dprint("[RemoveConditionalJmp] ea")
    print("[RemoveConditionalJmp] ea:{:x}".format(ea))
    
    if not isAnyJmp(ea):
        raise IndexError("No jump at this location {:x}".format(ea))
    if not isConditionalJmp(ea):
        raise IndexError("Jump already conditional at this location {:x}".format(ea))
    PatchNops(ea, GetInsnLen(ea))
    #  nassemble(ea, "nop".format(GetTarget(ea)), apply=1)
    
def hotkey_switch_jumptype(shift=0):
    # @static: last_ea
    if 'last_ea' not in hotkey_switch_jumptype.__dict__:  hotkey_switch_jumptype.last_ea  = None
    # @static: last_asm
    if 'last_asm' not in hotkey_switch_jumptype.__dict__: hotkey_switch_jumptype.last_asm = None

    ea = idc.get_screen_ea()
    # <kbd>J</kbd> Swap between jz and jnz (or whatever)
    if not shift:
        length = idc.get_item_size(ea)
        if length == 6 and idc.get_wide_byte(ea) == 0x0f:
            idc.patch_byte(ea + 1, idc.get_wide_byte(ea + 1) ^ 1)
    # Shift-J Swaping between jmp and jz (or whatever)
    else:
        if isCall(ea):
            nassemble(ea, "jmp 0x{:x}".format(GetTarget(ea)), apply=1)
        elif isAnyJmp(ea):
            if isConditionalJmp(ea):
                hotkey_switch_jumptype.last_ea = ea
                hotkey_switch_jumptype.last_asm = dii(ea, 6)
                nassemble(ea, "jmp 0x{:x}; nop".format(GetTarget(ea)), apply=1)
                idc.create_insn(ea + 5)
            else:
                if hotkey_switch_jumptype.last_ea == ea:
                    nassemble(ea, hotkey_switch_jumptype.last_asm, apply=1)

def hotkey_retrace():
    print("retrace: {}".format(retrace(adjustStack=1)))

def fake_cli_factory(text):
    def faker():
        fake_cli(text)
    return faker

def fake_cli(text):
    with ida_kernwin.disabled_script_timeout_t():

        # We'll now have to schedule a call to the standard
        # 'execute' action. We can't call it right away, because
        # the "Output window" doesn't have focus, and thus
        # the action will fail to execute since it requires
        # the "Output window" as context.

        def delayed_exec(*args):
            output_window_title = "Output window"
            tw = ida_kernwin.find_widget(output_window_title)
            if not tw:
                raise Exception("Couldn't find widget '%s'" % output_window_title)

            # convert from a SWiG 'TWidget*' facade,
            # into an object that PyQt will understand
            w = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw)

            line_edit = w.findChild(QtWidgets.QLineEdit)
            if not line_edit:
                raise Exception("Couldn't find input")
            line_edit.setFocus() # ensure it has focus
            QtWidgets.QApplication.instance().processEvents() # and that it received the focus event

            # inject text into widget
            line_edit.setText(text)

            # and execute the standard 'execute' action
            ida_kernwin.process_ui_action("cli:Execute")

        delayed_exec_timer.singleShot(0, delayed_exec)

def getSigsData():
    global addressList
    try:
        for ea in addressList:
            if not IsFunc_(ea):
                print("0x%x 0x%x %s" % (ea, idc.get_name_ea_simple(idc.get_func_name(ea)), idc.get_name(ea)))
                sig_maker_data(ea)
    except KeyboardInterrupt:
        raise KeyboardInterrupt


def getSigsCode():
    global addressList
    for ea in addressList:
        if IsFunc_(ea):
            print("0x%x 0x%x %s" % (ea, idc.get_name_ea_simple(idc.get_func_name(ea)), idc.get_func_name(ea)))
            sig_maker_ex(ea, ea + 64)


sn = [{'ea': 0x141501aec, 'name': 'SYSTEM::WAIT', 'path': [('offset', 0x10), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::WAIT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1415014cc, 'name': 'SYSTEM::START_NEW_SCRIPT', 'path': [('offset', 0x29), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::START_NEW_SCRIPT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1415015b0, 'name': 'SYSTEM::START_NEW_SCRIPT_WITH_ARGS', 'path': [('offset', 0x42), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::START_NEW_SCRIPT_WITH_ARGS'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1415015f0, 'name': 'SYSTEM::START_NEW_SCRIPT_WITH_NAME_HASH', 'path': [('offset', 0x5b), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::START_NEW_SCRIPT_WITH_NAME_HASH'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x141501634, 'name': 'SYSTEM::START_NEW_SCRIPT_WITH_NAME_HASH_AND_ARGS', 'path': [('offset', 0x74), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::START_NEW_SCRIPT_WITH_NAME_HASH_AND_ARGS'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe8f8, 'name': 'SYSTEM::TIMERA', 'path': [('offset', 0x8d), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::TIMERA'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe924, 'name': 'SYSTEM::TIMERB', 'path': [('offset', 0xa6), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::TIMERB'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe808, 'name': 'SYSTEM::SETTIMERA', 'path': [('offset', 0xbf), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SETTIMERA'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe838, 'name': 'SYSTEM::SETTIMERB', 'path': [('offset', 0xd8), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SETTIMERB'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe950, 'name': 'SYSTEM::TIMESTEP', 'path': [('offset', 0xf1), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::TIMESTEP'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe8b8, 'name': 'SYSTEM::SIN', 'path': [('offset', 0x105), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SIN'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe72c, 'name': 'SYSTEM::COS', 'path': [('offset', 0x11e), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::COS'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe8e4, 'name': 'SYSTEM::SQRT', 'path': [('offset', 0x137), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SQRT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe798, 'name': 'SYSTEM::POW', 'path': [('offset', 0x150), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::POW'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fea24, 'name': 'SYSTEM::VMAG', 'path': [('offset', 0x169), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::VMAG'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe9f4, 'name': 'SYSTEM::VMAG2', 'path': [('offset', 0x182), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::VMAG2'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe9b4, 'name': 'SYSTEM::VDIST', 'path': [('offset', 0x19b), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::VDIST'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe974, 'name': 'SYSTEM::VDIST2', 'path': [('offset', 0x1b4), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::VDIST2'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe890, 'name': 'SYSTEM::SHIFT_LEFT', 'path': [('offset', 0x1cd), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SHIFT_LEFT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe8a4, 'name': 'SYSTEM::SHIFT_RIGHT', 'path': [('offset', 0x1e6), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::SHIFT_RIGHT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe758, 'name': 'SYSTEM::FLOOR', 'path': [('offset', 0x1ff), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::FLOOR'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe6e8, 'name': 'SYSTEM::CEIL', 'path': [('offset', 0x218), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::CEIL'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe7c0, 'name': 'SYSTEM::ROUND', 'path': [('offset', 0x231), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::ROUND'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe960, 'name': 'SYSTEM::TO_FLOAT', 'path': [('offset', 0x24a), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::TO_FLOAT'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}, {'ea': 0x1414fe868, 'name': 'SYSTEM::_0x42B65DEEF2EDF2A1', 'path': [('offset', 0x263), ('is_mnem', 'lea'), ('rip', 0x4), ('name', 'SYSTEM::_0x42B65DEEF2EDF2A1'), ('type', 'void __fastcall(scrNativeCallContext *args)')], 'sub': False, 'type': 'void __fastcall(scrNativeCallContext *args)'}]
