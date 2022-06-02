import functools
import inspect
import json
import re
import copy

import ida_search
import idaapi
import idautils
import idc
from idc import BADADDR, LocByName, MakeNameEx, Wait, SegName, Demangle, Qword, GetTrueName
from idc import SEARCH_NOSHOW, SEARCH_NEXT, SEARCH_DOWN, SEARCH_CASE, DEMNAM_FIRST
#  from underscoretest import _
from exectools import _import
#  from sfida.sf_common import isStringish
#  from sfida.sf_is_flags import IsFuncHead, HasUserName
#  from sfida.sf_string_between import string_between

#  retrace = lambda ea, *a, **k: unpatch_func(ea)
from exectools import make_refresh
refresh_membrick = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

def trim_paren(hooka):
    while hooka and hooka[0] == '(' and hooka[-1] == ')':
        hooka = hooka[1:-1]
        print("hooka: {}".format(hooka))
    return hooka

# https://stackoverflow.com/questions/3749512/python-group-by
from functools import reduce # import needed for python3; builtin in python2
from collections import defaultdict

def groupBy(seq, func):
    return reduce(lambda grp, val: grp[func(val)].append(val) or grp, seq, defaultdict(list))


def check_patterns(s=None):
    if s is None:
        for fn in """david/DirectX11.cpp
features/hotkeys.cpp
HookCheckSomeThingy.cpp
HookChecksummers.cpp
HookCPedDictCrash.cpp
HookCrewKick.cpp
HookFatalError1.cpp
HookHook.cpp
HookInvalidObjectCrash.cpp
HookNetArray.cpp
HookNetworkBail.cpp
HookOzark13.cpp
HookPoolSlots.cpp
HookScriptVM.cpp
HookSpeedupNetCat.cpp
HookSpeedupStrlen.cpp
HookSync1.cpp
HookWriteQword.cpp
Patches.cpp
PlayerTracker/PlayerTrackerSession.cpp
Scripting/Hooking.cpp
Scripting/Hooking.h
WolfSniff.cpp""".split('\n'):
            check_patterns(file_get_contents('e:/git/pokey/src/' + fn))
        return

    s2 = []
    for line in s.split('\n'):
        s2.append(string_between('//', '', line, repl='', inclusive=1))
    s = ''.join(s2).replace('{', ';{').split(';')
    del s2
    for line in s:
        line = re.sub(r'if \([a-zA-Z0-9 ]+\)', '', line)
        line = string_between('if (', ')', line, greedy=1, retn_all_on_fail=1)
        hooka = string_between('HOOKA(', ')', line, greedy=1)
        if not hooka:
            hooka = string_between('MAKE_CLASS_FUNCTION_NO_ARGS(', ')', line, greedy=1)
        if not hooka:
            hooka = string_between('MAKE_CLASS_FUNCTION(', ')', line, greedy=1)

        try:
            spl = paren_split(hooka, strip=',', rtrim=1)
        except Exception as e:
            print("Exception: {} {}\nLine: {}".format(type(e), str(e), line))
            continue
        if len(spl) > 2:
            spl[0] = trim_paren(spl[0])
            reconstitute = []
            components = paren_split(spl[0], '.', strip='.', rtrim=1)
            pattern = string_between('("', '")', components[0])
            if not pattern:
                continue
            pattern = re.sub(r'"\s+"', '', pattern)
            hook = spl[1].strip()
            #  devstr = string_between('("', '")', spl[3])
            m = mem(pattern)
            if m.valid():
                reconstitute.append('mem("{}")'.format(m.pattern))
                for component in components[1:]:
                    method = string_between('', '(', component)
                    if not method.startswith('as<'):
                        arguments = string_between('(', ')', component, greedy=1)
                        try:
                            argument = int(arguments, base=0)
                        except ValueError:
                            print("{}: invalid argument: {}: {}".format(hook, method, arguments))
                            m.errored = True
                            break
                        method_attr = getattr(m, method, None)
                        if callable(method_attr):
                            m = method_attr(argument)
                            if not m.valid():
                                print("{}: failed argument: {}: {}".format(hook, method, arguments))
                                break
                            reconstitute.append('{}({})'.format(method, argument))

                if m.valid():
                    print("{}: pattern succeeded: {}: {} type('{}')".format(hook, '.'.join(reconstitute), describe_target(m.value()), idc.get_type(m.value()) ))
            else:
                print("{}: pattern failed: {}: {}".format(hook, pattern, hex(FindInSegments(pattern))))

        else:
            pass
            # print("line(spl): {}: {}".format(len(spl), line))
            



def joaat_memory(ea, length, hash = 0x4C11DB7):
    string = idc.get_bytes(ea, length)
    for b in string:
        hash = (hash + b) * 1025 & 0xFFFFFFFF
        hash = (hash >> 6 ^ hash)

    hash = (hash * 9) & 0xFFFFFFFF
    return (hash >> 11 ^ hash) * 32769 & 0xFFFFFFFF

def isStringish(o):
    return isinstance(o, (string_type, byte_type))

def can_call(fn):
    return fn in globals() and callable(globals()[fn])

if not idc or not can_call('refresh_start'):
    try:
        long_type = long
    except:
        long_type = int

elif can_call('refresh_start'):
    # from di import destart
    # from helpers import UnPatch
    pass

def MakeUniqueLabel(name, ea=BADADDR):
    fnLoc = idc.get_name_ea_simple(name)
    if fnLoc == BADADDR or fnLoc == ea:
        return name
    fmt = "%s_%%i" % name
    for i in range(65535):
        tmpName = fmt % i
        fnLoc = idc.get_name_ea_simple(tmpName)
        if fnLoc == BADADDR or fnLoc == ea:
            return tmpName
    print("[warn] failed to make unique label for {:x} last try: {}".format(ea, tmpName))
    return ""

def nameIfContainsElse(ea, match, name, fullname):
    fnName = label
    if fnName and ~fnName.find(match) and not ~fnName.find(fullname):
        fnName = "{}_{}".format(fnName, name)
    else:
        fnName = fullname
    return fnName

def MemLabelAddressPlus(ea, name, rename_old=False, force=False, replace=False):
    force = force or rename_old or replace
    if ea < idc.BADADDR:
        fnLoc = LocByName(name)
        if fnLoc == BADADDR:
            return MakeNameEx(ea, name, idc.SN_NOWARN)
        elif fnLoc == ea:
            return True

        if force:
            MakeNameEx(fnLoc, "", idc.SN_AUTO | idc.SN_NOWARN)
            Wait()
            return MakeNameEx(ea, name, idc.SN_NOWARN)

        name = MakeUniqueLabel(name, ea)
        return MakeNameEx(ea, name, idc.SN_NOWARN)

    else:
        print("0x0%0x: Couldn't label %s, BADADDR" % (ea, name))
        return False

def ensure_decl(name, decl, size=None):
    if not has_decl(name, size)[0]:
        idc.parse_decls(decl, idc.PT_SILENT)

def find_checksummers():
    strucText = """
        typedef unsigned char uint8_t;
        typedef int int32_t;
        typedef unsigned int uint32_t;
        struct arxan_range
        {
          uint32_t start;
          uint32_t len;
        };
    """
    ensure_decl('arxan_range', strucText)
    def predicate_checksummers(ea):
        o_rel = 3
        o_abs = 14
        #  o_base = -8 # may not find
        rel = mem(ea).add(o_rel).rip(4).val()
        abso = idc.get_qword(mem(ea).add(o_abs).rip(4).val())
        #  base = idc.get_qword(mem(ea).add(o_base).rip(4).val())
        if rel == abso: #  and base == idc.get_name_ea_simple("__ImageBase"):
            mem(abso).label('ArxanChecksumActual1')
            if idc.get_wide_byte(ea + 81) == 0xe8:
                mem(ea).add(82).rip(4).label('ArxanGetNextRange').type("void __fastcall f(uint8_t **guide, arxan_range *range);")
            mem(ea).add(o_abs).rip(4).label('pArxanChecksum_AbsAddressSelf')
            #  mem(ea).add(o_base).rip(4).label('__ImageBase')
            # MakeUnknown(ea, 82 + 4 + 5, DOUNK_DELNAMES)
            return abso
        else:
            print("rel: {:x}, abso: {:x}".format(rel, abso))
        return False


    pattern = '48 31 C0 0F 1F 84 00 00 00 00 00 0F 1F 84 00 00 00 00 00 66 0F 1F 44 00 00'
    if can_call('UnPatch'):
        for e in FindInSegments(pattern, '.text', None):
            UnPatch(e, e+75//3)

    # pattern = '38 48 8d 05 ?? ?? ?? ?? 48 89 45 18 48 8b 05 ?? ?? ?? ?? 48 f7 d8 48 03'
    pattern = '48 8d 05 ?? ?? ?? ?? 48 89 45 18 48 8b 05 ?? ?? ?? ?? 48 f7 d8'
    return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]

def find_checksummers2():

    def predicate_checksummers(ea):
        o_rel = 13
        o_abs = 3
        rel = mem(ea).add(o_rel).rip(4).val()
        abso = idc.get_qword(mem(ea).add(o_abs).rip(4).val())
        #  fnName = nameIfContainsElse(abso, "Arxan", "Mutator", "ArxanMutator")
        if rel == abso:
            #  mem(ea).add(o_abs).rip(4).label("p{}_AbsAddressSelf".format(fnName))
            #  mem(ea).add(o_rel).rip(4).label(fnName)
            #  mem(abso).label(fnName)
            mem(abso).label('ArxanChecksumActual2')
            return abso
        else:
            print("rel: {:x}, abso: {:x}".format(rel, abso))
        return False

    pattern = '48 8b 05 ?? ?? ?? ?? 48 f7 d8 48 8d 15 ?? ?? ?? ?? 48 8d 04 02'
    return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]

def find_checksummers3():

    def predicate_checksummers(ea):
        o_rel = 3
        o_abs = 14
        rel = mem(ea).add(o_rel).rip(4).val()
        abso = idc.get_qword(mem(ea).add(o_abs).rip(4).val())
        #  fnName = nameIfContainsElse(abso, "Arxan", "Decider", "ArxanDecider")
        if rel == abso:
            #  mem(ea).add(o_abs).rip(4).label("p{}_AbsAddressSelf".format(fnName))
            #  mem(ea).add(o_rel).rip(4).label(fnName)
            #  mem(abso).label(fnName)
            mem(abso).label('ArxanChecksumActual3')
            return abso
        else:
            print("{:x}: rel: {:x}, abso: {:x}".format(ea, rel, abso))
        return False

    pattern = '48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8B 05 ?? ?? ?? ?? 48 F7 D8'

    return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]


def find_checksummers6():
    """
    48 8b 05 ?? ?? ?? ?? 
    48 89 45 68 
    48 8d 05 ?? ?? ?? ?? 
    48 89 45 48 
    48 8b 05 ?? ?? ?? ?? 
    48 f7 d8 
    48 03 45 48 
    48 89 45 48 
    48 8b 45 48

    48 8b 05 ?? ?? ?? ??
    48 89 45 ??
    48 8d 05 ?? ?? ?? ??
    48 89 45 ??
    48 8b 05 ?? ?? ?? ??
    48 f7 d8
    48 03 45 ??
    48 89 45 ??
    48 8b 45 ??



    """

    """
    00  48 8B 05 9A 28 35 01                          mov     rax, cs:o_imagebase_189
    07  48 89 45 68                                   mov     [rbp+68h], rax
    11  48 8D 05 B1 E2 6A 00                          lea     rax, ArxanChecksumCallsGetNextRange_235
    18  48 89 45 48                                   mov     [rbp+48h], rax
    22  48 8B 05 E2 5C 8A FD                          mov     rax, cs:o_arxanchecksumcallsgetnextrange_235
    29  48 F7 D8                                      neg     rax
    32  48 03 45 48                                   add     rax, [rbp+48h]
    36  48 89 45 48                                   mov     [rbp+48h], rax
    40  48 8B 45 48                                   mov     rax, [rbp+48h]
    """
    def predicate_checksummers(ea):
        o_rel = 14
        o_abs = 25
        rel = mem(ea).add(o_rel).rip(4).val()
        abso = idc.get_qword(mem(ea).add(o_abs).rip(4).val())
        #  fnName = nameIfContainsElse(abso, "Arxan", "Decider", "ArxanDecider")
        if rel == abso:
            #  mem(ea).add(o_abs).rip(4).label("p{}_AbsAddressSelf".format(fnName))
            #  mem(ea).add(o_rel).rip(4).label(fnName)
            #  mem(abso).label(fnName)
            mem(abso).label('ArxanChecksumActual6')
            return abso
        else:
            print("{:x}: rel: {:x}, abso: {:x}".format(ea, rel, abso))
            mem(rel).label('ArxanChecksumActual7')
            return rel
        return False

    pattern = '48 8b 05 ?? ?? ?? ?? 48 89 45 ?? 48 8d 05 ?? ?? ?? ?? 48 89 45'

    return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]


def find_trace_hooks():
    patterns=[
        # Hook Tracing
        "0f b6 00 0f b6 c0 83 f8 49 0f 85",
        "0f b6 40 01 25 f8 00 00 00 3d b8 00 00 00 0f 85",
        "0f b6 40 01 48 8b 95 ?? ?? ?? ?? 0f b6 52 0b 33 c2 a8 07 0f 84",
        "0f b6 40 01 48 8b 95 ?? ?? ?? ?? 0f b6 52 0c 33 c2 a8 07 0f 85",
        "0f b6 40 0a 0f b6 c0 3d ff 00 00 00 0f 85",
        "0f b6 40 0a 0f b6 c0 83 f8 41 0f 85",
        "0f b6 40 0b 0f b6 c0 3d ff 00 00 00 0f 85",
        "0f b6 40 0b 25 f8 00 00 00 3d e0 00 00 00 0f 85",
        "0f b6 40 0c 25 f8 00 00 00 3d e0 00 00 00 0f 85",
        # Hook Detection
        "80 39 ff 74 0e 8a 01 04 17 41 3a c5 76 05 80 39 90",
    ]
    return [FindInSegments(x) for x in patterns]


def find_checksummers4():
    patterns = ['D3 E0 33 45 ?? 89 45 ?? 8B 45 ?? E9']

def find_checksummers5():
    __ImageBase = 0x140000000
    strucText = """
        typedef unsigned char uint8_t;
        typedef int int32_t;
        typedef unsigned int uint32_t;
        struct arxan_range
        {
          uint32_t start;
          uint32_t len;
        };
    """
    ensure_decl('arxan_range', strucText)
    def predicate_checksummers(ea):
        return False
        o_rel = 4
        o_abs = 15
        o_base = -7
        rel = mem(ea).add(o_rel).rip(4).val()
        abso = idc.get_qword(mem(ea).add(o_abs).rip(4).val())
        base = idc.get_qword(mem(ea).add(o_base).rip(4).val())
        if rel == abso and base == __ImageBase:
            mem(abso).label('ArxanChecksumActual5')
            if idc.get_wide_byte(ea + 81) == 0xe8:
                mem(ea).add(82).rip(4).label('ArxanGetNextRange').type("void __fastcall f(uint8_t **guide, arxan_range *range);")
            mem(ea).add(o_abs).rip(4).label('pArxanChecksum_AbsAddressSelf')
            mem(ea).add(o_base).rip(4).label('__ImageBase')
            # MakeUnknown(ea, 82 + 4 + 5, DOUNK_DELNAMES)
            return abso
        else:
            print("rel: {:x}, abso: {:x}".format(rel, abso))
        return False

    #  .text:143c81200   b8      sub_143ADEB2E    48 8d 05 ?? ?? ?? ??          	lea rax, [sub_143ADEB2E]
    #  .text:143c81207   b8      sub_143ADEB2E    48 89 45 ??                   	mov [rbp+0x18], rax
    #  .text:143c8120b   b8      sub_143ADEB2E    48 8b 05 ?? ?? ?? ??          	mov rax, [off_140D09274]
    #  .text:143c81212   b8      sub_143ADEB2E    48 f7 d8                      	neg rax
    #    = '38 48 8d 05 ?? ?? ?? ?? 48 89 45 18 48 8b 05 ?? ?? ?? ?? 48 f7 d8 48 03'
    pattern = "48 8d 05 ?? ?? ?? ?? 48 89 45 ?? 48 8b 05 ?? ?? ?? ?? 48 f7 d8"
    # which is the same as checksummer original, with a few bytes trimmed on either side.

    return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]

def find_set_return_addresses():
    patterns = ['55 48 83 ec 30 48 8d 6c 24 20 48 89 4d 20 48 89 55 28 8b 05']
    
    results = []
    for ea in FindInSegments(patterns, '.text'):
        ForceFunction(ea)
        SetType(ea, "int sub(uint8_t *imagebase, void *arg_0_ptr);")
        MemLabelAddressPlus(ea, 'SetReturnAddressTo_{:x}'.format(0x100000000 | idc.get_wide_dword(mem(ea + 0x14).rip(4).val())))
        results.append(ea)

    return results

def find_lame_memcpys():
    patterns = [
            '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82'
            #  '48 89 6c 24 f8 48 8d 64 24 f8 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 48 89 6c 24 f8 48 8d 64 24 f8 48 bd 0d',
            #  '48 8d 64 24 f8 48 89 2c 24 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9',
            #  '55 0f 1f 84 00 00 00 00 00 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9',
            #  '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9',
    ]
    patterns = [x[0:38] for x in patterns] 
    results = []
    for ea in FindInSegments(patterns, '.text'):
        #  if idc.get_wide_byte(ea) == 0x48:
            #  # short pattern
            #  fnStart = '; '.join([str(x).lower() for x in der(ea)][0:10])
            #  keyInsns = ['lea rbp, [rsp+0x20]', 'mov [rbp+0x10], rcx', 'mov [rbp+0x18], rdx', 'mov [rbp+0x20], r8d', 'mov eax, [rbp+0x20]']
            #  found = 0
            #  for k in keyInsns:
                #  if k in fnStart:
                    #  found += 1
            #  if found < 3:
                #  continue
        ForceFunction(ea)
        results.append(ea)

        #  MemLabelAddressPlus(ea, "ArxanMemcpy")
        # idc.add_func(ea)
        # MemLabelAddressPlus(ea, 'ArxanMemcpy')
        # Remove "FAR PROC" attribute and set "BP frame"
        if True:
            MemLabelAddressPlus(ea, 'ArxanMemcpy')
            idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x10) & ~0x22)
            idc.SetType(ea, "void f(uint8_t *dst, uint8_t *src, uint32_t len);") \
                    or idc.SetType(ea, "void f(BYTE *dst, BYTE *src, unsigned int len);")
            refFuncName = FuncRefsTo(ea)
            if len(refFuncName) == 1:
                for ref in refFuncName:
                    ref_ea = GetFuncStart(ref)
                    if not IsSameFunc(ea, eax(ref_ea)):
                        if HasAnyName(ref_ea):
                            if not HasUserName(eax(ref_ea)) and idc.get_name(ref_ea, ida_name.GN_VISIBLE).startswith('sub_'):
                                LabelAddressPlus(eax(ref_ea), "ArxanCallsMemcpy")
                            else:
                                suffix = re.sub(r'^[a-zA-Z]+', '', idc.get_name(ref_ea)) # string_between('_', '', mainName)
                                MemLabelAddressPlus(ea, suffix + 'ArxanMemcpy')


    return results

def find_checksum_workers():
    patterns = [[
            # start sigs
            '55 48 83 ec 40 48 8d 6c 24 20 48 89 4d 30 48 89 55 38 33 c0 89 45 08 89', 
            '48 8d 64 24 f8 48 89 2c 24 48 83 ec 40 48 8d 6c 24 20 48 89 4d 30 48 89 55 38',
            ], [
            # middle sigs
            '48 83 c2 01 48 8b 4d 30 48 89 11 3d 80 00 00 00', 
            '48 8b 45 30 48 8b 00 0f b6 00 83 e0 7f 8b 55 08 89 d1 d3 e0',
            '83 45 08 07 48 8b 45 30 48 8b 00 0f b6 00 0f b6 c0']]
    results = []
    for ea in FindInSegments(patterns[0], '.text'):
        results.append(ea)

        #  MemLabelAddressPlus(ea, "ArxanMemcpy")
        if not IsFuncHead(ea):
            if not ForceFunction(ea):
                print("{:x} ArxanGetNextRange Couldn't ForceFunction".format(ea))
        MemLabelAddressPlus(ea, 'ArxanGetNextRange')
        #  LabelAddressPlus(ea, 'ArxanGetNextRange')
        # Remove "FAR PROC" attribute and set "BP frame"
        idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x10) & ~2)
        idc.SetType(ea, "void __fastcall f(uint8_t **guide, arxan_range *range);")
        refFuncName = FuncRefsTo(ea)
        for ref in refFuncName:
            if not HasUserName(ref):
                MemLabelAddressPlus(idc.get_name_ea_simple(ref), "ArxanChecksumCallsGetNextRange")

    return results



def find_decrypted_loadlibs():
    # pattern = '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ??'
    # pattern = '48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 0f b6 00 48 0f be c0 85 c0 0f 84'
    pattern = "55 48 81 ec ?? ?? 00 00 48 8d 6c 24 ?? 48 89 9d ?? ?? 00 00"
    for ea in [e for e in FindInSegments(pattern, '.text')]:
        print(hex(ea))
        if can_call('retrace'):
            ForceFunction(ea)
            if 0:
                try:
                    retrace(ea)
                except RelocationTerminalError as e:
                    print("Exception: RelocationTerminalError: {}".format(e.args))

        LabelAddressPlus(ea, 'potential_ciphered_loadlib')

def find_arxan_mutators():
    # pattern = '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ??'
    # pattern = '48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 0f b6 00 48 0f be c0 85 c0 0f 84'
    patterns = [
        "55 48 81 ec c0 00 00 00 48 8d 6c 24 20 48 89 8d b0 00 00 00 48 c7 45 58 00 00 00 00 48 8d 85 b8 00 00 00 48 89 45 60 48 8b 45 60 48 8b 00 48 83 f8 18",
        "48 ?? ?? ?? ?? 48 ?? ?? ?? 48 81 EC A0 00 00 00 48 8D 6C 24 20 48 89 5D ?? 48 89 8D 90 00 00 00 48 C7 45 ?? ?? ?? ?? ?? 48 8D 85 98 00 00 00 48 89 45 ?? 48 8B 45 ?? 48 8B 00 48 83 F8 18 55 48 BD ?? ?? ?? ?? 01 00 00 00 48 87 2C 24 52 53 48 8B 54 24 10 48 BB ?? ?? ?? ?? 01 00 00 00 48 0F 45 D3 48 89 54 24 10 5B 5A C3",
        "48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 81 EC A0 00 00 00 48 8D 6C 24 20 48 89 5D ?? 48 89 8D 90 00 00 00 48 C7 45 ?? ?? ?? ?? ?? 48 8D 85 98 00 00 00 48 89 45 ?? 48 8B 45 ?? 48 8B 00 48 83 F8 18 55 48 BD ?? ?? ?? ?? 01 00 00 00 48 87 2C 24 52 53 48 8B 54 24 10 48 BB ?? ?? ?? ?? 01 00 00 00 48 0F 45 D3 48 89 54 24 10 5B 5A C3",
    ]
    results = []
    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            results.append(ea)
            print(hex(ea))
            LabelAddressPlus(ea, 'ArxanChecksumOrHealerA')
    return results

def find_vortex():
    patterns = [ "C1 E2 04 8D 04 42 8B 55 ?? C1 E2 07 03 C2 8B 55 ?? C1 E2 08 03 C2 8B 55 ?? C1 E2 18 03 C2 03 45" ]
    results = []
    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            results.append(ea)
            fnloc = GetFuncStart(ea)
            if HasUserName(fnloc):
                fnname = GetFuncName(fnloc)
                if fnname.startswith("Arxan"):
                    if 'Vortex' not in fnname:
                        LabelAddressPlus(fnloc, fnname.replace('Arxan', 'ArxanVortex'))
                    continue
            LabelAddressPlus(ea, 'OrphanedArxanVortex')
    return results

def find_setreturn():
    results = []
    for ea in _.flatten(FuncRefsTo(FunctionsMatching('SetReturnAddressTo'))):
        results.append(ea)
        fnloc = eax(ea)
        if HasUserName(fnloc):
            fnname = GetFuncName(fnloc)
            if fnname.startswith("Arxan"):
                if 'SetsReturn' not in fnname:
                    LabelAddressPlus(fnloc, fnname.replace('Arxan', 'ArxanSetsReturn'))
                continue
        LabelAddressPlus(fnloc, 'OrphanedArxanSetsReturn')
    return results

def find_antidebug():
    results = []
    s = FuncRefsTo(['GetCurrentProcess', 'FreeLibrary', 'CloseHandle', 'AddVectoredExceptionHandler', 'RemoveVectoredExceptionHandler', 'SetUnhandledExceptionFilter'])
    for ea in set(s[0]).intersection(s[4]):
        results.append(ea)
        fnloc = eax(ea)
        if HasUserName(fnloc):
            fnname = GetFuncName(fnloc)
            if fnname.startswith("Arxan"):
                if 'AntiDebug' not in fnname:
                    LabelAddressPlus(fnloc, fnname.replace('Arxan', 'ArxanAntiDebug'))
                continue
        LabelAddressPlus(fnloc, 'OrphanedArxanAntiDebug')
    return results

def find_rolls():
    patterns = [ '51 8b 4d ?? d3 45 ?? 59', '51 8B 8D ?? ?? ?? ?? D3 85 ?? ?? ?? ?? 59']
    results = []
    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            results.append(ea)
            fnloc = GetFuncStart(ea)
            if HasUserName(fnloc):
                fnname = GetFuncName(fnloc)
                if fnname.startswith("Arxan"):
                    if 'Roll' not in fnname:
                        LabelAddressPlus(fnloc, fnname.replace('Arxan', 'ArxanRoll'))
                    continue
            LabelAddressPlus(ea, 'OrphanedArxanRoll')
    return results

def fix_obfu_scan():
    patched = []
    for ea in [e for e in FindInSegments('48 8D 64 24 F8 48 89 2C 24', '.text')]:
        obfu._patch(ea)
        patched.append(ea)
    for ea in [e for e in FindInSegments('48 89 6C 24 F8 48 8D 64 24 F8', '.text')]:
        obfu._patch(ea)
        obfu._patch(ea)
        patched.append(ea)

    for ea in _.uniq(patched):
        obfu._patch(ea)
        EaseCode(ea, noExcept=1, forceStart=1)

def fix_old_balances():
    patterns = [
        # '48 8d 64 24 f8 48 89 2c 24 48 8d 2d 76 31 ff ff 48 87 2c 24 55 48 8d 2d 30 5a 48 00 48 87 2c 24 c3',
          '48 8d 64 24 f8 48 89 2c 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3',
        # 'e8 47 5a 48 00 e9 7c 31 ff ff 0f 1f 84 00 00 00 00 00 0f 1f 84 00 00 00 00 00 0f 1f 80 00 00 00 00',
        # 'e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f 1f 84 00 00 00 00 00 0f 1f 84 00 00 00 00 00 0f 1f 80 ?? ?? ?? ??')
          '48 89 6c 24 f8 48 8d 64 24 f8 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3'
    ]

    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            print("test: {:x}".format(ea))
            MyMakeUnknown(ea, 99 // 3, DOUNK_EXPAND)
            m = membrick_memo(ea, pattern=pattern)
            # asm = nassemble(ea, "call 0x{:x}; jmp 0x{:x}".format(m.add(72//3).rip(4).ea, m.add(36//3).rip(4).ea))
            asm = nassemble(ea, "call 0x{:x}; jmp 0x{:x}".format(m.autorip(1).ea, m.autorip(0).ea))
            PatchBytes(ea, asm, "BalanceJump")
            PatchNops(ea + 10, (1 + len(pattern)) // 3 - 10, "BalanceJumpSpare")
            if not IsCode_(ea):
                EaseCode(ea, (1 + len(pattern)) // 3, forceStart=1)
            fix_location_plus_2(ea, code=1)
            fix_location_plus_2(ea + 5, code=1)
            if IsFunc_(ea + 10):
                if IsSameFunc(ea + 10, ea - 10):
                    ZeroFunction(ea - 10)
                else:
                    SetFuncEnd(ea + 10, ea + 10)
    fix_obfu_scan()



def find_checksummers_from_balances():
    # pattern = '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ??'
    # pattern = '48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 0f b6 00 48 0f be c0 85 c0 0f 84'
    patterns = [
        "6A 10 48 F7 C4 0F 00 00 00 0F 85 ?? ?? ?? ?? E9",
        "68 10 00 00 00 48 F7 C4 0F 00 00 00 0F 85 ?? ?? ?? ?? E9",
    ]
    results = []
    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            try: 
                r = AdvanceToMnemEx(ea, term=('call', 'retn'), inclusive=1, ease=1)
                sti = CircularList(r)
                m = sti.multimatch([
                    r'push.*0x10',
                    r'test rsp, 0xf',
                    r'jnz .*',
                    r'push.*0x18',
                    r'(add|sub) rsp, .*',
                    r'(mov|lea).*r[sb]p.*r[sb]p',
                    r'(mov|lea).*r[sb]p.*r[sb]p',
                    r'lea rbp, \[rel ({jmp}\w+)]',
                    r'xchg \[rsp], rbp',
                    r'push rbp',
                    r'lea rbp, \[rel ({call}\w+)]',
                    r'xchg \[rsp], rbp',
                    r'retn?',
                ])
                target = None
                if m:
                    target = m['call'][0]
                    #  while obfu._patch(m['default'][5].ea):
                        #  pass
#  
                    #  r = AdvanceToMnemEx(ea, term='call', inclusive=1, ease=1)
                        
                if target or r and r.insns:
                    if not target:
                        insns = _.pluck(r.insns, 'insn')
                        if not (5 < len(insns) < 12):
                            print("{:x} [find_checksummers_from_balances] len(insns): {}".format(ea, len(insns)))
                            continue
                        insn = insns[-1]
                        target = string_between('', ' ', insn, greedy=1, inclusive=1, repl='')
                    print("{:x} {}".format(eax(target), target))
                    if not IsCode_(target):
                        EaseCode(ea, forceStart=1)
                    if isUnconditionalJmpOrCall(eax(target)):
                        continue
                    results.append(eax(target))
                    if not HasUserName(eax(target)):
                        LabelAddressPlus(eax(target), 'ArxanChecksumActual0')
            except AdvanceFailure:
                pass
    return results

def find_rbp_frame():
    patterns = ["55 48 81 ec ?? ?? 00 00 48 8d 6c 24 ??", 
                "55 48 83 EC ?? 48 8D 6C 24 ??",
                "48 89 6c 24 f8 48 8d 64 24 f8 48 81 ec ?? ?? 00 00 48 8d 6c 24 ??", 
                "48 89 6c 24 f8 48 8d 64 24 f8 48 83 EC ?? 48 8D 6C 24 ??"
                ]
    
    #   b1180
    #  .text:0000000143ADEB2E 000 48 89 6C 24 F8                                mov     [rsp+var_8], rbp ; [PatchBytes] mov/lea->push order swap: rbp
    #  .text:0000000143ADEB2E                                                                           ; [PatchBytes] lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
    #  .text:0000000143ADEB33 000 48 8D 64 24 F8                                lea     rsp, [rsp-8]
    #  .text:0000000143ADEB38 008 48 81 EC ?? ?? 00 00                          sub     rsp, 0B0h
    #  .text:0000000143ADEB3F 0B8 48 8D 6C 24 20                                lea     rbp, [rsp+20h]

    results = []
    for pattern in patterns:
        for ea in FindInSegments(pattern, '.text'):
            ea = idc.get_item_head(ea)
            next_ea = ea + (len(pattern) + 1) // 3
            ida_disasm = idc.generate_disasm_line(next_ea, idc.GENDSM_FORCE_CODE)
            mnem = string_between('', ' ', ida_disasm)
            print(hex(ea), ida_disasm)
            TagAddress([ea], "rbp_frame")
            results.append(ea)
    return results

def find_stack_align_adjust():
    patterns = ["6a 10 48 f7 c4 0f 00 00 00 0f 85 ?? ?? ?? ?? e9"]
    results = FindInSegments(patterns, '.text')
    starts = []
    for ea in results:
        # print(hex(ea), idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE))
        if HasUserName(ea):
            LabelAddressPlus(ea, '')
        print("find_stack_align_adjust: 0x{:x}".format(ea))
        fnStart = destart(ea, 0xa8)
        if fnStart is None:
            print("[find_stack_align_adjust] couldn't trace back from {:x}".format(ea))
            continue
        while diida(fnStart - 1).startswith("push"):
                fnStart -= 1
        if not fnStart:
            continue
        while idc.get_wide_byte(fnStart - 1) == 0x41 or idc.get_wide_byte(fnStart - 2) == 0x41:
            if idc.get_wide_byte(fnStart - 2) == 0x41:
                fnStart -= 2
            if idc.get_wide_byte(fnStart - 1) == 0x41:
                fnStart -= 1
        ForceFunction(fnStart)
        print(hex(fnStart), hex(ea), idc.generate_disasm_line(fnStart, idc.GENDSM_FORCE_CODE))
        push_count, new_ea, unused2 = CountConsecutiveMnem(fnStart, ["push", "pushf", "pushfq"])
        if push_count > 8 or diida(new_ea) == 'test rsp, 0xf':
            TagAddress([fnStart], "stack_align")
            starts.append(fnStart)
    return starts

        #  if can_call('retrace'):
            #  if not IsFuncHead(fnStart):
                #  ForceFunction(fnStart)
                #  ZeroFunction(fnStart)
            #  try:
                #  retrace(fnStart)
            #  except RelocationTerminalError as e:
                #  print("Exception: RelocationTerminalError: {}".format(e.args))

def find_imagebase_offsets():
    base = ida_ida.cvar.inf.min_ea
    r = xrefs_to(base)
    un = [x for x in r if Qword(x) == base]
    for x in un: 
        LabelAddressPlus(x, 'o_imagebase')

#  del retrace

#  def retrace(ea, *args, **kwargs):
    #  global retrace_later
    #  retrace_later.add(ea)
#  
#  retrace_later = set()

# sprint = print

def find_all_checksummers():
    cs = find_checksummers0()
    cs.extend( find_checksummers() )
    cs.extend( find_checksummers1() )
    cs.extend( find_checksummers2() )
    cs.extend( find_checksummers4() )
    cs.extend( find_checksummers5() )
    cs.extend( find_checksummers3() )
    cs.extend( find_checksummers6() )
    return cs


def find_shifty_stuff():
    results = {}
    setglobal('shifty', results)
    idc.batch(0)
    print("find_shifty_stuff()")
    pp(obfu)
    print("{}".format("arxan_mutators"))
    # print("{}".format("rbp_frame"))
    # results['rbp'] = find_rbp_frame()
    r = {}
    print("cs0")
    cs0 = find_checksummers_from_balances(); print("checksummers_0: {}".format(hex(cs0)))
    print("cs1")
    cs1 = find_checksummers(); print("checksummers: {}".format(hex(cs1)))
    print("cs2")
    cs2 = find_checksummers2(); print("checksummers2: {}".format(hex(cs2)))
    print("cs4")
    cs4 = find_checksummers4(); print("checksummers4: {}".format(hex(cs4)))
    print("cs5")
    cs5 = find_checksummers5(); print("checksummers5: {}".format(hex(cs5)))
    print("cs3")
    cs3 = find_checksummers3(); print("checksummers3: {}".format(hex(cs3)))
    print("cs6")
    cs6 = find_checksummers6(); print("checksummers6: {}".format(hex(cs6)))
    results['cs'] = [cs0, cs1, cs2, cs3, cs4, cs5, cs6]
    #  print("checksummers...")
    #  print([idc.get_func_name(x) for x in r])
    #  LabelManyAddresses(r, "ArxanChecksumTest", force=1)
    #  retrace_list(r)
    print("{}".format("lame_memcpys"))
    results['memcpy'] = find_lame_memcpys()
    # retrace_list(r)
    results['csworkers'] = find_checksum_workers()
    # retrace_list(r)
    #  print("{}".format("decrypted_loadlibs"))
    #  find_decrypted_loadlibs()
    print("{}".format("stack_align_adjust"))
    results['balance'] = find_stack_align_adjust()
    print("{}".format("imagebase_offsets"))
    find_imagebase_offsets()
    if False:
        for ea in [GetFuncStart(x) for x in FindInSegments("8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ??")]:
            AddTag(ea, "seldom")

    #  LabelManyAddresses(results['cs'][0], "ArxanCheckFunction__0", force=1)
    #  LabelManyAddresses(results['cs'][0], "ArxanCheckFunction__1", force=1)
    #  LabelManyAddresses(results['cs'][1], "ArxanCheckFunction__2", force=1)
    #  LabelManyAddresses(results['cs'][2], "ArxanCheckFunction__3", force=1)
    LabelManyAddresses(results['csworkers'], "ArxanGetNextRange", force=1)
    LabelManyAddresses(results['balance'], "ArxanBalance", force=1)
    for ea in results['balance']:
        Commenter(ea, 'line').remove('[DENY JMP]')
    LabelManyAddresses(results['memcpy'], "ArxanMemcpy", force=1)
    results['rol'] = find_rolls()
    results['setret'] = find_setreturn()
    results['vortex'] = find_vortex()
    results['setra'] = find_set_return_addresses()

    return results

def DoesFuncReturn(ea=None):
    """
    DoesFuncReturn

    @param ea: linear address
    """
    ea = eax(ea)
    return ida_funcs.func_does_return(ea)

def IsFarFunc(ea=None):
    """
    Is function FAR 

    calls idc.get_func_flags(ea) & 0x22

    @param ea: linear address
    @return combination of FUNC_FAR - 0x02 and FUNC_USERFAR - 0x20
    """
    ea = eax(ea)
    return idc.get_func_flags(ea) & 0x22

def SetFarFunc(ea=None, flags=None):
    """
    Is function FAR 

    calls idc.set_func_flags(ea) & 0x22

    @param ea: linear address
    @return: !=0 - ok
    """
    ea = eax(ea)
    if not flags:
        flags = 0
    elif flags and flags & 0x22 == 0:
        flags = 0x22

    return idc.set_func_flags(ea, (idc.get_func_flags(ea) & ~0x22) | flags & 0x22)

def FixFarFuncs():
    [SetFarFunc(x, 0) for x in Functions() if IsFarFunc(x)]

def StripTags(s):
    return string_between("_$.", "$", s, repl='', greedy=1)

def TagGetTagSubstring(s):
    return string_between("_$.", "$", s, greedy=1)

def HasTags(s):
    return "_$." in s

def TagRemoveSubstring(s):
    #  for tag in TagGetTagSubstring(s):
    r = string_between("_$.", "$", s, greedy=0, inclusive=1, repl='')
    return r

def TagAddSubstring(s, t):
    r = s + t
    return r

def TagGetTagsFromSubstring(s):
    tags = [x for x in TagGetTagSubstring(s).split('.') if x]
    if not tags:
        return []
    return list(set(tags))

def TagMakeTagSubstring(tags):
    tags = A(tags)
    tags.sort()
    if not len(tags):
        return ""
    # dprint("[debug] tags, len(tags)")
    #  print("[debug] tags:{}, len(tags):{}".format(tags, len(tags)))
    
    return "_$.{}$".format(".".join(tags))

def GetTags(ea):
    label = idc.get_name(get_ea_by_any(ea)) or ea
    return TagGetTagsFromSubstring(label)

def HasTag(ea, tag):
    return tag in GetTags(ea)

def UpgradeTag(ea, tags, remove=False):
    tags = A(tags)
    ea = get_ea_by_any(ea)
    _found = set()
    old_label = label = idc.get_name(ea)
    _existing = set(TagGetTagsFromSubstring(label))
    label = TagRemoveSubstring(label)
    pattern = r'_+(' + '|'.join(tags) + r')(?![a-zA-Z0-9])'
    matches = re.findall(pattern, label)
    if matches:
        # dprint("[debug] matches")
        #  print("[debug] matches:{}".format(matches))
        
        for match in matches:
            _found.add(match.lstrip('_'))
        label = re.sub(pattern, '', label)
        if not remove and _existing.symmetric_difference(_found):
            _existing = _existing.union(_found)
        label = label + TagMakeTagSubstring(_existing)
        if not idc.set_name(ea, label, idc.SN_NOWARN | idc.SN_NOCHECK):
            print("[warn] couldn't set name of {:x} to {}".format(ea, label))
        else:
            print("[info] set name of {:x} to {}".format(ea, label))

def RemoveTag(ea, tags):
    ea = get_ea_by_any(ea)
    _remove = set(A(tags))
    old_label = label = idc.get_name(ea)
    _existing = set(TagGetTagsFromSubstring(label))
    if _existing & _remove:
        label = TagRemoveSubstring(label)
        _new = _existing - _remove
        label = label + TagMakeTagSubstring(_new)
        if not idc.set_name(ea, label, idc.SN_NOWARN | idc.SN_NOCHECK):
            print("[warn] couldn't set name of {:x} to {}".format(ea, label))
        else:
            print("[info] set name of {:x} to {}".format(ea, label))

def RemoveTags(ea):
    ea = get_ea_by_any(ea)
    old_label = label = idc.get_name(ea)
    label = StripTags(label)
    if label != old_label:
        if not idc.set_name(ea, label, idc.SN_NOWARN | idc.SN_NOCHECK):
            print("[warn] couldn't set name of {:x} to {}".format(ea, label))
        else:
            print("[info] set name of {:x} to {}".format(ea, label))

def AddTag(ea, tags):
    ea = get_ea_by_any(ea)
    _add = set(A(tags))
    old_label = label = idc.get_name(ea)
    _existing = set(TagGetTagsFromSubstring(label))
    if _existing.symmetric_difference(_add):
        label = TagRemoveSubstring(label)
        _new = _existing.union(_add)
        label = label + TagMakeTagSubstring(_new)
        if not idc.set_name(ea, label, idc.SN_NOWARN | idc.SN_NOCHECK):
            print("[warn] couldn't set name of {:x} to {}".format(ea, label))
        else:
            print("[info] set name of {:x} to {}".format(ea, label))

def TagAddress(addr, tag, remove=False):
    if not tag:
        return
    addr = A(addr)
    for ea in addr:
        ea = get_ea_by_any(ea)
        if HasUserName(ea):
            if remove:
                RemoveTag(ea, tag)
            else:
                AddTag(ea, tag)
            label = idc.get_name(ea)
            _existing = set(TagGetTagsFromSubstring(label))
            if label.find("_{}".format(tag)) > 0:
                label = label.replace("_{}".format(tag), '')
            label = TagRemoveSubstring(label) + TagMakeTagSubstring(_existing)
            if not idc.set_name(ea, label, idc.SN_NOWARN | idc.SN_NOCHECK):
                print("[warn] couldn't set name of {:x} to {}".format(ea, label))
            else:
                print("[info] set name of {:x} to {}".format(ea, label))
        else:
            MemLabelAddressPlus(ea, "_{}_{:X}{}".format('sub' if IsFuncHead(ea) else 'loc', ea, TagMakeTagSubstring(tag)))

def LabelManyAddresses(l, label, force = False):
    for ea in l:
        #  #  head = ea
        #  #  if IsTail(head):
            #  #  head = idc.get_item_head(ea)
        #  #  if not IsCode_(head):
            #  #  try:
                #  #  forceCode(head)
            #  #  except AdvanceFailure:
                #  #  print("AdvanceFailure labelling {:x}".format(head))
                #  #  continue
        #  #  if not force and idc.hasUserName(idc.get_full_flags(ea)) and not idc.get_name(ea).startswith('_sub_'):
            #  #  continue
        # dprint("[labelling] ex, label")
        #  print("[labeling] ea:{:x}, label:{}".format(ea, label))
        
        MemLabelAddressPlus(ea, label)
        #  print("[labeled] ea:{:x}, label:{}".format(ea, idc.get_name(ea), ida_name.GN_VISIBLE))

def FunctionsMatching(regex=None, exclude=None, filter=lambda x: x, flags=0):
    if regex and not isinstance(regex, re.Pattern):
        regex = re.compile(regex, flags)
    if exclude and not isinstance(exclude, re.Pattern):
        exclude = re.compile(exclude, flags)
    result = [a for a in idautils.Functions() if filter(a) and (not regex or re.match(regex, idc.get_name(a)))]
    if exclude:
        result = [a for a in result if not re.search(regex, idc.get_name(a))]
    return result

def NamesMatching(regex=None, exclude=None, filter=lambda x: x, flags=0):
    if regex and not isinstance(regex, re.Pattern):
        regex = re.compile(regex, flags)
    if exclude and not isinstance(exclude, re.Pattern):
        exclude = re.compile(exclude, flags)
    result = [a[0] for a in idautils.Names() if filter(a[0]) and (not regex or re.match(regex, a[1]))]
    if exclude:
        result = [a for a in result if not re.search(regex, idc.get_name(a))]
    return result


def FunctionNamesMatching(regex=None, exclude=None, filter=lambda x: x, flags=0):
    return GetFuncName(FunctionsMatching(regex, exclude, filter, flags))

def FunctionsMatchingUi(*args, **kwargs):
    result = [[idc.get_name(x), hex(x)] for x in FunctionsMatching(*args, **kwargs)]
    result.sort()
    from HexRaysPyTools.forms import MyChoose
    variable_chooser = MyChoose(
        [x for x in result],
        "Select Function",
        [["Function name", 25], ["Function address", 16]]
    )
    row = variable_chooser.Show(modal=True)
    if row != -1:
        idc.jumpto(int(result[row][1], 16))
        #  idaapi.open_pseudocode(result[row][1], 0)



def FunctionsWhere(predicate):
    return [a for a in idautils.Functions() if predicate(idc.get_name(a), a)]


class MemBatchMode(object):
    old_batch_mode = None
    new_batch_mode = None

    def __init__(self, new_batch_mode):
        self.new_batch_mode = new_batch_mode

    def __enter__(self):
        self.old_batch_mode = idc.batch(self.new_batch_mode)
        return self.old_batch_mode

    def __exit__(self, exc_type, exc_value, traceback):
        if self.old_batch_mode is not None:
            idc.batch(self.old_batch_mode)

def FindRelRef(ea=None):
    """
    FindRelRef

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [FindRelRef(x) for x in ea]

    ea = eax(ea)

    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        print("segment: {}".format(seg_name))
        if seg_name == '.text':
            seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)

            for a in range(seg_start, seg_end):
                if a + MakeSigned(Dword(a)) + 4 == ea:
                    return a


def FindInSegments(searchstr, segments=None, start=None, stop=None, limit=None, predicate=None, iteratee=None, binary=True):
    """
    @param searchstr: a string as a user enters it for Search Text in Core
    @param segments: segment names (default: ['.text'])
    @param predicate: function(address) -> address or None
    @param limit: maximum number of results to return

    @return: [address, ...] of found results result or [] if none found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)

    @eg: filter(IsFuncHead, FindInSegments("ba 10 00 00 00 e9 ?? ?? ?? ??"))
    """
    if isinstance(searchstr, list):
        results = []
        for search in searchstr:
            results.extend(FindInSegments(search, start=start, stop=stop, segments=segments, limit=limit, predicate=predicate, iteratee=iteratee, binary=binary))
        return results

    if isinstance(searchstr, int):
        if searchstr < 0:
            searchstr = searchstr & 0xffffffff
        _len = math.ceil((len("{:x}".format(searchstr))) / 2)
        _bytes = searchstr.to_bytes(_len, byteorder='little')
        searchstr = ' '.join("{:02x}".format(x) for x in _bytes)


    if not segments:
        segments = ['.text', 'LOAD']

    if not binary:
        searchstr = ' '.join(["%02x" % x for x in asByteArray(searchstr)])

    
    searchstr = searchstr.lower().strip().replace('??', '?').replace('?', '??').rstrip(' ?')
    if not re.match(r'([0-9a-f][0-9a-f] |\?\? )+([0-9a-f][0-9a-f])$', searchstr):
        print("Invalid binary searchstring: '{}'".format(searchstr))
        return [];

    ea = 0
    results = []

    if start is not None and stop is not None:
        if stop < start:
            stop = stop + start
        ea = ida_search.find_binary(start, stop, searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        while ea < stop:
            skip = False
            r = ea
            if predicate and callable(predicate):
                pr = predicate(r)
                if not pr:
                    skip = True
                elif isinstance(pr, int) and pr > ida_ida.cvar.inf.min_ea:
                    r = pr
            if not skip:
                if iteratee and callable(iteratee):
                    r = iteratee(r)

                results.append(r)

                if limit and len(results) > limit:
                    return results
            #  with MemBatchMode(1):
            ea = ida_search.find_binary(ea, stop, searchstr, 16,
                                        SEARCH_CASE | SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW)

        return results

    seg_names = set()
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        seg_names.add(seg_name)
        if segments != "all" and seg_name not in segments:
            continue
        seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)
        ea = seg_start
        #  with MemBatchMode(1):
        ea = ida_search.find_binary(ea, seg_end, searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        while ea < seg_end:
            skip = False
            r = ea
            if predicate and callable(predicate):
                pr = predicate(r)
                if not pr:
                    skip = True
                elif isinstance(pr, int) and pr > ida_ida.cvar.inf.min_ea:
                    r = pr
            if not skip:
                if iteratee and callable(iteratee):
                    r = iteratee(r)

                results.append(r)
                #  if not predicate or not callable(predicate):
                    #  results.append(ea)
                #  else:
                    #  r = predicate(ea)
                    #  if r and r > 1:
                        #  results.append(r)
                        #  if callable(iteratee):
                            #  iteratee(r)
                    #  elif r:
                        #  results.append(ea)
                        #  if callable(iteratee):
                            #  iteratee(ea)

                if limit and len(results) > limit:
                    return results
            #  with MemBatchMode(1):
            ea = ida_search.find_binary(ea, seg_end, searchstr, 16,
                                        SEARCH_CASE | SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW)
    if not ea:
        print("Warning: No segments matched.  Try: {}".format(", ".join(seg_names)))

    return results

if can_call('_'):
    def get_vtable(name, exact=True, show=False):
        name = name.lower()
        if not exact:
            l = _(idautils.Names()).chain() \
                .filter(lambda x, *a: x[1].startswith('??_7')) \
                .map(lambda x, *a: (x[0], Demangle(x[1], idc.DEMNAM_FIRST))) \
                .filter(lambda x, *a: ~x[1].lower().find(name)) \
                .sortBy(lambda x, *a: len(x[1])) \
                .value()
        else:
            l = _(idautils.Names()).chain() \
                .filter(lambda x, *a: x[1].startswith('??_7')) \
                .map(lambda x, *a: (x[0], Demangle(x[1], DEMNAM_FIRST))) \
                .filter(lambda x, *a: x[1].lower().find(name + "::`vftable'") == 0) \
                .sortBy(lambda x, *a: len(x[1])) \
                .value()
        #  l = [y for y in Names() if y[1].find(name + "::`vftable'") > -1]
        ll = len(l)
        if ll == 0:
            return
        if show and can_call('_'):
            return _.map(l, lambda x, *a: (hex(x[0]), x[1]))
        if ll == 1:
            return l[0][0]
        if ll > 1 and can_call('_'):
            return _.map(l, lambda x, *a: x[0])
        else:
            return [x[0] for x in l]


def get_vfunction(rtti, number):
    """
    get_vfunction(rtti_type_name, vfunction_number)

    Note: calculated as LocByName(decorated_rtti) + number * 8
    -- sfinktah
    """

    # Qword(LocByName("??_7CAdminInvite@@6B@") + 3 * 8
    loc = LocByName("??_7" + rtti + "@@6B@")
    if loc < BADADDR:
        return Qword(loc + number * 8)
    else:
        return BADADDR

class __(object):
    """
    Use this class to alter __repr__ of
    mem object. So when you are using
    it on your project it will make sense
    """

    def __init__(self, repr, func):
        self._repr = repr
        self._func = func
        functools.update_wrapper(self, func)

    def __call__(self, *args, **kw):
        return self._func(*args, **kw)

    def __repr__(self):
        return self._repr(self._func)


def u_withrepr(reprfun):
    """ Decorator to rename a function
    """

    def _wrap(func):
        return __(reprfun, func)

    return _wrap


@u_withrepr(lambda x: "<MemBrick Object>")
def mb(pattern, limit=1, index=0):
    """
    mb function, which creates an instance of the mem object,
    We will also assign all methods of the mem class as a method
    to this function so that it will be usable as a static object
    """
    if isinstance(pattern, (int, long_type)) or 'membrick' in str(type(pattern)):
        return membrick_memo(pattern).chain()
    if isinstance(pattern, str):
        #  base = idaapi.cvar.inf.minEA
        #  ptr = idc.FindBinary(base, idc.SEARCH_DOWN | idc.SEARCH_CASE, pattern)
        if not limit:
            limit = 0
        results = FindInSegments(pattern, limit=limit + 1)
        if limit and len(results) != limit:
            # print("Incorrect result count ({}) search for \"{}\"".format(len(results), pattern))
            error = membrick_memo(None, pattern).chain()
            error.errored = True
            return error

        return membrick_memo(results[index], pattern).chain()
    if isinstance(pattern, list):
        for ea in pattern:
            # dprint("[find] ea")
            print("[mem instance] ea:{:x}".format(ea))
            m = membrick_memo(ea).chain().find(pattern, length=length)
            if not m.in_error():
                print("[find] [found]: {:x}".format(m.ea))
                return m


def mem(*args, **kwargs):
    return mb(*args, **kwargs)


def ProtectPattern(*args, **kwargs):
    return mb(*args, **kwargs)


def ProtectScan(*args, **kwargs):
    return mb(*args, **kwargs)

def pattern(*args, **kwargs):
    return mb(*args, **kwargs)

def get_pattern(pattern, offset=0):
    return mb(pattern).add(offset)

def get_call(ptr):
    return ptr.get_call()

def hook__get_call(*args, **kwargs):
    return get_call(*args, **kwargs)

def hook__jump(ptr, label=None):
    return ptr.label('fivem_' + label.replace('fivem_', ''))

def hook__get_address(address, offsetTo4ByteAddr=None, numBytesInLine=None):
    if offsetTo4ByteAddr or numBytesInLine:
        raise RuntimeError('unsupported: 3 parameter hook::get_address')
    return address.rip(4)

hook__call = hook__jump

def hook__get_pattern(*args, **kwargs):
    return get_pattern(*args, **kwargs)

def hook__pattern(*args, **kwargs):
    return pattern(*args, **kwargs)

class membrick_memo(object):
    """
    Instead of creating a class named mb (mem) I created mem
    So I can use mb function both statically and dynamically just it
    is in the original mem
    """

    original_object = None
    object = None
    """ Passed object
    """
    results = []

    VERSION = "0.0.1"

    errored = False

    chained = False
    """ If the object is in a chained state or not
    """

    Null = "__Null__"
    """
    Since we are working with the native types
    I can't compare anything with None, so I use a Substitute type for checking
    """

    _wrapped = Null
    """
    When object is in chained state, This property will contain the latest
    processed Value of passed object, I assign it no Null so I can check
    against None results
    """

    def __init__(self, obj, pattern=None):
        """ Let there be light
        """
        self.chained = False
        self.errored = False
        self.errors = []
        # self.object = getattr(obj, 'obj') if 'membrick_memo' in str(type(obj)) else obj
        #  print('obj: {}: {}'.format(type(obj), obj))
        self.object = getattr(obj, 'obj') if hasattr(obj, 'obj') else obj
        #  print('self.object: {}'.format(self.object))
        self.pattern = pattern
        self.original_object = obj

        class Namespace(object):
            """ For simulating full closure support
            """
            pass

        self.Namespace = Namespace

    def __nonzero__(self):
        return self.valid()

    def __bool__(self):
        return self.valid()

    def __add__(self, offset):
        return self.add(offset)

    def __sub__(self, offset):
        return self.add(-offset)

    def __str__(self):
        if self.obj is None:
            return "(error)"
        return hex(self.obj)

    def __repr__(self):
        if self.chained is True:
            return ("<MemBrick chained instance %s>" % hex(self.obj))
        else:
            return ("<MemBrick instance %s>" % hex(self.obj))

    @property
    def obj(self):
        """
        Returns passed object but if chain method is used
        returns the last processed result
        """
        if self._wrapped is not self.Null:
            return self._wrapped
        else:
            return self.object

    @obj.setter
    def obj(self, value):
        """ New style classes requires setters for @property methods
        """
        self.object = value
        return self.object

    def _wrap(self, ret):
        """
        Returns result but if chain method is used
        returns the object itself so we can chain
        """
        if self.chained:
            self._wrapped = ret
            return self
        else:
            return ret

    @property
    def _clean(self):
        """
        creates a new instance for Internal use to prevent problems
        caused by chaining
        """
        return membrick_memo(self.obj, self.pattern)

    def print_error(self, reason):
        print("[membrick::error] {}".format(reason))

    def error_return_chained(self, reason=None):
        if reason:
            self.errored = True;
            self.print_error(reason)
            self.errors.append(reason)
        return self

    def error_return(self, reason=None):
        if reason:
            self.print_error(reason)
            self.errors.append(reason)
        return not self.errored

    def in_error(self):
        if self.errored:
            return True
            #  print("in_error")
        return self.errored

    def valid(self):
        base = ida_ida.cvar.inf.min_ea
        end = ida_ida.cvar.inf.max_ea
        if self.in_error():
            return False
        if type(self.obj) != type(base):
            return False
        return base <= self.obj < end

    def clone(self):
        return copy.deepcopy(self)

    """
    Pointer Math Functions
    """

    def add(self, value):
        if self.in_error(): return self.error_return_chained()
        #  if self._clean.obj & 0xf000000000000000:
        #  self.errored = True
        #  return self.error_return()

        """ Increment pointer
        """
        cloned = self.clone()
        cloned.obj += value
        return cloned

        return self._wrap(self._clean.obj + value)

    def sub(self, value):
        return self.add(-value)

    def offset(self, value):
        """ alias for add
        """
        return self.add(value)

    def find(self, pattern, length=None):
        if self.in_error(): return self.error_return_chained()
        if isinstance(self.obj, list):
            for ea in self.obj:
                # dprint("[find] ea")
                print("[find] ea:{:x}".format(ea))
                m = membrick_memo(ea).chain().find(pattern, length=length)
                if not m.in_error():
                    print("[find] [found]: {:x}".format(m.ea))
                    return m

            return self.error_return_chained("unable to find sub-pattern")
        if length is None:
            seg_end = idc.get_segm_attr(self.obj, idc.SEGATTR_END)
            length = seg_end - self.obj
        addrs = FindInSegments(pattern, start=self.obj, stop=self.obj + length, limit=1)
        if addrs:
            cloned = self.clone()
            cloned.obj = addrs[0]
            return cloned
        else:
            return self.error_return_chained("unable to find sub-pattern")

    def is_match(self, pattern, bytelen=64, flags=0):
        if self.in_error(): return self.error_return_chained()
        if re.match(pattern, listAsHex(ida_bytes.get_bytes(self.obj, bytelen))):
            return self
        return self.error_return_chained("match failed")

    def rip(self, offset=4):
        """ Dereference pointer
        """
        if self.in_error(): return self.error_return_chained()
        try:
            return self.add(offset + MakeSigned(idc.get_wide_dword(self._clean.obj), 32))
        except TypeError:
            self.errored = True;
            return self.error_return_chained()

    def get_call(self):
        """ fivem_compat: add(1).rip(4) """
        return self.add(1).rip(4)

    def get_jump(self):
        return self._wrap(GetJumpTarget(self.obj))

    def get_autorips(self):
        if self.in_error(): return self.error_return()
        pos = 0
        found = -1
        results = []
        if self.pattern is None:
            return self.error_return("self.pattern is None")

        while True:
            if found > -1:
                pos += 11
            pos = self.pattern.find("?? ?? ?? ??", pos);
            if pos == -1:
                return results
            results.append(pos // 3)
            found += 1


    def autorip(self, index):
        if self.in_error(): return self.error_return_chained()
        pos = 0
        found = -1
        if self.pattern is None:
            return self.error_return_chained("self.pattern is None")

        while found < index:
            if found > -1:
                pos += 11
            pos = self.pattern.find("?? ?? ?? ??", pos);
            if pos == -1:
                return self.error_return_chained("?? ?? ?? ?? x {} not found".format(index))
            found += 1

        if debug: print(".add({}).rip(4)".format(pos // 3))
        return self.add(pos // 3).rip(4)

    def count(self, num, name=''):
        return self
        results = FindInSegments(self.original_object)
        if len(results) != num:
            return self.error_return("pattern({}) [{}] found {} times instead of {}".format(self.original_object, name, len(results), num))
        self.results = results
        return self

    def get(self, num):
        return self.add(num)
        if self.in_error(): return self.error_return_chained()
        if num < len(self.results):
            return self._wrap(self.results[num])
        else:
            return self.error_return("result {} not found ({} results exist)".format(num, len(self.results)))

    #  ti = idaapi.tinfo_t()
    #  ti.deserialize(None, t[0], t[1])
    def type(self, type=False):
        if self.in_error():
            return self.error_return()
        if type == False:
            return idc.get_type(self.val())
        if not type:
            return self
        #  if not IsHead(self.val()):
            #  return self.error_return_chained("cannot set type on non-head at 0x{:x}".format(self.val()))
        #  if IsCode(self.val()):
            #  return self.error_return_chained("cannot set type on non-func-head code at 0x{:x}".format(self.val()))
        #  if not IsFuncHead(self.val()) and not IsData(self.val()):
            #  return self.error_return_chained("cannot set type on non-data and non-func-head at 0x{:x}".format(self.val()))
        e = "invalid type for {:x} of {}".format(self.val(), type)
        r = idc.SetType(self.val(), type)
        if r is None:
            if '(' in type:
                if idc.SetType(self.val(), type.replace('(', ' mbfunc(')):
                    print("[membrick::info] set type of {:x} to {} by adding 'mbfunc' before '('".format(self.val(), type))
                else:
                    print("[memberick::warn] " + e)
                    return self.error_return_chained(e)
            else:
                print("[memberick::warn] " + e)
                return self.error_return_chained(e)
        elif r is False:
            print("[memberick::warn] " + e)
            return self.error_return_chained(e)
        return self

    def dword(self):
        if self.in_error():
            return self.error_return()
        return idc.get_wide_dword(self.obj)

    def As(self, type):
        if self.in_error():
            return self.error_return()
        if not type:
            return self
        self._as = type
        return self

    def typeinfo(self, _type=False):
        if self.in_error(): return self.error_return_chained()
        if not _type:
            return idc.get_tinfo(self.val())
        while isStringish(_type):
            _type = json.loads(_type)
        if not idc.apply_type(self.val(), _type):
            print("type({}) error setting type at '0x{:x}'".format(_type, self.val()))
        return self

    def tinfo(self, _type=False):
        if self.in_error(): return self.error_return_chained()
        if not _type:
            t = idc.get_tinfo(self.val())
            ti = idaapi.tinfo_t()
            if ti.deserialize(None, t[0], t[1]):
                return ti
            else:
                return False
        return self

    def mnem(self, force=0):
        if self.in_error(): return self.error_return_chained()
        if IsCode_(self.eax()) or force:
            return idc.print_insn_mnem(self.eax())
        return ''

    def is_mnem(self, mnem, force=0):
        if self.in_error(): return self.error_return_chained()
        if IsCode_(idc.get_item_head(self.eax())) or force:
            actual_mnem = idc.print_insn_mnem(idc.get_item_head(self.eax()))
            if actual_mnem == mnem:
                return self
            print("mnem mismatch: wanted:{} found:{}".format(mnem, actual_mnem))
        else:
            print("mnem loc invalid: {:x}".format(self.eax()))

        self.errored = True;
        return self.error_return_chained()

    def name(self, name=None, force=1):
        if self.in_error(): return self.error_return_chained()
        if name is None:
            return get_name_by_any(self.val())
        if not force and HasUserName(self.val()):
            return self
        if not idc.set_name(self.val(), name, idc.SN_NOWARN):
            print("name({}) error setting name at '0x{:x}' (currently {})".format(name, self.val(),
                                                                                  GetTrueName(self.val())))
        return self

    def label(self, name=None):
        if name is None:
            return get_name_by_any(self.val())
        if self.in_error(): return self.error_return_chained()
        MemLabelAddressPlus(self.val(), name)
        return self
    
    def add_tag(self, name):
        if self.in_error(): return self.error_return_chained()
        TagAddress(self.val(), name)
        return self

    def remove_tag(self, name):
        if self.in_error(): return self.error_return_chained()
        TagAddress(self.val(), name, remove=1)
        return self



    def deref(self):
        if self.in_error(): return self.error_return_chained()
        """ Dereference pointer
        """
        return self._wrap(idc.get_qword(self.val()))

    def val(self, T=long_type):
        if self.in_error(): return self.error_return()
        """ returns the object instead of instance
        """
        if self._wrapped is not self.Null:
            return T(self._wrapped)
        else:
            return T(self.obj)

    @property
    def ea(self):
        """
        returns self.obj
        """
        if self.in_error():
            return None
        return self.obj
    
    @ea.setter
    def ea(self, value):
        """ New style classes requires setters for @property methods
        """
        self.obj = value
        return self.obj
    
    def eax(self, T=long_type):
        """ returns the object instead of instance
        """
        if self.in_error(): return self.error_return_chained()
        if self._wrapped is not self.Null:
            return T(eax(self._wrapped))
        else:
            return T(eax(self.obj))


    def hex(self, T=long_type):
        """ returns the object in hex
        """
        if self.in_error(): return self.error_return()
        return hex(self.val(T))

    def get_strlit_contents(ea, length = -1, strtype = STRTYPE_C):
        if length == -1:
            length = ida_bytes.get_max_strlit_length(ea, strtype, ida_bytes.ALOPT_IGNHEADS)

        return ida_bytes.get_strlit_contents(ea, length, strtype)

    def str(self, length=-1, strtype = idc.STRTYPE_C):
        """
        Get string contents
        @param length: string length. -1 means to calculate the max string length
        @param strtype: the string type (one of STRTYPE_... constants)

        @return: string contents or empty string
        """
        if self.in_error(): return self.error_return()
        return idc.get_strlit_contents(self.val(), length, strtype)

    def dec(self, T=long_type):
        if self.in_error(): return self.error_return()
        """ returns the object in dec
        """
        return self.val(T)

    def jump(self):
        if self.in_error(): return self.error_return()
        idc.jumpto(self._clean.obj)

    """ Support functions
    """

    def chain(self):
        """ Add a "chain" function, which will delegate to the wrapper.
        """
        self.chained = True
        return self

    def value(self):
        """ returns the object instead of instance
        """
        if self.in_error(): return self.error_return()
        if self._wrapped is not self.Null:
            return self._wrapped
        else:
            return self.obj

    @staticmethod
    def makeStatic():
        """ Provide static access to mem class
        """
        for eachMethod in inspect.getmembers(membrick_memo,
                                             predicate=lambda value: inspect.ismethod(value) or
                                                                     inspect.isfunction(value)):
            m = eachMethod[0]
            if not hasattr(mb, m):
                def caller(a):
                    def execute(*args):
                        if len(args) == 1:
                            r = getattr(membrick_memo(args[0]), a)()
                        elif len(args) > 1:
                            rargs = args[1:]
                            r = getattr(membrick_memo(args[0]), a)(*rargs)
                        else:
                            r = getattr(membrick_memo([]), a)()
                        return r

                    return execute

                mb.__setattr__(m, caller(m))
        # put the class itself as a parameter so that we can use it on outside
        mb.__setattr__("membrick_memo", membrick_memo)
        mb.templateSettings = {}


# Imediatelly create static object
membrick_memo.makeStatic()

# The end
#
"""
.text:00000001438655C0 0B8 48 8B 45 70                                   mov     rax, [rbp+70h]
.text:00000001438655C4 0B8 48 03 05 EF BF E2 00                          add     rax, cs:qword_1446915BA ; 32
.text:00000001438655CB 0B8 48 8B 15 00 EB 8D 00                          mov     rdx, cs:off_1441440D2
.text:00000001438655D2 0B8 48 89 94 C5 A0 00 00 00                       mov     [rbp+rax*8+90h+_arg_0], rdx
.text:00000001438655DA 0B8 48 8B 45 70                                   mov     rax, [rbp+70h]
.text:00000001438655DE 0B8 48 03 05 02 41 1F FD                          add     rax, cs:qword_140A596E7 ; 31
.text:00000001438655E5 0B8 48 8B 15 12 C2 90 00                          mov     rdx, cs:off_1441717FE
.text:00000001438655EC 0B8 48 89 94 C5 A0 00 00 00                       mov     [rbp+rax*8+0A0h], rdx
.text:00000001438655F4 0B8 48 8B 45 70                                   mov     rax, [rbp+70h]
.text:00000001438655F8 0B8 48 03 05 E8 98 8C 00                          add     rax, cs:qword_14412EEE7 ; 30
.text:00000001438655FF 0B8 48 8B 15 70 C1 49 FD                          mov     rdx, cs:off_140D01776
.text:0000000143865606 0B8 48 89 94 C5 A0 00 00 00                       mov     [rbp+rax*8+0A0h], rdx
[
 48 8b 45 ?? 48 03 05 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 48 89 94 c5 ?? ?? 00 00
         ^^same      ^^ offset            ^^ location             ^^ same
'48 8b 45 ??', '48 03 05 ?? ?? ?? ??', '48 8b 15 ?? ?? ?? ??', '48 89 94 c5 ?? ?? 00 00',
'48 8b 45 ??', '48 03 05 ?? ?? ?? ??', '48 8b 15 ?? ?? ?? ??', '48 89 94 c5 ?? ?? 00 00',
]
"""

def find_rssig(game_version, bonus_type, ValueHash, HashSize, FirstByte, StartPage, EndPage, RegionSizeKB, Flags, Protect):
    def pred_rssig(ea):
        return joaat_memory(ea, HashSize) == ValueHash
    r = FindInSegments("%02x" % FirstByte, "all", predicate=pred_rssig)
    print(r)

def rssign():
    find_rssig(0x8c5, 0x8, 0xf445dc47, 0xb, 0xc7, 0x149000, 0x211000, 0x0, 0x20, 0x40)
    find_rssig(0x8c5, 0x8, 0xe9542016, 0xe, 0x5c, 0xa0f000, 0xad7000, 0x0, 0x20, 0x40)
    find_rssig(0x8c5, 0x8, 0xb19f1386, 0x1a, 0xb9, 0x1883000, 0x194b000, 0x0, 0x20, 0x40)
    find_rssig(0x8c5, 0x8, 0x5f492461, 0x13, 0x40, 0x149000, 0x211000, 0x0, 0x20, 0x40)
    find_rssig(0x8c5, 0x8, 0x2f37bb8, 0x11, 0x8b, 0x1264000, 0x132c000, 0x0, 0x20, 0x40)
    #  find_rssig(0x8c5, 0x7, 0xffba83ca, 0x1c, 0x5c, 0x0, 0xf000, 0x3a6000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xfba74c4a, 0x9, 0x47, 0xa000, 0x14000, 0x23000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xf790b12c, 0x9, 0x53, 0x0, 0xa000, 0x6a000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xf75a7efb, 0xf, 0x4e, 0x32000, 0x3c000, 0x42000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xf542b2d5, 0xe, 0x46, 0x45000, 0x51000, 0x57000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xf34150dd, 0x9, 0x43, 0x19000, 0x23000, 0x53000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xf04b3f6d, 0xa, 0x43, 0x1a000, 0x24000, 0x28000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xed43309, 0xd, 0x69, 0x12000, 0x1c000, 0x1e000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xe7ba8bb9, 0x9, 0x4c, 0x1c000, 0x26000, 0x4f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xe71d3b38, 0xa, 0x50, 0xa000, 0x14000, 0x4f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xe5f21a1a, 0xe, 0x56, 0x2a000, 0x34000, 0x79000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xe5c404ec, 0xd, 0x5a, 0x41000, 0x4b000, 0x76000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xd661f686, 0x11, 0x5a, 0x65000, 0x6f000, 0x79000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xd6432ac0, 0x11, 0x42, 0x4a000, 0x54000, 0x5f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xd60b7f07, 0x9, 0x48, 0x6000, 0x10000, 0x28000, 0x20, 0x40)
    #  find_rssig(0x8c5, 0x7, 0xcb5221fe, 0x7, 0x53, 0xa000, 0x14000, 0x3f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xbb93349, 0x10, 0x56, 0x0, 0x9000, 0x79000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xb9404fc8, 0x13, 0x54, 0x13000, 0x1d000, 0x4d000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xb54149d4, 0xa, 0x4f, 0x2f000, 0x43000, 0xa4000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xa9b9688d, 0x8, 0x48, 0x1000, 0xb000, 0x4e000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xa79591b8, 0xc, 0x46, 0x45000, 0x4f000, 0x57000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xa12bb456, 0xd, 0x4f, 0x2e000, 0x42000, 0xa4000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0xa0cfdfe6, 0xd, 0x70, 0x0, 0xb000, 0x67000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x9ebd06d5, 0xe, 0x4c, 0x0, 0xa000, 0x27000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x9d64e7ff, 0xa, 0x45, 0x9000, 0x13000, 0x4b000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x9c519db7, 0x2e, 0x39, 0x94000, 0x9e000, 0xe3000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x9bd91cf5, 0x8, 0x46, 0x8000, 0x12000, 0x32000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x97cbf1d6, 0xa, 0x52, 0x48000, 0x52000, 0x57000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x9674a72e, 0x12, 0x5a, 0x65000, 0x6f000, 0x79000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x95bb6fde, 0x8, 0x76, 0x13000, 0x1d000, 0x4f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x94708d43, 0x13, 0x5a, 0x50000, 0x5a000, 0x60000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x943b1914, 0xa, 0x50, 0x0, 0xd000, 0x269000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x94271870, 0x14, 0x53, 0x0, 0x9000, 0x7b000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x93764d7, 0xc, 0x53, 0xa000, 0x19000, 0x3f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x8ec4b88d, 0x6, 0x56, 0x947000, 0x951000, 0x95b000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x8e25e5d1, 0xe, 0x0, 0xa000, 0x14000, 0x3d000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x87a746d6, 0x8, 0x4d, 0x68000, 0x72000, 0xe9000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x858aa8a4, 0x9, 0x4d, 0xf000, 0x19000, 0x1a000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x84f973aa, 0x10, 0x25, 0x17000, 0x2b000, 0x1a1000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x82bee313, 0xb, 0x4d, 0x98000, 0xa2000, 0xa1000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x7e87b84d, 0xb, 0x5a, 0x9000, 0x13000, 0x35000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x7cf8adf6, 0x12, 0x35, 0x0, 0x9000, 0x7b000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x7b83e0fc, 0x8, 0x4c, 0x4000, 0xe000, 0x39000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x700101a1, 0xe, 0x31, 0x95000, 0x9f000, 0xe4000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x66dd632a, 0xb, 0x58, 0x1c000, 0x26000, 0x4f000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x61499ef7, 0xa, 0x43, 0x12000, 0x1c000, 0x1d000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x5f6520df, 0xb, 0x45, 0x9000, 0x13000, 0x4d000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x5e7240ab, 0xc, 0x5a, 0x28000, 0x32000, 0x62000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x595411d7, 0xe, 0x4e, 0x6000, 0x10000, 0x43000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x5488b355, 0xa, 0x48, 0x6000, 0x10000, 0x28000, 0x10, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x451c11e5, 0xd, 0x49, 0x1b000, 0x2f000, 0x1a2000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x3998a8c1, 0xd, 0x50, 0x8e000, 0xa2000, 0x1f8000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x36115f91, 0x12, 0x5a, 0x50000, 0x5a000, 0x60000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x34e68c60, 0x7, 0x47, 0xa000, 0x14000, 0x34000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x33be6767, 0xc, 0x53, 0x14000, 0x1e000, 0x21000, 0x20, 0x40)
    #  find_rssig(0x8c5, 0x7, 0x33625cf5, 0x6, 0x47, 0xa000, 0x14000, 0x35000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x2cb574f9, 0xe, 0x42, 0x65000, 0x6f000, 0x79000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x286c39ed, 0x12, 0x70, 0x4d000, 0x63000, 0x268000, 0x20, 0x2)
    #  find_rssig(0x8c5, 0x7, 0x21c9096, 0xb, 0x4d, 0xe000, 0x18000, 0x19000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x8, 0xcfda8fcd, 0x1b, 0xb9, 0x1873000, 0x193b000, 0x0, 0x20, 0x40)
    #  find_rssig(0x8a7, 0x7, 0xfdc80995, 0xa, 0x63, 0xb000, 0x15000, 0x50c00, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xf3e475fe, 0x7, 0x73, 0x55000, 0x5f000, 0x81000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xf017b223, 0x12, 0x69, 0xe000, 0x18000, 0x1e000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xe61dab46, 0x7, 0x6b, 0x7000, 0x11000, 0x20000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xdb63b090, 0xd, 0x48, 0x20000, 0x2a000, 0x4e000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xcd16115d, 0xc, 0x44, 0x6000, 0x10000, 0x3d000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xc20e6aeb, 0x14, 0x65, 0x5c000, 0x66000, 0x7b000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xbb2ee2dd, 0xe, 0x70, 0x0, 0xa000, 0x69000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xac5f40f6, 0x10, 0x68, 0x10000, 0x24000, 0x1a5800, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0xa400d842, 0x16, 0x50, 0x0, 0x10000, 0x26a000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x95b7b9d5, 0xb, 0x47, 0x68000, 0x72000, 0x81000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x89546c4, 0xb, 0x43, 0xb000, 0x15000, 0x2a000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x7fce709e, 0xe, 0x57, 0x7000, 0x11000, 0x26000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x7943a5df, 0x8, 0x53, 0x5000, 0xf000, 0x3d000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x787c6854, 0x11, 0x4d, 0xfc000, 0x106000, 0x1c1000, 0x20, 0x40)
    #  find_rssig(0x8a7, 0x7, 0x74b479e6, 0x12, 0x4f, 0x2e000, 0x42000, 0xa4000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x6fe0f1fd, 0x8, 0x41, 0x65000, 0x6f000, 0xa4000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x6e675166, 0xe, 0x22, 0x1aa000, 0x1b4000, 0x1fa000, 0x20, 0x40)
    #  find_rssig(0x8a7, 0x7, 0x5f8b4ec1, 0xb, 0x53, 0x6f000, 0x79000, 0x88000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x5c73172d, 0xd, 0x42, 0x0, 0xf000, 0x68000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x5adcc6ce, 0xd, 0x44, 0x30c000, 0x352000, 0x3d8000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x530e31b7, 0x12, 0x20, 0x6000, 0x10000, 0x23000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x506d4f84, 0xd, 0x41, 0xbb000, 0xc5000, 0xcc000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x500e0a1d, 0x7, 0x41, 0x65000, 0x6f000, 0xa4000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x4f1f42d7, 0x11, 0x50, 0x4000, 0xe000, 0x20000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x3af2d462, 0x8, 0x69, 0x19000, 0x23000, 0x21000, 0x20, 0x4)
    #  find_rssig(0x8a7, 0x7, 0x354009b8, 0x16, 0x6a, 0x141000, 0x14b000, 0x203000, 0x20, 0x40)
    #  find_rssig(0x8a7, 0x7, 0x33706c98, 0x9, 0x45, 0x9000, 0x13000, 0x4c000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x2aeb961b, 0xe, 0x49, 0x10000, 0x24000, 0x1a7c00, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x279c553e, 0xc, 0x47, 0x32000, 0x3c000, 0x3d000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x247936ae, 0xd, 0x56, 0x16000, 0x20000, 0x52000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x1d7e9754, 0x9, 0x4c, 0x4000, 0xe000, 0x37000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x1bd41152, 0x8, 0x43, 0x4a000, 0x54000, 0x53000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x19c101eb, 0xf, 0x7e, 0x71000, 0x8f000, 0x1cd000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x18f1567c, 0x11, 0x50, 0x4000, 0xe000, 0x20000, 0x20, 0x2)
    #  find_rssig(0x8a7, 0x7, 0x134f6e1a, 0xc, 0x53, 0x6f000, 0x79000, 0x88000, 0x20, 0x2)


#  chart2=[]
#  colors=[]
#  # for st in "platformName password email nickname".split(" "):
#  # for st in "Age CloudKey CountryCode Email LanguageCode MFAEnabled Minor Nickname PlayerAccountId PosixTime Privileges PublicIp Response RockstarAccount RockstarId SecsUntilExpiration Services SessionId SessionKey SessionTicket Status Ticket UpdatePassword".split(" "):
#  # for st in "platformName password email nickname".split(" "):
#  #  audience ttlminutes userdata rememberedMachineToken rememberMe keepMeSignedIn
#  tmp = []
#  for st in "Age CloudKey CountryCode Email LanguageCode MFAEnabled Minor PlayerAccountId PosixTime Privileges PublicIp Response RockstarAccount SecsUntilExpiration Services SessionId SessionKey SessionTicket Status Ticket UpdatePassword".split(" "):
    #  tmp.extend( FindInSegments(st, segments='.rdata', binary=0, predicate=lambda x: IsStrlit(x) and GetString(x) == asBytesRaw(st), iteratee=lambda x: RecurseCallersChart(x, exe=None)) )
#  RecurseCallersChart(tmp[0], exe='dot')
#  
# [0x2d2ba20, 0x2d2ba50, 0x2d2ba70, 0x2d2ba90, 0x2d2bab0, 0x2d2bad0, 0x2d2baf0, 0x2d2bb10, 0x2d2bb20, 0x2d2bb40, 0x2d2bb80, 0x2d2bb60, 0x2d2bbc0, 0x2d2bba0, 0x2d2bbe0, 0x2d2bc10, 0x2d2bc40, 0x2d2bc70, 0x2d2bca0, 0x2d2bcf0, 0x2d2bd10, 0x2d2bd40, 0x2d2bda0, 0x2d2bd70, 0x2d2be00, 0x2d2bdd0, 0x2d2be30, 0x2d2be80, 0x2d2bed0, 0x2d2bf20, 0x2d2bf90, 0x2d2bfb0, 0x2d2bfd0, 0x2d2bff0, 0x2d2c010, 0x2d2c030, 0x2d2c050, 0x2d2c070, 0x2d2c090, 0x2d2c0c0, 0x2d2c0f0, 0x2d2c0f0, 0x2d2c110, 0x2d2c130, 0x2d2c140, 0x2d2c2b0, 0x2d2c3e0, 0x2d2c520, 0x2d2c540, 0x2d2c560, 0x2d2c580, 0x2d2c6c0, 0x2d2c750, 0x2d2c7b0, 0x2d2c7e0, 0x2d2c810, 0x2d2c830, 0x2d2c850, 0x2d2c870, 0x2d2c890, 0x2d2c8b0, 0x2d2c8d0, 0x2d2c8f0, 0x2d2c910, 0x2d2c930, 0x2d2c950, 0x2d2c970, 0x2d2c9a0, 0x2d2c9c0, 0x2d2c9e0, 0x2d2ca00, 0x2d2ca20, 0x2d2ca40, 0x2d2ca70, 0x2d2cab0, 0x2d2caf0, 0x2d2cb30, 0x2d2cb60, 0x2d2cb90, 0x2d2cbb0, 0x2d2cbd0, 0x2d2cbf0, 0x2d2cc10, 0x2d2cc40, 0x2d2cc70, 0x2d2ce20, 0x2d2ce60, 0x2d2cee0, 0x2d2cf30, 0x2d2cfd0, 0x2d2cf80, 0x2d2d070, 0x2d2d020, 0x2d2cdd0, 0x2d2cca0, 0x2d2cd20, 0x2d2cd60, 0x2d2cdb0, 0x2d2d120, 0x2d2d1b0, 0x2d2dbc0, 0x2d2d1f0, 0x2d2d250, 0x2d2d470, 0x2d2d500, 0x2d2d7c0, 0x2d2d8a0, 0x2d2d8f0, 0x2d2d940, 0x2d2d980, 0x2d2d9a0, 0x2d2d9c0, 0x2d2d9e0, 0x2d2da00, 0x2d2da20, 0x2d2da40, 0x2d2da60, 0x2d2da80, 0x2d2daa0, 0x2d2dac0, 0x2d2dae0, 0x2d2db00, 0x2d2db20, 0x2d2db40, 0x2d2db60, 0x2d2db80, 0x2d2dba0, 0x2d2dc70, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0]
# [0x2d2b9bc, 0x2d2ba46, 0x2d2ba63, 0x2d2ba83, 0x2d2baa8, 0x2d2bacc, 0x2d2baec, 0x2d2bb04, 0x2d2bb1b, 0x2d2bb3c, 0x2d2bb5c, 0x2d2bb7c, 0x2d2bb9c, 0x2d2bbbc, 0x2d2bbdc, 0x2d2bbfd, 0x2d2bc2d, 0x2d2bc5d, 0x2d2bc95, 0x2d2bce1, 0x2d2bcfd, 0x2d2bd33, 0x2d2bd63, 0x2d2bd90, 0x2d2bdc0, 0x2d2bdf0, 0x2d2be20, 0x2d2be71, 0x2d2bec1, 0x2d2bf11, 0x2d2bf7f, 0x2d2bfa7, 0x2d2bfc3, 0x2d2bfe3, 0x2d2c003, 0x2d2c025, 0x2d2c043, 0x2d2c06a, 0x2d2c086, 0x2d2c0b2, 0x2d2c0eb, 0x2d2c105, 0x2d2c126, 0x2d2c13c, 0x2d2c2a9, 0x2d2c3a5, 0x2d2c519, 0x2d2c534, 0x2d2c559, 0x2d2c579, 0x2d2c62f, 0x2d2c74c, 0x2d2c779, 0x2d2c7d9, 0x2d2c80a, 0x2d2c82a, 0x2d2c84a, 0x2d2c869, 0x2d2c88a, 0x2d2c8aa, 0x2d2c8c9, 0x2d2c8e4, 0x2d2c908, 0x2d2c92a, 0x2d2c948, 0x2d2c96b, 0x2d2c990, 0x2d2c9b6, 0x2d2c9d4, 0x2d2c9f8, 0x2d2ca18, 0x2d2ca3b, 0x2d2ca60, 0x2d2ca9d, 0x2d2cadd, 0x2d2cb1e, 0x2d2cb4d, 0x2d2cb7d, 0x2d2cbac, 0x2d2cbca, 0x2d2cbea, 0x2d2cc09, 0x2d2cc31, 0x2d2cc61, 0x2d2cc90, 0x2d2ccd9, 0x2d2cd59, 0x2d2cd9d, 0x2d2cdc8, 0x2d2ce0d, 0x2d2ce53, 0x2d2cea0, 0x2d2ced5, 0x2d2cf25, 0x2d2cf75, 0x2d2cfc5, 0x2d2d015, 0x2d2d065, 0x2d2d0b5, 0x2d2d10d, 0x2d2d1a1, 0x2d2d1dd, 0x2d2d232, 0x2d2d245, 0x2d2d44b, 0x2d2d466, 0x2d2d4e2, 0x2d2d4f5, 0x2d2d712, 0x2d2d72e, 0x2d2d74c, 0x2d2d897, 0x2d2d8de, 0x2d2d93a, 0x2d2d97b, 0x2d2d994, 0x2d2d9b4, 0x2d2d9d4, 0x2d2d9f4, 0x2d2da14, 0x2d2da34, 0x2d2da54, 0x2d2da74, 0x2d2da94, 0x2d2dab4, 0x2d2dad4, 0x2d2daf4, 0x2d2db14, 0x2d2db34, 0x2d2db54, 0x2d2db74, 0x2d2db94, 0x2d2dbb4, 0x2d2dc5d, 0x2d2dc93]
#
#  _cases = [0x2d2ba20, 0x2d2ba50, 0x2d2ba70, 0x2d2ba90, 0x2d2bab0, 0x2d2bad0, 0x2d2baf0, 0x2d2bb10, 0x2d2bb20, 0x2d2bb40, 0x2d2bb80, 0x2d2bb60, 0x2d2bbc0, 0x2d2bba0, 0x2d2bbe0, 0x2d2bc10, 0x2d2bc40, 0x2d2bc70, 0x2d2bca0, 0x2d2bcf0, 0x2d2bd10, 0x2d2bd40, 0x2d2bda0, 0x2d2bd70, 0x2d2be00, 0x2d2bdd0, 0x2d2be30, 0x2d2be80, 0x2d2bed0, 0x2d2bf20, 0x2d2bf90, 0x2d2bfb0, 0x2d2bfd0, 0x2d2bff0, 0x2d2c010, 0x2d2c030, 0x2d2c050, 0x2d2c070, 0x2d2c090, 0x2d2c0c0, 0x2d2c0f0, 0x2d2c0f0, 0x2d2c110, 0x2d2c130, 0x2d2c140, 0x2d2c2b0, 0x2d2c3e0, 0x2d2c520, 0x2d2c540, 0x2d2c560, 0x2d2c580, 0x2d2c6c0, 0x2d2c750, 0x2d2c7b0, 0x2d2c7e0, 0x2d2c810, 0x2d2c830, 0x2d2c850, 0x2d2c870, 0x2d2c890, 0x2d2c8b0, 0x2d2c8d0, 0x2d2c8f0, 0x2d2c910, 0x2d2c930, 0x2d2c950, 0x2d2c970, 0x2d2c9a0, 0x2d2c9c0, 0x2d2c9e0, 0x2d2ca00, 0x2d2ca20, 0x2d2ca40, 0x2d2ca70, 0x2d2cab0, 0x2d2caf0, 0x2d2cb30, 0x2d2cb60, 0x2d2cb90, 0x2d2cbb0, 0x2d2cbd0, 0x2d2cbf0, 0x2d2cc10, 0x2d2cc40, 0x2d2cc70, 0x2d2ce20, 0x2d2ce60, 0x2d2cee0, 0x2d2cf30, 0x2d2cfd0, 0x2d2cf80, 0x2d2d070, 0x2d2d020, 0x2d2cdd0, 0x2d2cca0, 0x2d2cd20, 0x2d2cd60, 0x2d2cdb0, 0x2d2d120, 0x2d2d1b0, 0x2d2dbc0, 0x2d2d1f0, 0x2d2d250, 0x2d2d470, 0x2d2d500, 0x2d2d7c0, 0x2d2d8a0, 0x2d2d8f0, 0x2d2d940, 0x2d2d980, 0x2d2d9a0, 0x2d2d9c0, 0x2d2d9e0, 0x2d2da00, 0x2d2da20, 0x2d2da40, 0x2d2da60, 0x2d2da80, 0x2d2daa0, 0x2d2dac0, 0x2d2dae0, 0x2d2db00, 0x2d2db20, 0x2d2db40, 0x2d2db60, 0x2d2db80, 0x2d2dba0, 0x2d2dc70, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0]
#  _case_tails = [0x2d2b9bc, 0x2d2ba46, 0x2d2ba63, 0x2d2ba83, 0x2d2baa8, 0x2d2bacc, 0x2d2baec, 0x2d2bb04, 0x2d2bb1b, 0x2d2bb3c, 0x2d2bb5c, 0x2d2bb7c, 0x2d2bb9c, 0x2d2bbbc, 0x2d2bbdc, 0x2d2bbfd, 0x2d2bc2d, 0x2d2bc5d, 0x2d2bc95, 0x2d2bce1, 0x2d2bcfd, 0x2d2bd33, 0x2d2bd63, 0x2d2bd90, 0x2d2bdc0, 0x2d2bdf0, 0x2d2be20, 0x2d2be71, 0x2d2bec1, 0x2d2bf11, 0x2d2bf7f, 0x2d2bfa7, 0x2d2bfc3, 0x2d2bfe3, 0x2d2c003, 0x2d2c025, 0x2d2c043, 0x2d2c06a, 0x2d2c086, 0x2d2c0b2, 0x2d2c0eb, 0x2d2c105, 0x2d2c126, 0x2d2c13c, 0x2d2c2a9, 0x2d2c3a5, 0x2d2c519, 0x2d2c534, 0x2d2c559, 0x2d2c579, 0x2d2c62f, 0x2d2c74c, 0x2d2c779, 0x2d2c7d9, 0x2d2c80a, 0x2d2c82a, 0x2d2c84a, 0x2d2c869, 0x2d2c88a, 0x2d2c8aa, 0x2d2c8c9, 0x2d2c8e4, 0x2d2c908, 0x2d2c92a, 0x2d2c948, 0x2d2c96b, 0x2d2c990, 0x2d2c9b6, 0x2d2c9d4, 0x2d2c9f8, 0x2d2ca18, 0x2d2ca3b, 0x2d2ca60, 0x2d2ca9d, 0x2d2cadd, 0x2d2cb1e, 0x2d2cb4d, 0x2d2cb7d, 0x2d2cbac, 0x2d2cbca, 0x2d2cbea, 0x2d2cc09, 0x2d2cc31, 0x2d2cc61, 0x2d2cc90, 0x2d2ccd9, 0x2d2cd59, 0x2d2cd9d, 0x2d2cdc8, 0x2d2ce0d, 0x2d2ce53, 0x2d2cea0, 0x2d2ced5, 0x2d2cf25, 0x2d2cf75, 0x2d2cfc5, 0x2d2d015, 0x2d2d065, 0x2d2d0b5, 0x2d2d10d, 0x2d2d1a1, 0x2d2d1dd, 0x2d2d232, 0x2d2d245, 0x2d2d44b, 0x2d2d466, 0x2d2d4e2, 0x2d2d4f5, 0x2d2d712, 0x2d2d72e, 0x2d2d74c, 0x2d2d897, 0x2d2d8de, 0x2d2d93a, 0x2d2d97b, 0x2d2d994, 0x2d2d9b4, 0x2d2d9d4, 0x2d2d9f4, 0x2d2da14, 0x2d2da34, 0x2d2da54, 0x2d2da74, 0x2d2da94, 0x2d2dab4, 0x2d2dad4, 0x2d2daf4, 0x2d2db14, 0x2d2db34, 0x2d2db54, 0x2d2db74, 0x2d2db94, 0x2d2dbb4, 0x2d2dc5d, 0x2d2dc93]
#  _opcodes = "NOP IADD ISUB IMUL IDIV IMOD INOT INEG IEQ INE IGT IGE ILT ILE FADD FSUB FMUL FDIV FMOD FNEG FEQ FNE FGT FGE FLT FLE VADD VSUB VMUL VDIV VNEG IAND IOR IXOR I2F F2I F2V PUSH_CONST_U8 PUSH_CONST_U8_U8 PUSH_CONST_U8_U8_U8 PUSH_CONST_U32 PUSH_CONST_F DUP DROP NATIVE ENTER LEAVE LOAD STORE STORE_REV LOAD_N STORE_N ARRAY_U8 ARRAY_U8_LOAD ARRAY_U8_STORE LOCAL_U8 LOCAL_U8_LOAD LOCAL_U8_STORE STATIC_U8 STATIC_U8_LOAD STATIC_U8_STORE IADD_U8 IMUL_U8 IOFFSET IOFFSET_U8 IOFFSET_U8_LOAD IOFFSET_U8_STORE PUSH_CONST_S16 IADD_S16 IMUL_S16 IOFFSET_S16 IOFFSET_S16_LOAD IOFFSET_S16_STORE ARRAY_U16 ARRAY_U16_LOAD ARRAY_U16_STORE LOCAL_U16 LOCAL_U16_LOAD LOCAL_U16_STORE STATIC_U16 STATIC_U16_LOAD STATIC_U16_STORE GLOBAL_U16 GLOBAL_U16_LOAD GLOBAL_U16_STORE J JZ IEQ_JZ INE_JZ IGT_JZ IGE_JZ ILT_JZ ILE_JZ CALL GLOBAL_U24 GLOBAL_U24_LOAD GLOBAL_U24_STORE PUSH_CONST_U24 SWITCH STRING STRINGHASH TEXT_LABEL_ASSIGN_STRING TEXT_LABEL_ASSIGN_INT TEXT_LABEL_APPEND_STRING TEXT_LABEL_APPEND_INT TEXT_LABEL_COPY CATCH THROW CALLINDIRECT PUSH_CONST_M1 PUSH_CONST_0 PUSH_CONST_1 PUSH_CONST_2 PUSH_CONST_3 PUSH_CONST_4 PUSH_CONST_5 PUSH_CONST_6 PUSH_CONST_7 PUSH_CONST_FM1 PUSH_CONST_F0 PUSH_CONST_F1 PUSH_CONST_F2 PUSH_CONST_F3 PUSH_CONST_F4 PUSH_CONST_F5 PUSH_CONST_F6 PUSH_CONST_F7 BITTEST ERROR".split(" ")
#  for k, v in zip(_cases, _opcodes): idc.set_name(k, "VM_"+v, idc.SN_NOWARN | idc.SN_AUTO)
#
#  _cases = [0x2d2ba20, 0x2d2ba50, 0x2d2ba70, 0x2d2ba90, 0x2d2bab0, 0x2d2bad0, 0x2d2baf0, 0x2d2bb10, 0x2d2bb20, 0x2d2bb40, 0x2d2bb80, 0x2d2bb60, 0x2d2bbc0, 0x2d2bba0, 0x2d2bbe0, 0x2d2bc10, 0x2d2bc40, 0x2d2bc70, 0x2d2bca0, 0x2d2bcf0, 0x2d2bd10, 0x2d2bd40, 0x2d2bda0, 0x2d2bd70, 0x2d2be00, 0x2d2bdd0, 0x2d2be30, 0x2d2be80, 0x2d2bed0, 0x2d2bf20, 0x2d2bf90, 0x2d2bfb0, 0x2d2bfd0, 0x2d2bff0, 0x2d2c010, 0x2d2c030, 0x2d2c050, 0x2d2c070, 0x2d2c090, 0x2d2c0c0, 0x2d2c0f0, 0x2d2c0f0, 0x2d2c110, 0x2d2c130, 0x2d2c140, 0x2d2c2b0, 0x2d2c3e0, 0x2d2c520, 0x2d2c540, 0x2d2c560, 0x2d2c580, 0x2d2c6c0, 0x2d2c750, 0x2d2c7b0, 0x2d2c7e0, 0x2d2c810, 0x2d2c830, 0x2d2c850, 0x2d2c870, 0x2d2c890, 0x2d2c8b0, 0x2d2c8d0, 0x2d2c8f0, 0x2d2c910, 0x2d2c930, 0x2d2c950, 0x2d2c970, 0x2d2c9a0, 0x2d2c9c0, 0x2d2c9e0, 0x2d2ca00, 0x2d2ca20, 0x2d2ca40, 0x2d2ca70, 0x2d2cab0, 0x2d2caf0, 0x2d2cb30, 0x2d2cb60, 0x2d2cb90, 0x2d2cbb0, 0x2d2cbd0, 0x2d2cbf0, 0x2d2cc10, 0x2d2cc40, 0x2d2cc70, 0x2d2ce20, 0x2d2ce60, 0x2d2cee0, 0x2d2cf30, 0x2d2cfd0, 0x2d2cf80, 0x2d2d070, 0x2d2d020, 0x2d2cdd0, 0x2d2cca0, 0x2d2cd20, 0x2d2cd60, 0x2d2cdb0, 0x2d2d120, 0x2d2d1b0, 0x2d2dbc0, 0x2d2d1f0, 0x2d2d250, 0x2d2d470, 0x2d2d500, 0x2d2d7c0, 0x2d2d8a0, 0x2d2d8f0, 0x2d2d940, 0x2d2d980, 0x2d2d9a0, 0x2d2d9c0, 0x2d2d9e0, 0x2d2da00, 0x2d2da20, 0x2d2da40, 0x2d2da60, 0x2d2da80, 0x2d2daa0, 0x2d2dac0, 0x2d2dae0, 0x2d2db00, 0x2d2db20, 0x2d2db40, 0x2d2db60, 0x2d2db80, 0x2d2dba0, 0x2d2dc70, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0, 0x2d2b9c0]
#  _case_tails = [0x2d2b9bc, 0x2d2ba46, 0x2d2ba63, 0x2d2ba83, 0x2d2baa8, 0x2d2bacc, 0x2d2baec, 0x2d2bb04, 0x2d2bb1b, 0x2d2bb3c, 0x2d2bb5c, 0x2d2bb7c, 0x2d2bb9c, 0x2d2bbbc, 0x2d2bbdc, 0x2d2bbfd, 0x2d2bc2d, 0x2d2bc5d, 0x2d2bc95, 0x2d2bce1, 0x2d2bcfd, 0x2d2bd33, 0x2d2bd63, 0x2d2bd90, 0x2d2bdc0, 0x2d2bdf0, 0x2d2be20, 0x2d2be71, 0x2d2bec1, 0x2d2bf11, 0x2d2bf7f, 0x2d2bfa7, 0x2d2bfc3, 0x2d2bfe3, 0x2d2c003, 0x2d2c025, 0x2d2c043, 0x2d2c06a, 0x2d2c086, 0x2d2c0b2, 0x2d2c0eb, 0x2d2c105, 0x2d2c126, 0x2d2c13c, 0x2d2c2a9, 0x2d2c3a5, 0x2d2c519, 0x2d2c534, 0x2d2c559, 0x2d2c579, 0x2d2c62f, 0x2d2c74c, 0x2d2c779, 0x2d2c7d9, 0x2d2c80a, 0x2d2c82a, 0x2d2c84a, 0x2d2c869, 0x2d2c88a, 0x2d2c8aa, 0x2d2c8c9, 0x2d2c8e4, 0x2d2c908, 0x2d2c92a, 0x2d2c948, 0x2d2c96b, 0x2d2c990, 0x2d2c9b6, 0x2d2c9d4, 0x2d2c9f8, 0x2d2ca18, 0x2d2ca3b, 0x2d2ca60, 0x2d2ca9d, 0x2d2cadd, 0x2d2cb1e, 0x2d2cb4d, 0x2d2cb7d, 0x2d2cbac, 0x2d2cbca, 0x2d2cbea, 0x2d2cc09, 0x2d2cc31, 0x2d2cc61, 0x2d2cc90, 0x2d2ccd9, 0x2d2cd59, 0x2d2cd9d, 0x2d2cdc8, 0x2d2ce0d, 0x2d2ce53, 0x2d2cea0, 0x2d2ced5, 0x2d2cf25, 0x2d2cf75, 0x2d2cfc5, 0x2d2d015, 0x2d2d065, 0x2d2d0b5, 0x2d2d10d, 0x2d2d1a1, 0x2d2d1dd, 0x2d2d232, 0x2d2d245, 0x2d2d44b, 0x2d2d466, 0x2d2d4e2, 0x2d2d4f5, 0x2d2d712, 0x2d2d72e, 0x2d2d74c, 0x2d2d897, 0x2d2d8de, 0x2d2d93a, 0x2d2d97b, 0x2d2d994, 0x2d2d9b4, 0x2d2d9d4, 0x2d2d9f4, 0x2d2da14, 0x2d2da34, 0x2d2da54, 0x2d2da74, 0x2d2da94, 0x2d2dab4, 0x2d2dad4, 0x2d2daf4, 0x2d2db14, 0x2d2db34, 0x2d2db54, 0x2d2db74, 0x2d2db94, 0x2d2dbb4, 0x2d2dc5d, 0x2d2dc93]
#  _opcodes = "NOP IADD ISUB IMUL IDIV IMOD INOT INEG IEQ INE IGT IGE ILT ILE FADD FSUB FMUL FDIV FMOD FNEG FEQ FNE FGT FGE FLT FLE VADD VSUB VMUL VDIV VNEG IAND IOR IXOR I2F F2I F2V PUSH_CONST_U8 PUSH_CONST_U8_U8 PUSH_CONST_U8_U8_U8 PUSH_CONST_U32 PUSH_CONST_F DUP DROP NATIVE ENTER LEAVE LOAD STORE STORE_REV LOAD_N STORE_N ARRAY_U8 ARRAY_U8_LOAD ARRAY_U8_STORE LOCAL_U8 LOCAL_U8_LOAD LOCAL_U8_STORE STATIC_U8 STATIC_U8_LOAD STATIC_U8_STORE IADD_U8 IMUL_U8 IOFFSET IOFFSET_U8 IOFFSET_U8_LOAD IOFFSET_U8_STORE PUSH_CONST_S16 IADD_S16 IMUL_S16 IOFFSET_S16 IOFFSET_S16_LOAD IOFFSET_S16_STORE ARRAY_U16 ARRAY_U16_LOAD ARRAY_U16_STORE LOCAL_U16 LOCAL_U16_LOAD LOCAL_U16_STORE STATIC_U16 STATIC_U16_LOAD STATIC_U16_STORE GLOBAL_U16 GLOBAL_U16_LOAD GLOBAL_U16_STORE J JZ IEQ_JZ INE_JZ IGT_JZ IGE_JZ ILT_JZ ILE_JZ CALL GLOBAL_U24 GLOBAL_U24_LOAD GLOBAL_U24_STORE PUSH_CONST_U24 SWITCH STRING STRINGHASH TEXT_LABEL_ASSIGN_STRING TEXT_LABEL_ASSIGN_INT TEXT_LABEL_APPEND_STRING TEXT_LABEL_APPEND_INT TEXT_LABEL_COPY CATCH THROW CALLINDIRECT PUSH_CONST_M1 PUSH_CONST_0 PUSH_CONST_1 PUSH_CONST_2 PUSH_CONST_3 PUSH_CONST_4 PUSH_CONST_5 PUSH_CONST_6 PUSH_CONST_7 PUSH_CONST_FM1 PUSH_CONST_F0 PUSH_CONST_F1 PUSH_CONST_F2 PUSH_CONST_F3 PUSH_CONST_F4 PUSH_CONST_F5 PUSH_CONST_F6 PUSH_CONST_F7 BITTEST ERROR".split(" ")
#  for k, v in zip(_cases, _opcodes): idc.set_name(k, "VM_"+v, idc.SN_NOWARN | idc.SN_AUTO)
#
#
#  for asm, addrs in _.groupBy(t, lambda v, *asm: diida(v)).items():
#      for addr in addrs[1:]:
#          nassemble(addr, "jmp 0x{:x}".format(addrs[0]), 1)
#  
#

# funcs = _.uniq([x for x in GetFuncStart(xrefs_to(eax('register_native_handler'))) if x != idc.BADADDR])
# for func in funcs:
#     lines = decompile_function(func)
#     for line in lines:
#         #   register_native_handler(0xA50CED7FB6E38751LL, sub_143F980);
#         s1 = string_between('register_native_handler(', ');', line)
#         if s1:
#             hash = string_between('', ',', s1).rstrip('Lu')
#             sub = string_between(', ', '', s1)
#             name = "NATIVE::_0x{:016X}".format(int(hash, 16))
#             LabelAddressPlus(eax(sub), name)
