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
from execfile import _import
#  from sfida.sf_common import isStringish
#  from sfida.sf_is_flags import IsFuncHead, HasUserName
#  from sfida.sf_string_between import string_between

#  retrace = lambda ea, *a, **k: unpatch_func(ea)
from execfile import make_refresh
refresh_membrick = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

def trim_paren(hooka):
    while hooka and hooka[0] == '(' and hooka[-1] == ')':
        hooka = hooka[1:-1]
        print("hooka: {}".format(hooka))
    return hooka


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
            return MakeNameEx(ea, name, idc.SN_NOWARN | idc.SN_AUTO)
        elif fnLoc == ea:
            return True

        if force:
            MakeNameEx(fnLoc, "", idc.SN_AUTO | idc.SN_NOWARN)
            Wait()
            return MakeNameEx(ea, name, idc.SN_NOWARN)

        name = MakeUniqueLabel(name, ea)
        return MakeNameEx(ea, name, idc.SN_NOWARN | idc.SN_AUTO)

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
            mem(abso).label('ArxanChecksumActual')
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
            return abso
        else:
            print("rel: {:x}, abso: {:x}".format(rel, abso))
        return False

    pattern = '48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8B 05 ?? ?? ?? ?? 48 F7 D8'

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


def find_checksummers4():
    patterns = ['D3 E0 33 45 ?? 89 45 ?? 8B 45 ?? E9']

def find_checksummers5():
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
        if rel == abso and base == idc.get_name_ea_simple("__ImageBase"):
            mem(abso).label('ArxanChecksumActual')
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
        if False:
            MemLabelAddressPlus(ea, 'ArxanMemcpy')
            idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x10) & ~0x22)
            idc.SetType(ea, "void f(uint8_t *dst, uint8_t *src, uint32_t len);") \
                    or idc.SetType(ea, "void f(BYTE *dst, BYTE *src, unsigned int len);")
            refFuncName = FuncRefsTo(ea)
            for ref in refFuncName:
                if ref != ea:
                    if not HasUserName(eax(ref)):
                        LabelAddressPlus(eax(ref), "ArxanCallsMemcpy")

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

def find_arxan_mutators_from_balances():
    # pattern = '55 48 83 ec 20 48 8d 6c 24 20 48 89 4d 10 48 89 55 18 44 89 45 20 8b 45 20 83 f8 04 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ??'
    # pattern = '48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 0f b6 00 48 0f be c0 85 c0 0f 84'
    patterns = [
        "6A 10 48 F7 C4 0F 00 00 00 0F 85 ?? ?? ?? ?? E9",
    ]
    results = []
    for pattern in patterns:
        for ea in [e for e in FindInSegments(pattern, '.text')]:
            try: 
                EaseCode(ea, forceStart=1)
                r = AdvanceToMnemEx(ea, term='call', inclusive=1, ease=1)
                if r and r["insns"]:
                    insns = r["insns"]
                    if not (5 < len(insns) < 12):
                        print("{:x} [find_arxan_mutators_from_balances] len(insns): {}".format(ea, len(insns)))
                        continue
                    insn = insns[-1]
                    insn = string_between('', ' ', insn, greedy=1, inclusive=1, repl='')
                    print("{:x} {}".format(eax(insn), insn))
                    if not IsCode_(insn):
                        EaseCode(ea, forceStart=1)
                    results.append(eax(insn))
                    if not HasUserName(eax(insn)):
                        LabelAddressPlus(eax(insn), 'ArxanChecksumOrHealerB')
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
    cs = find_checksummers()
    cs.extend( find_checksummers2() )
    cs.extend( find_checksummers3() )
    return cs

debug = 0
def find_shifty_stuff_quick():
    find_arxan_mutators()
    cs = defaultglobal('cs', [])
    cs = find_checksummers()
    cs.extend( find_checksummers2() )
    cs.extend( find_checksummers3() )
    LabelManyAddresses(cs, "ArxanChecksumFunction", force=1)
    mc = defaultglobal('mc', [])
    mc = find_lame_memcpys()
    find_checksum_workers()
    # find_decrypted_loadlibs()
    find_rbp_frame()
    find_stack_align_adjust()
    find_imagebase_offsets()

def find_shifty_stuff():
    results = {}
    setglobal('shifty', results)
    idc.batch(0)
    print("find_shifty_stuff()")
    pp(obfu)
    print("{}".format("arxan_mutators"))
    results['checks'] = find_arxan_mutators_from_balances()
    # retrace_list(r)
    print("{}".format("rbp_frame"))
    results['rbp'] = find_rbp_frame()
    # retrace_list(r)
    r = find_checksummers()
    print("checksummers: {}".format(r))
    r.extend(find_checksummers2())
    print("checksummers: {}".format(r))
    r.extend(find_checksummers3())
    results['cs'] = r
    rc = r[0:]
    print("checksummers...")
    print([idc.get_func_name(x) for x in r])
    # LabelManyAddresses(r, "ArxanChecksumTest", force=1)
    # retrace_list(r)
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
    for ea in [GetFuncStart(x) for x in FindInSegments("8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ??")]:
        AddTag(ea, "seldom")
    if False:
        for ea in rc:
            decompile_arxan(ea)
            decompile_arxan(ea)

    LabelManyAddresses(results['checks'], "ArxanCheckFunction2", force=1)
    LabelManyAddresses(results['cs'], "ArxanCheckFunction", force=1)
    LabelManyAddresses(results['csworkers'], "ArxanGetNextRange", force=1)
    LabelManyAddresses(results['balance'], "ArxanBalance", force=1)
    LabelManyAddresses(results['memcpy'], "ArxanMemcpy", force=1)
    setglobal('shifty', results)
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
        head = ea
        if IsTail(head):
            head = idc.get_item_head(ea)
        if not IsCode_(head):
            forceCode(head)
        if not force and idc.hasUserName(idc.get_full_flags(ea)) and not idc.get_name(ea).startswith('_sub_'):
            continue
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

def FindInSegments(searchstr, segments=None, limit=None, predicate=None, iteratee=None, binary=True):
    """
    @param searchstr: a string as a user enters it for Search Text in Core
    @param segments: segment names (default: ['.text'])
    @param predicate: function(address) -> address or None
    @param limit: maximum number of results to return

    @return: [address, ...] of found results result or [] if none found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)

    @eg: filter(IsFuncHead, FindInSegments("ba 10 00 00 00 e9 ?? ?? ?? ??"))
    """
    if not segments:
        segments = ['.text']

    if not binary:
        searchstr = ' '.join(["%02x" % x for x in asByteArray(searchstr)])

    if isinstance(searchstr, list):
        results = []
        for search in searchstr:
            results.extend(FindInSegments(search, segments=segments, limit=limit, predicate=predicate, iteratee=iteratee))
        return results
    
    searchstr = searchstr.lower().strip().replace('??', '?').replace('?', '??').rstrip(' ?')
    if not re.match(r'([0-9a-f][0-9a-f] |\?\? )+([0-9a-f][0-9a-f])$', searchstr):
        print("Invalid binary searchstring: '{}'".format(searchstr))
        return [];

    ea = 0
    results = []
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
            if not predicate or not callable(predicate):
                results.append(ea)
            else:
                r = predicate(ea)
                if r and r > 1:
                    results.append(r)
                    if callable(iteratee):
                        iteratee(r)
                elif r:
                    results.append(ea)
                    if callable(iteratee):
                        iteratee(ea)

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

def MakeSigned(number, size):
    """
    MakeSigned(number, bits)

        Return a signed version of an unsigned number as retrieved by Qword,
        Dword, etc.
        -- sfinktah
    """
    number = number & (1 << size) - 1
    return number if number < 1 << size - 1 else - (1 << size) - (~number + 1)


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


def mem(pattern):
    return mb(pattern)


def ProtectPattern(pattern):
    return ProtectScan(pattern)


def ProtectScan(*args, **kwargs):
    return mb(*args, **kwargs)


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

    def error_return_chained(self):
        return self

    def error_return(self):
        return not self.errored

    def in_error(self):
        if self.errored:
            pass
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

    def rip(self, offset=4):
        """ Dereference pointer
        """
        if self.in_error(): return self.error_return_chained()
        try:
            return self.add(offset + MakeSigned(idc.get_wide_dword(self._clean.obj), 32))
        except TypeError:
            self.errored = True;
            return self.error_return_chained()

    def get_autorips(self):
        if self.in_error(): return self.error_return()
        pos = 0
        found = -1
        results = []
        if self.pattern is None:
            print("self.pattern is None")
            self.errored = True
            return self.error_return()

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
            print("self.pattern is None")
            self.errored = True
            return self.error_return_chained()

        while found < index:
            if found > -1:
                pos += 11
            pos = self.pattern.find("?? ?? ?? ??", pos);
            if pos == -1:
                print("?? ?? ?? ?? x {} not found".format(index))
                self.errored = True
                return self.error_return_chained()
            found += 1

        print(".add({}).rip(4)".format(pos // 3))
        return self.add(pos // 3).rip(4)

    def count(self, num, name):
        return self
        results = FindInSegments(self.original_object)
        if len(results) != num:
            print("pattern({}) [{}] found {} times instead of {}".format(self.original_object, name, len(results), num))
            self.errored = True
            return self.error_return()
        self.results = results
        return self

    def get(self, num):
        return self
        if self.in_error(): return self.error_return_chained()
        if num < len(self.results):
            return self._wrap(self.results[num])
        else:
            print("result {} not found ({} results exist)".format(num, len(self.results)))
            self.errored = True
            return self.error_return()

    #  ti = idaapi.tinfo_t()
    #  ti.deserialize(None, t[0], t[1])
    def type(self, type=False):
        if self.in_error():
            return self.error_return()
        if type == False:
            return idc.get_type(self.val())
        if not type:
            return self
        if not idc.SetType(self.val(), type):
            print("error setting type at '0x{:x}' from {} to {}".format(self.val(), idc.get_type(self.val()), type))
        return self

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

    def label(self, name):
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

    def ea(self, T=long_type):
        """ returns the object instead of instance
        """
        if self.in_error(): return self.error_return_chained()
        if self._wrapped is not self.Null:
            return T(self._wrapped)
        else:
            return T(self.obj)

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
