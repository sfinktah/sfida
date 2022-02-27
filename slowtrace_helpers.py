import collections
import inspect
import os
import traceback
import re
import subprocess
import math
from collections import defaultdict
from string_between import string_between
try:
    from execfile import _import, _from, execfile
except ModuleNotFoundError:
    from exectools import _import, _from, execfile
#  _import('from circularlist import CircularList')
#  _import('from ranger import *')
# causes loop in 2.7
# _import('from sfida.sf_is_flags import *')

try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_xref
    import ida_name
    import idaapi
    import idautils
    import idc
    from idc import BADADDR
    from ida_bytes import DELIT_NOTRUNC

except:
    class idc:
        BADADDR = 0xffffffffffffffff
    BADADDR = idc.BADADDR

if not idc:
    import obfu
    from collections import defaultdict
    from di import decode_insn
    from helpers import hasAnyName, hex
    from idc import BADADDR, FUNCATTR_FLAGS, CIC_FUNC, DELIT_DELNAMES, SetType, SN_NOWARN, SN_AUTO, FUNCATTR_OWNER, FUNCATTR_START, FUNCATTR_END, GetDisasm, FF_REF, FF_FLOW, DEMNAM_FIRST, get_name_ea_simple
    from idc import BADADDR, fl_JF, fl_JN, fl_CF, fl_CN, auto_wait, GetDisasm, is_data, is_head, isRef, hasName, hasUserName, is_qword, is_defarg0, is_off0, is_code, FUNCATTR_OWNER
    from idc_bc695 import GetFunctionName, GetIdbPath, LocByName, MakeNameEx, DOUNK_DELNAMES, DOUNK_EXPAND, DOUNK_NOTRUNC, Name, PatchByte, DelFunction, GetSpDiff, SetSpDiff, Dword, Qword, ItemHead, SegName, GetSpd, Demangle, GetMnem
    from idc_bc695 import GetOperandValue, SegName, LocByName, GetIdbPath, GetInputFile, ScreenEA, DOUNK_EXPAND, DOUNK_NOTRUNC, Wait, NextNotTail, AppendFchunk, GetFunctionName
    import sfida.is_flags
    from membrick import MakeSigned
    from obfu_helpers import PatchBytes
    from obfu_helpers import hex_byte_as_pattern_int
    from sfcommon import GetFuncEnd, GetFuncStart, MakeCodeAndWait
    from sftools import MyMakeFunction, MyMakeUnknown
    from sftools import MyMakeUnknown, MyMakeUnkn, MyMakeFunction
    from slowtrace2 import visited, get_byte, AdvanceFailure
    from start import isString
    from underscoretest import _

try:
    import __builtin__ as builtins
    integer_types = (int, long)
    string_types = (basestring, str, unicode)
    string_type = unicode
    byte_type = str
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str, bytes)
    byte_type = bytes
    string_type = str
    long_type = int
    long = int

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate
#  with open(os.path.dirname(__file__) + os.sep + 'refresh.py', 'r') as f: exec(compile(f.read().replace('__BASE__', os.path.basename(__file__).replace('.py', '')).replace('__FILE__', __file__), __file__, 'exec'))

print("[slowtrace-helpers loading]")
stk = []
for i in range(len(inspect.stack()) - 1, 0, -1):
    stk.append(inspect.stack()[i][3])
print((" -> ".join(stk)))

warn = 0

_file = os.path.abspath(__file__)
def refresh_slowtrace_helpers():
    execfile(_file)

def delete_all_from(ea):
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """

    # Brute-force nuke all info from all the heads
    while ea != BADADDR and ea <= ida_ida.cvar.inf.max_ea:
        ida_name.del_local_name(ea)
        ida_name.del_global_name(ea)
        func = clone_items(ida_funcs.get_func(ea))
        if func:
            ida_funcs.del_func_cmt(func, False)
            ida_funcs.del_func_cmt(func, True)
            ida_funcs.del_func(ea)
        ida_bytes.del_hidden_range(ea)
        PatchBytes(ea, [0] * 9)
        #  seg = ida_segment.getseg(ea)
        #  if seg:
        #  ida_segment.del_segment_cmt(seg, False)
        #  ida_segment.del_segment_cmt(seg, True)
        #  ida_segment.del_segm(ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)

        ea = ida_bytes.idc.next_head(ea, ida_ida.cvar.inf.max_ea)


def RebuildFuncAndSubs(ea):
    subs = RecurseCalled(ea)['calledLocs']
    subs.reverse()
    for addr in subs:
        ZeroFunction(addr)
        idc.auto_wait()
    ZeroFunction(ea)
    idc.auto_wait()


def RecurseCalled(ea=None, width=512, depth=5, data=0, makeChart=0, exe='dot', includeSubs=0, fixVtables=False):
    def all_xrefs_from(funcea, iteratee=None):
        if iteratee is None:
            iteratee = lambda x: x

        xrefs = []
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                xrefs.extend([GetFuncStart(x.to) for x in idautils.XrefsFrom(head) \
                        if x.type in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN) \
                        and not ida_funcs.is_same_func(funcea, x.to) \
                        and IsFunc_(x.to)])

        xrefs = list(set(xrefs))

        return xrefs

    def vtables_from(funcea, iteratee=None):
        if iteratee is None:
            iteratee = lambda x: x

        xrefs = []
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                xrefs.extend([x.to for x in idautils.XrefsFrom(head) \
                        if Name(x.to).startswith('??_7')])

        xrefs = list(set(xrefs))

        return xrefs

    if ea is None:
        ea = idc.get_screen_ea()

    calledNames = list()
    calledLocs = list()
    visited = set([])
    if isinstance(ea, list):
        pending = set(ea)
        initial = set([GetFuncStart(x) for x in ea])
    else:
        pending = set([ea])
        initial = set([GetFuncStart(ea)])
    count = 0
    added = [1]
    functionCalls = collections.defaultdict(set)
    namedFunctionCalls = collections.defaultdict(set)
    fwd = dict()
    rev = dict()
    vtables = set()

    while pending and depth and len(pending) < width:
        target = pending.pop()
        count += 1
        added[0] -= 1
        if added[0] < 1:
            depth -= 1
            added.pop()

        visited.add(target)

        fnName = idc.get_func_name(target) or idc.get_name(target) or "0x%x" % ref
        fnStart = GetFuncStart(target)

        if fnStart < idc.BADADDR:
            target = fnStart
            visited.add(target)
            if not fnStart in initial:
                calledNames.append(fnName)
                calledLocs.append(fnStart)

        vtables |= set(vtables_from(fnStart))
        refs = all_xrefs_from(fnStart)
        refs = set(refs)
        refs -= visited
        size1 = len(pending)
        pending |= refs
        size2 = len(pending) - size1
        added.append(size2)

    return {'calledName': calledNames,
            'calledLocs': calledLocs,
            'vtables': list(vtables),
           }

def func_rename_vtable_xref(ea=None, **kwargs):
    """
    func_rename_vtable_xref

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [func_rename_vtable_xref(x) for x in ea]

    ea = eax(ea)

    o = RecurseCalled(ea, **kwargs)
    vtables = _.filter(o['vtables'], lambda x, *a: 'HttpTask' in idc.get_name(x, ida_name.GN_DEMANGLED))
    if len(vtables) == 1:
        vtables = list(vtables)
        name = re.findall(r'\w+HttpTask\w*', idc.get_name(vtables[0], ida_name.GN_DEMANGLED))
        if len(name) == 1:
            name = name[0]
            print("{:x} renaming to: {}".format(ea, name))
            LabelAddressPlus(ea, 'uses_' + name)
        else:
            print("{:x} couldn't find matching vtable name".format(ea))
    else:
        print("{:x} vtables: {}".format(ea, len(vtables)))

    

def isListOf(o, t):
    if isinstance(o, list):
        if o:
            if isinstance(o[0], t):
                return True
    return False
        
def RecurseCalledRange(r=None, width=512, data=0, makeChart=1, exe='dot', includeSubs=0, fixVtables=False):
    from bisect import bisect_left, bisect_right, bisect
    chart = []

    def all_xrefs_from(startea, endea, iteratee=None, GetBlockStart=None):
        if iteratee is None:
            iteratee = lambda x: x

        xrefs = []
        for head in Heads(startea, endea):
            xrefs.extend([x for x in [GetBlockStart(x.to) for x in idautils.XrefsFrom(head) \
                    if x.type in (
                        #  ida_xref.fl_CF, ida_xref.fl_CN, 
                        ida_xref.fl_JF, ida_xref.fl_JN
                        ) \
                    ] if x])

        return list(set(xrefs))

    if not isListOf(r, GenericRange):
        raise ValueError('Not a list of GenericRage')

    calledNames = list()
    calledLocs = list()
    visited = set([])
    rdict = dict()
    for e in r:
        rdict[e.start] = (e.start, e.end)

    rdict_keys = _.sort(list(rdict.keys()))

    def GetBlockStart(start):
        left  = bisect_left(rdict_keys, start)
        right = bisect_right(rdict_keys, start)
        # dprint("[GetBlockStart] left, right")
        result = rdict[rdict_keys[left]][0]
        if start < result:
            return None
        print("[GetBlockStart] start:{:x} left:{:x}, right:{:x}, result:{:x}".format(start, rdict[rdict_keys[left]][0], rdict[rdict_keys[left]][1], result))
        
        return rdict[rdict_keys[left]][0]

    depth = 0
    count = 0
    added = [1]
    functionCalls = collections.defaultdict(set)
    namedFunctionCalls = collections.defaultdict(set)
    fwd = dict()
    rev = dict()

    assoc = defaultdict(list)
    for start, end in rdict.values():
        refs = all_xrefs_from(start, end, None, GetBlockStart)
        for ea in refs:
            # dprint("[adding] ea")
            print("[adding] ea:{}".format(ahex(ea)))
            
            chart.append([start, ea])
            assoc[start].append(ea)
            assoc[ea].append(start)

    used = set()
    sets = []
    addrs = []
    addrs2 = []
    for k in list(assoc.keys()):
        # dprint("[debug] k")
        print("[debug] k:{}".format(ahex(k)))
        
        addrs.clear()
        addrs2.clear()
        if k in assoc:
            for ea in assoc[k]:
                if ea not in used:
                    used.add(ea)
                    addrs.append(ea)
                    addrs2.append(ea)
            assoc.pop(k)

            while addrs:
                k = addrs.pop()
                if k in assoc:
                    for ea in assoc[k]:
                        if ea not in used:
                            used.add(ea)
                            addrs.append(ea)
                            addrs2.append(ea)
                    assoc.pop(k)

            # dprint("[debug] addrs")
            print("[debug] addrs:{}".format(hex(addrs2)))
            print("[debug] used:{}".format(hex(list(used))))
            
            sets.append(addrs)

    #  return chart
    return sets





    subs = []
    call_list = []
    for x in chart:
        x[0] = hex(x[0])
        x[1] = hex(x[1])
        subs.append(x[0])
        subs.append(x[1])
        if len(x) > 2:
            call_list.append('"{}" -> "{}" {};'.format(x[0], x[1], " ".join(x[2:])))
        else:
            call_list.append('"{}" -> "{}";'.format(x[0], x[1]))
    call_list.sort()
    call_list = _.uniq(call_list, True)
    # colors = colorSubs(subs, colors, [fnName])
    return call_list

    dot = __DOT.replace('%%MEAT%%', '\n'.join(_.uniq(colors + call_list)))
    r = dot_draw(dot, name="written", exe=exe)
    print("dot_draw r: {}".format(r))
    if isinstance(_, tuple):
        if not r[0]:
            print("dot_draw error: {}".format(r[1]))
        else:
            print("dot_draw good: {}".format(r[1]))

def CheckChunks(funcea=None):
    """
    CheckChunks - check all addresses in a function for shifty chunks

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    chunk_starts = set([])
    chunk_ends = set([])
    _chunks = idautils.Chunks(funcea)
    for (start_ea, end_ea) in _chunks:
        chunk_starts.add(start_ea)
        chunk_ends.add(end_ea)
        for _head in idautils.Heads(start_ea, end_ea):
            _owners = GetChunkOwners(_head)
            if len(_owners) != 1 or funcea not in _owners:
                print("[warn] function {:x}, chunk {:x}, owned by: {}".format(funcea, hex(_owners_)))
                return False

    if not chunk_starts.isdisjoint(chunk_ends):
        print("[warn] function {:x} has adjoining chunks at {}".format(funcea, hex(list(chunk_starts.intersection(chunk_ends)))))


    return True


def GetAllChunks():
    for cid in range(ida_funcs.get_fchunk_qty()): 
        yield ida_funcs.getn_fchunk(cid)


def NotHeads(start=None, end=None, predicate=None, advance=None):
    """
    Get a list of heads^H^H^H^H^H anything

    @param start: start address (default: inf.min_ea)
    @param end:   end address (default: inf.max_ea)
    @param predicate: if returns True, then address added
    @param advance: advance ea (default: ea += 1)

    @return: list of heads between start and end
    """
    if start is None: start = ida_ida.cvar.inf.min_ea
    if end is None:   end = ida_ida.cvar.inf.max_ea
    if predicate is None or not callable(predicate): 
        return
    if advance is None:
        advance = lambda a, e: a + 1

    ea = start
    if not predicate(ea):      # if not idc.is_head(ida_bytes.get_flags(ea)):
        ea = advance(ea, end)  # ea = ida_bytes.next_head(ea, end)
    while ea < end and ea != ida_idaapi.BADADDR:
        if predicate(ea):      # if not idc.is_head(ida_bytes.get_flags(ea)):
            yield ea
        ea = advance(ea, end)  # ea = ida_bytes.next_head(ea, end)


def TrimChunks(funcea=None):
    """
    TrimChunks

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    chunks = idautils.Chunks(funcea)
    for cstart, cend in chunks:
        new_cend = None
        cheads = list(idautils.Heads(cstart, cend))
        cheads_len = len(cheads)
        removed = 0
        while cheads and (isNop(cheads[-1]) or GetMnemDi(cheads[-1]).startswith(('int',))):
            removed += 1
            new_cend = cheads[-1]
            cheads.pop()

        if new_cend:
            if len(cheads) == 0:
                idc.remove_fchunk(funcea, cstart)
            elif IsFuncHead(cstart):
                SetFuncEnd(cstart, new_cend)
            else:
                SetChunkEnd(cstart, new_cend)

    return removed


def RemoveAllChunksAndFunctions(leave=[]):
    #  print("Stage #1")
    #  chunks = []
    #  for ea in range(0, ida_funcs.get_fchunk_qty()):
        #  chunk_ea = getn_fchunk(ea).start_ea
        #  chunks.append(chunk_ea)
    #  for ea in chunks:
        #  RemoveThisChunk(ea)

    print("Stage #2")
    for funcea in idautils.Functions():
        # RemoveAllChunks(funcea)
        ZeroFunction(funcea, 1)

def check_append_func_tail(func, ea1, ea2):
    funcea = func.start_ea

    fail = False
    errors = []
    if ea1 <= func.start_ea < ea2:
        msg = "attempted to overlap funchead at {:x} ({})".format(funcea, GetFuncName(funcea))
        errors.append(msg)

    #  if ida_funcs.get_func_chunknum(func, ea1) != -1:
        #  tail = ida_funcs.get_fchunk(ea1 - 1)
        #  print("append_func_tail: appending instead of extending:\nappend_func_tail(0x{:x}, 0x{:x}, 0x{:x})\n[overlaps existing function chunk at 0x{:x}]".format(funcea))
        #  print("executing instead: ida_funcs.set_func_end(0x{:x}, 0x{:x})".format(tail.start_ea, ea2))
        #  return ida_funcs.set_func_end(tail.start_ea, ea2)
    
    for ea in range(ea1, ea2): # if len(list(idautils.Chunks(ea))) > 1 and func.start_ea in GetChunkOwners(ea) or \
        if ida_funcs.get_func_chunknum(func, ea) != -1:
            msg = "overlaps existing function chunk at 0x{:x}\u2013{:x}".format(GetChunkStart(ea), GetChunkEnd(ea))
            errors.append(msg)
        owners = GetChunkOwners(ea, includeOwner=1)
        if owners:
            msg = "existing owners: {} ({})".format(hex(owners), GetFuncName(owners))
            errors.append(msg)

        owner = ida_funcs.get_func(ea)
        if owner and ida_funcs.get_func_chunknum(owner, ea) != -1:
            msg = "would overlap existing chunk #{}/{} of {} at {:x}\u2013{:x}".format(
                    GetChunkNumber(ea, eax(owner)), GetNumChunks(eax(owner)), GetFunctionName(eax(owner)), GetChunkStart(ea), GetChunkEnd(ea))
            errors.append(msg)

    if errors:
        #  for error in set(errors):
            #  print(error)
        raise AppendChunkError(_.uniq(errors))

    return True


def FindBadJumps():
    for funcea in idautils.Functions():
        for ea in GetFuncHeads(funcea):
            if isJmpOrCall(ea):
                opType = idc.get_operand_type(ea, 0)
                if opType in (idc.o_far, idc.o_near, idc.o_mem):
                    target = idc.get_operand_value(ea, 0)
                    if not IsValidEA(ea):
                        yield ea


def FindJmpChunks():
    for funcea in idautils.Functions():
        if GetNumChunks(funcea) > 1:
            for cstart, cend in idautils.Chunks(funcea):
                length = cend - cstart
                if length == 2 or length == 5:
                    if isUnconditionalJmp(cstart):
                        yield cstart

def SkipJmpChunks():
    patched = defaultglobal('_skipjmpchunks', set())
    for refs in [xrefs_to(x) for x in FindJmpChunks()]:
        count = 0
        for ea in [x for x in refs if isUnconditionalJmp(x)]:
            try:
                jumps = SkipJumps(ea, apply=1, returnJumps=1, returnTarget=1)
                count = max(count, len(jumps) - 1)
            except AdvanceFailure as e:
                if "couldn't create instruction" in e.args[0] or \
                        "couldn't get mnem from" in e.args[0] or \
                        "couldn't find valid insn" in e.args[0] or \
                        "couldn't find valid target" in e.args[0]:
                    print("[SkipJmpChunks] {:x} AdvanceFailure triggering unpatch and retrace".format(ea))
                    funcea = GetFuncStart(ea)
                    idc.del_func(funcea)
                    UnpatchUn()
                    retrace(funcea)
                else:
                    print("[SkipJmpChunks] {:x} AdvanceFailure: {}".format(ea, e))

        if count > 1:
            patched.add(ea)
            target = SkipJumps(ea)
            for ea in [x for x in refs if isConditionalJmp(x)]:
                insn_len = insn
                if InsnLen(ea) == 6:
                    nassemble(ea, "{} 0x{:x}".format(idc.print_insn_mnem(ea), target), apply=1)
                else:
                    # assemble using internal ida assembler which will
                    # automatically create short jmps (nassemble is set to
                    # strict mode an will always create regular jmps unless
                    # otherwise specified)
                    targets = _.reverse(jumps[1:])
                    for tgt in targets:
                        assembled = iassemble(ea, "{} 0x{:x}".format(idc.print_insn_mnem(ea), target))
                        if len(assembled) <= InsnLen(ea):
                            PatchBytes(ea, assembled, "SkipJmp")
                            break


def FixAllChunks(leave=None):
    print("Stage #1")
    for funcea in idautils.Functions():
        for r in range(20):
            if not FixChunks(funcea, leave=leave):
                break
            idc.auto_wait()
            pass

    print("Stage #2")
    chunks = []
    for ea in range(0, ida_funcs.get_fchunk_qty()):
        chunk_ea = ida_funcs.getn_fchunk(ea).start_ea
        chunks.append(chunk_ea)
    for ea in chunks:
        FixChunk(ea)


def FixChunks(funcea=None, leave=None):
    """
    call FixChunk for every chunk in a function

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    failed = fixed = 0

    chunk_count_1 = func.tailqty
    chunk_count_2 = len([x for x in idautils.Chunks(funcea)]) - 1
    if chunk_count_1 != chunk_count_2:
        print("[FixChunks] tailqty != len(Chunk)")

    if func and func.tailqty > 1:
        all_chunks = [x for x in idautils.Chunks(funcea)] #  if x[0] != funcea
        for chunk_start, chunk_end in all_chunks:
            _chunk_number = GetChunkNumber(chunk_start, funcea)
            if _chunk_number > -1 and GetChunkNumber(chunk_start) == -1:

                if len(GetChunkOwners(chunk_start)) == 0:
                    print("[FixChunk] We have a really messed up ghost chunk at 0x{:x} belonging to 0x{:x} with no ChunkOwners".format(chunk_start, funcea))
                    
                    _tailqty = func.tailqty
                    _chunk_list = GetChunks(funcea)
                    if len(_chunk_list) > _chunk_number:
                        _cc = _chunk_list[_chunk_number]


                    if not GetChunkOwners(_cc['start']):
                        if idaapi.cvar.inf.version >= 700 and sys.version_info >= (3, 7):
                            ZeroFunction(func.start_ea)
                        else:
                            print("[FixChunk] Attempting dangerous thing #1: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(func.start_ea, _cc['start'], _cc['end']))
                            r = ida_funcs.append_func_tail(func, _cc['start'], _cc['end'])
                            print("[FixChunk] Completed dangerous thing #1: {}".format(r))
                            if not r:
                                print("[FixChunk] Attempting dangerous thing #1.1: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(func.start_ea, _cc['start'], _cc['start'] + GetInsnLen(_cc['start'])))
                                r = ida_funcs.append_func_tail(func, _cc['start'], _cc['start'] + GetInsnLen(_cc['start']))
                                print("[FixChunk] Completed dangerous thing #1.1: {}".format(r))
                            if r:
                                idc.auto_wait()
                                if func.tailqty > _tailqty:
                                    print("[FixChunk] func {:x} grew from {} to {} tails".format(funcea, _tailqty, func.tailqty))
                                    # dangerous to mess further with this function and it's chunks right now
                                    return 1
                                else:
                                    if GetChunkNumber(chunk_start) > -1:
                                        print("[FixChunk] func {:x} didn't grow a new tail, but it has a chunk number now".format(funcea))
                                        return 1
                                    else:
                                        print("[FixChunk] func {:x} didn't grow a new tail".format(funcea))
                    else:
                        print("[FixChunk] #9")
                    return 0

                if funcea not in GetChunkOwners(chunk_start):
                    print("[FixChunk] We have a really messed up ghost chunk at 0x{:x} belonging to 0x{:x} with ChunkOwners: {}".format(chunk_start, funcea, GetChunkOwners(chunk_start)))

                    print("[FixChunk] Func {:x} isn't owner of own chunk {:x}", funcea, chunk_start)
                    _old_owners = GetChunkOwners(chunk_start)
                    SetChunkOwner(chunk_start, funcea)
                    for _owner in _old_owners:
                        if not idc.remove_fchunk(_owner, chunk_start):
                            # make triple sure of this, as we will crash ida 7.5 if we're wrong
                            if _owner not in GetChunkOwners(chunk_start):
                                print("[FixChunk] Attempting dangerous thing #2: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(GetFunc(_owner), chunk_start, GetChunkEnd(chunk_start)))
                                r = ida_funcs.append_func_tail(GetFunc(_owner), chunk_start, GetChunkEnd(chunk_start))
                                print("[FixChunk] Completed dangerous thing #2: {}".format(r))
                            print("[FixChunk] Attempting dangerous thing #3: idc.set_tail_owner({:x}, {:x})".format(chunk_start, _owner))
                            r = idc.set_tail_owner(chunk_start, _owner)
                            print("[FixChunk] Completed dangerous thing #3: {}".format(r))
                            print("[FixChunk] Attempting dangerous thing #4: idc.remove_fchunk({:x}, {:x})".format(_owner, chunk_start))
                            r = idc.remove_fchunk(_owner, chunk_start)
                            print("[FixChunk] Completed dangerous thing #4: {}".format(r))
                            if r:
                                print("[FixChunk] Managed to fix really fucked up ghost chunk")
                                continue
                            
            r = FixChunk(chunk_start, leave=funcea, owner=funcea, chunk_end=chunk_end)
            #  if r == False:
                #  return r
            if isinstance(r, integer_types):
                fixed += r
            elif r == False:
                failed += 1

    return fixed

def FixChunk(ea=None, leave=None, owner=None, chunk_end=None):
    """
    Attempt to fix broken-assed chunked, as in example below:

    ; START OF FUNCTION CHUNK FOR loc_140CB4F38
    ;   ADDITIONAL PARENT FUNCTION implsub_140CB4F38

    loc_144429DE8:                          ; CODE XREF: implsub_140CB4F38
                    or      eax, 0FFFFFFFFh
                    jmp     loc_140CB4D74
    ; END OF FUNCTION CHUNK FOR loc_140CB4F38

    @param ea: linear address
    """
    ea = eax(ea)

    if IsFuncHead(ea):
        return 0

    # Really invalid chunks may show up as being owned by chunkOwnersFuncNames non-function,
    # often loc_14xxxxxx. So we can use this quick cheat to sort them.
    if GetChunkNumber(ea) == 0:
        return 0

    if six.PY2:
        _append_func_tail = lambda x, *a: ida_funcs.append_func_tail(GetFunc(x), *a)
    else:
        _append_func_tail = my_append_func_tail
    chunkOwners = GetChunkOwners(ea)
    _chunkOwner = GetChunkOwner(ea) # this can turn up a different result
    _chunkNumber = GetChunkNumber(ea)
    if _chunkOwner == idc.BADADDR:
        _chunkOwner = None
    if _chunkOwner and _chunkOwner not in chunkOwners:
        print("[FixChunk] chunk:{:x} chunkOwner not in chunkOwners".format(ea))
        chunkOwners.append(_chunkOwner)
        _realOwner = PickChunkOwner(ea)

    chunkOwners = [x for x in chunkOwners if IsValidEA(x)]

    if _chunkNumber == -1 and chunkOwners:
        print("[FixChunk] chunk at {:x} is orphaned from {}".format(ea, hex(chunkOwners)))
        if len(chunkOwners) == 1:
            owner = _.first(chunkOwners)
            if not IsFuncHead(owner):
                print("need to create parent")
                if not ForceFunction(owner):
                    print("couldn't make parent")
            idc.auto_wait()
            if GetChunkNumber(ea) != -1:
                print("chunk has a number now, removing it")
                idc.remove_fchunk(owner, ea)
                return 1
            print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, GetChunkStart(ea), GetChunkEnd(ea)))
            if ida_funcs.append_func_tail(GetFunc(owner), GetChunkStart(ea), GetChunkEnd(ea)):
                if not idc.remove_fchunk(owner, GetChunkStart(ea)):
                    print("idc.remove_fchunk(0x{:x}, 0x{:x}) failed; recreating parent function".format(owner, GetChunkStart(ea)))
                    func = ida_funcs.get_func(owner)
                    fnLoc = func.start_ea
                    for start, end in idautils.Chunks(fnLoc):
                        idc.remove_fchunk(start, end)
                    ida_funcs.del_func(func.start_ea)
                    print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)))
                    if _append_func_tail(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)):
                        if not idc.remove_fchunk(fnLoc, GetChunkStart(ea)):
                            print("idc.remove_fchunk(0x{:x}, 0x{:x}) failed".format(fnLoc, GetChunkStart(ea)))
                            return 0
                        else:
                            return 1
                    else:
                        print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x}): failed".format(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)))
                        return 0
            else:
                print("couldn't append func to owner")

            return 1

    if not chunkOwners and owner:
        print("[FixChunk] chunk at {:x} appears to have no chunkOwners, what about {:x}?".format(ea, owner))
        if chunk_end and chunk_end == ea:
            print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, ea, ea + GetInsnLen(ea)))
            if _append_func_tail(owner, ea, ea + GetInsnLen(ea)):
                idc.auto_wait()
                if idc.remove_fchunk(owner, ea):
                    idc.auto_wait()
                    print("[FixChunk] chunk at {:x} removed".format(ea))
                    return 1
        print("[FixChunk] resorting to ZeroFunction of {:x}".format(owner))




    chunkOwnersFuncNames = [idc.get_func_name(x) for x in chunkOwners]
    chunkOwnersAnyNames = [idc.get_name(x) for x in chunkOwners]

    invalid_owners = []
    valid_owners = []
    ghost_owners = []

    for x, y, z in zip(chunkOwnersFuncNames, chunkOwnersAnyNames, chunkOwners):
        if z != idc.BADADDR:
            if not (x or y) or x != y:
                invalid_owners.append(z)
            else:
                valid_owners.append(z)
        #  print("[FixChunk] {}".format(pf({
                #  "x": x,
                #  "y": y,
                #  "z": hex(z),
            #  })))
#  
#  
    #  print("[FixChunk] {}".format(pf({
            #  "invalid_owners": hex(invalid_owners),
            #  "valid_owners": hex(valid_owners),
            #  "ghost_owners": hex(ghost_owners),
        #  })))

    #  if not valid_owners and not invalid_owners and owner and GetChunkNumber(ea, owner) > -1:
        #  ghost_owners.append(owner)


    needs_fixing = 0
    if ghost_owners:
        print("[FixChunk] ghost_owners:{:x} ghost_owners:{}" \
                .format(ea, hex(ghost_owners), GetFuncName(ghost_owners)))
        print("[FixChunks] RemoveAllChunks")
        chunks = RemoveAllChunks(owner)
        for r in range(len(chunks)):
            if GetNumChunks(owner) > 1:
                print("[FixChunks] RemoveAllChunks")
                RemoveAllChunks(owner)
            else:
                break
        idc.auto_wait()
        for cs, ce in chunks[1:]:
            print("[FixChunks] read chunk: {:x}, {:x}".format(cs, ce))
            print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, cs, ce))
            _append_func_tail(owner, cs, ce)

        return



    if invalid_owners or len(valid_owners) > 1:
        needs_fixing = 1
        print("[FixChunk] chunk:{:x} invalid_owners:{}, valid_owners:{}" \
                .format(ea, hex(invalid_owners), GetFuncName(valid_owners)))

    if invalid_owners:
        for funcea in invalid_owners:
            print("[FixChunk] Making function at {:x}".format(funcea))
            # if not MyMakeFunction(funcea):
            if not idc.add_func(funcea, GetInsnLen(funcea) + funcea):
                for _ea in invalid_owners + valid_owners: 
                    print("Removing all chunks from {:x}".format(_ea))
                    # for r in range(10):
                    while len(RemoveAllChunks(_ea)) > 1:
                        pass
                if len(GetChunkOwners(funcea)) > 1:
                    raise RuntimeError("[FixChunk] Couldn't make {:x} into a legitimate function".format(funcea))
    
            idc.auto_wait()
            # if we try to add chunkOwnersFuncNames chunk that overlaps an existing chunk owned by
            # the same function, IDA will crash.  So check for this first.
            if ida_funcs.get_func_chunknum(GetFunc(funcea), GetChunkStart(ea)) == -1:
                print("[FixChunk] Recovery mode #1 for owner {:x}".format(funcea))
                print("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, GetChunkStart(ea), GetChunkEnd(ea)))
                _append_func_tail(funcea, GetChunkStart(ea), GetChunkEnd(ea))
            else:
                print("[FixChunk] Recovery mode #2 for owner {:x}".format(funcea))
                idc.remove_fchunk(funcea, GetChunkStart(ea))

        for funcea in invalid_owners:
            print("[FixChunk] Removing invalid_owners function at {:x}".format(funcea))
            if not idc.del_func(funcea):
                if GetChunkNumber(ea, funcea) > -1:
                    raise RuntimeError("[FixChunk] Couldn't remove function at {:x}".format(funcea))
            idc.auto_wait()

    if len(valid_owners) > 1:
        print("[FixChunk] Multiple valid owners, removing them all from {:x} (except: {})".format(ea, hex(leave)))
        RemoveAllChunkOwners(ea, leave=leave)

    if len(GetChunkOwners(ea)) > 1:
        print("[FixChunk] Owners still > 1, removing all chunks...")
        for _ea in invalid_owners + valid_owners: 
            print("Removing all chunks from {:x}".format(_ea))
            # for r in range(10):
            while len(RemoveAllChunks(_ea)) > 1:
                pass
        if len(GetChunkOwners(ea)) > 1:
            print("[FixChunk] Owners really still > 1...")
            return False

    return needs_fixing


def FixAdjoiningChunks(ea=None, owner=None):
    """
    Attempt to fix broken-assed chunks, where there are two adjoining chunks
    belonging to the same function. Note, they usually aren't also
    multiply-owned chunks, but I believe that is how they come to be created.

    ; ---------------------------------------------------------------------------
    ; START OF FUNCTION CHUNK FOR netshop___0x45c52481c47b5e75_actual
    
    loc_140CD3AF2:                          ; CODE XREF: netshop___0x45c52481c47b5e75_actual-1822FE3
                    jmp     short loc_140CD3A9D
    ; END OF FUNCTION CHUNK FOR netshop___0x45c52481c47b5e75_actual
    ; ---------------------------------------------------------------------------
    ; START OF FUNCTION CHUNK FOR netshop___0x45c52481c47b5e75_actual
    
    loc_140CD3AF4:                          ; CODE XREF: netshop___0x45c52481c47b5e75_actual-1BEFBBC
                    jmp     loc_1452E1DB0
    ; END OF FUNCTION CHUNK FOR netshop___0x45c52481c47b5e75_actual
    ; ---------------------------------------------------------------------------

    @param ea: linear address
    """
    ea = eax(ea)
    owner = owner or GetChunkOwner(ea)

    # Really invalid chunks may show up as being owned but a non-function,
    # often loc_14xxxxxx. So we can use this quick cheat to sort them.
    chunk_start = GetChunkStart(ea - 1)
    chunk_end = GetChunkEnd(ea)
    if not idc.remove_fchunk(owner, ea - 1) or not SetChunkStart(ea, chunk_start):
        if not idc.remove_fchunk(owner, ea) or not SetChunkEnd(ea, chunk_end):
            print("[warn] FixAllChunks: couldn't fix adjoining chunks at {:x}".format(ea))



def ZeroFunction(funcea=None, total=False):
    """
    ZeroFunction

    @param funcea: any address in the function
    """

    # See also:
    # def ida_funcs.find_func_bounds(*args) -> "int":
    #     r"""
    # 
    # 
    #     Determine the boundaries of a new function. This function tries to
    #     find the start and end addresses of a new function. It calls the
    #     module with \ph{func_bounds} in order to fine tune the function
    #     boundaries.
    
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        ea = func.start_ea

    if total == -1:
        ida_funcs.reanalyze_function(func)
        return idc.auto_wait() # process and return true
    if total == -2:
        r = ida_funcs.find_func_bounds(func, FIND_FUNC_DEFINE | FIND_FUNC_IGNOREFN )
        l = ['FIND_FUNC_UNDEF', 'FIND_FUNC_OK', 'FIND_FUNC_EXIST']
        idc.auto_wait()
        return (r, l[r])

    # Don't hold the func_t object open
    func = clone_items(func)
    print("[ZeroFunction] {:x}".format(ea))
    # Keep existing comments
    with Commenter(ea, 'func') as commenter:
        fnLoc = func.start_ea
        fnName = ida_funcs.get_func_name(fnLoc)
        flags = func.flags  # idc.get_func_attr(ea, FUNCATTR_FLAGS)
        # remove library flag
        idc.set_func_attr(fnLoc, FUNCATTR_FLAGS, flags & ~4)
        ida_name.del_local_name(fnLoc)
        ida_name.del_global_name(fnLoc)
        # RemoveAllChunks(ea)
        for start, end in idautils.Chunks(ea):
            idc.remove_fchunk(start, end)
        ida_funcs.del_func(func.start_ea)
        ida_auto.auto_make_proc(func.start_ea)
        idc.auto_wait()
        idc.set_color(fnLoc, CIC_FUNC, 0xffffffff)
        if not total:
            func = ida_funcs.func_t(fnLoc)
            res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
            if res == ida_funcs.FIND_FUNC_UNDEF:
                print("0x%x ZeroFunction: func passed flow to unexplored bytes" % fnLoc)
            elif res == ida_funcs.FIND_FUNC_OK:
                ida_funcs.add_func_ex(func)

            idc.auto_wait()
            # remove library flag (again)
            idc.set_func_flags(fnLoc, idc.get_func_flags(fnLoc) & ~4)
            # return original function name
            
            idc.set_name(fnLoc, fnName, idc.SN_NOWARN)



def Decompile(ea):
    func = clone_items(ida_funcs.get_func(ea))
    if func:
        # SetType(ea, "void __fastcall func(native args);")
        try:
            cfunc = ida_hexrays.decompile(ea)
        except DecompilationFailure:
            print(("0x%x: failed to decompile" % ea))
            ea = GetFuncEnd(ea)
            return

        fnName = GetFunctionName(ea)
        s = fnName.partition('::')

        d = GetIdbPath()
        d = d[:d.rfind(os.sep)] + os.sep + "decompiled"
        if not os.path.isdir(d):
            os.mkdir(d)
        d = d + os.sep + s[0]
        if not os.path.isdir(d):
            os.mkdir(d)
        fnName = s[0]
        if s[2]:
            fnName = s[2]
        with open(d + os.sep + fnName + ".c", "w") as f:
            f.write(str(cfunc))

        ea = GetFuncEnd(ea)


def DecompileAllAfter(ea):
    while ea != BADADDR and ea <= ida_ida.cvar.inf.max_ea:
        func = clone_items(ida_funcs.get_func(ea))
        if func:
            SetType(ea, "void __fastcall func(native args);")
            try:
                cfunc = ida_hexrays.decompile(ea)
            except DecompilationFailure:
                print(("0x%x: failed to decompile" % ea))
                ea = GetFuncEnd(ea)
                continue

            fnName = GetFunctionName(ea)
            s = fnName.partition('::')

            d = GetIdbPath()
            d = d[:d.rfind(os.sep)] + os.sep + "decompiled"
            if not os.path.isdir(d):
                os.mkdir(d)
            d = d + os.sep + s[0]
            if not os.path.isdir(d):
                os.mkdir(d)
            fnName = s[0]
            if s[2]:
                fnName = s[2]
            with open(d + os.sep + fnName + ".c", "w") as f:
                f.write(str(cfunc))

            ea = GetFuncEnd(ea)
            continue
        ea = ida_bytes.idc.next_head(ea, ida_ida.cvar.inf.max_ea)


def RemoveLocName(name):
    loc = LocByName(name)

    if loc != BADADDR:
        if not MakeNameEx(loc, '', idc.SN_NOWARN):
            return False

    return True


def RemoveRelocFunction(ea):
    MyMakeUnkn(ea, DOUNK_DELNAMES | DOUNK_EXPAND | DOUNK_NOTRUNC)
    RemoveLocName(Name(ea))
    for ea in obfu.combEx(ea, oneChunk=1, includeNops=1, includeJumps=1)[0]:
        PatchByte(ea, 0)


def RemoveLoneNullSubs():
    fns = idautils.Functions()
    for ea in fns:
        if GetFunctionName(ea).startswith("nullsub_"):
            codeRefs = set(idautils.CodeRefsTo(ea, flow=False))
            if len(codeRefs) < 2:
                DelFunction(ea)
                MakeNameEx(ea, "", idc.SN_AUTO | idc.SN_NOWARN)


def IsSameChunk(ea1, ea2):
    # Could probably be done simpler
    ea1 = eax(ea1)
    ea2 = eax(ea2)
    if not ida_funcs.is_same_func(ea1, ea2):
        return False
    owners1 = set(GetChunkOwners(ea1))
    owners2 = set(GetChunkOwners(ea2))
    # dprint("[IsSameChunk] owners1, owners2")
    print("[IsSameChunk] owners1:{}, owners2:{}".format(owners1, owners2))
    
    if owners1 == owners2 and len(owners1):
        for owner in owners1:
            if GetChunkNumber(ea1, owner) != GetChunkNumber(ea2, owner):
                return False

    return True

def IsSameFunc(ea1, ea2):
    return ida_funcs.is_same_func(ea1, ea2) or GetFuncName(ea1) and GetFuncName(ea1) == GetFuncName(ea2)
    ea1 = clone_items(ida_funcs.get_func(ea1))
    ea2 = clone_items(ida_funcs.get_func(ea2))
    if ea1 is None or ea2 is None:
        return False
    return ea1 == ea2

def PerformInSegments(func, segments=None, limit=None, predicate=None):
    """
    @param func: a string as a user enters it for Search Text in Core
    @param segments: segment names (default: ['.text'])
    @param predicate: function(address) -> address or None
    @param limit: maximum number of results to return

    @return: [address, ...] of found results result or [] if none found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)

    @eg: filter(IsFuncHead, FindInSegments("ba 10 00 00 00 e9 ?? ?? ?? ??"))
    """
    if not segments:
        segments = ['.text']

    ea = idc.BADADDR
    results = []
    seg_names = set()
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        seg_names.add(seg_name)
        if seg_name not in segments:
            continue
        seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)
        ea = seg_start - 1
        while ea < seg_end:
            ea += 1
            if callable(predicate):
                if predicate(ea):
                    if not predicate(ea):
                        continue

            if limit and len(results) > limit:
                return results
            r = func(ea)
            if r:
                results.append(r)

    return results

def DecodePrevInsn(ea=None):
    """
    DecodePrevInsn

    @param ea: linear address
    """
    ea = eax(ea)
    results = []
    start = ea - 16
    for i in range(start, ea):
        insn_len = idaapi.decode_insn(i)
        results.append((insn_len, ea - i, i))
        if True:
            if insn_len == ea - i:
                forceCode(i, ea)
                return i

    return results

def CreateInsns(ea=None, length=None, count=None, min_length=None, max_length=None):
    """
    DecodePrevInsn

    @param ea: linear address
    """
    ea = eax(ea)
    results = []
    start = ea
    if length:
        if length > ea:
            end = length
        else:
            end = start + length
    else:
        end = idc.BADADDR

    if not count:
        count = idc.BADADDR

    pos = ea
    idx = 0
    while pos < end and idx < count:
        insn_len = idaapi.decode_insn(pos)
        if insn_len:
            idx += 1
            results.append((insn_len, pos))
            pos += insn_len
        else:
            break

    fail = 0
    if pos > end:
        # dprint("[debug] pos, end")
        print("[debug] pos:{:x}, end:{:x}".format(pos, end))
        fail = 1

    if pos < end:
        print("[debug] pos:{:x}, end:{:x}".format(pos, end))
        fail = 1

    if idx > count:
        # dprint("[debug] pos, end")
        print("[debug] idx:{:x}, count:{:x}".format(pos, end))
        fail = 1
        
    if not fail:
        for _len, _pos in results: 
            forceCode(_pos, _len)
        return True, results

    return False, results

def FindRvaOffsetsTo(target, segments=['.pdata']):
    target = target & 0xffffffff
    r = PerformInSegments(lambda ea: idc.get_wide_dword(ea) == target)
    return r

def FindOffsetsTo(target, segments=None):
    r = PerformInSegments(lambda ea: idc.get_qword(ea) == target)
    return r
    #  for x in un: LabelAddressPlus(x, 'o_imagebase')

def FastFindRefsTo(target, segments=None):
    """
    @param func: a string as a user enters it for Search Text in Core
    @param segments: segment names (default: ['.text'])
    @param predicate: function(address) -> address or None
    @param limit: maximum number of results to return

    @return: [address, ...] of found results result or [] if none found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)

    @eg: filter(IsFuncHead, FindInSegments("ba 10 00 00 00 e9 ?? ?? ?? ??"))
    """
    if not segments:
        segments = ['.text']

    ea = idc.BADADDR
    results = []
    seg_names = set()
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        seg_names.add(seg_name)
        if seg_name not in segments:
            continue
        seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)
        ea = seg_start - 1
        while ea < seg_end:
            ea += 1
            if idc.get_wide_dword(ea) + ea + 4 == target:
                print("Found: {:x}".format(ea))
                return DecodePrevInsn(ea + 4)
                results.append(ea)

    return results

def ForceFindRefsTo(ea=None):
    """
    ForceFindRefsTo

    @param ea: linear address
    """
    ea = eax(ea)
    def finder(addr):
        if idc.get_wide_dword(addr) + addr + 4 == ea:
            return addr

    return PerformInSegments(finder)
    
def GetTarget(ea, flow=0, calls=1, conditionals=1, operand=0, failnone=False):
    if isIterable(ea):
        return [GetTarget(x, flow=flow, calls=calls, conditionals=conditionals, operand=operand, failnone=failnone)
                for x in ea]
    ea = eax(ea)
    if (isJmpOrObfuJmp(ea) and not isJmp(ea)):
        return MakeSigned(idc.get_wide_dword(ea + 4)) + ea + 7
    mnem = idc.print_insn_mnem(ea)
    force_mnem = GetMnemForce(ea)
    disasm = idc.GetDisasm(ea)
    disasm_force = GetDisasmForce(ea)
    if not mnem:
        if IsUnknown(ea) or IsData(ea):
            end = EaseCode(ea, forceStart=1, noExcept=1)
            mnem = idc.print_insn_mnem(ea)
        if not mnem:
            di_mnem = GetMnemDi(ea)
            msg = "{:x} couldn't get mnem from '{}' | ida: {} distorm: {})".format(ea, disasm, mnem, di_mnem)
            if di_mnem != mnem:
                raise AdvanceFailure(msg)
            return None if failnone else BADADDR
    
    if mnem == "jmp" or (calls and mnem == "call") or (conditionals and mnem[0] == "j"):
        opType = idc.get_operand_type(ea, operand)
        if opType in (idc.o_near, idc.o_mem):
            return idc.get_operand_value(ea, operand)
        if opType == idc.o_reg:
            # 'call    rax ; j_smth_metric_tamper'
            s = string_between('; ', '', disasm).strip()
            if s:
                result = eax(s)
                if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
                    return result

        #  print("[warn] can't follow opType {} from {:x}".format(opType, ea))

    if flow:
        if idc.next_head(ea) == ea + idc.get_item_size(ea) and idc.is_flow(idc.get_full_flags(idc.next_head(ea))):
            return idc.next_head(ea)
        else:
            if debug: print("{:x} no flow".format(ea))

    # print("{:x} GetTarget: no idea what to do with '{}' [flow={},calls={},conditionals={}]".format(ea, diida(ea), flow, calls, conditionals))
    return None if failnone else BADADDR

def GetTarget7(ea):
    mnem = idc.print_insn_mnem(ea)
    if not mnem:
        return idc.BADADDR
    
    opType0 = idc.get_operand_type(ea, 0)
    if mnem == "jmp" or mnem == "call" or mnem[0] == "j":
        if opType0 != o_near and opType0 != o_mem:
            print("Can't follow opType0 " + opTypeAsName(opType0))
            return idc.BADADDR
        else:
            return idc.get_operand_value(ea, 0)

    if idc.next_head(ea) == ea + idc.get_item_size(ea) and \
            idc.is_flow(idc.get_full_flags(idc.next_head(ea))):
        return idc.next_head(ea)

def opTypeAsName(n):
    for item in [x for x in dir(idc) if x.startswith('o_')]:
        if getattr(idc, item) == n: return item

def PickChunkOwner(ea=None):
    """
    PickChunkOwner

    @param ea: linear address
    """
    ea = eax(ea)
    return list(set([GetChunkOwner(ea)] + GetChunkOwners(ea)).intersection( [GetFuncStart(x) for x in xrefs_to(ea)]))


def GetChunkOwner(ea=None):
    """
    GetChunkOwner

    @param ea: linear address
    """
    ea = eax(ea)
    r = idc.get_fchunk_attr(ea, FUNCATTR_OWNER)
    # if debug: print("[idapy] idc.get_fchunk_attr(0x{:x}, FUNCATTR_OWNER): {:x}".format(ea, r))
    return r

def GetChunkOwners(ea=None, includeOwner=False):
    """
    GetChunkOwners

    @param ea: linear address
    """
    ea = eax(ea)
    
    #  https://www.hex-rays.com/products/ida/support/sdkdoc/classfunc__parent__iterator__t.html
    #  func_parent_iterator_t fpi(fnt);
    #  for ( bool ok=fpi.first(); ok; ok=fpi.next() )
    #      ea_t parent = fpi.parent();

    # func = GetChunk(ea)
    func = ida_funcs.get_fchunk(ea)
    # if debug: print("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
    if not func:
        return []
    
    #  func = ida_funcs.func_t(ea)
    it = ida_funcs.func_parent_iterator_t(func)
    ok = it.first()
    if ok == False:
        return [func.start_ea]
    
    owners = []
    while ok:
        parent = it.parent()
        owners.append(parent)
        ok = it.next()

    if includeOwner:
        r = idc.get_fchunk_attr(ea, FUNCATTR_OWNER)
        if r != idc.BADADDR:
            if r not in owners:
                #  print("[GetChunkOwners] FUNCATTR_OWNER: {:x} not listed in owners".format(r))
                # owners.append(r)
                pass

    for owner in owners[:]:
        if owner & 0xff00000000000000:
            print("[GetChunkOwners] removing BADADDR: {:x}".format(owner))
            owners.remove(owner)
        if not idaapi.is_func(idc.get_full_flags(owner)):
            if idaapi.get_func(owner) is None:
                print("[GetChunkOwners] stated owner {:x} of chunk {:x} is not a function".format(owner, ea))
            else:
                print("[GetChunkOwners] stated owner {:x} of chunk {:x} is not the function head".format(owner, ea))

    return owners

def GetChunkReferers(ea=None):
    """
    Get all referers of a chunk

    @param ea: linear address
    """
    ea = eax(ea)
    owners = list()

    tail = GetChunk(ea)
    if tail:
        for i in range(tail.refqty):
            owners.append(tail.referers[i])

    return owners


def RemoveOtherChunkOwners(ea, fn):
    fn = GetFuncStart(fn)
    owners = GetChunkOwners(ea)
    for owner in owners:
        if owner != fn:
            if ida_funcs.get_func_chunknum(ida_funcs.get_func(fn), ea) == 0:
                # This is a head chunk
                SetFuncEnd(owner, ea)
                idc.auto_wait()
                continue
            idc.remove_fchunk(owner, ea)
    return owners

def idc_append_func_tail(funcea, ea1, ea2):
    """
    Append a function chunk to the function
    
    @param funcea: any address in the function
    @param ea1: start of function tail
    @param ea2: end of function tail
    @return: 0 if failed, 1 if success
    
    @note: If a chunk exists at the specified addresses, it must have exactly
           the specified boundaries
    """

    print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, ea1, ea2))
    return idc.append_func_tail(funcea, ea1, ea2)


def SmartAddChunkImpl(us, start, end, debug=False):
    return ShowAppendFchunk(us, start, end)
    instructions = GetInsnLenths(start)
    noOwners = list()
    otherOwners = list()
    weOwnIt = list()
    noCode = list()
    funcStart = list()
    lines = []
    line = ""
    for addr, length in instructions:
        if len(line):
            if debug: print(line)
            lines.append(cleanLine(line))
            line = ""

        line = "0x{:x} {} {} ".format(addr, GetFunctionName(addr), GetDisasm(addr))
        fnName = GetFunctionName(addr)
        fnLoc = LocByName(fnName)
        owner = fnLoc
        chunk_list = list(idautils.Chunks(fnLoc))
        if not chunk_list:
            line += "noChunks/noOwners "
            for i in range(length):
                noOwners.append(addr + i)
                continue

        if owner == us:
            line += "weOwnIt "
            for i in range(length):
                weOwnIt.append(addr + i)
        elif not IsCode_(addr):
            line += "notCode "
            for i in range(length):
                noCode.append(addr + i)
        elif owner is None:
            line += "noOwner "
            for i in range(length):
                noOwners.append(addr + i)
        elif owner != us:
            line += "otherOwners "
            if IsFuncHead(addr):
                line += "IsFuncHead "
                for i in range(length):
                    funcStart.append(addr + i)
            else:
                for i in range(length):
                    otherOwners.append(addr + i)

    otherOwnerRanges = GenericRanger(otherOwners)
    weOwnItRanges = GenericRanger(weOwnIt)
    funcStartRanges = GenericRanger(funcStart)

    for r in funcStartRanges:
        MyMakeUnknown(r.start, r.length, DOUNK_NOTRUNC)
        ida_auto.auto_wait()
    noCode.extend(funcStart)

    if len(otherOwnerRanges):
        # hopefully this will remove multiple levels of chunking
        for unused in range(4):
            for r in otherOwnerRanges:
                addr = r.start
                chunks = [x for x in GetChunks(addr) if x["start"] <= addr <= x["end"]]
                for chunk in chunks:
                    fnLoc = LocByName(chunk["func"])
                    idc.remove_fchunk(fnLoc, chunk["start"])

    noOwners.extend(otherOwners)

    # could also use
    # owner = GetChunkOwner(addr)
    # and append_tail_chunk

    noCodeRanges = GenericRanger(noCode)
    for r in noCodeRanges:
        #  Really slow and pointless
        #  analyze(r.start, r.start + r.length)
        #  ida_auto.auto_wait()
        if not IsCode_(r.start):
            MakeCodeAndWait(r.start)

    noOwners.extend(noCode)

    noOwnerRanges = GenericRanger(noOwners)

    result = 0
    for r in noOwnerRanges:
        try:
            result += ShowAppendFchunk(us, r.start, r.last + 1)
        except:
            print("Unusual Chunk Issue")
            print(result)
            print((re.sub(r'(\d+)L', lambda x: "0x{:x}".format(int(x.group(1))), pprint.pformat(r))))

    #  if result == 0:
    #  print("0x%x: Nothing to do from 0x%x to 0x%x" % (us, start, end))

    # if it turns out we can't make a single chunk like this, we need to use:
    #  SetChunkStart(ownedAddresses[ownerName][0], fnAddr)
    #  if flowEnd > ownedAddresses[ownerName][-1]:
    #  SetChunkEnd(ownedAddresses[ownerName][0], flowEnd)

    if debug:
        print(("\n".join(lines)))
        print(line)
        return {'otherOwnerRanges': otherOwnerRanges, 'noOwnerRanges': noOwnerRanges, 'weOwnItRanges': weOwnItRanges,
                'noCodeRanges': noCodeRanges, 'funcStartRanges': funcStartRanges}
    return result

def GetChunkStart(ea=None):
    ea = eax(ea)
    return idc.get_fchunk_attr(ea, FUNCATTR_START)

def GetChunkStarts(ea):
    for cstart, cend in idautils.Chunks(ea):
        yield cstart


def GetChunkEnd(ea=None):
    ea = eax(ea)
    return idc.get_fchunk_attr(ea, FUNCATTR_END)

def GetChunkNumber(ea=None, funcea=None):
    """
    Get number of chunk in function

    @param ea: linear address

    @return: chunk number
            -1   - ea is not a chunk
            0    - ea is in head chunk
            1..n - tail chunk number
    """
    ea = eax(ea)
    if funcea is None:
        owner = ida_funcs.get_func(ea)
        # if debug: print(f"[idapy] owner = ida_funcs.get_func({ea:#x}):\n{pfh(owner)}")
    elif isinstance(funcea, ida_funcs.func_t):
        pass
    else:
        owner = ida_funcs.get_func(eax(funcea))
        # if debug: print(f"[idapy] owner = ida_funcs.get_func({funcea:#x}):\n" + pfh(owner))
    r = ida_funcs.get_func_chunknum(owner, ea)
    # if debug: print(f"[idapy] ida_funcs.get_func_chunknum(owner, {ea:#x}): {r}")
    return r

def FuncContains(funcea=None, ea=None):
    """
    FuncContains

    @param funcea: any address in the function
    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_func(eax(funcea))

    if not func:
        return 0
    else:
        funcea = func.start_ea
    
    return idafuncs.func_contains(func, ea)

def RemoveChunkOwner(ea=None, funcea=None):
    """
    SetChunkOwner
    Set a function as the possessing function of a function tail. The
    function should already refer to the tail (after append_func_tail).

    @param funcea: any address in the function
    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_func(eax(funcea))

    if not func:
        return 0
    else:
        funcea = func.start_ea

    return RemoveChunk(funcea, ea)

def SetChunkOwner(ea=None, funcea=None):
    """
    SetChunkOwner
    Set a function as the possessing function of a function tail. The
    function should already refer to the tail (after append_func_tail).

    @param funcea: any address in the function
    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_func(eax(funcea))

    if not func:
        return 0
    else:
        funcea = func.start_ea

    return idc.set_tail_owner(ea, funcea)
    #  return ida_funcs.set_tail_owner(func, ea)

def GetChunkReferer(ea=None, n=0):
    """
    GetChunkReferer

    @param ea: linear address
    """
    ea = eax(ea)
    return ida_funcs.get_fchunk_referer(ea, n)
    



    
    

def GetNumChunks(funcea=None):
    """
    GetNumChunks

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        return func.tailqty

    chunk = idc.first_func_chunk(ea)
    return chunk.tailqty + 1

    count = 0
    while chunk != BADADDR:
        print("[GetNumChunks] chunk: {}".format(count))
        count += 1
        chunk = idc.next_func_chunk(ea, chunk)
    return count

def IsChunkEnd(ea=None):
    """
    IsChunkEnd

    @param ea: linear address
    """
    ea = eax(ea)
    return IsChunk(ea) and GetChunkEnd(ea) == ea



def IsChunk(ea=None, owner=None):   
    """ 
    Is address in a tail chunk 

    @param ea: linear address

    @return: 1-yes, 0-no
    """

    #  if not isInt(ea) and not isString(ea):
        #  print("[IsChunk] typeof ea: {}".format(type(ea)))
    if isinstance(ea, ida_funcs.func_t):
        return ea.flags & ida_funcs.FUNC_TAIL
    ea = eax(ea)
    if GetChunkNumber(ea) == 0:
        return False
    if GetChunkOwners(ea, includeOwner=1):
        return True
    return False



def GetInsnLen(ea):
    return MyGetInstructionLength(ea)


def InsnLen(ea):
    return MyGetInstructionLength(ea)


def InsnRange(ea):
    return list(range(ea, ea + GetInsnLen(ea)))


def InsnRangePlusOne(ea):
    return list(range(ea, ea + GetInsnLen(ea) + 1))


def InsnRangeIgnoreFirst(ea):
    return list(range(ea + 1, ea + GetInsnLen(ea) - 1))


def InsnRangePlusOneIgnoreFirst(ea):
    return list(range(ea + 1, ea + GetInsnLen(ea) + 0))

def GetRbp(ea):
    ea = eax(ea)
    func = GetFunc(ea)
    if not func:
        print("return_unless: func")
        return 
    
    return idc.get_spd(ea) + func.frsize - func.fpd + func.frregs

def GetSpDiffEx(ea):
    return [x for x in [idc.get_sp_delta(addr) for addr in InsnRangePlusOne(ea)] if x is not None]

def SetSpDiffEx(ea, value=None):
    #  valid = GetSpDiffEx(ea)
    ea = eax(ea)
    if value is None:
        value = GetSpDiff(ea)
    #  # need to filter out `None` values that occur at the end of blocks
    for idx, addr in enumerate(InsnRange(ea)):
        idc.del_stkpnt(GetFuncStart(ea), addr)
    idc.add_user_stkpnt(ea, value)


def ZeroCode(ea, length):
    return
    MyMakeUnknown(ea, length, DOUNK_EXPAND | DOUNK_NOTRUNC)
    #  for addr in range(ea, ea + length):
    #  SetSpDiff(ea, 0)

def IsOffset64(ea=None, apply=False, loose=False):
    ea = eax(ea)
    _is_offset = (True
            and ea & (ptrsize() - 1) == 0
            and (loose or IsOff0(ea))
            and ida_ida.cvar.inf.min_ea <= idc.get_qword(ea) < ida_ida.cvar.inf.max_ea
            and not IsCode_(ea) 
            and re.match(r'd\w offset ', idc.GetDisasm(ea))
    )

    if apply and _is_offset:
        idc.del_items(ea, DOUNK_NOTRUNC, ptrsize())
        idc.create_qword(ea)
        idc.op_plain_offset(ea, 0, 0)
    return _is_offset

IsOffset = IsOffset64

def IsHeadChunk(ea):
    return GetChunkNumber(ea) == 0


def IsChunked(ea):
    #  return idc.get_fchunk_attr(address, FUNCATTR_START) < BADADDR
    return len(list(idautils.Chunks(ea))) > 1


def SetChunkStart(ea, value):
    # idc.set_fchunk_attr(ea, FUNCATTR_START, value)
    if not IsChunked(ea):
        raise TypeError("0x%x is not a chunk" % ea)
    if GetChunkEnd(ea) == value:
        return True

    tail = GetChunk(ea)
    if tail.flags & idc.FUNC_TAIL == 0:
        raise ChunkFailure("SetChunkEnd: {:x} was a funchead".format(ea))

    return ida_funcs.set_func_start(tail.start_ea, value)


def SetChunkEnd(ea, value):
    # idc.set_fchunk_attr(ea, FUNCATTR_END, value)
    if not IsChunked(ea):
        raise TypeError("0x%x is not a chunk" % ea)
    if GetChunkEnd(ea) == value:
        return True

    # get_fchunk(ea) # will return chunk ptr, to any function
    tail = GetChunk(ea)
    if tail.flags & idc.FUNC_TAIL == 0:
        raise ChunkFailure("SetChunkEnd: {:x} was a funchead".format(ea))

    # get_func_chunknum(GetFunc(ea), ea) -> int
    return ida_funcs.set_func_end(tail.start_ea, value)
    # return SetFuncEnd(ea, value)

def SetFuncOrChunkEnd(ea, value):
    if IsHeadChunk(ea):
        return SetFuncEnd(ea, value) 
    elif IsChunk(ea, value):
        return SetChunkEnd(ea, value)
    else:
        print("[SetFuncOrChunkEnd] {:x} Not a chunk/func head)".format(ea))
        return False

def thing(x):
    return x[1] + hex(x[2]) + x[3]

def GetChunk(ea=None):
    """
    GetChunk

    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_fchunk(ea)
    # if debug: print("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
    return func


def GetChunkPP(ea=None):
    """
    GetChunkPP

    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_fchunk(ea)
    r = pf(func)
    print(re.sub(r"((?:, |: |\[|\{)-?)(\d\d+)([,}\]])", lambda m: m[1] + hex(m[2]) + m[3], r))

def IsNiceFunc(funcea=None):
    """
    IsNiceFunc

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    ea = funcea

    good = bad = 0
    if IsOff0(ea):
        return True
    if GetInsnLen(ea) == 1:
        return False
    if idc.print_insn_mnem(ea) == "push":
        if idc.get_wide_word(ea) & 0xf0ff == 0x5040:
            good += 1
    if IsFuncSpdBalanced(ea):
        good += 1
    else:
        return False
    if _.all(GetFuncHeads(ea), lambda x, *a: IsCode_(ea)):
        good += 1
    else:
        return False
    if _.any(GetFuncHeads(ea), lambda x, *a: (idc.get_spd(ea) % 10) == 0 and idc.get_wide_byte(ea) == 0xe9):
        return False
    if _.any(GetFuncHeads(ea), lambda x, *a: idc.get_wide_dword(ea) & 0x002d8d48 == 0x002d8d48 or idc.get_wide_dword(ea) & 0x242c8748 == 0x242c8748):
        return False

    return good

def GetFuncInfo(funcea=None):
    """
    GetFuncInfo

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [GetFuncInfo(x) for x in funcea]

    funcea = ea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    output = [
            "Function {} starting at 0x{:x} consists of {} chunks".format(idc.get_func_name(funcea), funcea, GetNumChunks(funcea)),
    ]
    if IsNiceFunc(funcea):
        output.append("Nice Function")
    output.append(describe_target(ea))
    return output
                
def GetFuncChunked(ea):
    #  return GetChunk(ea) is not None
    return len(list(idautils.Chunks(ea))) > 1


def GetFuncChunkCount(ea):
    #  return GetChunk(ea) is not None
    return len(list(idautils.Chunks(ea)))

def FuncRefsTo(ea):
    if isinstance(ea, list):
        return [FuncRefsTo(x) for x in ea]
    fnNames = set()
    for fnLoc in idautils.CodeRefsTo(eax(ea), 0):
        if GetFuncName(fnLoc):
            fnNames.add(GetFuncName(fnLoc))
    return list(fnNames)

def GetFuncName(ea, end = None):
    if isinstance(ea, list):
        return [GetFuncName(x) for x in ea]
    if end is None:
        if ea is None:
            ea = idc.get_screen_ea()
        if isInt(ea):
            r = idc.get_func_name(ea)
            # if debug: print("[idapy] idc.get_func_name(0x{:x}): {}".format(ea, r))
            return r
    if isInt(end):
        if end > ea:
            fnNames = set()
            heads = Heads(ea, end)
            if heads:
                for head in Heads(ea, end):
                    fnNames.add(GetFuncName(head))
                if '' in fnNames:
                    fnNames.remove('')
                return fnNames
    return ''

    

def GetFuncSize(ea):
    if not IsChunked(ea):
        return GetFuncEnd(ea) - GetFuncStart(ea)
    return _.reduce([get_end(x) - get_start(x) for x in idautils.Chunks(ea)], lambda v, memo, *a: memo + v, 0)

def GetUnchunkedFuncSize(ea):
    return GetFuncEnd(ea) - GetFuncStart(ea)


def GetJumpTarget(ea):
    return GetTarget(ea, failnone=True) or GetRawJumpTarget(ea)
    """
    probably just a complicated way of doing:
    GetOperandValue(ea, 0)
    """

def GetRawJumpTarget(ea):
    # dprint("[GetRawJumpTarget] ea")
    if ea is None:
        return None
    
    inslen = MyGetInstructionLength(ea)
    if not inslen:
        return None
    result = MakeSigned(idc.get_wide_dword(ea + inslen - 4), 32) + ea + inslen
    #  print("[GetRawJumpTarget] result:{:x}".format(result))
    if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
        return result
    return None

class SkipJumpsChunkTargetError(Exception):
    pass

def SkipJumps(ea, name=None, returnJumps=False, returnTarget=False, until=None,
        untilInclusive=0, notPatched=False, conditional=True,
        skipShort=False, skipNops=False, iteratee=None, apply=False,
        abortOnChunkTarget=False, unpatch=False, *args, **kwargs):
    if isIterable(ea):
        return [SkipJumps(x, name=name, until=until, untilInclusive=untilInclusive, notPatched=notPatched, skipShort=skipShort, skipNops=skipNops, iteratee=iteratee, apply=apply, *args, **kwargs)
                for x in ea]
    if not isInt(ea):
        print("ea was not int: {}".format(type(ea)))
    # apply = 0
    target = ea
    count = 0
    jumps = []
    start = ea
    targets = [ea]
    match_NN_rest = [idaapi.NN_jmp]
    match_NN_initial = [idaapi.NN_jmp]
    mnem_start = MyGetMnem(ea)
    if conditional:
        match_NN_initial.extend(range(idaapi.NN_ja, idaapi.NN_jz + 1))
    if callable(iteratee):
        iteratee(ea, -1, *args, **kwargs)
    while target != idc.BADADDR and not IsUnknown(target):
        if target == ea:
            match_NN = match_NN_initial
        else:
            match_NN = match_NN_rest
        if unpatch: #  or not idautils.DecodeInstruction(target):
            if IsUnknown(target) or IsData(target):
                for addr in targets:
                    unpatched = UnpatchUntilChunk(addr)
                    if debug: print("{:x} UnpatchUntilChunk: {}".format(addr, unpatched))
                return jumps if returnJumps else True
        if not IsCode_(target):
            forceCode(target)



        if until:
            endix = max(0, len(targets)-2+untilInclusive)
            # dprint("[debug] endix")
            #  print("[debug] endix:{}".format(endix))
            
            if isInt(until):
                if target == until:
                    return jumps if returnJumps else targets[endix]
            elif callable(until):
                r = until(target)
                if r:
                    if r < 0:
                        return jumps if returnJumps else r
                    return jumps if returnJumps else targets[endix]
        # print(("0x%x: target: 0x%x: %s" % (ea, target, dii(target))))
        insn = idautils.DecodeInstruction(target)
        if not insn:
            disasm_forced = idc.generate_disasm_line(target, idc.GENDSM_FORCE_CODE)
            print("Couldn't find insn at {:x} | forced: {}".format(target, disasm_forced))
            if not ida_ua.can_decode(target):
                raise AdvanceFailure("couldn't find valid insn at {:x} (started jumping at {:x})".format(target, start))
            return jumps if returnJumps else target
        _tgt = GetTarget(target)
        if not IsValidEA(_tgt):
            if _tgt != idc.BADADDR:
                print("Invalid _tgt: {:x}, called from {:x}".format(_tgt, ea))
                raise AdvanceFailure("couldn't find valid target at {:x} (started jumping at {:x})".format(target, start))
                #  UnPatch(target, InsnLen(target))
                ida_auto.auto_recreate_insn(target)
                idc.auto_wait()
            _tgt = GetTarget(target)
        if count == 0 and insn.itype == idaapi.NN_call and SkipJumps(_tgt) != _tgt:
            newTarget = SkipJumps(_tgt)
            if apply:
                print("performing: nassemble(0x{:x}, \"call 0x{:x}\")".format(target, newTarget))
                nassemble(target, "call 0x{:x}".format(newTarget), apply=1)
            return jumps if returnJumps else newTarget

        if IsFunc_(_tgt) and not IsFuncHead(_tgt) and abortOnChunkTarget:
            if noExcept:
                return jumps if returnJumps else target
            raise SkipJumpsChunkTargetError([target, _tgt])

        if insn.itype in match_NN and (not skipShort or GetInsnLen(target) > 2):
            if insn.Op1.type in (idc.o_mem, idc.o_near):
                if notPatched:
                    if ida_bytes.get_original_byte(target) != idc.get_wide_byte(target):
                        break
                newTarget = insn.Op1.addr
                if newTarget and newTarget != BADADDR:
                    count += 1
                    if target not in jumps:
                        jumps.append(target)
                    if returnTarget and newTarget not in jumps:
                        jumps.append(newTarget)
                    if name:
                        LabelAddressPlus(newTarget, name, *args, **kwargs)
                    while skipNops and isNop(newTarget):
                        newTarget = newTarget + GetInsnLen(newTarget)
                        if not IsCode_(newTarget):
                            print("SkipJumps: Skipped NOPs right into a non-instruction: {:x} jumps".format(newTarget))
                            return jumps if returnJumps else -1
                    if iteratee:
                        rv = iteratee(newTarget, count, *args, **kwargs)
                        if rv and isInt(rv) and rv > 1:
                            newTarget = rv
                    targets.append(newTarget)
                    target = newTarget
                    continue
        break
    if apply:
        skipped = len(jumps) - 1
        # for jmp in [ea] + jumps: # [1:-1]:
        for jmp in jumps: # [1:-1]:
            if idc.get_item_size(jmp) >= 5:
                nassemble(jmp, "{} 0x{:x}".format(mnem_start if jmp == ea else "jmp", targets[-1]), apply=1)
            else:
                skipped -= 1

        if isRet(targets[-1]):
            PatchBytes(ea, "c3")
            SetFuncEnd(ea, ea + 1)

        if skipped:
            print("SkipJumps: {:x} streamlined {} jumps".format(ea, skipped))
    return jumps if returnJumps else target

def CountConsecutiveMnem(ea, mnem, sameChunk=False):
    ori_ea = ea
    insn_count = 0
    mnem = A(mnem)
    insn_lens = 0
    insn_len = 0
    cstart = GetChunkStart(ea)
    if sameChunk and cstart == idc.BADADDR:
        return (0, 0, 'no_chunk_start')
    while MyGetMnem(ea) in mnem and (not sameChunk or GetChunkStart(ea) == cstart):
        insn_lens += insn_len
        insn_count += 1
        insn_len = GetInsnLen(ea)
        ea += insn_len
        if IsCode_(ea) and IsFlow(ea): continue
        break
    return (insn_count, ea, insn_lens)

def AdvanceToMnem(ea, mnem, addrs=[]):
    ori_ea = ea
    insn_count = 0
    mnem = A(mnem)
    while MyGetMnem(ea) not in mnem:
        addrs.append(ea)
        insn_count += 1
        if isUnconditionalJmp(ea):
            ea = GetTarget(ea)
            continue
        ea += GetInsnLen(ea)
        if IsCode_(ea) and IsFlow(ea): continue
        break
    return (insn_count, ea, get_name_by_any(ea))

def AdvanceToMnemEx(ea, term='retn', iteratee=None, **kwargs):
    start_ea = ea
    insn_count = 1
    byte_count = 0
    insns = []
    private = AttrDict()
    opt = AttrDict(kwargs)
    if callable(term):
        term_callback = term
    else:
        term_callback = None
    term = A(term)
    #  ignore_flow = 1
    labels = dict()
    refs_from = defaultdict(set)
    refs_to = defaultdict(set)
    flow_refs_to = defaultdict(set)
    flow_refs_from = defaultdict(set)
    pending = set([ea])
    visited = set()
    final_loop = 0
    results = []
    while pending:
        ignore_flow = 1
        ea = pending.pop()
        if getattr(opt, 'ease', 0):
            if debug: print('ease option, calling easecode')
            EaseCode(ea, forceStart=1, noExcept=1)
        while ea not in visited and IsCode_(ea) and (IsFlow(ea) or ignore_flow):
            label = ''
            visited.add(ea)
            insn = diida(ea)
            mnem = diida(ea, mnemOnly=1)
            size = GetInsnLen(ea)
            is_call = isCall(ea)
            is_follow_call = is_call and getattr(opt, 'follow_calls', 0) and GetTarget(ea, flow=0, calls=1) != idc.BADADDR
            is_any_jmp = isAnyJmp(ea) and idc.get_operand_type(ea, 0) != o_displ
            is_unc_jmp = is_any_jmp and isUnconditionalJmp(ea)
            is_con_jmp = is_any_jmp and not is_unc_jmp

            if (is_any_jmp or is_follow_call) and GetTarget(ea) != BADADDR:
                target = GetTarget(ea)
                if not IsValidEA(target):
                    UnPatch(ea)
                    target = GetTarget(ea)
                    if not IsValidEA(target):
                        msg = "Invalid target: {:x} {}".format(ea, GetDisasm(ea))
                        raise AdvanceFailure(msg)
            else:
                target = None
            if is_any_jmp:
                refs_from[ea].add(target)
                refs_to[target].add(ea)

            if IsFlow(ea):
                # might need to check for out-of-chunk flow
                flow_refs_to[ea].add(idc.prev_head(ea))

            if term_callback and term_callback(ea) or not term_callback and mnem in (term):
                if getattr(opt, 'inclusive', 0):
                    final_loop = 1
                else:
                    break
            insn_de = de(ea)[0]
            if IsRef(ea):
                label = idc.get_name(ea)
                if label.startswith("0x"):
                    label = "loc_" + string_between('0x', '', label, inclusive=1)
                labels[ea] = label
            else:
                label = ''

            for r in range(5):
                #  EaseCode(ea)
                idc.generate_disasm_line(ea, 0)
                next_head = idc.next_head(ea)
                next_insn = ea + GetInsnLen(ea)
                if next_insn == next_head:
                    break
                if next_insn < next_head:
                    if not isUnconditionalJmp(ea) and not isRet(ea):
                        forceCode(next_insn)
                        continue
                    else:
                        next_insn = next_head = 0
                        break
                if next_insn > next_head:
                    if not IsHead(ea):
                        print('{:x} not head'.format(ea))
                    raise RuntimeError('{:x} somehow next_insn > next_head {:x} != {:x}'.format(ea, next_insn, next_head))

            if next_insn != next_head:
                raise RuntimeError('{:x} {:x} next_insn != next_head {:x} != {:x}'.format(start_ea, ea, next_insn, next_head))

            is_next_flow = next_insn and IsFlow(next_insn)

            if iteratee:
                response = \
                    iteratee(AttrDict({'label': label,
                        'insn' : insn.strip(),
                        'mnem' : mnem,
                        'insn_de' : insn_de,
                        'ea' : ea,
                        'size' : size,
                        'branch': is_any_jmp and not is_unc_jmp,
                        'call': is_call,
                        'label': label,
                        'next': next_insn if is_next_flow else target,
                        'target' : target,
                        'chunk': GetChunkNumber(ea),
                        'bytes': bytearray([idc.get_wide_byte(x) for x in range(ea, ea+size)]),
                        'private' : private }))

                if isinstance(response, dict):
                    if 'result' in response:
                        results.append(response['result'])
                    

            if label:
                if len(insns) and re.match(r'\s*j\w+ ' + re.escape(label), insns[-1]):
                    insns.pop()
                insns.append("{}:".format(label))

            if not mnem in (['nop']):
                insns.append("    {}".format(insn))
                insn_count += 1
                byte_count += size

            ignore_flow = 0

            if target and is_follow_call:
                ea = target
                if getattr(opt, 'ease', 0):
                    if debug: print('ease option, calling easecode')
                    EaseCode(ea)
                ignore_flow = 1
                continue

            if target and is_any_jmp:
                if is_unc_jmp:
                    ea = target
                    if getattr(opt, 'ease', 0):
                        if debug: print('ease option, calling easecode')
                        EaseCode(ea, forceStart=1)
                    ignore_flow = 1
                    continue
                else:
                    pending.add(target)

            ea += size
            if final_loop:
                break

    # dprint("[flow] flow_refs_to")
    #  print("[flow] flow_refs_to:{}".format(flow_refs_to))
        
    for _to, _from in flow_refs_to.items():
        for _src in _from:
            flow_refs_from[_src].add(_to)

    for _to, _from in refs_to.items():
        for _ea in _from:
            refs_from[_ea].add(_to)

    unvisited = pending - visited
    if unvisited:
        unvisited_str = "[warn] unvisited: {}".format(hex(unvisited))
        globals()['warn'] += 1
        print(unvisited_str)
        insns.append("; {}".format(unvisited_str))

    return AttrDict({
        'insns': insns,
        'insn_count': insn_count, 
        'byte_count': byte_count,
        'results': results,
        'refs_from': refs_from,
        'refs_to': refs_to,
        'flow_refs_from': flow_refs_from,
        'flow_refs_to': flow_refs_to,
        'start_ea': start_ea,
        'end_ea': ea,
    })

def RemoveNativeRegistration():
    l = [ 0x140A876C8, 0x140A87914, 0x140A89C94, 0x140A89E13, 0x140A8BDB8,
            0x140A8BFE0, 0x140A8C6F4, 0x140A8CE90, 0x140A8D000, 0x140A8D180,
            0x140A8E994, 0x140A8EB58, 0x140A8F1A0, 0x140A8F40C, 0x140CD9C40,
            0x140CD9F9C, 0x140CDA4F4, 0x140CE1090, 0x140CE25B8, 0x140CE2C20,
            0x140CE33DC, 0x140CE8460, 0x140CE8AC8, 0x140CEAADC, 0x140CEAD28,
            0x140D0E1B4, 0x140D124AC, 0x140D12AB0, 0x140D12BEC, 0x140D12D04,
            0x140D12D74, 0x140D15820, 0x140D73534, 0x140D73A10, 0x140D73B90,
            0x140D746A0, 0x140D76EA4, 0x140D77E9C, 0x140D7A6B4, 0x140D806E4,
            0x140D80884, 0x140D817B0 ]

    l = [ 0x143EE6004 ]
    r = []
    for ea in l:
        result = AdvanceToMnemEx(ea, 'retn', lambda x, *a: {'result': (x.ea, x.ea + x.size)})
        if result and len(result) > 2 and isinstance(result[2], list):
            r.extend( result[2] )
  
    print("ranging results")
    rx = GenericRanger([GenericRange(x[0], x[1]) for x in r], sort=1, outsort=1)
    pp(rx[-100:])
    print("saving... {} ranges".format(len(rx)))
    json_save_safe('e:/git/ida/2245-native-remove-2.json', [(x.start-0x140000000, x.end-x.start-0x140000000) for x in rx])
    ## j = json_load('e:/git/ida/2245-native-remove.json')

    # rx = [(0x140ca4486, 0xc), (0x140caeeb2, 0xc), (0x140cb1d41, 0x16), (0x140cb6b2e, 0xc), (0x140cd0085, 0xc), (0x140cf4ff1, 0xc), (0x140cfab1a, 0xc), (0x140d0e1b4, 0x5), (0x140d0e1bf, 0xb), (0x140d0e1d5, 0x17), (0x140d0e1f7, 0x17), (0x140d0e219, 0x17), (0x140d0e23b, 0x17), (0x140d0e25d, 0x17), (0x140d0e27f, 0x17), (0x140d0e2a1, 0x17), (0x140d0e2c3, 0x17), (0x140d0e2e5, 0x17), (0x140d0e307, 0x17), (0x140d0e329, 0x17), (0x140d0e34b, 0x17), (0x140d0e36d, 0x17), (0x140d0e38f, 0x17), (0x140d0e3b1, 0x17), (0x140d0e3d3, 0x17), (0x140d0e3f5, 0x17), (0x140d0e417, 0x17), (0x140d0e439, 0x17), (0x140d0e45b, 0x17), (0x140d0e47d, 0x17), (0x140d0e49f, 0x17), (0x140d0e4c1, 0x17), (0x140d0e4e3, 0x17), (0x140d0e505, 0x17), (0x140d0e527, 0x17), (0x140d0e549, 0x17), (0x140d0e56b, 0x17), (0x140d0e58d, 0x17), (0x140d0e5af, 0x17), (0x140d0e5d1, 0x17), (0x140d0e5f3, 0x17), (0x140d0e615, 0x17), (0x140d0e637, 0x17), (0x140d0e659, 0x17), (0x140d0e67b, 0x17), (0x140d0e69d, 0x17), (0x140d0e6bf, 0x17), (0x140d0e6e1, 0x17), (0x140d0e703, 0x17), (0x140d0e725, 0x17), (0x140d0e747, 0x17), (0x140d0e769, 0x17), (0x140d0e78b, 0x17), (0x140d0e7ad, 0x17), (0x140d0e7cf, 0x17), (0x140d0e7f1, 0x17), (0x140d0e813, 0x17), (0x140d0e835, 0x17), (0x140d0e857, 0x17), (0x140d0e879, 0x17), (0x140d0e89b, 0x17), (0x140d0e8bd, 0x17), (0x140d0e8df, 0x17), (0x140d0e901, 0x17), (0x140d0e923, 0x17), (0x140d0e945, 0x17), (0x140d0e967, 0x17), (0x140d0e989, 0x17), (0x140d0e9ab, 0x17), (0x140d0e9cd, 0x17), (0x140d0e9ef, 0x17), (0x140d0ea11, 0x17), (0x140d0ea33, 0x17), (0x140d0ea55, 0x17), (0x140d0ea77, 0x17), (0x140d0ea99, 0x17), (0x140d0eabb, 0x17), (0x140d0eadd, 0x17), (0x140d0eaff, 0x17), (0x140d0eb21, 0x17), (0x140d0eb43, 0x17), (0x140d0eb65, 0x17), (0x140d0eb87, 0x17), (0x140d0eba9, 0x17), (0x140d0ebcb, 0x17), (0x140d0ebed, 0x17), (0x140d0ec0f, 0x17), (0x140d0ec31, 0x17), (0x140d0ec53, 0x17), (0x140d0ec75, 0x17), (0x140d0ec97, 0x17), (0x140d0ecb9, 0x17), (0x140d0ecdb, 0x17), (0x140d0ecfd, 0x17), (0x140d0ed1f, 0x17), (0x140d0ed41, 0x17), (0x140d0ed63, 0x17), (0x140d0ed85, 0x17), (0x140d0eda7, 0x17), (0x140d0edc9, 0x17), (0x140d0edeb, 0x17), (0x140d0ee0d, 0x17), (0x140d0ee2f, 0x17), (0x140d388e1, 0xc), (0x140d3b989, 0x16), (0x140d3beb1, 0xc), (0x14105a02e, 0xc), (0x14106fdf5, 0xc), (0x1413dd9b3, 0x16), (0x1417f9be4, 0xc), (0x141805414, 0xc), (0x141807dd4, 0xc), (0x141814e2e, 0xc), (0x14184707b, 0xc), (0x141847cf1, 0xc), (0x14184ceaa, 0xc), (0x14184d9ec, 0x16), (0x141858afb, 0xc), (0x14185918b, 0x16), (0x141859d81, 0xc), (0x141859feb, 0xc), (0x14185b8ea, 0x16), (0x14185c951, 0xc), (0x14185d994, 0x16), (0x14185ea03, 0xc), (0x141862f55, 0x16), (0x14186500e, 0x16), (0x14186654f, 0xc), (0x141868fbc, 0x16), (0x141868fdd, 0xc), (0x141869a0a, 0x16), (0x14186d61c, 0x16), (0x14186d6a8, 0x16), (0x14187002e, 0x16), (0x141870a78, 0x16), (0x141873386, 0x16), (0x1418743eb, 0x16), (0x141876aa4, 0xc), (0x141876ec7, 0xc), (0x141879add, 0xc), (0x14187c147, 0xc), (0x1418807b2, 0x16), (0x141888708, 0x16), (0x1430f0b11, 0x16), (0x1430f225f, 0x16), (0x1430fc19c, 0x16), (0x1432b633a, 0x16), (0x1432b8253, 0x16), (0x1432b95e1, 0x16), (0x1432c4224, 0x16), (0x1432c9831, 0x16), (0x1432cbbb2, 0x16), (0x1432ce58a, 0x16), (0x1432cecd4, 0x16), (0x1432d25db, 0x16), (0x1432d2dc7, 0x16), (0x1432e1584, 0x16), (0x1432e1dee, 0x16), (0x1432e2a5c, 0x16), (0x1432e470c, 0x16), (0x1432e4b20, 0xc), (0x1432e517f, 0x16), (0x1434a61a4, 0x16), (0x1434c6811, 0xc), (0x1434caced, 0xc), (0x1434da779, 0x16), (0x1434df64b, 0x16), (0x1434f5eac, 0xc), (0x1434f63f5, 0xc), (0x1434f7a28, 0x16), (0x1434fcab4, 0xc), (0x143500c96, 0xc), (0x14351b52b, 0x16), (0x14351d5b4, 0xc), (0x143586ac1, 0x16), (0x14358ebae, 0x16), (0x143594191, 0xc), (0x143594f5b, 0x10), (0x1435a70b7, 0x16), (0x143612c2d, 0xc), (0x14361d5e4, 0xc), (0x143625ce5, 0xc), (0x14362b27a, 0x16), (0x14363eb5d, 0xc), (0x14363fde5, 0x16), (0x143855cc5, 0xc), (0x14385c40b, 0x16), (0x14385ce05, 0x16), (0x1438ccb7c, 0x16), (0x1438e9eda, 0xc), (0x1438ed62a, 0xc), (0x1438fbf0c, 0x16), (0x1438fda30, 0x16), (0x1438fefb0, 0xc), (0x14390c3c6, 0xc), (0x14397585f, 0xc), (0x14398cda4, 0x16), (0x143991691, 0xc), (0x1439ba6ad, 0xc), (0x1439c0317, 0x16), (0x1439c162b, 0xc), (0x143e66857, 0xc), (0x143e6a800, 0x16), (0x143e6aaba, 0xc), (0x143e6f1c9, 0xc), (0x143e89f04, 0x16), (0x143e8b285, 0xc), (0x143e8ffba, 0x16), (0x143e91637, 0x16), (0x143e91e82, 0xc), (0x143e97978, 0x16), (0x143e99fdf, 0xc), (0x143e9e693, 0xc), (0x143ea5100, 0xc), (0x143ea8509, 0xc), (0x143eb4fe3, 0x16), (0x143edc5ac, 0xc), (0x143edefdf, 0x16), (0x143ee0251, 0x16), (0x143ee2eb9, 0xc), (0x143ee35eb, 0xc), (0x143ee37e0, 0xc), (0x143ee3885, 0xc), (0x143ee6930, 0x16), (0x143eee28a, 0x16), (0x143eee859, 0xc), (0x143ef0aa7, 0x16), (0x143efce87, 0x16), (0x143efd56f, 0x16), (0x143f5ad21, 0xc), (0x143f5ec13, 0xc), (0x143f60dad, 0x16), (0x143f6160f, 0xc), (0x143f7420e, 0x16), (0x143f7d1db, 0x16), (0x143fa0acc, 0x16), (0x143fa6e47, 0xc), (0x143fabdfa, 0xc), (0x143fee656, 0x16), (0x143fefd23, 0xc), (0x143ffa264, 0x16), (0x143fff6b0, 0x16), (0x14400332a, 0x16), (0x144007c1d, 0xc), (0x144009070, 0xc), (0x14401606d, 0x16), (0x14402b442, 0x16), (0x144037e3d, 0xc), (0x1440394f8, 0xc), (0x14403c479, 0x18), (0x14404a0f7, 0xc), (0x14405c80e, 0xc), (0x14408adec, 0xc), (0x144097fd4, 0x16), (0x14409aba5, 0x16), (0x14409fdd7, 0xc), (0x1440a6d6d, 0x16), (0x1440b0f96, 0xc), (0x1440b6463, 0xc), (0x1440c108b, 0xc), (0x1440c14e7, 0xc), (0x1440cc8a9, 0xc), (0x1440edbf1, 0xc), (0x1440eeca5, 0x16), (0x1445a1983, 0x16), (0x1445df4cd, 0x16), (0x1445e01f2, 0x16), (0x1445e646c, 0xc), (0x1447dd8a2, 0x16), (0x1449d5fec, 0x16), (0x1449dc8c1, 0x16), (0x1449dfcb4, 0xc), (0x1449e0054, 0x16), (0x144a67d2e, 0xc), (0x144a69345, 0x16), (0x144a7fad4, 0xc), (0x144afd832, 0x16), (0x144b059f6, 0x16), (0x144b09191, 0x16), (0x144b0d550, 0xc), (0x144b108cb, 0x16), (0x144b27534, 0x16), (0x144b39628, 0xc), (0x144b3bc25, 0x16), (0x144b5e759, 0xc)]
    # print("deleting funcs")
    count = 0
    print("deleting items")
    pp(r[-100:])
    #  for r in j:
        #  start, _len = r
        #  _len = 0x140000000 - ~_len
        #  _len -= 1
        #  count += _len
        #  start += 0x140000000
    for r in rx:
        start = r.start
        end = r.end
        _len = end - start
        MakeUnknown(start, _len, DOUNK_EXPAND | DOUNK_NOTRUNC)
        #  ida_bytes.put_bytes(start, b'\xcc' * _len)
        MakeUnknown(r.start, r.end - r.start, DOUNK_EXPAND | DOUNK_NOTRUNC)
        idc.del_func(get_start(r))
        ida_bytes.put_bytes(get_start(r), b'\xcc' * (get_end(r) - get_start(r)))
        for ea in range(start, start + _len):
            idc.set_color(ea, idc.CIC_ITEM, 0x111606)
    #  for r in rx:
        #  print(r[0], 0, r[1] - r[0])
        # idc.del_items(r[0], 0, r[1] - r[0])
    print("deleted {}".format(count))

def MutatorCombinations():
    letters = ['A', 'B', 'C', 'D']
    for i in itertools.permutations(letters):
        l = list(i)
        o = AttrDict()
        for r in range(4):
            o[l[r]] = r
        if o.B > o.A and o.D > o.C and o.D > o.B:
            print(o)


def hexf16(n):
    if isinstance(n, str):
        return "{:>16}".format(n)
    return "{:16x}".format(n)

def h16list(l):
    return " ".join([hexf16(x) for x in l])

def FindStackMutators(ea=None):
    ea = eax(ea)
    b = asBytes(GetFuncCodeNoJunk(ea))
    i = GetFuncCodeIndexNoJunk(ea)

    #  b323
    #  .text:0000000143DCA64D 48 8B 45 18                          mov     rax, [rbp+18h]
    #  .text:0000000143DCA651 48 03 05 8F A5 83 FD                 add     rax, cs:_6
    #  .text:0000000143DCA658 48 8B 15 5D AA 8E FD                 mov     rdx, cs:o_loc_1416a602b
    #  .text:0000000143DCA65F 48 89 54 C5 70                       mov     [rbp+rax*8+70h], rdx

    #  .text:00000001440C5289 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C5290 48 03 05 AE 02 9A FC                 add     rax, cs:_32
    #  .text:00000001440C5297 48 8B 15 3A EF FF FF                 mov     rdx, cs:off_1440C41D8
    #  .text:00000001440C529E 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001440C52A6 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C52AD 48 03 05 09 D0 ED FF                 add     rax, cs:_31
    #  .text:00000001440C52B4 48 8B 15 0D 80 A9 00                 mov     rdx, cs:off_144B5D2C8
    #  .text:00000001440C52BB 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001440C52C3 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C52CA 48 03 05 B7 05 BE FC                 add     rax, cs:_30
    #  .text:00000001440C52D1 48 8B 15 BB 38 78 FD                 mov     rdx, qword ptr cs:loc_141848B93
    #  .text:00000001440C52D8 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001434B8E2D 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62
    #  .text:00000001434B8E34 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]
    #  .text:00000001434B8E3B 48 03 15 53 20 7F FD                 add     rdx, qword ptr cs:loc_140CAAE95
    #  .text:00000001434B8E42 48 89 84 D5 90 01 00 00              mov     [rbp+rdx*8+180h+arg_0], rax

    #  .text:00000001434D1774 1B8 48 8B 05 BA EE 81 FD                 mov     rax, cs:off_140CF0635
    #  .text:00000001434D177B 1B8 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+var_28]
    #  .text:00000001434D1782 1B8 48 03 15 14 C1 15 FE                 add     rdx, cs:qword_14162D89D
    #  .text:00000001434D1789 1B8 48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax
    #  
    #  .text:00000001434B8E2D 1B8 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62
    #  .text:00000001434B8E34 1B8 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]
    #  .text:00000001434B8E3B 1B8 48 03 15 53 20 7F FD                 add     rdx, cs:_33
    #  .text:00000001434B8E42 1B8 48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax
    #  
    #  48 8B 05 B9 D4 24 FE             mov rax, cs:off_14186E902
    #  48 8B 95 58 01 00 00             mov rdx, [rbp+180h+_align]
    #  48 03 15 A6 24 44 FD             add rdx, cs:qword_140A638FD
    #  48 89 84 D5 90 01 00 00 00       mov [rbp+rdx*8+180h+arg_0], rax


    # regular
    # 48 8B 85 88 00 00 00              mov     rax, [rbp+0A0h+_align]           A     
    # 48 03 05 AE 02 9A FC              add     rax, cs:_32                      B 
    # 48 8B 15 3A EF FF FF              mov     rdx, cs:loc_resume_at            C   
    # 48 89 94 C5 B0 00 00 00 00        mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          

    #  1180
    #  48 8b 05 21 dd 48 00          	mov rax, [o_loc_1447c082b] 
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+0x170]       
    #  48 03 15 94 bd c3 fc          	add rdx, [qword_140CB8ABC] 
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+0x1a0], rax 

    # 1737
    # 48 8b 45 20                   	mov rax, [rbp+0x20]
    # 48 03 05 26 cf 48 fc          	add rax, [loc_140D0FA51]
    # 48 8b 15 e8 be be ff          	mov rdx, [o_sub_14436ccdf]
    # 48 89 94 c5 90 00 00 00       	mov [rbp+rax*8+0x90], rdx
    #
    #
    # 323
    # 48 8b 45 18                       mov rax, [rbp+18h]                       A
    # 48 03 05 8f a5 83 fd              add rax, cs:_6                           B
    # 48 8b 15 5d aa 8e fd              mov rdx, cs:o_loc_1416a602b              C
    # 48 89 54 c5 70                    mov [rbp+rax*8+70h], rdx                 D

    results = []
    c = MakeColumns()
    # 00 01 02 03|04 05 06 07 08 09 10|11 12 13 14 15 16 17|18 19 20 21 22 23 24 25
    # 48 8b 45 ??|48 03 05 ?? ?? ?? ??|48 8b 15 ?? ?? ?? ??|48 89 94 c5 ?? ?? 00 00
    #         ^^align     ^^ offset            ^^ location             ^^ arg0
    # 48 8b 45 20|48 03 05 26 cf 48 fc|48 8b 15 e8 be be ff|48 89 94 c5 90 00 00 00
    #
    # 48 8b 45 18|48 03 05 8f a5 83 fd|48 8b 15 5d aa 8e fd|48 89 54 c5 70         

    # r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89\x94\xc5..\x00\x00', b, re.DOTALL)
    r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89(\x94\xc5..\x00\x00|\x54\xc5.)', b, re.DOTALL)
    while r:
        s, e = r.span()
        _b = b[s:e]
        _i = i[s:e]
        try:
            align, offset, location, arg = struct.unpack('=xxxbxxxixxxixxxxi', _b)
        except:
            align, offset, location, arg = struct.unpack('=xxxbxxxixxxixxxxb', _b)
        print("[raw] align:{:x}, offset:{:x}, location:{:x}, arg:{:x}".format(align, offset, location, arg))
        offset += _i[10] + 1
        location += _i[17] + 1
        # dprint("[debug] align, offset, location, arg")
        print("[debug] align:{:x}, offset:{:x}, location:{:x}, arg:{:x}".format(align, offset, location, arg))
        
        _ori_location = idc.get_qword(location)
        location = SkipJumps(_ori_location)
        retrace(location)
        location = SkipJumps(_ori_location)

        # dprint("[debug] location")
        print("[debug] location:{:x}".format(location))
        
        if (Qword(location) << 8 | Byte(location + 8)) == 0x2464ff0824648d48f8:
            PatchBytes(location, [0xc3] + MakeNops(8))

        _insn = idc.generate_disasm_line(location, 1)[0:32]
        _insn = ' '.join(builtins.map(str.strip, _insn.split(' ', 1)))
        if _insn == 'lea rsp, [rsp+8]' and GetManyBytes(location, 9) == b'H\x8dd$\x08\xffd$\xf8':
            idc.patch_byte(location, 0xc3)
            ForceFunction(location)
            _insn = 'retn'
        _vals = [align, idc.get_qword(offset), location, arg, idc.print_insn_mnem(location), _insn, _ori_location]
        row = _.zipObject(['align', 'offset', 'location', 'arg', 'mnem', 'insn', 'ori_location'], _vals)
        results.append( row )
        #  c.addRow(row)
        b = b[e:]
        i = i[e:]
        # r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89\x94\xc5..\x00\x00', b, re.DOTALL)
        r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89(\x94\xc5..\x00\x00|\x54\xc5.)', b, re.DOTALL)

    #  print('c\n{}'.format('\n'.join(_.uniq(str(c).split('\n')))))

    #  .text:00000001440C5289                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]           A
    #  .text:00000001440C5290                 48 03 05 AE 02 9A FC                 add     rax, cs:qword_140A65545          B
    #  .text:00000001440C5297                 48 8B 15 3A EF FF FF                 mov     rdx, cs:off_1440C41D8            C
    #  .text:00000001440C529E                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx      D
    #
    #  .text:00000001440C52A6                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]
    #  .text:00000001440C52AD                 48 03 05 09 D0 ED FF                 add     rax, cs:qword_143FA22BD
    #  .text:00000001440C52B4                 48 8B 15 0D 80 A9 00                 mov     rdx, cs:off_144B5D2C8
    #  .text:00000001440C52BB                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx
    #
    #  .text:00000001440C52C3                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]
    #  .text:00000001440C52CA                 48 03 05 B7 05 BE FC                 add     rax, cs:qword_140CA5888
    #  .text:00000001440C52D1                 48 8B 15 BB 38 78 FD                 mov     rdx, cs:off_141848B93
    #  .text:00000001440C52D8                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx
    #
    #  .text:00000001440C5289 0    TheArxan   48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]           A     
    #  .text:00000001440C5290 0    TheArxan   48 03 05 AE 02 9A FC                 add     rax, cs:_32                      B 
    #  .text:00000001440C5297 0    TheArxan   48 8B 15 3A EF FF FF                 mov     rdx, cs:loc_resume_at            C   
    #  .text:00000001440C529E 0    TheArxan   48 89 94 C5 B0 00 00 00 00           mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #  
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_33                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         
    #  
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_34                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         

    #  .text:00000001434B8E2D                 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62            C
    #  .text:00000001434B8E34                 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A
    #  .text:00000001434B8E3B                 48 03 15 53 20 7F FD                 add     rdx, cs:_num                     B
    #  .text:00000001434B8E42                 48 89 84 D5 90 01 00 00              mov     [rbp+rdx*8+180h+arg_0], rax      D

    #  .text:000000014403A903     48 8B 45 20                     mov     rax, [rbp+80h+_align]
    #  .text:000000014403A907     48 03 05 E2 C1 CD FC            add     rax, cs:_offset
    #  .text:000000014403A90E     48 8B 15 04 08 9D 00            mov     rdx, cs:off_144A0B119
    #  .text:000000014403A915     48 89 94 C5 90 00 00 00         mov     [rbp+rax*8+90h], rdx

    #---
    #  .text:00000001440CC80B 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:00000001440CC80F 0B8 48 03 05 20 54 99 FC            add     rax, qword ptr cs:loc_140A61C36
    #  .text:00000001440CC816 0B8 48 8B 15 0D CF 9C 00            mov     rdx, cs:off_144A9972A
    #  .text:00000001440CC81D 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx

    #  .text:00000001436120AD 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:00000001436120B1 0B8 48 03 05 AA E7 6C FD            add     rax, cs:qword_140CE0862
    #  .text:00000001436120B8 0B8 48 8B 15 0B 42 69 FD            mov     rdx, cs:off_140CA62CA
    #  .text:00000001436120BF 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx
    #
    #  .text:000000014404A11D 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:000000014404A121 0B8 48 03 05 07 29 0A 00            add     rax, cs:qword_1440ECA2F
    #  .text:000000014404A128 0B8 48 8B 15 9B B7 F5 FF            mov     rdx, cs:off_143FA58CA
    #  .text:000000014404A12F 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx 
    #
    # 00 01 02 03|04 05 06 07 08 09 10|11 12 13 14 15 16 17|18 19 20 21 22 23 24 25
    # 48 8b 45 ??|48 03 05 ?? ?? ?? ??|48 8b 15 ?? ?? ?? ??|48 89 94 c5 ?? ?? 00 00
    #         ^^align     ^^ offset            ^^ location             ^^ arg0
    # 00 01 02 03 04 05 06|07 08 09 10 11 12 13|14 15 16 17 18 19 20|21 22 23 24 25 26 27 28
    # 48 8b 05 ?? ?? ?? ??|48 8b 95 ?? ?? 00 00|48 03 15 ?? ?? ?? ??|48 89 84 d5 ?? ?? 00 00
    # C        ^^ location|A        ^^ align   |B        ^^ offset  |D           ^^ arg0
    
    #  .text:00000001440C5289 0    TheArxan   48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]           A     
    #  .text:00000001440C5290 0    TheArxan   48 03 05 AE 02 9A FC                 add     rax, cs:_32                      B 
    #  .text:00000001440C5297 0    TheArxan   48 8B 15 3A EF FF FF                 mov     rdx, cs:loc_resume_at            C   
    #  .text:00000001440C529E 0    TheArxan   48 89 94 C5 B0 00 00 00 00           mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #  
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_33                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         
    #  
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_34                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         

    #  b1180
    #  48 8b 05 21 dd 48 00          	mov rax, [loc_resume_at]             C
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+_align]                A
    #  48 03 15 94 bd c3 fc          	add rdx, [_34]                       B
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+0x1a0], rax           D
    #
    #  b1180 (reordered)
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+_align]                A
    #  48 03 15 94 bd c3 fc          	add rdx, [_offset]                   B
    #  48 8b 05 21 dd 48 00          	mov rax, [location]                  C
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+arg_0], rax           D
    #
    #  48 8b 95 70 01 00 00             mov rdx, [rbp+190h+_align]        143ad2622 A 0 offset   location align
    #  48 03 15 1a a4 c8 fd             add rdx, cs:offset                143ad2629 B 1 location align    ofset
    #  48 8b 05 9a fa 01 00             mov rax, cs:location              143f9ab4a C 2 align    offset   location
    #  48 89 84 d5 a0 01 00 00          mov [rbp+rdx*8+190h+_arg_0], rax  143ad2630 D 3 arg      arg      arg
    #
    #  b2245 
    #  48 8B 85 88 00 00 00             mov rax, [rbp+0A0h+_align]           A     
    #  48 03 05 AE 02 9A FC             add rax, cs:_32                      B 
    #  48 8B 15 3A EF FF FF             mov rdx, cs:loc_resume_at            C   
    #  48 89 94 C5 B0 00 00 00          mov [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #
    #  .text:0000000143D123B4  48 8B 05 A5 DF 24 00               mov     rax, cs:o_loc_1447c082b
    #  .text:0000000143D123BB  48 8B 95 70 01 00 00               mov     rdx, [rbp+190h+_align]
    #  .text:0000000143D123C2  48 03 15 F3 66 FA FC               add     rdx, cs:qword_140CB8ABC
    #  .text:0000000143D123C9  48 89 84 D5 A0 01 00+              mov     [rbp+rdx*8+190h+_arg_0], rax
    #
    #  48 03 15 f3 66 fa fc
    #
    # valid permutations (A=0, B=1...)
    perms = [[0,1,2,3], [0,2,1,3], [2,0,1,3]]
    
    _results = []
    _header = ''
    field_names = \
        ['align',                'offset',         'location',       'arg'                   ]
    l = [7,                      7,                7,                8                       ] # instruction lengths
    r = [b'\x48\x8b...\x00\x00', b'\x48\x03.....', b'\x48\x8b.....', b'\x48\x89....\x00\x00' ] # regexes
    s = ['xxxi',                 'xxxi',           'xxxi',           'xxxxi'                 ] # struct.unpack parts
    four = list(range(4))

    for p in perms:
        b = asBytes(GetFuncCodeNoJunk(ea))
        i = GetFuncCodeIndexNoJunk(ea)

        regex = re.compile(r[p[0]] + r[p[1]] + r[p[2]] + r[p[3]], re.DOTALL)
        struc = '='      + s[p[0]] + s[p[1]] + s[p[2]] + s[p[3]]
        _tran = [p[x] for x in four]

        rev_index = [field_names[_tran[x]] for x in four]
        index = AttrDict(_.zipObject(rev_index, four))
        if not _header:
            _header = "                 {}".format(h16list([rev_index[x] for x in four]))

        match = re.search(regex, b)
        while match:
            mstart, mend = match.span()
            _b = b[mstart:mend]
            _i = i[mstart:mend]

            unpacked = struct.unpack(struc, _b)
            # cheating here, because the insn lens are always the same
            start_ea   = [_i[sum(l[0:x])] for x in four]
            end_ea     = [y + l[x] for x, y in  enumerate(start_ea)]
            #  start_ea   = [_i[0*7], _i[1*7], _i[2*7], _i[3*7]+1]
            #  end_ea     = [_i[0*6]+1, _i[1*6]+1, _i[2*6]+1, _i[3*7]+2]
            ptr        = [end_ea[j] + unpacked[j] for j in four]
            value      = [idc.get_qword(x) for x in ptr]

            #  idx = 0
            #  for start, end in zip(start_ea, end_ea):
                #  print("{:32} {:24} {:x} {} {} {:8} {:8} {:8}".format(idii(start), bytes_as_hex(getCode(start, end - start)), start, idx, p[idx], field_names[_tran[idx]], rev_index[idx], index.get(rev_index[idx])))
                #  idx += 1

            #  print(_header)
            #  print("                 {}".format((h16list(['-' * 16] * 4))))
#  
            #  print("unpacked:        {}".format((h16list(unpacked))))
            #  print("ptr:             {}".format((h16list(ptr))))
            #  print("value:           {}".format((h16list(value))))

            #                              align           offset         location              arg
            #  unpacked:                      88           ac3e30          167ee34               b0
            #  ptr:                    1434de50e        143fa22bd        144b5d2c8        1434de54c
            #  value:           c30000000000841f               31        143e73f80 89584503d8f75445


            # dprint("[indx] index, _tran")
            # print("[indx] index:{}, _tran:{}".format(index, _tran))
            
            _vals = [
                unpacked[index.align],
                value[index.offset],
                value[index.location],
                unpacked[index.arg],
            ]

            vals = [0, 0, 0, 0]
            obj_vals = AttrDict()
            for x, _p in enumerate(p):
                vals[x] = _vals[_p]

            for x in four:
                obj_vals[rev_index[x]] = vals[x]

            #  print("obj_vals: {}".format(obj_vals))
            _mnem     = idc.print_insn_mnem(obj_vals.location)
            _insn     = diida((obj_vals.location))
            if _insn == 'lea rsp, [rsp+8]' and GetManyBytes(obj_vals.location, 9) == b'H\x8dd$\x08\xffd$\xf8':
                ZeroFunction(obj_vals.location, 1)
                PatchBytes(obj_vals.location, [0xc3])
                #  ZeroFunction(obj_vals.location, 1)
                idc.auto_wait()
                idc.add_func(obj_vals.location, obj_vals.location+1)
                idc.auto_wait()
                remake_func(obj_vals.location)
                _insn = 'retn'
                _mnem = 'retn'
            obj_vals["ori_location"] = obj_vals["location"]
            obj_vals["location"] = SkipJumps(obj_vals["location"])

            _mnem     = GetMnemDi(obj_vals.location)
            _insn     = diida((obj_vals.location))
            obj_vals["mnem"] = _mnem 
            obj_vals["insn"] = _insn

            # from simple version:
            # row = _.zipObject(['align', 'offset', 'location', 'arg', 'mnem', 'insn', 'ori_location'], _vals)
            
            #  print("                 {}".format((h16list(['-' * 16] * 4))))
            _results.append("                 {}".format((h16list(vals))))
            print(_results[-1])
            #  print("                 {}\n".format((h16list(['=' * 16] * 4))))

            
            results.append(obj_vals)
            b = b[mend:]
            i = i[mend:]
            match = re.search(regex, b)
            #  print("next match: {}".format(match))

    #  _results = list(set(_results))
    #  _results.sort()
    #  print(_header)
    #  print("                 {}".format((h16list(['-' * 16] * 4))))
    #  print("\n".join(_results))

    results = _(results).chain().uniq().sortBy('offset').map(lambda v, *a: AttrDict(v)).value()

    #  location    align offset arg   ori_location mnem insn                       
    #  ----------- ----- ------ ----- ------------ ---- -------------------------- 
    #  0x1446c0b01 0x168 0x30   0x1a0 0x1446c0b01  cmp  cmp [dword_14258A208], ebx 
    #  0x140a91e94 0x168 0x31   0x1a0 0x140a91e94  retn retn                       
    #  0x1435dcb35 0x168 0x32   0x1a0 0x1435dcb35  push push rbp  

    c.addRows(_.map(results, lambda x, *a: _.only(x, 'location', 'offset', 'insn')))
    with Commenter(ea, 'func') as cm:
        cm.clear()
        cm.add("Arxan Stack Return Manipulations:\n\n" + str(c))
    #  print(c)
    #  pp(hex(results))
    return results


    # struct.unpack('BBBbBBBiBBBiBBBBi')

def find_element_in_list(element, list_element):
    try:
        index_element = list_element.index(element)
        return index_element
    except ValueError:
        return None


def fixRdata(ea):
    global st_limit
    if idc.get_full_flags(ea) & 0x30500500 == 0x30500500 and GetDisasm(ea).startswith("dq offset"):
        target = Qword(ea)
        if target != ItemHead(Qword(ea)):
            MakeCodeAndWait(target)
            # obfu.comb might be similar to EaseCode, but perhaps follows jumps?
            obfu.comb(target, 150, limit=st_limit)
            ida_auto.auto_wait()
            MyMakeFunction(target)
            ida_auto.auto_wait()


def fixAllRdata(ea):
    while SegName(ea) == ".rdata":
        try:
            fixRdata(ea)
        except:
            pass
        ea = idc.next_head(ea)


def SetSpd(ea, value):
    idc.del_stkpnt(ea, ea)
    targetValue = value
    currentValue = GetSpd(ea)
    adjustment = targetValue - currentValue
    print(("SetSped adjustment: 0x%x" % adjustment))
    idc.add_user_stkpnt(ea, adjustment)


sub_colors = dict()


def colorSubs(subs, colors=[], primary=[]):
    global sub_colors
    color = ''
    for f in subs:
        if f in sub_colors:
            color = ('"{}" {}'.format(f, sub_colors[f]))
        else:
            color = ('"{}" [ style=filled ] # default'.format(f))
            ea = eax(f)
            if not IsFunc_(ea):
                if idc.get_segm_name(ea) == '.rdata':
                    if IsOff0(ea):
                        color = ('"{}" [ fillcolor="#ffbb88" style=filled shape=cds label="vtable_{}" ]'.format(f, f))
                    elif IsStrlit(ea):
                        color = ('"{}" [ fillcolor="#ffbbcc" style=filled shape=note label="\\"{}\\"" ]'.format(f, asStringRaw(idc.get_strlit_contents(ea))))
                    else:
                        color = ('"{}" [ style="invis" ]'.format(f))
                else:
                    color = ('"{}" [ ] '.format(f))
                # color = color.replace('filled', 'dotted')
            elif IsChunked(ea):
                color = ('"{}" [ style=filled ] '.format(f))
                # color = color.replace('filled', 'dotted')

            if f.startswith('pHandle::'):
                color = ('"{}" [ fillcolor="1 0.4 1" style=filled ]'.format(f))
            if f.startswith('sub_'):
                color = ('"{}" [ fillcolor="0.6 0.6 0.6" style=filled ]'.format(f))
            if f.startswith('return_'):
                color = ('"{}" [ fillcolor="0.5 0.4 1" style=filled ]'.format(f))
            if ~f.find('_impl'):
                color = ('"{}" [ fillcolor="#ffbb33" style=filled ]'.format(f))
            if re.match(r'[A-Z]+::', f):
                color = ('"{}" [ fillcolor="#ffbb33" style=filled ]'.format(f))

            if "::m_" in f:
                color = ('"{}" [ fillcolor="#4488CC" style=filled ]'.format(f))

            if idc.get_func_flags(idc.get_name_ea_simple(f)) != -1 and \
                idc.get_func_flags(idc.get_name_ea_simple(f)) & idc.FUNC_LIB == idc.FUNC_LIB:
                color = ('"{}" [ fillcolor="#aabbff" style=filled ]'.format(f))

            if idc.get_name_ea_simple(f + "_RELOC_11") < BADADDR:
                color = ('"{}" [ fillcolor="0.2 0.4 1" style=filled ]'.format(f))

            if f in primary:
                color = ('"{}" [ fillcolor="#ff4488" style=filled ]'.format(f))
                sub_colors[f] = color

            if len(color):
                colors.append(color)
                if not f in color:
                    sub_colors[f] = color

    return colors

def TruncateThunks():
    # for ea in FunctionsMatching('sub_'):
    with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
        for ea in idautils.Functions():
            if ea + GetInsnLen(ea) < GetFuncEnd(ea):
                mnem = idc.print_insn_mnem(ea)
                if mnem and mnem.startswith('jmp'):
                    target = GetTarget(ea)
                    if not IsSameChunk(target, ea):
                        print("TruncateThunks", hex(ea), GetFuncName(ea))
                        SetFuncEnd(ea, ea + MyGetInstructionLength(ea))

chart2 = list()
colors = list()


def RecurseCallers(ea=None, width=512, data=0, makeChart=0, exe='dot', depth=5, includeSubs=0, fixVtables=False, new=False):
    global chart2
    global colors

    if new:
        chart2.clear()
        colors.clear()
    if ea is None:
        ea = idc.get_screen_ea()
    fnName = idc.get_func_name(ea)
    callers = list()
    visited = set([])
    pending = set(A(ea))
    vtableRefs = list()
    _depth = 0
    count = 0
    added = [1]
    _datarefs = data
    functionRefs = collections.defaultdict(set)
    namedRefs = collections.defaultdict(set)
    fwd = dict()
    rev = dict()
    chart = list()

    while _depth < depth and len(pending) and len(pending) < width:
        #  _depth = _depth - 1
        ea = pending.pop()
        count += 1
        added[0] -= 1
        if added[0] < 1:
            _depth += 1
            added.pop()
            #  print("_depth: %d count: %d" % (_depth, count))
        visited.add(ea)

        target = ea
        targetName = "0x%x" % target
        if Name(target):
            targetName = Name(target)
        if GetFunctionName(target):
            targetName = GetFunctionName(target)

        # Trace backwards the hard way if required
        if GetFuncStart(target) == BADADDR or not idc.get_full_flags(target) & FF_REF:
            if 0:
                while GetFuncStart(target) == BADADDR:
                    if idc.get_full_flags(target) & FF_FLOW:
                        prevEa = idc.prev_head(target)
                        if prevEa == BADADDR:
                            raise "0x%x: idc.prev_head returned BADADDR: details"
                        target = prevEa
                    else:
                        break

            visited.add(target)

        fnStart = GetFuncStart(target)

        if fnStart < BADADDR:
            target = fnStart
            visited.add(target)
            # targetName = GetFunctionName(target) # GetFunctionName
            _name = Name(target)
            if hasAnyName(idc.get_full_flags(target)):
                _name = GetFunctionName(target)
            if IsFunc_(target):
                _name = GetFunctionName(target)
            #  if _name:
            #  targetName = Name(target) # GetFunctionName
            if _name is not None:
                targetName = _name
            callers.append(targetName)

        # visited.add(target)

        refs = list(idautils.CodeRefsTo(target, 0))
        if _datarefs:
            refs.extend([x for x in idautils.DataRefsTo(target) if idc.get_segm_name(x) != '.pdata'])
            #  _datarefs = 0

        rdata_refs = [x for x in xrefs_to(target) if SegName(x) == '.rdata']
        refs.extend(rdata_refs)

        extra_refs = set([])
        for ref in refs:
            refName = "0x%x" % ref
            if Name(ref):
                refName = Name(ref)
            if GetFunctionName(ref):
                refName = GetFunctionName(ref)
            if SegName(ref) == '.rdata':
                addr = ref
                while not Name(addr).startswith('??_7') and SegName(addr) == '.rdata' and GetDisasm(addr).startswith(
                        'dq offset'):
                    addr = idc.prev_head(addr)
                if Name(addr).startswith('??_7'):
                    refName = Demangle(Name(addr), DEMNAM_FIRST)
                    if not refName:
                        refName = "unknown_vftable_0x%x" % addr
                    vtableRefs.append("%s_0x%x" % (refName, addr))
                    functionRefs[target].add(addr)
                    refName = refName.replace("::`vftable'", "")
                    refName = "{}::m_{:x}".format(refName, ref - addr)
                    chart.append([refName, targetName])
                    namedRefs[target].add(refName)
                    if fixVtables:
                        ClassMakerFamily(ea=addr, redo=1)

            #  refName = "{};;{}".format(refName, _depth)
            rev[targetName] = refName
            chart.append([refName, targetName])
            functionRefs[target].add(ref)

            #  targetName = GetFunctionName(target)
            #  _fnName = targetName
            #  while _fnName.endswith("_0"):
            #  _fnName = _fnName[:-2]
            #  extra_refs.add(LocByName(_fnName))

        # refs = set(filter(lambda x: GetFuncStart(x), refs))
        refs = set(refs)
        refs |= extra_refs
        refs -= visited
        size1 = len(pending)
        pending |= refs
        size2 = len(pending) - size1
        added.append(size2)
        #  print("refs: %s" % refs)
        #  print("pending: %s" % pending)
        #

    for (left, right) in _.uniq(chart):
        if debug: print(("left: {}, right: {}".format(left, right)))
        chart2.append([left, right])
        continue

        #  visited = set()
        #  if not includeSubs:
            #  while (right.startswith("loc_") or right.startswith("sub_")) and right in fwd and right != fwd[right]:
                #  right = fwd[right]
                #  if right in visited:
                    #  break
                #  visited.add(right)
                #  if debug: print(("right: %s" % right))
        #  else:
            #  while IsChunked(get_name_ea_simple(right)):
                #  right = fwd[right]
                #  if right in visited:
                    #  break
                #  visited.add(right)
                #  if debug: print(("right: %s" % right))
  
        #  visited = set()
        #  if not includeSubs:
            #  while (left.startswith("loc_") or left.startswith("sub_")) and left in rev and left != rev[left]:
                #  left = rev[left]
                #  if left in visited:
                    #  break
                #  visited.add(left)
        #  else:
            #  while IsChunked(get_name_ea_simple(left)):
                #  left = rev[left]
                #  if left in visited:
                    #  break
                #  visited.add(left)
                #  if debug: print(("left: %s" % left))


    if len(chart2):
        chart2 = _.uniq(chart2)
        chart2 = list([x for x in chart2 if x[0] != x[1]])
        #  pp(chart2)

    subs = []
    call_list = []
    for x in chart2:
        f = x[0]
        ea = eax(f)
        if not IsFunc_(ea):
            if idc.get_segm_name(ea) == '.rdata':
                if IsOff0(ea):
                    pass
                elif IsStrlit(ea):
                    pass
                else:
                    continue

        subs.append(x[0])
        subs.append(x[1])
        if len(x) > 2:
            call_list.append('"{}" -> "{}" {};'.format(x[0], x[1], " ".join(x[2:])))
        else:
            call_list.append('"{}" -> "{}";'.format(x[0], x[1]))
    call_list = _.uniq(call_list)
    colors = colorSubs(subs, colors, [fnName])
    if makeChart:
        dot = __DOT.replace('%%MEAT%%', '\n'.join(colors + call_list))
        chartName = idc.get_name(ea, ida_name.GN_VISIBLE) or 'default'
        r = dot_draw(dot, name=chartName, exe=exe)
        print("dot_draw returned: {}".format(r))
        if isinstance(r, tuple):
            if not r[0]:
                print("dot_draw error: {}".format(r[1]))
            else:
                print("dot_draw good: {}".format(r[1]))
                r = subprocess.getstatusoutput('start {}'.format(chartName + '.svg'))
                print("subprocess returned: ", r)
    named = []
    l = []
    for ref, s in list(functionRefs.items()):
        l.extend([GetFunctionName(e) for e in s])
        named = list([x for x in l if idc.hasUserName(idc.get_full_flags((LocByName(x))))])
    named.sort()
    if named:
        print(("Named Refs: %s" % named))

    l = []
    natives = []
    for ref, s in list(functionRefs.items()):
        l.extend([GetFunctionName(e) for e in s])
        natives = [x for x in l if ~x.find("::")]
        natives = [re.sub(r'(_0)+$', '', x) for x in natives]
    natives = list(natives).sort()
    if natives:
        print(("Natives: %s" % natives))

    l = []
    vtable = []
    for ref, s in list(namedRefs.items()):
        vtable.extend(list(s))
    vtable.sort()
    if vtable:
        print(("Vtable Refs: %s" % vtable))

    if vtableRefs:
        print("Vtables: %s" % vtableRefs)

    if len(pending):
        print(("0x%x: Leaving recurse callers too many pending: %d" % (ea, len(pending))))

    globals()['functionRefs'] = functionRefs

    if makeChart:
        return chart2

    return AttrDict({
            'named': named,
            'natives': natives,
            'vtableRefs': vtableRefs,
            'vtables': vtable,
    })


def RecurseCallersChart(ea, width=512, includeSubs=0, depth=5, exe='dot', new=False):
    par = locals()
    chart = RecurseCallers(makeChart=1, data=1, **par)
    for left, right in chart:
        print(('"{}" -> "{}";'.format(left, right)))

def FindDestructs(pattern="f6 c3 01 74 08 48 8b cf e8"):
    addrs = FindInSegments(pattern)
    def recurse(ea):
        for ref in xrefs_to(GetFuncStart(ea)):
            if idc.get_segm_name(ref) == '.rdata':
                print('0x{:x} {}'.format(ref, get_name_by_any(ref)))
                if not HasUserName(ref):
                    LabelAddressPlus(ref, '??_7vtable_{:x}@unknown@@6B@'.format(ref))
            else:
                recurse(ref)
    for ea in addrs:
        recurse(ea)


def _isCall_mnem(mnem): return mnem.startswith("call")


def _isJmp_mnem(mnem): return mnem.startswith("jmp")


def _isAnyJmp_mnem(mnem): return mnem.startswith("j")

def _isJmpOrCall(mnem): return mnem.startswith(("j", "call"))


def _isConditionalJmp_mnem(mnem): return mnem.startswith("j") and not mnem.startswith("jmp")


def _isUnconditionalJmp_mnem(mnem): return mnem.startswith("jmp")
def _isInterrupt_mnem(mnem): return mnem.startswith("int")


def _isUnconditionalJmpOrCall_mnem(mnem): return isUnconditionalJmp(mnem) or isCall(mnem)


def _isRet_mnem(mnem): return mnem.startswith("ret")


def _isPushPop_mnem(mnem): return mnem.startswith("push") or mnem.startswith("pop")

def _isNop_mnem(mnem): return mnem.startswith("nop") or mnem.startswith("pop")

def _unlikely_mnems(): return [
        'in', 'out', 'loop', 'cdq', 'lodsq', 'xlat', 'clc', 'adc', 'stc',
        'iret', 'stosd', 'bswap', 'wait', 'sbb', 'pause', 'retf', 'retnf',
        'test', 'scasb', 'cmc', 'insb', 'hlt', 'setnle', 'cwpd', 'loopne',
        'std', 'retf', 'loop', 'loope', 'loopz', 'popfq', 'pushfq', 'fisub',
        'iret', 'insd', 'cld', 'rcr', 'ins', 'ffreep', 'fcom', 'jceax',
        'ficom', 'jcrx', 'hnt jb', 'repne', 'lock', 'lock dec', 'bsf', 'hnt',
        'fcmovnbe', 'retnw', 'cdq', 'clc', 'cld', 'cli', 'cmc', 'cmpsb',
        'cmpsd', 'cwde', 'hlt', 'in', 'ins', 'in al', 'in eax', 'ins byte',
        'ins dword', 'int3', 'int', 'int 3', 'int1', 'iret', 'lahf', 'leave',
        'lodsb', 'lodsd', 'movsb', 'movsd', 'nop', 'out', 'outs', 'sahf',
        'scasb', 'scasd', 'stc', 'std', 'sti', 'stosb', 'stosd', 'wait',
        'xlat', 'fisttp', 'fbstp', 'fxch4', 'fld', 'fsubr' # 'xlat byte [rbx+al]'
        ]
def _isUnlikely_mnem(mnem): return mnem in _unlikely_mnems()

def _isFlowEnd_mnem(mnem): return mnem in ('ret', 'retn', 'jmp', 'int', 'ud2', 'leave', 'iret')

def _isInt(mnem): return mnem in ('int', 'ud2', 'int1', 'int3')

def perform(fun, *args):
    return fun(*args)


def preprocessIsX(fun, arg):
    if not arg:
        raise Exception("Invalid argument: {}".format(type(arg)))
    if isinstance(arg, str):
        return perform(fun, arg)
    if isinstance(arg, integer_types):
        mnem = GetMnem(arg)
        if not mnem:
            return False
        return perform(fun, mnem)
    raise Exception("Unknown type: {}".format(type(arg)))


def isUnlikely(arg): return preprocessIsX(_isUnlikely_mnem, arg)
def isFlowEnd(arg): return preprocessIsX(_isFlowEnd_mnem, arg)
def isInt(arg): return preprocessIsX(_isInt_mnem, arg)
def isAnyJmp(arg): return preprocessIsX(_isAnyJmp_mnem, arg)

def isJmpOrCall(arg): return preprocessIsX(_isJmpOrCall, arg)

def isCall(arg): return preprocessIsX(_isCall_mnem, arg)

def isJmpOrObfuJmp(ea, patch=0):
    if ea is None:
        return ValueError("ea was None")
    if isJmp(ea):
        return True
    if idc.get_wide_dword(ea) == 0x24648d48:
        searchstr = "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3"
        found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        if found == ea:
            if patch:
                l = [0xe9] + list(struct.unpack('4B', struct.pack('I', Dword(ea + 0x4) + 0x3)))
                PatchBytes(ea, l)
                SetFuncEnd(ea, ea + 5)
                if IsFuncHead(ea):
                    LabelAddressPlus(ea, 'ObfuThunk')
            return True

def isCallOrObfuCall(ea, patch=0):
    if isCall(ea):
        return True
    if idc.get_wide_dword(ea) == 0x24648d48:
        searchstr = '48 8d 64 24 f8 48 89 2c 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3'
        found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        if found == ea:
            if patch:
                l = [0xe8] + list(struct.unpack('4B', struct.pack('I', Dword(ea + 0x18) + 0x17))) + \
                    [0xe9] + list(struct.unpack('4B', struct.pack('I', Dword(ea + 0x0c) + 0x06)))
                PatchBytes(ea, l)
                SetFuncEnd(ea, ea + 10)
                if IsFuncHead(ea):
                    LabelAddressPlus(ea, 'StraightCall')
            return True

def isCallOrObfuCallPatch(ea):
    return isCallOrObfuCall(ea, 1) #  or SkipJumps(ea) != ea

def isConditionalJmp(arg): return preprocessIsX(_isConditionalJmp_mnem, arg)


def isJmp(arg): return preprocessIsX(_isJmp_mnem, arg)

def isPushPop(arg): return preprocessIsX(_isPushPop_mnem, arg)

def isNop(ea): 
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, get_ea_by_any(ea))
    if inslen == 0:
        return None 
    if insn.itype == idaapi.NN_nop:
        return True
    return idc.get_wide_word(ea) == 0x9066
    return GetInsn

def isUnconditionalJmp(arg): return preprocessIsX(_isUnconditionalJmp_mnem, arg)

def isOpaqueJmp(ea):
    if isUnconditionalJmp(ea):
        if opType0 in (idc.o_near, idc.o_mem):
            return False
        if opType0 == idc.o_reg:
            disasm = idc.GetDisasm(ea)
            if get_ea_by_any(string_between('; ', '', disasm)) != idc.BADADDR:
                return False
        return True
    return False


def isUnconditionalJmpOrCall(arg): return preprocessIsX(_isUnconditionalJmpOrCall_mnem, arg)
def isInterrupt(arg): return preprocessIsX(_isInterrupt_mnem, arg)


def isRet(arg): return preprocessIsX(_isRet_mnem, arg)

def isCodeish(a, minlen=16):
    if IsCode_(a):
        return True
    elif isJmp(a) and (GetInsnRange(jmpTarget(a) > minlen or isJump(jmpTarget(a)))):
        return True
    elif GetInsnRange(a) > minlen:
        return True
    return False

def jmpTarget(ea):
    return GetOperandValue(ea, 0)

def CountConsecutiveCalls(ea, checkFn = isCallOrObfuCallPatch):
    ori_ea = ea
    calls = []
    while ea and checkFn(ea) or isJmp(ea):
        if not isJmp(ea):
            calls.append(ea)
        tmp = GetJumpTarget(ea)
        if tmp:
            ea = tmp
        else:
            break
    return (calls, ea, get_name_by_any(ea))

def first_iterable(iterable, *defaultvalue):
    return next(iterable, *defaultvalue)

def last_iterable(iterable, *defaultvalue):
    last = next(iterable, *defaultvalue)
    for last in iterable:
        pass
    return last

    
def all_xrefs_(funcea=None, xref_getter=None, key='frm', iteratee=None, filter=None, pretty=False):
    if isinstance(funcea, list):
        return _.chain([all_xrefs_(x, xref_getter=xref_getter, key=key, iteratee=iteratee, filter=filter, pretty=pretty) for x in funcea]).flatten('shallow').sort().uniq('sorted').value()
    if xref_getter is None:
        xref_getter = idautils.XrefsTo
    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    #
    # Xref type names table
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    if iteratee is None:
        iteratee = _.identity
    if filter is None:
        filter = lambda x: x

    xrefs = []
    for head in GetFuncHeads(funcea):
        xrefs.extend([(
                getattr(x, key), 
                diida(x.frm),
                string_between('(', ')', XrefTypeName(x.type)),
                diida(x.to))
            for x in xref_getter(head)
            if x.type not in (ida_xref.fl_F,)])
    xrefs = _.chain([iteratee(x) for x in xrefs if filter(x) and not ida_funcs.is_same_func(x[0], funcea)]).sort().uniq('sorted').value()

    if pretty:
        for x in _.uniq(sorted(xrefs, key=lambda x: (x[2], x[0])), 1):
            print("0x{:09x} {:48} {:6} {}".format(*x))
        return
    return xrefs

def all_xrefs_to(funcea=None, iteratee=None, filter=None, pretty=False):
    return all_xrefs_(funcea=funcea, iteratee=iteratee, filter=filter, pretty=pretty, xref_getter=idautils.XrefsTo, key='frm')

def all_xrefs_from(funcea=None, iteratee=None, filter=None, pretty=False):
    return all_xrefs_(funcea=funcea, iteratee=iteratee, filter=filter, pretty=pretty, xref_getter=idautils.XrefsFrom, key='to')

def call_refs_from(funcea=None):
    return all_xrefs_from(funcea, filter=lambda x: x[2] == 'fl_CN', iteratee=lambda x: x[0])

def call_refs_to(funcea=None):
    return all_xrefs_to(funcea, filter=lambda x: x[2] == 'fl_CN', iteratee=lambda x: x[0])

#  def all_xrefs_from(funcea, iteratee=None, filter=None, pretty=0):
    #  if isinstance(funcea, list):
        #  return _.chain([all_xrefs_from(x, iteratee=iteratee, filter=filter, pretty=pretty) for x in funcea]).flatten('shallow').sort().uniq('sorted').value()
#  
    #  functionName = idc.get_func_name(funcea)
    #  
    #  # The first chunk will be the start of the function, from there -- they're sorted in 
    #  # order of location, not order of execution.
    #  #
    #  # Lets gather them all up first, then untangle them
    #  #
    #  # Xref type names table
    #  _ref_types = {
        #  ida_xref.fl_U : 'Data_Unknown (fl_U)',
        #  ida_xref.dr_O : 'Data_Offset (dr_O)',
        #  ida_xref.dr_W : 'Data_Write (dr_W)',
        #  ida_xref.dr_R : 'Data_Read (dr_R)',
        #  ida_xref.dr_T : 'Data_Text (dr_T)',
        #  ida_xref.dr_I : 'Data_Informational (dr_I)',
        #  ida_xref.fl_CF : 'Code_Far_Call (fl_CF)',
        #  ida_xref.fl_CN : 'Code_Near_Call (fl_CN)',
        #  ida_xref.fl_JF : 'Code_Far_Jump (fl_JF)',
        #  ida_xref.fl_JN : 'Code_Near_Jump (fl_JN)',
        #  20 : 'Code_User (20)',
        #  ida_xref.fl_F : 'Ordinary_Flow (fl_F)'
    #  }
#  
    #  def XrefTypeName(typecode):
        #  """
        #  Convert cross-reference type codes to readable names
#  
        #  @param typecode: cross-reference type code
        #  """
        #  assert typecode in _ref_types, "unknown reference type %d" % typecode
        #  return _ref_types[typecode]
#  
#  
#  
    #  if iteratee is None:
        #  iteratee = _.identity
    #  if filter is None:
        #  filter = lambda x: x
#  
    #  #
    #  xrefs = []
    #  for (startea, endea) in Chunks(funcea):
        #  for head in Heads(startea, endea):
            #  xrefs.extend([(x.to, diida(x.frm) or idc.get_func_name(x.to) or idc.get_name(x.to) or hex(x.to), string_between('(', ')', XrefTypeName(x.type)), diida(x.to)) for x in idautils.XrefsFrom(head) if x.type not in [ida_xref.fl_F]])
    #  #  xrefs = [x for x in xrefs if idc.get_func_name(x[0]) != functionName]
    #  xrefs = _.chain([iteratee(x) for x in xrefs if filter(x) and idc.get_func_name(x[0]) != functionName]).sort().uniq('sorted').value()
#  
    #  if pretty:
        #  for x in _.uniq(sorted(xrefs, key=lambda x: (x[2], x[0])), 1):
            #  print("0x{:09x} {:48} {:6} {}".format(*x))
        #  return
    #  return xrefs
#  
@static_vars(_ref_types = {
    0: 'Data_Unknown (fl_U)',
    1: 'Data_Offset (dr_O)',
    2: 'Data_Write (dr_W)',
    3: 'Data_Read (dr_R)',
    4: 'Data_Text (dr_T)',
    5: 'Data_Informational (dr_I)',
    16: 'Code_Far_Call (fl_CF)',
    17: 'Code_Near_Call (fl_CN)',
    18: 'Code_Far_Jump (fl_JF)',
    19: 'Code_Near_Jump (fl_JN)',
    20: 'Code_User (20)',
    21: 'Ordinary_Flow (fl_F)'})
def XrefTypeName(typecode):
    """
    Convert cross-reference type codes to readable names

    @param typecode: cross-reference type code
    """
    assert typecode in XrefTypeName._ref_types, "unknown reference type %d" % typecode
    return XrefTypeName._ref_types[typecode]

#  def all_xrefs_to(funcea, iteratee = None):
    #  # The first chunk will be the start of the function, from there -- they're sorted in 
    #  # order of location, not order of execution.
    #  #
    #  # Lets gather them all up first, then untangle them
    #  #
    #  # Xref type names table
    #  if iteratee is None:
        #  iteratee = _.identity
#  
    #  xrefs = []
    #  for (startea, endea) in Chunks(funcea):
        #  for head in Heads(startea, endea):
            #  xrefs.extend([(x.frm, idc.get_name(x.frm), XrefTypeName(x.type), diida(x.frm)) for x in idautils.XrefsTo(head) if x.type not in [ida_xref.fl_F]])
    #  xrefs = _.uniq([iteratee(x[0]) for x in xrefs if x[0] != idc.BADADDR and not ida_funcs.is_same_func(x[0], funcea)])
    #  return xrefs


def xrefs_to(ea, iteratee=None):
    if isinstance(ea, list):
        return [xrefs_to(x) for x in ea]

    ea = eax(ea)
    if callable(iteratee):
        return [iteratee(x.frm) for x in idautils.XrefsTo(ea)]
    return [x.frm for x in idautils.XrefsTo(ea)]

def func_refs_to(ea=None):
    return [x for x in xrefs_to(ea, iteratee=GetFuncStart) if x != idc.BADADDR]

def shared_xrefs_to(list_ea, iteratee = None):
    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    #
    # Xref type names table
    if iteratee is None:
        iteratee = _.identity

    xrefs = []
    for ea in list_ea:
        if not xrefs:
            xrefs.extend(xrefs_to(ea, iteratee=GetFuncStart))
        else:
            tmp = xrefs_to(ea, iteratee=GetFuncStart)
            xrefs = list(set(xrefs).intersection(set(tmp)))
    if callable(iteratee):
        xrefs = [iteratee(x) for x in xrefs]
    return xrefs

def xrefs_to_ex(ea=None, flow=1, iteratee=None, filter=None):
    """
    get detailed list of xrefs to address

    @param ea: linear address
    """
    #  Python>pp(next(XrefsFrom(ERROREA()))) {'frm': 5388374849, 'iscode': 1, 'to': 5388374854, 'type': 21}
    #  Python>pp(next(XrefsTo(ERROREA())))   {'frm': 5436471230, 'iscode': 1, 'to': 5388374849, 'type': 19}
    if isIterable(ea):
        result = []
        for x in ea:
            result.append(xrefs_to_ex(x))
        return [x for x in _.uniq(result) if x]
    ea = eax(ea)
    if callable(iteratee):
        xrefs = [iteratee(x) for x in idautils.XrefsTo(ea) if flow or x.type != ida_xref.fl_F]
    else:
        xrefs = [AttrDict({
            'frm': x.frm, 
            'frm_insn': 'offset' if IsOff0(x.frm) else diida(x.frm), 
            'type': string_between('(', ')', XrefTypeName(x.type)), 
            'type_code': x.type,
            'to': x.to,
            'to_insn': diida(x.to),
            'frm_seg': idc.get_segm_name(x.frm),
            'to_seg': idc.get_segm_name(x.to),
            }) for x in sorted(idautils.XrefsTo(ea), key=lambda x: x.type, reverse=True) if flow or x.type != ida_xref.fl_F]
    #  xrefs = [x for x in xrefs if idc.get_func_name(x[0]) != functionName]
    #  xrefs = _.uniq([iteratee(x) for x in xrefs if idc.get_func_name(x[0]) != functionName])

    if callable(filter):
        return _.filter(xrefs, filter)
    return xrefs

def seg_refs_to(ea=None, seg=['.text']):
    """
    references to address from nominated segment(s)

    @param ea: linear address
    """
    ea = eax(ea)
    seg = A(seg)
    return xrefs_to_ex(ea, filter=lambda e: e.frm_seg in seg)

def SegmentRefsTo(ea):
    return set([SegName(x) for x in xrefs_to(ea)])

def isSegmentInXrefsTo(ea, s):
    return s in SegmentRefsTo(ea)

def GetFuncHeads(funcea=None):
    """
    GetFuncHeads

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return []
    else:
        funcea = func.start_ea

    ea = funcea
    
    heads = []
    for start, end in idautils.Chunks(ea):
        heads.extend([head for head in idautils.Heads(start, end)])

    return heads


def GetDisasmFuncHeads(funcea=None):
    """
    GetFuncHeads

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return {}
    else:
        funcea = func.start_ea

    hash1 = GetFuncHash(funcea)
    for start, end in idautils.Chunks(funcea):
        for ea in idautils.Heads(start, EaseCode(start)): 
            GetDisasm(ea)
    hash2 = GetFuncHash(funcea)
    if hash1 != hash2:
        print("[GetDisasmFuncHeads] hash changed")
    

def GetMinSpd(ea = None):
    ea = eax(ea)
    minspd_ea = idc.get_min_spd_ea(ea)
    if minspd_ea == idc.BADADDR:
        return False
    return idc.get_spd(minspd_ea)


def GetSpds(funcea = None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    if GetMinSpd(ea) == False:
        return False
    spds = [idc.get_spd(head) for head in GetFuncHeads(ea) if isRet(head)]
    return spds

def GetAllSpds(funcea = None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    if GetMinSpd(ea) == False:
        return False
    spds = [idc.get_spd(head) for head in GetFuncHeads(ea)]
    return spds

def GetSpdsMinMax(funcea=None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    spds = GetSpds(ea)
    if spds:
        return min(spds), max(spds)
    return idc.BADADDR, idc.BADADDR

def GetAllSpdsMinMax(funcea=None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    spds = GetAllSpds(ea)
    if spds:
        return min(spds), max(spds)
    return idc.BADADDR, idc.BADADDR

def IsFuncSpdBalanced(funcea=None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    minmax = GetSpdsMinMax(ea)
    if not minmax:
        return False
    if minmax[0] == minmax[1] == idc.BADADDR:
        all_spds = GetAllSpds(ea)
        if all_spds == False:
            return False
        return all_spds[0] == all_spds[-1] == idc.get_spd(GetFuncStart(ea))
    return minmax[0] == minmax[1] == idc.get_spd(GetFuncStart(ea))

def IsFuncSpdZero(funcea=None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    minmax = GetSpdsMinMax(ea)
    if not minmax:
        return False
    return minmax[0] == minmax[1] == 0

def camelCase_snake(value):
    def _lower(s): return s.lower()

    def _cap(s): return s.capitalize()

    def camelsnake():
        yield _lower
        while True:
            yield _cap

    c = camelsnake()
    return "".join(next(c)(x)
                   if x else '_'
                   for x in value.split(" "))


camelize = camelCase_snake


def PascalCase(st, upper=True, split=None, repl=''):
    return camelCase(st, upper, split, repl)


def camelCase(st, upper=False, split=None, repl='', splitUpper=True):
    if split:
        output = repl.join(camelCase(x, upper=splitUpper) for x in re.split(split, st))
        if upper:
            return output
        return output[0].lower() + output[1:]

    output = ''.join(x for x in st.title() if x.isalnum())
    if upper:
        return output
    return output[0].lower() + output[1:]


def camel_case_to_snake_case(s):
    return ''.join(['_' + c.lower() if c.isupper() else c for c in str(s)]).lstrip('_')

def camelcase(st, upper=False, split='_', repl='_', splitUpper=False):
    if type(st) is str:
        # any pre-filtering done here
        # st = re.sub(r".*(__|::)", "", st)
        return camelCase(st, upper, split, repl, splitUpper)

    # unused afaik
    if type(st) is int:
        fnFull = idc.get_func_name(k)
        fnOnly = re.sub(r".*(__|::)", "", fnFull)
        if not fnOnly or not isString(fnOnly):
            raise "0x%x: couldn't get function name from %s"

        fnCamel = camelCase(fnOnly)
        print(("0x%x: CamelizeFunction('%s'): %s" % (st, fnFull, fnCamel)))
        return fnCamel


def MakeUniqueLabel(name, ea=BADADDR):
    fnLoc = LocByName(name)
    if fnLoc == BADADDR or fnLoc == ea:
        return name
    fmt = "%s_%%i" % name
    for i in range(100):
        tmpName = fmt % i
        fnLoc = LocByName(tmpName)
        if fnLoc == BADADDR or fnLoc == ea:
            return tmpName
    return ""


def shortName(name):
    return name
    if not name.find('sub_7FF79') or not name.find('loc_7FF79'):
        ba = bytearray(name)
        name = ba[0:1] + ba[9:12] + '_' + ba[12:16]
    return name


def compact(*names):
    caller = inspect.stack()[1][0]  # caller of compact()
    vars = {}
    for n in names:
        if n in caller.f_locals:
            vars[n] = caller.f_locals[n]
        elif n in caller.f_globals:
            vars[n] = caller.f_globals[n]
    return vars


def extract(vars):
    caller = inspect.stack()[1][0]  # caller of extract()
    for n, v in list(vars.items()):
        caller.f_globals[n] = v  # NEVER DO THIS - not guaranteed to work
        # caller.locals()[n] = v


__DOT = """digraph G {
    rankdir=TD
    node [ shape="box" style="filled" fillcolor="#ffffff" fontname="Roboto" fontsize=14 ]
    fontname="Roboto"
    shape=box
    fillcolor="#ffffff" 
    graph [splines=ortho]
    // ratio=compress
    compound=true
    // ranksep=0.15
    // mode=ipsep
    sep=0.1
    // splines=spline
    // splines=true
    // constraint=false
    // ordering=out
    // size="8,6"
    // ratio=fill
    bgcolor="#cccccc"

%%MEAT%%

}
"""


__DOT = """
digraph G {
    rankdir=TD
    node [ shape="box" style="filled" fillcolor="#ffffff" fontname="Roboto" fontsize=14 ]
    fontname="Roboto"
    shape=box
    fillcolor="#ffffff" 
    // graph [splines=ortho]
    // ratio=compress
    compound=true
    // ranksep=0.15
    // mode=ipsep
    sep=0.1
    splines=spline
    // splines=true
    // constraint=false
    // ordering=out
    // size="8,6"
    // ratio=fill
    bgcolor="#cccccc"

%%MEAT%%

}
"""

def is_possible_cygwin_symlink(fn):
    if not os.path.isfile(fn):
        return False

    if 10 < os.path.getsize(fn) < 256:
        return True

def read_possible_cygwin_symlink(fn):
    res = None
    with open(fn, 'rb') as fp:
        s = fp.read(1024)
        if s[0:10] == b'!<symlink>':
            u = s[10:]
            res = u.decode(encoding='utf-8').rstrip(chr(0))
            return res

# os.symlink(src, dst, target_is_directory=False, *, dir_fd=None)

def process_cygwin_symlinks(fn):
    """ this allows limited handling of cygwin symlinks from windows python """
    # if os.name == 'nt':
    _cygroot = "C:/Users/sfink/Downloads/cyg-packages/"

    _is_cygrooted = None
    _is_cygpath = None
    _cygroot = os.path.normcase(os.path.abspath(fn))
    _abs = ''
    fn = os.path.normcase(fn)

    if fn.startswith('cygwin:'):
        _is_cygpath = True
        # _abs = os.path.abspath(fn)
        fn = os.path.join(_cygroot, fn[7:])
        # dprint("[debug] _abs, fn")
        print("[debug] _abs:{}, fn:{}".format(_abs, fn))
        

    else:
        _abs = os.path.normcase(os.path.abspath(fn))
    
    _is_cygrooted = _abs.startswith(fn)
    # could probably have checked here to see if _abs.startswith(_cygroot)
    # or os.path.commonpath(paths) >=py3.5

    if not _is_cygrooted:
        return os.path.normcase(os.path.abspath(fn))

    _cfn = fn[len(_cygroot):]

    _nfn = []
    _restart = False
    while len(_nfn) < 256 and _restart:
        for x in _cfn.replace(os.path.sep, '/').split('/'):
            if is_possible_cygwin_symlink(x):
                _link = read_possible_cygwin_symlink(x)
                if _link:
                    if _link.startswith('/'):
                        _nfn.clear()
                        _cfn = _link
                        _restart = True
                        break
                    if '../' in _link:
                        raise ValueError('../ in cygwin symlink')
                    if '/' in _link:
                        _nfn.extend(_link.split('/'))
                        continue
                    x = _link

            _nfn.append(x)

        if _restart:
            continue

    # dprint("[_] _nfn")
    print("[_] _nfn:{}".format(_nfn))
    

    res = None
    if not os.path.isfile(fn):
        return res

    with open(fn, 'rb') as fp:
        s = fp.read(1024)
        if s[0:10] == b'!<symlink>':
            u = s[10:]
            res = u.decode(encoding='utf-8').rstrip(chr(0))

    if not res:
        return res

    # print("symlink: {} -> {}".format(fn, res))
    
    new = ''
    if res.startswith('/cygdrive/'):
        parts = res.split('/')[2:]
        new += parts[0] + ':/'
        parts = parts[1:]
    elif res.startswith('/'):
        new = fn
        parts = res.split('/')[1:]
    else:
        new = fn
        parts = res.split('/')[0:]

    while parts:
        new = os.path.join(new, parts[0])
        parts = parts[1:]

    # print("symlink final res: {}".format(new))
    return new

    return None

def process_path(path, limit=0):
    l = []
    for x in braceexpand(path):
        for y in x:
            l.append(glob(os.path.expanduser(os.path.expandvars(y))))

    if limit == 1:
        return l[0] if l else ''
    if limit and l:
        return l[0:limit]
    return l


def dot_draw(string, name="default", exe="dot"):
    if not name:
        name = "default"
    idb_subdir = GetIdbPath()
    idb_subdir = idb_subdir[:idb_subdir.rfind(os.sep)] + os.sep + "dot_%s" % GetInputFile()
    if not os.path.isdir(idb_subdir):
        os.mkdir(idb_subdir)

    filename = idb_subdir + os.sep + '%s.dot' % name
    with open(idb_subdir + os.sep + '%s.dot' % name, "w+") as fw:
        fw.write(string)

    dir = idb_subdir
    orig_dir = os.getcwd()
    os.chdir(dir)

    if exe is None:
        return False, "exe=None"

    #  path = 'c:/Program Files (x86)/Graphviz2.38/bin'
    path = r'c:\Program Files\Graphviz\bin'
    dot_filename = exe + ".exe"
    dot_executable_filepath = os.path.join(path, dot_filename)

    if not os.path.exists(dot_executable_filepath):
        raise Exception("Please install graphviz from https://graphviz.org/download/")

    args = list()
    args.append("-Tsvg")
    args.append("%s.dot" % os.path.abspath(name))
    args.append("-o%s.svg" % os.path.abspath(name))

    args = [dot_executable_filepath] + list(args)
    if debug: print(args)
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        ret = subprocess.check_output(args, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=startupinfo)
        #  ret = ret.decode('ascii')
        if len(ret):
            return False, ret
    except subprocess.CalledProcessError as e:
        if debug: print(("CalledProcessError: %s" % e.__dict__))
        return False, e.output

    # with open(idb_subdir + os.sep + '%s.svg' % name, "rb") as fr:
    with open("%s.svg" % os.path.abspath(name), "rb") as fr:
        o = fr.read()
        if len(o):
            print("dot_draw", filename)
            return True, "%s.svg" % os.path.abspath(name)
        else:
            return False, "no output"


def is_nothing_sub(fnName):
    return fnName.startswith('sub_')


def handle_function(func_start, limit=3, depth=0, calls_from=defaultdict(set)):
    global __DOT
    global colors
    fnName = idc.get_name(func_start)
    if depth >= limit:
        #  if fnName not in calls_from:
        #  calls_from[fnName] = None
        return
    if fnName in calls_from:
        return
    for h in idautils.FuncItems(func_start):
        for r in idautils.XrefsFrom(h, 0):
            include = 0
            if r.type == fl_JF or r.type == fl_JN:
                if IsFuncHead(r.to):
                    include = 1
            if r.type == fl_CF or r.type == fl_CN:
                include = 1
            if include:
                calls_from[idc.get_name(func_start)].add(idc.get_name(r.to))
                handle_function(r.to, limit, depth + 1, calls_from)

    if depth:
        return

    # our original calling function
    subs = set()
    calls_to = defaultdict(set)
    call_list = []
    for k in _.keys(calls_from):
        subs.add(k)
        for v in calls_from[k]:
            subs.add(v)
            calls_to[v].add(k)
            call_list.append('"{}" -> "{}";'.format(k, v))

    globals()["xx"] = [calls_from, calls_to]
    #  for nothing_sub in [s for s in subs if is_nothing_sub(s)]:
    #  if nothing_sub in calls_from and nothing_sub in calls_to:
    #  dest = calls_from[nothing_sub]
    #  tgt = calls_to[nothing_sub]
    #  for d in dest:
    #  if not is_nothing_sub(d):
    #  if d in calls_to:
    #  for s in calls_to[dest]:
    #  if not is_nothing_sub(s):
    #  print('found {} > {}', d, s)

    colors = colorSubs(subs, colors)

    dot = __DOT.replace('%%MEAT%%', '\n'.join(_.uniq(colors) + _.uniq(call_list)))
    return dot_draw(dot, name=idc.get_name(func_start, ida_name.GN_VISIBLE))


def traceBackwards(ea=None, fn1=None):
    if ea is None: ea = ScreenEA
    if fn1 is None: fn1 = idc.prev_not_tail

    try:
        nextEA = ea
        ea = 0
        while nextEA != ea and nextEA not in visited:
            ea = nextEA
            flags = idc.get_full_flags(ea)
            if not idc.is_flow(flags):  # we must have jumped here
                assert hasAnyName(flags), "No name flag"
                assert idc.isRef(flags), "No ref flag"
                refs = list(idautils.CodeRefsTo(ea, flow=0))
                assert len(refs) == 1, "More than 1 CodeRefTo: how to follow?"
                nextEA = refs[0]
            else:
                nextEA = fn1(ea)
    except:
        pass
    return ea

def UnpatchUntilChunk(ea=None, _range=1024):
    """
    UnpatchUntilChunk

    @param ea: linear address
    """
    ea = eax(ea)
    end = 0
    start_func_start = GetFuncStart(ea)
    start_chunk_num = GetChunkNumber(ea)

        #  print("[info] ourFunc is {:x}".format(ourFunc))
    #  print("[info] checking range ... {:#x}".format(ea))
    for r in range(_range):
        chunk_num = GetChunkNumber(ea + r)
        func_start = GetFuncStart(ea + r)
        end = ea + r
        if (func_start != start_func_start and func_start != -1) or (chunk_num != start_chunk_num and chunk_num != -1):
            break

    if end > ea:
        if debug: print("[UnpatchUntilChunk] UnPatch({:x}, {:x})".format(ea, end))
        return UnPatch(ea, end)

    return 0



def UnloadFunction(ea):
    # if idc.get_segm_name(ea) == '.text2' and get_name(ea).lower().startswith('system'):
    end = GetFuncEnd(ea)
    size = end - ea
    if size < 2048:
        while ea < end:
            ida_bytes.del_value(ea)
            ea += 1

def remove_func_or_chunk(func):
    if func.flags & idc.FUNC_TAIL:
        return idc.remove_fchunk(func.owner, func.start_ea)
    return idc.del_func(func.owner)

#  def forceCode(start, end=None, trim=False, delay=None):
    #  addr = start
    #  end = end or GetInsnLen(start)
    #  if end < idaapi.cvar.inf.minEA and end < start:
        #  end = start + end
    #  last_jmp_or_ret = 0
    #  last_addr = 0
    #  trimmed_end = 0
    #  happy = 0
    #  #  idc.del_items(start, idc.DELIT_EXPAND, end - start)
    #  while addr < end:
        #  happy = 0
        #  last_addr = addr
        #  if idc.is_tail(idc.get_full_flags(addr)):
            #  head = idc.get_item_head(addr)
            #  if head == addr:
                #  print("[warn] item_head == addr {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, start, start, end))
            #  #  if not idc.del_items(addr, 0, 1):
            #  if not idc.MakeUnknown(addr, 1, 0):
                #  print("[warn] couldn't del item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, start, start, end))
#  
        #  if idc.is_code(idc.get_full_flags(addr)):
            #  # seems to be that deleting the code and remaking it is the only way to ensure everything works ok
            #  if debug: print("[info] code already existing instruction at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, addr, start, end))
            #  idc.del_items(addr, 0, idc.get_item_size(addr))
            #  # addr += idc.get_item_size(addr)
            #  # happy = 1
        #  if 1:
            #  insn_len = idc.create_insn(addr)
            #  if debug: print("[info] idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, addr, start, end))
            #  if not insn_len:
                #  # record existing code heads
                #  existing_code = [x for x in range(addr, addr+15) if IsCode_(x)]
                #  idc.del_items(addr, 0, 15)
                #  insn_len = idc.create_insn(addr)
                #  if not insn_len and existing_code:
                    #  [idc.create_insn(x) for x in existing_code]
            #  if not insn_len:
                #  trimmed_end = last_jmp_or_ret + idc.get_item_size(last_jmp_or_ret) if last_jmp_or_ret else last_addr or addr
                #  print("[warn] couldn't create instruction at {:x}, shortening chunk to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, trimmed_end, addr, start, end))
                #  if trim:
                    #  if idc.get_func_name(start):
                        #  if not SetFuncEnd(start, trimmed_end):
                            #  print("[warn] couldn't set func end at {:x} or {:x} or {:x} or {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(end, last_jmp_or_ret, last_addr, addr, start, start, end))
                    #  idc.del_items(end, 0, end - trimmed_end)
            #  else:
                #  happy = 1
                #  addr += insn_len
#  
        #  if not happy:
            #  return (addr-start, start, end, trimmed_end)
#  
        #  mnem = idc.print_insn_mnem(last_addr).split(' ', 2)[0]
        #  if mnem in ('jmp', 'ret', 'retn', 'int'):
            #  last_jmp_or_ret = last_addr
#  
    #  return (addr-start, start, end, trimmed_end)

def CheckThunk(ea, skipShort=0):
    if not IsFuncHead(ea):
        print("CheckThunk: Not FuncHead {:x}".format(ea))
        return ea
    insn = idautils.DecodeInstruction(ea)
    if not insn:
        print("CheckThunk: Couldn't find insn at {:x}".format(ea))
        return ea
    if insn.itype == idaapi.NN_jmp and (not skipShort or GetInsnLen(ea) > 2):
        if insn.Op1.type in (idc.o_near,):
            if GetChunkEnd(ea) - GetChunkStart(ea) > GetInsnLen(ea):
                SetFuncEnd(ea, ea + GetInsnLen(ea))
        if not IsThunk(ea):
            #  print("[info] 1611: {}".format(ea))
            # idc.add_func(ea, insn_len)
            if not MakeThunk(ea):
                print("[warn] MakeThunk({:x}) failed".format(ea))
                globals()['warn'] += 1
            else:
                if debug: print("[info] MakeThunk({:x}) ok".format(ea))

def ForceFunction(start, unpatch=False, denyJmp=False):
    # dprint("[ForceFunction] start")   
    if debug: print("[ForceFunction] start:{:x}".format(start))
    if not IsValidEA(start):
        return False

    do_return = None
    ea = start

    if IsExtern(ea):
        print("[ForceFunction] 0x{:x} is a reference".format(ea))
        return 1
    if denyJmp:
        Commenter(start, 'line').add('[DENY JMP]')
    if IsFuncHead(start):
        if debug: print("[ForceFunction] IsFuncHead {:x}".format(start))
        return 1

    fnName = ''
    if HasUserName(ea):
        if IsFunc_(ea):
            fnName = idc.get_func_name(ea)
        else:
            fnName = idc.get_name(ea)

    fnStart = GetFuncStart(start)
    itemHead = idc.get_item_head(start)
    if fnStart < itemHead < idc.BADADDR:
        if not SetFuncEnd(fnStart, idc.get_item_head(start)):
            print("[warn] ForceFunction (inside funchead) SetFuncEnd({:x}, {:x}) failed".format(fnStart, idc.get_item_head(start)))
            ZeroFunction(ea, total=1)
            idc.auto_wait()
            return ForceFunction(ea)
            globals()['warn'] += 1
            return False
    func = clone_items(GetChunk(start))
    if func:
        if func.flags & idc.FUNC_TAIL or func.start_ea != start:
            if func.start_ea < start:
                if not SetFuncEnd(func.start_ea, start):
                    print("[warn] SetFuncEnd({:x}, {:x}) failed".format(func.start_ea, start))
                    globals()['warn'] += 1
                    return False
                else:
                    if debug: print("[info] SetFuncEnd({:x}, {:x}) ok".format(func.start_ea, start))
            else:
                if not remove_func_or_chunk(func):
                    print("[warn] remove_func_or_chunk({:x}) failed".format(func.start_ea))
                    globals()['warn'] += 1
                    return False
                else:
                    if debug: print("[info] remove_func_or_chunk({:x}) ok".format(func.start_ea))

        else:
            do_return = func.end_ea - func.start_ea

    if do_return is not None:
        CheckThunk(start)
        return do_return

    end = EaseCode(start, forceStart=1, noExcept=1)
    if not IsValidEA(start):
        print("[ForceFunction] InvalidEA start: {}".format(start))
        return False
    if not IsValidEA(end):
        print("[ForceFunction] InvalidEA end: {}".format(end))
        return False
    if not idc.add_func(start, end) and not IsFunc_(start):
        globals()['warn'] += 1
        print("[warn] couldn't create function at {:x}".format(start))
        return False
    else:
        return GetFuncSize(start)

    idc.auto_wait()
    if not IsFuncHead(start):
        print("[warn] failed to force_function after success {:#x} {}".format(start, ea - start))
        globals()['warn'] += 1
    if IsFuncHead(start):
        # CheckThunk(start)
        if fnName:
            LabelAddressPlus(start, fnName)
        return ea - start

    return False

def listOflistOfBytesAsHex(byteArray):
    b2 = [x for x in byteArray if x[0] != 0xe9]
    bytes = [item for sublist in b2 for item in sublist]
    bytesHex = " ".join([("%02x" % x) for x in bytes])
    return bytesHex


def hex_byte_as_pattern_int(string):
    return -1 if '?' in string else int(string, 16)

def hex_string_as_list(string):
    def intify(string): return -1 if '?' in string else int(string, 16)
    return [hex_byte_as_pattern_int(x) for x in string.split(' ')]

def hex_pattern(hexLists):
    result = [ ]
    # Convert a string into a list, just so we can process it
    if not isinstance(hexLists, list):
        hexLists = [hexLists]
    for l in hexLists:
        result.extend([hex_byte_as_pattern_int(item) for item in l.split(" ")])
    return result

def make_pattern_from_hex_list(hexLists):
    result = []
    for list in hexLists:
        result.append([hex_byte_as_pattern_int(item) for item in list.split(" ")])
    return result


def patternAsHex(pattern):
    return " ".join(["%02x" % x for x in pattern])


def compare(l1, l2):
    if l1 == []:
        return l2 == []
    if l1[0] == -1 or l2[0] == -1 or l1[0] == l2[0]:
        return ida_hexrays.compare(l1[1:], l2[1:])


def matcher(l1, l2):
    if l1 == []:
        return l2 == [] or l2 == ['*']
    if l2 == [] or l2[0] == '*':
        return matcher(l2, l1)
    if l1[0] == '*':
        return matcher(l1, l2[1:]) or matcher(l1[1:], l2)
    if l1[0] == l2[0]:
        return matcher(l1[1:], l2[1:])
    else:
        return False


def cleanLine(line):
    #  line = re.sub(r"\s*;\s+.*$", "", line)
    line = line.rstrip('; ');
    #  line = re.sub(r";\s*;", ";", line)
    #  line = re.sub(r";\s+$", "", line)
    #  line = re.sub(r"\s+$", "", line)
    return line


def exportFlags(f):
    return is_data(f) and is_head(f) and isRef(f) and hasName(f) and hasUserName(f) and is_qword(f) and not is_defarg0(
        f) and not is_off0(f) and not is_code(f)


def exportDataNames():
    return [x for x in idautils.Names() if
            exportFlags(idc.get_full_flags(x[0])) and not re.match(r'.*(_impl|_actual|::|[?$@]).*', x[1], re.I)]

def ShowAppendFunc(ea, funcea, new_func):
    result = None
    if debug:
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        print((" -> ".join(stk)))
        print(("0x%x: AppendFunc(0x%x, 0x%x)" % (funcea, funcea, new_func)))

    if not IsFunc_(new_func):
        if debug: print("ShowAppendFunc: {:x} is not a function".format(new_func))
        return result

    if not IsFuncHead(new_func):
        if debug: print("ShowAppendFunc: {:x} is not IsFuncHead".format(new_func))
        return result

    owners = GetChunkOwners(new_func)
    if len(owners) > 1:
        if debug: print("ShowAppendFunc: {:x} has multiple owners".format(new_func))
        if funcea in owners: print("ShowAppendFunc: {:x} we are one of those owners".format(new_func))
        raise ChunkFailure("ShowAppendFunc: {:x} has multiple owners".format(new_func))

    if funcea in owners or IsSameFunc(funcea, new_func):
        if debug: print("ShowAppendFunc: {:x} is already our func".format(new_func))
        return result

    chunkNumber = GetChunkNumber(new_func)
    if chunkNumber < 0:
        raise ChunkFailure("ShowAppendFunc: {:x} had no chunk number".format(new_func))
    elif chunkNumber > 1:
        raise ChunkFailure("ShowAppendFunc: {:x} wasn't the head chunk".format(new_func))
        # RemoveThisChunk(new_func)
    else:
        #  idc.del_func(new_func)
        chunks = RemoveAllChunks(new_func)
        ida_funcs.del_func(new_func)
        for x, y in chunks:
            ShowAppendFchunk(funcea, x, y, ea)
        result = len(chunks)
        result = 1

    return result

def force_chunk(funcea, start, end, callback):
    funcea = GetFuncStart(funcea)
    not_ours = set()
    for ea in six.moves.range(start, end):
        idc.auto_wait()
        tail = clone_items(GetChunk(ea))
        if not tail:
            not_ours.add(ea)
            print("[warn] force_chunk: no chunk at {:x}".format(ea))
            globals()['warn'] += 1
            continue
        else:
            head = not tail.flags & ida_funcs.FUNC_TAIL
            if head:
                # is this our own head?
                if tail.start_ea == funcea:
                    continue
                not_ours.add(ea)
                func = clone_items(ida_funcs.get_func(ea))
                if not func:
                    print("[warn] force_chunk: couldn't get_func {:x}".format(ea))
                    globals()['warn'] += 1
                else:
                    cstart, cend = func.start_ea, func.end_ea

                    if func.start_ea < end:
                        del func # can't delete if handle is open
                        if not ida_funcs.set_func_start(ea, end):
                            print("[warn] force_chunk: cannot change func start {:x} to {:x}".format(cstart, end))
                            globals()['warn'] += 1
                        else:
                            print("[info] force_chunk: changed func start from {:x} to {:x} for {:x}".format(cstart, end, cend))
                    if func.end_ea > start:
                        del func # can't delete if handle is open
                        if not SetFuncEnd(ea, start) and not SetFuncEnd(start, start):
                            print("[warn] force_chunk: cannot change func end ({:x}) {:x} to {:x}".format(ea, cend, start))
                            globals()['warn'] += 1
                        else:
                            print("[info] force_chunk: changed func end for {:x} from {:x} to {:x}".format(cstart, cend, start))
                    if func:
                        # evidently we couldn't find a way around this func
                        del func # can't delete if handle is open
                        if not ida_funcs.del_func(ea):
                            print("[warn] force_chunk: couldn't deleete func {:x}".format(ea))
                            globals()['warn'] += 1
                        else:
                            print("[info] force_chunk: deleted func {:x}".format(ea))
            else: # if chunk tail
                if tail.refqty == 1 and tail.owner == funcea:
                    pass
                else:
                    not_ours.add(ea)
                while tail and (tail.refqty > 1 or tail.owner != funcea):
                    if not tail.flags & ida_funcs.FUNC_TAIL:
                        print("[warn] force_chunk tail became head {:x}".format(ea))
                        globals()['warn'] += 1
                    if not idc.remove_fchunk(ea, start):
                        print("[warn] force_chunk cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
                        globals()['warn'] += 1
                        break
                    else:
                        print("[info] force_chunk removed whole fchunk {:x}\u2013{:x}".format(start, end))
                    idc.auto_wait()

                    tail = clone_items(GetChunk(ea))
    if len(not_ours):
        print("{:x} not ours: {}".format(funcea, hex(list(not_ours))))
        callback()


def adjust_tails(funcea, add=[], remove=[]):
    add = A(add)
    remove = A(remove)

    _chunks = [x for x in idautils.Chunks(funcea)]
    existing_range = _.flatten(asList([range(*x                  ) for x in _chunks]))
    altered_range = set(existing_range)
    existing_range = set(existing_range) # done afterwards to prevent altered_range becoming a shallow copy
    for _add in add:
        altered_range = altered_range.union(set(asList(six.moves.range(_add[0], _add[1]))))
    for _remove in remove:
        altered_range = altered_range.subtract(set(asList(six.moves.range(_remove[0], _remove[1]))))

    print("diff: {}".format(pf(existing_range.symmetric_difference(altered_range))))

    #  existing = _.flatten(asList(GenericRanger(existing_range, iteratee = lambda x, y: range(x, y+1))))
    #  altered  = _.flatten(asList(GenericRanger(altered_range,  iteratee = lambda x, y: range(x, y+1))))
    _chunks  =                  GenericRanger(existing_range, iteratee = lambda x, y: (x, y+1))
    _new     =                  GenericRanger(altered_range,  iteratee = lambda x, y: (x, y+1))
    _remove  =                  GenericRanger(existing_range.difference(altered_range), \
                                                              iteratee = lambda x, y: (x, y+1))
    _add     =                  GenericRanger(altered_range.difference(existing_range), \
                                                              iteratee = lambda x, y: (x, y+1))
    # _remove = GenericRanger(list(set(existing) - set(altered)), iteratee=lambda x, y: AttrDict({'start_ea':x, 'end_ea':y+1}))
    #  print("_chunks: {}" .format(hex((_chunks))))
    #  print("existing: {}".format(hex(list(existing))))
    #  print("altered: {}" .format(hex(list(altered))))
    #  print("_new: {}"    .format(hex((_new))))
    print("remove: {}" .format(hex(list(remove))))
    print("add: {}"    .format(hex(list(add))))
    print("_remove: {}" .format(hex(list(_remove))))
    print("_add: {}"    .format(hex(list(_add))))

    _overlap = _.reject(overlap3(_chunks, _new), lambda x, *a: x[2] == x[3])
    print("_overlap: {}"    .format(hex(_overlap)))

    warn = 0
    for c in _overlap:
        start, end, chunk, unused = c
        cstart, cend = chunk
        if start >= end:
            print("[info] start >= end {:x}\u2013{:x}".format(start, end))
            continue
        if cend == end:
            if cstart == start:
                print("[info] chunk remains unchanged {:x}\u2013{:x}".format(start, end))
                continue

                #  if not idc.remove_fchunk(funcea, start):
                    #  print("[warn] cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
                #  else:
                    #  print("[info] removed whole fchunk {:x}\u2013{:x}".format(start, end))
            else:
                # same end, different start
                #
                # fnStart = idc.get_func_attr(ea, idc.FUNCATTR_START)
                # fnEnd = idc.get_func_attr(ea, idc.FUNCATTR_END)
                if not ida_funcs.set_func_start(funcea, start):
                    print("[warn] cannot change fchunk start from {:x} to {:x}".format(cstart, start))
                    globals()['warn'] += 1
                else:
                    print("[info] changed fchunk start from {:x} to {:x} for {:x}".format(cstart, start, cstart))
        elif cstart == start:
            # end's cannot match
            if not SetFuncEnd(funcea, end):
                    print("[warn] (1) cannot change fchunk end ({:x}) {:x} to {:x}".format(funcea, cend, end))
                    globals()['warn'] += 1
                    warn += 1
            else:
                print("[info] changed fchunk end for {:x} from {:x} to {:x}".format(cstart, cend, end))
        else:
            # trickiest -- both ends have changed
            # TODO: do we have to check for overlap of existing chunk?  probably, even if from other function
            print("[info] preparing to DP chunk from {:x}\u2013{:x}, to {:x}\u2013{:x}".format(cstart, cend, start, end))
            if not SetFuncEnd(funcea, end):
                print("[warn] DPing chunk, cannot change fchunk end {:x}\u2013{:x}".format(cend, end))
                globals()['warn'] += 1
            elif not ida_funcs.set_func_start(funcea, start):
                print("[warn] cannot change fchunk start {:x} to {:x}".format(cstart, start))
                globals()['warn'] += 1
            else:
                print("[info] changed fchunk start from {:x} to {:x} for {:x}".format(cstart, end, cend))

            #  print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, end+1, cend))
            #  elif not idc.append_func_tail(funcea, end+1, cend):
                #  print("[warn] DPing chunk, cannot add new fchunk {:x}\u2013{:x}".format(end+1, cend))
            #  else:
                #  print("[info] Dped chunk in two: {:x}\u2013{:x}, {:x}\u2013{:x}".format(cstart, start, end+1, cend))


    __del, __add = not_overlap3(_chunks, _new)
    for start, end in __del:
        if not idc.remove_fchunk(funcea, start):
            print("[warn] cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
            globals()['warn'] += 1
            warn += 1

    return warn

def ShowAppendFchunk(ea, start, end, old):
    if debug: stacktrace()
    return ShowAppendFchunkReal(ea, start, end, old)

def ShowAppendFchunkReal(ea, start, end, old):
    funcea = GetFuncStart(ea)
    if debug: print(("0x%x: ShowAppendFchunk::AppendFchunk(0x%x, 0x%x, 0x%x)" % (funcea, funcea, start, end)))
    if funcea == BADADDR:
        print("[warn] funcea {:x} is not a function".format(funcea))
        return False
    fstart, fend = GetFuncStart(ea), GetFuncEnd(ea)
    cstart, cend = GetChunkStart(ea), GetChunkEnd(ea)

    if debug:
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        print((" -> ".join(stk)))

    we_own_all = True
    for i in range(start, end):
        owners = GetChunkOwners(i)
        if len(owners):
            if IsFuncHead(GetChunkStart(i)):
                if debug: print("ShowAppendFchunk: IsFuncHead: {:x}".format(i))
                if GetChunkStart(i) == funcea:
                    pass
                    #  if debug: print("ShowAppendFchunk: FuncHeadOwner: {:x} is us {:x}".format(GetChunkStart(i), funcea))
                else:
                    idc.del_func(i)
            for owner in owners:
                #  if debug: print("ShowAppendFchunk: Owner: {:x}".format(owner))
                if owner != funcea:
                    if debug: print("ShowAppendFchunk: Owner: {:x} is not us {:x}".format(owner, funcea))
                    idc.remove_fchunk(owner, i)
                    idc.auto_wait()
                else:
                    pass
                    #  if debug: print("ShowAppendFchunk: Owner: {:x} is us {:x}".format(owner, funcea))

    #  owners = GetChunkOwners(start)
    #  if len(owners) > 0:
        #  if len(owners) > 1:
            #  if debug: sprint("SmartAddChunk: {:x} has multiple owners".format(start))
            #  RemoveAllChunkOwners(start)
            #  # raise ChunkFailure("SmartAddChunk: {:x} has multiple owners".format(start))
        #  elif fstart in owners: 
            #  if debug: sprint("SmartAddChunk: {:x} we own this chunk".format(start))
            #  return
        #  else:
            #  RemoveAllChunkOwners(start)


    if GetChunkStart(start) != BADADDR:
        if GetFuncStart(start) != GetFuncStart(ea):
            happy = 0
            if IsFuncHead(start):
                if start != funcea:
                    if debug: sprint("Passing ShowAppendFchunk {} to ShowAppendFunc".format(hex(start)))
                    return ShowAppendFunc(ea, funcea, start, old)
                else:
                    return 1
            if GetFuncStart(start) == GetChunkStart(start):
                if not HasUserName(start):
                    if 1 and debug: sprint("ShowAppendFchunk: already owned by another func, deleting func at {:x}", format(start))
                    if idc.del_func(start):
                        happy = 1
                    #  ZeroFunction(start)
            if not happy:
                return 0

    #  print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, start, end))
    # return force_chunk(funcea, start, end, lambda: idc.append_func_tail(funcea, start, end))
    # return adjust_tails(funcea, add=[(start, end)])

    if debug: sprint("grupenrange")
    us = dict()
    other = dict()
    both = dict()
    any = dict()
    func = dict()
    all = []
    head = start
    while head < end:
        if GetChunkStart(head) == GetFuncStart(head) != idc.BADADDR:
            func[head] = GetFuncStart(head)
        other_own = [x for x in GetChunkOwners(head) if x != fstart]
        us_own = [x for x in GetChunkOwners(head) if x == fstart]
        if other_own:
            other[head] = other_own
        if us_own:
            us[head] = us_own
        if other_own and us_own:
            both[head] = other_own + us_own
        if other_own or us_own:
            any[head] = [x for x in GetChunkOwners(head)]
        all.append(head)
        head = idc.next_not_tail(head)
        #  owners = RemoveOtherChunkOwners(head, funcea)

    tuples = [(x, (x + GetInsnLen(x)) if IsCode(x) else idc.next_head(x), _(any.get(x, [0])).chain().sort().join(',').value()) for x in all if x not in func]
    gruppen = _.groupBy(tuples, lambda v, *a: v[2])
    gruppen_ranges = dict()
    for k in gruppen:
        gruppen_ranges[k] = GenericRanger(_(gruppen[k]).map(lambda v, *a: GenericRange(tuple(v[0:2]))), sort=1)

    if debug: pp(gruppen_ranges)

    if '0' in gruppen_ranges:
        for r in gruppen_ranges['0']:
            if isinstance(r, dict):
                pp(r)
            # dprint("[about-to-append-func-tail] r.start, GetFuncName(r.start)")
            #  print("[about-to-append-func-tail] r.start:{:x}, GetFuncName(r.start):{}".format(r.start, GetFuncName(r.start)))
            
            for e in Heads(r.start, r.end):
                if IsFuncHead(e):
                    #  begin, end = GetChunkStart(e), GetChunkEnd(e)
                    if 1 and debug: sprint("AddChunk: del_func: already owned by another func, deleting func at {:x}", format(e))
                    idc.del_func(e)

            _func = ida_funcs.get_func(funcea)
            for _ea in range(r.start + 1, r.end): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                    # XXX
                    # This might work:
                    # [warn] avoided crash: append_func_tail(0x14344b6a1, 0x14162bf12, 0x14162bf17) [overlaps existing function chunk
                    # ida_funcs.get_func_chunknum(0x14344b6a1, 0x14162bdca) == 5
                    # idc.remove_fchunk(0x14344b6a1, 0x14162bdca)
                    print("[warn] avoided crash: append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) [overlaps existing function chunk belonging to 0x{:x} at 0x{:x}]".format(
                        funcea, r.start, r.end, GetChunkOwner(_ea), _ea))
                    globals()['warn'] += 1
                    return 

            #  del _func

            # this turns undefined data into instructions (nicely, not forcefully)
            idc.auto_wait()
            for _ea in range(r.start + 1, r.end): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                    # XXX
                    # This might work:
                    # [warn] avoided crash: append_func_tail(0x14344b6a1, 0x14162bf12, 0x14162bf17) [overlaps existing function chunk
                    # ida_funcs.get_func_chunknum(0x14344b6a1, 0x14162bdca) == 5
                    # idc.remove_fchunk(0x14344b6a1, 0x14162bdca)
                    print("[warn] avoided crash: append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) [overlaps existing function chunk belonging to 0x{:x} at 0x{:x}]".format(
                        funcea, r.start, r.end, GetChunkOwner(_ea), _ea))
                    globals()['warn'] += 1
                    return 
            if IsHead(r.end) or  \
                    PrevHead(r.end) + GetInsnLen(PrevHead(r.end)) == r.end or \
                    IsCode(r.end) or (IsCode(PrevNotTail(r.end) + GetInsnLen(PrevNotTail(r.end))) and PrevNotTail(r.end) + GetInsnLen(PrevNotTail(r.end)) == r.end):
                pass
            else:
                print("dubious r.end: {:x}".format(r.end))
            #  rv = ida_auto.auto_wait_range(r.start, r.end)
            #  if debug: print("ida_auto.auto_wait_range(0x" + str(r.start) + ", 0x" + str(r.end) + "): " + str(rv))
            #  if debug: print("ida_auto.auto_apply_tail(0x" + str(r.start) + ", 0x" + str(funcea) + ")")
            #  ida_auto.auto_apply_tail(r.start, funcea)
            #  # ida_auto.plan_and_wait(r.start, r.end, True)
            #  rv = idc.auto_wait()
            #  if debug: print("idc.auto_wait(): {}".format(rv))

            if debug: print("EaseCode(0x{:x}, 0x{:x})".format(funcea, r.start, r.end))
            ease_end = EaseCode(r.start, r.end, forceStart=1, noExcept=1)
            if not isinstance(ease_end, integer_types):
                print("[warn] EaseCode {:x}: {}".format(r.start, ease_end))
                msg = "[warn] couldn't append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) from {}".format(r.start, r.end, funcea, funcea, r.start, r.end, hex(old))
                globals()['warn'] += 1
                raise AdvanceFailure(msg)
            if ease_end != r.end:
                print("[warn] ease_end {:x} != r.end {:x}".format(ease_end, r.end))
                #  pp([GetDisasm(x) for x in idautils.Heads(r.start, r.end)])
                [GetDisasm(x) for x in idautils.Heads(r.start, r.end)]
                r.end = ease_end
            ([idc.GetDisasm(x) for x in idautils.Heads(r.start, r.end)])
            #  ida_auto.auto_wait_range(r.start, r.end)
            #  ida_auto.plan_and_wait(r.start, r.end)
            #  idc.auto_wait()
            rv = idc.append_func_tail(funcea, r.start, r.end)
            if not rv:
                if GetChunkNumber(r.start, funcea) != -1:
                    print("append_func_tail failed but we have a chunk number")
                ([GetDisasm(x) for x in idautils.Heads(r.start, r.end)])
            if not rv:
                for _ea in range(r.start + 1, r.end): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                    if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                        print("now there's a chunknumber at {:x}".format(_ea))
                _ea = r.start
                _not_code = []
                while _ea < r.end:
                    print("[debug] {:x} {}".format(_ea, idc.generate_disasm_line(_ea, GENDSM_MULTI_LINE | GENDSM_FORCE_CODE)))
                    if not IsCode_(_ea):
                        _not_code.append(_ea)
                        #  return False
                    _insn_len = GetInsnLen(_ea)
                    if _insn_len:
                        _ea += _insn_len
                    else:
                        msg = "[ShowAppendFchunkReal] while checking we hit a non-code byte at {:x}".format(_ea)
                        raise AdvanceFailure(msg)
                    #  _ea = idc.next_head(_ea)
                if _not_code:
                    print("[info] EaseCode(0x{:x})".format(r.start))
                    EaseCode(r.start, noExcept=1, ignoreMnem=['int', 'int3', 'ud2'])
                    _ea = r.start
                    _not_code = []
                    while _ea < r.end:
                        print("[debug] {:x} {}".format(_ea, idc.generate_disasm_line(_ea, GENDSM_MULTI_LINE)))
                        if not IsCode_(_ea):
                            _not_code.append(_ea)
                        _ea = idc.next_head(_ea)
                    if _not_code:
                        print("[info] append_func_tail not code at 0x{:x}".format(_ea))
                        globals()['warn'] += 1
                        return False
                #  if not IsCode_(r.end):
                    #  print("[warn] append_func_tail not code at r.end 0x{:x}".format(r.end))
                    #  pass
                print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, r.start, r.end))
                rv = idc.append_func_tail(funcea, r.start, r.end)
                if not rv and GetChunkNumber(r.start, funcea) == -1:
                    #  print("[warn] append_func_tail failed, checking range is valid {:x}\u2013{:x} for idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(r.start, r.end, funcea, r.start, r.end))
                    msg = "[warn] couldn't append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) from {}".format(r.start, r.end, funcea, funcea, r.start, r.end, hex(old))
                    globals()['warn'] += 1
                    raise AdvanceFailure(msg)
                    return False
                else:
                    print("[info] succeeded! (rv:{}) append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(rv, r.start, r.end, funcea, funcea, r.start, r.end))
            # results.append(idc.append_func_tail(r.start, r.start + r.length))
    if debug: sprint("autowait...")
    ida_auto.auto_wait()
    if debug: sprint("autowait... done")

    return gruppen_ranges
    # [GenericRange(y) for y in [(x[0], x[0] + x[1]) for x in l if x[2][0]]
    # [(hex(x[0]), hex(x[1]), Name(x[2][0])) for x in l if x[2][0]]
    # GenericRanger([GenericRange(y) for y in [(x[0], x[0] + x[1]) for x in l if x[2][0]]], sort=0)
    # return tuples

    # TODO: deal with actual function heads being in our way

    #  if not ours:
        #  # print("[info] not ours: {:x} {:x}".format(start, end))
        #  print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, start, end))
        #  return idc.append_func_tail(funcea, start, end)
        #  #  forceCode(start, end)
        #  #  return GetChunkEnd(start) == end # or idc.append_func_tail(funcea, start, end)
    #  if not not_ours:
        #  # print("[info] not not_ours: {:x} {:x}".format(start, end))
        #  return 0
#  
    #  appendRanges = GenericRanger(not_ours)
#  
    #  results = []
    #  for r in appendRanges:
        #  print("[info] appendRanged: {:x} {:x}".format(r.start, r.last))
        #  forceCode(r.start, r.last)
        #  print("[info] append_func_tail: {:x} {:x}".format(r.start, r.start + r.length))
        #  print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(r.start, r.start + r.length))
        #  results.append(idc.append_func_tail(r.start, r.start + r.length))
    #  ida_auto.auto_wait()
    #  return min(results)


def GetInsnLenths(ea):
    return obfu.combEx(ea, 1024, oneChunk=1, includeNops=1, includeJumps=1)[1]


def GetInsnCount(ea):
    result = obfu.combEx(ea, 1024, oneChunk=1, includeNops=1, includeJumps=1)
    if isinstance(result, list):
        return len(result[1])
    return 0


def GetInsnRange(ea):
    result = obfu.combEx(ea, 1024, oneChunk=1, includeNops=1, includeJumps=1)
    if isinstance(result, tuple):
        if isinstance(result[0], list) and result[0]:
            count = max(result[0]) - min(result[0])
            if count < 4069:
                return count
            else:
                raise Exception("Sanity check: found {} addresses".format(count))

    return 0


def EndOfContig(ea):
    return _EndOfFlow(ea)

    result = obfu.combEx(ea, 1024, oneChunk=1, includeNops=1, includeJumps=1)
    if result:
        if result[0]:
            return result[0][-1] + 1
    return ea + InsnLen(ea)

def _EndOfFlow(ea=None, soft=False, limit=16):
    """
    _EndOfFlow

    @param ea: linear address
    """
    start = eax(ea)
    owners = GetChunkOwners(start)
    end = start + InsnLen(start)
    flow_ending = False
    last_mnem = ''
    while limit and not flow_ending and GetChunkOwners(end) == owners:
        mnem = MyGetMnem(end)
        if isFlowEnd(end): 
            flow_ending = True
            if soft and isInt(end) and mnem != last_mnem:
                flow_ending = False
        insn_len = InsnLen(end)
        if not insn_len:
            # print("[EndOfFlow] no insn at {:x} {} | {}".format(end, GetDisasm(end), diida(end)))
            break
        end += InsnLen(end)
        limit -= 1
        last_mnem = mnem
    return end

def EndOfFlow(ea, soft=False):
    return _EndOfFlow(ea, soft=soft)
    #  return EaseCode(ea, noExcept=1, forceStart=1)
    #  if EaseCode(ea, noExcept=1, forceStart=1) == False:
        #  return False
    #  if not soft:
        #  return EndOfContig(ea)
    #  return max( EndOfContig(ea), _EndOfFlow(ea) )

def MakeCodeEx(x, y):
    # del_items(ea, flags=0, nbytes=1, may_destroy=None) -> bool
    MyMakeUnknown(x, DOUNK_EXPAND | DOUNK_NOTRUNC, y - x)
    ida_auto.plan_range(x, y)
    ida_auto.auto_make_code(x)
    ida_auto.auto_wait()
    idc.plan_and_wait(x, y, 1)
    # SetFuncEnd(x, y)
    # ida_funcs.set_func_start(x, x)


def remake_func(ea):
    chunks = GetChunkAddresses(ea)
    for x, y in chunks:
        MyMakeUnknown(x, y - x, DOUNK_EXPAND | DOUNK_NOTRUNC)
    for x, y in chunks:
        ida_auto.revert_ida_decisions(x, y)
    for x, y in chunks:
        idc.remove_fchunk(ea, x)
        #  ida_auto.plan_and_wait(x, y)
    ida_auto.auto_make_proc(ea)
    ida_auto.auto_wait()


def reanal_func(ea):
    chunks = GetChunkAddresses(ea)
    for x, y in chunks:
        ida_auto.revert_ida_decisions(x, y)
    #  for x, y in chunks:
    #  ida_auto.plan_and_wait(x, y)
    idaapi.reanalyze_function(ida_funcs.func_t(ea))
    #  ida_auto.auto_make_proc(ea)
    ida_auto.auto_wait()



def fix_non_func(fnAddr, realFnAddr):
    return SmartAddChunkImpl(realFnAddr, fnAddr, EndOfFlow(fnAddr))
    cstart = GetChunkStart(fnAddr)

    if cstart == BADADDR:
        cstart = fnAddr
    cend = GetChunkEnd(fnAddr)
    flowEnd = EndOfFlow(fnAddr)

    # print("0x%x: fix_non_func (%x/%x, (%x), %x)" % (realFnAddr, fnAddr, cstart, cend, flowEnd))

    #  print("fix_non_func: {:x}\u2013{:x} and attach to {:x}".format(cstart, cend, realFnAddr))
    f = idc.get_full_flags(fnAddr)
    # if is_code(f) and is_head(f):
    for x in range(flowEnd - fnAddr):
        addr = fnAddr + x
        if not IsSameFunc(addr, realFnAddr):
            if len(GetFunctionName(addr)):
                ida_funcs.del_func(addr)
            #  idc.remove_fchunk(funcea, tailea)
            RemoveAllChunks(addr)
    #  MyMakeUnknown(cstart, cend, 0)
    if debug: print(("FixNonFunc::AppendFchunk( %x, %x, %x)" % (realFnAddr, fnAddr, flowEnd)))
    # A way to confirm we have a valid chunk to add too:
    targetChunk = idc.first_func_chunk(realFnAddr)
    if targetChunk == BADADDR:
        print("Exception(\"bad chunk\")")

    print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(targetChunk, fnAddr, flowEnd))
    if idc.append_func_tail(targetChunk, fnAddr, flowEnd) == 0:
        ownerNames = set()
        ownedAddresses = dict()
        for addr in range(fnAddr, flowEnd):
            owner = GetChunkOwner(addr)
            ownerName = GetFunctionName(owner)
            sprint("Chunk 0x%x: owned by: %s" % (addr, ownerName))
            if owner < BADADDR:
                dict_append(ownedAddresses, ownerName, addr)
                ownerNames.add(ownerName)

        if len(ownerNames) == 1:
            ownerName = ownerNames.pop()
            if ownerName == GetFunctionName(targetChunk):
                SetChunkStart(ownedAddresses[ownerName][0], fnAddr)
                if flowEnd > ownedAddresses[ownerName][-1]:
                    SetChunkEnd(ownedAddresses[ownerName][0], flowEnd)

        #  raise Exception("failed to add chunk")
    #  raise Exception("tmp")
    #  ida_auto.auto_wait()
    #  ida_auto.auto_make_code(cstart)
    #  MakeCode(cstart)
    #  MyMakeUnknown(GetFuncStart(fnAddr),  GetFuncEnd(fnAddr) - GetFuncStart(fnAddr), 0)

def SetFuncStart(funcea, start):
    """
    SetFuncStart

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    start = eax(start)

    rv = ida_funcs.set_func_start(funcea, start)
    l = ["MOVE_FUNC_OK",
        "MOVE_FUNC_NOCODE",
        "MOVE_FUNC_BADSTART",
        "MOVE_FUNC_NOFUNC",
        "MOVE_FUNC_REFUSED",
    ]
    if rv in l:
        return l[rv]


    

def SetFuncEnd(funcea, end):
    # func = clone_items(ida_funcs.get_func(funcea))
    # if func:
    # idc.auto_wait()
    if funcea == idc.BADADDR:
        return False 
    if IsTail(end):
        new_end = idc.get_item_head(end)
        print("[warn] SetFuncEnd: end {:#x} is not an itemhead, did you mean {:#x}?".format(end, new_end))
        globals()['warn'] += 1
        # end = new_end
        return False
    ida_auto.plan_range(funcea, end)
    if not ida_funcs.set_func_end(funcea, end):
        print("ida_funcs.set_func_end(0x{:x}, 0x{:x})".format(funcea, end))
    idc.auto_wait()
    func_start = GetFuncStart(funcea)
    func_end = GetFuncEnd(funcea)
    cstart, cend = GetChunkStart(funcea), GetChunkEnd(funcea)
    # dprint("[SetFuncENd] funcea, func_start, end, func_end")
    print("[SetFuncEnd] funcea:{:x}, end:{:x}, func_start:{:x}, func_end:{:x}".format(funcea, end, func_start, func_end))
    
    #  if cstart != func_start:
        #  print("[warn] Not a head chunk, consider using SetChunkEnd | {:x}\u2013{:x}" \
                #  .format(
                    #  #  idc.get_func_name(func_start), 
                    #  #  func_start, func_end, 
                    #  #  idc.get_func_name(cstart), 
                    #  cstart, cend
                #  ))
        #  return SetChunkEnd(funcea, end)

    if debug: print("func {}: {:x}\u2013{:x}  chunk {}: {:x}\u2013{:x}".format(idc.get_name(func_start), func_start, func_end, idc.get_name(cstart), cstart, cend))
    if end == cend:
        return True
    
    if not ida_funcs.is_same_func(funcea, idc.prev_head(end)):
        # if debug: print("[warn] set_func_end: end {:#x} or {:#x} should be part of function {:#x} or {:#x}".format(end, idc.prev_head(end), func_start, funcea))
        print("[warn] chunk owner '{}' does not match func owner '{}' | {:x}\u2013{:x}" \
                .format(
                    idc.get_func_name(funcea), 
                    idc.get_func_name(idc.prev_head(end)), 
                    cstart, cend,
                ))
        globals()['warn'] += 1

        #  ptr = idc.prev_head(idc.get_item_head(end))
        #  ptr = idc.get_item_head(end-1)
        ptr = end
        happy = 0
        heads = []
        for r in range(16):
            #  print("[debug] ptr is {:#x}".format(ptr))
            if IsFuncHead(ptr):
                heads.append(ptr)
                #  print("[debug] adding head {:#x}".format(ptr))
            #  else:
                #  print("[debug] not head {:#x}".format(ptr))
            ptr = idc.prev_head(ptr)
            if ida_funcs.is_same_func(funcea, ptr):
                happy = 1
                break
        if happy:
            if heads:
                print("[info] deleting func_heads: {}".format(hex(heads)))
            for head in heads: 
                idc.del_func(head)
            ce = GetChunkEnd(ptr)
            idc.del_items(ce, DOUNK_NOTRUNC, end-ce)
            print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(ptr, ce, end))
            if not idc.append_func_tail(ptr, ce, end):
                print("[warn] idc.append_func_tail({:#x}, {:#x}, {:#x}) failed".format(ptr, ce, end))
                globals()['warn'] += 1
            else:
                print("[info] idc.append_func_tail({:#x}, {:#x}, {:#x}) ok".format(ptr, ce, end))
    else:
        if idc.set_func_end(funcea, end):
            print("[info] set_func_end({:#x}, {:#x})".format(funcea, end))
        else:
            print("[warn] set_func_end({:#x}, {:#x}) failed".format(funcea, end))
            globals()['warn'] += 1
    result = GetChunkEnd(funcea)
    if result != end:
        print("[warn] SetFuncEnd: GetChunkEnd({:#x}) == {:#x}".format(funcea, result))
        globals()['warn'] += 1
        # raise Exception("Terrible")
    return result == end

def rangesAsChunks(_range):
    return [x.chunk() for x in _range]

def modify_chunks(funcea, chunks, keep=None, remove=None):
    # chunks = GenericRanger([GenericRange(x[0], x[1] - 1)           for x in _chunks],            sort = 1)
    # keep   = GenericRanger([GenericRange(a, a + GetInsnLen(a) - 1) for a in slvars.justVisited], sort = 1)
    funcea = GetFuncStart(eax(funcea))
    if funcea & 0xff00000000000000:
        print("[modify_chunks] bad funcea: {:x}".format(funcea))
        return False

    if not remove and not keep:
        return
    if remove is None:
        remove = difference(chunks, keep)
    elif keep is None:
        keep = difference(chunks, remove)

    #  remove = [x for x in remove if GetChunkNumber(x.start) > -1]
    #  if remove: print("remove: \n{}".format(remove))

    # for c in [(x.start, x.end) for x in remove]:
    #    start, end = c
    for chunk in chunks:
        tail = clone_items(GetChunk(chunk.start))
        if not tail:
            print("couldn't get tail from chunk.start {:x}".format(chunk.start))
            FixChunk(chunk.start, owner=funcea)
            continue
        subs = _.remove(remove, lambda x, *a: x.issubset(chunk))
        adds = _.remove(keep,   lambda x, *a: x.issubset(chunk))
        if subs:
            print("super: {}  subs: {}  adds: {}".format(hex(chunk), subs, adds))

            cstart, cend = chunk.chunk()

            if subs[0].start == chunk.start and not IsChunk(tail):
                msg = "can't trim start of head chunk: {}".format(describe_target(subs[0].start))
                raise ChunkFailure(msg)

            if len(subs) == 1 and subs[0].end == cend or subs[0].start == cstart:
                # might be more efficient to process this seperately, as we can
                # trim a chunk in one op
                start, end = subs[0].chunk()

                if end == cend and start == cstart:
                    if not idc.remove_fchunk(funcea, start):
                        print("[warn] cannot remove whole fchunk {}".format(describe_chunk(start, end)))
                        globals()['warn'] += 1
                    else:
                        if debug: print("[info] removed whole fchunk {:#x} - {:#x}".format(start, end))
                elif end == cend:
                    # same end, different start
                    if not ida_funcs.set_func_end(cstart, start): # and not SetFuncEnd(start, start):
                        print("[warn] (1) cannot change end of {} to {:#x}".format(describe_chunk(cstart, cend), start))
                        globals()['warn'] += 1
                        return False
                    else:
                        print("[info] (1) changed end of {} to {:#x}".format(describe_chunk(cstart, cend), start))
                elif start == cstart:
                    # end's cannot match
                    if not ida_funcs.set_func_start(cstart, end):
                        print("[warn] (2) cannot change start of {} to {:#x}".format(describe_chunk(cstart, cend), end))
                        globals()['warn'] += 1
                        return False
                    else:
                        print("[info] (2) changed start of {} to {:#x}".format(describe_chunk(cstart, cend), end))

                continue
            
            # else count(subs) > 1
            # first remove entire chunk
            if not IsChunk(tail):
                # head cannot be removed, trim instead
                if not ida_funcs.set_func_end(cstart, subs[0].start):
                    print("[warn] (4) cannot change end of {} to {:#x}".format(describe_chunk(cstart, cend), subs[0].start))
                    globals()['warn'] += 1
                    return False
                else:
                    print("[info] (4) changed end of {} to {:#x}".format(describe_chunk(cstart, cend), subs[0].start))
                    cend = subs[0].start
            else:
                if not idc.remove_fchunk(cstart, cend):
                    print("[warn] (3) cannot remove whole fchunk {}".format(describe_chunk(cstart, cend)))
                    globals()['warn'] += 1
                    return False
                else:
                    if debug: print("[info] removed whole fchunk {:#x} - {:#x}".format(cstart, cend))
                    cstart = None
                    cend = None

            # then re-add the sections we want to keep
            for start, end in rangesAsChunks(adds):
                if start != cstart:
                    print("[info] adding {}".format(describe_chunk(start, end)))
                    end = EaseCode(start, end, forceStart=1, noExcept=1, noFlow=1)
                    if isinstance(end, integer_types):
                        ida_auto.plan_and_wait(start, end)
                        idc.append_func_tail(funcea, start, end)

    if remove:
        print("unused remove subs: {}".format(remove))
    if keep:
        print("unused keep subs: {}".format(keep))


    return True

def chunk_remove_range(sEA, eEA):
    """
    @param sEA: starting linear address
    @param eEA: ending linear address (excluded)

    @return success: number of chunks modified (or 0)
    """
    result = True
    if eEA > sEA and eEA < BADADDR and eEA - sEA < 1024:
        heads = Heads(sEA, eEA)
        groups = _.groupBy(asList([0] + asList(heads)), lambda x, *a: GetChunkStart(x))
        print("groups", groups)
        
        for cstart, addresses in groups.items():
            chunks = [GenericRange(cstart, GetChunkEnd(cstart) - 1)]
            remove = GenericRanger([GenericRange(a, a + GetInsnLen(a) - 1) for a in addresses], sort = 1)
            if modify_chunks(GetFuncStart(sEA), chunks, remove=remove) == False:
                result = False 

    return result

def reloc_name(ea=None):
    if ea is None: ea = ScreenEA

    if idc.hasUserName(idc.get_full_flags(ea)):
        fnName = GetFunctionName(ea) + "_RELOC_11"
    else:
        fnName = "reloc10_%x" % ea
    return fnName


def readObjectFile(asmName):
    with open(asmName, "rb") as fr:
        o = fr.read()
        if len(o):
            return True, bytearray(o)
        else:
            return False, "no output"


def color_here(ea = None):
    if ea is None:
        color = idc.get_color(idc.here(), CIC_ITEM)
    else:
        color = idc.get_color(ea, CIC_ITEM)
    if color == 4294967295:
        color = 0x022028
    return color

def int_to_rgb(value):
    return hex_to_rgb(("#%06x" % value)[0:7])

def lighten(rgb):
    hsl = colorsys.rgb_to_hls(*rgb)
    lighter = (hsl[0], hsl[1] + 0.1, hsl[2])
    return colorsys.hls_to_rgb(*lighter)


def make_transpose_fn(sourceRange, targetRange):
    sourceRange = asList(sourceRange)
    targetRange = asList(targetRange)
    def transpose(value):
        if isIterable(value):
            result = list()
            for i, val in enumerate(value):
                result.append(transpose(val, sourceRange[i], targetRange[i]))
            return result

        return (value - sourceRange[0]) * (targetRange[1] - targetRange[0]) / (sourceRange[1] - sourceRange[0]) + targetRange[0];
    return transpose

def transpose(value, sourceRange, targetRange):
    return make_transpose_fn(sourceRange, targetRange)(value)

def gradient(begin, end, steps):
    hsv_begin = colorsys.rgb_to_hsv(*hex_to_colorsys_rgb(begin))
    hsv_end = colorsys.rgb_to_hsv(*hex_to_colorsys_rgb(end))

    hr = (hsv_begin[0], hsv_end[0])
    hs = (hsv_begin[1], hsv_end[1])
    hv = (hsv_begin[2], hsv_end[2])

    source_range = [(0, steps-1)] * 3

    result = list()

    for i in range(steps):
        vals = [i] * 3
        target_range = (hr, hs, hv)
        
        result.append(rgb_to_hex(colorsys_rgb_to_rgb(colorsys.hsv_to_rgb(*transpose(vals, source_range, target_range)))))

    return result

def hex_to_rgb(value):
    if isInt(value):
        value = "{:08x}".format(value)
    value = value.lstrip('#')
    lv = len(value)
    result = tuple(int(value[i:i + lv // 3], 16) for i in range(0, lv, lv // 3))
    if lv == 3:
        return tuple([x * 0x11 for x in result])
    
    return result


def hex_to_rgb_dword(value):
    if isinstance(value, str) or isString(value):
        src = hex_to_rgb(value)
    else:
        src = value
    
    t = [x for x in src]
    dw = 0
    sw = 16
    for x in t:
        dw |= x << sw
        sw -= 8

    return dw


def hex_to_colorsys_rgb(value):
    return tuple([x / 255.0 for x in hex_to_rgb(value)])


def colorsys_rgb_to_dword(value):
    color = [int(math.floor(x)) for x in value]
    t = [x for x in color]
    dw = 0
    sw = 16
    for x in t:
        dw |= x << sw
        sw -= 8

    return dw

def colorsys_rgb_to_rgb(value):
    return tuple([int(round(x * 255)) for x in value])


def rgb_to_hex(rgb):
    rgb = [int(x) for x in rgb]
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def rgb_to_int(rgb):
    return int(rgb_to_hex(rgb).lstrip('#'), 16)


def call_everything(insn, *args):
    def len(*args):
        try:
            return builtins.len(*args)
        except TypeError:
            return 0

    object_methods = [method_name for method_name in dir(insn) if not method_name.startswith('__') and method_name != 'clear' and not method_name.startswith('set')]
    # dprint("[call_everything] object_methods")
    print("[call_everything] object_methods:{}".format(object_methods))
    
    can_call = []
    for method_name in object_methods:
        try:
            if callable(getattr(insn, method_name)):
                can_call.append(method_name)
        except AttributeError:
            pass
    # dprint("[call_everything] object_methods")
    print("[call_everything] can_call:{}".format(can_call))
    should_call = []
    for method_name in can_call:
        if method_name[0].islower():
            try:
                argspec = inspect.getfullargspec(getattr(insn, method_name))
                print("argspec: {}".format(argspec))
                # [('annotations',    {},      "<class 'dict'>"),
                #  ('args',           ['self', 'default'],            "<class 'list'>"),
                #  ('defaults',       (None, ),"<class 'tuple'>"),
                #  ('kwonlyargs',     [],      "<class 'list'>"),
                #  ('kwonlydefaults', None,    "<class 'NoneType'>"),
                #  ('varargs',        None,    "<class 'NoneType'>"),
                #  ('varkw',          None,    "<class 'NoneType'>")]
                _args = argspec.args
                arglen = len(_args)
                if _args and _args[0] == 'self':
                    arglen -= 1
                arglen -= len(argspec.defaults)
                # arglen -= (len(argspec.defaults) - len(args))
                # dprint("[debug] arglen, len(args), len(argspec.defaults)")
                print("[debug] {} arglen:{}, len(args):{}, len(argspec.defaults):{}".format(method_name, arglen, len(args), len(argspec.defaults)))
                if arglen <= len(args):
                    should_call.append(method_name)
            except TypeError:
                doc = getattr(insn, method_name).__doc__
                if doc:
                    print("doc: {}".format(doc))
                    args = string_between('(', ')', doc)
                    retn = string_between('->', '', doc).strip()
                    print(retn, args)
                    if retn == 'int' and args:
                        args = args.split(',')
                        args = [x.strip() for x in args]
                        args = [x for x in args if x and x != 'self']
                        if len(args) == 0:
                            should_call.append(method_name)
    results = []
    # dprint("[debug] should_call")
    print("[debug] should_call:{}".format(should_call))
    
    for method_name in should_call:
        try:
            print("[calling] method_name:{}".format(method_name))
            result = getattr(insn, method_name)(*args)
            # dprint("[called] method_name, result")
            print("[called] method_name:{}, result:{}".format(method_name, result))
            
            if isinstance(result, integer_types) and result > 9:
                result = hex(result)
            results.append((method_name, result))
        except Exception as e:
            pass
            # results.append((method_name, e))
    return results


def clone_items(insn, filter_iteratee=None):
    obj = AttrDict()
    for item in [
            (method_name, getattr(insn, method_name))
            for method_name in dir(insn)
            if hasattr(insn, method_name) 
            and not method_name.startswith('_') 
            and not re.match(r'.*(method|proxy|Swig)', str(getattr(insn, method_name)), re.I)]:
        if not filter_iteratee or filter_iteratee(*item):
            obj[item[0]] = item[1]
    return obj
        

def read_everything(insn):
    return [(method_name, hex(getattr(insn, method_name)), str(type(getattr(insn, method_name)))) 
            for method_name in dir(insn)
            if hasattr(insn, method_name) 
            and not method_name.startswith('_') and method_name not in ('copyright', 'credits')
            and not re.match(r'.*(method|proxy|Swig)', str(getattr(insn, method_name)), re.I)
            and not issubclass(type(getattr(insn, method_name)), (Exception, BaseException))
            ]


class AppendChunkError(Exception):
    pass

class ChunkFailure(Exception):
    """ChunkFailure.
    """

    pass

def UnChunk(ea):
    """UnChunk.

    Args:
        ea:
    """
    chunks = []
    fnName = GetFunctionName(ea)
    if fnName:
        print("UnChunking fnName: %s" % fnName)
        fnLoc = LocByName(fnName)
        chunk_seq = idautils.Chunks(fnLoc)
        print("0x%0x fnName: %s (chunk_seq: %s)" % (fnLoc, fnName, len(list(chunk_seq))))
        for chunk in chunk_seq:
            chunkStart = chunk[0]
            chunkEnd = chunk[1]
            chunkName = Name(chunk[0])
            print("0x%0x - 0x%0x: %s" % (chunkStart, chunkEnd, chunkName))
            chunks.append(chunkStart)
            if len(chunks) > 1:
                print("removing chunk")
                RemoveFchunk(fnLoc, chunkStart)
        return True
    return False


"""
Python>DebugChunks(ERROREA())
Chunks belonging to: _0x58bb377bec7cd5f4_impl
    140a56d50 - 140a56d78  DATA     140a6ea3a  sub_140A8208B  loc_140A6EA3A  lea     rcx, _0x58bb377bec7cd5f4_impl; fn 
                           FLOW     140a56d4f                                int     3                     ; Trap to Debugger

 *  140390dd8 - 140390e27  JMP      140a56d5f  _0x58bb377bec7cd5f4_impl      jmp     loc_140390DD8 
                           JMP      140a56d73  _0x58bb377bec7cd5f4_impl      jmp     loc_140390DD8
                           SEGMENT  142dd05b8 .pdata
                           DATA     144a44fdc  APP::_0x9BD7BD55E4533183_0    lea     rbp, loc_140390DD8
                           DATA     143d2763d  APP::_0x58BB377BEC7CD5F4_0    lea     rbp, loc_140390DD8

"""

class ChunkFailure(Exception):
    """ChunkFailure.
    """

    pass

def GetAllNames(ea):
    """GetAllNames.

    Args:
        ea:
    """
    fnName = GetFunctionName(ea)
    locName = idc.get_name(ea)
    if not fnName:         return locName
    if not locName:        return fnName
    if fnName == locName:  return fnName
    return "%s  %s" % (fnName, locName)

def FindAll(patternHex):
    """FindAll.

    Args:
        patternHex:
    """
    found = 0x1400000
    addresses = set()
    while found != BADADDR:
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, patternHex)
        if found != BADADDR:
            addresses.add(found)

    return addresses

def RefsTo(ea = None):
    if ea is None:
        ea = idc.get_screen_ea()

    for xref in XrefsTo(here(), 0):                          
        print(xref.type, XrefTypeName(xref.type),            
                  'from', hex(xref.frm), 'to', hex(xref.to))

    refs = [x for x in XrefsTo(ea, 0)]

def AllRefsTo(ea):
    """AllRefsTo.

    Args:
        ea:
    """
    allRefs  = set()
    jmpRefs  = set()
    dataRefs = set()
    fnRefs   = set()
    unchunked= set();
    if isinstance(ea, set):
        for addr in ea:
            #  addr = idc.prev_head(idc.next_head(addr))
            addr = LocByName(Name((idc.prev_head(addr + 1))))
            print("Looking up %s" % hex(addr))
            if (addr != BADADDR):
                allRefs  = allRefs.union(set(idautils.CodeRefsTo(addr, 1)))
                jmpRefs  = allRefs.union(set(idautils.CodeRefsTo(addr, 0)))
                dataRefs = allRefs.union(set(idautils.DataRefsTo(addr)))
                for a in allRefs.union(dataRefs):
                    fnName = GetFunctionName(a)
                    if (len(fnName)):
                        fnRefs.add(fnName)


    else:
        allRefs  = set(idautils.CodeRefsTo(ea, 1))
        jmpRefs  = set(idautils.CodeRefsTo(ea, 0))
        dataRefs = set(idautils.DataRefsTo(ea))
    callRefs = set()
    segRefs  = set()
    jcRefs   = set()
    segRefNames = set()
    unchunked = [e for e in allRefs if idc.get_func_name(e) and not IsChunked(e)]

    _jmpRefs = jmpRefs
    jmpRefs = set()
    for a in _jmpRefs.copy():  
        insn = idautils.DecodeInstruction(a)
        if insn is not None:
            if insn.get_canon_mnem() == 'call':
                callRefs.add(a)
                _jmpRefs.remove(a)
            elif insn.get_canon_mnem() == 'jmp':
                jmpRefs.add(a)
            elif insn.get_canon_mnem().startswith('j'):
                jmpRefs.add(a)
                jcRefs.add(a)

    for a in _jmpRefs.difference(jmpRefs):
        print("deleting suspect jmpref: {:x} {}".format(a, diida(a)))
        ida_xref.del_cref(a, ea, 0)

    for a in dataRefs: 
        if SegName(a) != ".text": 
            segRefNames.add(SegName(a))
            segRefs.add(a)

    flowRefs  = allRefs - jmpRefs
    allRefs   = allRefs.union(dataRefs)
    nonFlowRefs = allRefs - flowRefs

    for a in allRefs:
        fnName = GetFunctionName(a)
        if (len(fnName)):
            fnRefs.add(fnName)




    dataRefs -= segRefs
    jmpRefs  -= callRefs
    return {
        "allRefs":     allRefs,
        "callRefs":    callRefs,
        "dataRefs":    dataRefs,
        "flowRefs":    flowRefs,
        "nonFlowRefs": nonFlowRefs,
        "fnRefs":      fnRefs,
        "jcRefs":      jcRefs,
        "jmpRefs":     jmpRefs,
        "segRefs":     segRefs,
        "segRefNames": segRefNames,
        "unchunked":   unchunked
    }

def AllRefsFrom(ea):
    """AllRefsFrom.

    Args:
        ea:
    """
    allRefs  = set()
    jmpRefs  = set()
    dataRefs = set()
    fnRefs   = set()
    codeRefs = set()
    if isinstance(ea, set):
        for addr in ea:
            #  addr = idc.prev_head(idc.next_head(addr))
            addr = LocByName(Name((idc.prev_head(addr + 1))))
            print("Looking up %s" % hex(addr))
            if (addr != BADADDR):
                allRefs  = allRefs.union(set(idautils.CodeRefsFrom(addr, 1)))
                jmpRefs  = allRefs.union(set(idautils.CodeRefsFrom(addr, 0)))
                dataRefs = allRefs.union(set(idautils.DataRefsFrom(addr)))
                for a in allRefs.union(dataRefs):
                    fnName = GetTrueName(a)
                    if IsFuncHead(a):
                        fnRefs.add(fnName)
                for a in allRefs.union(dataRefs):
                    if isCodeish(a):
                        codeRefs.add(a)
    else:
        allRefs  = set(idautils.CodeRefsFrom(ea, 1))
        jmpRefs  = set(idautils.CodeRefsFrom(ea, 0))
        dataRefs = set(idautils.DataRefsFrom(ea))
    callRefs = set()
    segRefs  = set()
    jcRefs   = set()
    segRefNames = set()

    for a in jmpRefs:  
        insn = idautils.DecodeInstruction(a)
        if insn is not None:
            if insn.get_canon_mnem() == 'call':
                callRefs.add(a)
            elif insn.get_canon_mnem() == 'jmp':
                pass
            elif insn.get_canon_mnem().startswith('j'):
                jcRefs.add(a)

    for a in dataRefs: 
        if SegName(a) != ".text": 
            segRefNames.add(SegName(a))
            segRefs.add(a)

    flowRefs  = allRefs - jmpRefs
    allRefs   = allRefs.union(dataRefs)
    nonFlowRefs = allRefs - flowRefs

    for a in allRefs:
        fnName = GetTrueName(a)
        if IsFuncHead(a):
            fnRefs.add(fnName)
        if isCodeish(a):
            codeRefs.add(a)



    dataRefs -= segRefs
    jmpRefs  -= callRefs
    return {
        "allRefs":     allRefs,
        "callRefs":    callRefs,
        "dataRefs":    dataRefs,
        "flowRefs":    flowRefs,
        "nonFlowRefs": nonFlowRefs,
        "fnRefs":      fnRefs,
        "jcRefs":      jcRefs,
        "jmpRefs":     jmpRefs,
        "segRefs":     segRefs,
        "segRefNames": segRefNames
    }

def find_function_callees( func_ea, maxlvl ):

    callees = []
    visited = set()
    pending = set( (func_ea,) )
    lvl = 0

    while len(pending) > 0:
        func_ea = pending.pop()
        visited.add(func_ea)

        func_name = idc.GetFunctionName(func_ea)
        if not func_name: continue
        callees.append(func_ea)

        func_end = idc.FindFuncEnd(func_ea)
        if func_end == idaapi.BADADDR: continue

        lvl +=1
        if lvl >= maxlvl: continue

        all_refs = set()
        for line in idautils.Heads(func_ea, func_end):

            if not ida_bytes.isCode(get_flags(line)): continue

            ALL_XREFS = 0
            refs = idautils.CodeRefsFrom(line, ALL_XREFS)
            refs = set( filter( lambda x: not (x >= func_ea and x <= func_end), 
                                refs) )
            all_refs |= refs

        all_refs -= visited
        pending |= all_refs

    return callees

def CallRefsTo(ea):
    """CallRefsTo.

    Args:
        ea:
    """
    return AllRefsTo(ea)["callRefs"]

def JmpRefsTo(ea):
    """JmpRefsTo.

    Args:
        ea:
    """
    return AllRefsTo(ea)["jmpRefs"]

def GetChunks(ea = 0, silent = True):
    """GetChunks.

    Args:
        ea:
        silent:
    """
    if not ea:
        ea = idc.get_screen_ea()

    if ea is str:
        fnLoc  = idc.get_name_ea_simple(ea)
        fnName = idc.get_func_name(fnLoc)
    else:
        fnName = idc.get_func_name(ea)
        fnLoc  = idc.get_name_ea_simple(fnName)

    chunk_list = list(idautils.Chunks(fnLoc))
    if not chunk_list:
        return list()


    if fnLoc != chunk_list[0][0]:
        raise ChunkFailure("0x%x: fnLoc != chunk_list[0][0]" % ea)

    chunks = list()
    if not silent: print("Chunks belonging to: %s" % fnName)

    for chunk in chunk_list:
        chunkStart = chunk[0]
        chunkEnd   = chunk[1]
        chunkName  = Name(chunk[0])

        refs = AllRefsTo(chunkStart)
        allRefs = refs["allRefs"]
        callRefs = refs["callRefs"]
        dataRefs = refs["dataRefs"]
        flowRefs = refs["flowRefs"]
        jmpRefs = refs["jmpRefs"]
        segRefs = refs["segRefs"]
        owners = GetChunkOwners(chunkStart)

        refList = list()
        chunks.append({ 
            'name': chunkName,
            'func': GetFunctionName(chunkStart),
            'names': GetAllNames(chunkStart),
            'start': chunkStart, 
            'end': chunkEnd, 
            'allRefs': allRefs - flowRefs, 
            'refs': refs,
            'owners': owners,
            'current': True if chunkStart <= ea < chunkEnd else False
        })
        for ref in jmpRefs:  refList.append("JMP      %09x  %-64s %s" % (ref, GetAllNames(ref), GetDisasm(ref)))
        for ref in callRefs: refList.append("CALL     %09x  %-64s %s" % (ref, GetAllNames(ref), GetDisasm(ref)))
        for ref in segRefs:  refList.append("SEGMENT  %09x %s"        % (ref, SegName(ref)))
        for ref in dataRefs: refList.append("DATA     %09x  %-64s %s" % (ref, GetAllNames(ref), GetDisasm(ref)))
        for ref in flowRefs: refList.append("FLOW     %09x  %-64s %s" % (ref, GetAllNames(ref), GetDisasm(ref)))

        currentChunk = "*" if chunkStart <= ea < chunkEnd else " "

        if not silent: print(" %s  %09x - %09x  %s " % (currentChunk, chunkStart, chunkEnd, refList[0] if refList else ""))

        if refList: refList.pop(0)
        for s in refList:
            if not silent: print("%27s%s" % ("", s))

        if not silent: print("")
    return chunks

def split_chunks(chunks):
    """ takes a list of chunks from idautils.Chunks and further seperates them if `jmp`s are encoutered.
        e.g.

        ; START OF FUNCTION CHUNK FOR func_1
        
        loc_140CA17AD:                      
                        jmp     loc_143DF57E6
        ; ---------------------------------------------------------------------------
        
        loc_140CA17B2:                     
                        jmp     loc_140D79FF4
        ; END OF FUNCTION CHUNK FOR func_1
    """

    for startea, endea in chunks:
        # EaseCode(startea, forceStartIfHead=1)
        pos = startea
        for i in range(1000):
            # if debug > 1: print("*** {:x} split_chunks".format(pos))
            insn_len = 9999
            while (pos == startea or pos < endea and IsFlow(pos)) and insn_len > 0:
                insn_len = GetInsnLen(pos)
                # if debug > 1: print("{:x} {}".format(pos, diida(pos)))
                #  if not insn_len:
                    #  print("[split_chunks] insn_len: {} at {:x}; ending chunk".format(insn_len, pos))
                    #  SetFuncOrChunkEnd(startea, pos)
                    #  endea = pos
                pos += GetInsnLen(pos)
            # if debug > 1: print("*** ".format(pos))
            if startea == pos:
                break
            yield startea, pos
            if pos < endea:
                startea = pos
            else:
                break


def OurGetChunkStart(ea, chunks):
    _start = GetChunkStart(ea)
    if _start & 0xff00000000000000:
        return _start

    for cstart, cend in chunks:
        # dprint("[debug] cstart, cend, ea")
        #  print("[debug] cstart:{:x}, cend:{:x}, ea:{:x}".format(cstart, cend, ea))
        
        if cstart <= ea < cend:
            #  print("[debug] cstart:{:x}, cend:{:x}, ea:{:x} **FOUND**".format(cstart, cend, ea))
            return cstart

    if debug: print("[OurGetChunkStart] couldn't find chunk for {:x}, returning GetChunkStart result: {:x}".format(ea, _start))
    return _start

def OurGetChunkEnd(ea, chunks):
    _start = GetChunkStart(ea)
    if _start & 0xff00000000000000:
        return _start

    for cstart, cend in chunks:
        #  dprint("[debug] cstart, cend, ea")
        # if debug > 1: print("[debug] cstart:{:x}, cend:{:x}, ea:{:x}".format(cstart, cend, ea))
        
        if cstart <= ea < cend:
            # if debug > 1: print("[debug] cstart:{:x}, cend:{:x}, ea:{:x} **FOUND**".format(cstart, cend, ea))
            return cend

    rv = GetChunkEnd(ea)
    print("[OurGetChunkEnd] couldn't find chunk for {:x}, returning GetChunkEnd result: {:x}".format(ea, rv))
    return rv



def GetChunkAddresses(ea = 0):
    """GetChunkAddresses.

    Args:
        ea:
    """
    chunks = GetChunks(ea, silent = 1)
    return [(x["start"], x["end"]) for x in chunks]

def GetChunkAddressesZeroOffset(ea = 0):
    """GetChunkAddresses.

    Args:
        ea:
    """
    chunks = GetChunks(ea, silent = 1)
    return [(x["start"] - 0x140000000, x["end"] - x["start"]) for x in chunks]
    # return [(x[0] - 0x140000000, x[1] - x[0]) for x in chunks]


def CheckAllChunkForMultipleOwners():
    for ea in idautils.Functions():
      o = _.uniq(_.flatten(_.pluck(GetChunks(ERROREA()), 'owners')))
      if len(o) > 1:
        print("{:x}".format(o))


def RemoveChunk(*args):
    """
    @brief RemoveChunk

    Removes a single chunk from a function.

    @param [optional] functionAddress: any address inside the function and chunk
    @param chunkAddress: any address inside the chunk
    """
    from inspect import getframeinfo, currentframe, getdoc

    if len(args) == 2:
        funcStart = args[0]
        chunkAddr = args[1]
    elif len(args) == 1:
        chunkAddr = args[0]
        funcStart = GetFuncStart(chunkAddr)
        if funcStart == BADADDR:
            print("Couldn't find function for chunk at {:x}".format(chunkAddr))
            return
    else:
        # https://stackoverflow.com/questions/8822701/how-to-print-docstring-of-python-function-from-inside-the-function-itself
        print(getdoc(globals()[getframeinfo(currentframe()).function]))

    return idc.remove_fchunk(funcStart, chunkAddr)

def RemoveThisChunk(ea = 0):
    """RemoveThisChunk.

    Args:
        ea:
    """
    if not ea:
        ea = ScreenERROREA()

    try:
        chunks = GetChunks(ea)
        if len(chunks) < 2:
            #  print("0x%x: This is not a chunk" % ea)
            return False

        for chunk in chunks:
            if chunk['current']:
                if chunks[0]['start'] == chunk['start']:
                    #  print("0x%x: Cannot remove primary chunk" % ea)
                    return False
                #  print("calling RemoveFChunk")
                return idc.remove_fchunk(chunks[0]['start'], chunk['start'])
    except ChunkFailure:
        pass


    return False

def RemoveGrannyChunks(ea = 0):
    """RemoveGrannyChunks.

    Args:
        ea:
    """
    if not ea:
        ea = ScreenERROREA()

    if ea is str:
        fnLoc  = LocByName(ea)
        fnName = GetFunctionName(fnLoc)
    else:
        fnName = GetFunctionName(ea)
        fnLoc  = LocByName(fnName)

    chunks = GetChunks(fnLoc)
    for chunk in chunks:
        if chunk["func"] != fnName:
            idc.remove_fchunk(fnLoc, chunk["start"])

def RemoveAllChunkOwners(ea=None, last=None, leave=None):
    """
    RemoveAllChunkOwners

    @param ea: linear address
    """
    ea = eax(ea)
    if leave:
        last = leave
    owners = GetChunkOwners(ea)
    for parent in owners:
        if not last or last != parent:
            if not idc.remove_fchunk(parent, ea):
                print("[RemoveAllChunkOwners] couldn't remove chunk {:x}".format(ea))
    if last: #  and not leave:
        idc.remove_fchunk(last, ea)
        print("[RemoveAllChunkOwners] couldn't remove last chunk {:x}".format(ea))

def RemoveAllChunks(ea = 0):
    """RemoveAllChunks.

    Args:
        ea:
    """
    if not ea:
        ea = ScreenERROREA()

    chunk_list = list(idautils.Chunks(ea))
    l = chunk_list[:]
    for r in range(100):
        if len(l) < 2:
            # print("0x%x: There are no chunks" % ea)
            return chunk_list

        l = list(idautils.Chunks(ea))
        for start, end in l:
            idc.remove_fchunk(GetFuncStart(ea), start)

    return chunk_list

def get_dtype(ea, op_idx):
    if idaapi.IDA_SDK_VERSION >= 700:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        dtype = insn.ops[op_idx].dtype
        dtyp_size = idaapi.get_dtype_size(dtype)
    else:
        dtype = idaapi.cmd.Operands[op_idx].dtyp
        dtyp_size = idaapi.get_dtyp_size(dtype)
    return dtype, dtyp_size

def get_create_data_func(size):
    sizes = [ ida_bytes.FF_BYTE, ida_bytes.FF_WORD, ida_bytes.FF_DWORD, ida_bytes.FF_QWORD, ida_bytes.FF_OWORD, ida_bytes.FF_YWORD ]
    n = log2(size);
    ff_size = sizes[n]
    return lambda x: ida_bytes.create_data(x, ff_size, size, ida_idaapi.BADADDR)


# This is the same as idautils.Chunks()
def testchunks(ea):
    """testchunks.

    Args:
        ea:
    """
    function_chunks = []

    #Get the tail iterator
    func_iter = idaapi.func_tail_iterator_t(idaapi.get_func(ea))

    # While the iterator?s status is valid
    status = func_iter.main()

    while status:
        # Get the chunk
        chunk = func_iter.chunk()

        # Store its start and ending address as a tuple
        function_chunks.append((chunk.start_ea, chunk.endEA))

        # Get the last status
        status = func_iter.next()

    return function_chunks



def AddRelocSegment(start_ea = None, size = 0x1000000, base = 1, use32 = 2, align = 3, comb = 2, flags = 0x20): # idc.ADDSEG_SPARSE
    """
    Create a new segment

    @param start_ea: linear address of the start of the segment
    @param endea: linear address of the end of the segment
               this address will not belong to the segment
               'endea' should be higher than 'start_ea'
    @param base: base paragraph or selector of the segment.
               a paragraph is 16byte memory chunk.
               If a selector value is specified, the selector should be
               already defined.
    @param use32: 0: 16bit segment, 1: 32bit segment, 2: 64bit segment
    @param align: segment alignment. see below for alignment values
    @param comb: segment combination. see below for combination values.
    @param flags: combination of ADDSEG_... bits

    @return: 0-failed, 1-ok
    """

    #  for k, v in idc._SEGATTRMAP.items():
    #      print(v[1], idc.get_segm_attr(0x144c13000, k))
    #  
    #  start_ea 5448478720
    #  end_ea 5468323840
    #  orgbase 0
    #  align 3
    #  comb 2
    #  perm 5
    #  bitness 2
    #  flags 0
    #  sel 1
    #  0 18446744073709551615
    #  1 18446744073709551615
    #  2 18446744073709551615
    #  3 18446744073709551615
    #  4 18446744073709551615
    #  5 18446744073709551615
    #  type 3
    if idc.selector_by_name('.text2') != BADADDR:
        return False

    if start_ea is None:
        existing_segment_starts = idautils.Segments()
        existing_segment_ends = [idc.get_segm_end(x) for x in existing_segment_starts]
        start_ea = _.max(existing_segment_ends)

    s = ida_segment.segment_t()
    s.start_ea = start_ea
    s.end_ea   = start_ea + size
    s.sel      = ida_segment.setup_selector(base)
    s.bitness  = use32
    s.align    = align
    s.comb     = comb
    s.perm     = 7
    r = ida_segment.add_segm_ex(s, ".text2", "CODE", flags)
    print("r", r)
    # if r:
    idc.set_segm_type(start_ea, idc.SEG_CODE)
    # idc.set_segm_attr(start_ea, SEGATTR_PERM, 7)
    LabelAddressPlus(start_ea, "next_relocation", force = 1)
    
    return r

def _fix_spd(l):
    # l = [ (0x140a5b4aa, 0x088), (0x140a68a7b, 0x088), (0x140a68a85, 0x088), (0x140a68aee, 0x088), (0x140aa42fc, 0x088), (0x140cc9241, 0x088), (0x140d09565, 0x000), (0x140d628c9, 0x090), (0x14181d848, 0x088), (0x14181d84c, 0x088), (0x141846c20, 0x088), (0x1433177ab, 0x088), (0x1433177b2, 0x088), (0x1433177b6, 0x088), (0x1433177bd, 0x088), (0x143dd53f9, 0x088), (0x143dd53ff, 0x088), (0x143dd5405, 0x088), (0x143e42f40, 0x088), (0x143ebb984, 0x008), (0x143ebb985, 0x000), (0x143ebb989, 0x000), (0x143ebb98d, 0x000), (0x14411a3bb, 0x088), (0x14411a3bf, 0x088), (0x14412d699, 0x088), (0x14412d6a0, 0x088), (0x1443caa98, 0x088), (0x1443caa9d, 0x088), (0x1443caaa3, 0x088), (0x1443caaa8, 0x088), (0x1445eeb3c, 0x088), (0x144600c8d, 0x088), (0x14460b1ca, 0x088), (0x14460b1cc, 0x088), (0x14462c33e, 0x088), (0x14462c343, 0x088), (0x144633381, 0x088), (0x144633389, 0x088), (0x14463338d, 0x088), (0x144633391, 0x088), (0x144633395, 0x008), (0x14463339e, 0x000), (0x144655b81, 0x088), (0x144655b86, 0x088), (0x144655b8b, 0x088), (0x144655b90, 0x088), (0x144679c94, 0x088), (0x1446931e9, 0x088), (0x1446931ed, 0x088), (0x1446931f4, 0x088), (0x1446931f8, 0x088), (0x1446fb1b4, 0x088), (0x1446fb1ba, 0x088), (0x1447227f7, 0x008), (0x1447227fe, 0x088), (0x144722803, 0x088) ]
    l.sort()
    # r = [ (hex(GetSpd(e)), hex(f), hex(e)) for e, f in l ]
    # pp(r)

    _chunks = list(split_chunks(idautils.Chunks(l[0][0])))

    for x in l:
        ea = x[0]
        if debug: print("[_fix_spd] {:x} {:x}".format(ea, x[1]))
        #  fnStart = GetFuncStart(ea)
        #  chunkStart = OurGetChunkStart(ea, _chunks)
        #  if chunkStart == fnStart:
            #  continue

        chunkEnd = OurGetChunkEnd(ea, _chunks)

        #  if not chunkStart == ea:
            #  continue
        
        correct_sp = 0 - x[1]   # -0x88
        actual_sp = idc.get_spd(ea)  # -0x8
        actual_delta = idc.get_sp_delta(ea) # -0x8
        if actual_sp is None or actual_delta is None:
            return False

        adjust = correct_sp - actual_sp # -0x88 - -0x8 == -0x80
        new_delta = adjust + actual_delta
        if debug: print("{:x} current spd: {:x}  desired spd: {:x}  current spdiff: {:x}  new spdiff: {:x}".format(ea, actual_sp, correct_sp, actual_delta, new_delta))
        if actual_sp != correct_sp:
            if debug: print("{:x} adjusting delta by {:x} to {:x}".format(ea, adjust, actual_delta + adjust))
            idc.add_user_stkpnt(ea, new_delta) # -0x8 + -0x80
            idc.auto_wait()
            return True

    return False

def _fix_spd_auto(funcea=None):
    """
    _fix_spd_auto

    @param funcea: any address in the function
    """
    if not isinstance(funcea, list):
        funcea = eax(funcea)
        func = ida_funcs.get_func(funcea)

        if not func:
            return
        else:
            funcea = func.start_ea

        ea = funcea
        spdList = []
        try:
            spd = slowtrace2(ea, spdList=spdList, vimlike=1)
            #  spd = slowtrace2(ea, vimlike=1, modify=0, ignoreStack=1, spdList=spdList)
        except RelocationStackError as e:
            print("[_fix_spd_auto] RelocationStackError: {}".format(e.args))
            return
        except BaseException as e:
            print("[_fix_spd_auto] BaseException: {}: {}".format(str(e), e.args))
            return
    else:
        spdList = funcea
    for r in range(100):
        if not _fix_spd(spdList):
            break

    if not isinstance(funcea, list):
        return spd
    # return slowtrace2(ERROREA(), modify=1, ignoreStack=1, spdList=spdList)

def generate_disasm_line_unspaced(ea, flags):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @param flags: combination of the GENDSM_ flags, or 0

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    line = idc.generate_disasm_line(ea, flags)
    if not line:
        return line
    return " ".join(filter(lambda x: x, line.split(' ')))

def fix_split_refs(ea):
    """
    Intended to be used for refs to .text (in this case the 3rd) sections
    .text:0000000143019000                                   ; ---------------------------------------------------------------------------
    .text:0000000143019000                                   ; Section 11. (virtual address 03019000)
    """
    refs = xrefs_to(ea)
    for e in refs:
        # fix_split_segment_jump(e)
        if Byte(e - 1) == 0x90:
            s = diida(e)
            nassemble(e - 1, s, apply=1)

def fix_split_refs_2245():
    fix_split_refs(0x143019000)
    while RemoveChunk(0x143019000):
        pass

def colwrap(col, s, pname = None):
    if isinstance(col, str):
        col = ord(col)
    if pname:
        return r"\x01\x{0:02x}(?P<{2}>{1})\x02\x{0:02x}".format(col, s, pname)
    return r"\x01\x{0:02x}{1}\x02\x{0:02x}".format(col, s)

def join2(l):
    return ''.join(_.flatten(l))

# this may still have some issues
def fix_split_segment_jump(ea):
    s = ida_lines.generate_disasm_line(ea, 1)

    '\x01\x05jg\x02\x05      \x01)\x01\x1a\x01(0000000143019000loc_143019000\x02\x1a\x01\t-\x02\t\x01\x0c231CCA5h\x02\x0c\x02)' 

    """
    \x01\x05jg\x02\x05      
    \s+
    \x01)
        \x01\x1a
            \x01(
            0000000143019000loc_143019000
        \x02\x1a
        \x01\t-\x02\t
        \x01\x0c231CCA5h\x02\x0c
    \x02)
    """
    sl11 = [ colwrap(0x1a, r'\x01\((?P<base>.{16})\w+') ]
    sl12 = [ colwrap("\t", r'-|\+', 'minus') ]
    sl13 = [ colwrap(0x0c, r'(?P<offset>[0-9a-fA-F]+)h?') ]

    sl1a = [ sl11, sl12, sl13 ]

    sl1 = [ colwrap(5, r'\w+', 'mnem') ]
    sl2 = [ r'\s+' ]
    sl3 = [ colwrap(')', join2(sl1a)) ]

    sl = join2( [sl1, sl2, sl3] )

    print(sl)

    m = re.search(sl, s)
    if m:
        correctTarget = GetTarget(ea)
        # Not sure it can be code, otherwise it would have a proper label.. but
        # it might be part of a higher CodeHead
        g = m.groupdict()
        a = "%s %s" % (g['mnem'], hex(correctTarget))
        print("correctAsm", a)
        inslen = GetInsnLen(ea)
        end = ea + inslen
        start = ea
        while IsFlow(start) and isNop(idc.prev_head(start)):
            start = idc.prev_head(start)
        offset = ea - start
        nassemble(start, a, apply=1)
        PatchNops(start + inslen, offset)

def fix_location_plus_2(ea):
    # mov edx, dword ptr cs:loc_140A68C50+2
    # add rdx, cs:qword_140D6A430+0A0h
    # ida_disasm = idc.GetDisasm(ea)
    # see also fix_loc_offset(badLabel)
    #  m = re.search(r'(\w*word ptr)? cs:([a-z]+_[A-F0-9]+\+[A-F0-9]+)h?', ida_disasm)
    s = ida_lines.generate_disasm_line(ea, 1)
    #                   loc_14469617D\x02\x1a\x01\t+\x02\t\x01\x0c1\x02\x0c\x02*
    m = re.search(r'.*(\x01\(.{16}\w+\x02.\x01\x09\+\x02\x09\x01\x0c[0-9a-fA-F]+h?)\x02', s)
    if m:
        correctTarget = idaapi.str2ea(ida_lines.tag_remove(m.group(1)))
        opNum = 1 if m.group(1).find("\x01\x09,x02\x09") else 0
        # Not sure it can be code, otherwise it would have a proper label.. but
        # it might be part of a higher CodeHead
        print("correctTarget", hex(correctTarget))
        code = idc.is_code(ida_bytes.get_flags(idc.get_item_head(correctTarget)))

        #  if code:
            #  #  print("ccccode")
            #  #  fix_loc_offset('loc_14064E290+2')
            #  MyMakeUnkn(correctTarget, 0)
            #  if code:
                #  MakeCodeAndWait(correctTarget + offset, force = 1)
            #  else:
                #  print("0x%x: not code: " % (correctTarget + offset))

        dtype, dtyp_size = get_dtype(ea, opNum)
        _make_x = get_create_data_func(dtyp_size)
        MyMakeUnknown(idc.get_item_head(correctTarget), 1, DOUNK_NOTRUNC)
        MyMakeUnknown(correctTarget, dtyp_size, ida_bytes.DOUNK_EXPAND | ida_bytes.DOUNK_NOTRUNC)
        MyMakeUnkn(correctTarget, DOUNK_NOTRUNC)
        if code:
            idc.create_insn(correctTarget)
        idc.auto_wait()
        if code:
            idc.create_insn(correctTarget) or forceAsCode(correctTarget)
        result = _make_x(correctTarget)
        if not result:
            print("couldn't turn {:x} into nice little data type (size: {})".format(correctTarget, dtyp_size))
        else:
            idc.auto_wait()
            print("turned {} into {}".format(ida_lines.tag_remove(m.group(1)), get_name_by_any(correctTarget) or "..."))
            #  if code: MakeCodeAndWait(loc + offset, force = 1)

def get_pdata_fnStart(ea):
    found = 0
    for ref in idautils.XrefsTo(ea):
        ea = ref.frm
        if idc.get_segm_name(ea) == '.pdata':
            unwind_info = ([x + 0x140000000 for x in struct.unpack('lll', get_bytes(ea, 12))])
            if ea == unwind_info[0]:
                return ea

    return idc.BADADDR


def fix_dualowned_chunk(ea):
    tail = GetChunk(ea)
    if not tail:
        return
    if tail.refqty < 2:
        return 
    if not tail.flags & ida_funcs.FUNC_TAIL:
        return 
    cstart = tail.start_ea
    # print("[info] fixing tail chunk @ {:x}".format(ea))
    labellen = 0
    idc.jumpto(tail.start_ea)
    fnNames = []
    fnLocs = []
    cName = idc.get_name(tail.start_ea, GN_VISIBLE).lower()
    while tail and tail.flags & ida_funcs.FUNC_TAIL: 
        fnName = idc.get_name(tail.owner, GN_VISIBLE).lower()
        fnLocs.append(tail.owner)
        fnNames.append(fnName)
        print("removing owner: {} from {:x} ({})".format(fnName, tail.start_ea, idc.get_name(tail.start_ea, GN_VISIBLE)))
        func = ida_funcs.get_func(tail.owner)
        if not ida_funcs.remove_func_tail(func, tail.start_ea):
            print("[warn] couldn't remove tail chunk {:x} from {:x}".format(tail.start_ea, tail.owner))
            globals()['warn'] += 1
            return
        else:
            print("[info] removed tail chunk {:x} from {:x}".format(tail.start_ea, tail.owner))

        idc.auto_wait()
        tail = GetChunk(ea)


    fnName = None
    if HasUserName(ea):
        if cName.endswith('impl'):
            fnName = cName
        #  else:
            #  similar = 0
            #  for fn in fnNames:
                #  if fn[0:10] == cName[0:10]:
                    #  similar = 1
            #  if similar:
                #  fnName = cName
            #  else:
                #  print("Ignoring dissimilar location name: {}".format(cName))    
                #  Commenter(ea, 'line').add("{}".format(cName))


    if fnName is None:
        fnName = ''
        for i in range(min([len(x) for x in fnNames])):
            u = _.uniq([ord(x[i]) for x in fnNames])
            if len(u) == 1:
                fnName += chr(u[0])
            else:
                break
        fnName += '_common'

    LabelAddressPlus(ea, fnName)

    del tail
    ForceFunction(ea)

    return True
    for ea in fnLocs:
        #  idc.jumpto(ea)
        if GetChunkStart(ea) == ea != BADADDR:
            retrace(ea)

    if not IsFunc_(cstart):
        #  idc.jumpto(cstart)
        retrace(cstart)
        # idc.add_func(cstart):
        # j:print("[warn] couldn't make func @ {:x} (please make manually)".format(ea))
        return

    return True
    
def fix_dualowned_chunks():
    fix_queue = []
    print("fixing double-owned chunks")
    for r in range(idaapi.get_fchunk_qty()):
        tail = idaapi.getn_fchunk(r)
        if tail.refqty > 1 and tail.flags & FUNC_TAIL:
            fix_queue.append(tail.start_ea)

    for ea in fix_queue:
        fix_dualowned_chunk(ea)


def name_priority(fn, *args):
    if fn == '': return 9;
    if re.match(r'[A-Z]+::[_A-Z][A-Z]', fn): return 1;
    if re.match(r'[A-Z]+::_0', fn): return 2;
    if re.match(r'[a-z]+(::|__)[_a-z][a-z]', fn): return 3;
    if re.match(r'[a-z]+(::|__)_0', fn): return 4;
    if re.match(r'Arxan', fn, re.I): return 8;
    return 7

if 'calledimpls' not in globals():
    calledimpls = []
def get_best_parent(ea):
    global calledimpls
    refs = [x for x in genAsList(idautils.CodeRefsTo(ea, 0)) if idc.get_func_name(x) and idc.print_insn_mnem(x).startswith('j') and MyGetInstructionLength(x) > 2]
    callrefs = [x for x in genAsList(idautils.CodeRefsTo(ea, 0)) if idc.get_func_name(x) and idc.print_insn_mnem(x).startswith('call') and MyGetInstructionLength(x) > 2]
    if callrefs:
        if ea not in calledimpls:
            calledimpls.append(ea)
            for crf in callrefs:
                print("[info] certified callref for {:x} from {} at {:x}".format(ea, idc.get_func_name(crf), crf))
        return ea

    refmap = dict()
    for ref in refs:
        if not ida_funcs.is_same_func(ea, ref):
            refmap[idc.get_func_name(ref)] = ref
    keys = genAsList(refmap.keys())
    pri = _.groupBy(keys, name_priority)
    pri2 = _(keys).chain().without(9).value()
    pri2.sort()
    print("pri2: {}".format(pf(pri2)))
    if len(pri2) > 1:
        return ea
    return _.first(pri2)

def find_database_errors():
    for f in Functions():
        for c in Chunks(f):
            pass

def ChunkHeads(ea=None):
    ea = eax(ea)
    for cs, ce in idautils.Chunks(ea):
        for h in idautils.Heads(cs, ce):
            yield h

def print_ip(ea=None):
    """
    print_ip

    @param ea: linear address
    """
    ea = eax(ea)
    d, c, b, a, p = struct.unpack('<BBBBH',idc.get_bytes(ea, 6))
    return "{}.{}.{}.{}:{}".format(a, b, c, d, p)

def make_ip(ea=None):
    """
    make_ip

    @param ea: linear address
    """
    ea = eax(ea)
    MakeUnknown(ea, 6, idc.DOUNK_EXPAND | ida_bytes.DELIT_NOTRUNC | ida_bytes.DELIT_NOTRUNC)
    idc.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR)
    idc.create_data(ea+4, FF_WORD, 2, ida_idaapi.BADADDR)
    if not HasUserName(ea):
        LabelAddressPlus(ea, 'dotted_quad')
    if not HasUserName(ea + 4):
        LabelAddressPlus(ea + 4, 'port')
    Commenter(ea, 'line').add(print_ip(ea)).commit()



def find_ips(start_ea=None, end_ea=None, step=8):
    """
    find_ips

    @param ea: linear address
    """
    start_ea = eax(start_ea)
    end_ea = end_ea or start_ea + 1024 * 64
    pins = dict()
    for ea in range(start_ea, end_ea, step):
        ip = print_ip(ea)
        if ip.endswith((':61456', ':6672', ':53858')) or ip.startswith(('192.168', '10.0.', '1.159.')):
            make_ip(ea)
            r = xrefs_to(ea)
            print(hex(ea), ip, hex(r))
            pins[ea] = 'x'
        else:
            pins[ea] = '.'

    #  return pins
    #

def EaseCode(ea=None, end=None, forceStart=False, forceStartIfHead=False, noExcept=False, noFlow=False, unpatch=False, ignoreMnem=[], create=None, fixChunks=False, origin=None):
    """
    EaseCode

    @param ea: linear address
    """
    ea = eax(ea)
    if not (ida_ida.cvar.inf.min_ea <= ea < ida_ida.cvar.inf.max_ea):
        raise AdvanceFailure("Invalid Address 0x{:x}".format(ea))
    if debug: 
        print("[EaseCode] {:x}".format(ea))
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        print((" -> ".join(stk)))
    #  d = ["{:x} {}".format(x, idc.generate_disasm_line(x, 0)) for x in range(ea, end or (ea+0x1000)) if not IsTail(x)]
    #  if debug:
        #  print("[EaseCode] pre-disasm\n{}".format("\n".join(d)))
    if not IsCode_(ea):
        if forceStartIfHead and IsHead(ea):
            r = forceCode(ea, GetInsnLen(ea), origin=origin)
            if debug: print("forceStartIfHead: {:x} {}".format(ea, diida(ea)))
        elif forceStart:
            r = forceCode(ea, GetInsnLen(ea), origin=origin)
            if debug: print("forceStart: {:x} {}".format(ea, diida(ea)))
        elif not idc.create_insn(ea):
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))
            else:
                raise AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))

    ida_auto.revert_ida_decisions(ea, GetInsnLen(ea))
    ida_auto.auto_recreate_insn(ea)
    start_ea = ea
    last_ea = ea
    at_end = False
    at_flow_end = False
    unhandled = code = tail = unknown = flow = False
    owners = GetChunkOwners(ea, includeOwner=1)
    _start = True
    _fixChunk = False
    while ea != idc.BADADDR and (end is None or ea < end):
        if _start:
            _start = False
        else:
            last_ea = ea
            ea = ea + insn_len
            if last_ea == start_ea and at_flow_end:
                if debug:
                    print("[EaseCode] ignoring at_flow_end during second loop")
                at_flow_end = False
            if at_end or at_flow_end:
                break

        if unpatch:
            UnPatch(ea, ea + 15)

        idc.GetDisasm(ea)
        idc.auto_wait()
        insn_len = GetInsnLen(ea)
        if not insn_len:
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
            raise AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
        _owners = GetChunkOwners(ea, includeOwner=1)
        if _owners:
            if _owners != owners:
                if debug: print("[EaseCode] _owners != owners; break")
                break
        else:
            owners = _owners

        unhandled = code = tail = unknown = flow = False
        next_head = idc.next_head(ea)
        mnem = ''

        if IsCode_(ea):
            # if debug: print("0x{:x} IsCode".format(ea))
            code = True
            mnem = idc.print_insn_mnem(ea)
            if mnem.startswith(('ret', 'jmp', 'int', 'ud2')):
                at_end = True
            if create: # or mnem.startswith(('ret', 'jmp', 'int', 'ud2', 'leave')):
                # raise RuntimeError("don't")
                ida_auto.revert_ida_decisions(ea, GetInsnLen(ea))
                ida_auto.auto_recreate_insn(ea)
                idc.auto_wait()

        else:
            if IsTail(ea):
                # if debug: print("0x{:x} IsTail".format(ea))
                tail = True
            if IsUnknown(ea) or IsData(ea):
                # if debug: print("0x{:x} IsUnknown".format(ea))
                unknown = True
        if not (code or tail or unknown):
            if debug: print("0x{:x} unhandled flags".format(ea))
            if debug: debug_fflags(ea)
        if IsFlow(ea):
            if debug: print("0x{:x} IsFlow ({}) +{}".format(ea, mnem, insn_len))
            flow = True
        elif ea != start_ea:
            prev_ea = last_ea
            prev_mnem = idc.print_insn_mnem(prev_ea)
            if prev_mnem not in ('ret', 'retn', 'retnw', 'jmp', 'int', 'ud2', 'leave', 'iret', 'retf'):
                if prev_mnem != 'call' or ida_funcs.func_does_return(GetTarget(prev_ea)):
                    print("{:x} Flow ended {:x} with '{}' (fixing)".format(ea, prev_ea, prev_mnem))
                    if fixChunks:
                        _fixChunk = True
                    ida_auto.auto_recreate_insn(prev_ea)
                    ida_auto.auto_wait()
                    #  ea1 = prev_ea
                    #  ea2 = idc.next_head(ea)

                    # ida_auto.auto_apply_tail(ea1, ea2)
                    #  print("ida_auto results: {}".format([
                        #  ida_auto.revert_ida_decisions(ea1, ea2), #
                        #  [ida_auto.auto_recreate_insn(x) for x in Heads(ea1, ea2)],
                        #  [ida_auto.plan_ea(x) for x in Heads(ea1, ea2)], #
                        #  ida_auto.auto_wait_range(ea1, ea2),
                        #  ida_auto.plan_and_wait(ea1, ea2),
                        #  ida_auto.plan_and_wait(ea1, ea2, True),
                        #  ida_auto.plan_range(ea1, ea2),  #
                        #  ida_auto.auto_wait()
                    #  ]))

                    #  idaapi.del_items(prev_ea, ida_bytes.DELIT_NOTRUC, ea - prev_ea)
                    #  if not idc.create_insn(prev_ea):
                        #  print("[EaseCode] couldn't recreate insn at {:x}".format(prev_ea))
                    #  ida_auto.auto_recreate_insn(idc.prev_head(prev_ea))
                    #  idc.auto_wait()
                    GetDisasm(prev_ea)
                    flow = True

        # TODO: amalgamate these two, they're basically the same
        if code and isFlowEnd(ea):
                if debug: print("0x{:x} code and isFlowEnd; at_end".format(ea))
                ida_auto.auto_recreate_insn(ea)
                at_flow_end = True
        elif not flow: #  or isFlowEnd(ea):
            if not noFlow and mnem not in ignoreMnem:
                if debug: print("0x{:x} no flow; at_end".format(ea))
                at_flow_end = True

        if tail:
            if debug: print("0x{:x} tail; break".format(ea))
            break

        if unknown:
            # dprint("[debug] next_head, ea, insn_len")
            if debug: print("[debug] next_head:{:x}, ea:{:x}, insn_len:{:x}".format(next_head, ea, insn_len))
            
            if next_head == ea + insn_len:
                pass
                #  print("0x{:x} next_head == ea + insn_len".format(ea))
            elif next_head > ea + insn_len:
                pass
                #  print("0x{:x} next_head > ea + insn_len".format(ea))
            else:
                #  print("0x{:x} next_head < ea + insn_len; forcing space to instruction".format(ea))

                idaapi.del_items(ea, ida_bytes.DELIT_NOTRUNC, insn_len)

            if not idc.create_insn(ea):
                if debug: print("0x{:x} couldn't idc.make_insn(0x{:x}); break".format(ea, ea))
                break

    if unpatch:
        UnPatch(start_ea, ea)

    #  ida_auto.plan_and_wait(start_ea, ea)

    #  ida_auto.plan_range(start_ea, ea)
    #  idc.auto_wait()
    if _fixChunk and GetChunkEnd(start_ea) < ea:
        SetFuncOrChunkEnd(start_ea, ea)
    return ea

def some_rubbish():
    bad_func = []
    for a in m:
        for cs, ce in idautils.Chunks(SkipJumps(a)):
            EaseCode(cs, fixChunks=1, forceStart=1)
    for a in m + l:
        for cs, ce in idautils.Chunks(SkipJumps(a)):
            nce = EaseCode(cs, fixChunks=1, forceStart=1)
            if nce != GetChunkEnd(cs):
                SetFuncOrChunkEnd(cs, nce)

def GetCodeHash(ea1, ea2):
    return hash(getCode(ea1, ea2))

def GetFuncHash(funcea=None):
    """
    GetFuncHash

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    codeChunks = tuple([getCode(ea1, ea2) for ea1, ea2 in idautils.Chunks(funcea)])
    return hash(codeChunks)
    #  flags = tuple([idc.get_full_flags(ea) for ea in _.flatten([genAsList(range(ea1, ea2)) for ea1, ea2 in idautils.Chunks(funcea)])])
    #  spd = tuple([idc.get_sp_delta(ea) for ea in _.flatten([genAsList(range(ea1, ea2)) for ea1, ea2 in idautils.Chunks(funcea)])])
    #  return hash((codeChunks, flags, spd))

def FixAllFixups():
    pe = idautils.peutils_t()
    ea = pe.imagebase + 1
    ea = idaapi.get_next_fixup_ea(ea - 1)
    count = 0
    while ea < idc.BADADDR:
        count += 1
        idaapi.del_fixup(ea)
        ea = idaapi.get_next_fixup_ea(ea)
    return count

def FindObfu():
    import time
    patterns = ["55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3", 
                "48 89 e0 48 05 f8 ff ff ff 48 89 c4 48 89 1c 24", 
                "55 48 bd ?? ?? ?? ?? ?? ?? 00 00 48 87 2c 24 ?? ?? 48 8b ?? 24 10 48 ?? ?? ?? ?? ?? ?? ?? 00 00 48 0f ?? ?? 48 89 ?? 24 10 ?? ?? c3", 
                "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24", 
                "48 89 6c 24 f8 48 8d 64 24 f8", 
                "48 8d 64 24 f8 48 89 2c 24", 
                "48 89 5c 24 f8 48 8d 64 24 f8", 
                "48 8d 64 24 f8 48 89 1c 24", 
                "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3",
                "48 8d 64 24 08 ff 64 24 f8", 
                ]

    with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
        for pattern in patterns:
            for ea in FindInSegments(pattern, '.text'):
                if not IsCode_(ea):
                    EaseCode(ea, forceStart=1)
                t0 = time.time()
                try:
                    while obfu._patch(ea, len(pattern) + 32)[0]:
                        t1 = time.time()
                        print("took: {}".format(t1 - t0))
                except RelocationAssemblerError:
                    pass


"""
idc.save_database('')
refresh_start()
FindObfu()
idc.save_database('')

ida_idaapi.IDAPython_ExecScript('e:/git/ida/start.py', globals())
idc.save_database('')
refresh_start()
find_shifty_stuff()
idc.save_database('')
retrace_all()

"""
def GetFunc(ea=None):
    ea = eax(ea)
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = ida_funcs.get_func(ea)
    return func


def GetFuncStart(ea=None):
    ea = eax(ea)
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    if isinstance(ea, list):
        return [GetFuncStart(x) for x in ea]

    func = ida_funcs.get_func(ea)
    if not func:
        return BADADDR
    return func.start_ea

def GetFuncEnd(ea=None):
    ea = eax(ea)
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    # return idc.find_func_end(ea)
    func = ida_funcs.get_func(ea)
    if not func:
        return BADADDR
    return func.end_ea

def hex_byte_as_pattern_int(string):
    return -1 if '?' in string else int(string, 16)

def MakeCodeAndWait(ea, force = False, comment = ""):
    """
    MakeCodeAndWait(ea)
        Create an instruction at the specified address, and idc.Wait() afterwards.
        
        @param ea: linear address
        
        @return: 0 - can not create an instruction (no such opcode, the instruction
        would overlap with existing items, etc) otherwise returns length of the
        instruction in bytes
    """
    ida_auto.auto_make_code(ea)
    idc.auto_wait()
    r = idc.create_insn(ea)
    if not force or r:
        return r
    if not r:
        if debug: print("0x%x: %s %s" % (ea, comment, GetDisasm(ea)))
        count = 0
        insLen = 0
        # This should work, as long as we are not started mid-stream
        while not insLen and count < 16: #  and idc.next_head(ea) != NextNotTail(ea):
            count += 1
            MyMakeUnknown(ea, EndOfContig(ea) - ea, 0)
            idc.Wait()
            insLen = MakeCodeAndWait(ea)
            #  print("0x%x: MakeCodeAndWait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
        if count > 0:
            if debug: print("0x%x: MakeCodeAndWait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
    # ida_auto.plan_ea(ea)
    return 1
    return

    if IsCode_(ea):
        if debug: print("0x%x: Already Code" % ea)
        return GetInsnLen(ea)

    if Byte(ea) == 0xcc:
        # print("0x%x: %s can't make 0xCC into code" % (ea, comment))
        return 0

    while IsData(ea):
        if debug: print("0x%x: MakeCodeAndWait - FF_DATA - MyMakeUnknown" % ea)
        MyMakeUnknown(ItemHead(ea), NextNotTail(ea) - ItemHead(ea), 0)
        idc.Wait()

    if isTail(idc.get_full_flags(ea)):
        if debug: print("0x%x: Tail" % ea)
        MyMakeUnknown(ItemHead(ea), ea - ItemHead(ea), 0)

    if not MakeCode(ea):
        if debug: print("0x%x: MakeCodeMakeUnknown" % ea)
        MyMakeUnknown(ea, 1, 0)
    insLen = MakeCode(ea)
    if insLen == 0:
        if force:
            if debug: print("0x%x: %s %s" % (ea, comment, GetDisasm(ea)))
            count = 0
            # This should work, as long as we are not started mid-stream
            while not insLen and count < 16: #  and idc.next_head(ea) != NextNotTail(ea):
                count += 1
                MyMakeUnknown(ItemHead(ea), count, 0)
                idc.Wait()
                insLen = MakeCodeAndWait(ea)
                #  print("0x%x: MakeCodeAndWait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
            if count > 0:
                if debug: print("0x%x: MakeCodeAndWait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
    #  print("0x%x: MakeCodeAndWait returning %i" % (ea, count))
    idc.Wait()
    return insLen


def partial(func, *args):
    def part(*args_rest):
        return func(*(args + args_rest)) 
    return part

def return_value(func, value, *args, **kwargs):
    func(*args, **kwargs)
    return value

def return_value_lambda(func, value, *args, **kwargs):
    return lambda *a: return_value(func, value, *args, **kwargs)

def return_value_lambda_args(func, value, *args, **kwargs):
    return lambda *a: return_value(func, value, *(args + a), **kwargs)

def setTimeout(func, timeout, *args, **kwargs):
    def part():
        func(*args, **kwargs)
        return -1 

    # timer = ida_kernwin.register_timer(part, timeout)
    # timer = ida_kernwin.register_timer(lambda: return_zero(lambda: func(*args, **kwargs)), timeout)
    timer = ida_kernwin.register_timer(timeout, return_value_lambda(func, -1, *args, **kwargs))

if 'CircularList' in globals():
    @static_vars(last=CircularList(16))
    def forceCode(start, end=None, trim=False, delay=None, origin=None):
        log = []
        ea = eax(start)
        ValidateEA(ea, origin=origin)
        log.append("start: {:x}".format(ea))
        if ea == idc.BADADDR or not ea:
            return (0, 0, 0, 0)
        end = end or GetInsnLen(start) or 15
        if end < idaapi.cvar.inf.minEA and end < start:
            end = start + end
        log.append("end: {:x}".format(end))

        if ea == forceCode.last:
            if _.all(forceCode.last, lambda x, *a: x == ea):
                raise RuntimeError("Repeated calls for forceCode for same address")
        forceCode.last.append(ea)

        if debug:
            # dprint("[forceCode] start, end, trim, delay")
            print("[forceCode] start:{:x}, end:{:x}, trim:{}, delay:{}".format(start, end, trim, delay))
            
        last_jmp_or_ret = 0
        last_addr = 0
        trimmed_end = 0
        happy = 0
        # dprint("[forceCode] start")
        #  print("[forceCode] start:{:x}".format(start))
        
        func_end = GetFuncEnd(start)
        # dprint("[forceCode] func_end")
        #  print("[forceCode] func_end:{:x}".format(func_end))
        
        func_start = GetFuncStart(start)
        chunk_end = GetChunkEnd(start)
        chunk_start = GetChunkStart(start)
        if debug:
            print("func_start, func_end", hex(func_start), hex(func_end))
            print("chunk_start, chunk_end", hex(func_start), hex(func_end))
        
        #  idc.del_items(start, idc.DELIT_EXPAND, end - start)
        if GetInsnLen(ea) == 2 and GetMnemDi(ea) == 'push' and MyGetMnem(ea) == '':
            log.append("{:x} insnlen == 2".format(ea))
            old_type = idc.get_type(ea + 1) if not idc.get_type(ea) else None
            old_name = idc.get_name(ea + 1) if HasUserName(ea + 1) and not HasUserName(ea) else None
            idc.del_items(ea, DELIT_DELNAMES, 2)
            size = idc.create_insn(ea)
            if size == 2:
                if old_name:
                    LabelAddressPlus(ea, old_name)
                if old_type:
                    SetType(ea, old_type)
                ea += 2
        while ea < end:
            log.append("{:x} {} | {}".format(ea, GetDisasm(ea), diida(ea)))
            happy = 0
            last_addr = ea
            if idc.is_tail(idc.get_full_flags(ea)):
                head = idc.get_item_head(ea)
                if head == ea:
                    print("[warn] item_head == ea {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                #  if not idc.del_items(ea, 0, 1):
                if not idc.MakeUnknown(ea, 1, 0):
                    print("[warn] couldn't del item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                else:
                    if debug: print("[debug] deleted item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))

            if idc.is_code(idc.get_full_flags(ea)):
                # seems to be that deleting the code and remaking it is the only way to ensure everything works ok
                # .. and it seems that deleting and remaking triggered stupid stupid things like the generation of nullsubs out of `retn` statements
                # .. but i think we will cheat and match the instruction against GetFuncEnd, since undefining the end of a chunk is what shrinks it.
                if False:
                    if debug: print("[info] code deleting already existing instruction at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, ea, start, end))
                    if not idc.del_items(ea, 0, idc.get_item_size(ea)):
                        print("[warn] couldn't del item({:x}, 0, get_item_size) | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                    else:
                        if debug: print("[debug] deleted item({:x}, 0, get_item_size) | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                else:
                    insn_len = idc.get_item_size(ea)
                    if debug: print("[info] {:x} code exists for {} bytes | {}".format(ea, insn_len, idc.generate_disasm_line(ea, 0)))
                    ea += insn_len
                    happy = 1
            if not happy:
                insn_len = idc.create_insn(ea)
                if debug: print("[info] (1) idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))
                if not insn_len:
                    # this
                    if debug: print("MyMakeUnknown(0x{:x}, {}, DELIT_DELNAMES | DELIT_NOTRUNC)".format(ea, GetInsnLen(ea)))
                    MyMakeUnknown(ea, GetInsnLen(ea), DELIT_DELNAMES | DELIT_NOTRUNC)
                    # or this (same result)
                    for r in range(ea + 1, GetInsnLen(ea)):
                        if HasAnyName(r):
                            LabelAddressPlus(r, '')
                            if debug: print("[info] removing label at {:x}".format(r))
                    insn_len = idc.create_insn(ea)
                    if debug: print("[info] (2) idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))
                    if insn_len == 0:
                        if origin and UnpatchUntilChunk(origin):
                            raise AdvanceReverse(origin)


                # restore function end if we just removed the last insn in a chunk
                if insn_len and insn_len + ea == chunk_end:
                    if debug: print("[info] restoring chunk_end to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(chunk_end, chunk_start, start, end))
                    SetFuncEnd(chunk_start, chunk_end)
                if not insn_len:
                    # record existing code heads
                    existing_code = [x for x in range(ea, ea+15) if IsCode_(x)]
                    idc.del_items(ea, 0, 15)
                    insn_len = idc.create_insn(ea)
                    if not insn_len and existing_code:
                        [idc.create_insn(x) for x in existing_code]
                if not insn_len:
                    trimmed_end = last_jmp_or_ret + idc.get_item_size(last_jmp_or_ret) if last_jmp_or_ret else last_addr or ea
                    if IsExtern(ea) or idc.get_segm_name(ea) == '.idata':
                        happy = 0
                        break
                    if not trim:
                        msg = "[warn] couldn't create instruction at {:x}".format(ea)
                        print("{}\n{}".format(msg, '\n'.join(log)))
                        raise AdvanceFailure(msg)
                    else:
                        print("[warn] couldn't create instruction at {:x}, shortening chunk to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, trimmed_end, ea, start, end))
                        if idc.get_func_name(start):
                            if not idc.set_func_end(start, trimmed_end):
                                print("[warn] couldn't set func end at {:x} or {:x} or {:x} or {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(end, last_jmp_or_ret, last_addr, ea, start, start, end))
                        idc.del_items(end, 0, end - trimmed_end)
                else:
                    happy = 1
                    ea += insn_len

            if not happy:
                return (ea-start, start, end, trimmed_end)

            mnem = idc.print_insn_mnem(last_addr).split(' ', 2)[0]
            if mnem in ('jmp', 'ret', 'retn', 'int'):
                last_jmp_or_ret = last_addr

        if func_start == start:
            idc.add_func(func_start)
        return (ea-start, start, end, trimmed_end)

def ReinforceFunc(ea, *args, **kwargs):
    good = []
    bad = []
    for chunk in idautils.Chunks(ea):
        r = forceCode(*(chunk + args), **kwargs)
        if r[0]:
            good.append( r[1], r[2] )
        else:
            bad.append( r[1], r[2] )

    return good, bad
    

def forceAllAsCode(ea, length, hard = 0, comment = ""):
    return forceCode(ea, length)[0]
    # hard is unused
    head = ItemHead(ea)
    if head == BADADDR:
        head = ea
    if MyMakeUnknown(head, length + (ea - head), DOUNK_EXPAND | DOUNK_NOTRUNC) == False:
        print("0x%x: Couldn't make unknown at 0x%x" % (ea, head))
        return 0
    idc.Wait()
    pos = ea
    end = ea + length
    while pos < end:
        #  codeLen = MakeCodeAndWait(pos, comment=comment)
        codeLen = forceCode(ea, length)[0]
        if codeLen:
            if not IsFunc_(pos):
                print("Couldn't convert block into code even though it said we did 0x%x" % pos)
                break
            pos += codeLen
        else:
            print("0x%x: Couldn't convert block into code at 0x%x (remaining length: %i)" % (ea, head, end - pos))
            raise "trace that broken code back"
            if pos < idaapi.cvar.inf.minEA or pos > idaapi.cvar.inf.maxEA:
                raise "trace that broken code back"
            break
    return pos - ea

def forceAsCode(ea, length = 1, hard = 0, comment = ""):
    return forceCode(ea, length)[0]
    # if hard or not isCode(idc.get_full_flags(ea)):
    if IsData(ea) or IsTail(ea):
        MyMakeUnknown(ea, 1, 0)
    head = ItemHead(ea)
    if head == BADADDR:
        head = ea
    if not isUnknown(idc.get_full_flags(head)):
        if MyMakeUnknown(head, length + (ea - head), DOUNK_EXPAND | DOUNK_NOTRUNC) == False:
            print("0x%x: forceAsCode: Couldn't make unknown at 0x%x" % (ea, head))
            return None
        idc.Wait()
    codeLen = MakeCodeAndWait(ea, comment=comment, force=1)

    if codeLen:
        if not isCode(idc.get_full_flags(ea)):
            print("Couldn't convert block into code even though it said we did 0x%x" % ea)
            return 0
        return codeLen
    else:
        print("0x%x: Couldn't convert block into code at (head: 0x%x)" % (ea, head))
        if ea < idaapi.cvar.inf.minEA or ea > idaapi.cvar.inf.maxEA:
            raise "trace that broken code back"
        return 0
    # return length

def MakeUniqueLabel(name, ea = BADADDR):
    fnLoc = LocByName(name)
    if fnLoc == BADADDR or fnLoc == ea:
        return name
    fmt = "%s_%%i" % name
    for i in range(99999):
        tmpName = fmt % i
        fnLoc = LocByName(tmpName)
        if fnLoc == BADADDR or fnLoc == ea:
            return tmpName
    return ""

def LabelAddressPlus(ea=None):
    """
    LabelAddressPlus

    @param ea: linear address
    """


def LabelAddressPlus(ea, name, force=False, append_once=False, unnamed=False, nousername=False, named=False, throw=False):
    """
    Label an address with name (forced) or an alternative_01
    :param ea: address
    :param name: desired name
    :param force: force name (displace existing name)
    :param append_once: append `name` if not already ending with `name`
    :param named: [str, callable(addr, name)] name for things with existing usernames
    :return: success as bool
    """
    def ThrowOnFailure(result):
        return result
        if not result and throw:
            raise RuntimeError("Couldn't label address {:x} with \"{}\"".format(ea, name))
        return result

    if isinstance(ea, list):
        return [LabelAddressPlus(x, name, force, append_once, unnamed, nousername, named, throw) for x in ea]

    ea = eax(ea)
    

    if nousername:
        unnamed = nousername
    if ea < BADADDR:
        if HasUserName(ea):
            if named:
                if callable(named):
                    _name = idc.get_name(ea)
                    _tags = TagGetTagSubstring(_name)
                    _name = TagRemoveSubstring(_name)
                    _name = named(ea, _name, name)
                    name = TagAddSubstring(_name, _tags)
                else:
                    name = named
            elif unnamed:
                return
        fnName = idc.get_name(ea)
        if append_once:
            if not fnName.endswith(name):
                name += fnName
            else:
                return ThrowOnFailure(False)
        fnLoc = idc.get_name_ea_simple(name)
        if fnLoc == BADADDR:
            return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))
        elif fnLoc == ea:
            return ThrowOnFailure(True)
        else:
            if force:
                MakeNameEx(fnLoc, "", idc.SN_AUTO | idc.SN_NOWARN)
                idc.Wait()
                return ThrowOnFailure(MakeNameEx(ea, name, idc.SN_NOWARN))
            else:
                name = MakeUniqueLabel(name, ea)
                return ThrowOnFailure(MakeNameEx(ea, name, idc.SN_NOWARN))

    else:
        print("0x0%0x: Couldn't label %s, BADADDR" % (ea, name))
        return False

def LabelAddress(ea, name):
    if ea < BADADDR:
        #  MakeFunction(ea)
        #  idc.Wait()
        fnFlags = idc.get_full_flags(ea)
        if ida_bytes.has_dummy_name(fnFlags) or not ida_bytes.has_any_name(fnFlags) or Name(ea).find('_BACK_') > -1:
            name = MakeUniqueLabel(name, ea)
            fnLoc = LocByName(name)
            if fnLoc == BADADDR:
                print("0x0%0x: Labelling: %s" % (ea, name))
                MakeNameEx(ea, name, idc.SN_NOWARN)
            else:
                print("0x0%0x: Already labelled: %s" % (ea, name))

            if name.endswith('Address'): MakeQword(ea)
            if name.endswith('Float'): MakeFloat(ea)
            if name.endswith('Func'):
                MakeCodeAndWait(ea)
                MakeFunction(ea)
                MakeCodeAndWait(ea)
            if name.endswith('Int'): MakeDword(ea)
        else:
            print("0x0%0x: %s matched %s" % (ea, Name(ea), name))
            #  if Name(ea) != name:
                #  Commenter(ea).add("[matched] %s" % name)
    else:
        print("Couldn't label %s, BADADDR" % (name))


def get_name_by_any(address):
    """
    returns the name of an address (and if address is
    a string, looks up address of string first).

    an easy way to accept either address or name as input.
    """

    if address is None:
        return 'None'
    if not isInt(address):
        address = eax(address)
    #  if isinstance(address, str):
        #  address = idc.get_name(idc.get_name_ea_simple(address))
    r = idc.get_name(address)
    if not r:
        return hex(address)
    return r

def Chunk(any=None):
    return ida_funcs.get_func(get_ea_by_any(any))


#  def GetChunk(any=None):
    #  return ida_funcs.get_func(get_ea_by_any(any))

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

    if isinstance(val, (int, long)):
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

def IsValidEA(*args):
    """
    IsValidEA

    @param ea: linear address
    """
    if len(args) == 0:
        args = [eax(None)]
    args = _.flatten(args)
    if len(args) > 1:
        return _.all(args, lambda x, *a: IsValidEA(x))
    if isInt(args[0]):
        return ida_ida.cvar.inf.min_ea <= args[0] < ida_ida.cvar.inf.max_ea
    return False

def ValidateEA(ea=None, origin=None):
    if not IsValidEA(ea):
        raise AdvanceFailure("Invalid Address 0x{:x} (origin: {})".format(ea, hex(origin)))


def get_cfunc_by_any(val):
    if isinstance(val, idaapi.cfuncptr_t):
        return val
    #  if isinstance(val, idaapi.vdui_t):
        #  return val.cfunc
    return decompile_function_as_cfunc(get_ea_by_any(val))


def get_func_by_any(val):
    if isinstance(val, ida_funcs.func_t):
        return val
    #  if isinstance(val, idaapi.vdui_t):
        #  val = val.cfunc
    #  if isinstance(val, idaapi.cfuncptr_t):
        #  val = val.entry_ea
    return idaapi.get_func(get_ea_by_any(val))


def jump(any):
    idc.jumpto(get_ea_by_any(any))

def fix_links_to_reloc(old_fn, new_fn):
    l = AllRefsTo(get_ea_by_any(old_fn))['callRefs']
    for ea in l:
        qassemble(ea, 'call %s' % get_name_by_any(new_fn), apply=1)
    l = AllRefsTo(get_ea_by_any(old_fn))['jmpRefs']
    for ea in l:
        qassemble(ea, 'jmp %s' % get_name_by_any(new_fn), apply=1)


def GetDisasmForce(ea=None):
    """
    Get disassembly line with GENDSM_FORCE_CODE flag:
    (generate a disassembly line as if there is an instruction at 'ea')

    @param ea: linear address of instruction

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    if ea is None:
        ea = idc.get_screen_ea()
    return idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)


def escape_c(c):
    if c < ' ' or c > '\x7e':
        return '\\x%02x' % ord(c)
    else:
        return c


def GetDisasmColor(ea=None):
    return ''.join([escape_c(c) for c in ida_lines.generate_disasm_line(ea)])

def isgenerator(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'__len__')

def isflattenable(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'isalnum')

def genAsList(o):
    return [x for x in o]

def glen(o):
    return len(genAsList(o))

def A(o):
    if o is None:
        return []
    elif isinstance(o, list):
        return o
    elif isflattenable(o) and len(list(o)) > 1:
        return list(o)
    elif isflattenable(o):
        return genAsList(o)
    else:
        return [o]


def dict_append(d, k, v):
    if k not in d:
        d[k] = A(v)
    if not isinstance(d[k], list):
        d[k] = A(v)
    else:
        d[k].append(v)



def rename_functions(pattern, replacement):
    for ea in idautils.Functions():
        if len(re.findall(pattern, GetFunctionName(ea))):
            LabelAddressPlus(ea, re.sub(pattern, replacement, GetFunctionName(ea)))

def file_size(fn):
    return os.path.getsize(fn)

def file_exists(fn):
    return os.path.exists(fn) and os.path.isfile(fn)

def dir_exists(fn):
    return os.path.exists(fn) and os.path.isdir(fn)


def file_get_contents(fn):
    return open(fn, encoding='utf-8', newline=None).read()

def file_get_contents_bin(fn):
    return open(fn, 'rb').read()


def file_put_contents(fn, data):
    with open(fn, 'w') as f:
        f.write(data)
    return os.path.abspath(fn)

def file_put_contents_bin(fn, data):
    with open(fn, 'wb') as f:
        f.write(data)
    return os.path.abspath(fn)



def bt_prevhead_until_noflow(ea):
    while idc.is_flow(idc.get_full_flags(ea)):
        ea = idc.prev_head(ea)
    return ea


def bt_prevhead_until_xref(ea):
    while True:
        while idc.is_flow(idc.get_full_flags(ea)) and not idc.isRef(idc.get_full_flags(ea)):
            ea = idc.prev_head(ea)
        if idc.isRef(idc.get_full_flags(ea)):
            refs = AllRefsTo(ea)
            # {'jmpRefs': set([5394414068L]), 'flowRefs': set([]), 'callRefs': set([]),
            #  'allRefs': set([5394414068L]), 'segRefs': set([]),  'fnRefs': set([]),
            #  'jcRefs': set([]),             'dataRefs': set([]), 'segRefNames': set([])}
            xrefCount = len(refs["allRefs"] - refs["flowRefs"])
            if xrefCount:
                if xrefCount < 2:
                    ea = list(refs["nonFlowRefs"])[0]
                    print(("xref: 0x{:x} {} {}".format(ea, GetFunctionName(ea), GetDisasm(ea))))
                else:
                    print("multiple refs")
                    break
        elif idc.is_flow(idc.get_full_flags(ea)):
            ea = idc.prev_head(ea)
        else:
            break

    return ea


def MyGetOperandValue(ea, n):
    # print(("MyGetOperandValue", hex(ea), n))
    d = de(ea)
    if d and isinstance(d, list) and d[0].operands and n < len(d[0].operands):
        return d[0].operands[n].value or d[0].operands[n].disp
    return -1

def MyGetOperandDisplacement(ea, n):
    # print(("MyGetOperandDisplacement", hex(ea), n))
    d = de(ea)
    if d and isinstance(d, list) and d[0].operands and n < len(d[0].operands):
        return d[0].operands[n].disp
    return -1

def MyMakeUnknown(ea, nbytes, flags = 0x4): # ida_bytes.DELIT_NOTRUNC
    r"""
    @param ea:      any address within the first item to delete (C++: ea_t)
    @param nbytes:  number of bytes in the range to be undefined (C++: asize_t)
    @param flags:   combination of:     DELIT_EXPAND    DELIT_DELNAMES
                                        ida_bytes.DELIT_NOTRUNC   DELIT_NOUNAME
                                        DELIT_NOCMT     DELIT_KEEPFUNC
    @param may_destroy: optional callback invoked before deleting a head item.
                        if callback returns false then deletion and operation
                        fail. (C++: may_destroy_cb_t *)
    @return: true on sucessful operation, otherwise false

    Convert item (instruction/data) to unexplored bytes. The whole item
    (including the head and tail bytes) will be destroyed. 
    """
    # check if caller has invoked with (start_ea, end_ea)
    if nbytes > ea:
        nbytes = nbytes - ea
    result = idaapi.del_items(ea, flags, nbytes)
    if not result:
        return result
    
    # check for fixups that must be removed 
    # https://reverseengineering.stackexchange.com/questions/27339/

    fx = idaapi.get_next_fixup_ea(ea - 1)
    while fx < ea + nbytes:
        idaapi.del_fixup(fx)
        fx = idaapi.get_next_fixup_ea(fx)

    return result

def MyMakeUnkn(ea, flags = 0):
    return MyMakeUnknown(ea, 1, flags)

def example_fixup_visitor(ea):
    line = idc.generate_disasm_line(ea, 0)
    print("{:16x} {}".format(ea, line))

def visit_fixups(iteratee):
    ea = idaapi.get_first_fixup_ea()
    while ea != idc.BADADDR:
        iteratee(ea)
        ea = idaapi.get_next_fixup_ea(ea)


def SetFuncFlags(ea, callback):
    flags = idc.get_func_flags(ea)
    if flags == -1:
        return
    flags = callback(flags)
    return idc.set_func_flags(ea, flags)

def MakeThunk(ea=None):
    """
    MakeThunk

    @param ea: linear address
    """
    ea = eax(ea)
    
    print("{:x} MakeThunk".format(ea))
    idc.auto_wait()
    ZeroFunction(ea)
    if IsFunc_(ea):
        if not IsFuncHead(ea):
            if not ForceFunction(ea):
                print("{:x} failed to forcefunction".format(ea))
                return False
        if GetNumChunks(ea) > 1:
            RemoveAllChunks(ea)
        if GetFuncEnd(ea) > ea + GetInsnLen(ea):
            if not SetFuncEnd(ea, ea + GetInsnLen(ea)):
                print("{:x} failed to setfuncend".format(ea))
                return False
            return True

        SetFuncFlags(ea, lambda f: f | idc.FUNC_THUNK)
        return True

    else:
        ForceFunction(ea)
        SetFuncFlags(ea, lambda f: f | idc.FUNC_THUNK)
        if GetFuncEnd(ea) > ea + GetInsnLen(ea):
            if not SetFuncEnd(ea, ea + GetInsnLen(ea)):
                print("{:x} failed to setfuncend".format(ea))
                return False
        return True


def FixFarFunc(ea = None):
    if ea is None:
        ea = idc.get_screen_ea()
    if IsFunc_(ea):
        return SetFuncFlags(ea, lambda f: f & ~idc.FUNC_FAR)
    return False

def IsThunk(ea = None):
    if ea is None:
        ea = idc.get_screen_ea()
    if not IsFunc_(ea):
        return False
    flags = idc.get_func_flags(ea)
    return flags & idc.FUNC_THUNK

def MyMakeFunction(ea, a2=BADADDR, a3=None):
    skip = False
    end = BADADDR
    if isinstance(a2, bool) or isinstance(a2, (bool, integer_types)) and a2 < 2: skip = a2
    if isinstance(a3, bool) or isinstance(a3, (bool, integer_types)) and a3 < 2: skip = a3
    if isinstance(a2, integer_types) and a2 > 1: end = a2
    if isinstance(a3, integer_types) and a3 > 1: end = a3
    if end < ea:
        end += ea
    if debug: print("MyMakeFunction(0x{:x}, 0x{:x}, {})".format(ea, end, skip))

    if IsFunc_(ea):
        if IsFuncHead(ea):
            if debug: print('already a funchead')
            return True
        if IsHead(ea):
            if debug: print('already a head inside a function')
            return False
        if debug: print('inside a function, but not a head, returning False')
        return False


    if skip:
        if debug: print('skipping makefunction')
        return IsFunc_(ea)

    if debug: print('making function')
    if not idc.add_func(ea, end):
        if debug: print('simple add didn\'t work, running forceCode')
        forceCode(ea)
        if not idc.add_func(ea, end):
            if debug: print('forceCode and add_func didn\'t work')
            return 0

    return 1




def EnsureFunction(ea):
    if not IsFunc_(ea):
        if debug: print('EnsureFunction')
        idc.add_func(ea)
    return ea


def Find(pattern):
    print('Starting')
    segments = [(x, idc.get_segm_attr(x, SEGATTR_END)) for x in
                [x for x in idautils.Segments() if x < 0x146000000 and SegName(x) == ".text"]]
    for base, end in segments:
        ptr = base
        while ptr < end:
            ptr = ida_search.find_binary(ptr + 1, end, pattern, 16, SEARCH_CASE | SEARCH_DOWN)
            if ptr < end:
                yield ptr


def findAndTrace():
    segments = [(x, idc.get_segm_attr(x, SEGATTR_END)) for x in
                [x for x in idautils.Segments() if x < 0x146000000 and SegName(x) == ".text"]]
    # pattern = "48 89 E0 48 05 F8 FF FF FF 48 89 C4 48 89 2C 24" # <-- pattern for add rsp, 0xffffff8
    patterns = ["48 8B 45 58 8B 00 89 45 6C 48 89 4C 24 F8", "48 8B 45 58 0F B6 00 0F B6 C0 33 45 68"]
    for pattern in patterns:
        # base = idaapi.cvar.inf.minEA
        for ptr in FindInSegments(pattern, '.text'):
            retrace(ptr)


def GetCodeRefsFromFunc(ea):
    l = obfu.combEx(ea, includeCode=0, includeJumps=1)[1]
    return [idautils.DecodeInstruction(x[0]).Op1.addr for x in l]


def analyze(start, end):
    if end - start < 8192:
        idaapi.analyze_area(start, end)


def analyzePlan(start, end):
    if end - start < 8192:
        ida_auto.plan_range(start, end)


def RecreateFunction(funcea=None):
    """
    RecreateFunction

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    del func

    chunks = asList(idautils.Chunks(funcea))

    idc.del_func(funcea)
    idc.auto_wait()
    for i, tpl in enumerate(chunks):
        start, end = tpl
        
        if i == 0:
            idc.add_func(start, end)
        else:
            idc.append_func_tail(funcea, start, end)
        
    #  func = ida_funcs.func_t()
    #  func.start_ea = funcea
    #  r = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
    #  if r == ida_funcs.FIND_FUNC_OK:
        #  print("FIND_FUNC_OK")
    #  SetFuncStart(funcea, func.start_ea)
    #  SetFuncEnd(funcea, func.end_ea)
    #  EaseCode(funcea)
#  
    #  for ea in GetFuncHeads(funcea):
        #  ida_auto.auto_recreate_insn(ea)


def dinjasm(ea):
    """
    Get disassembly line in NASM format

    @param ea: linear address of instruction

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    length = getLength(ea)
    i = diida(ea, length)  # distorm3 disassembler: will return smth like `MOV BYTE [RIP+0x2559079], 0x1`
    if i is None: return ''
    # i = i.lower()
    e = de(ea, length)  # distorm3 decomposer:   returns instruction metainfo
    if type(e) is list and len(e):
        e = e[0]
        regex = r"\b(rip[+-]0x[0-9a-f]+)"
        i = re.sub(regex, lambda m: ripadd(m.group(), e.address + e.size), i, 0, re.IGNORECASE)
        regex = r"(0x[0-9])\b"
        i = re.sub(regex, lambda m: str(int(m.group(), 16)), i, 0, re.IGNORECASE)
    return i

# An iterable object is an object that implements __iter__, which is expected
# to return an iterator object.
def isIterable(o):
    return hasattr(o, '__iter__') and not hasattr(o, 'ljust')

# An iterator is an object that implements __next__, which is expected to
# return the next element of the iterable object that returned it, and raise
# a StopIteration exception when no more elements are available.
def isIterator(o):
    return hasattr(o, '__next__')

def isIterableNotIterator(o):
    return isIterable(o) and not isIterator(o)

def oget(obj, key, default=None):
    """Get attribute or dictionary value of object
    Parameters
    ----------
    obj : object
        container with optional dict-like properties
    key : str
        key
    default : any
        value to return on failure

    Returns
    -------
    any
        similar to obj[key] or getattr(obj, key)

    See Also
    --------
    dotted : creates `path` from dotted string
    deep_get : uses `oget` to traverse deeply nested objects

    Examples
    --------
    >>> oget(sys.modules, '__main__')
    <module '__main__' (built-in)>
    >>> oget(sys.modules['__main__'], 'oget')
    <function oget at 0x000001A9A1920378>
    """
    if not isString(key):
        raise TypeError("oget(): attribute ('{}') name must be string".format(key))
    try:
        return obj[key] if key in obj else default
    except TypeError:
        # TypeError: 'module' object is not subscriptable
        return getattr(obj, key, default)

def dotted(key):
    """Convert dotted heirachical notation into list of keys

    Backslash may be used to prevent dots from being interpreted as separators

    Parameters
    ----------
    key : str
        key

    Returns
    -------
    list
        similar to `key.split('.')`

    Examples
    --------
    >>> dotted('a.b\.c.d')
    ['a', 'b.c', 'd']
    >>> dotted('a')
    ['a']
    """
    key = key.replace(r'\.', 'PSIOUFJRHPRIUENG')
    pieces = key.split('.')
    return [x.replace('PSIOUFJRHPRIUENG', '.') for x in pieces]

def deep_get(obj, path, default=AttributeError):
    """Get nth-depth value from nested dict-like or object-like containers

    Parameters
    ----------
    obj : object|dict
        container with dict-like or object-like properties
    path : list
        heirachical path
    default : any
        value to return if path or key is invalid

    Returns
    -------
    any
        similar to obj[path[0]][path[1]] (etc)

    Raises
    ------
    KeyError
        if one of the keys is not found and no default is specified

    See Also
    --------
    dotted : creates `path` from dotted string
    oget : get attribute or dictionary key


    Examples
    --------
    >>> deep_get(sys, 'modules.__main__.deep_get')
    <function deep_get at 0x000001A9A57DA1E0>
    """
    name = getattr(obj, '__name__', 'object')
    for piece in dotted(path):
        obj = oget(obj, piece, AttributeError)
        if obj == AttributeError:
            if default==AttributeError:
                # AttributeError: module '__main__' has no attribute 'xax'
                # KeyError: 'asdfg'
                raise KeyError("object '{}' has no attribute or key '{}'".format(name, piece))
            return default
        name += '.'
        name += piece
    return obj


def getmanyattr(o, *args):
    """
    getmanyattr(object, name1[, name2 ,[name3 ,...]], default]) -> value
    
    Get a name attributes from an object; getmanyattr(x, 'y', 'z', None) is
    equivalent to [x.y, x.z].  The default argument it is returned when the
    attribute doesn't exist.
    """
    default = args[-1]
    return [getattr(o, key, default) for key in args[0:-1]]

def isDictlike(o):
    return _.all(getmanyattr(o, 'values', 'keys', 'get', None), lambda x, *a: callable(x))

def isListlike(o):
    return _.all(getmanyattr(o, 'append', 'remove', '__len__', None), lambda x, *a: callable(x))

def isSliceable(o):
    try:
        o[0:0]
        return True
    except TypeError:
        return False

def hascallable(obj, name):
    """
    hascallable(obj, name, /)
        Return whether the object has a callable attribute with the given name.
        
        This is done by calling callable(getattr(obj, name, None))
    """
    return callable(oget(obj, name, None))

def array_count(o):
    if isinstance(o, tuple) or isListlike(o) and isSliceable(o):
        return len(o)
    return 0

IsArrayCount = array_count

def isByteArray(o):
    return isinstance(o, bytearray)

def isInt(o):
    return isinstance(o, integer_types)

def isString(o):
    return isinstance(o, string_types)

def isStringish(o):
    return isinstance(o, (string_type, byte_type, bytearray))

def isBytes(o):
    return isinstance(o, byte_type)

def isByteish(o):
    return isinstance(o, (byte_type, bytearray))

def asByteArray(o):
    if isByteish(o):
        return bytearray(o)
    if isStringish(o):
        return bytearray(o, 'raw_unicode_escape')
    if isIterable(o):
        return bytearray(o)
    if isIterator(o):
        raise RuntimeError('Will this ever happen, and can we handle it as an iterable via iter()?')

def asBytes(o):
    if isinstance(o, bytearray):
        return byte_type(o)
    return o if isBytes(o) else o.encode('utf-8')

def asString(o):
    return o if isString(o) else o.decode('utf-8')

def asBytesRaw(o):
    if isinstance(o, bytearray):
        return byte_type(o)
    return o.encode('raw_unicode_escape') if isString(o) else o

def asStringRaw(o):
    return o.decode('raw_unicode_escape') if (isBytes(o) or isByteArray(o)) else o

def asRaw(o):
    if hasattr(o, 'decode'):
        return o.decode('raw_unicode_escape')
    if hasattr(o, 'encode'):
        return o.encode('raw_unicode_escape')

def asDict(o):
    r = {}
    for k, v in o.items():
        r[k] = v
    return r


def intAsBytes(i, len=0):
    b = b''
    while len > 0:
        b += asBytesRaw(chr(i & 255))
        i >>= 8
        len -= 1
    return b

def bytesAsInt(b):
    i = 0
    for x in b:
        i <<= 8
        i |= x
    return i



def MakeUniqueLabel(name, ea):
    fnLoc = idc.LocByName(name)
    if fnLoc == BADADDR or fnLoc == ea:
        return name
    fmt = "%s_%%i" % name
    for i in range(10000):
        tmpName = fmt % i
        fnLoc = idc.LocByName(tmpName)
        if fnLoc == BADADDR or fnLoc == ea:
            return tmpName
    return ""

def get_start(r):
    return r.start if hasattr(r, 'start') else r[0]

def get_end(r):
    if hasattr(r, 'end'):
        return r.end
    if hasattr(r, 'stop'):
        return r.stop
    return r[1]

def intersect(r1, r2):
    if not overlaps(r1, r2):
        return []
    t =     min(get_end(r1), get_start(r2)), \
            min(get_end(r2), get_start(r1)), \
            max(get_end(r1), get_start(r2)), \
            max(get_end(r2), get_start(r1))
    return  max(t[0], t[1]), min(t[2], t[3])

def intersect_gap(r1, r2):
    if overlaps(r1, r2):
        return []
    t =     min(get_end(r1), get_start(r2)), \
            min(get_end(r2), get_start(r1)), \
            max(get_end(r1), get_start(r2)), \
            max(get_end(r2), get_start(r1))
    return  max(t[0], t[1]) + 1, min(t[2], t[3]) - 1

def overlaps(r1, r2):
    """Does the range r1 overlaps the range r2?"""
    return get_end(r1) >= get_start(r2) and get_end(r2) >= get_start(r1)

def issubset(r1, r2):
    """Is the range r1 a subset of the range r2?"""
    return get_end(r1) <= get_end(r2) and get_start(r1) >= get_start(r2)

def issuperset(r1, r2):
    """Is the range r1 a superset of the range r2?"""
    return get_end(r1) >= get_end(r2) and get_start(r1) <= get_start(r2)

def issettest():
    s1 = set([2,3,4])
    s2 = set([1,2,3,4,5])
    r1 = GenericRange(2,4)
    r2 = GenericRange([1,5])
    print("All tests should return True: {}".format([
        s1.issubset(s2)   == issubset(r1,   r2),
        s2.issubset(s1)   == issubset(r2,   r1),
        s1.issuperset(s2) == issuperset(r1, r2),
        s2.issuperset(s1) == issuperset(r2, r1),
        s2.issuperset(s2) == issuperset(r2, r2),
    ]))

def adjoins(r1, r2):
    """Does the range r1 adjoin or overlaps the range r2?"""
    return get_end(r1) + 1 >= get_start(r2) and get_end(r2) + 1 >= get_start(r1)

def union(r1, r2):
    try:
        return type(r1)([min(get_start(r1), get_start(r2)), max(get_end(r1), get_end(r2))])
    except TypeError:
        return type(r1)(min(get_start(r1), get_start(r2)), max(get_end(r1), get_end(r2)))

def overlap2a(ranges1, ranges2):
    overlaps = []
    for x, y in itertools.product(ranges1, ranges2):
        sx = set(range(get_start(x), get_end(x) + 1))
        sy = set(range(get_start(y), get_end(y) + 1))
        overlap.extend(sx & sy)
    return GenericRanger(overlaps, sort=1)

def difference(ranges2, ranges1):
    body = set()
    diff = set()
    for x in ranges1:
        sx = set(range(get_start(x), get_end(x) + 1))
        body = body.union(sx)
    for y in ranges2:
        sy = set(range(get_start(y), get_end(y) + 1))
        d = sy - body
        diff = diff.union(d)
    return GenericRanger(diff, sort=1)

def overlap2(ranges1, ranges2):
    len1 = len(ranges1)
    len2 = len(ranges2)
    i1 = 0
    i2 = 0
    loop = 0
    try:
        while i1 < len1 and i2 < len2:
            while loop or not overlaps(ranges1[i1], ranges2[i2]):
                loop = 0
                if ranges1[i1+1][0] < ranges2[i2+1][0]:
                    i1 += 1
                else:
                    i2 += 1
            s1 = set(range(ranges1[i1][0], ranges1[i1][1] + 1))
            s2 = set(range(ranges2[i2][0], ranges2[i2][1] + 1))
            s = list(s1 & s2)
            s.sort()
            yield (s[0], s[-1], ranges1[i1], ranges2[i2])

            loop = 1
    except IndexError:
        return

def overlap3(ranges1, ranges2):
    return [x for x in overlap2(ranges1, ranges2)]

def iter_overlap_test(range1, ranges2):
    for r2 in ranges2:
        if overlaps(range1, r2):
            return True
    return False

def not_overlap3(ranges1, ranges2):
    return ( [r1 for r1 in ranges1 if not iter_overlap_test(r1, ranges2)],
             [r2 for r2 in ranges2 if not iter_overlap_test(r2, ranges1)] )
        
def format_chunk_range(ea):
    return "{:x}\u2013{:x}".format(GetChunkStart(ea), GetChunkEnd(ea))

def describe_chunk(ea1=None, ea2=None):
    ea1 = eax(ea1)
    ea2 = ea2 or GetChunkEnd(ea1)
    return "{:x}\u2013{:x}".format(ea1, ea2)

def describe_target(ea=None):
    """
    describe_target

    @param ea: linear address
    """
    class TargetDescriptor:
        """
        defines an address with additional information regarding entry
        position, chunks, and such
        """
    
        def __init__(self, ea):
            """
            __init__

            @param ea: linear address
            """
            if isinstance(ea, list):
                return [TargetDescriptor(x) for x in ea]

            self.ea        = eax(ea)
            self.name      = idc.get_name(self.ea)
            self.func_ea   = None
            self.func_name = None
            self.chunk_ea  = None
            self.chunk_num = None
            self.chunk_qty = None
            self.offset    = None

            target = self.ea
            if IsFunc_(target):
                self.func_ea = GetFuncStart(target)
                self.func_name = GetFuncName(target)
                self.offset = target - self.func_ea
            if IsChunk(target):
                self.chunk_ea = GetChunkStart(target)
                self.chunk_num = GetChunkNumber(target)
                self.chunk_qty = GetNumChunks(target)
                self.offset = target - self.chunk_ea

        def __str__(self):
            target = eax(self.ea)
            desc = []
            desc1 = [hex(target)]
            if IsFunc_(target) or IsChunk(target):
                for funcea in GetChunkOwners(target, includeOwner=True):
                    if target == GetFuncStart(target):
                        desc1.append('start of')
                    elif target == GetChunkStart(target):
                        desc1.append('start of chunk {}/{} of'.format(GetChunkNumber(target) + 1, GetNumChunks(target)))
                    else:
                        desc1.append('offset 0x{} from chunk {}/{} of'.format(target - GetChunkStart(target), GetChunkNumber(target) + 1, GetNumChunks(target)))

                    desc1.append('function \"{}\" (0x{:x})'.format(idc.get_func_name(target), GetFuncStart(target)))
                    desc.append(" ".join(desc1))
            else:
                desc.append('non function \"{}\" (0x{:x})'.format(idc.get_name(target), target))

            return ", ".join(desc)

        def __repr__(self):
            return self.__str__()


    target_obj = TargetDescriptor(ea)
    return target_obj
    
def fix_func_tails(l, extra_args=dict()):
    print("[fix_func_tails] ")
    #  [error] 0x144758f25: external conditional jump to 0x14469e5d9 start of function "sub_14469E5D9" (0x14469e5d9)
    #  [error] 0x14469b532: external conditional jump to 0x144200c81 start of function "sub_144200C81" (0x144200c81)
    patched = 0
    for e in l:
        if issubclass(type(e), FuncTailsError):
            if isinstance(e, FuncTailsJump): 
                # FuncTailsJump(True, head, describe_target(target)
                    #  def __init__(self, conditional, frm, to):
                        #  self.conditional = conditional
                        #  self.frm = frm
                        #  self.to = to
                target = e.to.ea
                if idc.get_segm_name(target) == '.text':
                    if e.conditional:
                        idc.del_func(target)
                        patched += 1
                    else:
                        callrefs = _.uniq(GetFuncStart([ea for ea in list(CallRefsTo(target)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea)]))
                        jmprefs =  _.uniq(GetFuncStart([ea for ea in list(JmpRefsTo(target)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea) and GetInsnLen(ea) > 2]))
                        refs = _.uniq(callrefs + jmprefs)
                        ref_names = GetFuncName(refs)
                        if not e.to.func_ea:
                            if len(ref_names) > 1:
                                if not HasUserName(target):
                                    LabelAddressPlus(target, "common:" + ":".join(ref_names))
                            else:
                                if not e.to.name:
                                    LabelAddressPlus(target, idc.get_name(e.frm))
                            #  ForceFunction(target)
                        elif target == e.to.func_ea and len(ref_names) > 1:
                            Commenter(target, 'line').add('[ALLOW EJMP]')

            if isinstance(e, FuncTailsUnusedChunk): pass
            if isinstance(e, FuncTailsNoppedChunk): pass
            if isinstance(e, FuncTailsBadTail): 
                if e.tail_ea and isInterrupt(e.tail_ea):
                    if not extra_args.get('ignoreInt', None):
                        print("re-running with ignoreInt = True")
                        _.extend(extra_args, {'ignoreInt': True})
                        patched += 1

            if isinstance(e, FuncTailsAdditionalChunkOwners): pass
            if isinstance(e, FuncTailsInvalidTarget): pass
        else:
            raise RuntimeError('Unhandled FuncTail error type: {}'.format(e))
    return patched


def funcname(func):
    # <built-in method append of list object at 0x0000024BC770C388>
    return string_between('function ', ' at ', str(func)) \
            or string_between(' method ', ' of ', str(func))
        
def my_append_func_tail(funcea, ea1, ea2):
    """
    Append a function chunk to the function

    @param funcea: any address in the function
    @param ea1: start of function tail
    @param ea2: end of function tail
    @return: 0 if failed, 1 if success

    @note: If a chunk exists at the specified addresses, it must have exactly
           the specified boundaries
    """
    func = ida_funcs.get_func(funcea)

    if not isinstance(func, ida_funcs.func_t):
        return 0
    else:
        try:
            if check_append_func_tail(func, ea1, ea2):
                return ida_funcs.append_func_tail(func, ea1, ea2)
        except AppendChunkError as e:
            #  tb = traceback.format_exc()
            #  printi(tb)
            stk = []
            for i in range(len(inspect.stack()) - 1, 0, -1):
                stk.append(inspect.stack()[i][3])
            print((" -> ".join(stk)))
            print("append_func_tail(0x{:x}, 0x{:x}, 0x{:x}):".format(funcea, ea1, ea2))
            print(indent(4, _.flatten(e.args)))

if hasattr(idc, 'append_func_tail'):
    idc.append_func_tail = my_append_func_tail

def xxd(dump):
    import hexdump
    return hexdump.hexdump(asBytes(dump))


def GetBase64String(ea=None, length = -1, strtype = STRTYPE_C, hex=False):
    import base64
    """
    Get base64 decoded value from string contents
    @param ea: linear address
    @param length: string length. -1 means to calculate the max string length
    @param strtype: the string type (one of STRTYPE_... constants)

    @return: string contents or empty string
    """
    ea = eax(ea)
    if length == -1:
        length = ida_bytes.get_max_strlit_length(ea, strtype, ida_bytes.ALOPT_IGNHEADS)

    coded_string = ida_bytes.get_strlit_contents(ea, length, strtype)
    if hex:
        return xxd(base64.b64decode(coded_string))
    return base64.b64decode(coded_string)

def stacktrace():
    stk = []                                         
    raw = []
    for i in range(len(inspect.stack()) - 1, 0, -1): 
        s = inspect.stack()[i]
        s2 = s[0]
        raw.append((
            s2.f_code.co_filename,
            s2.f_lineno,
            s2.f_code.co_name,
        ))
        stk.append('  File "{}", line {}, in {}'.format(
            s2.f_code.co_filename,
            s2.f_lineno,
            s2.f_code.co_name,
        ))

        #  stk.append(s2.f_code.co_firstlineno)
        #  pp(inspect.stack()[i])
        #  stk.append(inspect.stack()[i])            
    print("\n".join(stk))
    return raw

def st1():
    return stacktrace()
def st2():
    return st1()

def clear():
    ida_kernwin.msg_clear()
cls = clear

def get_nbits(ea=None, bits=64, signed=False):
    """
    get_nbits

    @param ea: linear address
    @param bits: number of bits (32, 64 and such)
    """
    if isinstance(ea, list):
        return [get_nbits(x) for x in ea]

    ea = eax(ea)
    _bytes = bits >> 3
    _bits =  bits & 7
    _total = _bytes
    if _bits:
        _total += 1

    b = idc.get_bytes(ea, _total)
    t = 0
    for c in _.reverse(list(b)):
        t |= c
        t <<= 8
    t >>= 8 - _bits
    if signed:
        return MakeSigned(t, bits)
    return t


def read_all_emu(path):
    results = dict()
    with open(r'E:\git\distorm\examples\tests\memcpy2-good.txt') as logfile:
    #  fns = glob(fn + '/memcpy*.bin')
        for fn in logfile:
            fn = fn.strip()
            base = parseHex(string_between('_', '_', fn))
            results[base] = read_emu(fn.replace('/v', 'v:'))
    return results

def SuperJump(funcea=None):
    """
    SuperJump

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [SuperJump(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    for cs, ce in idautils.Chunks(funcea):
        for ea in idautils.Heads(cs, ce):
            if isUnconditionalJmpOrCall(ea):
                SkipJumps(ea, apply=1)




def fix_sub_args():
    for fn in decompile_regex(EA(), r'(\w+\(ptr_gta5\))'): 
        ea = eax(string_between('', '(', fn))
        _type = idc.get_type(ea)
        if _type:
            SetType(ea, GetType(ea).replace('__int64 a1', 'char* p_gta5'))
        else:
            SetType(ea, '__int64 sub(char* p_gta5);')

def fix_sub_args_unknown():
    for fn in decompile_regex(EA(), r'(\w+\(a1t\))'): 
        ea = eax(string_between('', '(', fn))
        _type = idc.get_type(ea)
        if _type:
            SetType(ea, GetType(ea).replace('__int64 a1', '__int64 a1t'))
        else:
            SetType(ea, '__int64 sub(__int64 a1t);')

def codeguard():
        #  loc_143AAB03D:                          ; CODE XREF: ArxanCheckFunction_115-D2506Fvj
        #  .text:0000000143AAB03D                                                                           ; ArxanCheckFunction_115-43DE14vj
        #  .text:0000000143AAB03D  8B 05 4F 88 23 FD                             mov     eax, cs:dword_140CE3892
        #  .text:0000000143AAB043  83 C0 FF                                      add     eax, 0FFFFFFFFh
        #  .text:0000000143AAB046  89 45 50                                      mov     [rbp+80h+__anonymous_12], eax
        #  .text:0000000143AAB049  8B 45 50                                      mov     eax, [rbp+80h+__anonymous_12]
        #  .text:0000000143AAB04C  85 C0                                         test    eax, eax
        #  .text:0000000143AAB04E  0F 8D B8 DD EC FF                             jge     loc_143978E0C
        #  .text:0000000143AAB054  E9 E5 1B C2 00                                jmp     loc_1446CCC3E
	# // ARXAN(R) PATENTED CODE GUARD(TM) TECHNOLOGY 
	# auto integrityPattern = hook::pattern("8b 05 ? ? ? ? 83 c0 ff 89 45 ? 8b 45 ? 85 c0 0f 8d").count_hint(UINT32_MAX);
        # integrityPattern = 0x143AAB03D
        #
        #  .text:000000014025E639  8B 05 FC 09 E8 02                             mov     eax, cs:dword_1430DF03B
        #  .text:000000014025E63F  83 C0 FF                                      add     eax, 0FFFFFFFFh
        #  .text:000000014025E642  89 45 78                                      mov     [rbp+78h], eax
        #  .text:000000014025E645  8B 45 78                                      mov     eax, [rbp+78h]
        #  .text:000000014025E648  85 C0                                         test    eax, eax
        #  .text:000000014025E64A  0F 8C B2 2A EE 02                             jl      loc_143141102
        #  .text:000000014025E650  E9 EC 3F 35 01                                jmp     loc_1415B2641
        #
        """
        v11 = &v16;                                                          v11 = &v16;                                                      
        v12 = &word_14021900E;                                               v12 = &word_14021900E;                                           
        for ( i = dword_1430DF03B - 1; i >= 0; --i )                         for ( i = dword_1430DF03B - 1; i >= 0; --i )                     
          *((_DWORD *)sub_14010B91A + i) = v11[i];                             *((_DWORD *)sub_14010B91A + i) = v11[i];                       
        i = dword_1430DF03B - 1;                                             for ( i = dword_1430DF03B - 1; i >= 0; --i )                     
        dword_1402BB609 = dword_1422061B0;                                   {                                                                
        result = qword_140267D60 + v7;                                         if ( v11[i] != *(_DWORD *)&v12[2 * i] )                        
        *(&v21 + qword_140267D60 + v7) = (__int64)off_14001749E;                 break;                                                       
        return result;                                                       }                                                                
                                                                             if ( i >= 0 )                                                    
                                                                             {                                                                
                                                                               LOBYTE(result) = SetReturnAddressTo_14009b951_0(v9, &v21);     
                                                                               result = (unsigned int)result;                                 
                                                                               if ( (_DWORD)result )                                          
                                                                                 return result;                                               
                                                                             }                                                                
                                                                             dword_1402BB609 = dword_1422061B0;                               
                                                                             result = qword_140267D60 + v7;                                   
                                                                             *(&v21 + qword_140267D60 + v7) = (__int64)off_14001749E;         
                                                                             return result;                                                   
                                                                      
        """
                                                                  
                                                                
                                                                
                                                                
                                                                
                                                                
                                                                
                                                                

        #
        p = 0x143141102
        jmp = p + 17
        stackIndex = idc.get_wide_byte(p + 11)
        target = GetTarget(jmp + 6)
        target = SkipJumps(target)
        valid = False

        if      idc.get_wide_byte(target) == 0x8b and \
                idc.get_wide_byte(target + 1) == 0x45 and \
                idc.get_wide_byte(target + 2) == stackIndex:
            target += 3;

            if idc.get_wide_byte(target) == 0x85 and idc.get_wide_byte(target + 1) == 0xC0:
                target += 2
                valid = True;
        # if we found the other pattern, nuke it too
        if valid:
            nassemble(target, 'nop; jmp 0x{:x}'.format(GetTarget(target)), apply=True)
        PatchNops(jmp, 6)
# vim: set ts=8 sts=4 sw=4 et:
