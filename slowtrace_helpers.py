import collections
import inspect
import os
import traceback
import re
import subprocess
import math
# from fnvhash import fnv1a_64 as fnv
from static_vars import *
from superglobals import *
from attrdict1 import SimpleAttrDict
from collections import defaultdict
from string_between import string_between, string_between_splice
try:
    from exectools import _import, _from, execfile
except ModuleNotFoundError:
    from exectools import _import, _from, execfile

try:
    from anytree import Node, RenderTree
except ModuleNotFoundError:
    print("pip install anytree (if you want to draw any graphs)")
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
    from idc_bc695 import GetFunctionName, GetIdbPath, LocByName, MakeNameEx, DELIT_DELNAMES, DELIT_EXPAND, DELIT_NOTRUNC, Name, PatchByte, DelFunction, GetSpDiff, SetSpDiff, Dword, Qword, ItemHead, SegName, GetSpd, Demangle, IdaGetMnem
    from idc_bc695 import GetOperandValue, SegName, LocByName, GetIdbPath, GetInputFile, ScreenEA, DELIT_EXPAND, DELIT_NOTRUNC, Wait, NextNotTail, AppendFchunk, GetFunctionName
    import sfida.is_flags
    from membrick import MakeSigned
    from obfu_helpers import PatchBytes
    from obfu_helpers import hex_byte_as_pattern_int
    from sfcommon import GetFuncEnd, GetFuncStart, MakeCodeAndWait
    from sftools import MyMakeFunction, MyMakeUnknown
    from sftools import MyMakeUnknown, MyMakeUnkn, MyMakeFunction
    from slowtrace2 import visited, get_byte, AdvanceFailure
    from start import isString
    # from underscoretest import _

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

execfile("fsm")

#  with open(os.path.dirname(__file__) + os.sep + 'refresh.py', 'r') as f: exec(compile(f.read().replace('__BASE__', os.path.basename(__file__).replace('.py', '')).replace('__FILE__', __file__), __file__, 'exec'))

def A(o):
    if o is None:
        return []
    if isinstance(o, list):
        return o
    if isflattenable(o) and len(list(o)) > 1:
        return list(o)
    if isflattenable(o):
        return genAsList(o)
    # list(o) will break up strings
    return [o]



class TraceDepth(object):
    _depth = 0

    def __enter__(self):
        TraceDepth._depth += 1
        return TraceDepth._depth

    def __exit__(self, exc_type, exc_value, traceback):
        TraceDepth._depth -= 1

    @staticmethod
    def get():
        return TraceDepth._depth


#
@static_vars(last_indent=0) 
def printi(value, sacrificial=None, depth=None, *args, **kwargs):
    g_depth = TraceDepth.get()

    if sacrificial is not None:
        value = ", ".join(str(x) for x in [value] + list(args))
    #  assert sacrificial is None
    if isinstance(depth, int):
        g_depth = depth


    indentString = ' '
    if g_depth > printi.last_indent:
        indentString = indentString.replace(' ', '>')
    elif g_depth < printi.last_indent:
        indentString = indentString.replace(' ', '<')

    printi.last_indent = g_depth



    g_output = getglobal('g_output', None)
    if g_depth:
        _str = indent(g_depth, value, width=0x70, indentString=indentString, n2plus=g_depth+4)
    else:
        _str = value
    if isinstance(g_output, list):
        g_output.append(_str)
        return
    try:
        if isinstance(g_output, Queue):
            g_output.put(_str)
            return
    except NameError:
        pass
    print(_str)


#  printi("[slowtrace-helpers loading]")
#  stk = []
#  for i in range(len(inspect.stack()) - 1, 0, -1):
    #  stk.append(inspect.stack()[i][3])
#  printi((" -> ".join(stk)))

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
            printi("{:x} renaming to: {}".format(ea, name))
            LabelAddressPlus(ea, 'uses_' + name)
        else:
            printi("{:x} couldn't find matching vtable name".format(ea))
    else:
        printi("{:x} vtables: {}".format(ea, len(vtables)))

    

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
        rdict[e.start] = (e.start, e.last)

    rdict_keys = _.sort(list(rdict.keys()))

    def GetBlockStart(start):
        left  = bisect_left(rdict_keys, start)
        right = bisect_right(rdict_keys, start)
        # dprint("[GetBlockStart] left, right")
        result = rdict[rdict_keys[left]][0]
        if start < result:
            return None
        printi("[GetBlockStart] start:{:x} left:{:x}, right:{:x}, result:{:x}".format(start, rdict[rdict_keys[left]][0], rdict[rdict_keys[left]][1], result))
        
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
            printi("[adding] ea:{}".format(ahex(ea)))
            
            chart.append([start, ea])
            assoc[start].append(ea)
            assoc[ea].append(start)

    used = set()
    sets = []
    addrs = []
    addrs2 = []
    for k in list(assoc.keys()):
        # dprint("[debug] k")
        printi("[debug] k:{}".format(ahex(k)))
        
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
            printi("[debug] addrs:{}".format(hex(addrs2)))
            printi("[debug] used:{}".format(hex(list(used))))
            
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
    printi("dot_draw r: {}".format(r))
    if isinstance(_, tuple):
        if not r[0]:
            printi("dot_draw error: {}".format(r[1]))
        else:
            printi("dot_draw good: {}".format(r[1]))

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
                printi("[warn] function {:x}, chunk {:x}, owned by: {}".format(funcea, hex(_owners_)))
                return False

    if not chunk_starts.isdisjoint(chunk_ends):
        printi("[warn] function {:x} has adjoining chunks at {}".format(funcea, hex(list(chunk_starts.intersection(chunk_ends)))))


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


def RemoveAllChunksAndFunctions(leave=None):
    #  printi("Stage #1")
    #  chunks = []
    #  for ea in range(0, ida_funcs.get_fchunk_qty()):
        #  chunk_ea = getn_fchunk(ea).start_ea
        #  chunks.append(chunk_ea)
    #  for ea in chunks:
        #  RemoveThisChunk(ea)

    printi("Stage #2")
    leave = A(leave)
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
        #  printi("append_func_tail: appending instead of extending:\nappend_func_tail(0x{:x}, 0x{:x}, 0x{:x})\n[overlaps existing function chunk at 0x{:x}]".format(funcea))
        #  printi("executing instead: ida_funcs.set_func_end(0x{:x}, 0x{:x})".format(tail.start_ea, ea2))
        #  return ida_funcs.set_func_end(tail.start_ea, ea2)
    
    all_owners = set()
    for ea in range(ea1, ea2): # if len(list(idautils.Chunks(ea))) > 1 and func.start_ea in GetChunkOwners(ea) or \
        if ida_funcs.get_func_chunknum(func, ea) != -1:
            msg = "overlaps existing function chunk at 0x{:x}\u2013{:x}".format(GetChunkStart(ea), GetChunkEnd(ea))
            errors.append(msg)
        owners = GetChunkOwners(ea, includeOwner=1)
        if owners:
            all_owners.update(owners)
            msg = "existing owners: {} ({})".format(hex(owners), GetFuncName(owners))
            errors.append(msg)

        func_owner = ida_funcs.get_func(ea)
        if func_owner and ida_funcs.get_func_chunknum(func_owner, ea) != -1:
            msg = "would overlap existing chunk #{}/{} of {} at {:x}\u2013{:x}".format(
                    GetChunkNumber(ea, eax(func_owner)), GetNumChunks(eax(func_owner)), GetFunctionName(eax(func_owner)), GetChunkStart(ea), GetChunkEnd(ea))
            errors.append(msg)

    if _.all(all_owners, lambda v, *a: v == funcea):
        msg = "all owners are us, who cares"
        return True
        errors.append(msg)
        for ea in range(ea1, ea2):
            if ida_funcs.get_func_chunknum(func, ea) != -1:
                ida_funcs.remove_fchunk(func, ea)

    if errors:
        #  for error in set(errors):
            #  printi(error)
        raise AppendChunkError(_.uniq(errors))

    return True


def FindBadJumps():
    for funcea in idautils.Functions():
        for ea in GetFuncHeads(funcea):
            if isAnyJmpOrCall(ea):
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
                    printi("[SkipJmpChunks] {:x} AdvanceFailure triggering unpatch and retrace".format(ea))
                    funcea = GetFuncStart(ea)
                    idc.del_func(funcea)
                    UnpatchUn()
                    retrace(funcea)
                else:
                    printi("[SkipJmpChunks] {:x} AdvanceFailure: {}".format(ea, e))

        if count > 1:
            patched.add(ea)
            target = SkipJumps(ea)
            for ea in [x for x in refs if isConditionalJmp(x)]:
                insn_len = insn
                if InsnLen(ea) == 6:
                    nassemble(ea, "{} 0x{:x}".format(IdaGetMnem(ea), target), apply=1)
                else:
                    # assemble using internal ida assembler which will
                    # automatically create short jmps (nassemble is set to
                    # strict mode an will always create regular jmps unless
                    # otherwise specified)
                    targets = _.reverse(jumps[1:])
                    for tgt in targets:
                        assembled = nassemble(ea, "{} 0x{:x}".format(IdaGetMnem(ea), target))
                        #  if len(assembled) <= InsnLen(ea):
                            #  PatchBytes(ea, assembled, "SkipJmp")
                            #  break


def FixAllChunks(leave=None):
    printi("Stage #1")
    for funcea in idautils.Functions():
        for r in range(20):
            if not FixChunks(funcea, leave=leave):
                break
            idc.auto_wait()
            pass

    printi("Stage #2")
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
        printi("[FixChunks] not a function: {}".format(hex(funcea)))
        return 0
    else:
        funcea = func.start_ea

    failed = fixed = 0

    chunk_count_1 = func.tailqty
    chunk_count_2 = len([x for x in idautils.Chunks(funcea)]) - 1
    if chunk_count_1 != chunk_count_2:
        printi("[FixChunks] tailqty != len(Chunk)")

    if func and func.tailqty > 1:
        all_chunks = [x for x in idautils.Chunks(funcea)] #  if x[0] != funcea
        if debug: printi("[FixChunks] total chunks: {}".format(len(all_chunks)))
        for chunk_start, chunk_end in all_chunks:
            _chunk_number = GetChunkNumber(chunk_start, funcea)
            if debug: printi("[FixChunks] checking chunk #{} ({})".format(_chunk_number, GetChunkNumber(chunk_start)))
            if _chunk_number > -1 and GetChunkNumber(chunk_start) == -1:
                if debug: printi("[FixChunks] invalid chunk number #{} ({})".format(_chunk_number, GetChunkNumber(chunk_start)))

                if len(GetChunkOwners(chunk_start)) == 0:
                    printi("[FixChunks] We have a really messed up ghost chunk at 0x{:x} belonging to 0x{:x} with no ChunkOwners".format(chunk_start, funcea))
                    ida_retrace(funcea)
                    printi("[FixChunks] Trying again after ida_retrace")
                    ida_retrace(funcea)
                    if len(GetChunkOwners(chunk_start)) == 0:
                        return False
                        printi("[FixChunks] We have a really messed up ghost chunk at 0x{:x} belonging to 0x{:x} with no ChunkOwners".format(chunk_start, funcea))
                    else:
                        return True
                    
                    _tailqty = func.tailqty
                    _chunk_list = GetChunks(funcea)
                    _ida_chunks = idautils.Chunks(funcea)
                    if len(_chunk_list) > _chunk_number:
                        _cc = _chunk_list[_chunk_number]


                    if not GetChunkOwners(_cc['start']):
                        if idaapi.cvar.inf.version >= 700 and sys.version_info >= (3, 7):
                            printi("[FixChunk] No ChunkOwners: {:#x}".format(_cc['start']))
                            # printi("[FixChunk] GhostChunk: ZeroFunction {:#x}".format(funcea))
                            # ZeroFunction(func.start_ea)
                            for cs, ce in _ida_chunks:
                                if idc.remove_fchunk(funcea, cs):
                                    printi("[FixChunk] GhostChunk: removed chunk {:#x}-{:#x} from {:#x}".format(cs, ce, funcea))
                                else:
                                    printi("[FixChunk] GhostChunk: couldn't remove chunk {:#x}-{:#x} from {:#x}".format(cs, ce, funcea))
                            for cs, ce in _ida_chunks:
                                if not IsChunk(cs):
                                    if idc.append_func_tail(funcea, cs, ce):
                                        printi("[FixChunk] GhostChunk: re-appended chunk {:#x}-{:#x} to {:#x}".format(cs, ce, funcea))
                                    else:
                                        printi("[FixChunk] GhostChunk: couldn't append chunk {:#x}-{:#x} to {:#x}".format(cs, ce, funcea))
                                else:
                                    printi("[FixChunk] GhostChunk: chunk {:#x}-{:#x} already added to {:#x}".format(cs, ce, funcea))
                        else:
                            printi("[FixChunks] Attempting dangerous thing #1: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(func.start_ea, _cc['start'], _cc['end']))
                            r = ida_funcs.append_func_tail(func, _cc['start'], _cc['end'])
                            printi("[FixChunks] Completed dangerous thing #1: {}".format(r))
                            if not r:
                                printi("[FixChunks] Attempting dangerous thing #1.1: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(func.start_ea, _cc['start'], _cc['start'] + IdaGetInsnLen(_cc['start'])))
                                r = ida_funcs.append_func_tail(func, _cc['start'], _cc['start'] + IdaGetInsnLen(_cc['start']))
                                printi("[FixChunks] Completed dangerous thing #1.1: {}".format(r))
                            if r:
                                idc.auto_wait()
                                if func.tailqty > _tailqty:
                                    printi("[FixChunks] func {:x} grew from {} to {} tails".format(funcea, _tailqty, func.tailqty))
                                    # dangerous to mess further with this function and it's chunks right now
                                    return 1
                                else:
                                    if GetChunkNumber(chunk_start) > -1:
                                        printi("[FixChunks] func {:x} didn't grow a new tail, but it has a chunk number now".format(funcea))
                                        return 1
                                    else:
                                        printi("[FixChunks] func {:x} didn't grow a new tail".format(funcea))
                    else:
                        printi("[FixChunks] #9")
                    return 0

                if funcea not in GetChunkOwners(chunk_start):
                    printi("[FixChunks] We have a really messed up ghost chunk at 0x{:x} belonging to 0x{:x} with ChunkOwners: {}".format(chunk_start, funcea, GetChunkOwners(chunk_start)))

                    printi("[FixChunks] Func {:x} isn't owner of own chunk {:x}".format(funcea, chunk_start))
                    _old_owners = GetChunkOwners(chunk_start)
                    SetChunkOwner(chunk_start, funcea)
                    for _owner in _old_owners:
                        if not idc.remove_fchunk(_owner, chunk_start):
                            # make triple sure of this, as we will crash ida 7.5 if we're wrong
                            if _owner not in GetChunkOwners(chunk_start):
                                printi("[FixChunks] Attempting dangerous thing #2: ida_funcs.append_func_tail({:x}, {:x}, {:x}".format(GetFunc(_owner), chunk_start, GetChunkEnd(chunk_start)))
                                r = ida_funcs.append_func_tail(GetFunc(_owner), chunk_start, GetChunkEnd(chunk_start))
                                printi("[FixChunks] Completed dangerous thing #2: {}".format(r))
                            printi("[FixChunks] Attempting dangerous thing #3: idc.set_tail_owner({:x}, {:x})".format(chunk_start, _owner))
                            r = idc.set_tail_owner(chunk_start, _owner)
                            printi("[FixChunks] Completed dangerous thing #3: {}".format(r))
                            printi("[FixChunks] Attempting dangerous thing #4: idc.remove_fchunk({:x}, {:x})".format(_owner, chunk_start))
                            r = idc.remove_fchunk(_owner, chunk_start)
                            printi("[FixChunks] Completed dangerous thing #4: {}".format(r))
                            if r:
                                printi("[FixChunks] Managed to fix really fucked up ghost chunk")
                                continue
                            
            else:
                pass
                #  if debug: printi("[FixChunks] valid chunk number #{} ({})".format(_chunk_number, GetChunkNumber(chunk_start)))
            r = FixChunk(chunk_start, leave=funcea, owner=funcea, chunk_end=chunk_end)
            #  if r == False:
                #  return r
            if isinstance(r, integer_types):
                fixed += r
            elif r == False:
                failed += 1
    else:
        if debug: printi("[FixChunks] not a func, or no tails: {}".format(hex(funcea)))
        pass


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
    _chunkOwners = GetChunkOwners(ea)
    _chunkOwner = GetChunkOwner(ea) # this can turn up a different result
    _chunkNumber = GetChunkNumber(ea)
    if _chunkOwner == idc.BADADDR:
        _chunkOwner = None
    if _chunkOwner and _chunkOwner not in chunkOwners:
        printi("[FixChunk] chunk:{:x} chunkOwner not in chunkOwners".format(ea))
        chunkOwners.append(_chunkOwner)
        _realOwner = PickChunkOwner(ea)

    chunkOwners = [x for x in chunkOwners if IsValidEA(x)]

    #  # dprint("[FixChunk] _chunkNumber, chunkOwners, _chunkOwner, set.intersection(set(chunkOwners), [_chunkOwner])")
    # print("[FixChunk] _chunkNumber:{}, _chunkOwners:{}, _chunkOwner:{}, set.intersection(set(_chunkOwners), [_chunkOwner]):{}".format(_chunkNumber, _chunkOwners, _chunkOwner, set.intersection(set(_chunkOwners), [_chunkOwner])))

    
    if _chunkNumber == -1 and _chunkOwners and _chunkOwner and not set.intersection(set(_chunkOwners), [_chunkOwner]):
        printi("[FixChunk] chunk at {:x} has conflicting and mutually exclusive owner and owners {}, {}".format(ea, hex(_chunkOwners), hex(_chunkOwner)))
        #  .text:0000000140A90F99     loc_140A90F99:                          ; CODE XREF: PED::_0x862C576661F1AAEF_ACTUAL_0_0-29DCF35↓j
        #  .text:0000000140A90F99 038                 nop
        #  .text:0000000140A90F9A 038                 nop                     ; jmp via push rbp and xchg
        #  .text:0000000140A90F9B 038                 jmp     loc_14336845F
        #
        # .text:0000000143C719B5     ; START OF FUNCTION CHUNK FOR NotRealSub [0x140a90fa0] (GetChunkOwner)
        # .text:0000000143C719B5     ;   ADDITIONAL PARENT FUNCTION CheckLoadedModules_inner [0x14345725b] (GetChunkOwners)
        # .text:0000000143C719B5
        # .text:0000000143C719B5     cs: 

        chunkOwners = GetChunkOwners(ea)
        chunkParent = chunkOwners[0]
        chunkAdditionalParent = _chunkOwner
        chunkStart = GetChunkStart(ea)
        chunkEnd = GetChunkEnd(ea)

        #  FixChunk(chunkStart)
        idc.del_func(chunkParent)
        #  FixChunk(chunkStart)
        idc.del_func(chunkAdditionalParent)
        #  FixChunk(chunkStart)
        append_func_tail(chunkParent, chunkStart, chunkEnd)
        remove_func_tail(GetFunc(chunkParent), chunkStart)
        RemoveAllChunkOwners(chunkStart)
        RemoveChunk(chunkStart)
        ForceFunction(chunkAdditionalParent)
        ForceFunction(chunkParent)
        ida_funcs.append_func_tail(GetFunc(chunkParent), chunkStart, chunkEnd)
        return idc.remove_fchunk(chunkParent, chunkStart)

        #        Python>chunkStart=chunkStart 
        #            chunkStart
        #        Python>ce=chunkEnd
        #            chunkEnd
        #        Python>FixChunk(chunkStart)
        #            [FixChunk] chunk:143c719b5 chunkOwner not in chunkOwners
        #            [FixChunk] chunk at 143c719b5 is orphaned from ['chunkAdditionalParent', 'chunkParent']
        #            [FixChunk] chunk:143c719b5 invalid_owners:['chunkParent'], valid_owners:['CheckLoadedModules_inner']
        #            [FixChunk] Making function at 140a90fa0
        #            [FixChunk] Recovery mode #1 for owner 140a90fa0
        #            _append_func_tail(chunkParent, chunkStart, chunkEnd)
        #            <module> -> FixChunk
        #            append_func_tail(chunkParent, chunkStart, chunkEnd):
        #                existing owners: ['chunkAdditionalParent'] (['CheckLoadedModules_inner'])
        #            [FixChunk] Removing invalid_owners function at 140a90fa0
        #            0x1
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            ([chunkAdditionalParent], chunkParent, -0x1)
        #        Python>idc.del_func(chunkAdditionalParent)
        #            True
        #        Python>FixChunk(chunkStart)
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            [FixChunk] chunk:143c719b5 chunkOwner not in chunkOwners
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            [FixChunk] chunk at 143c719b5 is orphaned from ['chunkAdditionalParent', 'chunkParent']
        #            [FixChunk] chunk:143c719b5 invalid_owners:['chunkAdditionalParent', 'chunkParent'], valid_owners:[]
        #            [FixChunk] Making function at 14345725b
        #            [FixChunk] Recovery mode #1 for owner 14345725b
        #            _append_func_tail(chunkAdditionalParent, chunkStart, chunkEnd)
        #            <module> -> FixChunk
        #            append_func_tail(chunkAdditionalParent, chunkStart, chunkEnd):
        #                existing owners: ['chunkAdditionalParent'] (['CheckLoadedModules_inner'])
        #            [FixChunk] Making function at 140a90fa0
        #            [FixChunk] Recovery mode #1 for owner 140a90fa0
        #            _append_func_tail(chunkParent, chunkStart, chunkEnd)
        #            <module> -> FixChunk
        #            append_func_tail(chunkParent, chunkStart, chunkEnd):
        #                existing owners: ['chunkAdditionalParent'] (['CheckLoadedModules_inner'])
        #            [FixChunk] Removing invalid_owners function at 14345725b
        #            [FixChunk] Removing invalid_owners function at 140a90fa0
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            0x1
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            ([chunkAdditionalParent], chunkParent, -0x1)
        #        Python>append_func_tail(chunkParent, chunkStart, chunkEnd)
        #            0x0
        #        Python>remove_func_tail(GetFunc(chunkParent), chunkStart)
        #            False
        #        Python>RemoveAllChunkOwners(chunkStart)
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            [RemoveAllChunkOwners] couldn t remove chunk 143c719b5
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            ([chunkAdditionalParent], chunkParent, -0x1)
        #        Python>RemoveChunk(chunkStart)
        #            couldn t find function for chunk at 143c719b5
        #        Python>GetFuncName(chunkAdditionalParent)
        #            ''
        #        Python>GetFuncName(chunkParent)
        #            ''
        #        Python>retrace(previousFunctionToChunk, adjustStack=1)
        #            [retrace] funcea:5432088992
        #            [retrace] address:5432088992
        #            slowtrace2 ea=previousFunctionToChunk sub_143C719A0 {}
        #            143c719a0 repl:        Search: 48 8d 64 24 f8 48 89 1c 24
        #                               Replace: ('push rbx',)
        #                               Comment: lea rsp, qword ptr [rsp-8]; mov [rsp], rbx
        #            143bc9313 replFunc:    Search: 55 48 bd -1 -1 -1 -1 -1 -1 00 00 48 87 2c 24 -1 -1 48 8b -1 24 10 48 -1 -1 -1 -1 -1 -1 -1 00 00 48 0f -1 -1 48 89 -1 24 10 -1 -1 c3
        #                               Replace: ['jg 0x140cfbfee', 'jmp 0x140a5c9b9', 'int3']
        #                               Comment: mini-cmov
        #            143bc9313 made patches (reversing head) to 143c719a0
        #            previousFunctionToChunk: 0x143bc9313: 8 130 fixing unexpected stack change from: nop | jmp     loc_143BA85C0
        #            140a5c9b9 repl:        Search: 48 8d 64 24 f8 4c 89 04 24
        #                               Replace: ('push r8',)
        #                               Comment: lea rsp, qword ptr [rsp-8]; mov [rsp], r8
        #            1434d992d repl:        Search: 48 8d 64 24 f8 48 89 14 24
        #                               Replace: ('push rdx',)
        #                               Comment: lea rsp, qword ptr [rsp-8]; mov [rsp], rdx
        #            *** non-str repl: (10, [72, 141, 100, 36, 248, 72, 137, 28, 36, 144])
        #            140d38d79 repl:        Search: 48 8d 64 24 f8 48 89 1c 24
        #                               Replace: ('push rbx',)
        #                               Comment: lea rsp, qword ptr [rsp-8]; mov [rsp], rbx
        #            previousFunctionToChunk: 0x140d38d7a: 28 138 fixing unexpected stack change from: nop     dword ptr [rax+00h] | jmp     loc_1435D681A
        #            [simple_patch_factory] result:['jmp 0x140cfbf67', 'int3']
        #            143655499 replFunc:    Search: 55 48 8d 2d -1 -1 -1 -1 48 87 2c 24 c3
        #                               Replace: ['jmp 0x140cfbf67', 'int3']
        #                               Comment: jmp via push rbp and xchg
        #            143655499 made patches (reversing head) to 143a74f6e
        #            previousFunctionToChunk: 0x1435d6822: 31 130 fixing unexpected stack change from: nop | nop     dword ptr [rax+rax+00000000h]
        #            1437ffc57 repl:        Search: 48 8d 64 24 08 ff 64 24 f8
        #                               Replace: ('retn', 'int3')
        #                               Comment: return disguised as lea + jmp
        #            1437ffc57 made patches (reversing head) to 14366685a
        #            previousFunctionToChunk: 0x1437ffc57: 81 8 retn: adding retn rsp of 0x8
        #
        #            slowtrace returned 8
        #            func_tails returned 0
        #            slowtrace2 ea=previousFunctionToChunk sub_143C719A0 {}
        #
        #            hash stayed at 27e6163397c96833
        #            slowtrace returned 0
        #            func_tails returned 0
        #            0 -- 140a5c9b9 adjusting delta by -140 to -128
        #            3 -- 140cb263d adjusting delta by 8 to 8
        #            25 -- 140d38d7b adjusting delta by 8 to 8
        #            32 -- 1433cf6cd adjusting delta by -120 to -120
        #            49 -- 143666856 adjusting delta by -8 to -8
        #            54 -- 1437ffc4e adjusting delta by 120 to 120
        #            57 -- 1438cfb74 adjusting delta by -128 to -128
        #            69 -- 143a97988 adjusting delta by 8 to 0
        #            73 -- 143bc9313 adjusting delta by -10 to 0
        #            79 -- 143c719a9 adjusting delta by 8 to 8
        #            _fix_spd(spdList) attempt 10
        #            0x0
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            [GetChunkOwners] stated owner 14345725b of chunk 143c719b5 is not a function
        #            ([chunkAdditionalParent], chunkParent, -0x1)
        #        Python>ForceFunction(chunkAdditionalParent)
        #            0x19
        #        Python>ForceFunction(chunkParent)
        #            0x8
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            ([chunkAdditionalParent], chunkParent, -0x1)
        #        Python>ida_funcs.append_func_tail(GetFunc(chunkParent), chunkStart, chunkEnd)
        #            True
        #        Python>GetChunkOwners(), GetChunkOwner(), GetChunkNumber()
        #            ([chunkParent, chunkAdditionalParent], chunkParent, 0x1)
        #        Python>idc.remove_fchunk(chunkParent, chunkStart)
        #            True


    if _chunkNumber == -1 and chunkOwners:
        printi("[FixChunk] chunk at {:x} is orphaned from {}".format(ea, hex(chunkOwners)))
        if len(chunkOwners) == 1:
            owner = _.first(chunkOwners)
            if not IsFuncHead(owner):
                printi("need to create parent")
                if not ForceFunction(owner):
                    printi("couldn't make parent")
            idc.auto_wait()
            if GetChunkNumber(ea) != -1:
                printi("chunk has a number now, removing it")
                idc.remove_fchunk(owner, ea)
                return 1
            printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, GetChunkStart(ea), GetChunkEnd(ea)))
            if ida_funcs.append_func_tail(GetFunc(owner), GetChunkStart(ea), GetChunkEnd(ea)):
                if not idc.remove_fchunk(owner, GetChunkStart(ea)):
                    printi("idc.remove_fchunk(0x{:x}, 0x{:x}) failed; recreating parent function".format(owner, GetChunkStart(ea)))
                    func = ida_funcs.get_func(owner)
                    fnLoc = func.start_ea
                    for start, end in idautils.Chunks(fnLoc):
                        idc.remove_fchunk(start, end)
                    ida_funcs.del_func(func.start_ea)
                    printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)))
                    if _append_func_tail(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)):
                        if not idc.remove_fchunk(fnLoc, GetChunkStart(ea)):
                            printi("idc.remove_fchunk(0x{:x}, 0x{:x}) failed".format(fnLoc, GetChunkStart(ea)))
                            return 0
                        else:
                            return 1
                    else:
                        printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x}): failed".format(fnLoc, GetChunkStart(ea), GetChunkEnd(ea)))
                        return 0
            else:
                printi("couldn't append func to owner")

            return 1

    if not chunkOwners and owner:
        printi("[FixChunk] chunk at {:x} appears to have no chunkOwners, arguments expected {:x} with chunk_end {}?".format(ea, owner, hex(chunk_end)))
        chunk_end = EaseCode(ea, forceStart=1)
        printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, ea, chunk_end))
        if _append_func_tail(owner, ea, chunk_end):
            idc.auto_wait()
            if idc.remove_fchunk(owner, ea):
                idc.auto_wait()
                printi("[FixChunk] chunk at {:x} removed".format(ea))
                return 1
        printi("[FixChunk] should resort to ZeroFunction of {:#x}, but won't".format(owner))
        raise RuntimeError("check it out")




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
        #  printi("[FixChunk] {}".format(pf({
                #  "x": x,
                #  "y": y,
                #  "z": hex(z),
            #  })))
#  
#  
    #  printi("[FixChunk] {}".format(pf({
            #  "invalid_owners": hex(invalid_owners),
            #  "valid_owners": hex(valid_owners),
            #  "ghost_owners": hex(ghost_owners),
        #  })))

    #  if not valid_owners and not invalid_owners and owner and GetChunkNumber(ea, owner) > -1:
        #  ghost_owners.append(owner)


    needs_fixing = 0
    if ghost_owners:
        printi("[FixChunk] ghost_owners:{:x} ghost_owners:{}" \
                .format(ea, hex(ghost_owners), GetFuncName(ghost_owners)))
        printi("[FixChunks] RemoveAllChunks")
        chunks = RemoveAllChunks(owner)
        for r in range(len(chunks)):
            if GetNumChunks(owner) > 1:
                printi("[FixChunks] RemoveAllChunks")
                RemoveAllChunks(owner)
            else:
                break
        idc.auto_wait()
        for cs, ce in chunks[1:]:
            printi("[FixChunks] read chunk: {:x}, {:x}".format(cs, ce))
            printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(owner, cs, ce))
            _append_func_tail(owner, cs, ce)

        return



    if invalid_owners or len(valid_owners) > 1:
        needs_fixing = 1
        printi("[FixChunk] chunk:{:x} invalid_owners:{}, valid_owners:{}" \
                .format(ea, hex(invalid_owners), GetFuncName(valid_owners)))

    if invalid_owners:
        for funcea in invalid_owners:
            printi("[FixChunk] Making function at {:x}".format(funcea))
            # if not MyMakeFunction(funcea):
            if not idc.add_func(funcea, IdaGetInsnLen(funcea) + funcea):
                for _ea in invalid_owners + valid_owners: 
                    printi("Removing all chunks from {:x}".format(_ea))
                    # for r in range(10):
                    while len(RemoveAllChunks(_ea)) > 1:
                        pass
                if len(GetChunkOwners(funcea)) > 1:
                    raise RuntimeError("[FixChunk] Couldn't make {:x} into a legitimate function".format(funcea))
    
            idc.auto_wait()
            # if we try to add chunkOwnersFuncNames chunk that overlaps an existing chunk owned by
            # the same function, IDA will crash.  So check for this first.
            if ida_funcs.get_func_chunknum(GetFunc(funcea), GetChunkStart(ea)) == -1:
                printi("[FixChunk] Recovery mode #1 for owner {:x}".format(funcea))
                printi("_append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, GetChunkStart(ea), GetChunkEnd(ea)))
                _append_func_tail(funcea, GetChunkStart(ea), GetChunkEnd(ea))
            else:
                printi("[FixChunk] Recovery mode #2 for owner {:x}".format(funcea))
                idc.remove_fchunk(funcea, GetChunkStart(ea))

        for funcea in invalid_owners:
            printi("[FixChunk] Removing invalid_owners function at {:x}".format(funcea))
            if not idc.del_func(funcea):
                if GetChunkNumber(ea, funcea) > -1:
                    raise RuntimeError("[FixChunk] Couldn't remove function at {:x}".format(funcea))
            idc.auto_wait()

    if len(valid_owners) > 1:
        printi("[FixChunk] Multiple valid owners ({}), removing them all from {:x} (except: {})".format(", ".join(GetFuncName(valid_owners)), ea, hex(leave)))
        RemoveAllChunkOwners(ea, leave=leave)

    if len(GetChunkOwners(ea)) > 1:
        printi("[FixChunk] Owners still > 1, removing all chunks...")
        for _ea in invalid_owners + valid_owners: 
            printi("Removing all chunks from {:x}".format(_ea))
            # for r in range(10):
            while len(RemoveAllChunks(_ea)) > 1:
                pass
        if len(GetChunkOwners(ea)) > 1:
            printi("[FixChunk] Owners really still > 1...")
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
            printi("[warn] FixAllChunks: couldn't fix adjoining chunks at {:x}".format(ea))



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
    
    if isinstance(funcea, list):
        for ea in funcea:
            ZeroFunction(ea, total=total)
        return

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        # allow to operate on non-function
        ea = funcea
    else:
        ea = func.start_ea

    fnLoc = ea
    fnName = None

    if total < 0:
        if not func:
            func = func_t()
            func.start_ea = ea
        if total == -1:
            return ida_funcs.reanalyze_function(func), idc.auto_wait() # process and return true
        if total == -2:
            r = ida_funcs.find_func_bounds(func, FIND_FUNC_DEFINE | FIND_FUNC_IGNOREFN )
            l = ['FIND_FUNC_UNDEF', 'FIND_FUNC_OK', 'FIND_FUNC_EXIST']
            idc.auto_wait()
            return (r, l[r], func.start_ea, func.end_ea)
        return None

    if debug: printi("[ZeroFunction] {:x}".format(ea))
    # Keep existing comments

    if func and func.end_ea:
        if debug: printi("[ZeroFunction]: {:#x} {:#x}-{:#x}".format(fnLoc, func.start_ea, func.end_ea))
        fnLoc = func.start_ea
        fnName = ida_funcs.get_func_name(fnLoc)
        flags = func.flags  # idc.get_func_attr(ea, FUNCATTR_FLAGS)
        # remove library flag
        idc.set_func_attr(fnLoc, FUNCATTR_FLAGS, flags & ~4)
        func = None
        #  ida_name.del_local_name(fnLoc)
        #  ida_name.del_global_name(fnLoc)
        #  # RemoveAllChunks(ea)
        #  for start, end in idautils.Chunks(ea):
            #  # idc.remove_fchunk(start, end)
            #  idc.remove_fchunk(ea, start)
        ida_funcs.del_func(fnLoc)

        # ida_auto.auto_make_proc(func.start_ea)
        # idc.auto_wait()
        idc.set_color(fnLoc, CIC_FUNC, 0xffffffff)

    if func:
        # don't leave func object open
        func = None

    if not total:

        #  # FIND_FUNC_NORMAL   = _ida_funcs.FIND_FUNC_NORMAL   """ stop processing if undefined byte is encountered """
        #  FIND_FUNC_DEFINE   = _ida_funcs.FIND_FUNC_DEFINE   """ create instruction if undefined byte is encountered """
        #  FIND_FUNC_IGNOREFN = _ida_funcs.FIND_FUNC_IGNOREFN """ ignore existing function boundaries. by default the function returns function boundaries if ea belongs to a function.  """
        #  # FIND_FUNC_KEEPBD   = _ida_funcs.FIND_FUNC_KEEPBD   """ just create instructions inside the boundaries.  do not modify incoming function boundaries, """
        #
        #  FIND_FUNC_UNDEF    = _ida_funcs.FIND_FUNC_UNDEF    """ nfn->end_ea will have the address of the unexplored byte.  function has instructions that pass execution flow to unexplored bytes.  """
        #  FIND_FUNC_OK       = _ida_funcs.FIND_FUNC_OK       """ ok, 'nfn' is ready for 'add_func()' """
        #  FIND_FUNC_EXIST    = _ida_funcs.FIND_FUNC_EXIST    """ its bounds are returned in 'nfn'.  function exists already.  """

        func = ida_funcs.func_t(fnLoc)
        res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
        if res == ida_funcs.FIND_FUNC_UNDEF:
            printi("[ZeroFunction]: {:#x} func passed flow to unexplored byte at {:#x}".format(fnLoc, func.end_ea))
        elif res == ida_funcs.FIND_FUNC_EXIST:
            printi("[ZeroFunction]: {:#x} func already exists at {:#x}-{:#x}".format(fnLoc, func.start_ea, func.end_ea))
        elif res == ida_funcs.FIND_FUNC_OK:
            if debug: pph(func)
            ida_funcs.add_func_ex(func)

        idc.auto_wait()
        # remove library flag (again)
        idc.set_func_flags(fnLoc, idc.get_func_flags(fnLoc) & ~4)
        # return original function name
        
        if fnName:
            idc.set_name(fnLoc, fnName, idc.SN_NOWARN)



def Decompile(ea):
    func = clone_items(ida_funcs.get_func(ea))
    if func:
        # SetType(ea, "void __fastcall func(native args);")
        try:
            cfunc = ida_hexrays.decompile(ea)
        except DecompilationFailure:
            printi(("0x%x: failed to decompile" % ea))
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
                printi(("0x%x: failed to decompile" % ea))
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
    MyMakeUnkn(ea, DELIT_DELNAMES | DELIT_EXPAND | DELIT_NOTRUNC)
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


def IsSameChunk(old, new):
    # Could probably be done simpler
    old = eax(old)
    new = eax(new)
    if not IsFunc_(old):
        printi("[IsSameChunk] old is not a function {:#x}".format(old))
        return False

    if not IsFunc_(new):
        return False

    if not ida_funcs.is_same_func(old, new):
        # printi("[IsSameChunk] different functions")
        return False
    # dprint("[IsSameChunk] owners1, owners2")
    #  printi("[IsSameChunk] owners1:{}, owners2:{}".format(hex(owners1), hex(owners2)))
    
    if GetChunkNumber(old) != GetChunkNumber(new):
        return False

    return True

    ## unused
    owners1 = set(GetChunkOwners(old))
    owners2 = set(GetChunkOwners(new))

    if not owners1 or not owners2:
        printi("[IsSameChunk] no owners")
        return False

    if owners1 != owners2:
        printi("[IsSameChunk] different owners")
        return False


def IsSameFunc(ea1, ea2):
    ea1 = eax(ea1)
    ea2 = eax(ea2)
    try:
        result = ida_funcs.is_same_func(ea1, ea2) or GetFuncName(ea1) and GetFuncName(ea1) == GetFuncName(ea2)
    except TypeError as e:
        printi("{}: {}: ({}, {})".format(e.__class__.__name__, str(e), ahex(ea1), ahex(ea2)))
        result = None
    return result


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
        printi("[debug] pos:{:x}, end:{:x}".format(pos, end))
        fail = 1

    if pos < end:
        printi("[debug] pos:{:x}, end:{:x}".format(pos, end))
        fail = 1

    if idx > count:
        # dprint("[debug] pos, end")
        printi("[debug] idx:{:x}, count:{:x}".format(pos, end))
        fail = 1
        
    if not fail:
        for _len, _pos in results: 
            forceCode(_pos, _len)
        return True, results

    return False, results

def FindRvaOffsetsTo(target, segments='.pdata'):
    segments = A(segments)
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
                printi("Found: {:x}".format(ea))
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
    
def GetTarget(ea, flow=0, calls=1, conditionals=1, operand=1, failnone=False):
    """
    @param operand bitmask 1 | 2 == 3 
    """
    if isIterable(ea):
        return [GetTarget(x, flow=flow, calls=calls, conditionals=conditionals, operand=operand, failnone=failnone)
                for x in ea]
    ea = eax(ea)
    if (isJmpOrObfuJmp(ea) and not isJmp(ea)):
        # return MakeSigned(idc.get_wide_dword(ea + 4)) + ea + 7
        return MakeSigned(idc.get_wide_dword(ea + 1)) + ea + 5
    elif idc.get_operand_type(ea, 1) in (idc.o_mem, idc.o_imm) and IsValidEA(idc.get_operand_value(ea, 1)): # and IsCode_(idc.get_operand_value(ea, 1)):
        return idc.get_operand_value(ea, 1)
    elif idc.get_operand_type(ea, 0) in (idc.o_mem, idc.o_imm) and IsValidEA(idc.get_operand_value(ea, 0)): # and IsCode_(idc.get_operand_value(ea, 1)):
        return idc.get_operand_value(ea, 0)
    if isOffset(ea):
        target = getptr(ea) 
        if idc.get_inf_attr(idc.INF_MIN_EA) <= target < idc.get_inf_attr(idc.INF_MAX_EA):
            return target

    mnem = IdaGetMnem(ea) or GetMnemForce(ea)
    disasm = idc.GetDisasm(ea) or GetDisasmForce(ea)
    if not mnem:
        if IsUnknown(ea) or IsData(ea):
            end = EaseCode(ea, forceStart=1, noExcept=1)
        idc.auto_wait()
        mnem = IdaGetMnem(ea)
        if not mnem:
            di_mnem = GetMnemDi(ea)
            msg = "{:x} couldn't get mnem from '{}' | ida: '{}' distorm: '{}')".format(ea, disasm, mnem, di_mnem)
            if di_mnem != mnem:
                raise AdvanceFailure(msg)
            return None if failnone else BADADDR
    
    rv = None
    if operand & 1 and (mnem == "jmp" or (calls and mnem == "call") or (conditionals and mnem[0] == "j")):
        opType = idc.get_operand_type(ea, 0)
        if opType in (idc.o_near, idc.o_mem):
            rv = idc.get_operand_value(ea, 0)
        elif opType == idc.o_reg:
            # 'call    rax ; j_smth_metric_tamper'
            s = string_between('; ', '', disasm).strip()
            if s:
                result = eax(s)
                if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
                    rv = result

    if operand & 2 and (mnem == "mov" or mnem == "lea"):
        opType = idc.get_operand_type(ea, 1)
        if opType in (idc.o_near, idc.o_mem):
            return idc.get_operand_value(ea, 1)
        if opType == idc.o_reg:
            # 'call    rax ; j_smth_metric_tamper'
            s = string_between('; ', '', disasm).strip()
            if s:
                result = eax(s)
                if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
                    rv = result
        #  printi("[warn] can't follow opType {} from {:x}".format(opType, ea))

    if not rv and flow:
        if idc.next_head(ea) == ea + idc.get_item_size(ea) and idc.is_flow(idc.get_full_flags(idc.next_head(ea))):
            rv = idc.next_head(ea)
        else:
            if debug: printi("{:x} no flow".format(ea))

    # printi("{:x} GetTarget: no idea what to do with '{}' [flow={},calls={},conditionals={}]".format(ea, diida(ea), flow, calls, conditionals))
    if rv and ida_ida.cvar.inf.min_ea <= rv < ida_ida.cvar.inf.max_ea:
        return rv
    return None if failnone else BADADDR

def GetTarget7(ea):
    mnem = IdaGetMnem(ea)
    if not mnem:
        return idc.BADADDR
    
    opType0 = idc.get_operand_type(ea, 0)
    if mnem == "jmp" or mnem == "call" or mnem[0] == "j":
        if opType0 != o_near and opType0 != o_mem:
            printi("Can't follow opType0 " + opTypeAsName(opType0))
            return idc.BADADDR
        else:
            return idc.get_operand_value(ea, 0)

    if idc.next_head(ea) == ea + idc.get_item_size(ea) and \
            idc.is_flow(idc.get_full_flags(idc.next_head(ea))):
        return idc.next_head(ea)

def opTypeAsName(n):
    for item in [x for x in dir(idc) if x.startswith('o_')]:
        if getattr(idc, item) == n: return f"idc.{item}"

def insnITypeAsName(n):
    for item in [x for x in dir(idaapi) if x.startswith('NN_')]:
        if getattr(idaapi, item) == n: return f"idaapi.{item}"

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
    # if debug: printi("[idapy] idc.get_fchunk_attr(0x{:x}, FUNCATTR_OWNER): {:x}".format(ea, r))
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
    # if debug: printi("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
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
        if IsValidEA(r):
            if r not in owners:
                printi("[GetChunkOwners] FUNCATTR_OWNER: {:x} not listed in owners".format(r))
                owners.append(r)
                pass

    for owner in owners[:]:
        if not IsValidEA(owner):
            printi("[GetChunkOwners] removing BADADDR: {:x}".format(owner))
            owners.remove(owner)
        if not idaapi.is_func(idc.get_full_flags(owner)):
            if idaapi.get_func(owner) is None:
                printi("[GetChunkOwners] stated owner {:x} of chunk {:x} is not a function".format(owner, ea))
            else:
                printi("[GetChunkOwners] stated owner {:x} of chunk {:x} is not the function head".format(owner, ea))

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

    printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, ea1, ea2))
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
            if debug: printi(line)
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
        MyMakeUnknown(r.start, r.length, DELIT_NOTRUNC)
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
            printi("Unusual Chunk Issue")
            printi(result)
            printi((re.sub(r'(\d+)L', lambda x: "0x{:x}".format(int(x.group(1))), pprint.pformat(r))))

    #  if result == 0:
    #  printi("0x%x: Nothing to do from 0x%x to 0x%x" % (us, start, end))

    # if it turns out we can't make a single chunk like this, we need to use:
    #  SetChunkStart(ownedAddresses[ownerName][0], fnAddr)
    #  if flowEnd > ownedAddresses[ownerName][-1]:
    #  SetChunkEnd(ownedAddresses[ownerName][0], flowEnd)

    if debug:
        printi(("\n".join(lines)))
        printi(line)
        return {'otherOwnerRanges': otherOwnerRanges, 'noOwnerRanges': noOwnerRanges, 'weOwnItRanges': weOwnItRanges,
                'noCodeRanges': noCodeRanges, 'funcStartRanges': funcStartRanges}
    return result

def GetChunkStart(ea=None):
    ea = eax(ea)
    return idc.get_fchunk_attr(ea, FUNCATTR_START)

def GetChunkStarts(ea):
    for cstart, cend in idautils.Chunks(ea):
        yield cstart

def GetChunkCount(ea):
    count = 0
    for cstart, cend in idautils.Chunks(ea):
        count += 1
    return count


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
        # if debug: printi(f"[idapy] owner = ida_funcs.get_func({ea:#x}):\n{pfh(owner)}")
    elif isinstance(funcea, ida_funcs.func_t):
        pass
    else:
        owner = ida_funcs.get_func(eax(funcea))
        # if debug: printi(f"[idapy] owner = ida_funcs.get_func({funcea:#x}):\n" + pfh(owner))
    r = ida_funcs.get_func_chunknum(owner, ea)
    # if debug: printi(f"[idapy] ida_funcs.get_func_chunknum(owner, {ea:#x}): {r}")
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
        printi("[GetNumChunks] chunk: {}".format(count))
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
        #  printi("[IsChunk] typeof ea: {}".format(type(ea)))
    if isinstance(ea, ida_funcs.func_t):
        return ea.flags & ida_funcs.FUNC_TAIL
    ea = eax(ea)
    if GetChunkNumber(ea) == 0:
        return False
    if GetChunkOwners(ea, includeOwner=1):
        return True
    return False



def IdaGetInsnLen(ea):
    i = ida_ua.insn_t(); l = ida_ua.decode_insn(i, ea); return l

#  def GetInsnLen(*args):
    #  return IdaGetInsnLen(*args)
#  
#  def InsnLen(ea):
    #  return MyGetInstructionLength(ea)

GetInsnLen = IdaGetInsnLen
InsnLen = IdaGetInsnLen

def InsnRange(ea):
    return list(range(ea, ea + IdaGetInsnLen(ea)))


def InsnRangePlusOne(ea):
    return list(range(ea, ea + IdaGetInsnLen(ea) + 1))


def InsnRangeIgnoreFirst(ea):
    return list(range(ea + 1, ea + IdaGetInsnLen(ea) - 1))


def InsnRangePlusOneIgnoreFirst(ea):
    return list(range(ea + 1, ea + IdaGetInsnLen(ea) + 0))

def GetRbp(ea):
    ea = eax(ea)
    func = GetFunc(ea)
    if not func:
        printi("return_unless: func")
        return 
    
    return idc.get_spd(ea) + func.frsize - func.fpd + func.frregs

def GetSpDiffEx(ea=None):
    ea = eax(ea)
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
    MyMakeUnknown(ea, length, DELIT_EXPAND | DELIT_NOTRUNC)
    #  for addr in range(ea, ea + length):
    #  SetSpDiff(ea, 0)

def IsOffset64(ea=None, apply=False, loose=False):
    ea = eax(ea)
    _is_offset = (True
            and (loose or ea & (ptrsize() - 1) == 0)
            and IsOff0(ea)
            and IsValidEA(getptr(ea))
            and not IsCode_(ea) 
            and re.match(r'd\w offset ', idc.GetDisasm(ea))
            and True
    )

    if apply and _is_offset:
        idc.del_items(ea, DELIT_NOTRUNC, ptrsize())
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


def AppendFunc(funcea=None, append=None):
    """
    AppendFunc

    @param funcea: any address in the function
    """
    if isinstance(append, list):
        return [AppendFunc(funcea, x) for x in append]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    append_ea = eax(append_ea)
    append_func = ida_funcs.get_func(append_ea)

    if not append_func:
        return 0
    else:
        append_ea = append_func.start_ea

    chunks = list(idautils.Chunks(append_ea))
    idc.del_func(append_ea)
    for cs, ce in chunks:
        idc.append_func_tail(funcea, cs, ce)

    
    

def FuncFindRetrace(cs=False, **kwargs):
    idc.jumpto(GetFuncStart(here()))
    FuncFindApplySkipJumps()
    while FuncFindBadJumps(here()):
            for ea in FuncFindBadJumps(here()): 
                try:
                    if cs:
                        ea = GetChunkStart(ea)
                    print("Trying address: 0x{:x}".format(ea))
                    slowtrace2(here(), midfunc=ea, count=100, **kwargs)
                except Exception as e:
                    print("{}: {}".format(e.__class__.__name__, str(e)))
            FuncFindApplySkipJumps()

def FuncFindNopChunks(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindNopChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    for cs, ce in MicroChunks(funcea):
        if _.all(idautils.Heads(cs, ce), lambda v, *a: isNop(v)):
            results.append(cs)

    return results

def FuncFindTrailingChunks(funcea=None, fix=False):
    """
    FuncFindTrailingChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindTrailingChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    for cs, ce in MicroChunks(funcea):
        #  print("{}, {}".format(cs, ce))
        ea = _.last(list(idautils.Heads(cs, ce)))
        if not ea:
            print("*** {:x}".format(cs))
        else:
            if not isJmp(ea) and not isRet(ea):
                results.append((cs, ea))

    if fix:
        # should be set to use microchunks
        for ea in [x[0] for x in results]: SetFuncEnd(GetChunkStart(ea), EaseCode(GetChunkStart(ea)))
    return results

def FuncFindBadJumps(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindNopChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    for cs, ce in idautils.Chunks(funcea):
        #  ea = _.last(list(idautils.Heads(cs, ce)))
        for ea in idautils.Heads(cs, ce):
            if isAnyJmp(ea) and get_operand_type(ea, 0) not in (1, ) and not ida_funcs.is_same_func(funcea, GetTarget(ea)):
                results.append(ea)

    return results

def FuncFindApplySkipJumps(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindApplySkipJumps(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    for cs, ce in Chunks(funcea):
        for ea in idautils.Heads(cs, ce):
        #  ea = _.first(list(idautils.Heads(cs, ce)))
            if isAnyJmp(ea):
                SkipJumps(ea, skipNops=1, apply=1)
                results.append(ea)

    for ea in FuncFindUnusedChunks(): ida_funcs.remove_func_tail(func, ea)

    return results


def FuncFindUnusedChunks(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindUnusedChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    for cs, ce in MicroChunks(funcea):
        if cs != funcea:
            if not _.any(idautils.Heads(cs, ce), lambda v, *a: _.any(xrefs_to(v), lambda v, *a: ida_funcs.is_same_func(funcea, v))):
                results.append(cs)

    return results

def FuncTidyJumps(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncFindNopChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    results = []
    FuncFindApplySkipJumps(funcea)
    for ea in FuncFindApplySkipJumps(funcea):
        idc.remove_fchunk(funcea, ea)
        # RemoveThisChunk(ea)
        results.append(ea)

    return results

def FuncObfuPatch(funcea=None):
    """
    FuncFindNopChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncObfuPatch(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    patch_results = []
    p = ProgressBar(GetChunkCount(funcea))
    n = 0
    for cs, ce in idautils.Chunks(funcea):
        n += 1
        p.update(n)
        for ea in idautils.Heads(cs, ce):
            if not isNop(ea):
                patch_result = True
                while patch_result:
                    patch_result = obfu.patch(ea)
                    if patch_result:
                        patch_results.append(patch_result)
                        # pat, result = patch_results.pat, patch_results.result
                        # must_reverse = forceReflow or getattr(pat.options, 'reflow', None) or noResume
                        #  if must_reverse:
                            #  break
    return patch_results

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

    # global_chunks[tail.start_ea].update(idautils.Chunks(tail.start_ea))
    # get_func_chunknum(GetFunc(ea), ea) -> int
    return ida_funcs.set_func_end(tail.start_ea, value)
    # return SetFuncEnd(ea, value)

def SetFuncOrChunkEnd(ea, value):
    if IsHeadChunk(ea):
        return SetFuncEnd(ea, value) 
    elif IsChunk(ea, value):
        return SetChunkEnd(ea, value)
    else:
        printi("[SetFuncOrChunkEnd] {:x} Not a chunk/func head)".format(ea))
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
    # if debug: printi("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
    return func


def GetChunkPP(ea=None):
    """
    GetChunkPP

    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_fchunk(ea)
    r = pf(func)
    printi(re.sub(r"((?:, |: |\[|\{)-?)(\d\d+)([,}\]])", lambda m: m[1] + hex(m[2]) + m[3], r))

def IsNiceFunc(funcea=None, verbose=False, noChunks=False):
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

    insn = ida_ua.insn_t()
    insnlen = ida_ua.decode_insn(insn, eax(ea))

    if insnlen == 1:
        return False

    # mov [rsp+arg_0], rbx
    # sub rsp, imm
    if (insn.ops[0].type, insn.ops[0].reg) in ((4, 4), (1, 4)): 
        good += 1
    # mov    reg, rsp
    elif (insn.ops[1].type, insn.ops[1].reg) == (1, 4): 
        good += 1

    elif insn_match(ea, idaapi.NN_mov, (idc.o_reg, 0), (idc.o_reg, 4), comment='mov rax, rsp'):
        good += 1

    elif insn_match(ea, idaapi.NN_test, (idc.o_reg, None), (idc.o_reg, None), comment='test rdx, rdx'):
        good += 1

    elif insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp TheJudge_rough_labor_orgy_0_0'):
        good += 0


    elif IdaGetMnem(ea) == "push" and idc.get_wide_word(ea) & 0xf0ff == 0x5040:
        good += 1


    else:
        if verbose: print(f"{ea:#x} didn't start with anything nice")
        return False
    
    if noChunks and GetNumChunks(ea) != 0:
        if verbose: print(f"{ea:#x} GetNumChunks() == {GetNumChunks(ea)}")
        return False
  
    if ida_funcs.func_does_return(ea):
        # if verbose: print(f"{ea:#x} func_does_return(): Yes")
        if IsFuncSpdBalanced(ea):
            # if verbose: print(f"{ea:#x} IsFuncSpdBalance(): Yes")
            good += 1
        else:
            if verbose: print(f"{ea:#x} IsFuncSpdBalance(): No")
            return False
    else:
        if verbose: print(f"{ea:#x} func_does_return(): No")

    if len([x for x in range(GetFuncStart(ea), GetFuncEnd(ea)) if not IsCode_(x) and not IsTail(x)]):
        if verbose: print(f"{ea:#x} Non-Code present")
        return False
    if _.any(GetFuncHeads(ea), lambda x, *a: (idc.get_spd(ea) % 10) == 0 and idc.get_wide_byte(ea) == 0xe9):
        if verbose: print("(idc.get_spd({:#x}) % 10) == 0 and idc.get_wide_byte({:#x}) == 0xe9".format(ea, ea))
        return False
    if _.any(GetFuncHeads(ea), lambda x, *a: idc.get_wide_dword(ea) & 0x002d8d48 == 0x002d8d48 or idc.get_wide_dword(ea) & 0x242c8748 == 0x242c8748):
        if verbose: print("idc.get_wide_dword({:#x}) & 0x002d8d48 == 0x002d8d48 or idc.get_wide_dword({:#x}) & 0x242c8748 == 0x242c8748".format(ea, ea))
        return False

    return good

def insn_opercount(insn):
    return len(_.filter(_.pluck(insn.ops, ['dtype', 'phrase', 'reg', 'type']), lambda x, *a: sum(x)))

def insn_preview(ea=None, returnOutput=False, multi=False):
    """
    SampleFuncStart

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [insn_preview(x, returnOutput=returnOutput, multi=multi) for x in ea]

    result = []

    def output(s):
        if returnOutput:
            result.append(s)
        else:
            print(s)

    ea = eax(ea)

    insn = ida_ua.insn_t()
    insnlen = ida_ua.decode_insn(insn, eax(ea))
    ida_ua.decode_insn(insn, ea)

    oc = insn_opercount(insn)
    if multi:
        if oc > 1:
            output("({}, ({}, {}), ({}, {}))".format(insnITypeAsName(insn.itype), opTypeAsName(insn.ops[0].type), insn.ops[0].reg, opTypeAsName(insn.ops[1].type), insn.ops[1].reg))
        else:
            output("({}, ({}, {}))".format(insnITypeAsName(insn.itype), opTypeAsName(insn.ops[0].type), insn.ops[0].reg))
    else:
        if oc > 1:
            output("insn_match(ea, {}, ({}, {}), ({}, {}), comment='{}')".format(insnITypeAsName(insn.itype), opTypeAsName(insn.ops[0].type), insn.ops[0].reg, opTypeAsName(insn.ops[1].type), insn.ops[1].reg, diida(ea)))
        else:
            output("insn_match(ea, {}, ({}, {}), comment='{}')".format(insnITypeAsName(insn.itype), opTypeAsName(insn.ops[0].type), insn.ops[0].reg, diida(ea)))

    if returnOutput:
        return "".join(result)

def insn_mpreview(start=None, end=None, returnOutput=False):
    """
    insn_mpreview

    @param start: start address (default: screen_ea)
    @param end:   end address (default: end of flow)
    """
    if isinstance(start, list) and end is None:
        return [insn_mpreview(x, y, returnOutput=returnOutput) for x, y in start]

    start = eax(start)
    end = eax(end) if end else EaseCode(start)

    if returnOutput:
        return [insn_preview(ea, returnOutput=True, multi=True) for ea in idautils.Heads(start, end)]

    print('insn_mmatch(ea, [{}])'.format(
        ", ".join( ["{}".format(insn_preview(ea, returnOutput=True, multi=True)) for ea in idautils.Heads(start, end)])
        ))


def di_insn_preview(ea=None):
    """
    SampleFuncStart

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [SampleFuncStart(x) for x in ea]

    ea = eax(ea)

    insn = de(ea)
    if not insn:
        return none

    insn = insn[0]
    oc = len(insn.operands)
    if oc > 1:
        print("insn_match(ea, {}, ({}, {}), ({}, {}), comment='{}')".format(insn.mnemonic, insn.operands[0].type, insn.operands[0].name, insn.operands[1].type, insn.operands[1].name, diida(ea)))
    else:
        print("insn_match(ea, {}, ({}, {}), comment='{}')".format(insn.mnemonic, insn.operands[0].type, insn.operands[0].name, diida(ea)))


def insn_match(ea=None, itype=None, op0=None, op1=None, comment=None, verbose=False):
    """
    insn_match

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [insn_match(x) for x in ea]

    ea = eax(ea)
    
    if itype is re.Pattern:
        raise ValueError("Unimplemented")
    elif isinstance(itype, str):
        raise ValueError("Unimplemented")
    elif isinstance(itype, int):
        itype = asTuple(itype)

    insn = ida_ua.insn_t()
    insnlen = ida_ua.decode_insn(insn, eax(ea))
    ida_ua.decode_insn(insn, ea)

    if itype and insn.itype not in itype:
        if verbose: print("insn.itype {} failed to match {}".format(insn.itype, itype))
        return False

    if op0:
        if isinstance(op0, int):
            op0 = ((op0,), None)
        if len(op0) < 2:
            op0 = (op0[0], None)
        op0 = (asTuple(op0[0]), asTuple(op0[1]))

        if None not in op0[0] and insn.ops[0].type not in op0[0]:
            if verbose: print("op0[0] failed to match")
            return False

        if None not in op0[1] and insn.ops[0].reg not in op0[1]:
            if verbose: print("op0[1] failed to match")
            return False

    if op1:
        if isinstance(op1, int):
            op1 = ((op1,), None)
        if len(op1) < 2:
            op1 = (op1[0], None)
        op1 = (asTuple(op1[0]), asTuple(op1[1]))

        if None not in op1[0] and insn.ops[1].type not in op1[0]:
            if verbose: print("op1[0] failed to match")
            return False

        if None not in op1[1] and insn.ops[1].reg not in op1[1]:
            if verbose: print("op1[1] failed to match")
            return False

    return True
    

def insn_mmatch(ea=None, patterns=None):
    """
    insn_match

    @param ea: linear address
    """

    ea = eax(ea)
    if patterns:
        for pat in patterns:
            print("insn_match({})".format((ea, *pat)))
            if not insn_match(ea, *pat):
                return False
            ea = ea + IdaGetInsnLen(ea)

    return True
    

    insn_mmatch(
            EA(), 
            [
                ((idaapi.NN_lea, idc.o_reg), (2, idc.o_mem)), 
                ((idaapi.NN_mov, idc.o_reg), (1, idc.o_imm)), 
                ((idaapi.NN_jmp, idc.o_near))])


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
            # if debug: printi("[idapy] idc.get_func_name(0x{:x}): {}".format(ea, r))
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

def RenameFunctionsRe(pattern, repl, functions=None, exclude=None, filter=None, dryRun=True, flags=0):
    result = []
    def perform(ea, prev, name):
        if not dryRun:
            if prev != name:
                LabelAddressPlus(ea, name)
        return ea, prev, name

    if pattern and not isinstance(pattern, re.Pattern):
        pattern = re.compile(pattern, flags)
    if exclude and not isinstance(exclude, re.Pattern):
        exclude = re.compile(exclude, flags)
    if functions is None:
        functions = idautils.Functions()
    for a in functions:
        fnName = idc.get_name(a)
        if re.search(pattern, fnName, flags): #  and (not filter or filter(fnName)): #  and (not exclude or not re.search(exclude, fnName, flags)):
            result.append(perform(a, fnName, re.sub(pattern, repl, fnName, flags)))


    return result
    

def GetFuncSize(ea):
    if not IsChunked(ea):
        return GetFuncEnd(ea) - GetFuncStart(ea)
    return _.reduce([get_last(x) - get_start(x) for x in idautils.Chunks(ea)], lambda v, memo, *a: memo + v, 0)

def GetUnchunkedFuncSize(ea):
    return GetFuncEnd(ea) - GetFuncStart(ea)


def GetJumpTarget(ea):
    return GetTarget(ea, failnone=True) or GetRawJumpTarget(ea)
    """
    probably just a complicated way of doing:
    GetOperandValue(ea, 0)
    """

def MakeSigned(number, size=32):
    number = number & (1<<size) - 1
    return number if number < 1<<size - 1 else - (1<<size) - (~number + 1)

def GetRawJumpTarget(ea):
    if ea is None:
        return None
    
    insnlen = IdaGetInsnLen(ea)
    if not insnlen:
        return None
    result = MakeSigned(idc.get_wide_dword(ea + insnlen - 4), 32) + ea + insnlen
    if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
        return result
    return None

class SkipJumpsChunkTargetError(Exception):
    pass

def SkipJumps(ea=None,
		apply=False,
		includeEnd=False,
		includeStart=False,
		returnTarget=False,
		iteratee=None,
		name=None,
		notPatched=False,
        skipObfu=False,
		returnJumps=False,
		skipConditionals=True,
		skipNops=False,
		unpatch=False,
		until=None,
        abortOnChunkTarget=False,
        skipCalls=True,
        skipShort=True,
        untilInclusive=0,
		*args,
		**kwargs):

    if isIterable(ea):
        return [SkipJumps(
            ea=x,
            apply=apply,
            abortOnChunkTarget=abortOnChunkTarget,
            skipConditionals=skipConditionals,
            includeEnd=includeEnd,
            includeStart=includeStart,
            returnTarget=returnTarget,
            iteratee=iteratee,
            name=name,
            notPatched=notPatched,
            skipObfu=skipObfu,
            returnJumps=returnJumps,
            skipNops=skipNops,
            skipShort=skipShort, 
            skipCalls=skipCalls,
            unpatch=unpatch,
            until=until,
            untilInclusive=untilInclusive,
            *args,
            **kwargs)
                for x in ea]

    ea = eax(ea)
    start = ea
    target = ea
    jumps = []
    count = 0
    targets = [ea]
    iterateeQueue = []
    iterateeQueueHistory = set()
    iterateeQueueEnd = []
    processedIterateeQueue = []

    if not IsValidEA(ea):
        raise ValueError("Invalid start: {:#x}".format(ea))

    def return_jumps():
        jumps.extend(targets)
        if returnTarget:
            return _.uniq(jumps + targets)
        else:
            return _.uniq(jumps + targets)[0:-1]


    def iterateeAdd(_count, _ea):
        if _ea not in iterateeQueueHistory:
            iterateeQueueHistory.add(_ea)
            iterateeQueue.append([_count, _ea])
            # printi("iterateeAdd: {}, {:#x}".format(_count, _ea))
            if _count == -1:
                processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)

    def processIterateeQueue(q, state, *args, **kwargs):
        removeLater = []
        # dprint("[processIterateeQueue] q")
        #  print("[processIterateeQueue] q:{}, state:{}".format(q, state))
        
        if state != 'end':
            return
        if state == 'end':
            if not iterateeQueueEnd:
                iterateeQueueEnd.append(True)
                if iterateeQueue and (iterateeQueue[-1][0] != 0 or not includeEnd): 
                    iterateeQueue[-1][0] = -1
            else:
                raise RuntimeError("processIterateeQueue called twice with end")
        if iteratee:
            for i, item in enumerate(q):
                # dprint("[processIterateeQueue] i, item[0], item[1]")
                if debug: print("[processIterateeQueue] i:{}, item[0]:{}, item[1]:{:#x}".format(i, item[0], item[1]))
                if item[0] == 0 and not includeStart:
                    continue
                if item[0] == -1 and not includeEnd:
                    continue
                if debug: print("calling iteratee from processedIterateeQueue")
                iteratee(item[1], item[0], *args, **kwargs)
                #  removeLater.append(i)

        if apply and state == 'end' and len(processedIterateeQueue) > 1:
            # dprint("[processIterateeQueue] processIterateeQueue")
            # print("[processIterateeQueue] processedIterateeQueue:{}".format(processedIterateeQueue))
            
            # adding targets to the end and _uniqing is just a hack, need to fix properly adding final target
            _start, *_mid, _end = _.uniq([x[1] for x in processedIterateeQueue] + targets)
            # dprint("[processIterateeQueue] _start, _mid, _end")
            # print("[processIterateeQueue] _start:{}, _mid:{}, _end:{}".format(_start, _mid, _end))
            
            Commenter(_start, 'line').add('SkipJumpsIterateeStart: here -> {}'.format(" -> ".join(hex(_mid + [_end]))))
            Commenter(_end, 'line').add('SkipJumpsIterateeEnd: {} -> here'.format(" -> ".join(hex([_start] + _mid))))
            for _ea in _mid:
                Commenter(_ea, 'line').add('SkipJumpsIterateeMid: {}'.format(" -> ".join(hex([_start] + _mid + [_end]))))

        processedIterateeQueue.extend(q)
        q.clear()

    if not isInt(ea):
        printi("ea was not int: {}".format(type(ea)))
    if not isCall(ea):
        skipCalls = False
    if not isConditionalJmp(ea):
        skipConditionals = False

    # apply = 0
    if (IsOff0(ea) and IsOffset(ea) and IsCode_(getptr(ea))):
        skipConditionals = False
        skipCalls = False
        finalTarget = SkipJumps(
                ea=getptr(ea),
                apply=apply,
                # returnJumps=returnJumps,
                abortOnChunkTarget=abortOnChunkTarget,
                includeEnd=includeEnd,
                includeStart=includeStart,
                returnTarget=returnTarget,
                iteratee=iteratee,
                name=name,
                skipObfu=skipObfu,
                notPatched=notPatched,
                skipCalls=False,
                skipConditionals=False,
                skipNops=skipNops,
                skipShort=skipShort, 
                unpatch=unpatch,
                until=until,
                untilInclusive=untilInclusive,
                *args,
                **kwargs
        )
        if apply and finalTarget != getptr(ea) and IsValidEA(finalTarget):
            target = finalTarget
            # deal with fixups
            length = 8
            fx = idaapi.get_next_fixup_ea(ea - 1)
            while fx < ea + length:
                idaapi.del_fixup(fx)
                fx = idaapi.get_next_fixup_ea(fx)

            if not HasUserName(target) and HasUserName(getptr(ea)):
                LabelAddressPlus(target, ean(getptr(ea)), force=1)
                SetType(target, idc.get_type(getptr(ea)))
            setptr(ea, target)
            Commenter(ea, 'line').add('SkipJumps: Offset -> {}'.format(hex(target)))

        # TODO: iteratee will get called twice (once by finalTarget)
        iterateeAdd(0, ea)
        iterateeAdd(-1, finalTarget)
        return target

    # isJmpOrObfuJmp(ea)

    if isUnconditionalJmp(ea) and isRet(GetTarget(ea)):
        if apply:
            prevInsnLen = InsnLen(ea)
            PatchBytes(ea, "c3", "jmp locret")
            PatchNops(ea + 1, prevInsnLen - 1)
            if GetChunkEnd(ea) == ea + prevInsnLen:
                SetFuncEnd(ea, ea + 1)

    # lea rax, sub_1234 or whatever
    if IsCode_(ea) and idc.get_operand_type(ea, 1) == idc.o_mem and IsCode_(GetTarget(ea)):
        target = idc.get_operand_value(ea, 1)
        if IsValidEA(target) and IsCode_(target):
            new_target = SkipJumps(
                    ea=target,
                    apply=apply,
                    includeEnd=includeEnd,
                    includeStart=includeStart,
                    returnTarget=returnTarget,
                    iteratee=iteratee,
                    name=name,
                    skipObfu=skipObfu,
                    notPatched=notPatched,
                    skipCalls=skipCalls,
                    skipConditionals=skipConditionals,
                    skipNops=skipNops,
                    skipShort=skipShort, 
                    unpatch=unpatch,
                    until=until,
                    untilInclusive=untilInclusive,
                    *args,
                    **kwargs
            )
            if new_target != target:
                if apply:
                    nassemble(ea, string_between('[rel ', ']', diida(ea), repl=hex(new_target)), apply=1)
                    Commenter(ea, 'line').add('SkipJumps: Operand 1 {}'.format(hex(new_target)))
                    Commenter(target, 'line').add('SkipJumps: from Operand 1: {}'.format(hex(target)))
                # TODO: iteratee will get called twice (once by finalTarget)
                iterateeAdd(0, target)
                iterateeAdd(-1, new_target)

        return return_jumps() if returnJumps else target

    
    match_NN_rest = [idaapi.NN_jmp]
    match_NN_initial = [idaapi.NN_jmp]
    mnem_start = IdaGetMnem(ea)

    # XXX: this will never be true, as target is always ea at this point
    if callable(iteratee) and target != ea:
        print("this point never reached?")
        iteratee(target, -1, *args, **kwargs)

    jumps.append(target)
    while target != idc.BADADDR:
        iterateeAdd(count, target) # target == ea 
        count += 1
        if count > 100:
            raise AdvanceFailure("[SkipJumps] Possible recursive jump, origin: {:#x}".format(ea))
        if IsTail(target):
            print("[SkipJumps] {:#x} {:#x} IsTail".format(ea, target))
            try:
                EaseCode(target, forceStart=1)
            except AdvanceFailure:
                printi("[SkipJumps] AdvanceFailure: Jump Origin: {:#x}".format(ea))
                raise
            # break
        if IsUnknown(target):
            print("[SkipJumps] {:#x} {:#x} IsUnknown".format(ea, target))
            try:
                EaseCode(target, forceStart=1)
            except AdvanceFailure:
                printi("[SkipJumps] AdvanceFailure: Jump Origin: {:#x}".format(ea))
                raise
        if target == ea:
            match_NN = match_NN_initial
        else:
            match_NN = match_NN_rest
        if unpatch: #  or not idautils.DecodeInstruction(target):
            if IsUnknown(target) or IsData(target):
                for addr in targets:
                    unpatched = UnpatchUntilChunk(addr)
                    if debug: printi("{:x} UnpatchUntilChunk: {}".format(addr, unpatched))
                return return_jumps() if returnJumps else True
        if not IsCode_(target):
            try:
                forceCode(target)
            except AdvanceFailure as e:
                print("AdvanceFailure performing SkipJump from {:#x} to {:#x}".format(ea, target))
                raise

        if until:
            endix = max(0, len(targets)-2+untilInclusive)
            # dprint("[debug] endix")
            #  printi("[debug] endix:{}".format(endix))
            
            if isInt(until):
                if target == until:
                    return return_jumps() if returnJumps else targets[endix]
            elif callable(until):
                r = until(target)
                if r:
                    if r < 0:
                        return return_jumps() if returnJumps else r
                    return return_jumps() if returnJumps else targets[endix]
        # printi(("0x%x: target: 0x%x: %s" % (ea, target, dii(target))))

        insn = GetInsn(target)
        if not insn:
            disasm_forced = idc.generate_disasm_line(target, idc.GENDSM_FORCE_CODE)
            printi("Couldn't find insn at {:x} | forced: {}".format(target, disasm_forced))
            if not ida_ua.can_decode(target):
                raise AdvanceFailure("couldn't find valid insn at {:x} (started jumping at {:x})".format(target, start))
            processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)
            return return_jumps() if returnJumps else target
        directTarget = GetTarget(target)
        _obfuJump = False
        if skipObfu:
            #  printi("skipObfu: isObfuJmp({:#x}) == {}".format(target, ahex(isObfuJmp(target))))
            _obfuJump = isObfuJmp(target)

        if not IsValidEA(directTarget):
            if directTarget != idc.BADADDR:
                processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)
                printi("Invalid directTarget: {:x}, called from {:x}".format(directTarget, ea))
                raise AdvanceFailure("couldn't find valid target at {:x} (started jumping at {:x})".format(target, start))
                #  UnPatch(target, InsnLen(target))
                ida_auto.auto_recreate_insn(target)
                idc.auto_wait()

        # skipCalls is disabled after this, so we can be sure it is the first instruction
        if skipCalls and insn.itype == idaapi.NN_call \
                or skipConditionals and isConditionalJmp(target) and MyGetInstructionLength(target) > 4:
            skipCalls = False
            skipConditionals = False
            mnem = IdaGetMnem(target)
            if GetTarget(directTarget) != directTarget:
                finalTargets = SkipJumps(
                        ea=directTarget,
                        apply=apply,
                        returnJumps=True,
                        returnTarget=True,
                        abortOnChunkTarget=abortOnChunkTarget,
                        includeEnd=False,
                        includeStart=False,
                        # iteratee=iteratee,
                        name=name,
                        skipObfu=skipObfu,
                        notPatched=notPatched,
                        skipCalls=False,
                        skipConditionals=False,
                        skipNops=skipNops,
                        skipShort=skipShort, 
                        unpatch=unpatch,
                        until=until,
                        untilInclusive=untilInclusive,
                        *args,
                        **kwargs
                )
                jumps.extend(finalTargets)
                finalTarget = finalTargets[-1]
                for addr in finalTargets:
                    iterateeAdd(count, addr)
                    count += 1
                processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)

                if directTarget != finalTarget:
                    if apply:
                        printi("performing: iassemble2(0x{:x}, \"{} 0x{:x}\")".format(target, mnem, finalTarget))
                        prevInsnLen = InsnLen(target)
                        assembled = iassemble(target, "{} 0x{:x}".format(mnem, finalTarget), apply=1)
                        Commenter(target, 'line').add('SkipJumps: {} {:#x}'.format(mnem.title(), finalTarget))
                        Commenter(finalTarget, 'line').add('SkipJumps: From {}: {:#x}'.format(mnem.title(), target))
                        if len(assembled) < prevInsnLen:
                            PatchNops(target + len(assembled), prevInsnLen - len(assembled), 'SkipJumps: Call {:#x}'.format(finalTarget))
                        elif len(assembled) > prevInsnLen:
                            raise RuntimeError("Somehow overwrite smaller instruction at {:#x}".format(target))

                    return return_jumps() if returnJumps else finalTarget
                #  else:
                    #  return return_jumps() if returnJumps else target

            return return_jumps() if returnJumps else target

        skipCalls = False
        skipConditionals = False

        if IsFunc_(directTarget) and not IsFuncHead(directTarget) and abortOnChunkTarget:
            processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)
            if noExcept:
                return return_jumps() if returnJumps else target
            raise SkipJumpsChunkTargetError([target, directTarget])

        while _obfuJump or insn_match(target, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_1434D63EA') and (IdaGetInsnLen(target) > 2 or skipShort):
            if notPatched:
                if ida_bytes.get_original_byte(target) != idc.get_wide_byte(target):
                    break
            newTarget = _obfuJump or GetTarget(target)
            if IsValidEA(newTarget) and newTarget != target:
                iterateeAdd(1, newTarget)
                if target not in jumps:
                    jumps.append(target)
                if name:
                    LabelAddressPlus(newTarget, name, *args, **kwargs)
                while skipNops and isNop(newTarget):
                    newTarget = newTarget + IdaGetInsnLen(newTarget)
                    if not IsCode_(newTarget) and not EaseCode(newTarget, forceStart=1) and not IsCode_(newTarget):
                        printi("SkipJumps: Skipped NOPs right into a non-instruction: {:x} jumps".format(newTarget))
                        return return_jumps() if returnJumps else -1
                    # XXX: let over from where we called iteratee at this point
                    #  if rv and isInt(rv) and rv > 1:
                        #  newTarget = rv
                targets.append(newTarget)
                target = newTarget
                if skipObfu:
                    _obfuJump = isObfuJmp(target)
                continue
            break
        break

    if apply:
        skipped = len(jumps) - 1
        # for jmp in [ea] + jumps: # [1:-1]:
        if len(jumps) > 1:
            
            for jmp in jumps: # [1:-1]:
                # dprint("[SkipJumpsChunkTargetError] jmp")
                if idc.get_item_size(jmp) >= 5:
                    currentTarget = GetTarget(jmp)
                    
                    if currentTarget != targets[-1]:
                        stmt = "{} 0x{:x}".format(mnem_start if mnem_start and jmp == ea else "jmp", targets[-1])
                        printi("iassemble1(0x{:x}, '{}')".format(jmp, stmt))
                        prevInsnLen = InsnLen(jmp)
                        assembled = iassemble(jmp, stmt, apply=1)
                        Commenter(jmp, 'line').add('SkipJumps: {}'.format(hex(targets)))
                        if len(assembled) < prevInsnLen:
                            PatchNops(jmp + len(assembled), prevInsnLen - len(assembled), "SkipJumps: {}".format(hex(targets)))

            # dprint("[SkipJumps] jumps, targets")
            # print("[SkipJumps] ea: {}, jumps: {}, targets: {}".format(hex(ea), hex(jumps), hex(targets)))
            
            Commenter(jumps[-1], 'line').add('SkipJumps from jumps: {}'.format(hex(targets)))
            Commenter(targets[-1], 'line').add('SkipJumps from targets: {}'.format(hex(targets)))

            if not skipConditionals and isRet(targets[-1]):
                # raise RuntimeError("boo2 @ {:x}".format(targets[-1]))
                prevInsnLen = InsnLen(ea)
                PatchBytes(ea, "c3", "jmp locret")
                PatchNops(ea + 1, prevInsnLen - 1)
                if GetChunkEnd(ea) == ea + prevInsnLen:
                    SetFuncEnd(ea, ea + 1)

    processIterateeQueue(iterateeQueue, 'end', *args, **kwargs)
    # dprint("[SkipJumpsChunkTargetError] jumps, targets")
    #  print("[SkipJumpsChunkTargetError] jumps:{}, targets:{}".format(hex(jumps), hex(targets)))
        
    return return_jumps() if returnJumps else target

def FuncSkipJumps(funcea=None):
    """
    FuncSkipJumps

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncSkipJumps(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea
    
    loop = -1
    while True:
        loop += 1
        changed = 0
        
        for ea in GetFuncHeads(funcea):
            # dprint("[FuncSkipJumps] ea")
            #  print("[FuncSkipJumps] ea:{}".format(hex(ea)))
            
            if not loop:
                if SkipJumps(ea, apply=1) not in (ea, GetTarget(ea)):
                    changed += 1
            if idc.get_operand_type(ea, 1) == idc.o_mem and IsCode_(idc.get_operand_value(ea, 1)):
                retrace(idc.get_operand_value(ea, 1))
            elif isCall(ea):
                retrace(ea)
            if SkipJumps(ea, apply=1) not in (ea, GetTarget(ea)):
                changed += 1
        if not changed:
            break


def CountConsecutiveMnem(ea, mnem, sameChunk=False):
    ori_ea = ea
    insn_count = 0
    mnem = A(mnem)
    insn_lens = 0
    insn_len = 0
    cstart = GetChunkStart(ea)
    if sameChunk and cstart == idc.BADADDR:
        return (0, 0, 'no_chunk_start')
    while IdaGetMnem(ea) in mnem and (not sameChunk or GetChunkStart(ea) == cstart):
        insn_lens += insn_len
        insn_count += 1
        insn_len = IdaGetInsnLen(ea)
        ea += insn_len
        if IsCode_(ea) and IsFlow(ea): continue
        break
    return (insn_count, ea, insn_lens)


@static_vars(break_after={}, break_before={}, skip={}, no_count={})
def AdvanceToMnem(ea, mnem=None, count=pow(8,8), include=False, addrs=None, visited=None, rules=None, ignoreInt=False, skipNops=False):
    if addrs is None:
        addrs = []
    if visited is None:
        visited = set()
    if rules is None:
        rules = []
    
    ori_ea = ea
    insn_count = 0
    if mnem is not None:
        mnem = A(mnem)
    while insn_count < count:
        insn_mnem = IdaGetMnem(ea)
        if mnem and not include and IsCode_(ea) and insn_mnem in mnem:
            break
        if ea in visited:
            if debug: print('AdvanceToMnem already visited {:#x}'.format(ea))
            break

        if not IsCode_(ea):
            EaseCode(ea, forceStart=1)
            if not IsCode_(ea):
                print(TypeError("!IsCode({:#x}) starting from {:#x}".format(ea, ori_ea)))
                break


        visited.add(ea)
        addrs.append(ea)
        insn_count += 1

        for condition, action in rules:
            # dprint("[AdvanceToMnem] condition, action")
            # print("[AdvanceToMnem] condition:{}, action:{}".format(condition, action))
            
            if condition(ea):
                res = _.last(action(ea)) if callable(action) else action
                if isinstance(res, int) and IsValidEA(res):
                    ea = res
                    continue
                if res is AdvanceToMnem.break_after:
                    break
                if res is AdvanceToMnem.break_before:
                    # cheat
                    visited.remove(ea)
                    addrs.pop()
                    insn_count -= 1
                    break
                if res is AdvanceToMnem.skip:
                    ea = idc.next_not_tail(ea)
                    insn_count -= 1
                    continue
                if res is AdvanceToMnem.no_count:
                    insn_count -= 1
                elif res is None:
                    pass
                else:
                    raise TypeError("Unable to handle action result type '{}'".format(type(res)))
            #  else:
                #  print("condition({:#x}) return non-True".format(ea))

        if (insn_match(ea, idaapi.NN_retn, comment='retn')
                or insn_match(ea, idaapi.NN_jmpni, (idc.o_displ, None), comment='jmp qword [reg+0x28]')
                or insn_match(ea, idaapi.NN_jmpni, (idc.o_mem, 5), comment='jmp qword [rel UnhandledExceptionFilter]')
                or insn_match(ea, idaapi.NN_jmpni, (idc.o_phrase, None), comment='jmp qword [rax+r8*8]')
                or insn_match(ea, idaapi.NN_jmpni, (idc.o_reg, 0), comment='jmp rax')
                or not ignoreInt and (
                    insn_match(ea, idaapi.NN_int3, comment='int 3') or 
                    insn_match(ea, idaapi.NN_ud2,  comment='ud2'))
                ):
            break

        if mnem and include and IsCode_(ea) and insn_mnem in mnem:
            GetDisasm(idc.next_not_tail(ea))
            ea = idc.next_not_tail(ea)
            break



        if isUnconditionalJmp(ea):
            ea = GetTarget(ea)
        else:
            ea1 = ea + IdaGetInsnLen(ea)
            ea2 = idc.next_not_tail(ea)
            if ea1 != ea2:
                ea1 = ea + IdaGetInsnLen(ea)
                ea2 = idc.next_not_tail(ea)
                if ea1 != ea2:
                    pph(addrs)
                    RuntimeError("ea1(InsnLen) != ea2(NextNotTail) {:#x} != {:#x} (ea: {:#x}, ori_ea: {:#x})".format(ea1, ea2, ea, ori_ea))
            ea = ea1
        # if IsCode_(ea) and IsFlow(ea): continue
    #  if ori_ea ==  0x14383FADA:
        #  # dprint("[AdvanceToMnem] di(ori_ea, ea)")
        #  print("[AdvanceToMnem] {}".format(di(ori_ea, ea)))
        #  raise RuntimeError("DEBUG")
        
    return (insn_count, ea, get_name_by_any(ea))
    # return SimpleAttrDict(_.object(('count', 'ea', 'name'), (calls, ea, get_name_by_any(ea))))

def OldAdvanceToMnemEx(ea, term='retn', iteratee=None, **kwargs):
    start_ea = ea
    insn_count = 1
    byte_count = 0
    insns = []
    private = SimpleAttrDict()
    opt = SimpleAttrDict(kwargs)
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
            if debug: printi('ease option, calling easecode')
            EaseCode(ea, forceStart=1, noExcept=1)
        while ea not in visited and IsCode_(ea) and (IsFlow(ea) or ignore_flow):
            label = ''
            visited.add(ea)
            insn = diida(ea)
            mnem = diida(ea, mnemOnly=1)
            size = IdaGetInsnLen(ea)
            is_call = isCall(ea) and idc.get_wide_byte(ea) == 0xe8 and idc.get_operand_type(ea, 0) not in (o_displ, 2)
            is_follow_call = is_call and getattr(opt, 'follow_calls', 0) and GetTarget(ea, flow=0, calls=1) != idc.BADADDR
            is_any_jmp = isAnyJmp(ea) and idc.get_operand_type(ea, 0) not in (o_displ, 2)
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
                next_insn = ea + IdaGetInsnLen(ea)
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
                        printi('{:x} not head'.format(ea))
                    raise RuntimeError('{:x} somehow next_insn > next_head {:x} != {:x}'.format(ea, next_insn, next_head))

            if next_insn != next_head:
                raise RuntimeError('{:x} {:x} next_insn != next_head {:x} != {:x}'.format(start_ea, ea, next_insn, next_head))

            is_next_flow = next_insn and IsFlow(next_insn)

            if iteratee:
                response = \
                    iteratee(SimpleAttrDict({'label': label,
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
                    if debug: printi('ease option, calling easecode')
                    EaseCode(ea)
                ignore_flow = 1
                continue

            if target and is_any_jmp:
                if is_unc_jmp:
                    ea = target
                    if getattr(opt, 'ease', 0):
                        if debug: printi('ease option, calling easecode')
                        EaseCode(ea, forceStart=1)
                    ignore_flow = 1
                    continue
                else:
                    pending.add(target)

            ea += size
            if final_loop:
                break

    # dprint("[flow] flow_refs_to")
    #  printi("[flow] flow_refs_to:{}".format(flow_refs_to))
        
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
        printi(unvisited_str)
        insns.append("; {}".format(unvisited_str))

    return SimpleAttrDict({
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
  
    printi("ranging results")
    rx = GenericRanger([GenericRange(x[0], last=x[1]) for x in r], sort=1, outsort=1)
    pp(rx[-100:])
    printi("saving... {} ranges".format(len(rx)))
    json_save_safe('e:/git/ida/2245-native-remove-2.json', [(x.start-ida_ida.cvar.inf.min_ea, x.trend-x.start-ida_ida.cvar.inf.min_ea) for x in rx])
    ## j = json_load('e:/git/ida/2245-native-remove.json')

    # rx = [(0x140ca4486, 0xc), (0x140caeeb2, 0xc), (0x140cb1d41, 0x16), (0x140cb6b2e, 0xc), (0x140cd0085, 0xc), (0x140cf4ff1, 0xc), (0x140cfab1a, 0xc), (0x140d0e1b4, 0x5), (0x140d0e1bf, 0xb), (0x140d0e1d5, 0x17), (0x140d0e1f7, 0x17), (0x140d0e219, 0x17), (0x140d0e23b, 0x17), (0x140d0e25d, 0x17), (0x140d0e27f, 0x17), (0x140d0e2a1, 0x17), (0x140d0e2c3, 0x17), (0x140d0e2e5, 0x17), (0x140d0e307, 0x17), (0x140d0e329, 0x17), (0x140d0e34b, 0x17), (0x140d0e36d, 0x17), (0x140d0e38f, 0x17), (0x140d0e3b1, 0x17), (0x140d0e3d3, 0x17), (0x140d0e3f5, 0x17), (0x140d0e417, 0x17), (0x140d0e439, 0x17), (0x140d0e45b, 0x17), (0x140d0e47d, 0x17), (0x140d0e49f, 0x17), (0x140d0e4c1, 0x17), (0x140d0e4e3, 0x17), (0x140d0e505, 0x17), (0x140d0e527, 0x17), (0x140d0e549, 0x17), (0x140d0e56b, 0x17), (0x140d0e58d, 0x17), (0x140d0e5af, 0x17), (0x140d0e5d1, 0x17), (0x140d0e5f3, 0x17), (0x140d0e615, 0x17), (0x140d0e637, 0x17), (0x140d0e659, 0x17), (0x140d0e67b, 0x17), (0x140d0e69d, 0x17), (0x140d0e6bf, 0x17), (0x140d0e6e1, 0x17), (0x140d0e703, 0x17), (0x140d0e725, 0x17), (0x140d0e747, 0x17), (0x140d0e769, 0x17), (0x140d0e78b, 0x17), (0x140d0e7ad, 0x17), (0x140d0e7cf, 0x17), (0x140d0e7f1, 0x17), (0x140d0e813, 0x17), (0x140d0e835, 0x17), (0x140d0e857, 0x17), (0x140d0e879, 0x17), (0x140d0e89b, 0x17), (0x140d0e8bd, 0x17), (0x140d0e8df, 0x17), (0x140d0e901, 0x17), (0x140d0e923, 0x17), (0x140d0e945, 0x17), (0x140d0e967, 0x17), (0x140d0e989, 0x17), (0x140d0e9ab, 0x17), (0x140d0e9cd, 0x17), (0x140d0e9ef, 0x17), (0x140d0ea11, 0x17), (0x140d0ea33, 0x17), (0x140d0ea55, 0x17), (0x140d0ea77, 0x17), (0x140d0ea99, 0x17), (0x140d0eabb, 0x17), (0x140d0eadd, 0x17), (0x140d0eaff, 0x17), (0x140d0eb21, 0x17), (0x140d0eb43, 0x17), (0x140d0eb65, 0x17), (0x140d0eb87, 0x17), (0x140d0eba9, 0x17), (0x140d0ebcb, 0x17), (0x140d0ebed, 0x17), (0x140d0ec0f, 0x17), (0x140d0ec31, 0x17), (0x140d0ec53, 0x17), (0x140d0ec75, 0x17), (0x140d0ec97, 0x17), (0x140d0ecb9, 0x17), (0x140d0ecdb, 0x17), (0x140d0ecfd, 0x17), (0x140d0ed1f, 0x17), (0x140d0ed41, 0x17), (0x140d0ed63, 0x17), (0x140d0ed85, 0x17), (0x140d0eda7, 0x17), (0x140d0edc9, 0x17), (0x140d0edeb, 0x17), (0x140d0ee0d, 0x17), (0x140d0ee2f, 0x17), (0x140d388e1, 0xc), (0x140d3b989, 0x16), (0x140d3beb1, 0xc), (0x14105a02e, 0xc), (0x14106fdf5, 0xc), (0x1413dd9b3, 0x16), (0x1417f9be4, 0xc), (0x141805414, 0xc), (0x141807dd4, 0xc), (0x141814e2e, 0xc), (0x14184707b, 0xc), (0x141847cf1, 0xc), (0x14184ceaa, 0xc), (0x14184d9ec, 0x16), (0x141858afb, 0xc), (0x14185918b, 0x16), (0x141859d81, 0xc), (0x141859feb, 0xc), (0x14185b8ea, 0x16), (0x14185c951, 0xc), (0x14185d994, 0x16), (0x14185ea03, 0xc), (0x141862f55, 0x16), (0x14186500e, 0x16), (0x14186654f, 0xc), (0x141868fbc, 0x16), (0x141868fdd, 0xc), (0x141869a0a, 0x16), (0x14186d61c, 0x16), (0x14186d6a8, 0x16), (0x14187002e, 0x16), (0x141870a78, 0x16), (0x141873386, 0x16), (0x1418743eb, 0x16), (0x141876aa4, 0xc), (0x141876ec7, 0xc), (0x141879add, 0xc), (0x14187c147, 0xc), (0x1418807b2, 0x16), (0x141888708, 0x16), (0x1430f0b11, 0x16), (0x1430f225f, 0x16), (0x1430fc19c, 0x16), (0x1432b633a, 0x16), (0x1432b8253, 0x16), (0x1432b95e1, 0x16), (0x1432c4224, 0x16), (0x1432c9831, 0x16), (0x1432cbbb2, 0x16), (0x1432ce58a, 0x16), (0x1432cecd4, 0x16), (0x1432d25db, 0x16), (0x1432d2dc7, 0x16), (0x1432e1584, 0x16), (0x1432e1dee, 0x16), (0x1432e2a5c, 0x16), (0x1432e470c, 0x16), (0x1432e4b20, 0xc), (0x1432e517f, 0x16), (0x1434a61a4, 0x16), (0x1434c6811, 0xc), (0x1434caced, 0xc), (0x1434da779, 0x16), (0x1434df64b, 0x16), (0x1434f5eac, 0xc), (0x1434f63f5, 0xc), (0x1434f7a28, 0x16), (0x1434fcab4, 0xc), (0x143500c96, 0xc), (0x14351b52b, 0x16), (0x14351d5b4, 0xc), (0x143586ac1, 0x16), (0x14358ebae, 0x16), (0x143594191, 0xc), (0x143594f5b, 0x10), (0x1435a70b7, 0x16), (0x143612c2d, 0xc), (0x14361d5e4, 0xc), (0x143625ce5, 0xc), (0x14362b27a, 0x16), (0x14363eb5d, 0xc), (0x14363fde5, 0x16), (0x143855cc5, 0xc), (0x14385c40b, 0x16), (0x14385ce05, 0x16), (0x1438ccb7c, 0x16), (0x1438e9eda, 0xc), (0x1438ed62a, 0xc), (0x1438fbf0c, 0x16), (0x1438fda30, 0x16), (0x1438fefb0, 0xc), (0x14390c3c6, 0xc), (0x14397585f, 0xc), (0x14398cda4, 0x16), (0x143991691, 0xc), (0x1439ba6ad, 0xc), (0x1439c0317, 0x16), (0x1439c162b, 0xc), (0x143e66857, 0xc), (0x143e6a800, 0x16), (0x143e6aaba, 0xc), (0x143e6f1c9, 0xc), (0x143e89f04, 0x16), (0x143e8b285, 0xc), (0x143e8ffba, 0x16), (0x143e91637, 0x16), (0x143e91e82, 0xc), (0x143e97978, 0x16), (0x143e99fdf, 0xc), (0x143e9e693, 0xc), (0x143ea5100, 0xc), (0x143ea8509, 0xc), (0x143eb4fe3, 0x16), (0x143edc5ac, 0xc), (0x143edefdf, 0x16), (0x143ee0251, 0x16), (0x143ee2eb9, 0xc), (0x143ee35eb, 0xc), (0x143ee37e0, 0xc), (0x143ee3885, 0xc), (0x143ee6930, 0x16), (0x143eee28a, 0x16), (0x143eee859, 0xc), (0x143ef0aa7, 0x16), (0x143efce87, 0x16), (0x143efd56f, 0x16), (0x143f5ad21, 0xc), (0x143f5ec13, 0xc), (0x143f60dad, 0x16), (0x143f6160f, 0xc), (0x143f7420e, 0x16), (0x143f7d1db, 0x16), (0x143fa0acc, 0x16), (0x143fa6e47, 0xc), (0x143fabdfa, 0xc), (0x143fee656, 0x16), (0x143fefd23, 0xc), (0x143ffa264, 0x16), (0x143fff6b0, 0x16), (0x14400332a, 0x16), (0x144007c1d, 0xc), (0x144009070, 0xc), (0x14401606d, 0x16), (0x14402b442, 0x16), (0x144037e3d, 0xc), (0x1440394f8, 0xc), (0x14403c479, 0x18), (0x14404a0f7, 0xc), (0x14405c80e, 0xc), (0x14408adec, 0xc), (0x144097fd4, 0x16), (0x14409aba5, 0x16), (0x14409fdd7, 0xc), (0x1440a6d6d, 0x16), (0x1440b0f96, 0xc), (0x1440b6463, 0xc), (0x1440c108b, 0xc), (0x1440c14e7, 0xc), (0x1440cc8a9, 0xc), (0x1440edbf1, 0xc), (0x1440eeca5, 0x16), (0x1445a1983, 0x16), (0x1445df4cd, 0x16), (0x1445e01f2, 0x16), (0x1445e646c, 0xc), (0x1447dd8a2, 0x16), (0x1449d5fec, 0x16), (0x1449dc8c1, 0x16), (0x1449dfcb4, 0xc), (0x1449e0054, 0x16), (0x144a67d2e, 0xc), (0x144a69345, 0x16), (0x144a7fad4, 0xc), (0x144afd832, 0x16), (0x144b059f6, 0x16), (0x144b09191, 0x16), (0x144b0d550, 0xc), (0x144b108cb, 0x16), (0x144b27534, 0x16), (0x144b39628, 0xc), (0x144b3bc25, 0x16), (0x144b5e759, 0xc)]
    # printi("deleting funcs")
    count = 0
    printi("deleting items")
    pp(r[-100:])
    #  for r in j:
        #  start, _len = r
        #  _len = ida_ida.cvar.inf.min_ea - ~_len
        #  _len -= 1
        #  count += _len
        #  start += ida_ida.cvar.inf.min_ea
    for r in rx:
        start = r.start
        end = r.trend
        _len = end - start
        MakeUnknown(start, _len, DELIT_EXPAND | DELIT_NOTRUNC)
        #  ida_bytes.put_bytes(start, b'\xcc' * _len)
        MakeUnknown(r.start, r.trend - r.start, DELIT_EXPAND | DELIT_NOTRUNC)
        idc.del_func(get_start(r))
        ida_bytes.put_bytes(get_start(r), b'\xcc' * (get_last(r) - get_start(r)))
        for ea in range(start, start + _len):
            idc.set_color(ea, idc.CIC_ITEM, 0x111606)
    #  for r in rx:
        #  printi(r[0], 0, r[1] - r[0])
        # idc.del_items(r[0], 0, r[1] - r[0])
    printi("deleted {}".format(count))

def MutatorCombinations():
    letters = ['A', 'B', 'C', 'D']
    for i in itertools.permutations(letters):
        l = list(i)
        o = SimpleAttrDict()
        for r in range(4):
            o[l[r]] = r
        if o.B > o.A and o.D > o.C and o.D > o.B:
            printi(o)


def hexf16(n):
    if isinstance(n, str):
        return "{:>16}".format(n)
    return "{:16x}".format(n)

def h16list(l):
    return " ".join([hexf16(x) for x in l])

def find_element_in_list(element, list_element):
    try:
        index_element = list_element.index(element)
        return index_element
    except ValueError:
        return None

def fixCallAndJmpObfu(func=None):
    if func is None:
        func = obfu.patch
    for ea in FindInSegments("48 89 6c 24 f8 48 8d 64 24 f8 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 e9 ?? ?? ?? ??"):
        for r in range(3):
            obfu.patch(ea)
    for ea in FindInSegments("48 8d 64 24 f8 48 89 2c 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 e9 ?? ?? ?? ??"):
        for r in range(2):
            obfu.patch(ea)
    for ea in FindInSegments("48 8D 64 24 F8 48 89 2C 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3"):
        for r in range(2):
            obfu.patch(ea)
    for ea in FindInSegments("48 89 6c 24 f8 48 8d 64 24 f8 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3"):
        for r in range(3):
            obfu.patch(ea)

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
    printi(("SetSped adjustment: 0x%x" % adjustment))
    idc.add_user_stkpnt(ea, adjustment)


sub_colors = dict()


def colorSubs(subs, colors=None, primary=None):
    colors = A(colors)
    primary = A(primary)
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

def is_in_later2(ea, **kwargs):
    if kwargs.get('noLater', 0):
        return False
    return ea in later2


def ida_retrace_patch(chunkStart, chunkEnd=None, addressHistory=None, patchedAddresses=None, **kwargs):
    count = 0
    if kwargs.get('noObfu', 0):
        return 0
    if chunkEnd is None:
        chunkEnd = GetChunkEnd(chunkStart)
    if patchedAddresses is None:
        patchedAddresses = set()
    addressHistory = A(addressHistory)
    lastAddress = False
    if chunkEnd > chunkStart and IsValidEA((chunkStart, chunkEnd)) and chunkEnd - chunkStart < 8192:
        reflow = True
        while reflow:
            reflow = False
            addrs = list(idautils.Heads(chunkStart, chunkEnd))
            if lastAddress == False:
                lastAddress = _.last(addrs)
            for ea in addrs:
                if isJmp(ea) or isCall(ea) or isNop(ea):
                    continue
                try:
                    # TODO: have patch alter our queue/visited addresses 
                    patches = []
                    tmp = obfu.patch(ea)
                    while tmp:
                        patches.extend(A(tmp))
                        obfu.combed.clear()
                        tmp = obfu.patch(ea)
                    
                    for p in patches:
                        count += 1
                        patchedAddresses.update(deep_get(p, 'result.result.patchedAddresses', set()))
                        #  for addr in deep_get(p, 'result.result.patchedAddresses', set()):
                            #  addressHistory.remove(addr)

                        #  if deep_get(p, 'pat.options.reflow', '') == 'reflow':
                            #  reflow = True
                except TypeError as e:
                    print('[Exception] {}: {}'.format(e.__class__.__name__, str(e)))

                #  if ea == lastAddress and count:
                    #  lastAddress = True
                    #  reflow = True
                    #  idc.auto_wait()


    return count

def ida_retrace_advance(start, queue, queue2, call_queue, visited, **kwargs):
    new_addrs = []
    def queueAppendTarget(q, ea):
        target = GetTarget(ea)
        if target in visited or target in queue or target in queue2:
            if debug: print("{:#x} already in a queue".format(target))
        else:
            q.append((target, EaseCode(target, forceStart=1, noExcept=1)))

    end = AdvanceToMnem(start, mnem='jmp', include=True, addrs=new_addrs, visited=visited, rules=[
        (
            lambda ea: insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_143A8E11B'),
            lambda ea: queueAppendTarget(queue, ea)
        ),
        (
            isConditionalJmp,
            lambda ea: queueAppendTarget(queue2, ea)
        ),
        (
            lambda ea: insn_match(ea, idaapi.NN_call, (idc.o_near, 0), comment='call sub_140CA5095'),
            lambda ea: queueAppendTarget(call_queue, ea)
        ),
        ],
        **(_.pick(kwargs, 'ignoreInt'))

        )
    return new_addrs, end[1]

def ida_retrace_extend(ea, addrs=None, visited=None, call_queue=None, block_count=None, **kwargs):
    addrs = A(addrs)
    call_queue = A(call_queue)
    if visited is None:
        visited = set()
    patch_queue = []
    ignoreInt = ignoreInt=kwargs.get('ignoreInt', 0)
    noLater = kwargs.get('noLater', 0)
    chunk_starts = [ea]
    #  r = func_tails(ea, quiet=1, returnErrorObjects=1, ignoreInt=ignoreInt)
    #  if debug: print("{} issues...".format(len(r)))
    #  if not r:
        #  if debug: print("{} issues... returning".format(len(r)))
        #  return
    revisit = set()
    if isInt(ea):
        queue = [(ea, EaseCode(ea, forceStart=1))]
    elif _.isTuple(ea):
        queue = [ea]
        ea = ea[0]
    
    queue2 = []
    addressHistory = CircularList(40)

    # conditional jmp queue
    #  for x in r:
        #  if isinstance(x, FuncTailsJump): 
            #  # frm = x.frm
            #  # dprint("[ida_retrace] x.to.ea")
            #  if debug: print("[ida_retrace] x.to.ea:{:#x}".format(x.to.ea))
            #  queue.append(x.to.ea)
    count = 0
    did_chunk_starts = False
    while queue or queue2 or chunk_starts and not did_chunk_starts and not kwargs.get('noObfu', 0):
        if block_count is not None:
            block_count += 1
        if not queue:
            if queue2:
                # printi("swapping queue and queue2")
                # queue, queue2 = queue2, queue
                queue.append(queue2.pop(0))
            elif chunk_starts and not did_chunk_starts and kwargs.get('noObfu', 0):
                for first in _.reverse(chunk_starts):
                    end = EaseCode(first)
                    queue.append((first, end))
                    revisit.add(first)
                #  print('queue empty')
                #  for first, end in _.reverse(patch_queue):
                    #  patches = ida_retrace_patch(first, end, **kwargs)
                    #  if patches:
                        #  # dprint("[ida_retrace_extend] patches")
                        #  print("[ida_retrace_extend] queue_patches:{}".format(patches))
                        #  end = EaseCode(first)
                        #  queue.append((first, end))
                        #  revisit.add(first)
                #  patch_queue.clear()
            if not queue:
                break

        # print("{}, {}, {}, {:#x}".format(len(queue), len(queue2), len(patch_queue))
        count += 1
        start, *a = queue.pop(0)
        if not IsValidEA(start):
            continue
        if start in visited:
            if start in revisit:
                revisit.remove(start)
            else:
                print("[ida_retrace] already visited: hex(start):{}".format(hex(start)))
                continue
        if count > 1 and not kwargs.get('ignoreChunks', 0) and IsFunc_(start): #  and not ida_funcs.is_same_func(start, funcea):
            if not ida_funcs.is_same_func(ea, start) and kwargs.get('forceRemoveFuncs', 0):
                RemoveChunk(start)
            else:
                print("[ida_retrace] {:#x} chunk-start owned by us/other func; us? {}".format(start, ida_funcs.is_same_func(ea, start)))
                continue
        if a:
            end = a[0]
        else:
            end = EaseCode(start, forceStart=True, ignoreInt=ignoreInt)
        if debug: print("[ida_retrace] from queue: {} - {}".format(ahex(start), ahex(end)))
        # if _.any(NotTails(start, end), lambda ea, *a: IsFunc_(ea) and not ida_funcs.is_same_func(ea, funcea)):
        try:
            if not kwargs.get('ignoreChunks', 0) and \
                    _.any(list(NotTails(start, end)), lambda addr, *a: IsFunc_(addr) and not ida_funcs.is_same_func(ea, addr)):
                print("[ida_retrace] {:#x}-{:#x} chunk-part owned by func other than {:#x}".format(start, end, ea))
                continue
        except TypeError:
            # dprint("[ida_retrace_extend] ea, addr")
            print("[ida_retrace_extend] ea:{} iter:{}".format(ea, list(NotTails(start, end))))
            raise
            

        new_visited = set() # visited.copy()
        new_addrs, end = ida_retrace_advance(start, queue, queue2, call_queue, new_visited, ignoreInt=ignoreInt)
        # dprint("[debug] queue")
        if debug: print("[debug] queue:{}".format(ahex(queue)))
        
        visited.update(new_visited)
        addressHistory.extend(new_addrs)
        if debug:
            # dprint("[ida_retrace_extend] new_addrs")
            print("[ida_retrace_extend] advance: new_addrs:{}".format(hex(new_addrs)))
            


        first = _.firstOr(new_addrs, 0)
        
        if first: #  and first not in visited:
            #  if first in visited:
                #  print('[ida_retrace_extend] old first: {}'.format(ahex(first)))

            # dprint("[ida_retrace_extend] first")
            if debug: print("[ida_retrace_extend] first:{}".format(hex(first)))
                
            chunk_starts.append(first)
            # addrs.extend(new_addrs)

            #  end = idc.next_not_tail(_.last(new_addrs))
            patchedAddresses = set()
            patches = 0
            tmp = ida_retrace_patch(first, end, addressHistory=addressHistory, patchedAddresses=patchedAddresses, **kwargs)
            while tmp:
                patches += tmp
                tmp = ida_retrace_patch(first, end, addressHistory=addressHistory, patchedAddresses=patchedAddresses, **kwargs)

            #  later2.difference_update(patchedAddresses)
            #  later.difference_update(patchedAddresses)

            if False and patches:
                if True:
                    rcount = 0
                    src = len(chunk_starts)
                    if not src:
                        dst = 0
                    else:
                        dst = src - 1
                        while dst and rcount < 16:
                            count = AdvanceToMnem(chunk_starts[dst], mnem='jmp', include=True, rules=[
                                    (
                                        isUnconditionalJmp,
                                        AdvanceToMnem.no_count
                                    ),
                                    (
                                        isNop,
                                        AdvanceToMnem.no_count
                                    ),
                            ])[0]
                            # dprint("[ida_retrace_extend] count, dst")
                            # print("[ida_retrace_extend] count:{}, dst:{}".format(count, dst))
                            dst = dst - 1
                            rcount += count
                    

                    # dst = len(chunk_starts) - 8
                    # if dst < 0: dst = 0
                    if block_count is not None:
                        print('***FOUND*** {} {}'.format(block_count, ahex(chunk_starts[dst])))
                    print('***CONTINUE*** {} {}'.format(src - dst, ahex(chunk_starts[dst])))
                    _blocks = [Block(x) for x in patchedAddresses.union(addressHistory) if IsCode_(x)]
                    blockRanges = GenericRanger(_blocks, sort = 1)
                    blockRangesExpanded = _.reduce(blockRanges, lambda memo, value, index: memo + list(value), [])
                    visited.difference_update(list(blockRangesExpanded))
                    done2.difference_update(list(blockRangesExpanded))
                    for _addr in chunk_starts[dst:]:
                        if _addr in visited:
                            visited.remove(_addr)
                    ida_retrace_extend(chunk_starts[dst], addrs=addrs, visited=visited, call_queue=call_queue, block_count=0, **kwargs)
                    return
                else:
                    _blocks = [Block(x) for x in patchedAddresses.union(addressHistory) if IsCode_(x)]
                    blockRanges = GenericRanger(_blocks, sort = 1)
                    # dprint("[ida_retrace_extend] blockRanges")
                    #  print("[ida_retrace_extend] blockRanges:{}".format(blockRanges))
                    blockRangesExpanded = _.reduce(blockRanges, lambda memo, value, index: memo + list(value), [])
                    #  if not noLater: 
                        #  later2.difference_update(list(blockRangesExpanded))
                        #  later.difference_update(list(blockRangesExpanded))
                    visited.difference_update(list(blockRangesExpanded))
                    done2.difference_update(list(blockRangesExpanded))

                    historyRanges = GenericRanger([Block(x) for x in addressHistory if IsCode_(x)], sort=1)
                    historyRangesExpanded = _.reduce(historyRanges, lambda memo, value, index: memo + [(value.start, value.trend)], [])
                    for _addr in historyRangesExpanded:
                        if _addr[0] not in patchedAddresses:
                            #  print("inserting {:#x}-{:#x}".format(_addr[0], _addr[1]))
                            queue.insert(0, _addr)
                # dprint("[ida_retrace_extend] queue")
                #  print("[ida_retrace_extend] queue:{}".format(ahex(queue)))
                continue
                
                
        elif not first:
            if debug: print('[ida_retrace_extend] no first: {}'.format(ahex(first)))

        visited.update(new_visited)


    if debug: print('cleaning up')
    for start in chunk_starts:
        start = _.first(start)
        for addr in idautils.Heads(start, EaseCode(start)):
            addrs.append(addr)


    # dprint("[ida_retrace_extend] addrs")
    if debug: print("done")
    #  print("[ida_retrace_extend] addrs:{}".format(hex(addrs)))
    


    
def ida_retrace(funcea=None, extend=True, zero=True, calls=False, smart=True, plan=False, *args, **kwargs):
    """
    ida_retrace

    @param funcea: any address in the function
    """
    # global global_chunks

    if False and isinstance(funcea, list):
        p = ProgressBar(len(funcea))
        n = 0
        for ea in funcea:
            n += 1
            p.update(n)
            ida_retrace(ea, extend=extend, zero=zero, smart=smart, *args, **kwargs)
        return

    queue = A(funcea)
    if not queue:
        queue = [eax(None)]
    funcea = eax(_.first(_.first(queue)))
    # dprint("[ida_retrace] funcea, _.first(queue)")
    print("[ida_retrace] funcea:{:#x}, _.first(queue):{:#x}".format(funcea, _.first(queue)))
    
    func = ida_funcs.get_func(funcea)

    if not func:
        funcea = funcea
    else:
        funcea = func.start_ea

    ea = funcea
    count = 0
    noLater = kwargs.get('noLater', 0)
    # gc = global_chunks[ea]
    # gc.update(idautils.Chunks(ea))
    # with InfAttr(idc.INF_AF, lambda v: v | 0):
    with InfAttr(idc.INF_AF, lambda v: v | (0xdfe67f1d if smart else 0)):
        # return ida_funcs.reanalyze_function(GetFunc(ea), *args)
        if not IsFunc_(funcea) and kwargs.get('func', 0):
            idc.add_func(funcea)
        if zero:
            rv = ZeroFunction(ea, **(_.pick(kwargs, 'total')))
            if debug: print("[ZeroFunction] returned {}".format(str(rv)))
        if extend:
            #  all_addrs = []
            while queue:
                ea = queue.pop(0)
                first_ea = _.first(ea)
                if first_ea in done2:
                    print('ida_retrace done2 {:#x}'.format(first_ea))
                    continue

                if first_ea in later:
                    later.remove(first_ea)
                #  if first_ea in visited:
                    #  print('ida_retrace visited {:#x}'.format(first_ea))
                    #  continue
                if first_ea in queue:
                    print('ida_retrace removing duplicate from queue')
                    queue.remove(first_ea)
                #  if is_in_later2(first_ea, **kwargs):
                    #  if debug: print('ida_retrace {:#x} in later2'.format(first_ea))
                    # continue
                if IsTail(first_ea):
                    print('ida_retrace {:#x} is tail'.format(first_ea))
                    continue
                print('ida_retrace ({}): {}'.format(len(queue), ean(first_ea)))
                addrs = []
                call_queue = []
                try:
                    rv = ida_retrace_extend(ea=ea, addrs=addrs, call_queue=call_queue, **kwargs)
                    if rv == -1:
                        queue.insert(0, ea)
                        continue

                    if debug: print('ida_retrace call_queue: {}'.format(hex(call_queue)))
                except AdvanceFailure as e:
                    print("{}: {}".format(e.__class__.__name__, str(e)))
                done2.add(first_ea)
                _removed = 0
                for addr in addrs:
                    if addr in queue:
                        _removed += 1
                        queue.remove(addr)
                    if not noLater: later2.add(addr)
                if _removed: print("removed {} items from queue".format(_removed))

                #  all_addrs.extend(addrs)
                if calls:
                    # dprint("[ida_retrace] call_queue")
                    # print("[ida_retrace] call_queue:{}".format(call_queue))
                    
                    if call_queue:
                        for r in call_queue:
                            addr = _.first(r)
                            if not is_in_later2(addr):
                                later2.add(addr)
                                later.add(addr)
                            if addr not in queue:
                                queue.append(r)
                                # dprint("[ida_retrace] queue")
                                #  print("[ida_retrace] queue:{}".format(queue))
                                

                if addrs and kwargs.get('func', 0):
                    # dprint("[ida_retrace] addrs")
                    if debug: print("[ida_retrace] addrs:{}".format(hex(addrs)))
                    
                    _chunks = [x for x in idautils.Chunks(ea)]
                    chunks = GenericRanger([GenericRange(x[0], trend=x[1])           for x in _chunks],            sort = 1)
                    keep = GenericRanger([GenericRange(a, trend=a + IdaGetInsnLen(a)) for a in addrs], sort = 1)
                    # remove = difference(chunks, keep)
                    add = difference(keep, chunks)
                    #  if keep or remove:
                        #  modify_chunks(ea, chunks, keep, remove)

                    setglobal('_keep', keep)
                    setglobal('_chunks', chunks)
                    setglobal('_remove', remove)
                    setglobal('_add', add)
                    if True:
                        
                        for cs, ce in [(x.start, x.trend) for x in add]:
                            # printi('append_func_tail({:#x}, {:#x}, {:#x})...'.format(ea, cs, ce))
                            if not idc.append_func_tail(ea, cs, ce):
                                printi('append_func_tail({:#x}, {:#x}, {:#x}) failed'.format(ea, cs, ce))
                            else: 
                                #  gc.add((cs, ce))
                                count += 1
                else:
                    pass
                    # dprint("[ida_retrace] addrs")
                    # print("[ida_retrace] addrs:{}".format(addrs))
                
                idc.msg("[{}]".format(count))
                idc.auto_wait()
        if plan:
            # for cs, ce in idautils.Chunks(ea): ida_auto.plan_and_wait(cs, ce)
            for cs, ce in idautils.Chunks(ea): 
                ida_auto.revert_ida_decisions(cs, ce)
                ida_auto.plan_range(cs, ce)
            ida_auto.auto_wait()



                    #  func = ida_funcs.func_t(to)
                    #  f = ida_funcs.find_func_bounds(func, FIND_FUNC_DEFINE | FIND_FUNC_IGNOREFN )
                    #  if f == ida_funcs.FIND_FUNC_OK:
                        #  if not idc.append_func_tail(ea, func.start_ea, func.end_ea):
                            #  printi('append_func_tail failed')
def BlockStart(ea=None):
    """
    BlockStart

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [BlockStart(x) for x in ea]

    ea = eax(ea)
    if not IsCode_(ea):
        return idc.BADADDR
    tmp = ea
    while IsCode(tmp):
        ea = tmp
        if not IsFlow(tmp):
            break
        tmp = idc.prev_not_tail(ea)

    return ea

def BlockEnd(ea=None):
    """
    BlockStart

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [BlockStart(x) for x in ea]

    ea = start_ea = eax(ea)
    if not IsCode_(ea):
        return idc.BADADDR
    while IsCode(ea) and (ea == start_ea or IsFlow(ea)):
        ea = idc.next_not_tail(ea)

    return ea


def Block(ea=None):
    """
    Block

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [Block(x) for x in ea]

    ea = eax(ea)
    return BlockStart(ea), BlockEnd(ea)





def FixThunks():
    # for ea in FunctionsMatching('sub_'):
    with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
        for ea in idautils.Functions():
            if isUnlikely(ea) and not HasUserName(ea) or ean(ea).startswith('_'):
                idc.del_func(ea)
            elif ea + IdaGetInsnLen(ea) < GetFuncEnd(ea):
                if insn_match(ea, (idaapi.NN_call, idaapi.NN_jmp), idc.o_near):
                    if not SetFuncEnd(ea, ea + IdaGetInsnLen(ea)):
                        GetDisasm(ea)
                        ZeroFunction(ea)
                #  mnem = IdaGetMnem(ea)
                #  if mnem and mnem.startswith('jmp'):
                    #  target = GetTarget(ea)
                    #  if not IsSameChunk(target, ea):
            elif isUnconditionalJmpOrCall(ea) and GetChunkCount(ea) > 1:
                RemoveAllChunks(ea)
                # ZeroFunction(ea)

TruncateThunks = FixThunks

def FixJmpLocRet():
    for ea in Heads(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea):
        if IsCode_(ea) and insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0)):
            target = GetTarget(ea)
            if insn_match(target, idaapi.NN_retn, comment='retn'):
                printi("fixing jmp locret at {:#x}".format(ea))
                SkipJumps(ea, apply=1)

chart2 = list()
colors = list()


def RecurseCallers(ea=None, width=512, data=0, makeChart=0, exe='dot', depth=5, iteratee=None, subsOnly=0, includeSubs=0, fixVtables=False, new=False, strata=False):
    global chart2
    global colors

    if isinstance(ea, list):
        return [RecurseCallers(x, width=width, data=data, makeChart=makeChart, exe=exe, depth=depth, subsOnly=subsOnly, includeSubs=includeSubs, fixVtables=fixVtables, new=new, strata=strata) for x in ea]

    if new:
        chart2.clear()
        colors.clear()
    if ea is None:
        ea = idc.get_screen_ea()
    fnName = idc.get_func_name(ea)
    callers = list()
    visited = set([])
    pending = defaultdict(set) # (A(ea))
    vtableRefs = list()
    _depth = 0
    count = 0
    added = [1]
    _datarefs = data
    functionRefs = collections.defaultdict(set)
    namedRefs = collections.defaultdict(set)
    fwd = defaultdict(list)
    rev = defaultdict(list)
    iteratee_results = []
    depthlist = defaultdict(list)
    chart = list()
    pending[_depth] |= set([ea])

    while _depth < depth:
        while len(pending[_depth]):
            if len(depthlist[_depth]) > width:
                printi(("0x%x: Leaving this depth, too many processed: %d pending: %d (depth: %d, width: %d)" % (ea, len(depthlist[_depth]), len(pending[_depth]), _depth, width)))
                _depth += 1
                continue

            #  _depth = _depth - 1
            ea = pending[_depth].pop()
            count += 1
                #  printi("_depth: %d count: %d" % (_depth, count))
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
            if _datarefs or _depth == 0 and IsData(target):
                refs.extend([x for x in idautils.DataRefsTo(target) if idc.get_segm_name(x) == '.text'])
                #  _datarefs = 0

            rdata_refs = [x for x in xrefs_to(target) if SegName(x) == '.rdata']
            refs.extend(rdata_refs)

            extra_refs = set([])
            for ref in refs:

                if callable(iteratee):
                    ir = iteratee(ref)
                    if ir is not None:
                        iteratee_results.append(ir)
                refName = "0x%x" % ref
                if Name(ref):
                    refName = Name(ref)
                if GetFunctionName(ref):
                    refName = GetFunctionName(ref)
                if SegName(ref) == '.rdata':
                    addr = ref
                    flags = idc.get_full_flags(addr)

                    _name_demang     = idc.get_name(addr, GN_DEMANGLED)
                    _disasm          = idc.GetDisasm(addr)
                    _ptr_name_raw    = idc.get_name(getptr(addr), 0)
                    _ptr_name_demang = idc.get_name(getptr(addr), GN_DEMANGLED)
                    _ptr_name_color  = idc.get_name(getptr(addr), GN_COLORED)


                    while IsOff0(addr):
                        if HasAnyName(addr) and idc.get_name(addr, GN_DEMANGLED).endswith("`vftable'"):
                            refName = idc.demangle_name(idc.get_name(addr, 0), DEMNAM_FIRST)
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
                            
                            break

                        addr = idc.prev_head(addr)

                #  refName = "{};;{}".format(refName, _depth)
                rev[targetName].append(refName)
                depthlist[_depth].append(refName)
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
            pending[_depth + 1] |= refs
            
            
        printi(("0x%x: processed: %d pending: %d (depth: %d, width: %d)" % (ea, len(depthlist[_depth]), len(pending[_depth]), _depth, width)))
        _depth += 1

    chart.sort()
    for (left, right) in _.uniq(chart, 1):
        if debug: printi(("left: {}, right: {}".format(left, right)))
        chart2.append([left, right])
        continue

        #  visited = set()
        #  if not includeSubs:
            #  while (right.startswith("loc_") or right.startswith("sub_")) and right in fwd and right != fwd[right]:
                #  right = fwd[right]
                #  if right in visited:
                    #  break
                #  visited.add(right)
                #  if debug: printi(("right: %s" % right))
        #  else:
            #  while IsChunked(get_name_ea_simple(right)):
                #  right = fwd[right]
                #  if right in visited:
                    #  break
                #  visited.add(right)
                #  if debug: printi(("right: %s" % right))
  
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
                #  if debug: printi(("left: %s" % left))


    if len(chart2):
        #  chart2 = _(chart2).chain().sort().uniq(1).value()
        chart2 = list([x for x in chart2 if x[0] != x[1]])
        if subsOnly:
            chart2 = list([x for x in chart2 if IsFunc_(x[0]) and IsFunc_(x[1]) and not IsSameFunc(x[0], x[1])])
        #  pp(chart2)

    subs = []
    call_list = []

    nodes = dict()

    for x in chart2:
        left = x[0]
        right = x[1]
        ea = eax(left)
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
        """
        left: sub_1418319BC, right: sub_141830FC0
        left: sub_141831B2C, right: sub_141830FC0
        left: sub_141831CF0, right: sub_141830FC0
        """
        if False:
            if right not in nodes:
                nodes[right] = Node(right)
            if left not in nodes:
                nodes[left] = Node(left, parent=nodes[right])
            elif not nodes[left].parent:
                nodes[left].parent = nodes[right]

        if len(x) > 2:
            call_list.append('"{}" -> "{}" {};'.format(x[0], x[1], " ".join(x[2:])))
        else:
            call_list.append('"{}" -> "{}";'.format(x[0], x[1]))
    call_list = _(call_list).chain().sort().uniq(1).value()
    colors = colorSubs(subs, colors, [fnName])
    if makeChart:
        # return nodes
        dot = __DOT.replace('%%MEAT%%', '\n'.join(colors + call_list))
        chartName = clean_path(idc.get_name(ea, ida_name.GN_VISIBLE) or 'default')
        r = dot_draw(dot, name=chartName, exe=exe)
        printi("dot_draw returned: {}".format(r))
        if isinstance(r, tuple):
            if not r[0]:
                printi("dot_draw error: {}".format(r[1]))
            else:
                printi("dot_draw good: {}".format(r[1]))
                r = subprocess.getstatusoutput('start {}'.format(chartName + '.svg'))
                printi("subprocess returned: {}".format(r))
    named = []
    l = []
    for ref, s in list(functionRefs.items()):
        l.extend([GetFunctionName(e) for e in s])
    named = [x for x in l if HasUserName(eax(x))]
    named.sort()
    if named:
        named = _.uniq(named, 1)
        #  printi(("Named Refs: %s" % named))

    l = []
    natives = []
    for ref, s in list(functionRefs.items()):
        l.extend([GetFunctionName(e) for e in s])
        natives = [x for x in l if ~x.find("::")]
        natives = [re.sub(r'(_0)+$', '', x) for x in natives]
    natives = list(natives)
    natives.sort()
    if natives:
        natives = _.uniq(natives, 1)
        #  printi(("Natives: %s" % natives))

    l = []
    vtable = []
    for ref, s in list(namedRefs.items()):
        vtable.extend(list(s))
    if vtable:
        vtable.sort()
        vtable = _.uniq(vtable, 1)
        #  printi(("Vtable Refs: %s" % vtable))

    if vtableRefs:
        vtableRefs.sort()
        vtableRefs = _.uniq(vtableRefs, 1)
        #  printi("Vtables: %s" % vtableRefs)

    #  if len(pending):
        #  printi(("0x%x: Leaving recurse callers too many pending: %d (depth: %d)" % (ea, len(pending), len(depthlist))))

    globals()['functionRefs'] = functionRefs

    globals()['_rev'] = rev
    globals()['_depth'] = depthlist

    if makeChart:
        return chart2

    return SimpleAttrDict({
            'named': named,
            'natives': natives,
            'vtableRefs': vtableRefs,
            'vtables': vtable,
            'iteratee': iteratee_results,
    })


def RecurseCallersChart(ea, width=512, includeSubs=0, depth=5, exe='dot', new=False):
    par = locals()
    chart = RecurseCallers(makeChart=1, data=1, **par)
    for left, right in chart:
        printi(('"{}" -> "{}";'.format(left, right)))

def FindDestructs(pattern="f6 c3 01 74 08 48 8b cf e8"):
    addrs = FindInSegments(pattern)
    def recurse(ea):
        for ref in xrefs_to(GetFuncStart(ea)):
            if idc.get_segm_name(ref) == '.rdata':
                printi('0x{:x} {}'.format(ref, get_name_by_any(ref)))
                if not HasUserName(ref):
                    LabelAddressPlus(ref, '??_7vtable_{:x}@unknown@@6B@'.format(ref))
            else:
                recurse(ref)
    for ea in addrs:
        recurse(ea)



def _unlikely_mnems(): return [
        'in', 'out', 'loop', 'cdq', 'lodsq', 'xlat', 'clc', 'adc', 'stc',
        'iret', 'stosd', 'bswap', 'wait', 'sbb', 'pause', 'retf', 'retnf',
        'scasb', 'cmc', 'insb', 'hlt', 'setnle', 'cwpd', 'loopne',
        'std', 'retf', 'loop', 'loope', 'loopz', 'fisub',
        'iret', 'insd', 'cld', 'rcr', 'ins', 'ffreep', 'fcom', 'jceax',
        'ficom', 'jcrx', 'hnt jb', 'repne', 'lock', 'lock dec', 'bsf', 'hnt',
        'fcmovnbe', 'retnw', 'cdq', 'clc', 'cld', 'cli', 'cmc', 'cmpsb',
        'cmpsd', 'cwde', 'hlt', 'in', 'ins', 'in al', 'in eax', 'ins byte',
        'ins dword', 'int3', 'int', 'int 3', 'int1', 'iret', 'lahf', 'leave',
        'lodsb', 'lodsd', 'out', 'outs', 'sahf',
        'scasb', 'scasd', 'stc', 'std', 'sti', 'stosd', 'wait',
        'xlat', 'fisttp', 'fbstp', 'fxch4', 'fld', 'fisubr', 'fsubr', 'bnd', 'db', # 'xlat byte [rbx+al]'
        'punpckhdq', 'psrad', 'fidiv', 'fild', 'fcom',
        ]
def _isUnlikely_mnem(mnem, *args, **kwargs): return mnem in _unlikely_mnems()


def perform(fun, *args, **kwargs):
    return fun(*args, **kwargs)

@static_vars(last_insn=None, last_time=None, last_result=None)
def preprocessIsX(fun, *args, **kwargs):
    arg = _.firstOr(args, idc.here())
    if isinstance(arg, str):
        return perform(fun, arg, **kwargs)
    if isinstance(arg, integer_types):
        mnem = IdaGetMnem(arg)
        if not mnem:
            disasm = GetDisasm(arg)
            mnem = string_between('', ' ', disasm, greedy=0)
        if not mnem:
            return False
        return perform(fun, mnem, ea=arg, **kwargs)
    raise Exception("Unknown argument type: {}".format(type(arg)))

def _isCall_mnem(mnem, ea=None, *args, **kwargs):                   return mnem.startswith("call")
def _isJmp_mnem(mnem, ea=None, *args, **kwargs):                    return mnem.startswith("jmp")
def _isAnyJmp_mnem(mnem, ea=None, *args, **kwargs):                 return mnem.startswith("j")
def _isAnyJmpOrCall(mnem, ea=None, *args, **kwargs):                return mnem.startswith(("j", "call"))
def _isConditionalJmp_mnem(mnem, ea=None, *args, **kwargs):         return mnem.startswith("j") and not mnem.startswith("jmp")
def _isUnconditionalJmp_mnem(mnem, ea=None, *args, **kwargs):       return mnem.startswith("jmp")
def _isOffset(mnem, ea=None, *args, **kwargs):                      return mnem.startswith(("dq offset", "dd offset"))
def _isUnconditionalJmpOrCall_mnem(mnem, ea=None, *args, **kwargs): return isUnconditionalJmp(mnem) or isCall(mnem)
def _isRet_mnem(mnem, ea=None, *args, **kwargs):                    return mnem.startswith("ret")
def _isPushPop_mnem(mnem, ea=None, *args, **kwargs):                return mnem.startswith("push") or mnem.startswith("pop")
def _isPop_mnem(mnem, ea=None, *args, **kwargs):                    return mnem.startswith("pop")
def _isNop_mnem(mnem, ea=None, *args, **kwargs):                    return mnem.startswith("nop") or mnem.startswith("pop")
def _isFlowEnd_mnem(mnem, ea=None, 
        ignoreInt=False, *args, **kwargs):                          return mnem.startswith(('ret', 'jmp', 'int', 'ud2', 'leave', 'iret') if not ignoreInt else ('ret', 'jmp', 'leave', 'iret'))
def _isInterrupt_mnem(mnem, ea=None, 
        ignoreInt=False, *args, **kwargs):                          return mnem in ('int', 'ud2', 'int1', 'int3')

def isUnlikely(*args, **kwargs):               return preprocessIsX(_isUnlikely_mnem, *args, **kwargs)
def isFlowEnd(*args, **kwargs):                return preprocessIsX(_isFlowEnd_mnem, *args, **kwargs)
def isAnyJmp(*args, **kwargs):                 return preprocessIsX(_isAnyJmp_mnem, *args, **kwargs)
def isOffset(*args, **kwargs):                 return preprocessIsX(_isOffset, *args, **kwargs)
def isRet(*args, **kwargs):                    return preprocessIsX(_isRet_mnem, *args, **kwargs)
def isAnyJmpOrCall(*args, **kwargs):           return preprocessIsX(_isAnyJmpOrCall, *args, **kwargs)
def isCall(*args, **kwargs):                   return preprocessIsX(_isCall_mnem, *args, **kwargs)
def isConditionalJmp(*args, **kwargs):         return preprocessIsX(_isConditionalJmp_mnem, *args, **kwargs)
def isJmp(*args, **kwargs):                    return preprocessIsX(_isJmp_mnem, *args, **kwargs)
def isPushPop(*args, **kwargs):                return preprocessIsX(_isPushPop_mnem, *args, **kwargs)
def isPop(*args, **kwargs):                    return preprocessIsX(_isPop_mnem, *args, **kwargs)
def isUnconditionalJmp(*args, **kwargs):       return preprocessIsX(_isUnconditionalJmp_mnem, *args, **kwargs)
def isUnconditionalJmpOrCall(*args, **kwargs): return preprocessIsX(_isUnconditionalJmpOrCall_mnem, *args, **kwargs)
def isInterrupt(*args, **kwargs):              return preprocessIsX(_isInterrupt_mnem, *args, **kwargs)

def isObfuJmp(ea):
    ea = eax(ea)
    if not IsValidEA(ea): return False
    if isJmp(ea):
        return False
    if idc.get_wide_dword(ea)    == 0x2d8d4855 and \
       idc.get_wide_dword(ea+8)  == 0x242c8748 and \
       idc.get_wide_byte(ea+12)  == 0xc3:
        # FindInSegments('55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 48 8d 64 24 08 ff 64 24 f8'); FindInSegments('55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3')
        return True
        searchstr = "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3"
        b = bytes(bytearray.fromhex(searchstr))
        return ida_bytes.equal_bytes(ea, b, None, len(b), ida_bytes.BIN_SEARCH_CASE | ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)

        #  found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        #  if found == ea:
            #  target = GetTarget(ea + 1)
            #  if IsValidEA(target):
                #  return target
    return False

def isJmpOrObfuJmp(ea, patch=0):
    if ea is None:
        return ValueError("ea was None")
    while patch and obfu.patch(ea):
        printi("isJmp-patching {:x}...".format(ea))
    if isJmp(ea):
        return True
    if idc.get_wide_dword(ea) == 0x24648d48:
        # FindInSegments('55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 48 8d 64 24 08 ff 64 24 f8'); FindInSegments('55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3')
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

@static_vars(bitmasks = [BitwiseMask(x) for x in ['48 8d 64 24 f8', '48 89 2c 24', '48 8d 2d ?? ?? ?? ??', '48 87 2c 24', '55', '48 8d 2d ?? ?? ?? ??', '48 87 2c 24 c3']])
def isCallOrObfuCall(ea, patch=0):
    ea = eax(ea)
    if False:
        while obfu.patch(ea):
            printi("isCall-patching {:x}...".format(ea))
    if isCall(ea):
        return True
    if idc.get_qword(ea) >> 24 == 0xf824648d48:
        searchstr = ['48 8d 64 24 f8', '48 89 2c 24', '48 8d 2d ?? ?? ?? ??', '48 87 2c 24', '55', '48 8d 2d ?? ?? ?? ??', '48 87 2c 24 c3']
        for bm in bitmasks:
            if not bm.match_addr(ea): return False
            r = AdvanceToMnem(start, count=1, rules=[
                (
                    # lambda ea: insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_143A8E11B'),
                    isUnconditionalJmp,
                    AdvanceToMnem.no_count
                ),
                (
                    isNop,
                    AdvanceToMnem.no_count
                ),
                ])
            if not r.count:
                print("couldn't move forward from {:#x}".format(ea))
                return False
            ea = r.ea

        if patch:
            while obfu.patch(ea): pass

        return True

            # searchstr = '48 8d 64 24 f8 48 89 2c 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3'
            # found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
            # if found == ea:
            #     if patch:
            #         l = [0xe8] + list(struct.unpack('4B', struct.pack('I', Dword(ea + 0x18) + 0x17))) + \
            #             [0xe9] + list(struct.unpack('4B', struct.pack('I', Dword(ea + 0x0c) + 0x06)))
            #         PatchBytes(ea, l)
            #         SetFuncEnd(ea, ea + 10)
            #         if IsFuncHead(ea):
            #             LabelAddressPlus(ea, 'StraightCall')
            #     return True

def isCallOrObfuCallPatch(ea):
    return isCallOrObfuCall(ea, 1) #  or SkipJumps(ea) != ea



def isNop(ea): 
    insn = ida_ua.insn_t()
    insnlen = ida_ua.decode_insn(insn, get_ea_by_any(ea))
    if insnlen == 0:
        return None 
    if insn.itype == idaapi.NN_nop:
        return True
    return idc.get_wide_word(ea) == 0x9066
    return GetInsn


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





def isCodeish(a, minlen=16):
    if IsCode_(a):
        return True
    elif isJmp(a) and (GetInsnRange(jmpTarget(a) > minlen or isJump(jmpTarget(a)))):
        return True
    elif GetInsnRange(a) > minlen:
        return True
    return False

def IsFlowEx(pos, ignoreInt=False):
    return IsFlow(pos) or (ignoreInt and isInterrupt(idc.prev_not_tail(pos)))

def jmpTarget(ea):
    return GetOperandValue(ea, 0)

def CountConsecutiveCalls(ea, checkFn = isCallOrObfuCallPatch):
    ori_ea = ea
    calls = []
    while ea and checkFn(ea) or isJmp(ea):
        if not isJmp(ea):
            calls.append(ea)
        tmp = GetJumpTarget(ea)
        if IsValidEA(tmp):
            ea = tmp
        else:
            break
    return SimpleAttrDict(_.object(('count', 'ea', 'name'), (calls, ea, get_name_by_any(ea))))

def first_iterable(iterable, *defaultvalue):
    return next(iterable, *defaultvalue)

def last_iterable(iterable, *defaultvalue):
    last = next(iterable, *defaultvalue)
    for last in iterable:
        pass
    return last

    
def all_xrefs_(funcea=None, xref_getter=None, key='unset', iteratee=None, filter=None, pretty=False):
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
                string_between('(', ')', XrefTypeNames(x.type)),
                diida(x.to))
            for x in xref_getter(head)
            if x.type not in (ida_xref.fl_F,)])
    xrefs = _.chain([iteratee(x) for x in xrefs if filter(x) # and not ida_funcs.is_same_func(x[0], funcea)
        ]).sort().uniq('sorted').value()

    if pretty:
        for x in _.uniq(sorted(xrefs, key=lambda x: (x[2], x[0])), 1):
            printi("0x{:09x} {:48} {:6} {}".format(*x))
        return
    return xrefs

def all_xrefs_from(funcea=None, iteratee=None, filter=None, pretty=False, key='to'):
    return all_xrefs_(funcea=funcea, iteratee=iteratee, filter=filter, pretty=pretty, xref_getter=idautils.XrefsFrom, key=key)

def all_xrefs_to(funcea=None, iteratee=None, filter=None, pretty=False, key='frm'):
    return all_xrefs_(funcea=funcea, iteratee=iteratee, filter=filter, pretty=pretty, xref_getter=idautils.XrefsTo, key=key)

def external_refs_to(funcea=None):
    return all_xrefs_to(funcea, filter=lambda x: (x[2] == 'fl_JN' or x[2] == 'fl_CN') and not IsSameFunc(funcea, x[0]), iteratee=lambda x: x[0])

def call_refs_from(funcea=None):
    return all_xrefs_from(funcea, filter=lambda x: x[2] == 'fl_CN', iteratee=lambda x: x[0])

def jmp_refs_from(funcea=None):
    return all_xrefs_from(funcea, filter=lambda x: x[2] == 'fl_JN', iteratee=lambda x: x[0])

def external_refs_from(funcea=None):
    return all_xrefs_from(funcea, filter=lambda x: (x[2] == 'fl_JN' or x[2] == 'fl_CN') and not IsSameFunc(funcea, x[0]), iteratee=lambda x: x[0])

def external_refs_from_unique(funcea, filter):
    return all_xrefs_from(funcea, filter=lambda x: (x[2] == 'fl_JN' or x[2] == 'fl_CN') and filter(x[0]) and not IsSameFunc(funcea, x[0]), iteratee=lambda x: x[0])

def jmp_refs_from(funcea=None):
    return all_xrefs_from(funcea, filter=lambda x: x[2] == 'fl_JN', iteratee=lambda x: x[0])


def call_refs_to(funcea=None):
    return all_xrefs_to(funcea, filter=lambda x: x[2] == 'fl_CN', iteratee=lambda x: x[0])

def skip_jmp_refs_to(dst=None):
    """
    skip_jmp_refs_to

    @param dst: linear address
    """
    if isinstance(dst, list):
        return [skip_jmp_refs_to(x) for x in dst]

    dst = eax(dst)
    
    if not IsValidEA(dst):
        return 0

    # {'frm': 0x141084154, 'iscode': 1, 'to': 0x143b0a21a, 'type': 0x13, 'user': 0})
    for src in xrefs_to(dst, filter=lambda x: x.type in (idc.fl_CN, idc.fl_JN)):
        if isCall(src):
            target = SkipJumps(src, apply=1)
            ida_xref.add_cref(src, target, idc.fl_CN)
        elif isUnconditionalJmp(src):
            skip_jmp_refs_to(src)
        else:
            target = SkipJumps(dst, apply=1)
            ida_xref.add_cref(dst, target, idc.fl_JN)
        # TODO: add one for lea rbp, [loc_1234]

        # SkipJumps(src, apply=1)
        # ida_xref.del_cref(src, dst, 1)
        #  skip_jmp_refs_to(src)
        
# x[2] == 'fl_JN' and isUnconditionalJmp(x[0]), iteratee=lambda x: x[0])

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
    #  def XrefTypeNames(typecode):
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
            #  xrefs.extend([(x.to, diida(x.frm) or idc.get_func_name(x.to) or idc.get_name(x.to) or hex(x.to), string_between('(', ')', XrefTypeNames(x.type)), diida(x.to)) for x in idautils.XrefsFrom(head) if x.type not in [ida_xref.fl_F]])
    #  #  xrefs = [x for x in xrefs if idc.get_func_name(x[0]) != functionName]
    #  xrefs = _.chain([iteratee(x) for x in xrefs if filter(x) and idc.get_func_name(x[0]) != functionName]).sort().uniq('sorted').value()
#  
    #  if pretty:
        #  for x in _.uniq(sorted(xrefs, key=lambda x: (x[2], x[0])), 1):
            #  printi("0x{:09x} {:48} {:6} {}".format(*x))
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
def XrefTypeNames(typecode=None, pattern=None):
    """
    Convert cross-reference type codes to readable names, or
    return list of typecodes matching regex `.*pattern.*`

    @example: XrefTypeNames('call|jump|data') or XrefTypeNames(17)

    @param typecode: cross-reference type code
    @param pattern: regular expression to be searched
    """
    if pattern is None and not isinstance(typecode, int):
        pattern, typecode = typecode, pattern
    if typecode is not None:
        assert typecode in XrefTypeNames._ref_types, "unknown reference type %d" % typecode
        return XrefTypeNames._ref_types[typecode]

    if pattern is not None:
        if not isListlike(pattern):
            pattern = [pattern]

        return [x for x, y in XrefTypeNames._ref_types.items() if _.any(pattern, lambda p, *a: not not re.search(p, y, flags=re.I))]
        

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
            #  xrefs.extend([(x.frm, idc.get_name(x.frm), XrefTypeNames(x.type), diida(x.frm)) for x in idautils.XrefsTo(head) if x.type not in [ida_xref.fl_F]])
    #  xrefs = _.uniq([iteratee(x[0]) for x in xrefs if x[0] != idc.BADADDR and not ida_funcs.is_same_func(x[0], funcea)])
    #  return xrefs


def SkipJumpsTo(ea=None, **kwargs):
    """
    SkipJumpsTo

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [SkipJumpsTo(x) for x in ea]

    ea = eax(ea)
    for addr in xrefs_to(ea, filter=lambda x: isUnconditionalJmpOrCall(x.frm)): 
        SkipJumps(ea, apply=1, **kwargs)
    # for addr in xrefs_to(xrefs_to(ea, filter=lambda x: isUnconditionalJmp(x.frm)), filter=lambda x: isUnconditionalJmp(x.frm)): SkipJumps(ea, apply=1, **kwargs)


def label_import_thunks():
    ea = eax('.idata')
    while idc.get_segm_name(ea) == '.idata':
        l = xrefs_to(ea, filter=lambda v: isJmp(v.frm))
        name = idc.get_name(ea, ida_name.GN_VISIBLE)
        if l:
            for addr in l: 
                if IsFuncHead(addr):
                    print("FuncHead: {}: {:x}".format(name, addr))
                    LabelAddressPlus(addr, name)
                    SetFuncFlags(addr, lambda f: f | idc.FUNC_LIB)
                elif not IsFunc_(addr) and HasUserName(addr) and not IsFlow(addr):
                    print("NonFunc: {}: {:x} {}".format(name, addr, idc.get_name(addr), ida_name.GN_VISIBLE))
                    # LabelAddressPlus(addr, name)
                    idc.add_func(addr)
                    SetFuncFlags(addr, lambda f: f | idc.FUNC_LIB)
        print("{:x} {}".format(ea, name))

        ea = idc.next_head(ea)



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
        xrefs = [SimpleAttrDict({
            'frm': x.frm, 
            'frm_insn': 'offset' if IsOff0(x.frm) else diida(x.frm), 
            'type': string_between('(', ')', XrefTypeNames(x.type)), 
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

def xrefs_to(ea, include=None, iteratee=None, filter=None):
    """
    filter is passed {'frm': 0x140a66258, 'iscode': 1, 'to': 0x140a6625c, 'type': 0x15, 'user': 0}
    >> for xref in XrefsTo(here(), 0):
         printi(xref.type, XrefTypeNames(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
    
    21 Ordinary_Flow (fl_F) from 0x140a66258 to 0x140a6625c
        if isinstance(ea, list):
            return [xrefs_to(x) for x in ea]
    """

    if isinstance(ea, list):
        return [xrefs_to(x, include=include, iteratee=iteratee, filter=filter) for x in ea]

    if include:
        filter = lambda x: x.type in XrefTypeNames(include)

    if not filter:
        filter = lambda x: x.type not in (ida_xref.fl_F, )

    ea = eax(ea)
    def collect(ea):
        for x in idautils.XrefsTo(ea):
            # {'frm': 0x140a66258, 'iscode': 1, 'to': 0x140a6625c, 'type': 0x15, 'user': 0}
            if not filter or filter(x):
                yield iteratee(x.frm) if iteratee else x.frm
                #  call_if_callable(filter, x.frm, default=x.frm)

    return list(collect(ea))

#  
    #  if callable(iteratee):
        #  return [iteratee(x.frm) for x in idautils.XrefsTo(ea)]
    #  return [x.frm for x in idautils.XrefsTo(ea)]
def seg_refs_to(ea=None, seg='.text'):
    """
    references to address from nominated segment(s)

    @param ea: linear address
    """
    seg = A(seg)
    ea = eax(ea)
    seg = A(seg)
    return xrefs_to_ex(ea, filter=lambda e: e.frm_seg in seg)

def SegmentRefsTo(ea):
    return set([SegName(x) for x in xrefs_to(ea)])

def isSegmentInXrefsTo(ea, s):
    return s in SegmentRefsTo(ea)

def GetFuncHeadsIter(funcea=None):
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

    heads = []
    for start, end in idautils.Chunks(funcea):
        yield from idautils.Heads(start, end)
        # heads.extend([head for head in idautils.Heads(start, end)])

    # return heads

def GetFuncHeads(funcea=None):
    return list(GetFuncHeadsIter(funcea))

def CheckFuncSpDiffs(funcea=None, value=None):
    """
    CheckFuncSpDiffs

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [CheckFuncSpDiffs(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    for start, end in idautils.Chunks(funcea):
        for head in idautils.Heads(start, end):
            if value is not None:
                SetSpDiffEx(head, value)
            else:
                SetSpDiffEx(head, GetSpDiff(head))

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
        printi("[GetDisasmFuncHeads] hash changed")
    

def GetMinSpd(ea = None):
    ea = eax(ea)
    minspd_ea = idc.get_min_spd_ea(ea)
    if minspd_ea == idc.BADADDR:
        return False
    return idc.get_spd(minspd_ea)

def bad_as_none(ea=None):
    """
    bad_as_none

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [bad_as_none(x) for x in ea]

    if ea == idc.BADADDR:
        return None 
    return ea
    



def GetSpds(funcea = None, verbose=False):
    ea = eax(funcea)
    if not IsFunc_(ea):
        if verbose: print("not IsFunc_")
        return False
    #  if GetMinSpd(ea) == False:
        #  return False
    func_heads = GetFuncHeads(ea)
    last_head = func_heads[-1]
    spds = [idc.get_spd(head) for head in GetFuncHeads(ea) if 
            (insn_match(head, idaapi.NN_retn, comment='retn')
                    or insn_match(head, idaapi.NN_jmpni, (idc.o_displ, None), comment='jmp qword [reg+0x28]')
                    or insn_match(head, idaapi.NN_jmpni, (idc.o_mem, 5), comment='jmp qword [rel UnhandledExceptionFilter]')
                    or insn_match(head, idaapi.NN_jmpni, (idc.o_phrase, None), comment='jmp qword [rax+r8*8]')
                    or insn_match(head, idaapi.NN_jmpni, (idc.o_reg, 0), comment='jmp rax')
                    or head == last_head and insn_match(head, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_140112E28') and not ida_funcs.is_same_func(ea, GetTarget(head))
                    )]

    if False and len(spds) == 1 and len(func_heads) > 2:
        if verbose: print("len(spds) == 1 and len(func_heads) > 2")
        mi, ma = GetAllSpdsMinMax(ea)
        if verbose:
            # dprint("[GetSpds] ma, mi, idc.get_spd(last_head), IsFuncHead(last_head)")
            print("[GetSpds] ma:{}, mi:{}, idc.get_spd(last_head):{}, IsFuncHead(last_head):{}".format(ma, mi, idc.get_spd(last_head), IsFuncHead(last_head)))
            print("insn_match: {}".format(insn_match(last_head, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_140112E28')))
            
        if ma == 0 and mi < 0 and insn_match(last_head, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_140112E28') and idc.get_spd(last_head) == 0 and not IsFuncHead(last_head):
            _ft = func_tails(ea, returnErrorObjects=1, quiet=1)
            if verbose: print("_ft: {}".format(_ft))
            if _ft and not _.all(_ft, lambda v, *a: isinstance(v, FuncTailsJump)):
                return False
            tgt = GetTarget(last_head)
            if verbose: print("tgt: {:#x}".format(tgt))
            if not IsFunc_(tgt):
                if verbose: print("not isfunc(tgt)")
                ForceFunction(tgt)
                ida_retrace(tgt)
                if not IsFunc_(tgt):
                    retrace(tgt, once=1)
                Commenter(tgt, 'line').add('[DENY JMP]: (GetSpds)')
            else:
                if not IsFuncHead(tgt):
                    _fh = GetFuncStart(tgt)
                    ForceFunction(tgt)
                    ida_retrace(tgt)
                    if not IsFunc_(tgt):
                        retrace(tgt, once=1)
                    Commenter(tgt, 'line').add('[DENY JMP]: (GetSpds)')
                    if _fh != ea:
                        retrace(_fh, once=1)


    return spds

def GetAllSpds(funcea = None, address=False):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return None
    #  if GetMinSpd(ea) == False:
        #  return False
    if address:
        spds = [(head, idc.get_spd(head)) for head in GetFuncHeads(ea)]
        if not _.all(spds, lambda v, *a: isinstance(v[1], int)):
            return None
    else:
        spds = [idc.get_spd(head) for head in GetFuncHeads(ea)]
        if not _.all(spds, lambda v, *a: isinstance(v, int)):
            return None
    return spds

def RemoveLameFuncs():
    l1 = []
    l2 = []
    l3 = []
    for ea in Functions():
        if GetFuncName(ea).startswith('sub_'):
            ccount = GetChunkCount(ea)
            mnem = IdaGetMnem(ea)
            if mnem and mnem.startswith('jmp'):
                if ccount > 1:
                    print("{:#x}".format(ea))
                    idc.del_func(ea)
                    l3.append(ea)
                elif ea + IdaGetInsnLen(ea) < GetFuncEnd(ea):
                    print("{:#x}".format(ea))
                    idc.del_func(ea)
                    l3.append(ea)
            else:
                spds = GetSpds(ea)
                if len(spds) == 0:
                    print("{:#x}".format(ea))
                    idc.del_func(ea)
                    l1.append(ea)
                elif sum(spds) != 0:
                    print("{:#x}".format(ea))
                    idc.del_func(ea)
                    l2.append(ea)


def GetSpdsMinMax(funcea=None, predicate=None):
    ea = eax(funcea)

    def ret(lhs, rhs):
        if callable(predicate):
            return predicate(lhs, rhs)
        return lhs, rhs

    if not IsFunc_(ea):
        return ret(idc.BADADDR, idc.BADADDR)
    spds = GetSpds(ea)
    if spds and _.all(spds, lambda x, *a: x is not None):
        return ret(min(spds), max(spds))
    return ret(idc.BADADDR, idc.BADADDR)

def GetAllSpdsMinMax(funcea=None, predicate=None):
    ea = eax(funcea)

    def ret(lhs, rhs):
        if callable(predicate):
            return predicate(lhs, rhs)
        return lhs, rhs

    if not IsFunc_(ea):
        return ret(idc.BADADDR, idc.BADADDR)
    spds = GetAllSpds(ea)
    if spds:
        return ret(min(spds), max(spds))
    return ret(idc.BADADDR, idc.BADADDR)

def IsFuncSpdBalanced(funcea=None, nonzero=False):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    minmax = GetSpdsMinMax(ea)
    if minmax[0] == minmax[1] == 0:
        spds = GetAllSpdsMinMax(ea)
        if spds[0] <= (-1 if nonzero else 0) and spds[1] == 0:
            return True
    return False
    

def IsFuncSpdZero(funcea=None):
    ea = eax(funcea)
    if not IsFunc_(ea):
        return False
    minmax = GetSpdsMinMax(ea)
    if minmax[0] == minmax[1] == 0:
        spds = GetAllSpdsMinMax(ea)
        if spds[0] == spds[1] == 0:
            return True
    return False

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
    if not st:
        return st
    elif len(st) == 1:
        return st.upper() if upper else st.lower()

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
        printi(("0x%x: CamelizeFunction('%s'): %s" % (st, fnFull, fnCamel)))
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

def is_prime(n):
  if isinstance(n, list):
      return [is_prime(x) for x in n]
  if n == 2 or n == 3: return True
  if n < 2 or n%2 == 0: return False
  if n < 9: return True
  if n%3 == 0: return False
  r = int(n**0.5)
  # since all primes > 3 are of the form 6n ± 1
  # start with f=5 (which is prime)
  # and test f, f+2 for being prime
  # then loop by 6. 
  f = 5
  while f <= r:
    print('\t',f)
    if n % f == 0: return False
    if n % (f+2) == 0: return False
    f += 6
  return True    

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
        printi("[debug] _abs:{}, fn:{}".format(_abs, fn))
        

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
    printi("[_] _nfn:{}".format(_nfn))
    

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

    # printi("symlink: {} -> {}".format(fn, res))
    
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

    # printi("symlink final res: {}".format(new))
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

def clean_path(s):
    return re.sub(r'[^\w_. -]', '_', s)

def dot_draw(string, name="default", exe="dot"):
    if not name:
        name = "default"
    idb_subdir = GetIdbPath()
    idb_subdir = idb_subdir[:idb_subdir.rfind(os.sep)] + os.sep + "dot_%s" % GetInputFile()
    if not os.path.isdir(idb_subdir):
        os.mkdir(idb_subdir)

    filename = idb_subdir + os.sep + '%s.dot' % clean_path(name)
    with open(filename, "w+") as fw:
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
        raise Exception("Please install graphviz from https://graphviz.org/download/ to c:/Program Files/Graphviz")

    args = list()
    args.append("-Tsvg")
    args.append("%s.dot" % os.path.abspath(name))
    args.append("-o%s.svg" % os.path.abspath(name))

    args = [dot_executable_filepath] + list(args)
    if debug: printi(args)
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
        if debug: printi(("CalledProcessError: %s" % e.__dict__))
        return False, e.output

    # with open(idb_subdir + os.sep + '%s.svg' % name, "rb") as fr:
    with open("%s.svg" % os.path.abspath(name), "rb") as fr:
        o = fr.read()
        if len(o):
            printi("dot_draw: {}".format( filename) )
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
    #  printi('found {} > {}', d, s)

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

        #  printi("[info] ourFunc is {:x}".format(ourFunc))
    #  printi("[info] checking range ... {:#x}".format(ea))
    for r in range(_range):
        chunk_num = GetChunkNumber(ea + r)
        func_start = GetFuncStart(ea + r)
        end = ea + r
        if (func_start != start_func_start and func_start != -1) or (chunk_num != start_chunk_num and chunk_num != -1):
            break

    if end > ea:
        if debug: printi("[UnpatchUntilChunk] UnPatch({:x}, {:x})".format(ea, end))
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
    #  end = end or IdaGetInsnLen(start)
    #  if end < idaapi.cvar.inf.min_ea and end < start:
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
                #  printi("[warn] item_head == addr {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, start, start, end))
            #  #  if not idc.del_items(addr, 0, 1):
            #  if not idc.MakeUnknown(addr, 1, 0):
                #  printi("[warn] couldn't del item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, start, start, end))
#  
        #  if idc.is_code(idc.get_full_flags(addr)):
            #  # seems to be that deleting the code and remaking it is the only way to ensure everything works ok
            #  if debug: printi("[info] code already existing instruction at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, addr, start, end))
            #  idc.del_items(addr, 0, idc.get_item_size(addr))
            #  # addr += idc.get_item_size(addr)
            #  # happy = 1
        #  if 1:
            #  insn_len = idc.create_insn(addr)
            #  if debug: printi("[info] idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, addr, start, end))
            #  if not insn_len:
                #  # record existing code heads
                #  existing_code = [x for x in range(addr, addr+15) if IsCode_(x)]
                #  idc.del_items(addr, 0, 15)
                #  insn_len = idc.create_insn(addr)
                #  if not insn_len and existing_code:
                    #  [idc.create_insn(x) for x in existing_code]
            #  if not insn_len:
                #  trimmed_end = last_jmp_or_ret + idc.get_item_size(last_jmp_or_ret) if last_jmp_or_ret else last_addr or addr
                #  printi("[warn] couldn't create instruction at {:x}, shortening chunk to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(addr, trimmed_end, addr, start, end))
                #  if trim:
                    #  if idc.get_func_name(start):
                        #  if not SetFuncEnd(start, trimmed_end):
                            #  printi("[warn] couldn't set func end at {:x} or {:x} or {:x} or {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(end, last_jmp_or_ret, last_addr, addr, start, start, end))
                    #  idc.del_items(end, 0, end - trimmed_end)
            #  else:
                #  happy = 1
                #  addr += insn_len
#  
        #  if not happy:
            #  return (addr-start, start, end, trimmed_end)
#  
        #  mnem = IdaGetMnem(last_addr).split(' ', 2)[0]
        #  if mnem in ('jmp', 'ret', 'retn', 'int'):
            #  last_jmp_or_ret = last_addr
#  
    #  return (addr-start, start, end, trimmed_end)

def CheckThunk(ea, skipShort=0):
    if not IsFuncHead(ea):
        printi("CheckThunk: Not FuncHead {:x}".format(ea))
        return ea
    insn = idautils.DecodeInstruction(ea)
    if not insn:
        printi("CheckThunk: Couldn't find insn at {:x}".format(ea))
        return ea
    if insn.itype == idaapi.NN_jmp and (not skipShort or IdaGetInsnLen(ea) > 2):
        if insn.Op1.type in (idc.o_near,):
            if GetChunkEnd(ea) - GetChunkStart(ea) > IdaGetInsnLen(ea):
                SetFuncEnd(ea, ea + IdaGetInsnLen(ea))
        if not IsThunk(ea):
            #  printi("[info] 1611: {}".format(ea))
            # idc.add_func(ea, insn_len)
            if not MakeThunk(ea):
                printi("[warn] MakeThunk({:x}) failed".format(ea))
                globals()['warn'] += 1
            else:
                if debug: printi("[info] MakeThunk({:x}) ok".format(ea))

def ForceFunction(start, unpatch=False, denyJmp=False):
    # dprint("[ForceFunction] start")   
    if debug: printi("[ForceFunction] start:{:x}".format(start))
    if not IsValidEA(start):
        return False

    do_return = None
    ea = start

    if IsExtern(ea):
        printi("[ForceFunction] 0x{:x} is a reference".format(ea))
        return 1
    if denyJmp:
        Commenter(start, 'line').add('[DENY JMP]')
    if IsFuncHead(start):
        if debug: printi("[ForceFunction] IsFuncHead {:x}".format(start))
        return 1

    fnName = ''
    if HasUserName(ea):
        if IsFunc_(ea):
            fnName = idc.get_func_name(ea)
        else:
            fnName = idc.get_name(ea)

    fnStart = GetFuncStart(start)
    isStartChunk = IsSameChunk(fnStart, start)
    itemHead = idc.get_item_head(start)
    if isStartChunk and fnStart < itemHead < idc.BADADDR:
        # dprint("[SetFuncEnd #1] fnStart, start")
        print("[SetFuncEnd #1] fnStart:{:#x}, start:{:#x}".format(fnStart, start))
        
        if not SetFuncEnd(fnStart, idc.get_item_head(start)):
            printi("[warn] ForceFunction (inside funchead) SetFuncEnd({:x}, {:x}) failed".format(fnStart, idc.get_item_head(start)))
            ZeroFunction(ea, total=1)
            idc.auto_wait()
            return ForceFunction(ea)
            globals()['warn'] += 1
            return False
    func = clone_items(GetChunk(start))
    if func:
        if func.flags & idc.FUNC_TAIL or func.start_ea != start:
            if func.start_ea < start:
                # dprint("[SetFuncEnd #2] func.start_ea, start")
                print("[SetFuncEnd #2] func.start_ea:{}, start:{}".format(func.start_ea, start))
                
                if not SetFuncEnd(func.start_ea, start):
                    printi("[warn] SetFuncEnd({:x}, {:x}) failed".format(func.start_ea, start))
                    globals()['warn'] += 1
                    return False
                else:
                    if debug: printi("[info] SetFuncEnd({:x}, {:x}) ok".format(func.start_ea, start))
            else:
                if not remove_func_or_chunk(func):
                    printi("[warn] remove_func_or_chunk({:x}) failed".format(func.start_ea))
                    globals()['warn'] += 1
                    return False
                else:
                    if debug: printi("[info] remove_func_or_chunk({:x}) ok".format(func.start_ea))

        else:
            do_return = func.end_ea - func.start_ea

    if do_return is not None:
        CheckThunk(start)
        return do_return

    end = EaseCode(start, forceStart=1, noExcept=1)
    if not IsValidEA(start):
        printi("[ForceFunction] InvalidEA start: {}-{}".format(ahex(start), ahex(end)))
        return False
    if not IsValidEA(end):
        printi("[ForceFunction] InvalidEA end: {}-{}".format(ahex(start), ahex(end)))
        return False
    if not idc.add_func(start, end) and not IsFunc_(start):
        globals()['warn'] += 1
        printi("[warn] couldn't create function at {:x}-{:x}".format(start, end))
        return False
    else:
        return GetFuncSize(start)

    idc.auto_wait()
    if not IsFuncHead(start):
        printi("[warn] failed to force_function after success {:#x} {}".format(start, ea - start))
        globals()['warn'] += 1
    if IsFuncHead(start):
        # CheckThunk(start)
        if fnName:
            LabelAddressPlus(start, fnName)
        return ea - start

    return False

def listOfBytesAsHex(byteArray):
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

def hex_patterns(hexLists):
    result = [ ]
    # Convert a string into a list, just so we can process it
    if not isinstance(hexLists, list):
        hexLists = [hexLists]
    for l in hexLists:
        result.append([hex_byte_as_pattern_int(item) for item in l.split(" ")])
    return result

def make_pattern_from_hex_list(hexLists):
    result = []
    for list in hexLists:
        result.append([hex_byte_as_pattern_int(item) for item in list.split(" ")])
    return result

def swap32(x, n=4):
    return int.from_bytes(x.to_bytes(n, byteorder='little'), byteorder='big', signed=False)

def swap64(x, n=8):
    return swap32(x, n)

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
        printi((" -> ".join(stk)))
        printi(("0x%x: AppendFunc(0x%x, 0x%x)" % (ea, funcea, new_func)))

    if not IsFunc_(new_func):
        if debug: printi("ShowAppendFunc: {:x} is not a function".format(new_func))
        return result

    if not IsFuncHead(new_func):
        if debug: printi("ShowAppendFunc: {:x} is not IsFuncHead".format(new_func))
        return result

    owners = GetChunkOwners(new_func)
    if len(owners) > 1:
        if debug: printi("ShowAppendFunc: {:x} has multiple owners".format(new_func))
        if funcea in owners: printi("ShowAppendFunc: {:x} we are one of those owners".format(new_func))
        raise ChunkFailure("ShowAppendFunc: {:x} has multiple owners".format(new_func))

    if funcea in owners or IsSameFunc(funcea, new_func):
        if debug: printi("ShowAppendFunc: {:x} is already our func".format(new_func))
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
            print("Adding chunk starting at: {:#x} {}".format(x, GetDisasm(x)))
            print("Adding chunk starting at: {:#x} {}".format(x, diida(x)))
            if IsTail(y):
                y = EaseCode(x)
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
            printi("[warn] force_chunk: no chunk at {:x}".format(ea))
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
                    printi("[warn] force_chunk: couldn't get_func {:x}".format(ea))
                    globals()['warn'] += 1
                else:
                    cstart, cend = func.start_ea, func.end_ea

                    if func.start_ea < end:
                        del func # can't delete if handle is open
                        if not ida_funcs.set_func_start(ea, end):
                            printi("[warn] force_chunk: cannot change func start {:x} to {:x}".format(cstart, end))
                            globals()['warn'] += 1
                        else:
                            printi("[info] force_chunk: changed func start from {:x} to {:x} for {:x}".format(cstart, end, cend))
                    if func.end_ea > start:
                        del func # can't delete if handle is open
                        if not SetFuncEnd(ea, start) and not SetFuncEnd(start, start):
                            printi("[warn] force_chunk: cannot change func end ({:x}) {:x} to {:x}".format(ea, cend, start))
                            globals()['warn'] += 1
                        else:
                            printi("[info] force_chunk: changed func end for {:x} from {:x} to {:x}".format(cstart, cend, start))
                    if func:
                        # evidently we couldn't find a way around this func
                        del func # can't delete if handle is open
                        if not ida_funcs.del_func(ea):
                            printi("[warn] force_chunk: couldn't deleete func {:x}".format(ea))
                            globals()['warn'] += 1
                        else:
                            printi("[info] force_chunk: deleted func {:x}".format(ea))
            else: # if chunk tail
                if tail.refqty == 1 and tail.owner == funcea:
                    pass
                else:
                    not_ours.add(ea)
                while tail and (tail.refqty > 1 or tail.owner != funcea):
                    if not tail.flags & ida_funcs.FUNC_TAIL:
                        printi("[warn] force_chunk tail became head {:x}".format(ea))
                        globals()['warn'] += 1
                    if not idc.remove_fchunk(ea, start):
                        printi("[warn] force_chunk cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
                        globals()['warn'] += 1
                        break
                    else:
                        printi("[info] force_chunk removed whole fchunk {:x}\u2013{:x}".format(start, end))
                    idc.auto_wait()

                    tail = clone_items(GetChunk(ea))
    if len(not_ours):
        printi("{:x} not ours: {}".format(funcea, hex(list(not_ours))))
        callback()


def adjust_tails(funcea, add=None, remove=None):
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

    printi("diff: {}".format(pf(existing_range.symmetric_difference(altered_range))))

    #  existing = _.flatten(asList(GenericRanger(existing_range, iteratee = lambda x, y: range(x, y+1))))
    #  altered  = _.flatten(asList(GenericRanger(altered_range,  iteratee = lambda x, y: range(x, y+1))))
    _chunks  =                  GenericRanger(existing_range, iteratee = lambda x, y: (x, y+1))
    _new     =                  GenericRanger(altered_range,  iteratee = lambda x, y: (x, y+1))
    _remove  =                  GenericRanger(existing_range.difference(altered_range), \
                                                              iteratee = lambda x, y: (x, y+1))
    _add     =                  GenericRanger(altered_range.difference(existing_range), \
                                                              iteratee = lambda x, y: (x, y+1))
    # _remove = GenericRanger(list(set(existing) - set(altered)), iteratee=lambda x, y: SimpleAttrDict({'start_ea':x, 'end_ea':y+1}))
    #  printi("_chunks: {}" .format(hex((_chunks))))
    #  printi("existing: {}".format(hex(list(existing))))
    #  printi("altered: {}" .format(hex(list(altered))))
    #  printi("_new: {}"    .format(hex((_new))))
    printi("remove: {}" .format(hex(list(remove))))
    printi("add: {}"    .format(hex(list(add))))
    printi("_remove: {}" .format(hex(list(_remove))))
    printi("_add: {}"    .format(hex(list(_add))))

    _overlap = _.reject(overlap3(_chunks, _new), lambda x, *a: x[2] == x[3])
    printi("_overlap: {}"    .format(hex(_overlap)))

    warn = 0
    for c in _overlap:
        start, end, chunk, unused = c
        cstart, cend = chunk
        if start >= end:
            printi("[info] start >= end {:x}\u2013{:x}".format(start, end))
            continue
        if cend == end:
            if cstart == start:
                printi("[info] chunk remains unchanged {:x}\u2013{:x}".format(start, end))
                continue

                #  if not idc.remove_fchunk(funcea, start):
                    #  printi("[warn] cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
                #  else:
                    #  printi("[info] removed whole fchunk {:x}\u2013{:x}".format(start, end))
            else:
                # same end, different start
                #
                # fnStart = idc.get_func_attr(ea, idc.FUNCATTR_START)
                # fnEnd = idc.get_func_attr(ea, idc.FUNCATTR_END)
                if not ida_funcs.set_func_start(funcea, start):
                    printi("[warn] cannot change fchunk start from {:x} to {:x}".format(cstart, start))
                    globals()['warn'] += 1
                else:
                    printi("[info] changed fchunk start from {:x} to {:x} for {:x}".format(cstart, start, cstart))
        elif cstart == start:
            # end's cannot match
            if not SetFuncEnd(funcea, end):
                    printi("[warn] (1) cannot change fchunk end ({:x}) {:x} to {:x}".format(funcea, cend, end))
                    globals()['warn'] += 1
                    warn += 1
            else:
                printi("[info] changed fchunk end for {:x} from {:x} to {:x}".format(cstart, cend, end))
        else:
            # trickiest -- both ends have changed
            # TODO: do we have to check for overlap of existing chunk?  probably, even if from other function
            printi("[info] preparing to DP chunk from {:x}\u2013{:x}, to {:x}\u2013{:x}".format(cstart, cend, start, end))
            if not SetFuncEnd(funcea, end):
                printi("[warn] DPing chunk, cannot change fchunk end {:x}\u2013{:x}".format(cend, end))
                globals()['warn'] += 1
            elif not ida_funcs.set_func_start(funcea, start):
                printi("[warn] cannot change fchunk start {:x} to {:x}".format(cstart, start))
                globals()['warn'] += 1
            else:
                printi("[info] changed fchunk start from {:x} to {:x} for {:x}".format(cstart, end, cend))

            #  printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, end+1, cend))
            #  elif not idc.append_func_tail(funcea, end+1, cend):
                #  printi("[warn] DPing chunk, cannot add new fchunk {:x}\u2013{:x}".format(end+1, cend))
            #  else:
                #  printi("[info] Dped chunk in two: {:x}\u2013{:x}, {:x}\u2013{:x}".format(cstart, start, end+1, cend))


    __del, __add = not_overlap3(_chunks, _new)
    for start, end in __del:
        if not idc.remove_fchunk(funcea, start):
            printi("[warn] cannot remove whole fchunk {:x}\u2013{:x}".format(start, end))
            globals()['warn'] += 1
            warn += 1

    return warn

def ShowAppendFchunk(ea, start, end, old):
    global global_chunks
    if debug: stacktrace()
    rv = None
    try:
        rv = ShowAppendFchunkReal(ea, start, end, old)
    finally:
        pass
        # global_chunks[ea].update(idautils.Chunks(ea))
    return rv

def ShowAppendFchunkReal(ea, start, end, old):
    funcea = GetFuncStart(ea)
    if debug: printi(("0x%x: ShowAppendFchunk::AppendFchunk(0x%x, 0x%x, 0x%x)" % (ea, funcea, start, end)))
    if funcea == BADADDR:
        printi("[warn] funcea {:x} is not a function".format(funcea))
        return False

    [GetDisasm(x) for x in idautils.Heads(start, end)]

    fstart, fend = GetFuncStart(ea), GetFuncEnd(ea)
    cstart, cend = GetChunkStart(ea), GetChunkEnd(ea)

    if debug:
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        printi((" -> ".join(stk)))

    we_own_all = True
    # for i in range(start, end):
    owners = []
    for i in idautils.Heads(start, end):
        owners.append((i, GetChunkOwners(i)))

    if _.all(owners, lambda v, *a: v[1] == [fstart]):
        if debug: print("[ShowAppendFchunkReal] we own it all")
        return

    notown = _.filter(owners, lambda v, *a: v[1] and v[1] != [fstart])
    if notown:
        if debug: print("[ShowAppendFchunkReal] notown, what you want?")
        #  pph(notown)
        #  raise RuntimeError("[ShowAppendFchunkReal] notown by us {:#x}, what you want?".format(fstart))

    if not idc.append_func_tail(fstart, start, end):
        if debug: printi("no easy idc.append_func_tail({:#x}, {:#x}, {:#x})".format(fstart, start, end))
        # raise RuntimeError("[ShowAppendFchunkReal] couldn't idc.append_func_tail({:#x}, {:#x}, {:#x})".format(fstart, start, end))


    # return

    if True:
        owners = GetChunkOwners(i)
        if owners:
            if IsFuncHead(GetChunkStart(i)):
                if debug: printi("ShowAppendFchunk: IsFuncHead: {:x}".format(i))
                if GetChunkStart(i) == funcea:
                    pass
                    #  if debug: printi("ShowAppendFchunk: FuncHeadOwner: {:x} is us {:x}".format(GetChunkStart(i), funcea))
                else:
                    idc.del_func(i)
            for owner in owners:
                #  if debug: printi("ShowAppendFchunk: Owner: {:x}".format(owner))
                if owner != funcea:
                    if debug: printi("ShowAppendFchunk: Owner: {:x} is not us {:x}".format(owner, funcea))
                    idc.remove_fchunk(owner, i)
                    idc.auto_wait()
                else:
                    pass
                    #  if debug: printi("ShowAppendFchunk: Owner: {:x} is us {:x}".format(owner, funcea))

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
                    return ShowAppendFunc(ea, funcea, start)
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

    #  printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, start, end))
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

    tuples = [(x, (x + IdaGetInsnLen(x)) if IsCode(x) else idc.next_head(x), _(any.get(x, [0])).chain().sort().join(',').value()) for x in all if x not in func]
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
            #  printi("[about-to-append-func-tail] r.start:{:x}, GetFuncName(r.start):{}".format(r.start, GetFuncName(r.start)))
            
            for e in Heads(r.start, r.last):
                if IsFuncHead(e):
                    #  begin, end = GetChunkStart(e), GetChunkEnd(e)
                    if 1 and debug: sprint("AddChunk: del_func: already owned by another func, deleting func at {:x}", format(e))
                    idc.del_func(e)

            _func = ida_funcs.get_func(funcea)
            for _ea in range(r.start + 1, r.last): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                    # XXX
                    # This might work:
                    # [warn] avoided crash: append_func_tail(0x14344b6a1, 0x14162bf12, 0x14162bf17) [overlaps existing function chunk
                    # ida_funcs.get_func_chunknum(0x14344b6a1, 0x14162bdca) == 5
                    # idc.remove_fchunk(0x14344b6a1, 0x14162bdca)
                    printi("[warn] avoided crash: append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) [overlaps existing function chunk belonging to 0x{:x} at 0x{:x}]".format(
                        funcea, r.start, r.last, GetChunkOwner(_ea), _ea))
                    globals()['warn'] += 1
                    return 

            #  del _func

            # this turns undefined data into instructions (nicely, not forcefully)
            idc.auto_wait()
            for _ea in range(r.start + 1, r.last): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                    # XXX
                    # This might work:
                    # [warn] avoided crash: append_func_tail(0x14344b6a1, 0x14162bf12, 0x14162bf17) [overlaps existing function chunk
                    # ida_funcs.get_func_chunknum(0x14344b6a1, 0x14162bdca) == 5
                    # idc.remove_fchunk(0x14344b6a1, 0x14162bdca)
                    printi("[warn] avoided crash: append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) [overlaps existing function chunk belonging to 0x{:x} at 0x{:x}]".format(
                        funcea, r.start, r.last, GetChunkOwner(_ea), _ea))
                    globals()['warn'] += 1
                    return 
            if IsHead(r.last) or  \
                    PrevHead(r.last) + IdaGetInsnLen(PrevHead(r.last)) == r.last or \
                    IsCode(r.last) or (IsCode(PrevNotTail(r.last) + IdaGetInsnLen(PrevNotTail(r.last))) and PrevNotTail(r.last) + IdaGetInsnLen(PrevNotTail(r.last)) == r.last):
                pass
            else:
                printi("dubious r.last: {:x}".format(r.last))
            #  rv = ida_auto.auto_wait_range(r.start, r.last)
            #  if debug: printi("ida_auto.auto_wait_range(0x" + str(r.start) + ", 0x" + str(r.last) + "): " + str(rv))
            #  if debug: printi("ida_auto.auto_apply_tail(0x" + str(r.start) + ", 0x" + str(funcea) + ")")
            #  ida_auto.auto_apply_tail(r.start, funcea)
            #  # Plan(r.start, r.last, True)
            #  rv = idc.auto_wait()
            #  if debug: printi("idc.auto_wait(): {}".format(rv))

            if debug: printi("EaseCode(0x{:x}, 0x{:x})".format(funcea, r.start, r.last))
            ease_end = EaseCode(r.start, r.last, forceStart=1, noExcept=1)
            if not isinstance(ease_end, integer_types):
                printi("[warn] EaseCode {:x}: {}".format(r.start, ease_end))
                msg = "[warn] couldn't append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) from {}".format(r.start, r.last, funcea, funcea, r.start, r.last, hex(old))
                globals()['warn'] += 1
                raise AdvanceFailure(msg)
            if ease_end != r.last:
                printi("[warn] ease_end {:x} != r.last {:x}".format(ease_end, r.last))
                #  pp([GetDisasm(x) for x in idautils.Heads(r.start, r.last)])
                [GetDisasm(x) for x in idautils.Heads(r.start, r.last)]
                r.last = ease_end
            ([idc.GetDisasm(x) for x in idautils.Heads(r.start, r.last)])
            #  ida_auto.auto_wait_range(r.start, r.last)
            #  Plan(r.start, r.last)
            #  idc.auto_wait()
            rv = idc.append_func_tail(funcea, r.start, r.last)
            if not rv:
                if GetChunkNumber(r.start, funcea) != -1:
                    printi("append_func_tail failed but we have a chunk number")
                ([GetDisasm(x) for x in idautils.Heads(r.start, r.last)])
            if not rv:
                for _ea in range(r.start + 1, r.last): # if len(list(idautils.Chunks(_ea))) > 1 and func.start_ea in GetChunkOwners(_ea) or \
                    if GetChunkNumber(funcea, _ea) != -1 or ida_funcs.get_func_chunknum(_func, _ea) != -1:
                        printi("now there's a chunknumber at {:x}".format(_ea))
                _ea = r.start
                _not_code = []
                while _ea < r.last:
                    printi("[debug] {:x} {}".format(_ea, idc.generate_disasm_line(_ea, GENDSM_MULTI_LINE | GENDSM_FORCE_CODE)))
                    if not IsCode_(_ea):
                        _not_code.append(_ea)
                        #  return False
                    _insn_len = IdaGetInsnLen(_ea)
                    if _insn_len:
                        _ea += _insn_len
                    else:
                        msg = "[ShowAppendFchunkReal] while checking we hit a non-code byte at {:x}".format(_ea)
                        raise AdvanceFailure(msg)
                    #  _ea = idc.next_head(_ea)
                if _not_code:
                    printi("[info] EaseCode(0x{:x})".format(r.start))
                    EaseCode(r.start, noExcept=1, ignoreMnem=['int', 'int3', 'ud2'])
                    _ea = r.start
                    _not_code = []
                    while _ea < r.last:
                        printi("[debug] {:x} {}".format(_ea, idc.generate_disasm_line(_ea, GENDSM_MULTI_LINE)))
                        if not IsCode_(_ea):
                            _not_code.append(_ea)
                        _ea = idc.next_head(_ea)
                    if _not_code:
                        printi("[info] append_func_tail not code at 0x{:x}".format(_ea))
                        globals()['warn'] += 1
                        return False
                #  if not IsCode_(r.last):
                    #  printi("[warn] append_func_tail not code at r.last 0x{:x}".format(r.last))
                    #  pass
                printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, r.start, r.last))
                rv = idc.append_func_tail(funcea, r.start, r.last)
                if not rv and GetChunkNumber(r.start, funcea) == -1:
                    #  printi("[warn] append_func_tail failed, checking range is valid {:x}\u2013{:x} for idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(r.start, r.last, funcea, r.start, r.last))
                    msg = "[warn] couldn't append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x}) from {}".format(r.start, r.last, funcea, funcea, r.start, r.last, hex(old))
                    globals()['warn'] += 1
                    raise AdvanceFailure(msg)
                    return False
                else:
                    printi("[info] succeeded! (rv:{}) append_func_tail {:x}\u2013{:x} to {:x} idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(rv, r.start, r.last, funcea, funcea, r.start, r.last))
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
        #  # printi("[info] not ours: {:x} {:x}".format(start, last))
        #  printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(funcea, start, end))
        #  return idc.append_func_tail(funcea, start, end)
        #  #  forceCode(start, end)
        #  #  return GetChunkEnd(start) == end # or idc.append_func_tail(funcea, start, end)
    #  if not not_ours:
        #  # printi("[info] not not_ours: {:x} {:x}".format(start, end))
        #  return 0
#  
    #  appendRanges = GenericRanger(not_ours)
#  
    #  results = []
    #  for r in appendRanges:
        #  printi("[info] appendRanged: {:x} {:x}".format(r.start, r.last))
        #  forceCode(r.start, r.last)
        #  printi("[info] append_func_tail: {:x} {:x}".format(r.start, r.start + r.length))
        #  printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(r.start, r.start + r.length))
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
    return EndOfFlow(ea)

    result = obfu.combEx(ea, 1024, oneChunk=1, includeNops=1, includeJumps=1)
    if result:
        if result[0]:
            return result[0][-1] + 1
    return ea + InsnLen(ea)

def _EndOfFlow(ea=None, soft=False, limit=16, ignoreInt=False):
    """
    _EndOfFlow

    @param ea: linear address
    """
    insn_start = eax(ea)
    owners = GetChunkOwners(insn_start)
    insn_end = insn_start + InsnLen(insn_start)
    flow_ending = False
    last_mnem = ''
    while limit and not flow_ending and GetChunkOwners(insn_end) == owners:
        #  insn_mnem = IdaGetMnem(insn_end)
        insn_len = InsnLen(insn_end)
        if isFlowEnd(insn_end, ignoreInt=ignoreInt or soft): 
            flow_ending = True
            # if soft and isInterrupt(insn_end) and insn_mnem != last_mnem: flow_ending = False
        if not insn_len:
            # printi("[EndOfFlow] no insn at {:x} {} | {}".format(insn_end, GetDisasm(insn_end), diida(insn_end)))
            break
        insn_end += insn_len
        limit -= 1
        #  last_mnem = insn_mnem
    return insn_end

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
    MyMakeUnknown(x, DELIT_EXPAND | DELIT_NOTRUNC, y - x)
    ida_auto.plan_range(x, y)
    ida_auto.auto_make_code(x)
    ida_auto.auto_wait()
    idc.plan_and_wait(x, y, 1)
    # SetFuncEnd(x, y)
    # ida_funcs.set_func_start(x, x)


def remake_func(ea):
    chunks = GetChunkAddresses(ea)
    for x, y in chunks:
        MyMakeUnknown(x, y - x, DELIT_EXPAND | DELIT_NOTRUNC)
    for x, y in chunks:
        ida_auto.revert_ida_decisions(x, y)
    for x, y in chunks:
        idc.remove_fchunk(ea, x)
        #  Plan(x, y)
    ida_auto.auto_make_proc(ea)
    ida_auto.auto_wait()


def reanal_func(ea):
    chunks = GetChunkAddresses(ea)
    for x, y in chunks:
        ida_auto.revert_ida_decisions(x, y)
    #  for x, y in chunks:
    #  Plan(x, y)
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

    # printi("0x%x: fix_non_func (%x/%x, (%x), %x)" % (realFnAddr, fnAddr, cstart, cend, flowEnd))

    #  printi("fix_non_func: {:x}\u2013{:x} and attach to {:x}".format(cstart, cend, realFnAddr))
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
    if debug: printi(("FixNonFunc::AppendFchunk( %x, %x, %x)" % (realFnAddr, fnAddr, flowEnd)))
    # A way to confirm we have a valid chunk to add too:
    targetChunk = idc.first_func_chunk(realFnAddr)
    if targetChunk == BADADDR:
        printi("Exception(\"bad chunk\")")

    printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(targetChunk, fnAddr, flowEnd))
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
    if not IsFunc_(funcea):
        return False 
    # global_chunks[funcea].update(idautils.Chunks(funcea))
    if IsTail(end):
        new_end = idc.get_item_head(end)
        printi("[warn] SetFuncEnd: end {:#x} is a tailbyte, did you mean {:#x}?".format(end, new_end))
        globals()['warn'] += 1
        # end = new_end
        return False
    if abs(funcea - end) > 65535:
        printi("[error] end {:x} too far from function start {:x}".format(end, funcea))
        return False
    ida_auto.plan_range(funcea, end)
    if not ida_funcs.set_func_end(funcea, end):
        printi("ida_funcs.set_func_end(0x{:x}, 0x{:x}) failed".format(funcea, end))
    idc.auto_wait()
    if not IsFunc_(funcea) or not IsFunc_(end):
        # printi("[warn] (2) Not an fchunk {:#x} or {:#x}".format(funcea, end))
        return True
    func_start = GetFuncStart(funcea)
    func_end = GetFuncEnd(funcea)
    cstart, cend = GetChunkStart(funcea), GetChunkEnd(funcea)
    # dprint("[SetFuncENd] funcea, func_start, end, func_end")
    if debug: printi("[SetFuncEnd] funcea:{:x}, end:{:x}, func_start:{:x}, func_end:{:x}".format(funcea, end, func_start, func_end))
    
    #  if cstart != func_start:
        #  printi("[warn] Not a head chunk, consider using SetChunkEnd | {:x}\u2013{:x}" \
                #  .format(
                    #  #  idc.get_func_name(func_start), 
                    #  #  func_start, func_end, 
                    #  #  idc.get_func_name(cstart), 
                    #  cstart, cend
                #  ))
        #  return SetChunkEnd(funcea, end)

    if debug: printi("func {}: {:x}\u2013{:x}  chunk {}: {:x}\u2013{:x}".format(idc.get_name(func_start), func_start, func_end, idc.get_name(cstart), cstart, cend))
    if end == cend:
        return True
    
    if not ida_funcs.is_same_func(funcea, idc.prev_head(end)):
        # if debug: printi("[warn] set_func_end: end {:#x} or {:#x} should be part of function {:#x} or {:#x}".format(end, idc.prev_head(end), func_start, funcea))
        printi("[warn] SetFuncEnd({:#x}, {:#x}) chunk owner '{}' does not match func owner '{}' | {:x}\u2013{:x}" \
                .format(
                    funcea,
                    end,
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
            #  printi("[debug] ptr is {:#x}".format(ptr))
            if IsFuncHead(ptr):
                heads.append(ptr)
                #  printi("[debug] adding head {:#x}".format(ptr))
            #  else:
                #  printi("[debug] not head {:#x}".format(ptr))
            ptr = idc.prev_head(ptr)
            if ida_funcs.is_same_func(funcea, ptr):
                happy = 1
                break
        if happy:
            if heads:
                printi("[info] deleting func_heads: {}".format(hex(heads)))
            for head in heads: 
                idc.del_func(head)
            ce = GetChunkEnd(ptr)
            idc.del_items(ce, DELIT_NOTRUNC, end-ce)
            printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(ptr, ce, end))
            if not idc.append_func_tail(ptr, ce, end):
                printi("[warn] idc.append_func_tail({:#x}, {:#x}, {:#x}) failed".format(ptr, ce, end))
                globals()['warn'] += 1
            else:
                printi("[info] idc.append_func_tail({:#x}, {:#x}, {:#x}) ok".format(ptr, ce, end))
    else:
        if idc.set_func_end(funcea, end):
            printi("[info] set_func_end({:#x}, {:#x})".format(funcea, end))
        else:
            printi("[warn] set_func_end({:#x}, {:#x}) failed".format(funcea, end))
            globals()['warn'] += 1
    result = GetChunkEnd(funcea)
    if not IsValidEA(result):
        printi("[warn] SetFuncEnd: Invalid GetChunkEnd({:#x}) == {:#x}".format(funcea, result))
        globals()['warn'] += 1
    if result != end:
        printi("[warn] SetFuncEnd: GetChunkEnd({:#x}) == {:#x}".format(funcea, result))
        globals()['warn'] += 1
        # raise Exception("Terrible")
    return result == end

def rangesAsChunks(_range):
    return [x.chunk() for x in _range]

def modify_chunks(funcea, chunks, keep=None, remove=None):
    global global_chunks
    # chunks = GenericRanger([GenericRange(x[0], x[1] - 1)           for x in _chunks],            sort = 1)
    # keep   = GenericRanger([GenericRange(a, a + IdaGetInsnLen(a) - 1) for a in slvars.justVisited], sort = 1)
    funcea = GetFuncStart(eax(funcea))
    # global_chunks[funcea].update(idautils.Chunks(funcea))
    if funcea & 0xff00000000000000:
        printi("[modify_chunks] bad funcea: {:x}".format(funcea))
        return False

    if not remove and not keep:
        return
    if remove is None:
        remove = difference(chunks, keep)
    elif keep is None:
        keep = difference(chunks, remove)

    #  remove = [x for x in remove if GetChunkNumber(x.start) > -1]
    #  if remove: printi("remove: \n{}".format(remove))

    # for c in [(x.start, x.end) for x in remove]:
    #    start, end = c
    for chunk in chunks:
        tail = clone_items(GetChunk(chunk.start))
        if not tail:
            printi("couldn't get tail from chunk.start {:x}".format(chunk.start))
            continue
            FixChunk(chunk.start, owner=funcea)
            continue
        subs = _.remove(remove, lambda x, *a: x.issubset(chunk))
        adds = _.remove(keep,   lambda x, *a: x.issubset(chunk))
        if subs: #  or adds:
            printi("super: {}  subs: {}  adds: {}".format(hex(chunk), subs, adds))

            cstart, cend = chunk.chunk()

            if subs:
                if subs[0].start == chunk.start and not IsChunk(tail):
                    msg = "can't trim start of head chunk: {}".format(describe_target(subs[0].start))
                    # raise ChunkFailure(msg)
                    return

                if len(subs) == 1 and subs[0].trend == cend or subs[0].start == cstart:
                    # might be more efficient to process this seperately, as we can
                    # trim a chunk in one op
                    start, end = subs[0].chunk()

                    if end == cend and start == cstart:
                        if debug: printi("idc.remove_fchunk(0x{:x}, 0x{:x})".format(funcea, start))
                        if not idc.remove_fchunk(funcea, start):
                            printi("[warn] cannot remove whole fchunk {}".format(describe_chunk(start, end)))
                            globals()['warn'] += 1
                        else:
                            if debug: printi("[info] removed whole fchunk {:#x} - {:#x}".format(start, end))
                    elif end == cend:
                        # same end, different start
                        if debug: printi("ida_funcs.set_func_end(0x{:x}, 0x{:x})".format(cstart, start))
                        if not ida_funcs.set_func_end(cstart, start): # and not SetFuncEnd(start, start):
                            printi("[warn] (1) cannot change end of {} to {:#x}".format(describe_chunk(cstart, cend), start))
                            globals()['warn'] += 1
                            return False
                        else:
                            printi("[info] (1) changed end of {} to {:#x}".format(describe_chunk(cstart, cend), start))
                    elif start == cstart:
                        # end's cannot match
                        if debug: printi("ida_funcs.set_func_start(0x{:x}, 0x{:x})".format(cstart, end))
                        if ida_funcs.set_func_start(cstart, end):
                            printi("[warn] (2) cannot change start of {} to {:#x}".format(describe_chunk(cstart, cend), end))
                            globals()['warn'] += 1
                            return False
                        else:
                            printi("[info] (2) changed start of {} to {:#x}".format(describe_chunk(cstart, cend), end))

                    continue
                
                # else count(subs) > 1
                # first remove entire chunk
                if not IsChunk(tail):
                    # head cannot be removed, trim instead
                    if not ida_funcs.set_func_end(cstart, subs[0].start):
                        printi("[warn] (4) cannot change end of {} to {:#x}".format(describe_chunk(cstart, cend), subs[0].start))
                        globals()['warn'] += 1
                        return False
                    else:
                        printi("[info] (4) changed end of {} to {:#x}".format(describe_chunk(cstart, cend), subs[0].start))
                        cend = subs[0].start
                else:
                    if not idc.remove_fchunk(funcea, cstart):
                        printi("[warn] (3) cannot remove whole fchunk {}".format(describe_chunk(cstart, cend)))
                        globals()['warn'] += 1
                        return False
                    else:
                        if debug: printi("[info] removed whole fchunk {:#x} - {:#x}".format(cstart, cend))
                        cstart = None
                        cend = None

            if adds:
                # then re-add the sections we want to keep
                for start, end in rangesAsChunks(adds):
                    if start != cstart:
                        printi("[info] adding {}".format(describe_chunk(start, end)))
                        # end = EaseCode(start, end, forceStart=1, noExcept=1, noFlow=1)
                        if isinstance(end, integer_types):
                            Plan(start, end, name='modify_chunks.add')
                            idc.append_func_tail(funcea, start, end)

    if remove:
        printi("unused remove subs: {}".format(remove))
    if keep:
        printi("unused keep subs: {}".format(keep))


    # global_chunks[funcea].update(idautils.Chunks(funcea))
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
        printi("groups: {}".format(groups))
        
        for cstart, addresses in groups.items():
            chunks = [GenericRange(cstart, trend=GetChunkEnd(cstart))]
            remove = GenericRanger([GenericRange(a, trend=a + IdaGetInsnLen(a)) for a in addresses], sort = 1)
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
            for val in value:
                result.append(transpose(val)) # , sourceRange[i], targetRange[i]))
            return result

        return (value - sourceRange[0]) * (targetRange[1] - targetRange[0]) / (sourceRange[1] - sourceRange[0]) + targetRange[0];
    return transpose

def transpose(value, sourceRange, targetRange):
    if isIterable(value):
        result = list()
        for v, s, t in zip(value, sourceRange, targetRange):
            result.append(make_transpose_fn(s, t)(v))
        return result
    
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
    printi("[call_everything] object_methods:{}".format(object_methods))
    
    can_call = []
    for method_name in object_methods:
        try:
            if callable(getattr(insn, method_name)):
                can_call.append(method_name)
        except AttributeError:
            pass
    # dprint("[call_everything] object_methods")
    printi("[call_everything] can_call:{}".format(can_call))
    should_call = []
    for method_name in can_call:
        if method_name[0].islower():
            try:
                argspec = inspect.getfullargspec(getattr(insn, method_name))
                printi("argspec: {}".format(argspec))
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
                printi("[debug] {} arglen:{}, len(args):{}, len(argspec.defaults):{}".format(method_name, arglen, len(args), len(argspec.defaults)))
                if arglen <= len(args):
                    should_call.append(method_name)
            except TypeError:
                doc = getattr(insn, method_name).__doc__
                if doc:
                    printi("doc: {}".format(doc))
                    args = string_between('(', ')', doc)
                    retn = string_between('->', '', doc).strip()
                    printi(retn, args)
                    if retn == 'int' and args:
                        args = args.split(',')
                        args = [x.strip() for x in args]
                        args = [x for x in args if x and x != 'self']
                        if len(args) == 0:
                            should_call.append(method_name)
    results = []
    # dprint("[debug] should_call")
    printi("[debug] should_call:{}".format(should_call))
    
    for method_name in should_call:
        try:
            printi("[calling] method_name:{}".format(method_name))
            result = getattr(insn, method_name)(*args)
            # dprint("[called] method_name, result")
            printi("[called] method_name:{}, result:{}".format(method_name, result))
            
            if isinstance(result, integer_types) and result > 9:
                result = hex(result)
            results.append((method_name, result))
        except Exception as e:
            pass
            # results.append((method_name, e))
    return results


def clone_items(insn, filter_iteratee=None):
    obj = SimpleAttrDict()
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
        printi("UnChunking fnName: %s" % fnName)
        fnLoc = LocByName(fnName)
        chunk_seq = idautils.Chunks(fnLoc)
        printi("0x%0x fnName: %s (chunk_seq: %s)" % (fnLoc, fnName, len(list(chunk_seq))))
        for chunk in chunk_seq:
            chunkStart = chunk[0]
            chunkEnd = chunk[1]
            chunkName = Name(chunk[0])
            printi("0x%0x - 0x%0x: %s" % (chunkStart, chunkEnd, chunkName))
            chunks.append(chunkStart)
            if len(chunks) > 1:
                printi("removing chunk")
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
        printi(xref.type, XrefTypeNames(xref.type),            
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
            printi("Looking up %s" % hex(addr))
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
        printi("deleting suspect jmpref: {:x} {}".format(a, diida(a)))
        ida_xref.del_cref(a, ea, 0)

    for a in dataRefs: 
        if SegName(a) != ".text": 
            segRefNames.add(SegName(a))
            segRefs.add(a)

    flowRefs  = (allRefs - jmpRefs) - callRefs
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
            printi("Looking up %s" % hex(addr))
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
    if not silent: printi("Chunks belonging to: %s" % fnName)

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

        if not silent: printi(" %s  %09x - %09x  %s " % (currentChunk, chunkStart, chunkEnd, refList[0] if refList else ""))

        if refList: refList.pop(0)
        for s in refList:
            if not silent: printi("%27s%s" % ("", s))

        if not silent: printi("")
    return chunks

def MicroChunks(funcea=None):
    """
    MicroChunks

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [MicroChunks(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    return split_chunks(list(idautils.Chunks(funcea)))

def split_chunks(chunks, endea=None, ignoreInt=False):
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

    if endea:
        chunks = [(chunks, endea)]
    if chunks:
        for startea, endea in chunks:
            # EaseCode(startea, forceStartIfHead=1)
            pos = startea
            for i in range(1000):
                # if debug > 1: printi("*** {:x} split_chunks".format(pos))
                insn_len = IdaGetInsnLen(pos)
                while (
                        insn_len and 
                        pos < endea and
                        (
                            pos == startea or 
                            IsFlow(pos) or 
                            (ignoreInt and isInterrupt(idc.prev_not_tail(pos)))
                        )
                    ):
                    # if debug > 1: printi("{:x} {}".format(pos, diida(pos)))
                    #  if not insn_len:
                        #  printi("[split_chunks] insn_len: {} at {:x}; ending chunk".format(insn_len, pos))
                        #  SetFuncOrChunkEnd(startea, pos)
                        #  endea = pos
                    if insn_len:
                        pos += IdaGetInsnLen(pos)
                        insn_len = IdaGetInsnLen(pos)
                # if debug > 1: printi("*** ".format(pos))
                
                if pos > startea:
                    yield startea, pos
                    if pos < endea:
                        startea = pos
                        continue
                break

def split_chunks_compact(chunks, ignoreInt=False):
    def _GetInsnLen(ea):
        i = ida_ua.insn_t(); l = ida_ua.decode_insn(i, ea); return l

    def _IsFlow(ea): return (idc.get_full_flags(ea) & idc.FF_FLOW) != 0

    for cs, ce in chunks:
        pos = cs
        for i in range(1000):
            insn_len = _GetInsnLen(pos)
            while (insn_len and pos < ce and (pos == cs or _IsFlow(pos))):
                if insn_len: pos += insn_len; insn_len = _GetInsnLen(pos)
            if pos > cs:
                yield cs, pos
                if pos < ce:
                    cs = pos; continue
            break


def _fix_spd_wrapper_compact(l):
    def fsc(l):
        l.sort()
        for i, x in enumerate(l):
            # ea = x[0]; csp = 0 - x[1]; asp = idc.get_spd(ea)
            csp, asp, ad = 0 - x[1], idc.get_spd(x[0]), idc.get_sp_delta(x[0]) 
            if asp is None or ad is None: return
            adj = csp - asp; nd = adj + ad
            if debug: printi("{} -- {:x} current spd: {:x}  desired spd: {:x}  current spdiff: {:x}  new spdiff: {:x}".format(i, x[0], asp, csp, ad, nd))
            if asp != csp:
                printi("{:4} -- {:x} adjusting delta from {:6x} to {:6x}     ({:>6x})".format(i, x[0], ad, nd, csp)) # adj, ad + adj))
                idc.add_user_stkpnt(x[0], nd); idc.auto_wait(); return True
    for r in range(1000):
        if not fsc(l):
            print("fsc failed"); break

def OurGetChunkStart(ea, chunks):
    _start = GetChunkStart(ea)
    if _start & 0xff00000000000000:
        return _start

    for cstart, cend in chunks:
        # dprint("[debug] cstart, cend, ea")
        #  printi("[debug] cstart:{:x}, cend:{:x}, ea:{:x}".format(cstart, cend, ea))
        
        if cstart <= ea < cend:
            #  printi("[debug] cstart:{:x}, cend:{:x}, ea:{:x} **FOUND**".format(cstart, cend, ea))
            return cstart

    if debug: printi("[OurGetChunkStart] couldn't find chunk for {:x}, returning GetChunkStart result: {:x}".format(ea, _start))
    return _start

def OurGetChunkEnd(ea, chunks):
    _start = GetChunkStart(ea)
    if _start & 0xff00000000000000:
        return _start

    for cstart, cend in chunks:
        #  dprint("[debug] cstart, cend, ea")
        # if debug > 1: printi("[debug] cstart:{:x}, cend:{:x}, ea:{:x}".format(cstart, cend, ea))
        
        if cstart <= ea < cend:
            # if debug > 1: printi("[debug] cstart:{:x}, cend:{:x}, ea:{:x} **FOUND**".format(cstart, cend, ea))
            return cend

    rv = GetChunkEnd(ea)
    printi("[OurGetChunkEnd] couldn't find chunk for {:x}, returning GetChunkEnd result: {:x}".format(ea, rv))
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
    return [(x["start"] - ida_ida.cvar.inf.min_ea, x["end"] - x["start"]) for x in chunks]
    # return [(x[0] - ida_ida.cvar.inf.min_ea, x[1] - x[0]) for x in chunks]


def CheckAllChunkForMultipleOwners():
    for ea in idautils.Functions():
      o = _.uniq(_.flatten(_.pluck(GetChunks(ERROREA()), 'owners')))
      if len(o) > 1:
        printi("{:x}".format(o))


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
            printi("Couldn't find function for chunk at {:x}".format(chunkAddr))
            return
    else:
        # https://stackoverflow.com/questions/8822701/how-to-printi-docstring-of-python-function-from-inside-the-function-itself
        printi(getdoc(globals()[getframeinfo(currentframe()).function]))

    if isinstance(chunkAddr, list):
        return [RemoveChunk(funcStart, ea) for ea in chunkAddr]

    funcStart = eax(funcStart)
    chunkAddr = eax(chunkAddr)
    chunkStart = GetChunkStart(chunkAddr)
    if chunkStart == funcStart or IsFuncHead(chunkStart):
        idc.del_func(funcStart)
    else:
        try:
            return idc.remove_fchunk(funcStart, chunkAddr)
        except TypeError as e:
            # dprint("[RemoveChunk] funcStart, chunkAddr")
            print("[RemoveChunk] funcStart:{}, chunkAddr:{}".format(hex(funcStart), hex(chunkAddr)))
            raise
        

def RemoveThisChunk(ea = 0):
    """RemoveThisChunk.

    Args:
        ea:
    """
    ea = eax(ea)

    try:
        chunks = GetChunks(ea)
        if len(chunks) < 2:
            #  printi("0x%x: This is not a chunk" % ea)
            return False

        for chunk in chunks:
            if chunk['current']:
                if chunks[0]['start'] == chunk['start']:
                    #  printi("0x%x: Cannot remove primary chunk" % ea)
                    return False
                #  printi("calling RemoveFChunk")
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
                printi("[RemoveAllChunkOwners] couldn't remove chunk {:x}".format(ea))
    if last: #  and not leave:
        idc.remove_fchunk(last, ea)
        printi("[RemoveAllChunkOwners] couldn't remove last chunk {:x}".format(ea))

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
            # printi("0x%x: There are no chunks" % ea)
            return chunk_list

        l = list(idautils.Chunks(ea))
        for start, end in l:
            idc.remove_fchunk(GetFuncStart(ea), start)

    return chunk_list

def GetFuncType(funcea=None):
    """
    GetFuncType

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [GetFuncType(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    if not IsFuncHead(funcea):
        return None
    
    #  GN_VISIBLE = ida_name.GN_VISIBLE     # replace forbidden characters by SUBSTCHAR
    #  GN_COLORED = ida_name.GN_COLORED     # return colored name
    #  GN_DEMANGLED = ida_name.GN_DEMANGLED # return demangled name
    #  GN_STRICT = ida_name.GN_STRICT       # fail if cannot demangle
    #  GN_SHORT = ida_name.GN_SHORT         # use short form of demangled name
    #  GN_LONG = ida_name.GN_LONG           # use long form of demangled name
    #  GN_LOCAL = ida_name.GN_LOCAL         # try to get local name first; if failed, get global
    #  GN_ISRET = ida_name.GN_ISRET         # for dummy names: use retloc
    #  GN_NOT_ISRET = ida_name.GN_NOT_ISRET # for dummy names: do not use retloc
    fnName = idc.get_name(funcea, ida_name.GN_VISIBLE)
    if not fnName:
        fnName = "invalid"
    fnType = idc.get_type(funcea) 
    if fnType:
        return fnType.replace('(', ' ' + fnName + '(', 1)

    return None

def MyGetType(ea=None):
    """
    MyGetType

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [MyGetType(x) for x in ea]

    ea = eax(ea)
    
    if IsFuncHead(ea):
        return GetFuncType(ea)
    return idc.get_type(ea)

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
    # return lambda x: ida_bytes.create_data(x, ff_size, size, ida_idaapi.BADADDR)
    return lambda x: (MyMakeUnknown(x, size, 0), ida_bytes.create_data(x, ff_size, size, ida_idaapi.BADADDR))[1]


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
        function_chunks.append((chunk.start_ea, chunk.end_ea))

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

    if idc.selector_by_name('.text2') != BADADDR:
        return False

    if start_ea is None:
        existing_segment_starts = idautils.Segments()
        existing_segment_ends = [idc.get_segm_end(x) for x in existing_segment_starts]
        start_ea = max(existing_segment_ends)

    s = ida_segment.segment_t()
    s.start_ea = start_ea
    s.end_ea   = start_ea + size
    s.sel      = ida_segment.setup_selector(base)
    s.bitness  = use32
    s.align    = align
    s.comb     = comb
    s.perm     = 7
    r = ida_segment.add_segm_ex(s, ".text2", "CODE", flags)
    # if r:
    idc.set_segm_type(start_ea, idc.SEG_CODE)
    # idc.set_segm_attr(start_ea, SEGATTR_PERM, 7)
    try:
        LabelAddressPlus(start_ea, "next_relocation", force = 1)
    except:
        pass
    
    return r

def _fix_spd(l, addresses=None):
    # l = [ (0x140a5b4aa, 0x088), (0x140a68a7b, 0x088), (0x140a68a85, 0x088), (0x140a68aee, 0x088), (0x140aa42fc, 0x088), (0x140cc9241, 0x088), (0x140d09565, 0x000), (0x140d628c9, 0x090), (0x14181d848, 0x088), (0x14181d84c, 0x088), (0x141846c20, 0x088), (0x1433177ab, 0x088), (0x1433177b2, 0x088), (0x1433177b6, 0x088), (0x1433177bd, 0x088), (0x143dd53f9, 0x088), (0x143dd53ff, 0x088), (0x143dd5405, 0x088), (0x143e42f40, 0x088), (0x143ebb984, 0x008), (0x143ebb985, 0x000), (0x143ebb989, 0x000), (0x143ebb98d, 0x000), (0x14411a3bb, 0x088), (0x14411a3bf, 0x088), (0x14412d699, 0x088), (0x14412d6a0, 0x088), (0x1443caa98, 0x088), (0x1443caa9d, 0x088), (0x1443caaa3, 0x088), (0x1443caaa8, 0x088), (0x1445eeb3c, 0x088), (0x144600c8d, 0x088), (0x14460b1ca, 0x088), (0x14460b1cc, 0x088), (0x14462c33e, 0x088), (0x14462c343, 0x088), (0x144633381, 0x088), (0x144633389, 0x088), (0x14463338d, 0x088), (0x144633391, 0x088), (0x144633395, 0x008), (0x14463339e, 0x000), (0x144655b81, 0x088), (0x144655b86, 0x088), (0x144655b8b, 0x088), (0x144655b90, 0x088), (0x144679c94, 0x088), (0x1446931e9, 0x088), (0x1446931ed, 0x088), (0x1446931f4, 0x088), (0x1446931f8, 0x088), (0x1446fb1b4, 0x088), (0x1446fb1ba, 0x088), (0x1447227f7, 0x008), (0x1447227fe, 0x088), (0x144722803, 0x088) ]
    if addresses is None:
        addresses = set()
    l.sort()
    # r = [ (hex(GetSpd(e)), hex(f), hex(e)) for e, f in l ]
    # pp(r)

    # _chunks = list(split_chunks(idautils.Chunks(l[0][0])))

    for i, x in enumerate(l):
        ea = x[0]
        # if debug: printi("[_fix_spd] {:x} {:x}".format(ea, x[1]))
        #  fnStart = GetFuncStart(ea)
        #  chunkStart = OurGetChunkStart(ea, _chunks)
        #  if chunkStart == fnStart:
            #  continue

        #  if not chunkStart == ea:
            #  continue
        
        correct_sp = 0 - x[1]   # -0x88
        actual_sp = idc.get_spd(ea)  # -0x8
        actual_delta = idc.get_sp_delta(ea) # -0x8
        if actual_sp is None or actual_delta is None:
            return False

        adjust = correct_sp - actual_sp # -0x88 - -0x8 == -0x80
        new_delta = adjust + actual_delta
        if debug: printi("{} -- {:x} current spd: {:x}  desired spd: {:x}  current spdiff: {:x}  new spdiff: {:x}".format(i, ea, actual_sp, correct_sp, actual_delta, new_delta))
        if actual_sp != correct_sp:
            printi("{:4} -- {:x} adjusting delta from {:6x} to {:6x}     ({:>6x})".format(i, ea, actual_delta, new_delta, correct_sp)) # adjust, actual_delta + adjust))
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
            printi("[_fix_spd_auto] RelocationStackError: {}".format(e.args))
            return
        except BaseException as e:
            printi("[_fix_spd_auto] BaseException: {}: {}".format(str(e), e.args))
            return
    else:
        spdList = funcea
    for r in range(10000):
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

    printi(sl)

    m = re.search(sl, s)
    if m:
        correctTarget = GetTarget(ea)
        # Not sure it can be code, otherwise it would have a proper label.. but
        # it might be part of a higher CodeHead
        g = m.groupdict()
        a = "%s %s" % (g['mnem'], hex(correctTarget))
        printi("correctAsm: " + a)
        insnlen = IdaGetInsnLen(ea)
        end = ea + insnlen
        start = ea
        while IsFlow(start) and isNop(idc.prev_head(start)):
            start = idc.prev_head(start)
        offset = ea - start
        nassemble(start, a, apply=1)
        PatchNops(start + insnlen, offset)

def fix_location_plus_2(ea, code=False):
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
        if debug: printi("correctTarget: " + hex(correctTarget))
        code = code or idc.is_code(ida_bytes.get_flags(idc.get_item_head(correctTarget)))

        #  if code:
            #  #  printi("ccccode")
            #  #  fix_loc_offset('loc_14064E290+2')
            #  MyMakeUnkn(correctTarget, 0)
            #  if code:
                #  MakeCodeAndWait(correctTarget + offset, force = 1)
            #  else:
                #  printi("0x%x: not code: " % (correctTarget + offset))

        dtype, dtyp_size = get_dtype(ea, opNum)
        _make_x = get_create_data_func(dtyp_size)
        MyMakeUnknown(idc.get_item_head(correctTarget), 1, DELIT_NOTRUNC)
        MyMakeUnknown(correctTarget, dtyp_size, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_NOTRUNC)
        MyMakeUnkn(correctTarget, DELIT_NOTRUNC)
        if code:
            idc.create_insn(correctTarget)
        idc.auto_wait()
        if code:
            idc.create_insn(correctTarget) or forceAsCode(correctTarget)
        result = _make_x(correctTarget)
        if not result:
            printi("couldn't turn {:x} into nice little data type (size: {})".format(correctTarget, dtyp_size))
        else:
            idc.auto_wait()
            if debug: printi("turned {} into {}".format(ida_lines.tag_remove(m.group(1)), get_name_by_any(correctTarget) or "..."))
            #  if code: MakeCodeAndWait(loc + offset, force = 1)

def FunctionsPdata():
    start_ea = idc.get_segm_start(eax('.pdata'))
    end_ea = idc.get_segm_end(eax('.pdata'))
    for ea in range(start_ea, end_ea, 4 * 3):
        start, end, handler = struct.unpack('III', ida_bytes.get_bytes(ea, 12))
        start += ida_ida.cvar.inf.min_ea
        if IsValidEA(start):
            yield start

def remove_crappy_funcs():
    pdaddy = set(FunctionsPdata())
    all = set(idautils.Functions())
    lame = all - pdaddy
    # dprint("[remove_crappy_funcs] len(pdaddy), len(all), len(lame)")
    print("[remove_crappy_funcs] len(pdaddy):{}, len(all):{}, len(lame):{}".format(len(pdaddy), len(all), len(lame)))
    
    for ea in lame:
        if idc.get_name(ea, ida_name.GN_VISIBLE).startswith('sub_'):
            idc.del_func(ea)

def populate_functions_from_pdata(iteratee=None, *args, **kwargs):
    start_ea = idc.get_segm_start(eax('.pdata'))
    end_ea = idc.get_segm_end(eax('.pdata'))
    for ea in range(start_ea, end_ea, 4 * 3):
        start, end, handler = struct.unpack('III', ida_bytes.get_bytes(ea, 12))
        start += ida_ida.cvar.inf.min_ea
        end += ida_ida.cvar.inf.min_ea
        idc.add_func(start, end)
        #  if idc.get_name(start, ida_name.GN_VISIBLE).startswith('pdub_'):
            #  LabelAddressPlus(start, '')
        # LabelAddressPlus(start, 'pdub_{:x}'.format(start))
        if iteratee:
            iteratee(start, *args, **kwargs)

def get_pdata_fnStart(ea=None):
    """
    get_pdata_fnStart

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [get_pdata_fnStart(x) for x in ea]

    ea = eax(ea)

    found = 0
    for ref in idautils.XrefsTo(ea):
        addr = ref.frm
        if idc.get_segm_name(addr) == '.pdata':
            unwind_info = ([x + ida_ida.cvar.inf.min_ea for x in struct.unpack('lll', get_bytes(addr, 12))])
            if ea == unwind_info[0]:
                return ea

    return idc.BADADDR

def isPdata(ea=None):
    """
    isPdata

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [isPdata(x) for x in ea]

    ea = eax(ea)
    return get_pdata_fnStart(ea) == ea



def fix_dualowned_chunk(ea):
    tail = GetChunk(ea)
    if not tail:
        return
    if tail.refqty < 2:
        return 
    if not tail.flags & ida_funcs.FUNC_TAIL:
        return 
    cstart = tail.start_ea
    # printi("[info] fixing tail chunk @ {:x}".format(ea))
    labellen = 0
    idc.jumpto(tail.start_ea)
    fnNames = []
    fnLocs = []
    cName = idc.get_name(tail.start_ea, GN_VISIBLE).lower()
    while tail and tail.flags & ida_funcs.FUNC_TAIL: 
        fnName = idc.get_name(tail.owner, GN_VISIBLE).lower()
        fnLocs.append(tail.owner)
        fnNames.append(fnName)
        printi("removing owner: {} from {:x} ({})".format(fnName, tail.start_ea, idc.get_name(tail.start_ea, GN_VISIBLE)))
        func = ida_funcs.get_func(tail.owner)
        if not ida_funcs.remove_func_tail(func, tail.start_ea):
            printi("[warn] couldn't remove tail chunk {:x} from {:x}".format(tail.start_ea, tail.owner))
            globals()['warn'] += 1
            return
        else:
            printi("[info] removed tail chunk {:x} from {:x}".format(tail.start_ea, tail.owner))

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
                #  printi("Ignoring dissimilar location name: {}".format(cName))    
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
        # j:printi("[warn] couldn't make func @ {:x} (please make manually)".format(ea))
        return

    return True
    
def fix_dualowned_chunks():
    fix_queue = []
    printi("fixing double-owned chunks")
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
    refs = [x for x in genAsList(idautils.CodeRefsTo(ea, 0)) if idc.get_func_name(x) and IdaGetMnem(x).startswith('j') and MyGetInstructionLength(x) > 2]
    callrefs = [x for x in genAsList(idautils.CodeRefsTo(ea, 0)) if idc.get_func_name(x) and IdaGetMnem(x).startswith('call') and MyGetInstructionLength(x) > 2]
    if callrefs:
        if ea not in calledimpls:
            calledimpls.append(ea)
            for crf in callrefs:
                printi("[info] certified callref for {:x} from {} at {:x}".format(ea, idc.get_func_name(crf), crf))
        return ea

    refmap = dict()
    for ref in refs:
        if not ida_funcs.is_same_func(ea, ref):
            refmap[idc.get_func_name(ref)] = ref
    keys = genAsList(refmap.keys())
    pri = _.groupBy(keys, name_priority)
    pri2 = _(keys).chain().without(9).value()
    pri2.sort()
    printi("pri2: {}".format(pf(pri2)))
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
    MakeUnknown(ea, 6, idc.DELIT_EXPAND | ida_bytes.DELIT_NOTRUNC | ida_bytes.DELIT_NOTRUNC)
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
            printi(hex(ea), ip, hex(r))
            pins[ea] = 'x'
        else:
            pins[ea] = '.'

    #  return pins
    #

def EaseCode(ea, *args, **kwargs):
    run_twice = lambda *args, **kwargs: _.last(_.times(2, lambda *a: _EaseCode(*args, **kwargs)))
    if isinstance(ea, list):
        return [run_twice(x, *args, **kwargs) for x in ea]
    try:
        return run_twice(ea, *args, **kwargs)
    except Exception as e:
        printi("[_EaseCode] {:#x}: Initial Exception: {}: {} (will try again)".format(ea, e.__class__.__name__, str(e)))
        return run_twice(ea, *args, **kwargs)

bad_insns = getglobal('bad_insns', default=set())

def _EaseCode(ea=None, end=None, forceStart=False, check=False, verbose=False,
        forceStartIfHead=False, noExcept=False, noFlow=False, unpatch=False,
        ignoreInt=False, ignoreMnem=None, create=None, fixChunks=False,
        origin=None):
    """
    EaseCode

    @param ea: linear address
    """
    global bad_insns
    ignoreMnem = A(ignoreMnem)
    ea = eax(ea)
    if not IsValidEA(ea):
        if noExcept:
            return ea
        raise AdvanceFailure("Invalid Address 0x{:x}".format(ea))
    if verbose and debug:
        printi("[EaseCode] {:x}".format(ea))
    if verbose and debug: 
        printi("[EaseCode] {:x}".format(ea))
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        printi((" -> ".join(stk)))
    #  d = ["{:x} {}".format(x, idc.generate_disasm_line(x, 0)) for x in range(ea, end or (ea+0x1000)) if not IsTail(x)]
    #  if verbose and debug:
        #  printi("[EaseCode] pre-disasm\n{}".format("\n".join(d)))
    if IsValidEA(idc.get_qword(ea)):
        idc.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)
        return ea + 8

    _bad_mnems = ['ret', 'retn', 'retnw', 'jmp', 'int', 'int1', 'int3', 'ud2', 'leave', 'iret', 'retf']
    if ignoreInt:
        if verbose and debug: printi("[EaseCode] ignoreInt")
        _bad_mnems = _.without(_bad_mnems, 'int', 'ud2', 'int1', 'int3')
    
    if not IsCode_(ea):
        if verbose and debug: printi("{:#x} not IsCode: {}".format(ea, diida(ea)))
        if forceStartIfHead and IsHead(ea):
            r = forceCode(ea, IdaGetInsnLen(ea), origin=origin)
            if verbose and debug: printi("forceStartIfHead: {:x} {}".format(ea, diida(ea)))
        elif forceStart:
            try:
                r = forceCode(ea, IdaGetInsnLen(ea), origin=origin)
            except AdvanceFailure as e:
                if noExcept:
                    return e
                raise
            if verbose and debug: printi("forceStart: {:x} {}".format(ea, diida(ea)))
        elif not idc.create_insn(ea):
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))
            else:
                raise AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))

    ida_auto.revert_ida_decisions(ea, IdaGetInsnLen(ea))
    ida_auto.auto_recreate_insn(ea)
    start_ea = ea
    prev_ea = ea
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
            prev_ea = ea
            ea = ea + insn_len
            if prev_ea == start_ea and at_flow_end:
                if verbose and debug:
                    printi("[EaseCode] ignoring at_flow_end during second loop")
                at_flow_end = False
            if at_end or at_flow_end:
                if verbose and debug:
                    # dprint("[_EaseCode] at_end, at_flow_end")
                    print("[_EaseCode] at_end:{}, at_flow_end:{}".format(at_end, at_flow_end))
                    
                break

        if unpatch:
            UnPatch(ea, ea + 15)

        idc.GetDisasm(ea)
        idc.auto_wait()
        insn_len = IdaGetInsnLen(ea)
        if not insn_len:
            bad_insns.add(ea)
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
            raise AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
        _owners = GetChunkOwners(ea, includeOwner=1)
        if _owners:
            if _owners != owners:
                if verbose and debug: printi("[EaseCode] _owners != owners; break")
                break
        else:
            owners = _owners

        unhandled = code = tail = unknown = flow = False
        next_head = idc.next_head(ea)
        mnem = ''

        if IsCode_(ea):
            # if verbose and debug: printi("0x{:x} IsCode".format(ea))
            code = True
            mnem = IdaGetMnem(ea)
            if isFlowEnd(mnem, ignoreInt=ignoreInt):
                if verbose and debug: printi("0x{:x} isFlowEnd({})".format(ea, mnem))
                at_end = True
            if create: # or mnem.startswith(('ret', 'jmp', 'int', 'ud2', 'leave')):
                # raise RuntimeError("don't")
                ida_auto.revert_ida_decisions(ea, IdaGetInsnLen(ea))
                ida_auto.auto_recreate_insn(ea)
                idc.auto_wait()

        else:
            if IsTail(ea):
                if verbose and debug: printi("0x{:x} IsTail".format(ea))
                tail = True
            elif IsUnknown(ea) or IsData(ea):
                if verbose and debug: printi("0x{:x} IsUnknown".format(ea))
                unknown = True
            else:
                if verbose and debug: printi("0x{:x} NFI".format(ea))
                # unknown = True
        if not (code or tail or unknown):
            if verbose and debug: printi("0x{:x} unhandled flags".format(ea))
            if verbose and debug: debug_fflags(ea)
        if ignoreInt and isInterrupt(prev_ea):
            if verbose and debug: printi("0x{:x} Forcing Flow (ignoreInt) ({}) +{}".format(ea, mnem, insn_len))
            flow = True
        elif IsFlowEx(ea, ignoreInt=ignoreInt):
            if verbose and debug: printi("0x{:x} IsFlow ({}) +{}".format(ea, mnem, insn_len))
            flow = True
        elif ea != start_ea:
            prev_mnem = IdaGetMnem(prev_ea)
            if prev_mnem not in _bad_mnems:
                # TODO: now that GetTarget is more expansive, we should check this
                if prev_mnem != 'call' or ida_funcs.func_does_return(GetTarget(prev_ea)):
                    if verbose and debug: printi("{:x} Flow ended {:x} with '{}' (fixing)".format(ea, prev_ea, prev_mnem))
                    if fixChunks:
                        _fixChunk = True
                    ida_auto.auto_recreate_insn(prev_ea)
                    ida_auto.auto_wait()
                    GetDisasm(prev_ea)
                    flow = True
            else:
                if verbose and debug: printi("0x{:x} Unflow-ish mnemonic {}".format(ea, mnem))

        # TODO: amalgamate these two, they're basically the same
        if code and isFlowEnd(ea, ignoreInt=ignoreInt):
            if verbose and debug: printi("0x{:x} code and isFlowEnd; at_end".format(ea))
            ida_auto.auto_recreate_insn(ea)
            at_flow_end = True
        elif not flow: #  or isFlowEnd(ea):
            if not noFlow and mnem not in ignoreMnem:
                if verbose and debug: printi("0x{:x} no flow; at_end".format(ea))
                at_flow_end = True

        if tail:
            if verbose and debug: printi("0x{:x} tail; break".format(ea))
            break

        if unknown:
            # dprint("[debug] next_head, ea, insn_len")
            if verbose and debug: printi("[debug] next_head:{:x}, ea:{:x}, insn_len:{:x}".format(next_head, ea, insn_len))
            
            if next_head == ea + insn_len:
                pass
                #  printi("0x{:x} next_head == ea + insn_len".format(ea))
            elif next_head > ea + insn_len:
                pass
                #  printi("0x{:x} next_head > ea + insn_len".format(ea))
            else:
                #  printi("0x{:x} next_head < ea + insn_len; forcing space to instruction".format(ea))

                idaapi.del_items(ea, ida_bytes.DELIT_NOTRUNC, insn_len)

            if not idc.create_insn(ea):
                if verbose and debug: printi("0x{:x} couldn't idc.make_insn(0x{:x}); break".format(ea, ea))
                break

    if unpatch:
        UnPatch(start_ea, ea)

    #  Plan(start_ea, ea)

    #  ida_auto.plan_range(start_ea, ea)
    #  idc.auto_wait()
    if _fixChunk and GetChunkEnd(start_ea) < ea:
        SetFuncOrChunkEnd(start_ea, ea)

    if check:
        for addr in idautils.Heads(start_ea, ea):
            if isUnlikely(addr):
                if verbose: printi("unlikely: {} at {:x}".format(diida(addr), addr))
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
    patterns = [
                "48 05 f8 ff ff ff"
                "48 87 ?? 24", 
                "48 89 ?? 24", 
                "48 89 c4",
                "48 89 e0",
                "48 8b ?? 24 10",
                "48 8d 2d ?? ?? ?? ??",
                "48 8d ?? 24", 
                "55 48 8d 2d", 
                "55 48 bd", 
                ]
    """
                "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3", 
                "48 89 e0 48 05 f8 ff ff ff 48 89 c4 48 89 1c 24", 
                "55 48 bd ?? ?? ?? ?? ?? ?? 00 00 48 87 2c 24 ?? ?? 48 8b ?? 24 10 48 ?? ?? ?? ?? ?? ?? ?? 00 00 48 0f ?? ?? 48 89 ?? 24 10 ?? ?? c3", 
                "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24", 
                "48 89 6c 24 f8 48 8d 64 24 f8", 
                "48 8d 64 24 f8 48 89 2c 24", 
                "48 89 5c 24 f8 48 8d 64 24 f8", 
                "48 8d 64 24 f8 48 89 1c 24", 
                "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3",
                "48 8d 64 24 08 ff 64 24 f8", 
    """

    found = set()
    with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
        for pattern in patterns:
            for ea in FindInSegments(pattern, '.text'):
                if ea not in found:
                    found.add(ea)
    return found
                    # ida_retrace(ea, zero=0, smart=0, calls=1, forceRemoveFuncs=1, ignoreChunks=1)
                # obfu.patch(ea)
                #  if not IsCode_(ea):
                    #  EaseCode(ea, forceStart=1)
                #  t0 = time.time()
                #  try:
                    #  while obfu.patch(ea, len(pattern) + 32)[0]:
                        #  t1 = time.time()
                        #  printi("took: {}".format(t1 - t0))
                #  except RelocationAssemblerError:
                    #  pass


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

def GetFuncStartOrEa(ea=None):
    ea = eax(ea)
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    if isinstance(ea, list):
        return [GetFuncStartOrEa(x) for x in ea]

    func = ida_funcs.get_func(ea)
    if not func:
        return ea
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
        Create an instruction at the specified address, and idc.auto_wait() afterwards.
        
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
        if debug: printi("0x%x: %s %s" % (ea, comment, GetDisasm(ea)))
        count = 0
        insLen = 0
        # This should work, as long as we are not started mid-stream
        while not insLen and count < 16: #  and idc.next_head(ea) != NextNotTail(ea):
            count += 1
            MyMakeUnknown(ea, EndOfContig(ea) - ea, 0)
            idc.auto_wait()
            insLen = MakeCodeAndWait(ea)
            #  printi("0x%x: MakeCodeAndWait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
        if count > 0:
            if debug: printi("0x%x: MakeCodeAndWait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
    # ida_auto.plan_ea(ea)
    return 1
    return

    if IsCode_(ea):
        if debug: printi("0x%x: Already Code" % ea)
        return IdaGetInsnLen(ea)

    if Byte(ea) == 0xcc:
        # printi("0x%x: %s can't make 0xCC into code" % (ea, comment))
        return 0

    while IsData(ea):
        if debug: printi("0x%x: MakeCodeAndWait - FF_DATA - MyMakeUnknown" % ea)
        MyMakeUnknown(ItemHead(ea), NextNotTail(ea) - ItemHead(ea), 0)
        idc.auto_wait()

    if isTail(idc.get_full_flags(ea)):
        if debug: printi("0x%x: Tail" % ea)
        MyMakeUnknown(ItemHead(ea), ea - ItemHead(ea), 0)

    if not MakeCode(ea):
        if debug: printi("0x%x: MakeCodeMakeUnknown" % ea)
        MyMakeUnknown(ea, 1, 0)
    insLen = MakeCode(ea)
    if insLen == 0:
        if force:
            if debug: printi("0x%x: %s %s" % (ea, comment, GetDisasm(ea)))
            count = 0
            # This should work, as long as we are not started mid-stream
            while not insLen and count < 16: #  and idc.next_head(ea) != NextNotTail(ea):
                count += 1
                MyMakeUnknown(ItemHead(ea), count, 0)
                idc.auto_wait()
                insLen = MakeCodeAndWait(ea)
                #  printi("0x%x: MakeCodeAndWait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
            if count > 0:
                if debug: printi("0x%x: MakeCodeAndWait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
    #  printi("0x%x: MakeCodeAndWait returning %i" % (ea, count))
    idc.auto_wait()
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
        if isinstance(start, list):
            return [forceCode(x) for x in start]

        ea = eax(start)
        ValidateEA(ea, origin=origin)
        log.append("start: {:x}".format(ea))
        if ea == idc.BADADDR or not ea:
            return (0, 0, 0, 0)
        end = end or IdaGetInsnLen(start) or 15
        if end < idaapi.cvar.inf.min_ea and end < start:
            end = start + end
        log.append("end: {:x}".format(end))

        if ea == forceCode.last:
            if _.all(forceCode.last, lambda x, *a: x == ea):
                raise RuntimeError("Repeated calls for forceCode for same address")
        forceCode.last.append(ea)

        if debug:
            # dprint("[forceCode] start, end, trim, delay")
            printi("[forceCode] start:{:x}, end:{:x}, trim:{}, delay:{}".format(start, end, trim, delay))
            
        last_jmp_or_ret = 0
        last_addr = 0
        trimmed_end = 0
        happy = 0
        # dprint("[forceCode] start")
        #  printi("[forceCode] start:{:x}".format(start))
        
        func_end = GetFuncEnd(start)
        # dprint("[forceCode] func_end")
        #  printi("[forceCode] func_end:{:x}".format(func_end))
        
        func_start = GetFuncStart(start)
        chunk_end = GetChunkEnd(start)
        chunk_start = GetChunkStart(start)
        if debug:
            printi("func_start: {}, func_end: {}".format(hex(func_start), hex(func_end)))
            printi("chunk_start: {}, chunk_end: {}".format(hex(func_start), hex(func_end)))
        
        #  idc.del_items(start, idc.DELIT_EXPAND, end - start)
        if IdaGetInsnLen(ea) == 2 and GetMnemDi(ea) == 'push' and IdaGetMnem(ea) == '':
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
                    printi("[warn] item_head == ea {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                #  if not idc.del_items(ea, 0, 1):
                if not idc.MakeUnknown(ea, 1, 0):
                    printi("[warn] couldn't del item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                else:
                    if debug: printi("[debug] deleted item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))

            if idc.is_code(idc.get_full_flags(ea)):
                # seems to be that deleting the code and remaking it is the only way to ensure everything works ok
                # .. and it seems that deleting and remaking triggered stupid stupid things like the generation of nullsubs out of `retn` statements
                # .. but i think we will cheat and match the instruction against GetFuncEnd, since undefining the end of a chunk is what shrinks it.
                if False:
                    if debug: printi("[info] code deleting already existing instruction at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, ea, start, end))
                    if not idc.del_items(ea, 0, idc.get_item_size(ea)):
                        printi("[warn] couldn't del item({:x}, 0, get_item_size) | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                    else:
                        if debug: printi("[debug] deleted item({:x}, 0, get_item_size) | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
                else:
                    insn_len = idc.get_item_size(ea)
                    if debug: printi("[info] {:x} code exists for {} bytes | {}".format(ea, insn_len, idc.generate_disasm_line(ea, 0)))
                    ea += insn_len
                    happy = 1
            if not happy:
                insn_len = idc.create_insn(ea)
                if debug: printi("[info] (1) idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))
                if not insn_len:
                    # this
                    if debug: printi("MyMakeUnknown(0x{:x}, {}, DELIT_DELNAMES | DELIT_NOTRUNC)".format(ea, IdaGetInsnLen(ea)))
                    MyMakeUnknown(ea, IdaGetInsnLen(ea), DELIT_DELNAMES | DELIT_NOTRUNC)
                    # or this (same result)
                    for r in range(ea + 1, IdaGetInsnLen(ea)):
                        if HasAnyName(r):
                            LabelAddressPlus(r, '')
                            if debug: printi("[info] removing label at {:x}".format(r))
                    insn_len = idc.create_insn(ea)
                    if debug: printi("[info] (2) idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))
                    if insn_len == 0:
                        if origin and UnpatchUntilChunk(origin):
                            raise AdvanceReverse(origin)


                # restore function end if we just removed the last insn in a chunk
                if insn_len and insn_len + ea == chunk_end:
                    if debug: printi("[info] restoring chunk_end to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(chunk_end, chunk_start, start, end))
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
                        msg = "[warn] (1) couldn't create instruction at {:x}".format(ea)
                        # bad_insns.add(ea)
                        printi("{}\n{}".format(msg, '\n'.join(log)))
                        raise AdvanceFailure(msg)
                    else:
                        printi("[warn] (2) couldn't create instruction at {:x}, shortening chunk to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, trimmed_end, ea, start, end))
                        if idc.get_func_name(start):
                            if not idc.set_func_end(start, trimmed_end):
                                printi("[warn] couldn't set func end at {:x} or {:x} or {:x} or {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(end, last_jmp_or_ret, last_addr, ea, start, start, end))
                        idc.del_items(end, 0, end - trimmed_end)
                else:
                    happy = 1
                    ea += insn_len

            if not happy:
                return (ea-start, start, end, trimmed_end)

            mnem = IdaGetMnem(last_addr).split(' ', 2)[0]
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
    if MyMakeUnknown(head, length + (ea - head), DELIT_EXPAND | DELIT_NOTRUNC) == False:
        printi("0x%x: Couldn't make unknown at 0x%x" % (ea, head))
        return 0
    idc.auto_wait()
    pos = ea
    end = ea + length
    while pos < end:
        #  codeLen = MakeCodeAndWait(pos, comment=comment)
        codeLen = forceCode(ea, length)[0]
        if codeLen:
            if not IsFunc_(pos):
                printi("Couldn't convert block into code even though it said we did 0x%x" % pos)
                break
            pos += codeLen
        else:
            printi("0x%x: Couldn't convert block into code at 0x%x (remaining length: %i)" % (ea, head, end - pos))
            raise "trace that broken code back"
            if pos < idaapi.cvar.inf.min_ea or pos > idaapi.cvar.inf.maxEA:
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
        if MyMakeUnknown(head, length + (ea - head), DELIT_EXPAND | DELIT_NOTRUNC) == False:
            printi("0x%x: forceAsCode: Couldn't make unknown at 0x%x" % (ea, head))
            return None
        idc.auto_wait()
    codeLen = MakeCodeAndWait(ea, comment=comment, force=1)

    if codeLen:
        if not isCode(idc.get_full_flags(ea)):
            printi("Couldn't convert block into code even though it said we did 0x%x" % ea)
            return 0
        return codeLen
    else:
        printi("0x%x: Couldn't convert block into code at (head: 0x%x)" % (ea, head))
        if ea < idaapi.cvar.inf.min_ea or ea > idaapi.cvar.inf.maxEA:
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

def LabelAddressPlus(ea, name, force=False, append_once=False, unnamed=False, nousername=False, named=False, throw=False, flags=0):
    """
    Label an address with name (forced) or an alternative_01
    :param ea: address
    :param name: desired name
    :param force: force name (displace existing name)
    :param append_once: append `name` if not already contains `name`
    :param named: [str, callable(addr, name)] name for things with existing usernames
    :return: success as bool
    """
    def ThrowOnFailure(result):
        # return result
        if result is True:
            return result
        if not result:
            result = "Couldn't label address {:x} with \"{}\"".format(ea, name)
        if throw:
            raise RuntimeError("LabelAddressPlus: " + str(result))
        return result

    if isinstance(ea, list):
        return [LabelAddressPlus(x, name, force, append_once, unnamed, nousername, named, throw, flags) for x in ea]

    ea = eax(ea)
    

    if nousername:
        unnamed = nousername
    if IsValidEA(ea):
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
            if not name in fnName:
                name = fnName + name
            else:
                return ThrowOnFailure(False)
        fnLoc = idc.get_name_ea_simple(name)
        if fnLoc == BADADDR:
            return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN | flags))
        elif fnLoc == ea:
            return ThrowOnFailure(True)
        else:
            if force:
                MakeNameEx(fnLoc, "", idc.SN_NOWARN | flags)
                idc.auto_wait()
                return ThrowOnFailure(MakeNameEx(ea, name, idc.SN_NOWARN | flags))
            else:
                name = MakeUniqueLabel(name, ea)
                return ThrowOnFailure(MakeNameEx(ea, name, idc.SN_NOWARN | flags))

    else:
        ThrowOnFailure("0x0%0x: Couldn't label %s, BADADDR" % (ea, name))
        return False

def LabelAddress(ea, name):
    if ea < BADADDR:
        #  MakeFunction(ea)
        #  idc.auto_wait()
        fnFlags = idc.get_full_flags(ea)
        if ida_bytes.has_dummy_name(fnFlags) or not ida_bytes.has_any_name(fnFlags) or Name(ea).find('_BACK_') > -1:
            name = MakeUniqueLabel(name, ea)
            fnLoc = LocByName(name)
            if fnLoc == BADADDR:
                printi("0x0%0x: Labelling: %s" % (ea, name))
                MakeNameEx(ea, name, idc.SN_NOWARN)
            else:
                printi("0x0%0x: Already labelled: %s" % (ea, name))

            if name.endswith('Address'): MakeQword(ea)
            if name.endswith('Float'): MakeFloat(ea)
            if name.endswith('Func'):
                MakeCodeAndWait(ea)
                MakeFunction(ea)
                MakeCodeAndWait(ea)
            if name.endswith('Int'): MakeDword(ea)
        else:
            printi("0x0%0x: %s matched %s" % (ea, Name(ea), name))
            #  if Name(ea) != name:
                #  Commenter(ea).add("[matched] %s" % name)
    else:
        printi("Couldn't label %s, BADADDR" % (name))


def get_name_by_any(address):
    """
    returns the name of an address (and if address is
    a string, looks up address of string first).

    an easy way to accept either address or name as input.
    """

    if address is None:
        return 'None'
    if isIterable(address):
        return [ean(x) for x in address]
    if not isInt(address):
        address = eax(address)
    #  if isinstance(address, str):
        #  address = idc.get_name(idc.get_name_ea_simple(address))
    r = idc.get_name(address)
    if not r:
        return hex(address)
    return r

ean = get_name_by_any
def make_rtti_json():
    print(json.dumps([(x, string_between('const ', '::`', demangle_name(ean(x), 0))) for x in  NamesMatching(r'\?\?_7')]))

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

    if type(val) is int:
        return val
            

    if isinstance(val, list):
        return [get_ea_by_any(x, d) for x in val]
    if isinstance(val, str):
        if '*' in val:
            addresses = FunctionsMatching(val)
            if addresses:
                return get_ea_by_any(addresses[0])
            else:
                raise ValueError("Couldn't matching any function with regex " + val)
        r = idaapi.str2ea(val)
        if r and r != idc.BADADDR:
            return r

        match = re.match(r'(sub|off|loc|byte|word|dword|qword|nullsub|locret)_([0-9a-fA-F]+)$', val)
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

def IsValidEA(args):
    """
    IsValidEA

    @param ea: linear address
    """
    if isInt(args):
        return ida_ida.cvar.inf.min_ea <= args < ida_ida.cvar.inf.max_ea

    count = 0
    for ea in _.flatten(args):
        count += 1
        if not IsValidEA(ea): return False

    return count

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
                    printi(("xref: 0x{:x} {} {}".format(ea, GetFunctionName(ea), GetDisasm(ea))))
                else:
                    printi("multiple refs")
                    break
        elif idc.is_flow(idc.get_full_flags(ea)):
            ea = idc.prev_head(ea)
        else:
            break

    return ea


def MyGetOperandValue(ea, n):
    # printi(("MyGetOperandValue", hex(ea), n))
    d = de(ea)
    if d and isinstance(d, list) and d[0].operands and n < len(d[0].operands):
        return d[0].operands[n].value or d[0].operands[n].disp
    return -1

def MyGetOperandDisplacement(ea, n):
    # printi(("MyGetOperandDisplacement", hex(ea), n))
    d = de(ea)
    if d and isinstance(d, list) and d[0].operands and n < len(d[0].operands):
        return d[0].operands[n].disp
    return -1

def MyMakeUnknown(ea, nbytes=None, flags=0x4): # ida_bytes.DELIT_NOTRUNC
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
    if isinstance(ea, GenericRange) or isinstance(ea, tuple) and len(ea) == 2:
        _s, _e = ea[0], ea[-1]
        if _e > _s:
            _e -= _s
        ea, nbytes = _s, _e
    assert nbytes is not None
        

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
    printi("{:16x} {}".format(ea, line))

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
    
    global global_chunks

    # global_chunks[ea].update(idautils.Chunks(ea))
    printi("{:x} MakeThunk".format(ea))
    # idc.auto_wait()
    # ZeroFunction(ea)
    if not IsCode_(ea):
        EaseCode(ea, forceStart=1)
    if not IsFunc_(ea) or not IsFuncHead(ea):
        if IsFunc_(ea):
            idc.remove_fchunk(ea, ea)
        idc.add_func(ea, EaseCode(ea))
    elif IsFuncHead(ea):
        if GetNumChunks(ea) > 1:
            RemoveAllChunks(ea)
        if GetFuncEnd(ea) > ea + IdaGetInsnLen(ea):
            if not SetFuncEnd(ea, ea + IdaGetInsnLen(ea)):
                printi("{:x} failed to setfuncend".format(ea))
                return False
    if idc.get_func_flags(ea) & idc.FUNC_THUNK == 0:
        SetFuncFlags(ea, lambda f: f | idc.FUNC_THUNK)
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
    if debug: printi("MyMakeFunction(0x{:x}, 0x{:x}, {})".format(ea, end, skip))

    if IsFunc_(ea):
        if IsFuncHead(ea):
            if debug: printi('already a funchead')
            return True
        if IsHead(ea):
            if debug: printi('already a head inside a function')
            return False
        if debug: printi('inside a function, but not a head, returning False')
        return False


    if skip:
        if debug: printi('skipping makefunction')
        return IsFunc_(ea)

    if debug: printi('making function')
    if not idc.add_func(ea, end):
        if debug: printi('simple add didn\'t work, running forceCode')
        forceCode(ea)
        if not idc.add_func(ea, end):
            if debug: printi('forceCode and add_func didn\'t work')
            return 0

    return 1




def EnsureFunction(ea):
    if not IsFunc_(ea):
        if debug: printi('EnsureFunction')
        idc.add_func(ea)
    return ea


def Find(pattern):
    printi('Starting')
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
        # base = idaapi.cvar.inf.min_ea
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
        #  printi("FIND_FUNC_OK")
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

def oget(obj, key, default=None, call=False):
    """Get attribute or dictionary value of object
    Parameters
    ----------
    obj : object
        container with optional dict-like properties
    key : str
        key
    default : any
        value to return on failure
    call : bool
        call attr if callable

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
    r = None

    if isinstance(obj, dict):
        return obj.get(key, default)
    try:
        r = obj[key] if key in obj else getattr(obj, key, default)
    except TypeError:
        # TypeError: 'module' object is not subscriptable
        r = getattr(obj, key, default)

    if call and callable(r):
        r = r()

    return r


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


def isByteArray(o):
    return isinstance(o, bytearray)

def isInt(o):
    return isinstance(o, integer_types)

def isIntString(obj):
    """ Check if the given object is an int
    """
    isint = False
    if isinstance(obj, str):
        for c in obj:
            if c < '0' or c > '9':
                return False
            else:
                isint = True

    return isint


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
    return o if isString(o) and not isByteish(o) else o.decode('utf-8')

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

def asTuple(o):
    return tuple(asList(o))



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
    fnLoc = idc.get_name_ea_simple(name)
    if fnLoc == BADADDR or fnLoc == ea:
        return name
    fmt = "%s_%%i" % name
    for i in range(10000):
        tmpName = fmt % i
        fnLoc = idc.get_name_ea_simple(tmpName)
        if fnLoc == BADADDR or fnLoc == ea:
            return tmpName
    return ""


def get_start(r):
    return r.start if hasattr(r, 'start') else r[0]

def get_last(r):
    if hasattr(r, 'last'):
        return r.last
    if hasattr(r, 'stop'):
        return r.stop - 1
    return r[1]


def intersect(r1, r2):
    if not overlaps(r1, r2):
        return []
    t =     min(get_last(r1), get_start(r2)), \
            min(get_last(r2), get_start(r1)), \
            max(get_last(r1), get_start(r2)), \
            max(get_last(r2), get_start(r1))
    return  max(t[0], t[1]), min(t[2], t[3])

def intersect_gap(r1, r2):
    if overlaps(r1, r2):
        return []
    t =     min(get_last(r1), get_start(r2)), \
            min(get_last(r2), get_start(r1)), \
            max(get_last(r1), get_start(r2)), \
            max(get_last(r2), get_start(r1))
    return  max(t[0], t[1]) + 1, min(t[2], t[3]) - 1

def overlaps(r1, r2):
    """Does the range r1 overlaps the range r2?"""
    return get_last(r1) >= get_start(r2) and \
           get_last(r2) >= get_start(r1)

def issubset(r1, r2):
    """Is the range r1 a subset of the range r2?"""
    return get_last(r1) <= get_last(r2) and get_start(r1) >= get_start(r2)

def issuperset(r1, r2):
    """Is the range r1 a superset of the range r2?"""
    return get_last(r1) >= get_last(r2) and get_start(r1) <= get_start(r2)

def indexOfSet(ranges, r1, func=issubset):
    """Which range is r1 a subset of?"""
    for i, r in enumerate(ranges):
        if func(r1, r):
            return i
    return -1


def issettest():
    s1 = set([2,3,4])
    s2 = set([1,2,3,4,5])
    r1 = GenericRange(2,last=4)
    r2 = GenericRange([1,5])
    printi("All tests should return True: {}".format([
        s1.issubset(s2)   == issubset(r1,   r2),
        s2.issubset(s1)   == issubset(r2,   r1),
        s1.issuperset(s2) == issuperset(r1, r2),
        s2.issuperset(s1) == issuperset(r2, r1),
        s2.issuperset(s2) == issuperset(r2, r2),
    ]))

def adjoins(r1, r2):
    """Does the range r1 adjoin or overlaps the range r2?"""
    return get_last(r1) + 1 >= get_start(r2) and get_last(r2) + 1 >= get_start(r1)

def union(r1, r2):
    try:
        return type(r1)([min(get_start(r1), get_start(r2)), max(get_last(r1), get_last(r2))])
    except TypeError:
        return type(r1)(min(get_start(r1), get_start(r2)), max(get_last(r1), get_last(r2)))

def overlap2a(ranges1, ranges2):
    overlaps = []
    for x, y in itertools.product(ranges1, ranges2):
        sx = set(range(get_start(x), get_last(x) + 1))
        sy = set(range(get_start(y), get_last(y) + 1))
        overlap.extend(sx & sy)
    return GenericRanger(overlaps, sort=1)

def difference(x, y, ordered=False):
    sx = set()
    sy = set()
    for r in y:
        sx.update(r for r in range(get_start(r), get_last(r) + 1))
    for r in x:
        sy.update(r for r in range(get_start(r), get_last(r) + 1))
    d = sy - sx
    result = GenericRanger(d, sort=1)
    if ordered:
        result = _.sortBy(result, lambda v, *a: indexOfSet(x, v))
    return result


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
                        desc1.append('chunk {} of'.format(GetChunkNumber(target) + 1, GetNumChunks(target)))
                    else:
                        desc1.append('offset of')
                    desc1.append('function \"{}\" (0x{:x})'.format(idc.get_func_name(target), (target)))

                    desc.append(" ".join(desc1))
            else:
                desc.append('location \"{}\" (0x{:x})'.format(idc.get_name(target), target))

            return ", ".join(desc)

        def __repr__(self):
            return self.__str__()


    target_obj = TargetDescriptor(ea)
    return target_obj

def auto_name_common_functions():
    for ea in later:
        if Name(ea).startswith(('sub_', 'common:')): print(name_common_function(ea))

def bestOf3Names(container, iteratee=None):
    if iteratee is None:
        iteratee = lambda x, *a: x
    counted = _.countBy(container, iteratee)
    #  print(counted)
    # {0x1: 0x1, 0x2: 0x2, 0x3: 0x1}
    q = _.reverse(_.sortBy(_.map(counted, lambda count, ea, *a: {'count': count, 'ea': ea}), 'count'))
    # dprint("[bestOf3Names] q")
    # print("[bestOf3Names] q:{}".format(q))
    
    # return q
    best = ''
    e = q
    argc = len(e)
    if not argc:
        pass
    elif argc == 1:
        best = e[0]['ea']
    else:
        # dprint("[bestOf3Names] e[0]['count'], e[1]['count']")
        
        if e[0]['count'] >= (2 * e[1]['count']):
            # print("[bestOf3Names] e[0]['count']:{}, e[1]['count']:{}... q:{}".format(e[0]['count'], e[1]['count'], q))
            best = e[0]['ea']
    return best
    # print("bestOf3: undecided: {}".format(q))

def name_common_function(ea=None, dryRun=False):
    """
    name_common_function

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [x for x in [name_common_function(x, dryRun=dryRun) for x in ea] if x is not None]

    ea = eax(ea)
    if not IsFuncHead(ea):
        return
    if HasUserName(ea):
        return
    if idc.get_name(ea).startswith(("__", "return")):
        return
    #  if not IsFuncStart(ea):
        #  return "Is not function start: {}".format(describe_target(ea))
    
    r = RecurseCallers(ea, width=1000, depth=1, new=1)
    if 'named' in r:
        named = r['named']
        named = _.uniq(_.filter(named, lambda v, *a: v.endswith('_ACTUAL')))
        if debug: print("named: {}".format(named))
        if debug: print("bestOf3: {}".format(bestOf3Names(r['named'])))
        possibles = [r for r in [bestOf3Names(named, lambda v, *a: v[0:x]) for x in range(1,64)] if r]
        if debug: print("possibles: {}".format(possibles))
        if possibles:
            label = 'common2:{}'.format(string_between('NATIVE::', '', possibles[-1], rightmost=1, retn_all_on_fail=1))
            print("label: {}".format(label))
            if not dryRun:
                LabelAddressPlus(ea, label)
                # Commenter(ea, 'line').add('[ALLOW EJMP]')
            else:
                print("{:x} {}".format(ea, label))
            return hex(ea), label


    return
    if idc.get_segm_name(ea) == '.text':
        #  refs = xrefs_to(ea, include='call|jump')
        #  refNames = _.uniq(_.sort([string_between(re.compile('_actual', flags=re.I), '', x, inclusive=1, repl='') for x in GetFuncName(refs) if _.contains(x, ['::_0x', '___0x']) and not x.startswith(('common:', 'return_', 'nullsub_'))]) , True)
        #  if not refNames:
            #  refNames = _.uniq(_.sort([string_between(re.compile('_actual', flags=re.I), '', x, inclusive=1, repl='') for x in GetFuncName(refs) if _.contains(x, ['::_0x', '___0x']) and not x.startswith(('return_', 'nullsub_'))]) , True)
        # otherNames = _.uniq(_.sort([x for x in GetFuncName(refs) if x and not _.contains(x, ['::_0x', '___0x'])]), True)
        otherNames = []
        refNames = FuncRefsTo(ea)

        #  fnName = idc.get_name(ea)
        #  fnName = fnName.replace('::', '!!').replace('__', '##')
        nonNativeNames = []
        nativeNames = []
        otherCount = 0
        for token in _.uniq(_.sort(_.flatten([fnName.replace('::', '!!').replace('__', '##').split(':') for fnName in refNames])), 1):
            if '!!' in token or '##' in token:
                token = token.replace('!!', '::').replace('##', '__')
            if '::_0x' in token or '___0x' in token:
                nativeNames.append(token)
            elif '_others' in token:
                otherCount += int(string_between('_', '_others', token, rightmost=1))
            elif 'Others' in token:
                otherCount += int(string_between('', 'Others', token).strip('_'))
            elif '_helper' in token:
                pass
            elif token == 'common':
                pass
            else:
                otherCount += 1
                pass
                #  nonNativeNames.append(token)

        nativeNames = _.map(nativeNames, lambda v, *a: re.sub(r"_(ACTUAL|helper).*", "", v, re.I))

        #  callrefs = _.uniq(GetFuncStart([ea for ea in list(CallRefsTo(ea)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea)]))
        #  jmprefs =  _.uniq(GetFuncStart([ea for ea in list(JmpRefsTo(ea)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea) and IdaGetInsnLen(ea) > 2]))
        #  if e.conditional and len(callrefs + jmprefs) == 0:
            #  idc.del_func(ea)
            #  patched += 1
        if len(nativeNames) == 1 and otherCount == 0:
            label = "{}_helper".format(nativeNames[0])
            if not dryRun:
                LabelAddressPlus(ea, label)
                Commenter(ea, 'line').remove('[ALLOW EJMP]')
            else:
                print("{:x} {}".format(ea, label))
            return hex(ea), label
        if not nativeNames:
            label=''
        else:
            label = ":".join(['common'] + nativeNames + nonNativeNames)
            if otherCount:
                label += ":_{}_others".format(otherCount)
            if not dryRun:
                LabelAddressPlus(ea, label)
                Commenter(ea, 'line').add('[ALLOW EJMP]')
            else:
                print("{:x} {}".format(ea, label))
            return hex(ea), label

def diStripNatives():
    for ea in m + l:
        ea = SkipJumps(ea)
        if IsFuncHead(ea):
            for cs, ce in idautils.Chunks(ea):
                diStrip(cs)


    
def fix_func_tails(l, extra_args=dict()):
    printi("[fix_func_tails] ")
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
                    callrefs = _.uniq(GetFuncStart([ea for ea in list(CallRefsTo(target)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea)]))
                    jmprefs =  _.uniq(GetFuncStart([ea for ea in list(JmpRefsTo(target)) if idc.get_segm_name(ea) == '.text' and IsFunc_(ea) and IsNiceFunc(ea) and IdaGetInsnLen(ea) > 2]))
                    if e.conditional and len(callrefs + jmprefs) == 0:
                        idc.del_func(target)
                        patched += 1
                    else:
                        refs = _.uniq(callrefs + jmprefs)
                        ref_names = GetFuncName(refs)
                        if not e.to.func_ea:
                            if len(ref_names) > 1:
                                if not HasUserName(target):
                                    LabelAddressPlus(target, "common:" + ":".join([x for x in ref_names if not x.startswith('sub_')]))
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
                        printi("interupt found at 0x{:x}, pass it as ok".format(e.tail_ea))
                        return "int"
                        printi("re-running with ignoreInt = True")
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
            printi((" -> ".join(stk)))
            printi("append_func_tail(0x{:x}, 0x{:x}, 0x{:x}):".format(funcea, ea1, ea2))
            printi(indent(4, _.flatten(e.args)))

if hasattr(idc, 'append_func_tail'):
    idc.append_func_tail = my_append_func_tail

def xxd(dump):
    import hexdump
    return hexdump.hexdump(asBytes(dump))


def GetBase64String(ea=None, length = -1, strtype = 0, hex=False):
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
    printi("\n".join(stk))
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

def join_helper_functions():
    global later2
    for ea in later2:
        if IsFuncStart(ea):
            refs = xrefs_to(ea)
            if len(refs) == 1:
                Commenter(ea, 'line').remove('[ALLOW EJMP]')
                ref = refs[0]
                if not IsFuncHead(ref):
                    print("considering: {:x} -> {:x}".format(ref, ea))
                    if isAnyJmp(ref): #  and not len(all_xrefs_from(ea, filter=lambda x: not x[2].startswith('fl_'))):
                        print("trying: {:x}".format(ea)) 
                        retrace(ref, once=1)
                        if not IsFuncStart(ea): print("joined {:x}".format(ea))

def process_balance(ea=None, compact=False):
    """
    process_balance

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [process_balance(x) for x in ea]

    if ea is None and IsFunc_(here()):
        ea = here()
    ea = eax(ea)
    _list = AdvanceToMnemEx(ea, inclusive=True)
    setglobal('_list', _list)
    if not _list:
        raise ValueError("empty list at {:#x}".format(ea))
    sti = CircularList(_list)
        # in func_tails(ea=ea, quiet=1, returnOutput='buffer', returnFormat=lambda o: o) if not x.insn.startswith(('nop', 'jmp'))])
    setglobal('sti', sti)
    # sti = func_tails(returnOutput='buffer')
    #  if False:
        #  m = sti.multimatch([
            #  r'({push}push.*)**',
            #  r'lea rsp, .*',
            #  r'(movupd .*)**',
            #  r'push 0x10',
            #  #  r'test rsp, 0xf',
            #  #  r'jnz .*',
            #  #  r'push 0x18',
            #  #  r'(add|sub) rsp, .*',
            #  r'call ({call}.*)',
            #  r'(add|lea) rsp, \[rsp\+8\]',
            #  r'(movupd .*)**',
            #  r'lea rsp, \[rsp\+({rspdiff}[^\]]+)\]',
            #  r'(pop.*)**',
            #  r'({extra}.*)**',
            #  #  r'retn',
            #  ], groupiter=lambda o: o, gettext=lambda o: o.insn, predicate=lambda o: not o.insn.startswith('jmp'))
        #  if m:
            #  return m
#  
    m = sti.multimatch([
        r'({push}push.*)**',
        r'lea rsp, .*',
        r'(movupd .*)**',
        r'push 0x10',
        r'call ({call}.*)',
        r'(lea|add) rsp, .*',
        r'(movupd .*)**',
        r'lea rsp, \[rsp\+({rspdiff}[^\]]+)\]',
        r'(pop.*)**',
        r'({extra}.*)**',
        ], groupiter=lambda o: o, gettext=lambda o: o.insn, predicate=lambda o: not o.insn.startswith('jmp'))

    if not m:
        m = sti.multimatch([
            r'({push}push.*)**',
            r'test rsp, 0xf',
            r'jnz .*',
            r'push (dword )?0x18',
            r'(add|sub) rsp, .*',
            r'call ({call}.*)',
            r'(lea|add) rsp, .*',
            r'(pop.*)**',
            r'({extra}.*)**',
            ], groupiter=lambda o: o, gettext=lambda o: o.insn, predicate=lambda o: not o.insn.startswith('jmp'))


    if m:
        if compact:
            setglobal('_m', m)
            setglobal('sti', sti)
            #  if len(m.get('extra', [])) == 1 and m.get('extra')[0].insn.startswith('ret'): m['extra'] = []
            if 'extra' in m and 'push' in m:
                #  len(m.extra) == 1 and m.extra[0].strip() == 'retn':
                if len(m.push) > 8 and len(m.extra):
                    nop = []
                    for r in m.default:
                        if r not in m.extra:
                            printi("[process_balance] nopping {:x}: {}".format(r.ea, r))
                            for ea in range(r.ea, r.ea + len(r)):
                                nop.append(ea)
                    nopRanges = GenericRanger(nop, sort=0, outsort=0)
                    printi("[process_balance] nopRanges: {}".format(nopRanges, nop))
                    for r in nopRanges:
                        print("[process_balance] r.start:{:x}, r.trend:{:x}".format(r.start, r.trend))
                        
                        PatchNops(r.start, r.length, "compacted stack balance")
                    printi("[patch_stack_align] assembling at {:x}".format(m.push[0].ea))
                    if m.extra[0].insn == 'retn':
                        assembled = nassemble(m.push[0].ea,
                            #  push    rbp
                            #  sub     rsp, 32
                            """
                            {}
                            {}
                            """.format(m.call[0], "\n".join(_.pluck(m.extra, 'labeled_value'))), apply=1)
                    else:
                        assembled = nassemble(m.push[0].ea,
                            #  push    rbp
                            #  sub     rsp, 32
                            """
                            {}
                            jmp 0x{:x}
                            """.format(m.call[0], SkipJumps(m.extra[0].ea)), apply=1)
                    SetFuncOrChunkEnd(m.push[0].ea, m.push[0].ea + len(assembled)) # , m.push[0].ea + len(assembled))
                        #  add     rsp, 32
                        #  pop     rbp
                else:
                    printi("[patch_stack_align] len(push) or len(extra) wrong")
                    # dprint("[process_balance] len(m.push) > 8, len(m.extra) == 1, m.extra[0] == 'retn'")
                    print("[process_balance] len(m.push) > 8:{}, len(m.extra) == 1:{}, m.extra[0] == 'retn':{}".format(len(m.push) > 8, len(m.extra) == 1, m.extra[0] == 'retn'))
                    
            else:
                printi("[patch_stack_align] extra or push not in m")
        return m

    #  if m and isDictlike(m):
        #  return _.without(m, 'default')
    return m

def call_if_callable(func, *args, default=None, **kwargs):
    #  if func: printi("[call_if_callable] func.__name__:{}, args:{}, kwargs:{}".format(func.__name__, args, kwargs))
    if not func or not callable(func):
        return default
    
    # dprint("[call_if_callable] func.__name__, args, kwargs")
    
    return func(*args, **kwargs)
    
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
            
def namesource(source):
    # source = list(later)
    n = xrefs_to(source)
    results = []
            
    addrs = [x for x in n if idc.get_segm_name(x) == '.text' and IsFunc_(x) and GetFuncSize(x) > 5 and not isConditionalJmp(x)]
    u = _.uniq(GetFuncName(addrs))
    if len(u) == 1:
        printi("{} {}".format(len(u), " ".join(u)))
        # BRAIN::_0x8C504465D29C987A_ACTUAL
        #  LabelAddressPlus(source, u[0])
    else:
        printi("{} {}".format(len(u), " ".join(u)))
        # BRAIN::_0x8C504465D29C987A_ACTUAL
        results.append( (len(u), source) )

    return results


def bin32(n):
    n = n & 0xffffffff
    return (('0' * 32) + bin(n)[2:])[-32:]

def polymul(num_bits, num_from, num_to):
    while (num_from & 1) == 0:
        assert (num_to & 1) == 0
        num_from >>= 1
        num_to >>= 1

    mask = (1 << num_bits) - 1
    value = 0
    result = 0

    for i in range(num_bits):
        if (value ^ num_to) & (1 << i):
            result |= (1 << i)
            value += num_from << i
            value &= mask

    assert value == num_to

    return result


prngSeed = 0x13C938FF # (0x214013 * 2531011) & 0xffffffff

#  def prngSeedNext():
    #  global prngSeed
#  
    #  # prngSeed        = 214013 * prngSeed + 2531011;
    #  prngSeed          = ((0xffffffff & (214013 * prngSeed)) + 2531011) & 0xffffffff;
    #  return prngSeed

def prngSeedNext():
    global prngSeed

    prngSeed = prngSeedNextCalc(prngSeed)
    return prngSeed

def prngSeedPrev():
    global prngSeed

    prngSeed = prngSeedPrevCalc(prngSeed)
    return prngSeed

def prngSeedPrevCalc(prngSeed):

    num_bits = 32
    mask = (1 << num_bits) - 1
    mul = 0xb9b33155
    r = prngSeed
    r -= 2531011
    r &= mask
    r *= mul
    r &= mask
    return r

def prngNextCalc(prngSeed):
    return ((0xffffffff & (214013 * prngSeed)) + 2531011) & 0xffffffff;

def rng_init(data = 0x12345678):
    global prngSeed
    a1     = [0] * 45;
    a1[43] = prngSeedNext()
    a1[44] = prngSeedNext()
    a1[41] = data & prngSeed
    a1[42] = data & ~prngSeed
    return a1

def HIWORD(das):
    return (das >> 16) & 0xffff

def rng_twirl(a1):
    global prngSeed
    seed              = a1[44];
    das               = a1[41];
    dans              = a1[42];
    data              = das & seed | dans & ~seed;
    # unused
    a1[41]            = das & seed | ((das & ~seed) << 16) | HIWORD(das) & (~seed >> 16);
    # unused
    a1[42]            = rol(dans & seed, 16, 32) | a1[42] & ~a1[44];
    a1[43]            = prngSeedNext();
    a1[44]            = prngSeedNext();
    data_and_not_seed = data & ~prngSeed;
    a1[41]            = data & prngSeed;
    a1[42]            = data_and_not_seed;
    return data;

def rngtest(ea=None, verbose=False):
    """
    rngtest - determine if RandEncrypted struct is present at ea

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [rngtest(x) for x in ea]

    ea = eax(ea)
    das = idc.get_wide_dword(ea)
    dans = idc.get_wide_dword(ea+4)
    seed0 = idc.get_wide_dword(ea+8)
    seed = idc.get_wide_dword(ea+12)
    if seed and seed0 and das ^ dans == das & seed | dans & ~seed:
        if not seed == (seed0 * 0x343fd + 0x269ec3) & 0xffffffff:
            # pass
            if verbose:
                printi("0x{:x} data: 0x{:08x} (seeds were not sequential) d:{:08x} dn:{:08x} s0:{:08x} s:{:08x}".format(ea, das ^ dans, das, dans, seed0, seed))
            return None
        
        else:
            if verbose:
                printi("0x{:x} data: 0x{:08x} d:{:08x} dn:{:08x} s0:{:08x} s:{:08x}".format(ea, das ^ dans, das, dans, seed0, seed))
            return True
    else:
        if verbose:
            printi("fail: 0x{:x} data: 0x{:08x} d:{:08x} dn:{:08x} s0:{:08x} s:{:08x}".format(ea, das ^ dans, das, dans, seed0, seed))
        return False


def rng_test(ea = None):
    # a1[0] & a1[3] | a1[1] & ~a1[3],
    a1 = rng_init(0x12345678)
    for r in range(31337):
        rng_twirl(a1)
    printi("test1: {}\ntest2: {}".format(
        a1[41] ^ a1[42] == a1[41] & a1[44] | a1[42] & ~a1[44],
        prngNextCalc(a1[43]) == a1[44]
    ))

"""
0 214013 2531011
1 -1443076087 505908858
2 1170746341 -755606699
3 -570470319 159719620
4 675975949 -1567142793
5 257342169 773150046
6 203977589 548247209
7 -191841887 2115878600
8 -1065380067 -1462599061
9 1744563881 2006221698

def s32(v):
    m = 1 << 31
    return (v & (m - 1)) - (v & m)

x = 1
y = 0
for i in range(10):
    x *= 214013
    y *= 214013
    y += 2531011
    x &= 0xFFFFFFFF
    y &= 0xFFFFFFFF
    printi(i, s32(x), s32(y))

Advance an LCG in linear time:

for (uint32_t n = 0; n < 100; ++n) {
    uint32_t mul = 1;
    uint32_t inc = 0;

    for (uint32_t i = n, j = 214013, k = 2531011; i; i >>= 1, k += k * j, j *= j) {
        if (i & 1) {
            mul *= j;
            inc *= j;
            inc += k;
        }
    }

    printf("%2u 0x%08X 0x%08X\n", n, mul, inc);
}

Skipping backwards is the same as skipping forwards, just using the reversed mul and inc constants I showed

#include <cstdint>

bool PolyMul(uint32_t from, uint32_t to, uint32_t& out_mul)
{
    for (; ~from & 1; from >>= 1, to >>= 1) {
        if (to & 1)
            return false;
    }

    uint32_t value = 0;
    uint32_t result = 0;

    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t m = UINT32_C(1) << i;

        if ((value ^ to) & m) {
            result |= m;
            value += from << i;
        }
    }

    out_mul = result;

    return true;
}

// easier to understand version

bool PolyMul(uint32_t from, uint32_t to, uint32_t& out_mul)
{
    for (; ~from & 1; from >>= 1, to >>= 1) {
        if (to & 1)
            return false;
    }

    uint32_t result = 0;

    while (uint32_t v = (from * result) ^ to) {
        result |= v & -int32_t(v);
    }
    
    out_mul = result;

    return true;
}


void SkippingLCG(uint32_t n, uint32_t& mul, uint32_t& inc)
{
    uint32_t out_mul = 1;
    uint32_t out_inc = 0;

    for (uint32_t i = n, j = mul, k = inc; i; i >>= 1, k += k * j, j *= j) {
        if (i & 1) {
            out_mul *= j;
            out_inc *= j;
            out_inc += k;
        }
    }

    mul = out_mul;
    inc = out_inc;
}

template <uint32_t Mul = 214013, uint32_t Inc = 2531011>
struct LCG {
    uint32_t state;

    LCG(uint32_t seed)
        : state(seed)
    {
    }

    void skip(int32_t n = 1)
    {
        if (n == 0)
            return;

        uint32_t mul = Mul;
        uint32_t inc = Inc;

        if (n < 0) {
            PolyMul(mul, 1, mul);
            inc *= uint32_t(-int32_t(mul));
            n = -n;
        }

        if (n > 1) {
            SkippingLCG(n, mul, inc);
        }

        state = (state * mul) + inc;
    }

    uint32_t operator()(int32_t n = 1)
    {
        uint32_t result = state;
        skip(n);
        return result;
    }
};


// Z3 version
import z3

solver = z3.Solver()

x = z3.BitVecVal(0x55C180C3, 32)
y = z3.BitVec('y', 32)

solver.add(x * y == 1)

if solver.check() == z3.sat:
    m = solver.model()
    printi(hex(m[y].as_long()))





"""
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


"""
// [PATTERN;REMOTE:gtasc-2372] '48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 8b 05 ?? ?? ?? ?? 48 8b f9 48 8b da be c3 9e 26 00 69 c0 fd 43 03 00 03 c6 89 05 ?? ?? ?? ?? 89 41 08 8b 05 ?? ?? ?? ?? 69 c0 fd 43 03 00 03 c6 89 '
void __fastcall Rand4DwordMap::GetValueAndTwirl(dw4* dst, dw4* src) {
    int das_and_seed;       // er11                          int src_dans; // eax
    int dans;               // eax                           int data; // er9 MAPDST
    unsigned int not_seed;  // er8                           int seed; // ecx MAPDST
    int v6;                 // er9
    int data;               // eax
    int data_and_not_seed;  // edx MAPDST

    prngSeed = 214013 * prngSeed + 2531011;             src_dans = src->dans;
    dst->seed1 = prngSeed;                              data = src_dans ^ src->das;
    prngSeed = 214013 * prngSeed + 2531011;             seed = 2851891209 * prngSeed + 505908858;
    dst->seed2 = prngSeed;                              dst->seed2 = seed;
    das_and_seed = src->seed2 & src->das;               data = src_dans ^ src->seed2 & data;
    dans = src->dans;                                   seed = 214013 * seed + 2531011;
    not_seed = ~src->seed2;                             src->seed1 = seed;
    v6 = __ROL4__(src->seed2 & dans, 16);               seed = 214013 * seed + 2531011;
    data = das_and_seed | not_seed & dans;              src->seed2 = seed;
    src->das = das_and_seed | ((not_seed & src->das) << 16)
             | HIWORD(not_seed) & HIWORD(src->das);
    src->dans = v6 | src->dans & ~src->seed2;           src->das = seed & data;
    prngSeed = 214013 * prngSeed + 2531011;             seed = 214013 * seed + 2531011;
    src->seed1 = prngSeed;                              src->dans = data & ~seed;
    prngSeed = 214013 * prngSeed + 2531011;             dst->seed1 = seed;
    src->seed2 = prngSeed;                              seed *= 214013;
    data_and_not_seed = data & ~prngSeed;               prngSeed = seed + 2531011;
    src->das = data & prngSeed;                         dst->seed2 = seed + 2531011;
    src->dans = data_and_not_seed;                      dst->das = (seed + 2531011) & data;
    prngSeed = 214013 * prngSeed + 2531011;             dst->dans = data & ~(seed + 2531011);
    dst->seed1 = prngSeed;
    prngSeed = 214013 * prngSeed + 2531011;
    dst->seed2 = prngSeed;
    data_and_not_seed = data & ~prngSeed;
    dst->das = data & prngSeed;
    dst->dans = data_and_not_seed;


network___network_has_game_been_altered_actual:
    push rbx
    sub rsp, 0x30
    mov rdx, [rel gp_SessionManager]

        mov     eax, DWORD [rdx+4]
        mov     ecx, DWORD [rdx]
        xor     ecx, eax
        and     ecx, DWORD [rdx+12]
        xor     ecx, eax
        imul    eax, DWORD [rel prngSeed], 1170746341
        mov     r8d, ecx
        sub     eax, 755606699
        mov     DWORD [rdx+8], eax
        imul    eax, eax, 214013
        add     eax, 2531011
        and     r8d, eax
        mov     DWORD [rdx+12], eax
        mov     DWORD [rdx], r8d
        mov     r8d, eax
        imul    eax, eax, -570470319
        not     r8d
        and     r8d, ecx
        add     eax, 159719620
        mov     DWORD [rdx+4], r8d
        mov     DWORD [rel prngSeed], eax
        xor     eax, eax
        cmp     ecx, 1
        setg    al

    add rsp, 0x30
    pop rbx
    retn


}

# hash1
# hash2
# data1_and_seed2
# data1_and_not_seed2
# seed1
# seed2
# data2_and_seed4
# data2_and_not_seed4
# seed3
# seed4
# data3_and_seed6
# data3_and_not_seed6
# seed5
# seed6

"""


from collections import Sequence
import six
from six.moves import builtins


def isgenerator(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'__len__')

# https://stackoverflow.com/questions/42095393/python-map-a-function-over-recursive-iterables
def recursive_map(seq, func):
    for item in seq:
        #  if isinstance(item, six.string_types):
            #  yield func(long(item, 0))
        #  if str(type(item)) in ("<class 'generator'>", "<class 'range'>") and getattr(item, '__iter__', None):
        if isgenerator(item) or isinstance(item, (six.moves.range)):
            # print("recurse_map isgen")
            yield func([x for x in item])
        elif isinstance(item, six.string_types):
            yield func(item)
        elif isinstance(item, Sequence):
            # print("recurse_map {} {}".format(item, type(item)))
            yield type(item)(recursive_map(item, func))
        else:
            yield func(item)


def _makeSequenceMapper(f, pre=None, post=None):
    def _identity(o): 
        return o
    pre = pre or _identity
    post = post or _identity
    def fmap(seq, func):
        return recursive_map(seq, func)
    def function(item):
        # if str(type(item)) in ("<class 'generator'>", "<class 'range'>"):
        if isgenerator(item) or isinstance(item, (six.moves.range,)):
            # print("_makeSequenceMapper isgen")
            return post(type([])(fmap(item, f)))
            #  return [f(x) for x in item]
        elif isinstance(item, six.string_types):
            return post(f(item))
        elif isinstance(item, Sequence):
            return post(type(item)(fmap(item, f)))
        return post(f(item))
    return function

def hexmap(seq):
    return recursive_map(seq, hex)

def hex_callback(item):    
    """
    hex(...)
        hex([number|list]) -> string
        
        Return the hexadecimal representation of [list of] integer or long integer.
    """
    def builtin_hex(number):
        result = builtins.hex(number)
        return result.rstrip('L')

    if isinstance(item, six.string_types):
        try:
            result = builtin_hex(six.integer_types[-1](item, 0))
            return result
        #  except TypeError: return item
        except ValueError:
            return item
    elif isinstance(item, six.integer_types):
        return builtin_hex(item)
    #  if isgenerator(item) or isinstance(item, (six.moves.range, range)):
        #  return [hex(x) for x in item]
    #  if isinstance(item, set):
        #  return type(item)(hexmap(list(item)))
    #  if isinstance(item, Sequence):
        #  return type(item)(hexmap(item))
    else:
        return item


def ahex(item):
    if isIterable(item):
        return str([ahex(x) for x in item]).replace("'", "")
    if isinstance(item, six.integer_types):
        if item > 9:
            return hex(item)
    return str(item)

def listComp(item):
    return [x for x in item] if isgenerator(item) or isinstance(item, (six.moves.range, range)) else item

_asList = _makeSequenceMapper(listComp, pre=None) # , post=A)
def asList(o):
    def isIterable(o):
        return hasattr(o, '__iter__') and not hasattr(o, 'ljust')

    l = []
    if isIterable(o):
        l = [x for x in o]
    else:
        l = _asList(o)

    if not isinstance(l, list) or len(l) == 1 and l[0] == o:
        return [o]
    return l

hex = _makeSequenceMapper(hex_callback)

def asHexList(o):
    return [hex(x) for x in asList(o)]

def addrAsVtable(ea=None, m=True):
    """
    addrAsVtable

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [addrAsVtable(x) for x in ea]

    ea = eax(ea)
    
    if SegName(ea) == '.rdata':
        addr = ea

        _name_demang     = idc.get_name(addr, GN_DEMANGLED)
        _disasm          = idc.GetDisasm(addr)
        _ptr_name_raw    = idc.get_name(getptr(addr), 0)
        _ptr_name_demang = idc.get_name(getptr(addr), GN_DEMANGLED)
        _ptr_name_color  = idc.get_name(getptr(addr), GN_COLORED)


        while IsOff0(addr):
            if HasAnyName(addr) and idc.get_name(addr, GN_DEMANGLED).endswith("`vftable'"):
                refName = idc.demangle_name(idc.get_name(addr, 0), DEMNAM_FIRST)
                if not refName:
                    refName = "unknown_vftable_0x%x" % addr
                refName = refName.replace("::`vftable'", "")
                if m:
                    refName = "{}::m_{:x}".format(refName, ea - addr)
                return refName

            addr = idc.prev_head(addr)
    return ""

def rename_nullsub_offsets():
    for ea in [x for x in _.flatten(xrefs_to(NamesMatching('nullsub_'))) if IsOff0(x)]: LabelAddressPlus(ea, "off" + ean(getptr( ea ) ))
    # [IsFuncHead(x) for x in m]
    m = FindInSegments('55 48 81 EC D0 00 00 00 48 8D 6C 24 20 48 89 9D A0 00 00 00 89', ['.text', '.rdata'], limit=100)
    for ea in m: LabelAddressPlus(ea, 'CheckLoadedModules')
    m = FindInSegments('55 48 83 ec 40 48 8d 6c 24 20 89 4d 30 48 89 55 38 48 8b', ['.text', '.rdata'], limit=100)
    for ea in m: LabelAddressPlus(ea, 'CheckLoadedModules_ToLowerChar')
    m = FindInSegments('55 48 83 ec 40 48 8d 6c 24 20 89 4d 30 48 8b 42 08 48 89 45 00 8b 45 30 48 63', ['.text', '.rdata'], limit=100)
    for ea in m: LabelAddressPlus(ea, 'CheckLoadedModules_ToLowerWideChar')
    for ea in m: SetType(ea, 'int __fastcall CheckLoadedModules_ToLowerWideChar_2(int offset, UNICODE_STRING *str)')
    m = FindInSegments('55 48 83 ec 40 48 8d 6c 24 20 89 4d 30 48 89 55 38 48 8b', ['.text', '.rdata'], limit=100)
    for ea in m: SetType(ea, 'int __fastcall CheckLoadedModules_ToLowerChar_14(int offset, char *str)')
    m = FindInSegments('55 48 81 ec 80 00 00 00 48 8d 6c 24 20 48 89 5d 50 48 89 4d 70 33 c0 48 89 45 30 48 89 45 38 48 89 45 28', ['.text', '.rdata'], limit=100)
    for ea in m: LabelAddressPlus(ea, 'OtherCheckLoadedModules')
    for ea in m: SetType(ea, 'void __fastcall CheckLoadedModules_ToLowerChar_14(__int64)')

def __ummm():
    addr = ida_ida.cvar.inf.min_ea + 0x0a59e0c
    for ea in xrefs_to(getptr(addr), filter=lambda x: IsOff0(x.frm)): LabelAddressPlus(ea, 'o_MakeTamperActionBonusReport')
    GetType(getptr(addr))
    SetType(getptr(addr), 'void __fastcall(eAntiCheatBonusEventHttpTaskItemId acHash)')
    for ea in xrefs_to(getptr(addr), filter=lambda x: IsOff0(x.frm)): SetType(ea, 'void (__fastcall *o_MakeTamperActionBonusReportAndSmth_8)(eAntiCheatBonusEventHttpTaskItemId);')

def __ummm2():
    addr = ida_ida.cvar.inf.min_ea + 0x0D4AB7B
    for ea in xrefs_to(getptr(addr), filter=lambda x: IsOff0(x.frm)): LabelAddressPlus(ea, 'o_MakeTamperActionBonusReportAndSmth')
    GetType(getptr(addr))
    SetType(getptr(addr), 'void __fastcall(eAntiCheatBonusEventHttpTaskItemId acHash)')
    for ea in xrefs_to(getptr(addr), filter=lambda x: IsOff0(x.frm)): SetType(ea, 'void (__fastcall *o_MakeTamperActionBonusReportAndSmth_8)(eAntiCheatBonusEventHttpTaskItemId);')


def label_time_vars():
    for ea in _.uniq(GetFuncStart(xrefs_to(eax('timeGetTime')))):
        for line in decompile_function_search(ea, 'dword_[0-9A-F]+ .= timeGetTime'):
            LabelAddressPlus(eax(string_between('', ' ', line)), 'g_timeAffectedDword')

def label_sign_extend_helpers():
    for ea in FindInSegments("55 48 83 ec 20 48 8d 6c 24 20 88 4d 10 0f b6 45 10 48 0f be c0 48 63 c0 48 8d 65 00 5d c3"): LabelAddressPlus(ea, 'sign_extend_char')
    for ea in FindInSegments("55 48 83 ec 20 48 8d 6c 24 20 89 4d 10 8b 45 10 48 63 c0 48 8d 65 00 5d c3"): LabelAddressPlus(ea, 'sign_extend_int')

def label_CreateThread_callers():
    for ea in FunctionsMatching('CreateThread'):
        refs = [x for x in xrefs_to(ea) if GetFuncName(x)]
        for addr in refs:
            fnHead = GetFuncStart(addr)
            if not HasUserName(fnHead):
                callsFnName = GetFuncName(ea)
                LabelAddressPlus(fnHead, f'calls_{callsFnName}')

def fix_fat_jumps():
    for ea in Heads(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea):
        if isUnconditionalJmp(ea) and 0x40 <= Byte(ea) < 0x4f:
            forceCode(ea + 1)

def big_chunks():
    return _.sort([(GetChunkCount(ea), ean(ea)) for ea in Functions()])[-50:]



def fig():
    r = []
    count = 1
    while count:
        print("count: {}".format(count))
        count = 0
        r.extend(FindInSegments(["55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3", "55 48 8d 2d ?? ?? ?? ?? 48 87", "48 8d 64 24 08 48 8b", "48 8d 64 24 f8 ?? 89", "54 58 48 83 ?? 08 ??", "54 5a 48 83 ?? 08 ??", "55 48 bd ?? ?? ?? ??"], 'any'))
        r = list(set(r))
        if not r:
            break
        for ea in r:
            # print("fig {:#x}".format(ea))
            while obfu.patch(ea):
                count += 1

def name_vtable_refs():
    r = [ea for ea in xrefs_to('GTAAlloc_16') if isCall(ea)]
    r.extend([ea for ea in xrefs_to('GTAAlloc_16_0') if isCall(ea)])
    r2 = [_.filter(GetFuncHeads(ea), lambda ea, *a: insn_match(ea, idaapi.NN_lea, (idc.o_reg, None), (idc.o_mem, 5)) and re.match(r'\?\?_7\w', ean(GetTarget(ea)))) for ea in r]
    r3 = _.filter(r2)
    for ea in r3:
        if len(ea) == 1:
            ea = ea[0]
            fnLoc = GetFuncStart(ea)
            if not IsValidEA(fnLoc):
                continue
            fnName = GetFuncName(fnLoc)
            # dprint("[name_vtable_refs] fnName")
            tgt = GetTarget(ea)
            print("[name_vtable_refs] fnName:{} - {}".format(fnName, ean(tgt)))
            
            dem = idc.demangle_name(ean(tgt), DEMNAM_NAME)
            # dprint("[name_vtable_refs] dem")
            print("[name_vtable_refs] dem:{}".format(dem))
            
            if not dem:
                continue
            vtbl_name = string_between('const ', "::`vftable'", dem)
            # dprint("[name_vtable_refs] vtbl_name")
            print("[name_vtable_refs] vtbl_name:{}".format(vtbl_name))
            
            # dprint("[name_vtable_refs] ean(fnLoc)")
            print("[name_vtable_refs] ean(fnLoc):{}".format(ean(fnLoc)))
            
            if vtbl_name and not HasUserName(fnLoc) or ean(fnLoc).startswith(('au_', 'allocsub_', 'possible_')):
                LabelAddressPlus(fnLoc, 'possible_init_{}'.format(vtbl_name))

def make_patch(funcea=None, *args, **kwargs):
    """
    make_patch

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [make_patch(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    print("\n".join(make_native_patchfile(funcea, *args, **kwargs)))

def compact_spdlist(spdList):
    """
    json.dumps(_.flatten(list(compact_spdlist(spdList))))
    """
    l = iter(spdList)
    x = next(l)
    yield x
    last = x[0]
    lspd = x[1]
    for x in l:
        x = (x[0] - last, x[1] - lspd)
        last = x[0] + last
        lspd = x[1] + lspd
        yield "({},{})".format(*x)

def expand_spdlist(c):
    l = iter(c); x = next(l); yield x; j, k = x
    for x in l: x = (x[0] + j, x[1] + k); j, k = x; yield x

def expand_chunklist(c):
    l = iter(c); x = next(l); yield (x[0], x[0] + x[1]); j, k = x; 
    for x in l: x = (x[0] + j, x[0] + j + x[1]); j, k = x; yield x

def compact_chunklist(spdList):
    """
    json.dumps(_.flatten(list(compact_spdlist(spdList))))
    """
    l = iter(spdList)
    x = next(l)
    yield "({},{})".format(x[0], x[1]-x[0])
    last = x[0]
    for x in l:
        x = (x[0] - last, x[1] - x[0])
        last = x[0] + last
        yield "({},{})".format(*x)

def expand_chunklist(c):
    l = iter(c); x = next(l); yield (x[0], x[0] + x[1]); j, k = x; 
    for x in l: x = (x[0] + j, x[0] + j + x[1]); j, k = x; yield x
    
def NotTails(start=None, end=None):
    """
    Get a list of heads (instructions or data items)

    @param start: start address (default: inf.min_ea)
    @param end:   end address (default: inf.max_ea)

    @return: list of heads between start and end
    """
    if start is None: start = ida_ida.cvar.inf.min_ea
    if end is None:   end = ida_ida.cvar.inf.max_ea

    ea = start
    if idc.is_tail(ida_bytes.get_flags(ea)):
        ea = ida_bytes.next_not_tail(ea)
    while ea < end and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.next_not_tail(ea)

def add_xrefs(ea=None):
    """
    add_xrefs

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [add_xrefs(x) for x in ea]

    ea = eax(ea)
    target = GetTarget(ea)
    if not IsValidEA(target):
        raise TypeError("Invalid instruction (no target) {:#x}".format(ea))

    if insn_match(ea, _jump_allins, (idc.o_near, 0), comment='jmp loc_140A86F59'):
        ida_xref.add_cref(ea, target, idc.fl_JN)
    elif insn_match(ea, idaapi.NN_call, (idc.o_near, 0), comment='call loc_1415C051C'):
        ida_xref.add_cref(ea, target, idc.fl_CN)
    elif insn_match(ea, idaapi.NN_callni, (idc.o_mem, 5), comment='call qword [rel GetEnvironmentVariableA]'):
        ida_xref.add_cref(ea, target, idc.fl_CN)
        ida_xref.add_dref(ea, target, idc.dr_R)
    elif insn_match(ea, idaapi.NN_lea, (idc.o_reg, None), (idc.o_mem, 5), comment='lea rdx, [rel unk_140A5BAD0]'):
        ida_xref.add_dref(ea, target, idc.dr_O)
    elif insn_match(ea, idaapi.NN_mov, (idc.o_reg, None), (idc.o_mem, 5), comment='mov r14, [rel qword_14278B698]'):
        ida_xref.add_dref(ea, target, idc.dr_R)
    elif insn_match(ea, idaapi.NN_mov, (idc.o_reg, None), (idc.o_imm, 0), comment='mov rbp, loc_14389EB8B'):
        ida_xref.add_dref(ea, target, idc.dr_O)
    elif insn_match(ea, idaapi.NN_mov, (idc.o_mem, 5), (idc.o_reg, None), comment='mov [rel qword_14278AE20], rax'):
        ida_xref.add_dref(ea, target, idc.dr_W)
    elif IsValidEA(target):
        insn_preview(ea)

_conditional_allins = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
_jump_allins = _conditional_allins + [ida_allins.NN_jmp]
def apply_xrefs():
    frms = [eax(x[1]) for x in file_enumerate_lines('i:/ida/gtasc-2699.16/xrefs.txt') if x[1]]
    srcs = [x[0] for x in [(ea, dii(ea)) for ea in frms] if x[1] and (x[1].startswith(('jmp', 'call')) or 'rip' in x[1])]
    failures = []
    for ea in srcs: 
        if ea in failures:
            continue
        create_insn(ea)
        end = EaseCode(ea, noExcept=1)
        if not IsValidEA(end):
            MyMakeUnknown(ea, 1, DOUNK_EXPAND)
            failures.append(ea)
            continue

        if IsCode_(ea) and IsValidEA(GetTarget(ea)):
            add_xrefs(ea)
        else:
            failures.append(ea)

    return failures

def fuckoff_concurrency():
    for ea in NamesMatching('.*Concurrency'): SetFuncFlags(ea, lambda f: f & ~idc.FUNC_LIB)
    for ea in NamesMatching('.*Concurrency'): LabelAddressPlus(ea, '')

def nop_unused_chunks(addrs=None, dryRun=False, put=False, nonfuncs=None):
    """
    nop_unused_chunks

    @param funcea: any address in the function
    """
    global global_chunks

    addrs = A(addrs)
    nonfuncs = A(nonfuncs)
    remove = set()
    keep = set()
    funcs = set()
    
    for addr in addrs:
        addr = eax(addr)
        func = ida_funcs.get_func(addr)

        if not func:
            print(AdvanceFailure("{:#x} wasn't a func (start)".format(addr)))
            continue

        funcea = func.start_ea
        ea = funcea
        funcName = ean(ea) if HasUserName(ea) else None

        remove.update([x for x in global_chunks[ea]]) # set([(0x14360fe0a, 0x14360fe1a), (0x140d098a8, 0x140d0990e), (0x143948961, 0x14394896d), (0x143948961, 0x143948968)])
        keep.update([x for x in idautils.Chunks(ea)])
        for cs, ce in global_chunks[ea]:
            for head in idautils.Heads(cs, ce):
                if IsFunc_(head) or _.filter(xrefs_to(head), lambda v, *a: IsFunc_(v)):
                    funcs.add(head)
                elif HasUserName(head):
                    keep.add((head, idc.next_not_tail(head)))

        while insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp TheJudge_rough_labor_orgy_0_0'):
            ea = GetTarget(ea)
            if not IsFunc_(ea):
                # raise AdvanceFailure("{:#x} wasn't a funchead".format(ea))
                nonfuncs.append(funcea)
                print(AdvanceFailure("{:#x} wasn't a func".format(ea)))
            else:
                keep.update([x for x in idautils.Chunks(ea)])
            if ea in global_chunks:
                remove.update([x for x in global_chunks[ea]])
            if not funcName and HasUserName(ea):
                funcName = ean(ea)
            if isNop(ea) and isJmp(idc.next_not_tail(ea)):
                ea = idc.next_head(ea)


            for cs, ce in global_chunks[ea]:
                for head in idautils.Heads(cs, ce):
                    if IsFunc_(head):
                        funcs.add(head)
                    elif HasUserName(head):
                        keep.add((head, idc.next_not_tail(head)))

    print("adding tangential functions")
    for head in funcs:
        keep.update([x for x in idautils.Chunks(head)])

    print("genericranging1")
    rse1 = GenericRanger([GenericRange(x[0], trend=x[1]) for x in remove], sort=1)
    print("genericranging2")
    rse2 = GenericRanger([GenericRange(x[0], trend=x[1]) for x in keep], sort=1)
    # dprint("[nop_unused_chunks] rse1, rse2")
    # print("[nop_unused_chunks] rse1:{}, rse2:{}".format(rse1, rse2))
    
    print("difference")
    kill = difference(rse1, rse2)

    setglobal('rse1', rse1)
    setglobal('rse2', rse2)
    setglobal('_remove', remove)
    setglobal('_keep', keep)
    if not dryRun:
        for d0 in kill:
            PatchNops(d0.start, len(d0), put=put, nop=0x00, comment="unused: {}".format(funcName or ean(funcea)))
    return kill


def test12(ProcessAffinityMask):
    # gets num of bits set as long as ProcessAffinityMask is uint8_t
    v7 = ((ProcessAffinityMask - ((_uint32(ProcessAffinityMask) >> 1) & 0x55555555)) & 0x33333333) \
       + (((_uint32(ProcessAffinityMask) - ((_uint32(ProcessAffinityMask) >> 1) & 0x55555555)) >> 2) & 0x33333333)
    v8 = (0x1010101 * ((v7 + (v7 >> 4)) & 0xF0F0F0F)) >> 24
    return v8

def test13(b):
    # gets num of bits set as long as ProcessAffinityMask is uint8_t
    return _uint32((b & 0xFF00 | (b << 16)) << 8) | ((HIWORD(b) | b & 0xFF0000) >> 8)

def chunkdenser(gc):
    _chunks = [x for x in gc]
    existing_range = _.flatten(asList([range(*x) for x in _chunks]))
    return set([x.chunk() for x in GenericRanger(existing_range, sort=1)])

def global_chunkdenser():
    gc = defaultdict(set)
    for addr, chunks in global_chunks.items():
        if chunks:
            gc[addr] = chunkdenser(chunks)

    return gc

def re_match_array(pattern, strings, flags=0):
    """
    match(pattern, strings, flags=0)

    Try to apply the pattern at the start of each string in the list, returning
    a match object, or None if no match was found.
    """

    for string in strings:
        res = re.match(pattern, string, flags=flags)
        if res:
            return res

def truncate_arxan_leaders():
    for ea in FunctionsMatching(r'The(Judge|Witch|Corpsegrinder|Investigator)'):
        if isCall(ea):
            if GetNumChunks(ea) > 1:
                RemoveAllChunks(ea)
            if GetFuncEnd(ea) > ea + IdaGetInsnLen(ea):
                if not SetFuncEnd(ea, ea + IdaGetInsnLen(ea)):
                    printi("{:x} failed to setfuncend".format(ea))

def find_call_nop_jumps():
    l = FindInSegments('e8 ?? ?? ?? ?? 90 e9 ?? ?? ?? ??')
    l = [x for x in l if not IsFunc_(x) and IsValidEA(GetTarget(x)) and IsValidEA(GetTarget(x + 6))]
    count_good = 0
    count_bad = 0
    visited = set()
    p = ProgressBar(len(l), len(l))
    p.always_print = True
    p.show_percentage = False
    for ea in l.copy():
        target = GetTarget(ea)
        possible_later_targets = SkipJumps(target, returnJumps=True, returnTarget=True)
        if not _.any(possible_later_targets, lambda v, *a: v in later2):
            later2.add(target)
            later.add(target)
        if IsFunc_(ea):
            continue
        r = pprev(ea, 1, quiet=1)
        print("[find_call_nop_jumps] {:#x} ... {}".format(ea, ahex(r)))
        p.update(count_good, count_bad)
        if IsValidEA(r) and r not in visited and not ean(r).startswith(('Arxan')):
            visited.add(r)
            # ida_retrace(r)
            ida_retrace(r, zero=0, smart=0, calls=1, forceRemoveFuncs=1, ignoreChunks=1)
            if retrace(r, noResume=1) == 0:
                to_remove = [x for x in l if IsFunc_(x)]
                count_good += len(to_remove)
                for addr in to_remove:
                    l.remove(addr)
                    continue
                if not IsFunc_(r):
                    print("{:#x} was not the solution for {:#x}".format(r, ea))
        count_bad += 1

def rename_native_helpers(funcea=None):
    ctr_text = "░▒▓█▓▒░┅"
    ctr = 0
    ctr_len = len(ctr_text)
    ctr_interval = 1
    ctr_icount = 0
    ctr_interval_count = 0
    ctr_hpos = 0
    for ea in (_.uniq(_.sort(SkipJumps(l, skipObfu=1, skipNops=1)), 1) if funcea is None else [funcea]):
        " // [NATIVE-ARGS] 0x2d15550f7fcd5086 APPS FUNC STRING APP_GET_STRING(STRING name) "
        " // [NATIVE-ARGS] 0xbe6c25a9cd239f04 APPS PROC APP_CLEAR_BLOCK()"

        with Commenter(ea, 'func') as c:
            r = c.matches('\[NATIVE-ARGS]')
        if not r:
            print('No [NATIVE-ARGS] comment at {:#x}'.format(ea))
            continue
        bn = r[0]

        _u,        bn = string_between_splice('', '[NATIVE-ARGS] ', bn, repl='', inclusive=1)
        _hash,     bn = string_between_splice('', ' ',              bn, repl='', inclusive=1)
        _ns,       bn = string_between_splice('', ' ',              bn, repl='', inclusive=1)
        _funcproc, bn = string_between_splice('', ' ',              bn, repl='', inclusive=1)
        _rtype = 'void*'
        if _funcproc.startswith('FUNC'):
            _rtype, bn =  string_between_splice('', ' ', bn, repl='', inclusive=1)
        elif _funcproc.startswith('PROC'):
            _rtype = '__int64'
        else:
            # dprint("[rename_native_helpers] _funcproc")
            # dprint("[rename_native_helpers] _u, _hash, _ns, _funcproc")
            print("[rename_native_helpers] r[0]:{}, _u:{}, _hash:{}, _ns:{}, _funcproc:{}".format(r[0], _u, _hash, _ns, _funcproc))
            
            
        _args = [string_between('', '=', x, retn_all_on_fail=1) for x in _.filter(string_between('(', ')', bn).split(', '))]
        # list(filter(lambda x: x, ''.split(',')))
        
        fnName = GetFuncName(ea).replace('NATIVE::', '')
        "common2:NETSHOPPING::NET_GAMESERVER_TRANSFER_WALLET_TO_BANK_ACT"
        filter = lambda x: x.type not in (ida_xref.fl_F, )
        all_helpers = external_refs_from(ea)
        helpers = [helper for helper in all_helpers 
                if not _.any(xrefs_to(helper, filter=lambda x: x.type in (idc.fl_JN, idc.fl_CN)), 
                    lambda v, *a: 
                        IsFunc_(v) and 'NATIVE::' in GetFuncName(v) and not ida_funcs.is_same_func(ea, v)
                        # or 'common2' in GetFuncName(v) and GetFuncName(v)[8:-4] not in fnName
                        )
                ]
        # dprint("[rename_native_helpers] x")
        # print("[rename_native_helpers] helpers:{}".format(ean(helpers)))
        
        # dprint("[rename_native_helpers] _names")
        # print("[rename_native_helpers] _names:{}".format(_names))
        

        # helpers = _.filter([external_refs_from_unique(ea, lambda x: len(xrefs_to(x)) == 1)])
        if not all_helpers:
            continue

        for addr in all_helpers:
            if addr not in later2:
                later2.add(addr)
                later.add(addr)

        fnCode = decompile_function(ea)
        '// [NATIVE-ARGS] 0x2d15550f7fcd5086 APPS FUNC STRING APP_GET_STRING(STRING name)'
        'void __fastcall NATIVE::APPS::APP_GET_STRING_ACTUAL(native args)'
        '{'
        '    args->pReturn->a1.STRING_ = apps_app_get_string_impl((__int64)args->pArgs->a1.STRING_);'
        '}'
        'args->pReturn->a1.ABILITY_ICON_ = (unsigned __int8)return_false(qword_1420CEA38) == 0;'

        if debug: print("{}: {}/{} helpers".format(ean(ea), len(helpers), len(all_helpers)))

        if not debug:
            ctr_icount += 1
            if ctr_icount == ctr_interval:
                ctr_icount = 0
                ctr_interval_count += 1
                _msgline = len(ida_kernwin.msg_get_lines(1)[-1])
                _advanced = _msgline - ctr_hpos
                # idc.msg(str(_advanced))
                if ctr_interval_count > 2 and _advanced > 3 and ctr_hpos > -1:
                    idc.msg("\n")
                    ctr_hpos = 0 
                else:
                    ctr_hpos = _msgline
                idc.msg(ctr_text[ctr] + " ")
                ctr += 1
                if ctr >= ctr_len:
                    ctr = 0
        for y in all_helpers:
            nicename = ean(y).lstrip('_').replace('common2:', 'common2_')
            if not IsValidEA(y):
                print("{}: invalid ea".format(y))
                continue
            _type = idc.GetType(y)
            _call = _.first(_.filter(fnCode, lambda v, *a: (nicename + '(') in v)) or\
                    _.first(_.filter(fnCode, lambda v, *a: (nicename + ')(') in v))
            if not _call:
                print("skipping helper {}".format(nicename))
                later2.add(y)
                continue
            # dprint("[rename_native_helpers] call")
            #  print("[rename_native_helpers] call:{}".format(_call))
            
            _cargs = string_between(nicename + '(', ')', _call, greedy=1)
            # dprint("[rename_native_helpers] _type, _cargs")
            # print("[rename_native_helpers] _type:{}, _cargs:{}".format(_type, _cargs))
            
            while True:
                _cast, _cargs = string_between_splice('(', ')', _cargs, repl='', inclusive=1)
                if not _cast: break
            # dprint("[rename_native_helpers] _cargs")
            # print("[rename_native_helpers] _cargs:{}".format(_cargs))
            '[rename_native_helpers] _cargs:args->pArgs->a1.ABILITY_ICON_, args->pArgs->a2.ABILITY_ICON_'

            if _.all(_cargs.split(', '), lambda v, i, *a: f'pArgs->a{i+1}' in v):
                _type = f'{_rtype} __fastcall func({", ".join(_args)});'
                if not idc.SetType(y, _type):
                    print("!SetType({:#x}, '{}')".format(y, _type))
                else:
                    if debug: print("SetType({:#x}, '{}')".format(y, _type))

            else:
                pass
                if debug: print("Nope: {}({})".format(nicename, _cargs))


            'char *__fastcall(__int64)'
            if y in helpers:
                LabelAddressPlus(
                    y, 
                    fnName
                        .replace('NATIVE::', '')
                        .replace('_ACTUAL', '_impl')
                        .replace('::', '_').lower()
                    )

def top():
    import sys
    def sizeof_fmt(num, suffix='B'):
        ''' by Fred Cirera,  https://stackoverflow.com/a/1094933/1870254, modified'''
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)

    for name, size in sorted(((name, sys.getsizeof(value)) for name, value in locals().items()),
                             key= lambda x: -x[1])[:10]:
        print("{:>30}: {:>8}".format(name, sizeof_fmt(size)))

def Plan(*args, name='unknown'):
    # from...
    'unpatch_func2'
    'unpatch_func2'
    'PatchNops'
    'modify_chunks.add'
    'SmartAddChunk.shorten'
    'SmartAddChunk.lengthen'
    'SmartAddChunk.new'
    ida_auto.revert_ida_decisions(*args[0:2])
    ida_auto.plan_range(*args[0:2])
    return 1
    return ida_auto.plan_and_wait(*args)

if hasglobal('PerfTimer'):
    __slowtrace_helpers__ = [ida_retrace_patch, ida_retrace_extend, ida_retrace_advance, _fix_spd, Plan, RebuildFuncAndSubs, RecurseCalled, func_rename_vtable_xref, isListOf, RecurseCalledRange, CheckChunks, GetAllChunks, NotHeads, TrimChunks, RemoveAllChunksAndFunctions, check_append_func_tail, FindBadJumps, FindJmpChunks, SkipJmpChunks, FixAllChunks, FixChunks, FixChunk, FixAdjoiningChunks, ZeroFunction, Decompile, DecompileAllAfter, RemoveLocName, RemoveRelocFunction, RemoveLoneNullSubs, IsSameChunk, IsSameFunc, PerformInSegments, DecodePrevInsn, CreateInsns, FindRvaOffsetsTo, FindOffsetsTo, FastFindRefsTo, ForceFindRefsTo, GetTarget, GetTarget7, opTypeAsName, insnITypeAsName, PickChunkOwner, GetChunkOwner, GetChunkOwners, GetChunkReferers, RemoveOtherChunkOwners, idc_append_func_tail, SmartAddChunkImpl, GetChunkStart, GetChunkStarts, GetChunkCount, GetChunkEnd, GetChunkNumber, FuncContains, RemoveChunkOwner, SetChunkOwner, GetChunkReferer, GetNumChunks, IsChunkEnd, IsChunk, IdaGetInsnLen, InsnRange, InsnRangePlusOne, InsnRangeIgnoreFirst, InsnRangePlusOneIgnoreFirst, GetRbp, GetSpDiffEx, SetSpDiffEx, ZeroCode, IsOffset64, IsHeadChunk, IsChunked, SetChunkStart, AppendFunc, FuncFindRetrace, FuncFindNopChunks, FuncFindTrailingChunks, FuncFindBadJumps, FuncFindApplySkipJumps, FuncFindUnusedChunks, FuncTidyJumps, FuncObfuPatch, SetChunkEnd, SetFuncOrChunkEnd, thing, GetChunk, GetChunkPP, IsNiceFunc, insn_opercount, insn_preview, insn_mpreview, di_insn_preview, insn_match, insn_mmatch, GetFuncInfo, GetFuncChunked, GetFuncChunkCount, FuncRefsTo, GetFuncName, RenameFunctionsRe, GetFuncSize, GetUnchunkedFuncSize, GetJumpTarget, MakeSigned, GetRawJumpTarget, SkipJumps, FuncSkipJumps, CountConsecutiveMnem, AdvanceToMnem, OldAdvanceToMnemEx, RemoveNativeRegistration, MutatorCombinations, hexf16, h16list, find_element_in_list, fixCallAndJmpObfu, fixRdata, fixAllRdata, SetSpd, colorSubs, ida_retrace, FixThunks, FixJmpLocRet, RecurseCallers, RecurseCallersChart, FindDestructs, _isUnlikely_mnem, perform, preprocessIsX, _isJmp_mnem, _isAnyJmpOrCall, _isUnconditionalJmp_mnem, _isUnconditionalJmpOrCall_mnem, _isPushPop_mnem, _isNop_mnem, _isInterrupt_mnem, isUnlikely, isFlowEnd, isAnyJmp, isOffset, isRet, isAnyJmpOrCall, isCall, isConditionalJmp, isJmp, isPushPop, isPop, isUnconditionalJmp, isUnconditionalJmpOrCall, isInterrupt, isObfuJmp, isJmpOrObfuJmp, isCallOrObfuCall, isCallOrObfuCallPatch, isNop, isOpaqueJmp, isCodeish, IsFlowEx, jmpTarget, CountConsecutiveCalls, first_iterable, last_iterable, all_xrefs_, all_xrefs_from, all_xrefs_to, external_refs_to, call_refs_from, jmp_refs_from, external_refs_from, external_refs_from_unique, jmp_refs_from, call_refs_to, skip_jmp_refs_to, XrefTypeNames, SkipJumpsTo, label_import_thunks, func_refs_to, shared_xrefs_to, xrefs_to_ex, xrefs_to, seg_refs_to, SegmentRefsTo, isSegmentInXrefsTo, GetFuncHeadsIter, GetFuncHeads, CheckFuncSpDiffs, GetDisasmFuncHeads, GetMinSpd, bad_as_none, GetSpds, GetAllSpds, RemoveLameFuncs, GetSpdsMinMax, GetAllSpdsMinMax, IsFuncSpdBalanced, IsFuncSpdZero, camelCase_snake, PascalCase, camelCase, camel_case_to_snake_case, camelcase, MakeUniqueLabel, shortName, compact, extract, is_prime, is_possible_cygwin_symlink, read_possible_cygwin_symlink, process_cygwin_symlinks, process_path, clean_path, dot_draw, is_nothing_sub, handle_function, traceBackwards, UnpatchUntilChunk, UnloadFunction, remove_func_or_chunk, CheckThunk, ForceFunction, listOfBytesAsHex, hex_byte_as_pattern_int, hex_string_as_list, hex_pattern, make_pattern_from_hex_list, swap32, swap64, patternAsHex, compare, matcher, cleanLine, exportFlags, exportDataNames, ShowAppendFunc, force_chunk, adjust_tails, ShowAppendFchunk, ShowAppendFchunkReal, GetInsnLenths, GetInsnCount, GetInsnRange, EndOfContig, EndOfFlow, MakeCodeEx, remake_func, reanal_func, fix_non_func, SetFuncStart, SetFuncEnd, rangesAsChunks, modify_chunks, chunk_remove_range, reloc_name, readObjectFile, color_here, int_to_rgb, lighten, make_transpose_fn, transpose, gradient, hex_to_rgb, hex_to_rgb_dword, hex_to_colorsys_rgb, colorsys_rgb_to_dword, colorsys_rgb_to_rgb, rgb_to_hex, rgb_to_int, call_everything, clone_items, read_everything, UnChunk, GetAllNames, FindAll, RefsTo, AllRefsTo, AllRefsFrom, find_function_callees, CallRefsTo, JmpRefsTo, GetChunks, MicroChunks, split_chunks, split_chunks_compact, OurGetChunkStart, OurGetChunkEnd, GetChunkAddresses, GetChunkAddressesZeroOffset, CheckAllChunkForMultipleOwners, RemoveChunk, RemoveThisChunk, RemoveGrannyChunks, RemoveAllChunkOwners, RemoveAllChunks, GetFuncType, MyGetType, get_dtype, get_create_data_func, testchunks, AddRelocSegment, _fix_spd_auto, generate_disasm_line_unspaced, fix_split_refs, fix_split_refs_2245, colwrap, join2, fix_split_segment_jump, fix_location_plus_2, FunctionsPdata, remove_crappy_funcs, populate_functions_from_pdata, get_pdata_fnStart, isPdata, fix_dualowned_chunk, fix_dualowned_chunks, name_priority, get_best_parent, find_database_errors, ChunkHeads, print_ip, make_ip, find_ips, EaseCode, some_rubbish, GetCodeHash, GetFuncHash, FixAllFixups, FindObfu, GetFunc, GetFuncStart, GetFuncStartOrEa, GetFuncEnd, hex_byte_as_pattern_int, MakeCodeAndWait, partial, return_value, return_value_lambda, return_value_lambda_args, setTimeout, ReinforceFunc, forceAllAsCode, forceAsCode, MakeUniqueLabel, LabelAddressPlus, LabelAddress, get_name_by_any, make_rtti_json, Chunk, get_ea_by_any, eax, IsValidEA, ValidateEA, get_cfunc_by_any, get_func_by_any, jump, fix_links_to_reloc, GetDisasmForce, escape_c, GetDisasmColor, isgenerator, isflattenable, genAsList, glen, dict_append, rename_functions, bt_prevhead_until_noflow, bt_prevhead_until_xref, MyGetOperandValue, MyGetOperandDisplacement, MyMakeUnknown, MyMakeUnkn, example_fixup_visitor, visit_fixups, SetFuncFlags, MakeThunk, FixFarFunc, IsThunk, MyMakeFunction, EnsureFunction, Find, findAndTrace, GetCodeRefsFromFunc, analyze, analyzePlan, RecreateFunction, dinjasm, oget, dotted, deep_get, getmanyattr, isDictlike, isListlike, isSliceable, hascallable, array_count, isIterable, isIterator, isIterableNotIterator, isByteArray, isInt, isIntString, isString, isStringish, isBytes, isByteish, asByteArray, asBytes, asString, asBytesRaw, asStringRaw, asRaw, asDict, asTuple, intAsBytes, bytesAsInt, MakeUniqueLabel, get_start, get_last, intersect, intersect_gap, overlaps, issubset, issuperset, issettest, adjoins, union, overlap2a, difference, overlap2, overlap3, iter_overlap_test, not_overlap3, format_chunk_range, describe_chunk, describe_target, auto_name_common_functions, bestOf3Names, name_common_function, diStripNatives, fix_func_tails, funcname, my_append_func_tail, xxd, GetBase64String, stacktrace, st1, st2, clear, get_nbits, read_all_emu, SuperJump, join_helper_functions, process_balance, call_if_callable, fix_sub_args, fix_sub_args_unknown, namesource, bin32, polymul, prngSeedNext, prngSeedPrev, prngSeedPrevCalc, prngNextCalc, rng_init, HIWORD, rng_twirl, rngtest, rng_test, codeguard, isgenerator, isflattenable, recursive_map, hexmap, hex_callback, ahex, listComp, asList, asHexList, addrAsVtable, rename_nullsub_offsets, label_time_vars, label_sign_extend_helpers, label_CreateThread_callers, fix_fat_jumps, big_chunks, fig, name_vtable_refs, make_patch, compact_spdlist, expand_spdlist, expand_chunklist, compact_chunklist, expand_chunklist, NotTails, add_xrefs, apply_xrefs, fuckoff_concurrency, nop_unused_chunks, test12, test13, chunkdenser, global_chunkdenser, re_match_array, truncate_arxan_leaders, find_call_nop_jumps, rename_native_helpers]
    PerfTimer.binditems(locals(), funcs=__slowtrace_helpers__, name='slowtrace_helpers')
# b0
# r = read_emu_glob(['lobby_idaho_alert', 'total_bleed_alan', 'scent_seek_alive', 'drain_novel_alert', 'gun_fear_alert'])
# ['drain_novel_alert', 'cali_cream_alan', 'were_site_air', 'hal_trend_alike', 'rank_civic_orgy', 'film_been_alan', 'sour_style_alike', 'gash_tool_alert', 'lobby_idaho_alert', 'rigid_hen_alert', 'mine_sum_air', 'total_bleed_alan', 'god_tie_alert', 'suit_hello_orgy', 'stood_screw_air', 'spoke_noon_alert', 'acres_tale_alike', 'fed_bring_alfa', 'onset_roman_air', 'sew_lean_orgy', 'slave_asked_ally', 'greek_life_alive', 'grew_story_air', 'voice_roof_air', 'gun_fear_alert', 'some_papa_alike']
# b16
# r = read_emu_glob('rub_duck_aim') 
# r.extend(read_emu_glob('moved_shell_aim'))
# r.extend(read_emu_glob('pip_obey_air'))
# r.extend(read_emu_glob('set_win_orgy'))
# r.extend(read_emu_glob('error_site_aim'))
#
# r.extend(read_emu_glob('moved_shell_aim', 'balance', skipFuncs=1))
# r.extend(read_emu_glob('pip_obey_air', 'balance', skipFuncs=1))
# r.extend(read_emu_glob('set_win_orgy', 'balance', skipFuncs=1))
# r.extend(read_emu_glob(['desk_honey_air', 'belt_just_alert', 'pity_rob_orgy', 'apply_nail_air', 'error_site_aim', 'beam_agree_aim'], 'balance', skipFuncs=1))
#
# post-unpack: register_native_namespaces: 'fail_jump_alert', 
# already included in dump: 'piano_daily_acid', 'hair_greed_aim'
# pb = unpatch_all()
# r = read_emu_glob(['piano_daily_acid', 'hair_greed_aim', 'gear_among_aim', 'admit_arm_orgy', 'apply_nail_air', 'beam_agree_aim', 'belt_just_alert', 'bet_buy_acid', 'check_silk_aim', 'desk_honey_air', 
#    'error_site_aim', 'house_fog_alert', 'moved_catch_air', 'moved_shell_aim', 'phone_null_alert', 'pip_obey_air', 'pity_rob_orgy', 'pogo_shelf_aim', 'rub_duck_aim', 'set_win_orgy', 'still_lift_aim', 
#     'alert_hear_air',     'fail_jump_alert'] , 'balance', put=0)
# for x, y in pb: ida_bytes.patch_byte(x, y)
# r2 = emujoin(_.flatten(r, 1))
# 
# pb = unpatch_all()
# r = read_emu_glob(['gear_among_aim', 'admit_arm_orgy', 'apply_nail_air', 'beam_agree_aim', 'belt_just_alert', 'bet_buy_acid', 'check_silk_aim', 'desk_honey_air', 
#    'error_site_aim', 'house_fog_alert', 'moved_catch_air', 'moved_shell_aim', 'phone_null_alert', 'pip_obey_air', 'pity_rob_orgy', 'pogo_shelf_aim', 'rub_duck_aim', 'set_win_orgy', 'still_lift_aim', 
#     'alert_hear_air',] , 'balance', put=1)
# for x, y in pb: ida_bytes.patch_byte(x, y)
# r2 = emujoin(_.flatten(r, 1))
# [name_common_function(x) for x in [external_refs_from(addr) for addr in FunctionsMatching('NATIVE::.*_ACTUAL$')]];
#
# for ea in FindInSegments("55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24", 'any'): obfu.patch(ea)
# for ea in [x for x in FindInSegments('48 BD ?? ?? ?? ?? 01 00 00 00') if IsCode_(x)]: idc.op_plain_offset(ea, 1, 0)
# for ea in FunctionsPdata(): SkipJumps(ea, 1) or EaseCode(ea, forceStart=1), SkipJumps(ea, 1)
# for ea in FunctionsPdata(): EaseCode(ea, forceStart=1), EaseCode(SkipJumps(ea, 1), forceStart=1)
# for ea in FunctionsPdata(): EaseCode(ea, forceStart=1), EaseCode(SkipJumps(ea, 1), forceStart=1); l = list(FunctionsPdata()); retrace_list(l, once=1)
# for ea in FunctionsPdata(): EaseCode(ea, forceStart=1), EaseCode(SkipJumps(ea, 1), forceStart=1); l = [x for x in FunctionsPdata() if not IsNiceFunc(x)]; retrace_list(l, once=1)
# l = [x for x in SkipJumps(FunctionsPdata()) if not IsNiceFunc(x, verbose=1)]; retrace_list(l, once=1)
# skjpd = SkipJumps(FunctionsPdata()); l = [x for x in skjpd if not IsNiceFunc(x, verbose=1)]; retrace_list(l, once=1)
#
# Python>for ea in [x for x in _.uniq(GetFuncStart(call_refs_to('RegisterNative'))) if IsValidEA(x)]:
# Python>    for cs, ce in Chunks(ea):
# Python>        PatchNops(cs, ce - cs)
# Python>    ZeroFunction(ea)
# Python>
#
# [ida_bytes.revert_byte(ea) for ea in _.flatten([list(y) for y in [range(x, x + GetInsnLen(x)) for x in m]])]
# r3 = [eax(x) for x in _.uniq(r2, 0, lambda v, *a: GetFuncName(v) or ean(v))]
# for ea in FindInSegments("55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3", 'any'): obfu.patch(ea)
# for ea in FindInSegments("55 48 8d 2d ?? ?? ?? ?? 48 87", 'any'): obfu.patch(ea)
# l1 = [x[0] for x in r if x[1][1] in (4,) and xrefs_to_ex(x[0], flow=0, filter=lambda x: x.type.startswith('d'))]; l2 = [x[0] for x in r if x[1][1] in (4,) and not xrefs_to_ex(x[0], flow=0, filter=lambda x: not x.type.startswith('d'))]; r = [x for x in r if x[0] not in l1 and x[0] not in l2]
# 
# ZeroFunction([ea for ea in Functions() if _.any(ean(GetFuncStart(list(DataRefsTo(ea)))), lambda v, *a: v.startswith('Arxan'))], total=1)
# for ea in ([x for x in NamesMatching('.*BunnyCave') if len(xrefs_to(x)) == 0], ''): (LabelAddressPlus(ea, ''), RemoveChunk(GetFuncStart(ea), ea))
# ZeroFunction([ea for ea in Functions() if _.any(GetFuncName(_.flatten(xrefs_to(GetFuncStart(xrefs_to(ea))))), lambda v, *a: v.startswith('Arxan'))], total=1)
# pprev
# nice = _.countBy([insn_preview(ea) for ea in [x for x in FunctionsPdata() if GetNumChunks(x) == 0 and IsFuncSpdBalanced(x, nonzero=1) ]])
#  _.filter(xrefs_to(helper, filter=lambda x: x.type in (idc.fl_JN, idc.fl_CN)), 
    #  lambda v, *a: 
    #  'NATIVE::' in ean(v) and ean(v) != fnName or 
    #  'common2' in ean(v) and ean(v)[8:-4] not in fnName)
    #
#  r = read_emu_glob(['piano_daily_acid', 'hair_greed_aim', 'gear_among_aim', 'admit_arm_orgy', 'apply_nail_air', 'beam_agree_aim', 'belt_just_alert', 'bet_buy_acid', 'check_silk_aim', 'desk_honey_air',
   #  'error_site_aim', 'house_fog_alert', 'moved_catch_air', 'moved_shell_aim', 'phone_null_alert', 'pip_obey_air', 'pity_rob_orgy', 'pogo_shelf_aim', 'rub_duck_aim', 'set_win_orgy', 'still_lift_aim',
    #  'alert_hear_air',     'fail_jump_alert'] , 'balance', put=0)
#  r2 = emujoin(_.flatten(r, 1))
#  find_shifty_stuff()
# l3 = r2 + [x.ea for x in failed] + l + _.flatten(shifty) + [x for x in FindInSegments('e8 ?? ?? ?? ?? 90 e9 ?? ?? ?? ??') if IsValidEA(GetTarget(x)) and IsValidEA(GetTarget(x + 6))] + FindObfu()
# l3 = [x.ea for x in r2 if isinstance(x, FuncTailsInsn)] + [x for x in r2 if isinstance(x, int)] + [x.ea for x in failed] + list(l) + \
#      list(_.flatten(shifty)) + [x for x in FindInSegments('e8 ?? ?? ?? ?? 90 e9 ?? ?? ?? ??') if IsValidEA(GetTarget(x)) and IsValidEA(GetTarget(x + 6))] + list(FindObfu())
# ida_retrace(ea, zero=0, smart=0, calls=1, forceRemoveFuncs=1, ignoreChunks=1)
