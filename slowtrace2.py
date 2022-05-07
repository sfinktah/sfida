from __future__ import print_function
import colorsys
import idc
import re
from static_vars import static_vars
from queue import Queue
import traceback
import inspect
import subprocess
import textwrap
from static_vars import static_vars
from superglobals import *
from attrdict1 import SimpleAttrDict
_import("progress")
# _import("from rle import RunLengthList")
from rle import RunLengthList

# #  from sets import set
#  from circularlist import CircularList
if not idc:
    # import obfu
    # from di import *
    # from helpers import *
    # from membrick import *
    # from nasm import *
    # from obfu_helpers import *
    # from ranger import GenericRanger
    # from sfcommon import *
    # from sftools import fix_links_to_reloc, SmartAddChunkImpl, smartadder, MyMakeUnkn, MyMakeUnknown, MyMakeFunction, \
    #    analyze, dinjasm
    # from slowtrace2_helpers import isSegmentInXrefsTo, opTypeAsName, traceBackwards, ForceFunction, forgeAheadWithCode, \
    #    cleanLine, ShowAppendFchunk, EndOfContig, EndOfFlow, remake_func, fix_non_func, reloc_name, hex_to_colorsys_rgb, \
    #    colorsys_rgb_to_rgb, rgb_to_int
    # from slowtrace_helpers import ZeroFunction, IsFunc_, IsFuncHead, IsSameFunc, GetChunkOwner, GetChunkEnd, InsnLen, \
    #    InsnRange, SetSpDiffEx, IsChunked, GetFuncSize, SetSpd, isAnyJmp, isCall
    # from start import *
    # from string_between import string_between_repl
    from test import *

if six.PY2:
    itertools.zip_longest = itertools.izip_longest

#  from commenter import Commenter

#  def refresh(filepath = __file__, _globals = None, _locals = None):
#  print("Reading {}...".format(filepath))
#  if _globals is None:
#  _globals = globals()
#  _globals.update({
#  "__file__": filepath,
#  "__name__": "__main__",
#  })
#  with open(filepath, 'rb') as file:
#  exec(compile(file.read(), filepath, 'exec'), _globals, _locals)


def is_healed_col(c): return is_hldchk_col(c) & c >> 16 in (1, 0x14)
def is_checkd_col(c): return is_hldchk_col(c) & c >> 16 in (1, 0x28)
def is_hldchk_col(c): return is_hldchk_msk(c) & c >> 16 == 1
def is_hldchk_msk(c): return c & 0xc2ffff == 0x000128
get_byte = idc.get_wide_byte

#  with open(os.path.dirname(__file__) + os.sep + 'refresh.py', 'r') as f: exec (
    #  compile(f.read().replace('__BASE__', os.path.basename(__file__).replace('.py', '')).replace('__FILE__', __file__),
            #  __file__, 'exec'))

from exectools import execfile, make_refresh
_refresh_slowtrace2 = make_refresh(os.path.abspath(__file__))
_refresh_slowtrace_helpers = make_refresh(os.path.abspath(__file__.replace('2', '_helpers')))
def refresh_slowtrace2():
    _refresh_slowtrace_helpers()
    _refresh_slowtrace2()
    refresh_func_tails()

check_for_update_1 = make_auto_refresh(os.path.abspath(__file__.replace('2', '_helpers')))
check_for_update_2 = make_auto_refresh(os.path.abspath(__file__))
check_for_update = lambda: (check_for_update_1(), check_for_update_2())

def auto_refresh(fn):
    check = make_auto_refresh(fn)
    def decorate(func):
        check()
        return func
    return decorate

re_version = re.compile(r'gta(s[ct]).*?[^0-9](\d{3,4})[^0-9]')
if 'get_idb_path' not in globals():
    _source = 'sc'
    _build = '2372'
else:
    for __source, __build in re.findall(re_version, get_idb_path()):
        _source = __source
        _build = __build


class SlowtraceSingleStep(Exception):
    """ChunkFailure.
    """

    pass

sprint = print

def indent(n, s, skipEmpty=True, splitWith='\n', joinWith='\n', n2plus=None, skipFirst=False, stripLeft=False, width=70, indentString=' '):
    
    if isString(s):
        s = s.replace('\r', '').split(splitWith)

    if width:
        assert isinstance(width, int)
        r = []
        if skipFirst:
            r.append(s[0][0:width])
            s[0] = s[0][width:]
            if not s[0]:
                s.pop(0)
        r.extend([textwrap.wrap(line, width=width - n) for line in s])
        s = _.flatten(r)

    result = []

    for i, line in enumerate(s):
        if i == 1 and n2plus is not None:
            n = n2plus
        if isinstance(line, list):
            print("[indent] line: {}".format(line))
            continue
        
        if stripLeft:
            line = line.lstrip()
        if skipFirst and not i:
            result.append(line)
            continue
        if not skipEmpty or line.rstrip():
            if isinstance(n, str):
                result.append(n + line)
            elif isinstance(n, int):
                result.append(indentString * n + line)

    if joinWith:
        return joinWith.join(result)
    return result

def getglobal(key, default=None):
    """
    getglobal(key[, default]) -> value
    
    Return the value for key if key is in the global dictionary, else default.
    """
    return globals().get(key, default)
    pass

debug = getglobal('debug', 0)

def itypes(pattern):
    keys = [k for k in ida_allins.__dict__ if re.match(r'(?:NN_)?' + pattern, k, re.I)]
    return [getattr(ida_allins, k, -1) for k in keys]

def IsStackOperand(ea, ignoreLeaDisplacement=0):
    if isinstance(ea, ida_ua.insn_t):
        insn = ea
    else:
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, get_ea_by_any(ea))
        if inslen == 0:
            return None 

        # lea     rsp, [rbp+80h]
        if ignoreLeaDisplacement:
            if insn.itype == 0x5c: # lea
                if insn.ops[0].type == ida_ua.o_reg and \
                   insn.ops[1].type == ida_ua.o_displ:
                       return False

        # if insn.itype in itypes(r'(push|pop)'): return True
        if insn.itype in [0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x2c2]: 
            # printi(hex(ea), 'insn.itype', get_itype_string(insn.itype))
            return True

        # rsp is operand 1
        if insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == 4 \
                and insn.ops[1].type != ida_ua.o_reg: 
                    if insn.itype in [ida_allins.NN_test]:
                        Commenter(ea).add("Warning: stack-alignment obfu")
                        return False

                    return True
        return False

def vimlike(ea=None, **kwargs):
    """
    open de-chunked asm listing in vim

    @param ea: linear address
    """
    ea = GetFuncStart(eax(ea))
    return slowtrace2(ea, removeFuncs=1, noObfu=1, silent=1, vim=-1, modify=0, ignoreStack=1, ignoreExtraStack=1, fatalStack=0, **kwargs)

def vim(ea=None, **kwargs):
    """
    open de-chunked asm listing in vim

    @param ea: linear address
    """
    ea = GetFuncStart(eax(ea))
    slowtrace2(ea, removeFuncs=1, noObfu=1, silent=1, vim=1, modify=0, ignoreStack=1, ignoreExtraStack=1, fatalStack=0, **kwargs)

def vimr(ea=BADADDR):
    if ea == BADADDR:
        ea = ScreenEA()
    slowtrace2(ea, removeFuncs=1, noObfu=1, silent=1, vim=1, modify=0, reloc=1, force=1)


#  idaapi.add_hotkey("Shift-Alt-S", smartadder)


def remake(ea):
    return remake_func(ea)


#  def MakeFunction(start, end=ida_idaapi.BADADDR):
#  return ida_funcs.add_func(start, end)


def retrace_noexcept(address=0, live=False):
    if address == 0:
        address = ScreenEA()
    if not IsFunc_(address) and not add_func(address) and not ForceFunction(address):
        return
    ea = address
    while True:
        slowtrace2(ea, color="#224", removeFuncs=1, silent=1, live=live)
        ida_auto.auto_wait()
        slowtrace2(address, color="#224", removeFuncs=1, silent=1, live=live)
        ida_auto.auto_wait()
        break


def reloc(address=0, live=False, force=False, color="#224"):
    if address == 0:
        address = ScreenEA()
    if not ForceFunction(address):
        printi("[warn] reloc: couldn't force function at {:x}".format(address))
        return
    ea = address
    count = -1 
    while True:
        try:
            count += 1
            if force and count > 0:
                return
            # idc.set_color(address, CIC_ITEM, ~idc.get_color(address, CIC_ITEM) & 0xffffff)
            slowtrace2(ea, cursor=1, color=color, removeFuncs=1, silent=1, live=live, reloc=1, force=force, modify=count)
            ida_auto.auto_wait()
            break
        except RelocationPatchedError as e:
            pass
        except RelocationStackError as e:
            if count > 1:
                return
        except RelocationInvalidStackError as e:
            if count > 1:
                return
        except KeyboardInterrupt as e:
            printi("******* KEYTHINGY!! ********")
            raise e
        except:
            if count > 1:
                return
    ida_auto.auto_wait()


def follow_call_thunks(ea = 0):
    if ea == 0:
        ea = idc.get_screen_ea()
    count = 0
    while idc.get_wide_byte(ea) == 0xe8:
        ea = ea + 5 + MakeSigned(idc.get_wide_dword(ea + 1), 32)
        count += 1
    return ea, count

def stopped():
    return os.path.exists('e:/git/ida/stop')

def retrace_list(address, pre=None, post=None, recolor=0, func=0, color="#280c01", spd=0, tails=0, dual=0, jump=0, zero=0, unpatch=0, chunk=False, *args, **kwargs):
    if address is None:
        return
    if os.path.exists('e:/git/ida/stop'):
        printi("*** STOP ***")
        return
    skipped = list()

    def fail(ea, post):
        if post:
            post = list(post)
            for _post in post:
                if callable(_post):
                    _post(ea)
                    
    def success(ea, post):
        return fail(ea, post)

    def color_thunks():
        if ea not in skipped:
            l = ''
            if HasUserName(ea):
                l = GetTrueName(ea)
            skipped.append((ea, l))
        retrace_list_thunk_colors = gradient("#280c01", "#643700", len(skipped))
        for i, x in enumerate(skipped):
            addr, label = x
            Wait()
            if func:
                if addr == ea:
                    r = MyMakeFunction(addr)
                else:
                    r = MyMakeFunction(addr, GetInsnLen(addr))
                if not r:
                    printi("{} MyMakeFunction(0x{:x}) returned {}".format(i, addr, r))
            if IsFuncHead(addr):
                idc.set_color(addr, CIC_FUNC, hex_to_rgb_dword(retrace_list_thunk_colors[i]))
            else:
                idc.set_color(addr, CIC_ITEM, hex_to_rgb_dword(retrace_list_thunk_colors[i]))
                LabelAddressPlus(addr, label)

    def skip(x):
        l = ''
        if HasUserName(x):
            l = GetTrueName(x)
        skipped.append((x, l))
        if 0:
            if not recolor: 
                ZeroFunction(x, 1)

    # retrace_list_thunk_colors = gradient("#280c01", "#662222", 6)
    if not recolor: 
        p = ProgressBar(len(address), len(address))
        p.always_print = True
    good = 0
    bad = 0
    for i, ea in enumerate([x for x in list(address) if IsValidEA(x)]):
    # for ea in address[0:]:
        rv = None
        pre_tried = []
        if pre is not None:
            _unchanged_hash_count = 0
            _new_hash = None
            _last_hash = None
            pre = list(pre)
            for _pre in pre:
                if callable(_pre):
                    pre_tried.append(_pre.__name__)
                    if _new_hash is not None:
                        if _new_hash == _last_hash:
                            _unchanged_hash_count += 1
                        else:
                            _unchanged_hash_count = 0
                    _last_hash = _new_hash
                    try: 
                        printi("*****")
                        printi("** pre: [{}] {}-{} for {}".format(_pre.__name__, _unchanged_hash_count, hex(_last_hash), idc.get_name(ea, ida_name.GN_VISIBLE)))
                        _pre(ea)
                        printi("*****")
                        try: 
                            rv = retrace(SkipJumps(ea), chunk=chunk, **kwargs)
                            _new_hash = GetFuncHash(ea)
                            if rv == 0:
                                printi("********** SOLVED {} **********".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                                printi("********** SOLVED {} **********".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                                printi("********** SOLVED {} **********".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                                printi("********** SOLVED {} **********".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                                printi("pre_tried: {}".format(", ".join(pre_tried)))
                                address.remove(ea)
                                break

                        except Exception as e:
                            printi("**** pre inner: Exception: {}: {}".format(e.__class__.__name__, str(e)))
                    except Exception as e:
                        printi("** pre: Exception: {}: {}".format(e.__class__.__name__, str(e)))
                    _new_hash = GetFuncHash(ea)

        if pre is not None:
            if rv != 0:
                fail(ea, post)
                printi("########## FAILED {} ##########".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                printi("########## FAILED {} ##########".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                printi("########## FAILED {} ##########".format(idc.get_name(ea), ida_name.GN_VISIBLE))
                printi("########## FAILED {} ##########".format(idc.get_name(ea), ida_name.GN_VISIBLE))
            if rv == 0:
                success(ea, post)
            continue
        try:
            skipped.clear()
        except AttributeError:
            # py2
            del skipped[:]

        if not recolor:
            p.update(good, bad)
            #  p.update_good(good)
            #  p.update_bad(bad)
            #  p.update(i)
        try:
            sk = SkipJumps(ea, skipShort=0, iteratee=lambda x, *a: skip(x))
            ValidateEA(sk)
        except AdvanceFailure as e:
            printi("AdvanceFailure: {}".format(str(e)))
            raise
            #  printi("[retrace_list] SkipJumps::AdvanceFailure {}".format('\n'.join(e.args)))
            #  if 'unpatch_func2' in globals():
                #  skipped.reverse()
                #  for x in skipped:
                    #  unpatch_func2(x[0], unpatch=1)
            #  return
        try:
            #  printi("num: {}".format(i))
            #  if idc.get_segm_name(ea) == '.text' and idc.get_func_attr(ea, idc.FUNCATTR_FLAGS) & FUNC_LIB == 0:
            if jump:
                idc.jumpto(sk)
            if unpatch:
                # UnpatchFunc(sk)
                unpatch_func(sk)
            if zero:
                ZeroFunction(sk)
            if not recolor:
                MyMakeFunction(sk)
            if not recolor:
                rv = retrace(sk, chunk=chunk, **kwargs)
                msg = ("retrace returned {} for {:x}".format(hex(rv), sk))
                printi(msg)
                #  if chunk:
                    #  yield msg

            if rv != 0:
                fail(ea, post)
            if rv == 0:
                success(ea, post)
            if recolor or rv == 0:
                # printi("*** GOOD *** {:x}".format(sk))
                address.remove(ea)
                good += 1
                if recolor and skipped:
                    skipped.reverse()
                    color_thunks()
                if func:
                    MyMakeFunction(sk)
                if tails:
                    func_tails(sk, externalTargets=externalTargets, extra_args=kwargs)
                if spd:
                    _fix_spd_auto(sk)
                continue
            else:
                pass
                #  if not recolor:
                    #  if dual:
                        #  for addr in Chunks(sk):
                            #  fix_dualowned_chunk(addr[0])
                        #  ZeroFunction(ea)
        except RelocationStackError as e:
            if ~str(e).find('incorrect SpDiff 0x0'):
                for addr in Chunks(sk):
                    fix_dualowned_chunk(addr[0])

            else:
                fail(ea, post)
                continue
                #  ZeroFunction(sk)
        except AdvanceFailure as e:
            printi("AdvanceFailure: {}".format(str(e)))
            fail(ea, post)
            raise

        except AttributeError as e:
            raise

        except Exception as e:
            printi("* pre outer: Exception: {}: {}".format(e.__class__.__name__, str(e)))
            fail(ea, post)
            pass

        bad += 1

def iter_retrace_list(address, recolor=0, func=0, color="#280c01", spd=0, tails=0, dual=0, jump=0, zero=0, unpatch=0, chunk=False, *args, **kwargs):
    if address is None:
        return
    skipped = list()
    def skip(x):
        l = ''
        if HasUserName(x):
            l = GetTrueName(x)
        skipped.append((x, l))
        if 0:
            if not recolor: 
                ZeroFunction(x, 1)

    # retrace_list_thunk_colors = gradient("#280c01", "#662222", 6)
    good = 0
    bad = 0
    for i, ea in enumerate([x for x in list(address) if IsValidEA(x)]):
    # for ea in address[0:]:
        try:
            skipped.clear()
        except AttributeError:
            # py2
            del skipped[:]

        try:
            sk = SkipJumps(ea, skipShort=0, iteratee=lambda x, *a: skip(x))
            ValidateEA(sk)
        except AdvanceFailure as e:
            print("[retrace_list] SkipJumps::AdvanceFailure {}".format('\n'.join(e.args)))
            if 'unpatch_func2' in globals():
                skipped.reverse()
                for x in skipped:
                    unpatch_func2(x[0], unpatch=1)
        try:
            #  printi("num: {}".format(i))
            #  if idc.get_segm_name(ea) == '.text' and idc.get_func_attr(ea, idc.FUNCATTR_FLAGS) & FUNC_LIB == 0:
            if jump:
                idc.jumpto(sk)
            if unpatch:
                UnpatchFunc(sk)
            if zero:
                ZeroFunction(sk)
            MyMakeFunction(sk)
            output = []
            rv = retrace(sk, output=output, **kwargs)
            msg = ("retrace returned {} for {:x}".format(hex(rv), sk))
            yield [msg] + output

        except RelocationStackError as e:
            if ~str(e).find('incorrect SpDiff 0x0'):
                for addr in Chunks(sk):
                    fix_dualowned_chunk(addr[0])

            else:
                continue
                #  ZeroFunction(sk)
        except AdvanceFailure as e:
            printi("AdvanceFailure: {}".format(str(e)))
            pass

        bad += 1
def unpatch(funcea=None):
    """
    unpatch

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    for r in range(10):
        UnpatchFunc(funcea)
        slowtrace2(ea, removeFuncs=1, noObfu=1, silent=1, vim=-1, modify=0, ignoreStack=1, ignoreExtraStack=1, fatalStack=0)
        ZeroFunction(funcea)
        slowtrace2(ea, removeFuncs=1, noObfu=1, silent=1, vim=-1, modify=0, ignoreStack=1, ignoreExtraStack=1, fatalStack=0)


def RecreateFunctionThunks(ea=None):
    """
    RecreateFunctionThunks

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [RecreateFunctionThunks(x) for x in ea]

    def helper(x, *a):
        if IsFunc_(x):
            unpatch_func2(x, unpatch=1)
            idc.del_func(x)
            idc.auto_wait()
        UnpatchUntilChunk(x)
        # ForceFunction(x)

    ea = eax(ea)

    jumps = SkipJumps(ea, returnJumps=1)
    target = SkipJumps(ea)
    jumps = _.uniq(jumps)
    print("[RecreateFunctionThunks] jumps: {} target: {:x}".format(hex(jumps), target))
    for addr in jumps:
        helper(addr)
    for addr in jumps:
        retrace(addr, thunk=1)
        if isJmp(addr):
            jumps.append(GetTarget(addr))


def retrace_add_chunks(ea=None, **kwargs):
    return retrace_list(ea, removeFuncs=1, noObfu=1, modify=0, adjustStack=1, appendChunks=1, once=1, **kwargs)

def retrace_skip_jumps(ea=None, **kwargs):
    return retrace_list(ea, removeFuncs=1, noObfu=1, modify=0, adjustStack=1, applySkipJumps=1, once=1, **kwargs)

def retrace_unpatch(address, **kwargs):
    clear(); 
    # refresh_slowtrace2(); 
    retrace_list(address, applySkipJumps=0, forceRemoveChunks=0, once=1, pre=[GetFuncName, unpatch_func2, unpatch_func, ZeroFunction, unpatch_func2, unpatch_func, ZeroFunction, unpatch_func2, unpatch_func, ZeroFunction], **kwargs)

def retrace(address=None, color="#280c01", retails=False, redux=False, unpatchFirst=False, unpatch=False, once=False, recreate=False, chunk=False, **kwargs):
    if isinstance(address, list):
        return [retrace(x, **kwargs) for x in address]


    externalTargets = defaultglobal('externalTargets', set())
    global warn
    # dprint("[retrace] args, kwargs")
    if idc.batch(0):
        printi("*** Batch Was enabled ***")
    with TraceDepth() as _depth:

    # printi("[retrace] args:{}, kwargs:{}".format(args, kwargs))
    

        funcea = GetFuncStart(address)
        if funcea != idc.BADADDR:
            address = funcea
        address = SkipJumps(eax(address))
        start_address = address
        #  depth = kwargs.get('depth', 0)
        if not 'last_retrace' in globals() or isinstance(globals()['last_retrace'], int):
            globals()['last_retrace'] = [hex(address)]
        else:
            globals()['last_retrace'].insert(0, indent(_depth, ' ', hex(address)))
        if not IsFuncHead(address) and not ForceFunction(address) and not IsFuncHead(address):
            printi("[retrace] [warn] couldn't force function at {:x}".format(address))
            
            return

        if recreate:
            RecreateFunction(funcea)

        rv = None
        funcea_ori = funcea
        if retails or redux:
            funcea = SkipJumps(funcea)
        if retails:
            output = None
            ft = func_tails(funcea, quiet=1, output=output, externalTargets=externalTargets, extra_args=kwargs)
            if ft:
                printi('\n'.join(ft))
                RecreateFunction(funcea)
                ft = func_tails(funcea, quiet=1, output=output, externalTargets=externalTargets, extra_args=kwargs)
                if ft:
                    printi('\n'.join(ft))
            if not ft:
                if not redux:
                    rv = _fix_spd_auto(funcea)
                    
                    return rv
        if redux:
            try:
                if (retails and rv == 0) or retrace(funcea, vimlike=1, once=1, **kwargs) == 0:
                    printi("{:x} vimlike retrace: {}".format(funcea, 0))
                    _fix_spd_auto(funcea)
                    if IsFuncSpdBalanced:
                        printi("{:x} SpdBalanced: {}".format(funcea, 'ok'))
                        ft = func_tails(funcea, quiet=1, externalTargets=externalTargets, extra_args=kwargs)
                        if ft:
                            printi("{:x} func_tails: {}".format(funcea, "\n".join(ft)))
                        else:
                            printi("{:x} func_tails: {}".format(funcea, 'clean'))
                            
                            return 0
            except AdvanceFailure as e:
                printi("{:x} AdvanceFailure: {}".format(funcea, e))

            locs = SkipJumps(start_address, returnJumps=1)
            locs.append(SkipJumps(start_address))
            for ea in locs:
                idc.del_func(ea)
            UnpatchUn()
            SkipJumps(start_address, iteratee=lambda x, *a: idc.add_func(x, EaseCode(x)))

        if unpatchFirst:
            unpatch_func2(funcea, unpatch=1)
            ZeroFunction(funcea)

        if idc.get_func_flags(funcea) & idc.FUNC_FAR:
            # printi("[info] removed FUNC_FAR from {:x}".format(funcea))
            SetFuncFlags(funcea, lambda f: f & ~(idc.FUNC_FAR | idc.FUNC_USERFAR))

        ea = address
        count = -1
        rv = 0
        count_limit = 3
        last_hash = None
        _hash = None
        patchResults = []
        last_error = None
        extra_args = dict()
        extra_args.update(kwargs)
        while count < count_limit:
            if patchResults: # patches or rv != last_rv:
                if count_limit < 50:
                    if (count_limit - count) < 3:
                        count_limit = count + 3 
                patchResults = []
            count += 1
            try:
                if os.path.exists('e:/git/ida/stop'):
                    printi("*** STOP ***")
                    
                    return
                last_rv = rv
                last_hash = _hash
                FixChunks(ea, leave=ea)
                
                warn = 0
                traceOutput = []
                patches = 0
                # slvars.rsp_diff was none
                _old_hash = GetFuncHash(ea)
                patchResults = []
                spdList = []
                setglobal('spdList', spdList)
                try:
                    #  print("count #{}/{}".format(count, count_limit))
                    rv = slowtrace2(ea, color=color, returnPatches=patchResults, returnOutput=traceOutput, spdList=spdList, **kwargs)
                except AdvanceReverse as e:
                    rv = slowtrace2(e.args[0], color=color, returnPatches=patchResults, returnOutput=traceOutput, spdList=spdList, **kwargs)
                _new_hash = GetFuncHash(ea)
                if _old_hash == _new_hash:
                    printi("hash stayed at {:x}".format(_new_hash))
                if once:
                    if rv != 0 and unpatch:
                        UnpatchFunc(ea)
                        
                        return retrace(ea, once=once, **kwargs)
                    
                    return rv
                for r in patchResults:
                        #  pp(r)
                    patches += 1
                for r in traceOutput:
                    if re.match(r""".*(slvars.rsp_diff|couldn't create instruction|\[warn]|unexpected stack change)""", r):
                        #  pp(r)
                        patches += 1
                printi("slowtrace returned {}".format(rv))
                ft_patches = 0
                ft = func_tails(funcea, returnErrorObjects=1, quiet=1, externalTargets=externalTargets, extra_args=extra_args)
                printi("func_tails returned {}".format(len(ft)))
                if ft:
                    # ft = func_tails(ft)
                    printi("fix_func_tails({}, {})".format(pph(ft), extra_args))
                    ft_patches += fix_func_tails(ft, extra_args)
                    printi("fix_func_tails returned")
                if _old_hash == _new_hash and rv != 0:
                    if rv != 0 and unpatch:
                        UnpatchFunc(ea)
                    printi("Finishing as hash stayed at {:x}".format(_new_hash))
                    
                    return rv

                if ft_patches:
                    printi("***** RERUNNING DUE TO FIX_FUNC_TAILS *****")
                if patches:
                    printi("***** RERUNNING DUE TO PATCHES|WARNING MESSAGES *****")
                if ft_patches or patches:
                    count += 1
                    continue
                if rv == 0:
                    if last_rv == 0:
                        if warn:
                            if count < count_limit - 1:
                                printi("***** RERUNNING DUE TO WARNING MESSAGES *****")
                                count = count_limit - 1
                                continue
                    # ft = func_tails(funcea, returnErrorObjects=1, quiet=1, externalTargets=externalTargets)
                    if ft:
                        if not IsFunc_(funcea):
                            printi("0x{:x} is no longer a function, switching to 0x{:x}".format(funcea, address))
                            funcea = address
                        ft = func_tails(funcea, returnErrorObjects=0, quiet=1, externalTargets=externalTargets, extra_args=extra_args)
                    if ft:
                        printi('\n'.join([str(x) for x in ft]))
                        
                        return -1
                    elif spdList:
                        #  spd = _fix_spd_auto(SkipJumps(ea)) != 0
                        for r in range(100):
                            if r > 10:
                                printi("_fix_spd(spdList) attempt {}".format(r))
                            if not _fix_spd(spdList):
                                break
                    
                    return rv
            except RelocationUnpatchRequest as e:
                printi("slowtrace threw {} {}".format(e.__class__.__name__, str(e)))
                #  UnpatchFunc(ea)
                
                return -1
                pass

            except AdvanceFailure as e:
                printi("retrace caught {} {}".format(e.__class__.__name__, str(e)))
                dontraise = True
                sb = string_between('advance past ', '', str(e)) or \
                        string_between('create instruction at ', '', str(e))
                if sb:
                    sbi = int(sb, 16)
                    for x in range(sbi, sbi+8):
                        if idc.get_wide_dword(x) == 0:
                            dontraise = True
                            printi("reverting dword at 0x{:x}".format(x))
                            UnPatch(sbi, x+4)


                if '0xffffffffffffffff' in str(e):
                    dontraise=1
                if not dontraise:
                    printi("not dontraise")
                    raise

                tb = traceback.format_exc()
                printi(tb)
                if type(last_error) == type(e):
                    
                    return -2
                    unpatch_func2(ea, unpatch=1)
                    UnpatchUn()
                    last_error = None
                else:
                    last_error = e
                #  self.exc_info = sys.exc_info()
                pass
            except RelocationStackError as e:
                printi("[retrace] slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                if once:
                    return -1
                # unconditional jmp to another sub 0x143abfbe2, retn rsp of 88
                # dprint("[debug] type(e.args)")
                #  m = re.search(r"unconditional jmp to another sub ([^,]+), retn rsp of ([-0-9a-f]+)", e.args[0])
                m = re.search(r"\((0x[0-9a-fA-F]+)\) which has no stack", str(e))
                if m:
                    if count == 0:
                        printi("checking offending function")
                        retrace(eax(m.group(1)), once=1, forceRemoveChunks=1, **kwargs)
                #  if re.search(r"isRealFunc: jmpRef: more than 1 ref", str(e)):
                    #  if count == 0:
                        #  TruncateThunks()
                #  tb = traceback.format_exc()
                #  printi(tb)
                pass
            except RelocationInvalidStackError as e:
                printi("[retrace] slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                
                return -1
            except RelocationTerminalError as e:
                printi("[retrace] slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                tb = traceback.format_exc()
                printi(tb)
                FixChunks(ea, leave=ea)
                #  ZeroFunction(ea)
                pass
            except RelocationPatchedError as e:
                printi("[retrace] slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                tb = traceback.format_exc()
                printi(tb)
                count_limit = min(10, count_limit + 1)
                pass
            except ChunkFailure as e:
                printi("[retrace] slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                tb = traceback.format_exc()
                printi(tb)
                FixChunks(ea, leave=ea)
                pass
                #  printi("RelocationPatchedError...")
                #  printi(e)
                #  printi(e.value)
                #  printi(type(e.value))
                #  printi("Done")
                #  if isinstance(e.value, circularlist):
                #  addr = e.value[0]
                #  if True and isinstance(addr, (int, long)) and addr != ea:
                #  if True or debug: printi("0x%x: shifting start to 0x%x" % (ea, addr))
                #  ea = addr
            #  except RelocationInvalidStackError:
                #  pass
    #  
            except KeyboardInterrupt as e:
                printi("******* KEYTHINGY!! ********")
                raise KeyboardInterrupt
        ida_auto.auto_wait()


# http://stackoverflow.com/questions/1112618/import-python-package-from-local-directory-into-interpreter
# nvm
# from sfcommon import *

st_limit = None

branches = []

class ObfuError(Exception):
    def __str__(self):
        return ' '.join([ahex(x) for x in self.args])
    pass

class ChunkFailure(ObfuError):
    pass

class ArxanFailure(ObfuError):
    pass


class AdvanceFailure(ObfuError):
    pass

class AdvanceReverse(ObfuError):
    pass

class InvalidInstruction(ObfuError):
    pass


class RelocationDupeError(ObfuError):
    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        super(RelocationDupeError, self).__init__(message)

        # Now for your custom code...
        #  self.errors = errors

class RelocationUnpatchRequest(ObfuError):
    pass

class RelocationStackError(ObfuError):
    pass


class RelocationInvalidStackError(ObfuError):
    pass


class RelocationPatchedError(ObfuError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class RelocationTerminalError(ObfuError):
    pass


class RelocationAssemblerError(ObfuError):
    pass

later = globals().get('later', set())
later2 = globals().get('later2', set())
if 'arxan_comments' not in globals():
    arxan_comments = dict()

@auto_refresh(__file__)
def slowtrace2(ea=None,
               addComments=None,
               addFuncs=False,
               addsp=False,
               adjustCallers=False,
               adjustStack=True,
               adjustStackFake=False,
               anal=False,
               codeRefsTo=set(),
               color=None,
               cursor=False,
               follow=False,
               delsp=False,
               depth=0,
               distorm=False,
               extremeStack=True,
               fakesp=False,
               fatalStack=False,
               force=False,
               forceRemoveChunks=False,
               fresh=True,
               helper=None,
               ignoreExtraStack=False,
               ignoreInt=False,
               ignoreStack=False,
               include=False,
               jcFirst=False,
               labelNextCall=False,
               limit=BADADDR,
               live=False,
               max_depth=32,
               modify=True,
               noAppendChunks=False,
               noDenyJmp=False,
               noJunk=True,
               noMakeFunction=False,
               noObfu=False,
               noPdata=False,
               noResume=False,
               output=None,
               plan=False,
               process=None,
               regexPatch=False,
               relabel=False,
               reloc=False,
               remake=False,
               removeFuncs=True,
               removeDenyJmp=False,
               returnOutput=None,
               returnPatches=None,
               returnResult=False,
               showComments=False,
               silent=True,
               single=False,
               skipJumps=True,
               applySkipJumps=False,
               skipNops=False,
               spdList=[],
               stop=BADADDR,
               stopAtCall=False,
               stopAtJmp=False,
               thunk=False,
               vim=False,
               vimedit=False,
               vimlike=False,
               which=None,
               appendChunks=False,
               ):
    ##  check_for_update()
    check_for_update_1()
    check_for_update_2()

    if vimlike:
        removeFuncs=1
        noObfu=1
        silent=1
        vim=-1
        modify=0
        ignoreStack=1
        ignoreExtraStack=1
        fatalStack=0
    def arg_check(arg_list, arg_name, arg_value, arg_default):
        if arg_value != arg_default:
            arg_list[arg_name] = arg_value
        return arg_list

    arg_list = dict()
    for k, v in slowtrace2.defaults:
        if k in ('ea', ):
            continue
        value = eval(k, locals(), locals())
        if isinstance(value, list):
            pass
        else:
            arg_check(arg_list, k, value, v)

    pl = pprint.pformat(arg_list)

    global later
    global later2
    global arxan_comments
    later_pending = set()
    setglobal('g_output', output)
    slvars = SimpleAttrDict()
    slvars2 = SimpleAttrDict()
    slvars.addresses = set()
    global patchmarks
    patchmarks.clear()

    def sprint(*args):
        s = args[-1]
        if isinstance(s, Exception):
            printi("0x{:09x}: 0x{:09x}: {} {:x} {!r} ({})".format(slvars.startLoc, ea, len(slvars.addresses), slvars.rsp, str(s), type(s)))
            buf = "0x{:09x}: 0x{:09x}: {} {:x} {!s}".format(slvars.startLoc, ea, len(slvars.addresses), slvars.rsp, str(s))
            raise (type(s))(buf)
            
        buf = "0x{:09x}: 0x{:09x}: {} {:x} {}".format(slvars.startLoc, ea, len(slvars.addresses), slvars.rsp, str(s))
        if isinstance(args[0], tuple):
            if isinstance(debug, list):
                for filter in debug:
                    if re.search(filter, "::".join(args[0])):
                        printi(buf)
                return
        printi(buf)
        return s

    printi("slowtrace2 ea=0x{:09x} {} {}".format(ea, idc.get_func_name(ea), pl))
    global st_limit

    st_limit = limit
    if limit is None:
        st_limit = BADADDR
    colors = color
    color_darker = 0xffffffff
    color_darkest = 0xffffffff
    color_cursor = 0xffffffff
    if isinstance(color, str):
        color_cursor = ~hex_to_rgb_dword(color) & 0xffffff

        hsv_color_tuple = colorsys.rgb_to_hsv(*hex_to_colorsys_rgb(color))
        hsv_color_list = list(hsv_color_tuple)
        hsv_color_darker_list = hsv_color_list
        hsv_color_darker_list[1] -= 0.2
        hsv_color_darkest_list = hsv_color_list
        hsv_color_darkest_list[1] -= 0.3

        #  color = rgb_to_int(hex_to_rgb(color))
        color = rgb_to_int(colorsys_rgb_to_rgb(colorsys.hsv_to_rgb(*hsv_color_tuple)))
        color_darker = rgb_to_int(colorsys_rgb_to_rgb(colorsys.hsv_to_rgb(*hsv_color_darker_list)))
        color_darkest = rgb_to_int(colorsys_rgb_to_rgb(colorsys.hsv_to_rgb(*hsv_color_darkest_list)))


    slvars.addressesRemoved = 0
    slvars.cbuffer = CircularList(16)
    slvars.chunkAdding = 0
    slvars.contig = 0
    slvars.currentChunk = GetFuncStart(ea)
    slvars2.instructions = CircularList(200)
    slvars2.helped = set()
    slvars.maxSp = 0
    slvars.minSp = 0
    slvars.realStartLoc = GetFuncStart(ea)
    slvars.retSps = set()
    slvars.startFnName = get_name(ea) # if hasUserName(ida_bytes.get_flags(ea)) else "_{}".format(get_name(ea))
    slvars.startLoc = GetFuncStart(ea)
    slvars.name = Name(ea)
    if slvars.startLoc == BADADDR:
        slvars.startLoc = ea
    slvars.rspMarks = dict()
    slvars.rspHist = RunLengthList()
    slvars.insnCount = 0
    if debug: print("Start of slowtrace, type rspHist: {}".format(type(slvars.rspHist)))

    slvars2.appendLines = []
    slvars2.outputLines = []
    slvars2.previousHeads = CircularList(32)

    # note: these two can apply to the whole function, or just a chunk (if a chunk is what we're working with)
    idc.auto_wait()
    if not IsFuncHead(ea) and not ForceFunction(ea):
        if not IsFuncHead(ea):
            msg = ("[warn] slowtrace init: couldn't force function at {:x}".format(ea))
            raise RuntimeError(msg)

    slvars.chunkList = []
    slvars.fakedAddresses = []

    # new slvars
    slvars.willVisit = set()
    slvars.justVisited = set()
    slvars.justVisitedRsp = dict()
    slvars.branchStack = []
    slvars.branchNumber = []
    slvars.rsp = 0
    slvars.indent = 0

    idc.add_func(ea)
    if idc.get_fchunk_attr(ea, FUNCATTR_START) == BADADDR:
        sprint("Can't find func_start, making one here")
        if not ForceFunction(ea):
            raise AdvanceFailure("couldn't force function")

    #  sprint("%s" % GetFunctionName(ea))
    #  ida_auto.auto_wait()
    #  if type(max_depth) is int:
        #  depth = max_depth

    if reloc and force and idc.get_name_ea_simple(reloc_name(ea)) < BADADDR and idc.get_segm_name(
            idc.get_name_ea_simple(reloc_name(ea))) == '.text2':
        ZeroFunction(LocByName(reloc_name(ea)), total=True)
    if reloc and not vimedit and not distorm and LocByName(reloc_name(ea)) < BADADDR:
        msg = sprint("Function has already been relocated")
        if 'slvars' in globals(): sprint(RelocationDupeError(msg))
        raise RelocationDupeError(msg)

    relocPrefix = []
    patches = 0
    must_reverse = 0
    patched = []
    stateStack = []
    callStack = []
    rspStack = []
    mnemStack = []
    mnem = "unset"
    slvars.rsp_diff = 0
    line = ""
    disasm = ""
    counter = 0x00
    byteArray = []
    byteHexArray = []
    disasmArray = []
    tmpLimit = BADADDR
    obfu.combed.clear()
    if ea is BADADDR:
        return 0

    def VimEdit(address, string, wait=0):
        idb_subdir = GetIdbPath()
        idb_subdir = idb_subdir[:idb_subdir.rfind(os.sep)] + os.sep + "lst_%s" % GetInputFile()
        if not os.path.isdir(idb_subdir):
            os.mkdir(idb_subdir)

        fnName = GetFunctionName(address)  # "f_" + "%09x" % ea
        if fnName:
            asmName = re.sub(r'[^a-zA-Z0-9_]', '_', fnName)
        else:
            asmName = "unknown"

        if not wait:
            with open(idb_subdir + os.sep + '%s.lst' % asmName, "w+") as fw:
                fw.write(string)

        dir = idb_subdir

        os.chdir(dir)

        path = None
        if os.path.exists('C:/Users/sfink/Downloads/cyg-packages/bin'):
            path = 'C:/Users/sfink/Downloads/cyg-packages/bin'
        elif os.path.exists('C:/cygwin64/bin'):
            path = 'C:/cygwin64/bin'

        vim_filename = 'cmdvim.bat'
        if path is None:
            vim_executable_filepath = r'C:\Program Files (x86)\Vim\vim82\gvim.exe'
            if not os.path.exists(dot_executable_filepath):
                raise Exception("Please install gvim from https://www.vim.org/download.php")
        else:
            vim_executable_filepath = os.path.join(path, vim_filename)

        args = list()
        args.append("%s.lst" % asmName)

        args = [vim_executable_filepath] + list(args)
        if debug: sprint(args)
        # https://stackoverflow.com/a/6309753/912236
        try:
            if wait:
                process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE)
                process.wait()
                with open(idb_subdir + os.sep + '%s.lst' % asmName, "r") as f:
                    s = f.read()
                    printi(s)
                    return s
            else:
                subprocess.call(args)
        except subprocess.CalledProcessError as e:
            sprint("CalledProcessError: %s" % e.__dict__)
            return False, e.output

    def output(s):
        s = s.rstrip()
        if not showComments:
            cl = cleanLine(s)
            if reloc or vim or returnResult or showComments or ~cl.find(' '):
                slvars2.outputLines.append(cl)
        else:
            slvars2.outputLines.append(s)

        if not silent:
            printi(s)
        if isinstance(returnOutput, list):
            returnOutput.append(s)
        return ''

    def CheckChunkChange(new, old):
        # TODO: should check if chunk can be extended, even if belonging to same func
        
        if GetChunkNumber(new) != GetChunkNumber(old) and new != slvars.startLoc:
            rv = SmartAddChunk(new, old)
            #
        #  if GetChunkNumber(new) != GetChunkNumber(old) and GetChunkNumber(new) != 0:
            #  if IsSameFunc(new, old):
                #  if IsFlow(GetChunkEnd(idc.prev_head(new))):
                    #  print("Checking Chunk End (flows) {:x}".format(idc.prev_head(new)))
                #  else:
                    #  return
            #  rv = SmartAddChunk(new, old)

    def SmartAddChunk(new, old, end=0):
        if not modify and not appendChunks:
            return

        if GetChunkStart(new) == slvars.startLoc:
            return
        if GetChunkNumber(new, slvars.startLoc) == 0:
            return

        if IsChunk(new):
            owners = GetChunkOwners(new, includeOwner=1)
            if len(owners) > 0:
                if len(owners) > 1:
                    if debug: sprint("SmartAddChunk: {:x} has multiple owners".format(new))
                    FixChunk(new)
                    #  RemoveAllChunkOwners(new)
                    #  raise ChunkFailure("SmartAddChunk: {:x} has multiple owners".format(new))
                elif slvars.startLoc not in owners: 
                    if not HasUserName(owners[0]):
                        if debug: sprint("removing chunk from no-name func {:x} at {:x}".format(owners[0], new))
                        idc.remove_fchunk(owners[0], new)
                    else:
                        msg = "SmartAddChunk: {} already owned by {} while attempting to add to {}".format(
                                format_chunk_range(new), 
                                describe_target(owners[0]), 
                                describe_target(slvars.startLoc))
                        retrace(owners[0], once=1, forceRemoveChunks=1)
                        raise ChunkFailure(msg)

            if GetChunkNumber(new, slvars.startLoc) != GetChunkNumber(old, slvars.startLoc):
                cstart = GetChunkStart(new)
                cend = GetChunkEnd(new)
                if IsValidEA(cstart) and IsValidEA(cend):
                    sh = set((Heads(cstart, cend)))
                    snt = set((NotHeads(cstart, cend, lambda x: not IsTail(x), lambda x, *a: idc.next_not_tail(x))))
                    if snt.difference(sh) or not isFlowEnd(idc.prev_head(cend)):
                        end = EaseCode(cstart)
                        if end > cend:
                            printi("[SmartAddChunk] Setting chunk end from EaseCode: {:x} -> {:x}".format(cend, end))
                            SetChunkEnd(cstart, end)
                            ida_auto.plan_and_wait(cstart, end)
        else:
            # end = EndOfContig(new)
            try:
                end = EaseCode(new, forceStart=1) 
            except AdvanceFailure as e:
                printi("slowtrace threw {}: {}".format(e.__class__.__name__, str(e)))
                sb = string_between('advance past ', '', str(e))
                if sb:
                    sbi = int(sb, 16)
                    if idc.get_wide_dword(sbi) == 0:
                        printi("reverting dword at 0x{:x}".format(sbi))
                        for x in range(sbi, sbi+4):
                            ida_bytes.revert_byte(x)
                    else:
                        raise
                else:
                    raise

            #  if isRet(end):
                #  end += 1
            if debug: printi("[SmartAddChunk] New Chunk: {:x}-{:x}".format(new, end))
            if IsValidEA(end):
                rv = ida_auto.plan_and_wait(new, end)
                if not my_append_func_tail(slvars.startLoc, new, end):
                    for ea in idautils.Heads(new, end): GetDisasm(ea)
                    if not my_append_func_tail(slvars.startLoc, new, end):
                        printi("couldn't append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(slvars.startLoc, new, end))
                    else:
                        printi("succeeded after GetDisasm(EaseCode): append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(slvars.startLoc, new, end))
                else:
                    #  print("succeeded append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(slvars.startLoc, new, end))
                    if GetChunkNumber(new) == -1:
                        printi("why is chunk# -1 after append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(slvars.startLoc, new, end))

                idc.auto_wait()
        # EaseCode(new)

        if IsSameFunc(slvars.startLoc, new):
            return
        if not end:
            if 1:
                #  func = ida_funcs.func_t(new)
                cend = EndOfFlow(new, soft=ignoreInt)
            else:
                cend = new + GetInsnLen(new)
            #  res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
            #  if res == ida_funcs.FIND_FUNC_UNDEF:
                #  # func passed flow to unexplored bytes
                #  sprint("find_func_bounds: func passed flow to unexplored bytes")
            #  elif res == ida_funcs.FIND_FUNC_OK:
                #  cstart = func.start_ea
                #  cend = func.end_ea
            if debug: sprint("ShowAppendFchunk 48")
            return ShowAppendFchunkReal(slvars.startLoc, new, cend, old)
            #  idc.find_func_end
            #  end = EndOfContig(new)
                #  return SmartAddChunkImpl(slvars.startLoc, new, end)

    slvars.notification_interval = 128

    def ShouldAddChunk(old, new):
        if modify or appendChunks:
            # if debug: sprint("ShouldAddChunk: 0x{:x}, 0x{:x}".format(old, new))
            if new == old: return
            slvars.addresses.add(new)
            if len(slvars.addresses) % slvars.notification_interval == 0:
                #  slvars.addressesRemoved += len(slvars.addresses)
                #  slvars.addresses.clear()
                printi("{}k chunks...".format((slvars.addressesRemoved + len(slvars.addresses)) / 1024.0))
                #  slvars.notification_interval *= 2
            if GetChunkNumber(old) != GetChunkNumber(new):
                #  fix_non_func(new, old)
                CheckChunkChange(new, old)
                slvars.currentChunk = new
                slvars.contig = 1

    def ChangeTarget(old, new):
        if debug: sprint("Changing target 0x{:x}".format(new))
        ShouldAddChunk(old, new)
        return new

    def PopTarget(old, new):
        if debug: sprint("Popping target 0x{:x}".format(new))
        return ChangeTarget(old, new)

    def FollowTarget(old, new):
        return ChangeTarget(old, new)

    def ReverseHead(current_ea):
        if single:
            raise SlowtraceSingleStep("single-step enabled")
        if not len(slvars2.previousHeads):
            printi("no previous heads to reverse to")
            return current_ea

        branch = slvars2.previousHeads[0]
        slvars2.previousHeads.restart(1)
        for k in _.keys(branch.state):
            v = getattr(slvars, k, None)
            b = branch.state[k]
            if debug: printi("ReverseHead: {} := {}".format(k, hex(b) if isIterable(b) else b))
            if k == 'ea':
                pass
            elif k == 'instructions':
                if debug: sprint("rewrote slvars2.instructions with {} entries".format(len(b)))
                slvars2[k].clear()
                slvars2[k].extend(b)
            elif k == 'addresses':
                if debug: sprint("rewrote slvars.addresses with {} entries".format(len(b)))
                slvars[k].clear()
                for x in b:
                    slvars[k].add(x)
                #  slvars[k] == set([x for x in b])
            elif k not in slvars:
                printi("Reversing: would be adding field {} to slvars".format(k))
                v = None
            elif isinstance(v, list):
                #  printi("copying2 {} {}".format(k, v))
                v.clear()
                v.extend(b)
            elif isinstance(v, set):
                if isinstance(b, tuple):
                    if len(b) != 1:
                        raise RuntimeError("tuple of unhandy length {}".format(len(b)))
                    else:
                        b = b[0]
                # printi("copying type {} {} as list {} to set {}".format(type(b), b, k, v))
                v.clear()
                v.update(set(b))
                # printi("copied to set {}: {}".format(k, v))
            elif callable_m(v, 'copy'):
                #  printi("copying1 {} {}".format(k, v))
                setattr(slvars, k, v.copy())
                #  v.clear()
                #  v.extend(b)
            elif isinstance(v, integer_types):
                slvars[k] = b
            elif isinstance(v, string_types):
                slvars[k] = b

            else:
                #  printi(f"Reversing {k} {ahex(v)} -> {ahex(b)}")
                printi("Reversing: unhandled type: slvars[{}] (type:{}, expected:{})".format(k, type(b), type(v)))
                slvars[k] = b

        slvars.branchStack = branch.branchStack[0:]
        #  slvars.indent = branch.state.slvars.indent
        #  slvars.name = branch.state.slvars.name
        #  slvars.rsp = branch.state.slvars.rsp
        #  callStack = branch.state.callStack
        #  rspStack = branch.state.rspStack
        #  disasm = branch.state.disasm
        #  mnemStack = branch.state.mnemStack
        #  mnem = branch.state.mnem
        # slvars.justVisited.remove(new_ea)
        # slvars.justVisited.remove(new_ea + GetInsnLen(new_ea))
        new_ea = branch.state.ea
        if debug: printi("ReverseHead {} {}".format(hex(current_ea), hex(new_ea)))
        if new_ea in slvars.justVisited:
            slvars.justVisited.remove(new_ea)
        return new_ea

    def AdvanceHead(current_ea, new_ea = None):
        if helper and new_ea not in slvars2.helped:
            _start, _end = helper(new_ea)
            for _ea in range(_start, _end):
                slvars2.helped.add(_ea)
        #  if debug: sprint("AdvanceHead({:x}, {:x})".format(current_ea, new_ea if new_ea else 0))
        #  if new_ea == GetChunkStart(new_ea):
            #  EaseCode(new_ea)
        #  ori_new_ea = new_ea
        #  if new_ea is None:
            #  if IsFlow(current_ea):
                #  new_ea = idc.next_head(current_ea)
            #  else:
                #  raise AdvanceFailure("AdvanceHead should be smarter: mnem: {}".format(idc.print_insn_mnem(current_ea)))
        head_dict = SimpleAttrDict(
            source=current_ea,
            branchStack=slvars.branchStack[0:],
            state=SimpleAttrDict(getState(advance_head = 1))
        )
        #  slvars.cbuffer.append(current_ea)

        if modify and not noObfu:
            slvars2.previousHeads.append(head_dict)

        if new_ea:
            CheckChunkChange(new_ea, current_ea)

        #  return new_ea

        slvars.insnCount += 1

        if new_ea:
            if not vim and not noAppendChunks:
                if debug: sprint("ShowAppendFchunk 767")
                # TODO: should be SmartAddChunk
                # dprint("[new_ea] new_ea")
                if debug: sprint("[new_ea] new_ea:{:x}".format(new_ea))
                # SmartAddChunk(new_ea, current_ea)
                # ShowAppendFchunk(slvars.startLoc, new_ea, EndOfFlow(new_ea, soft=ignoreInt), current_ea)
            #  if debug: sprint("AdvanceHead is returning {} (new_ea specified as argument)".format(hex(new_ea)))
            return new_ea


        _next_insn = current_ea + GetInsnLen(current_ea)
        _next_head = idc.next_head(current_ea)
        _next_mnem = idc.print_insn_mnem(_next_insn)
        if isUnconditionalJmp(current_ea):
            raise RuntimeError("Should we be getting UnconditionalJmp's here?")
        if not isUnconditionalJmp(current_ea) and not isRet(current_ea) and not IsCode_(_next_insn):
            if ida_ua.can_decode(_next_insn): # , idc.GENDSM_FORCE_CODE):
                if idc.create_insn(_next_insn) or forceAsCode(_next_insn):
                    if idc.is_flow(ida_bytes.get_flags(_next_insn)):
                        if debug: sprint("adding new code")
                        new_ea = _next_insn
                        CheckChunkChange(new_ea, current_ea)
                        #  if debug: sprint("AdvanceHead is returning {} (created new code)".format(hex(new_ea)))
                        return new_ea
                    else: 
                        msg = "(noflow at {:x} from {:x})".format(_next_insn, current_ea)
                        sprint(AdvanceFailure(msg))
                        return AdvanceFailure(msg)
                else: 
                    printi("else2 (couldn't make insn at {:x} from {:x})".format(_next_insn, current_ea))
                    MakeCodeAndWait(_next_insn, force=1)
            else: 
                printi("else3 (couldn't read valid insn {:x} from {:x})".format(_next_insn, current_ea))
                raise RelocationUnpatchRequest()

        if idc.is_flow(ida_bytes.get_flags(_next_head)) and not isFlowEnd(current_ea) and _next_head == _next_insn:
            if GetChunkNumber(_next_head) > 0 and GetChunkEnd(current_ea) == _next_head:
                #  sprint("Losing our chunk (AdvanceHead): GetChunkEnd(current_ea) == _next_head == 0x{:x}".format(_next_head))
                #  if not IsSameFunc(current_ea, _next_head) and IsFunc_(_next_head):
                    #  DelFunction(_next_head)
                # XXX
                new_owners = GetChunkOwners(_next_head)
                if new_owners:
                    if slvars.startLoc in new_owners:
                        if len(new_owners) == 1:
                            printi("{:x} adjacent chunks with same owner".format(_next_head))
                            thisChunkStart = GetChunkStart(current_ea)
                            RemoveThisChunk(current_ea)
                            SetChunkStart(_next_head, thisChunkStart)
                            #  if 'slvars' in globals(): sprint(ChunkFailure("{:x} adjacent chunks with same owner".format(_next_head)))
                            #  raise ChunkFailure("{:x} adjacent chunks with same owner".format(_next_head))
                        else:
                            msg = "{:x} adjacent chunks with same owner (multiple owners): {}".format(_next_head, hex(new_owners))
                            printi(msg)
                            if 'slvars' in globals(): sprint(ChunkFailure(msg))
                            raise ChunkFailure(msg)
                            #  RemoveAllChunkOwners(_next_head, last=slvars.startLoc)
                        idc.auto_wait()

                if debug: sprint("ShowAppendFchunk 8150")
                ShowAppendFchunk(slvars.startLoc, _next_head, EndOfFlow(_next_head, soft=ignoreInt), current_ea)
                if GetChunkEnd(current_ea) == _next_head:
                    if 'slvars' in globals(): sprint(AdvanceFailure("attempting to advance to alien chunk"))
                    raise AdvanceFailure("Losing our chunk")


        _is_offset = IsOffset(current_ea, apply=1, loose=1)
        if 0 and isUnconditionalJmp(current_ea):
            msg = "0x%x: can't advance past absolute jmp" % current_ea
            if 'slvars' in globals(): sprint(AdvanceFailure(msg))
            raise AdvanceFailure(msg)

        if isRet(current_ea):
            msg = "0x%x: can't advance past ret" % current_ea
            if 'slvars' in globals(): sprint(AdvanceFailure(msg))
            raise AdvanceFailure(msg)

        if _is_offset:
            msg = "0x%x: can't advance past illdefined offset" % current_ea
            if 'slvars' in globals(): sprint(AdvanceFailure(msg))
            raise AdvanceFailure(msg)

        loop = 0
        nextHead = 1
        nextAny = 0
        fnEnd = EndOfFlow(current_ea)
        hitFnEnd = False
        while True:
            slvars.cbuffer.append(current_ea)
            #  EaseCode(current_ea, noExcept=1)
            loop += 1
            _next_insn = current_ea + GetInsnLen(ea)
            nextHead = idc.next_head(current_ea)
            nextAny = NextNotTail(current_ea)
            if debug: sprint("nextHead: {:x} nextAny: {:x} nextInsn: {:x}".format(nextHead, nextAny, _next_insn))
            if nextHead != nextAny or nextHead != _next_insn:
                if IsCode(_next_insn):
                    if debug: sprint("_next_insn is code, good")
                    # dprint("[debug] _next_insn, nextHead, nextAny")
                    r = ida_auto.auto_recreate_insn(current_ea)
                    printi("[debug] current_ea:{:x}, _next_insn:{:x}, nextHead:{:x}, nextAny:{:x}, auto_recreate_insn: {}".format(current_ea, _next_insn, nextHead, nextAny, r))
                    #  idc.auto_wait()
                    if r and r + current_ea == _next_insn:
                        nextHead = nextAny = _next_insn
                        break
                    
                else:
                    # The means that the next instruction is data, not good.
                    if debug: sprint("nextHead is data")
                    forceCode(nextHead)
                    #  MyMakeUnknown(nextAny, NextNotTail(nextAny) - nextAny, DOUNK_EXPAND | DOUNK_NOTRUNC)
                    #  ida_auto.auto_wait()
                    #  MakeCodeAndWait(nextAny)
                    if loop == 1:
                        # It might mean the end of the function needs expanding too.
                        # Doesn't do much: idaapi.reanalyze_function(idaapi.get_func(ERROREA()))
                        # SetFunctionEnd
                        if nextHead > fnEnd:
                            if debug: sprint("nextHead > fnEnd")
                            hitFnEnd = True
                        #  if not rv:
                        #  sprint("0x%x: MakeCodeAndWait failed" % nextAny)
                        #  else:
                        #  sprint("0x%x: MakeCodeAndWait returned %i" % (nextAny, rv))
                        continue
                    if loop > 3:
                        msg = "0x%x: couldn't resolve address of next instruction (1)" % current_ea
                        if 'slvars' in globals(): sprint(AdvanceFailure(msg))
                        raise AdvanceFailure(msg)
                        break
                    diff = nextHead - nextAny
                    if diff < 0:
                        msg = "negative difference idc.next_head/NextNotTail"
                        if 'slvars' in globals(): sprint(AdvanceFailure(msg))
                        raise AdvanceFailure(msg)
            else:
                break
        if nextHead != nextAny or nextHead != _next_insn:
            msg = sprint("0x%x: %x: %x: idc.next_head and NextNotTail disagree by %i byte" % (current_ea, nextHead, nextAny, diff))
            #  sprint("0x%x: can't advance, no code" % current_ea)
            if 'slvars' in globals(): sprint(AdvanceFailure(msg))
            raise AdvanceFailure(msg)
        else:
            if debug: sprint("considering extending function")
            #  fnEnd = EndOfFlow(current_ea)
            if nextHead >= fnEnd and idc.is_flow(ida_bytes.get_flags(nextHead)) and not isFlowEnd(current_ea):
        #  if idc.is_flow(ida_bytes.get_flags(_next_head)) and not isFlowEnd(current_ea) and _next_head == _next_insn:
                #  sprint("0x%x: Adjusting fnEnd from 0x%x to 0x%x" % (current_ea, fnEnd, NextNotTail(nextHead)))
                # TODO: should we be doing this, is this causing overspill?
                if GetChunkStart(fnEnd) == GetFuncStart(fnEnd):
                    if debug: printi("SetFuncEnd(0x{:x}, 0x{:x})".format(fnEnd - 1, NextNotTail(nextHead)))
                    SetFuncEnd(current_ea, NextNotTail(nextHead))
                else:
                    printi("SetChunkEnd(0x{:x}, 0x{:x})".format(fnEnd - 1, NextNotTail(nextHead)))
                    try:
                        SetChunkEnd(current_ea, NextNotTail(nextHead))
                    except TypeError as e:
                        printi("Exception calling SetChunkEnd({:#x}, {:#x})".format(current_ea, idc.next_not_tail(nextHead)))
                        raise e
            else:
                if debug: sprint("considering extending function.. nope")
            CheckChunkChange(nextHead, current_ea)
            #  if debug: sprint("AdvanceHead is returning {}".format(hex(nextHead)))
            return nextHead
        if debug: sprint("AdvanceHead is returning None")

    def getState(advance_head = 0):
        state_dict = SimpleAttrDict(
            callStack = callStack,
            disasm = disasm,
            ea = ea,
            addresses = list(slvars.addresses),
            instructions = slvars2.instructions.copy(),
            mnem = mnem,
            mnemStack = mnemStack,
            rspStack = rspStack,
            indent = slvars.indent,
            name = slvars.name,
            rsp = slvars.rsp,
            rsp_diff = slvars.rsp_diff,
            rspHist = slvars.rspHist.copy(),
            minSp = slvars.minSp,
            maxSp = slvars.maxSp,
        )
        if advance_head:
            state_dict.retSps = list(slvars.retSps)
            state_dict.justVisited=list(slvars.justVisited),

        _ignore = [ 'callStack', 'disasm', 'mnem', 'mnemStack', 'rspStack' ]
        for x in _ignore:
            if x in state_dict:
                del state_dict[x]
        return state_dict

    def pushState():
        state_dict = getState()
        stateStack.append(state_dict)

    def pushBranch(target, advance_head = 0):
        if target in slvars.willVisit:
            return 0
        if target in slvars.justVisited:
            return 0
        slvars.willVisit.add(target)
        branch_dict = SimpleAttrDict(
            source=ea,
            target=target,
            # slvars.justVisited = 0,
            state=SimpleAttrDict(getState(advance_head))
        )
        slvars.branchStack.append(branch_dict)
        slvars.branchNumber.append(hex(ea))
        return ea

    def popState():
        return stateStack.pop()

    def getIndent(adjustment=0):
        return "\t" * (callStack.__len__() + 1 + adjustment)

    def getColor(color):
        if isinstance(color, list):
            return color[0]
        elif isinstance(color, int):
            return color
        else:
            return False

    def nextColor(color, ea):
        c = idc.get_color(ea, idc.CIC_ITEM)
        if is_hldchk_msk(c):
            return
        if color is False:
            idaapi.del_item_color(ea)
        elif type(color) is int:
            idaapi.set_item_color(ea, color)
        elif isinstance(color, list):
            color = color[1:]
            idaapi.set_item_color(ea, color[0])

    def skip_initial_jumps(ea):
        while not noMakeFunction and slvars.startLoc == ea and skipJumps and isUnconditionalJmp(ea) and GetInsnLen(ea) > 1:
            if debug: sprint("0x%x: Mnem::%s" % (ea, idc.print_insn_mnem(ea)))
            nextColor(color, ea)

            fnDecl = GetType(ea)
            funcEnd = GetFuncEnd(ea)
            insnLen = GetInsnLen(ea)

            if thunk:
                MakeThunk(ea)
                return False
            #  if (funcEnd - slvars.startLoc) > 5:
            #  RemoveAllChunks(ea)

            #  RemoveAllChunks(ea)
            #  ZeroFunction(ea)

            # target = Dword(ea + 1) + ea + 5
            target = GetTarget(ea) # target = GetOperandValue(ea, 0)
            if target not in later2 and not IsUnknown(target) and idc.get_func_attr(GetJumpTarget(ea), idc.FUNCATTR_FLAGS) & FUNC_LIB == 0:
                later.add(GetJumpTarget(ea))
                later2.add(GetJumpTarget(ea))

            if reloc and not distorm and LocByName(reloc_name(target)) < BADADDR:
                sprint("Function has already been relocated")
                msg = reloc_name(slvars.startLoc)
                if 'slvars' in globals(): sprint(RelocationDupeError(msg))
                raise RelocationDupeError(msg)

            if debug: sprint("0x%x: considering changing function start to 0x%x" % (ea, target))
            if IsExtern(target):
                # reference/offset/library ptr
                printi("Reference: {:x}".format(target))
                break
            if not IsCode_(target):
                if not EaseCode(target, forceStart=1, noExcept=1, origin=ea):
                    raise AdvanceFailure("{:x} Couldn't skip through initial jumps".format(ea))

            if not IsFuncHead(target):
                if debug: sprint('MakeFunction456')
                if IsSameFunc(ea, target):
                    RemoveAllChunks(ea)
                ida_auto.auto_wait()
                if not ForceFunction(target):
                    printi("{:x} couldn't forcefunction".format(ea))
                ida_auto.auto_wait()

            #  CheckChunkChange(target)
            if idc.get_segm_name(target) != '.text':
                printi("we're not in kansas (.text) anymore")
                return -1

            printi("{:x} skipping to {:x}".format(ea, target))
            if type(fnDecl) is str:
                SetType(target, fnDecl)
                ida_auto.auto_wait()

            # take care of previous function, now that it's safe (it won't attempt to chunk us)
            if not MakeThunk(ea):
                printi("{:x} Couldn't make thunk".format(ea))

            if False and IsFunc_(ea) or MyMakeFunction(ea, ea + insnLen):
                if GetFuncSize(ea) > insnLen and Byte(ea) in (0xe9, 0xeb):
                    if IsSameFunc(ea, target) and GetChunkEnd(ea) == ea + insnLen:
                        pass
                    else:
                        # dprint("[makethunk234] ea, insnLen, GetFuncSize(ea)")
                        printi("[makethunk234] ea:{:x}, insnLen:{:x}, GetFuncSize(ea):{:x}".format(ea, insnLen, GetFuncSize(ea)))
                        
                        if debug: sprint('MAkeThunk234')
                        if GetFuncEnd(ea) != ea + insnLen and not SetFunctionEnd(ea, ea + insnLen):
                            printi("GetFunctionEnd({:x}): {:x}  insnLen: {}".format(ea, GetFuncEnd(ea), insnLen))
                            printi("SetFunctionEnd({:x}, {:x})".format(ea, ea + insnLen))
                            msg = "0x%x: %s @ 0x%x" % (target, "Not sure how to proceed, can't thunk this func", ea)
                            if 'slvars' in globals(): sprint(AdvanceFailure(msg))
                            raise AdvanceFailure(msg)
                        ida_auto.auto_wait()
                        if debug: sprint("0x%x: changing function start to 0x%x" % (target, target))

            if GetFuncSize(ea) == insnLen:
                ea = target
                slvars.startLoc = target
                slvars.currentChunk = target
                slvars.startFnName = "%s_0" % slvars.startFnName
            else:
                break


            # if reloc and LocByName(reloc_name(slvars.startLoc)) != BADADDR:
            if reloc and 'slvars' in globals():
                if LocByName(reloc_name(slvars.startLoc)) != BADADDR:
                    sprint(RelocationDupeError(reloc_name(slvars.startLoc)))
                    raise RelocationDupeError(reloc_name(slvars.startLoc))
            if not IsFunc_(ea) or not IsHead(ea):
                if not MyMakeFunction(ea) and not ForceFunction(ea):
                    sprint("Couldn't make function at start: 0x{:x}".format(ea))
                    msg = "Couldn't make function at new start"
                    if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
                    raise RelocationTerminalError(msg)

            if not LabelAddressPlus(ea, slvars.startFnName, force=1):
                sprint("Couldn't label function at start: 0x{:x}".format(ea))
                msg = "Couldn't label function at new start"
                if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
                raise RelocationTerminalError(msg)


                #  MakeCodeAndWait(ea)
                #  if debug: sprint('MAkeFunction111')
                #  MyMakeFunction(ea, noMakeFunction)
                #  LabelAddressPlus(ea, slvars.startFnName, force=1)

        slvars.name = Name(ea)
        if isRet(ea): # idc.get_wide_byte(ea) == 0xc3:
            if GetNumChunks(ea) > 1:
                RemoveAllChunks(ea)
            if GetFuncEnd(ea) != ea + GetInsnLen(ea):
                SetFuncEnd(ea, ea + GetInsnLen(ea))
            #  return 0

        return ea

    def is_real_func(ea, fnLoc):
        reason = ["No reason"]
        def setIsRealFunc(_reason):
            printi("[IsRealFunc] \"{}\" jumping from {:x} to {:x}".format(_reason, ea, fnLoc))
            reason[:] = [ _reason ]
            return True

        if idc.get_segm_name(fnLoc) == '.idata' and idc.get_type(fnLoc):
            return setIsRealFunc("0x%x: (.idata with Type) jmp <0x%x>" % (ea, target))

        if debug: sprint((_file, 'is_real_func'), "0x%x: (removeFuncs) jmp <0x%x>" % (ea, target))
        if IsExtern(fnLoc):
            return setIsRealFunc("IsExtern(0x{:x})".format(fnLoc))
        if not IsCode_(fnLoc): # idc.is_code(ida_bytes.get_flags(fnLoc)):
            insLen = forceCode(fnLoc)
            if not insLen:
                if debug: sprint((_file, 'is_real_func'), AdvanceFailure("Couldn't convert code at jmp fnLoc {:x}".format(fnLoc)))
        target_flags = ida_bytes.get_flags(fnLoc)
        codeRefs = list(
            [x for x in list(idautils.CodeRefsTo(fnLoc, 0)) if idc.get_segm_name(x) == '.text'])
        callRefs = list([x for x in list(CallRefsTo(fnLoc)) if idc.get_segm_name(x) == '.text' and IsFunc_(x) and not idc.get_func_name(x).startswith("do_") and GetInsnLen(x) > 2])
        jmpRefs = list([x for x in list(JmpRefsTo(fnLoc)) if idc.get_segm_name(x) == '.text' and IsFunc_(x) and GetFuncSize(x) > 5 and not isConditionalJmp(x)])
        currentStackDiff = GetSpd(ea)
        targetStackDiff = GetSpd(fnLoc)
        if delsp:
            idc.del_stkpnt(slvars.startLoc, fnLoc)
            ida_auto.auto_wait()
        elif addsp and currentStackDiff != targetStackDiff:
            SetSpd(fnLoc, currentStackDiff)
            ida_auto.auto_wait()


        if not idc.is_code(target_flags):
            if debug: sprint((_file, 'is_real_func'), "0x%x: Potential function !isCode: 0x%x" % (ea, fnLoc))
            rspTmp = slvars.rsp
            if rspTmp is None:
                rspTmp = -0x9999
            rspTmpStr = "0x%x" % rspTmp
            if rspTmp < 0:
                rspTmpStr = "-0x%x" % (0 - rspTmp)
            if debug: sprint((_file, 'is_real_func'), "0x%x: (removeFuncs) fnLoc flags & FF_CODE != 600: (rsp: %s) flags: %s" % (
                ea, rspTmpStr, str(list_fflags(target_flags))))
            if debug: sprint((_file, 'is_real_func'), "not code")
            raise sprint(AdvanceFailure("couldn't get code for jump target {:x}".format(fnLoc)))


        fnLoc = fnLoc
        fnName = GetFunctionName(fnLoc)

        fnEnd = FindFuncEnd(fnLoc)
        fnEndMnem = idc.print_insn_mnem(idc.prev_head(fnEnd))

        if debug: sprint(
            "0x%x: %s to (fnName: %s): %s" % (fnLoc, GetFunctionName(ea), fnName, GetDisasm(ea)))

        tmpLimit = BADADDR

        if 0:
            if hasglobal('m') and isinstance(getglobal('m'), (list, set)):
                if fnLoc in getglobal('m'):
                    tmpLimit = fnLoc
                if (~GetFuncName(fnLoc).find("___0x") or ~GetFuncName(fnLoc).find("::_0x")) and not ida_funcs.is_same_func(ea, fnLoc):
                    tmpLimit = fnLoc

        isRealFunc = None
        canInclude = False
        isSameFunc = IsSameFunc(ea, fnLoc)

        if debug: sprint((_file, 'is_real_func'),
            "0x%0x: 0x%x: Potential Func: 0x%x / %s" % (slvars.startLoc, ea, fnLoc, fnName))
        c = Commenter(ea, "line")
        ct = Commenter(fnLoc, "line")
        if c.exists("[ALLOW JMP]") or ct.exists("[ALLOW JMP]"): 
            if debug: sprint((_file, 'is_real_func'), "allow jmp")
            isRealFunc = False
        elif not noDenyJmp and (c.exists("[DENY JMP]") or ct.exists("[DENY JMP]")):
            isRealFunc = setIsRealFunc("[DENY JMP]")
        elif fnLoc == tmpLimit:
            isRealFunc = setIsRealFunc("0x%x: legitimate function (is in limit): 0x%x: %s" % ( ea, fnLoc, fnName))
        elif fnLoc == tmpLimit:
            isRealFunc = setIsRealFunc("0x%x: legitimate function (impl_addresses): 0x%x: %s" % ( ea, fnLoc, fnName))
        elif len(callRefs) > 0:
            isRealFunc = setIsRealFunc("0x%x: legitimate function (callRefs): 0x%x: %s" % (ea, fnLoc, fnName))

        elif len(jmpRefs) > 0:
            if debug: sprint("is_real_func: jmpRefs: {}".format(hex(jmpRefs)))
            ourNamespace = ''
            ourHexStr = string_between(['::_0x', '___0x'], '', slvars.startFnName).lower()
            ourHexStr = string_between('_', '', ourHexStr, repl='', inclusive=1)
            if debug: sprint((_file, 'is_real_func'), "ourHexStr: {}".format(ourHexStr))
            if len(ourHexStr) == 16:
                ourHex = int(ourHexStr, 16)
                if debug: sprint((_file, 'is_real_func'), "ourHex: {}".format(ourHex))
                ourNamespace = string_between('', ['::_0x', '___0x'], slvars.startFnName)
            else: 
                ourHex = 0
            for r in jmpRefs:
                refName = idc.get_func_name(r)
                refHexStr = string_between(['::_0x', '___0x'], '', refName).lower()
                refHexStr = string_between('_', '', refHexStr, repl='', inclusive=1)
                refNamespace = string_between('', ['::_0x', '___0x'], refName)
                if len(refHexStr) == 16:
                    refHex = int(refHexStr, 16)
                    if refHex and ourHex and refHex != ourHex or refNamespace != ourNamespace:
                        isRealFunc = setIsRealFunc("jmpRef: different hexes: {} {}".format(ourHexStr, refHexStr))
            if not ourHexStr or not refHexStr:
                if len(_.uniq(GetFuncName(jmpRefs))) > 1:
                    isRealFunc = setIsRealFunc("jmpRef: more than 1 ref: {}".format(_.uniq(GetFuncName(jmpRefs))))
            if debug:
                for r in jmpRefs:
                    sprint((_file, 'is_real_func'), "jmpRef: {}".format(idc.GetDisasm(r)))
        elif not noPdata and isSegmentInXrefsTo(fnLoc, '.pdata') and get_pdata_fnStart(ea) == fnLoc:
            isRealFunc = setIsRealFunc("0x%x: legitimate function (in .pdata): 0x%x: %s" % (ea, fnLoc, fnName))
        elif idc.get_wide_byte(target) == 0xc3 and not isConditionalJmp(ea):
            if debug: sprint((_file, 'is_real_func'), "target is retn")
            nassemble(ea, 'retn', apply=1)
        elif fnName.startswith("Arxan") and not isSameFunc:
            isRealFunc = setIsRealFunc("fnName.startswith('Arxan')")
        elif fnLoc in slvars.justVisited:   
            if debug: sprint((_file, 'is_real_func'), "justVisited")
            isRealFunc = False
        elif IsFunc_(fnLoc) and not isSameFunc and not noDenyJmp and Commenter(GetFuncStart(fnLoc)).exists("[DENY JMP]"):
            if debug: sprint((_file, 'is_real_func'), "IsFunc_ not isSameFunc")
            isRealFunc = setIsRealFunc("IsFunc_")



        elif False and isSegmentInXrefsTo(fnLoc, '.rdata') and idc.get_segm_name(ea) != '.rdata' and not IsSameFunc(ea, fnLoc):
            isRealFunc = setIsRealFunc("0x%x: legitimate function (in .rdata): 0x%x: %s" % (ea, fnLoc, fnName))

        elif ida_funcs.is_same_func(ea, fnLoc):
            isRealFunc = False

        #

        if isRealFunc is None:
            if debug: sprint((_file, 'is_real_func'), "[info] couldn't decide if this was a real func {:x}".format(target))
            isRealFunc = False
        if isRealFunc and canInclude and include:
            isRealFunc = False
        if isRealFunc:
            codeRefsTo.add(fnLoc)
            if debug: sprint((_file, 'is_real_func'), "real func")
            if IsChunkHead(fnLoc) and not IsFuncHead(fnLoc):
                printi("{:x} chunkhead".format(fnLoc))
                ForceFunction(fnLoc)
                retrace(fnLoc, once=1, depth=depth+1, max_depth=max_depth)
            if addFuncs:
                if not isSameFunc and not IsFunc_(fnLoc):
                    if debug: sprint((_file, 'is_real_func'), "0x%x: adding function: %s at 0x%x" % (ea, GetFunctionName(fnLoc), fnLoc))
                    if not MyMakeFunction(fnLoc, noMakeFunction):
                        if debug: sprint((_file, 'is_real_func'), "0x%x: removing chunk in order to make function: 0x%x" % (ea, fnLoc))
                        RemoveThisChunk(fnLoc)
                        RemoveThisChunk(fnLoc)
                        if not MyMakeFunction(fnLoc, noMakeFunction):
                            sprint(
                                "0x%x: removing chunk in order to make function: 0x%x (didn't work)" % (
                                    ea, fnLoc))
                if not idc.hasUserName(ida_bytes.get_flags(fnLoc)):
                    LabelAddressPlus(fnLoc, slvars.startFnName + "_impl")
                else:
                    cf = Commenter(fnLoc)
                    cf.add("[JMP_FROM] " + slvars.startFnName)

            if fnLoc in slvars.justVisited:
                pass
            else:
                if slvars.rsp: 
                    if depth == 0:
                        if not IsCode_(idc.prev_not_tail(fnLoc)) and IsFunc_(idc.prev_not_tail(fnLoc)):
                            printi("refreshing annoying function @ {:x}".format(fnLoc))
                            unpatch_func2(fnLoc, unpatch=1)
                            retrace(fnLoc, once=1, forceRemoveChunks=1, depth=depth+1, max_depth=max_depth)
                    printi("[annoying] depth:{}, hex(fnLoc):{}, IsCode_(idc.prev_not_tail(fnLoc)):{}, IsFunc_(idc.prev_not_tail(fnLoc)):{}".format(depth, hex(fnLoc), IsCode_(idc.prev_not_tail(fnLoc)), IsFunc_(idc.prev_not_tail(fnLoc))))
                    
                    msg = ("{:x}: jmp to {} which has no stack (isRealFunc: {}) retn rsp of {}".format(ea, describe_target(fnLoc), reason[0], slvars.rsp))
                    if not vim: raise RelocationStackError(msg)
                if not skipAddRsp:
                    slvars.retSps.add(slvars.rsp)
        else:
            if debug: sprint((_file, 'is_real_func'), "not real func {:x}".format(fnLoc))
            if removeFuncs and not isSameFunc:
                if IsFunc_(fnLoc) and not IsFuncHead(fnLoc):
                    if (GetChunkStart(fnLoc) < fnLoc):
                        if debug: sprint((_file, 'is_real_func'), "removeFuncs: doing wierd shit: GetChunkStart(0x{:x}) 0x{:x} < 0x{:x}".format(fnLoc, GetChunkStart(fnLoc), fnLoc))
                        SetFuncEnd(GetChunkStart(fnLoc), fnLoc)

                if IsFunc_(fnLoc):
                    ShowAppendFunc(ea, slvars.startLoc, fnLoc)
                else:
                    SmartAddChunk(fnLoc, ea)

        return reason[0] if isRealFunc else False

    if debug: sprint("0x%x: Mnem::%s" % (ea, idc.print_insn_mnem(ea)))
    if not IsFunc_(ea):
        if debug: sprint('MAkeFunction112')
        if not MyMakeFunction(ea) and not ForceFunction(ea):  # , noMakeFunction):
            sprint("Couldn't make function at start: 0x{:x}".format(ea))
            msg = "Couldn't make function at start"
            if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
            raise RelocationTerminalError(msg)

    if not LabelAddressPlus(ea, slvars.startFnName, force=1):
        sprint("Couldn't label function at start: 0x{:x}".format(ea))
        msg = "Couldn't label function at new start"
        if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
        raise RelocationTerminalError(msg)

    if reloc:
        if vimedit:
            origin = ea
        else:
            origin = LocByName("next_relocation")
        if origin == BADADDR:
            msg = "0x%x: 'next_relocation' label not found" % ea
            if 'slvars' in globals(): sprint(Exception(msg))
            raise Exception(msg)
        for l in """
          _____.__        __      __         .__      
  _______/ ____\__| ____ |  | ___/  |______  |  |__   
 /  ___/\   __\|  |/    \|  |/ /\   __\__  \ |  |  \  
 \___ \  |  |  |  |   |  \    <  |  |  / __ \|   Y  \ 
/____  > |__|  |__|___|  /__|_ \ |__| (____  /___|  / 
     \/  obfu kungfu   \/     \/ version 1 \/     \/  
        """.splitlines():
            relocPrefix.append('; ' + l)

        fnName = GetFunctionName(ea)
        if not len(fnName):
            fnName = "unknown_function"
        relocPrefix.append("")
        relocPrefix.append(";;;".ljust(len(fnName) + 6, ";"))
        relocPrefix.append(";; " + fnName + " ;;")
        relocPrefix.append(";;;".ljust(len(fnName) + 6, ";"))
        relocPrefix.append("")
        relocPrefix.append("[org {:x}h]".format(origin))
        relocPrefix.append("[bits 64]")
        relocPrefix.append("[default rel]")
        relocPrefix.append("")

    lastEa = ea
    #  with JsonStoredSet('obfu-targets.json') as redux:
    #  if 1:
    if remake:
        funcSize = GetFuncSize(ea)
        if funcSize > 9999:
            if debug: sprint("made funcSize = 1 since funcSize was {}".format(funcSize))
            funcSize = 1
        MyMakeUnknown(ItemHead(ea), funcSize, DOUNK_EXPAND | DOUNK_NOTRUNC)
        ida_auto.auto_wait()
        if debug: sprint('MAkeFunction012')
        MyMakeFunction(ea, noMakeFunction)
        ida_auto.auto_wait()

    for cn in range(999999):
        if cn >= stop: raise Exception("Stop!")
        fatal = False
        ShouldAddChunk(lastEa, ea)
        for step in range(5):
            cn += 1
            if cn >= stop: raise Exception("Stop!")
            eaFuncName = idc.get_func_name(ea)
            #  if debug: sprint("step: {} {} {}".format(step, eaFuncName, slvars.startFnName))
            if debug: sprint("step# {}: {}".format(step, eaFuncName))
            if eaFuncName == slvars.startFnName:
                if debug: printi("eaFuncName == slvars.startFnName")
                break

            if len(eaFuncName) == 0:
                #  if debug: sprint('MAkeFunction125')
                #  if MyMakeFunction(ea, noMakeFunction):
                #  continue

                if debug: sprint("no function name, dubiously calling called shouldaddchunk, IsFuncHead: {}, name: {}".format(IsFuncHead(ea), GetFuncName(ea)))
                # ForceFunction(ea)
                SmartAddChunk(ea, ea)
                # ShouldAddChunk(lastEa, ea)
                break

            if step == 0 or step == 2:
                DelFunction(LocByName(GetFunctionName(ea)))
                ida_auto.auto_wait()
                continue

            if step == 1 or step == 3:
                if debug: sprint("step1/3 RemoveAllChunks")
                RemoveAllChunks(ea)
                continue

            if step == 4:
                msg = "0x%x: Function Change from %s to %s" % (ea, slvars.startFnName, eaFuncName)
                if 'slvars' in globals(): sprint(AdvanceFailure(msg))
                raise AdvanceFailure(msg)

        MakeCodeAndWait(ea)
        #  flags = ida_bytes.get_flags(ea)
        # TODO improve loop to check for existing off-head code, undefined
        # code, data, and such - forcing to code where appropriate
        #
        # while idc.is_code(ida_bytes.get_flags(ea)) or idc.plan_and_wait(ea, EndOfContig(ea)) or idc.create_insn(ea):
        while idc.is_code(ida_bytes.get_flags(ea)): # or idc.plan_and_wait(ea, EndOfContig(ea)) or idc.create_insn(ea):
            if ea == slvars.startLoc:
                new_ea = skip_initial_jumps(ea)
                if new_ea == False:
                    return
                if new_ea != ea:
                    AdvanceHead(ea, new_ea)

            if ea == slvars.startLoc and not IsFuncHead(ea):
                MyMakeFunction(ea)
            forceJump = None
            forceJumpRsp = None
            if debug: sprint("Top of loop, type rspHist: {}".format(type(slvars.rspHist)))
            slvars.rspHist.append(slvars.rsp)

            if cursor:
                idc.set_color(ea, CIC_ITEM, color_cursor)
            if follow:
                idc.jumpto(ea)
            cn += 1
            if cn >= stop: raise Exception("Stop!")
            if live:
                idc.jumpto(ea)
            if ea in slvars.willVisit:
                slvars.willVisit.remove(ea)
            if ea in slvars.justVisited:
                if debug: 
                    sprint("forceJump - justVisited")
                forceJump = ea
                forceJumpRsp = slvars.justVisitedRsp[ea]

            ShouldAddChunk(lastEa, ea)

            if slvars.rsp_diff:
                if slvars.rsp == None:
                    sprint("rsp was none")
                    msg = "No message"
                    if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
                    raise RelocationTerminalError(msg)
                else:
                    slvars.rsp = slvars.rsp - slvars.rsp_diff
                slvars.rsp_diff = 0

            lastEa = ea

            mnem = idc.print_insn_mnem(ea)
            #  with PerfTimer(mnem):
            decomp = de(ea)
            decomp = decomp[0] if len(decomp) else None
            if decomp is None:
                sprint("distorm3::de returned invalid result")
                msg = "distorm3::de returned invalid result"
                if 'slvars' in globals(): sprint(AdvanceFailure(msg))
                raise AdvanceFailure(msg)

            skipAddRsp = False
            #  if debug: sprint("0x%x: slowtrace::mainloop" % (ea))
            if fakesp:
                idc.add_user_stkpnt(ea, -10)
                for addr in InsnRange(ea):
                    slvars.fakedAddresses.append(addr)
            if delsp and ea != slvars.startLoc:
                for addr in InsnRange(ea):
                    idc.del_stkpnt(slvars.startLoc, addr)
                # SetSpDiffEx(ea, 0)
            #  forceCode(ea)
            MakeCodeAndWait(ea)
            MakeCodeAndWait(idc.next_head(ea), comment=slvars.startFnName)
            #  if ea == 0x140cb33f1:
            if debug: print("line 12B")
            if modify:
                opType0 = GetOpType(ea, 0)  # 4  o_displ
                opType1 = GetOpType(ea, 1)  # 1  o_reg

                if 1:
                    if opType0:
                        opText0 = GetOpnd(ea, 0)
                        if ~opText0.find('rsp') and (~opText0.find('arg_') or ~opText0.find('var_')):
                            pass  # OpNumber(ea, 0)
                    if opType1:
                        opText1 = GetOpnd(ea, 1)
                        if ~opText1.find('rsp') and (~opText1.find('arg_') or ~opText1.find('var_')):
                            OpNumber(ea, 1)

                # disasm = kp.ida_get_disasm(ea, fixup=0)
                disasm = diida(ea)
                mnem = idc.print_insn_mnem(ea)
                if mnem and (mnem == "nop" or Word(ea) == 0x9066 or isAnyJmp(mnem)):
                    pass
                elif noObfu:
                    slvars2.instructions.append(FuncTailsInsn(disasm, ea, disasm, size=MyGetInstructionLength(ea), sp=slvars.rsp, spd=slvars.rsp_diff))
                    # slvars.rspMarks[disasm] = slvars.rsp
                    sti = slvars2.instructions
                    #  if disasm.startswith('mov rsp'):
                    globals()['sti'] = sti
                    try:
                        # intentionally dumbing this down to match IDA's new capability
                        # which applies the SPD to the `call _alloca_probe` not the
                        # subsequent sub slvars.rsp.
                            #  push rbp
                            #  lea rbp, [rel sub_1417DBB0C]
                            #  xchg [rsp], rbp
                            #  retn
                        if sti[-1] == 'retn' and sti[-2] == 'xchg [rsp], rbp' and sti[-4] == 'push rbp':
                            printi("[feel] jump: {}".format(sti[-3]))
                            target = eax(string_between('[rel ', ']', str(sti[-3])) or string_between(', ', '', str(str[-3])))
                            printi("[feel] target: {}".format(hex(target)))
                            ea = AdvanceHead(ea, target)
                            continue
                    except IndexError:
                        pass


                elif not noObfu:
                    # (self, insn=None, ea=None, text=None, size=None,
                    # comments=None, sp=None, spd=None, warnings=None,
                    # errors=None, chunkhead=None, op=None, labels=[],
                    # refs_from={}, refs_to={}, flow_refs_from={},
                    # flow_refs_to={}):
                    #  slvars2.instructions.append(disasm)
                    slvars2.instructions.append(FuncTailsInsn(disasm, ea, disasm, size=MyGetInstructionLength(ea), sp=slvars.rsp, spd=slvars.rsp_diff))
                    slvars.rspMarks[disasm] = slvars.rsp
                    sti = slvars2.instructions
                    #  if disasm.startswith('mov rsp'):
                    globals()['sti'] = sti
                    try:
                        # intentionally dumbing this down to match IDA's new capability
                        # which applies the SPD to the `call _alloca_probe` not the
                        # subsequent sub slvars.rsp.
                        if sti[-1] == "call __alloca_probe" and \
                           sti[-2].startswith("mov eax, "):
                            s = sti[-2]
                        #  if \
                                #  sti[-1] == "sub rsp, rax" and \
                                        #  sti[-2] == "call __alloca_probe" and \
                                        #  sti[-3].startswith("mov eax, "):
                            #  s = sti[-3]
                            spd = 0 - int(str(s)[len("mov eax, "):].rstrip('h'), 16)
                            slvars.rsp = slvars.rsp - spd
                            print("Setting spd at {:x}".format(sti[-1].ea + GetInsnLen(sti[-1].ea)))
                            SetSpDiff(sti[-1].ea + GetInsnLen(sti[-1].ea), spd)

                            cmt = "[SPD:ALLOCA=%s]" % hex(spd)
                            Commenter(sti[-1].ea, "line").remove_matching(r'.*SPD.*')
                            Commenter(sti[-1].ea, "line").add(cmt)
                            #  if not Commenter(ea, "line").match(r'^\[SPD='):
                    except IndexError:
                        pass

                        """
                            {   'address': 5434450470,
                                'dt': 2,
                                'flags': ['FLAG_DST_WR'],
                                'flowControl': 'FC_NONE',
                                'meta': 256,
                                'mnemonic': 'LEA',
                                'rawFlags': 2624,
                                'registers': ['RM_SP', 'RM_R11'],
                                'usedRegistersMask': 131088,
                            Python>pp(de(ERROREA())[0].operands[0].__dict__)
                                'index': 11,
                                'name': 'R11',
                                'size': 64,
                                'type': 'Register',
                            Python>pp(de(ERROREA())[0].operands[1].__dict__)
                                'disp': 208,
                                'index': 4,
                                'scale': 1,
                                'segment': 255,
                                'type': 'AbsoluteMemory',
                        """
                    """
                    lea r11, [rsp+0xb0]
                    mov rbx, [r11+0x10]
                    mov rdi, [r11+0x18]
                    push r11
                    pop rsp

                    'lea r11, [rsp+0xb0]',
                    'mov rbx, [r11+0x10]',
                    'mov rdi, [r11+0x18]',
                    'push r11',
                    'pop rsp',

                    """

                    # ArxanBalance
                    if 0:
                        m = sti.multimatch([
                            r'(push \w+)**',
                            r'lea rsp, .*',
                            r'(movupd .*)**',
                            r'push 0x10',
                            r'test rsp, 0xf',
                            #  r'jnz .*',
                            r'push 0x18',
                            r'(add|sub) rsp, .*',
                            r'call ({call}.*)',
                            r'add rsp, \[rsp\+8\]',
                            r'(movupd .*)**',
                            r'lea rsp, \[rsp\+({rspdiff}[^\]]+)\]',
                            r'(pop \w+)**',
                            r'({extra}.*)**?',
                            r'retn',
                        ])
                        if m:
                            sprint("*** found balance ***")
                            sprint("*** {} ***".format(m))

                    #  48 8b 05 43 dd 00 fd          	mov rax, [off_140D0AB4C]   
                    #  8b 15 2d 6c d6 fc             	mov edx, [dword_140A63A3C] 
                    #  89 d1                         	mov ecx, edx               
                    #  55                            	push rbp                   
                    #  48 8d 2d a2 bc db ff          	lea rbp, [label22]         
                    #  48 87 2c 24                   	xchg [rsp], rbp            
                    #  50                            	push rax                   
                    #  c3                            	retn                       
                    if False:
                        m = sti.multimatch([
                            r'mov rax, ({call}\[\w+])',
                            r'({movs}mov \w+, .*)**',
                            r'(push rbp)',
                            r'lea rbp, \[({retn}.*)]',
                            r'xchg \[rsp], rbp',
                            r'push rax',
                            r'retn',
                        ])
                        if m:
                            sprint("*** found something we haven't de-obfu written for yet ***")
                            sprint("*** {} ***".format(m))


                    if True:
                        m = sti.multimatch([
                            r'mov rax, rsp',
                            # sub rsp, 0xb8
                            r'lea r11, \[rax]',
                            r'mov rsp, r11'
                            # retn
                        ])
                        if m:
                            target_rsp = slvars.rspMarks[m.default[0]]
                            spd = -slvars.rsp
                            sprint("[slowtrace2] adjusting spd at {:x} from {:x} by {:x} to get {:x}".format(ea, spd, target_rsp - spd, target_rsp))
                            _spd = target_rsp - spd
                            idc.add_user_stkpnt(ea + GetInsnLen(ea), _spd)
                            cmt = "[SSSSPD={}]".format( hex(_spd) )
                            Commenter(ea, "line").remove_matching(r'^\[SSSSPD=')
                            Commenter(ea, "line").add(cmt).commit()

                    #  m = sti.multimatch([
                        #  #  r'push rbp',
                        #  # lea rbp, [rsp+0x40]
                        #  r'lea rbp, \[rsp.*'
                        #  r'mov rsp, rbp',
                    #  ])
                    #  if m:
                        #  target_rsp = slvars.rspMarks[m.default[0].group(0)]
                        #  spd = -slvars.rsp
                        #  printi("adjusting spd at {:x} from {:x} by {:x} to get {:x}".format(ea, spd, target_rsp - spd, target_rsp))
                        #  _spd = target_rsp - spd
                        #  idc.add_user_stkpnt(ea + GetInsnLen(ea), _spd)
                        #  cmt = "[SPD=0x{:x}]".format( _spd )
                        #  Commenter(ea, "line").remove_matching(r'^\[SPD=')
                        #  Commenter(ea, "line").add(cmt).commit()
#  



                    #  sti.multimatch([
                        #  # load r11 with stack adjustment: lea r11, [slvars.rsp+xxx]
                        #  r'pop rcx',
                        #  r'mov byte.*'
                    #  ])
                    setglobal('sti', sti)
                    m = sti.multimatch([
                        # load r11 with stack adjustment: lea r11, [slvars.rsp+xxx]
                        r'lea r11, \[rsp\+(0x[0-9a-fA-F]+|[0-9a-fA-F]+h)]',

                        # a bunch of mov and movabs statements

                        # then either mov slvars.rsp, r11; lea slvars.rsp, [r11];
                        # or push r11 & pop slvars.rsp
                        r'mov rsp, r11|lea rsp, \[r11]|pop rsp'
                    ])
                    
                    if m:
                        #  sprint("*** found r11 spd shennanigans***")
                        setglobal('_m', m)
                        sti.clear()
                        #  stack = string_between(
                                #  ["[rsp+0x", "[rsp+" ], 
                                #  [      "]",    "h]" ], 
                                #  m.default[0].group(0)) 
                        stack = string_between(
                                "[rsp+0x", "]", 
                                m.default[0], retn_all_on_fail=1) 

                        if stack:
                            if debug: sprint("m.default: {}".format(m.default))
                            
                            spd = int(stack, 16)
                            if m.default[1] == 'pop rsp':
                                spd += 8
                                # slvars.rsp += 8

                            idc.add_user_stkpnt(idc.next_head(ea), spd)

                            cmt = "[SSPD=%s]" % hex(spd)
                            #  if not Commenter(ea, "line").match(r'^\[SPD='):
                            Commenter(ea, "line").remove_matching(r'^\[SSPD=')
                            Commenter(ea, "line").add(cmt)
                        else:
                            sprint("couldn't get stack adjustment from %s" % m.default[0])

                    #  if \
                    #  sti[-1] == "mov rsp, r11" or \
                    #  sti[-1] == "lea rsp, [r11]" or \
                    #  (sti[-1] == "pop rsp" and sti[-2] == "push r11"):
                    #  # -7 'lea r11, [rsp+170h]',
                    #  # -6 'mov rbx, [r11+10h]',
                    #  # -5 'mov rsi, [r11+18h]',
                    #  # -4 'mov rdi, [r11+20h]',
                    #  # -3 'mov r14, [r11+28h]',
                    #  # -2 'push r11',
                    #  # -1 'pop rsp',
                    #  for i in range(len(sti) - 2):
                    #  j = -1 - i
                    #  if j == -1 and sti[-1] == "pop rsp": continue
                    #  if j == -2 and sti[-1] == "pop rsp": continue
                    #  if sti[j].startswith("mov"):
                    #  continue
                    #  elif sti[j].startswith("lea r11, "):
                    #  # lea r11, [slvars.rsp+1140h]
                    #  s = string_between_repl("[rsp+", "h]", sti[j])
                    #  if not s:
                    #  s = string_between_repl("[rsp+0x", "]", sti[j])
                #
                #  if s:
                #  spd = int(s, 16)
                #  if sti[-1] == "pop rsp":
                #  spd += 8
                #
                #  idc.add_user_stkpnt(idc.next_head(ea), spd)
                #
                #  cmt = "[SPD=%i]" % spd
                #  #  if not Commenter(ea, "line").match(r'^\[SPD='):
                #  Commenter(ea, "line").remove_matching(r'^\[SPD=')
                #  Commenter(ea, "line").add(cmt)
                    #  except ValueError as ex:
                        #  sprint("Exception: ValueError: %s" % pprint.pprint(ex))
                #  length = 150
                #  try:
                    #  min_val = min([i for i in slvars.justVisited if i > ea])
                    #  length = min(150, min_val - ea)
                #  except ValueError:
                    #  pass


                if noObfu:
                    pass
                elif Commenter(ea, "line").match(r'\[NO-OBFU]'):
                    printi("no-obfu comment at {:x}".format(ea))
                    #  printi("no-obfu option: {} {}".format(noObfu, type(noObfu)))
                else:
                    if debug: sprint("checking for patches")
                    _loop = True
                    while _loop:
                        _loop = False
                        patch_result = True
                        patch_results = []
                        while patch_result:
                            patch_result = obfu._patch(ea, context={'slvars': slvars, 'slvars2': slvars2}, depth=depth)
                            if patch_result:
                                patch_results = patch_result
                        if patch_results:
                            #  printi("patch at insn {}".format(slvars.insnCount))
                            if isinstance(patch_results, list):
                                patch_results = patch_results[0]
                            if isinstance(patch_results, PatternResult):
                                if isinstance(returnPatches, list):
                                    returnPatches.append(patch_results)
                                    if debug: sprint("found patternresult")

                                if debug: sprint("found one")
                                pat, result = patch_results.pat, patch_results.result
                                patches += 1
                                must_reverse = getattr(pat.options, 'reflow', None) #  or noResume
                                if must_reverse is None:
                                    must_reverse = not getattr(pat.options, 'resume', False)
                                    _loop = getattr(pat.options, 'resume', False)
                                if False and len(slvars.justVisited) > 100:
                                    # we don't want to have to restart later if were're this far in 
                                    must_reverse = True
                                EaseCode(ea)
                                [GetDisasm(x) for x in idautils.Heads(ea, ea+32)]
                                idc.auto_wait()
                            elif isinstance(patch_results, int):
                                if debug: sprint("patch_results wre int {} (0 is good)".format(patch_results))
                                if patch_results != 0:
                                    raise ObfuFailure("patchresults was non-zero int")
                            else:
                                msg = "cannot handle patch result type: {}".format(type(patch_results))
                                raise ObfuFailure(msg)
                    #  if result and result[0]:
                        #  for r in patch_results[1]:
                            #  patched.extend(r['addressList'])
            # If we patched something, we need to start the trace again
            # or do we? should we?
            if debug: print("line 12A")
            if patches:
                patches = 0
                if single:
                    raise SlowtraceSingleStep()
                if must_reverse:
                    prev_ea = ea
                    ea = ReverseHead(ea)
                    msg = "{:x} made patches (reversing head) to {:x}".format(prev_ea, ea)
                    printi(msg)
                    continue
                else:
                    msg = "made patches (resuming)"
                    printi(msg)
                    continue
                #  printi("slvars.rsp", slvars.rsp)
                
                #  printi("slvars.rsp", slvars.rsp)

                #  if not silent or debug: sprint("0x%x: Return early due to application of patch" % ea)
                #  end = idc.get_fchunk_attr(ea, FUNCATTR_END)
                #  #  analyze(ea, end)
                #  #  idaapi.func_setend(ea, end)
                #  if debug: printi("cbuffer", slvars.cbuffer)
                #  raise RelocationPatchedError(slvars.cbuffer)
            # sprint("0x%x: patch: %i" % (ea, obfu._patch(ea)))
            if line:
                # line = re.sub('7ff79', '', line, 0, re.IGNORECASE)
                if not showComments:
                    line = output(cleanLine(line))
                else:
                    line = output(line)
                line = ""

            if modify:
                c = idc.get_color(ea, idc.CIC_ITEM)
                if not is_hldchk_msk(c):
                    if type(getColor(color)) is int:
                        idaapi.set_item_color(ea, getColor(color))

            #  if debug: sprint("justVisited += {} ({})".format(hex(ea), len(slvars.justVisited)))
            if ea in slvars.justVisited:
                if debug: sprint("already in justVisited: {}".format(hex(ea)))

            # this check is just a formality
            if ea not in slvars.justVisited:
                slvars.justVisited.add(ea)
                slvars.justVisitedRsp[ea] = slvars.rsp

            refs = list(idautils.CodeRefsFrom(ea, 0))
            num_refs = len(refs)
            jump = 0
            cond = 0

            # A rather silly way to do things, we could just
            # read the diff directly into slvars.rsp without looking
            # ahead -- really? how?
            #  if insn.itype == idaapi.NN_jmp:
            #  newea = insn.Op1.addr
            #  if newea and newea != BADADDR:
            #  ea = newea
            #  if d and d.flowControl and re.match(r'FC_(RET|SYS|UNC_BRANCH|INT)', d.flowControl):
            #  slvars.rsp_diff = 0
            #  # FC_NONE: Indicates the instruction is not a flow-control instruction.
            #  # FC_CALL: Indicates the instruction is one of: CALL, CALL FAR.
            #  # FC_RET:  Indicates the instruction is one of: RET, IRET, RETF.
            #  # FC_SYS:  Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
            #  # FC_UNC_BRANCH: Indicates the instruction is one of: JMP, JMP FAR.
            #  # FC_CND_BRANCH: JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
            #  # FC_INT:  Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
            #  # FC_CMOV: Indicates the instruction is one of: CMOVxx.

            # XXX: might re-enable this
            #  SetSpDiffEx(ea)
            slvars.rsp_diff = 0
            if not modify:
                # removed CALL from regex to avoid trouncing __alloca_probe call 
                if not re.match(r'FC_(CND_BRANCH|UNC_BRANCH|CXXXXALL)', decomp.flowControl):
                    slvars.rsp_diff = GetSpDiff(idc.next_head(ea))
            if modify:
                insn = idautils.DecodeInstruction(ea)
                if not insn:
                    if 'slvars' in globals(): sprint(AdvanceFailure("insn could not be decoded"))
                    raise RelocationStackError("insn could not be decoded")
                if re.match(r'FC_(CND_BRANCH|UNC_BRANCH|CALL)', decomp.flowControl):
                    #  if getColor(color) is False:
                    #  idaapi.del_item_color(ea)
                    if type(getColor(color)) is int:
                        c = idc.get_color(ea, idc.CIC_ITEM)
                        if not is_hldchk_msk(c):
                            idaapi.set_item_color(ea, getColor(color))
                    #  if idc.is_flow(ida_bytes.get_flags(idc.next_head(ea))):
                    #  SetSpDiffEx(idc.next_head(ea), 0)
                    slvars.rsp_diff = 0
                elif insn.itype == idaapi.NN_nop or (insn.size == 2 and Word(ea) == 0x9066):
                    #  if getColor(color) is False:
                    #  idaapi.del_item_color(ea)
                    if type(getColor(color)) is int:
                        c = idc.get_color(ea, idc.CIC_ITEM)
                        if not is_hldchk_msk(c):
                            idaapi.set_item_color(ea, color_darkest)
                    if idc.is_flow(ida_bytes.get_flags(idc.next_head(ea))):
                        pass
                        # SetSpida_funcs.FIND_FUNC_OK:DiffEx(idc.next_head(ea), 0)
                    slvars.rsp_diff = 0
                # elif idc.is_flow(ida_bytes.get_flags(idc.next_head(ea))):
                else:
                    # deal with any flow issues
                    _next_head = idc.next_head(ea)
                    _next_insn = ea + GetInsnLen(ea)
                    if not isFlowEnd(ea):
                        if _next_head != _next_insn:
                            if debug: sprint("Forcing code, _next_head: {:x} _next_insn: {:x}".format(_next_head, _next_insn))
                            _insn_len = forceCode(ea)[0]
                            if _insn_len:
                                _insn_len = forceCode(ea + _insn_len)[0]
                            idc.auto_wait()
                            #  if _insn_len + ea != _next_insn:
                                #  sprint("No instruction at {:x}".format(_next_insn))
                                #  raise RelocationTerminalError('No instruction at {:x}'.format(_next_insn))

                        if not idc.is_flow(ida_bytes.get_flags(_next_insn)):
                            if debug: sprint("no flow to {:x}".format(_next_insn))
                            # raise RelocationTerminalError('No flow')

                    for r in range(10):
                        if IsFunc_(ea):
                            break
                        if r == 9:
                            sprint("Lost and couldn't remake our own function")
                            if 'slvars' in globals(): sprint(RelocationTerminalError("Lost and couldn't remake our own function"))
                            raise RelocationStackError("Lost and couldn't remake our own function")
                        if not IsFunc_(ea):
                            if not IsFuncHead(slvars.startLoc):
                                msg = sprint("Lost our own function")
                                if MyMakeFunction(slvars.startLoc):
                                    LabelAddressPlus(slvars.startLoc, slvars.startFnName)
                                raise AdvanceFailure(msg)

                        if not IsFunc_(_next_insn):
                            msg = sprint("No func/chunk at {:x}".format(_next_insn))
                            raise AdvanceFailure(msg)
                            break

                    if idc.is_flow(ida_bytes.get_flags(_next_insn)) and not isFlowEnd(ea):
                        if GetChunkEnd(ea) == idc.next_head(ea):
                            if debug: sprint("GetChunkEnd(ea) == idc.next_head(ea)")
                            if idc.is_flow(ida_bytes.get_flags(idc.next_head(idc.next_head(ea)))):
                                if isFlowEnd(ea):
                                    ida_auto.auto_recreate_insn(ea)
                                else:
                                    if debug: sprint(".. but flow continues past chunk end")

                                    #  func = ida_funcs.func_t(ea)
                                    #  res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
                                    #  if res == ida_funcs.FIND_FUNC_UNDEF:
                                        #  # func passed flow to unexplored bytes
                                        #  sprint("find_func_bounds: func passed flow to unexplored bytes")
                                    #  elif res == ida_funcs.FIND_FUNC_OK:
                                        #  cstart = func.start_ea
                                        #  cend = func.end_ea
                                        #  if debug: sprint("find_func_bound: {:x} - {:x}".format(cstart, cend))
                                    cstart = idc.next_head(ea)
                                    cend = EndOfFlow(cstart, soft=ignoreInt)
                                    ptr = cstart
                                    cnum = GetChunkNumber(ptr)
                                    if cnum > -1:
                                        while ptr < cend:
                                            _cnum = GetChunkNumber(ptr)
                                            if _cnum != cnum:
                                                if _cnum > 0:
                                                    if debug: sprint("removing chunk {}".format(_cnum))
                                                    RemoveChunk(ptr)



                                            ptr = idc.next_head(ptr)
                                    if debug: sprint("ShowAppendFchunk 1061")
                                    ShowAppendFchunk(slvars.startLoc, cstart, cend, ea)


                            #  tmp = end = start = idc.next_head(ea)
                            #  while idc.is_flow(ida_bytes.get_flags(tmp)):
                                #  end = tmp
                                #  tmp = idc.next_head(end)
                            #  ShowAppendFchunk(slvars.startLoc, start, EndOfFlow(end + InsnLen(end, soft=ignoreInt)))
                            idc.auto_wait()

                        slvars.rsp_diff = GetSpDiff(idc.next_head(ea))
                        if not ignoreStack:
                            if slvars.rsp_diff is None:

                                _chunk_owners = GetChunkOwners(ea)
                                _chunk_owners_include_us = False
                                if slvars.startLoc in _chunk_owners:
                                    _chunk_owners.remove(slvars.startLoc)
                                    _chunk_owners_include_us = True
                                _chunk_start = GetChunkStart(ea)
                                _chunk_end = GetChunkEnd(ea)
                                _chunk_number = GetChunkNumber(ea, _chunk_owners[0]) if _chunk_owners else -2
                                if len(_chunk_owners) == 1 and _chunk_number == -1:
                                    _chunk_owner = _chunk_owners[0]
                                    if not IsFuncHead(_chunk_owner):
                                        forceCode(_chunk_owner, _chunk_owner + GetInsnLen(_chunk_owner))
                                        idc.add_func(_chunk_owner, _chunk_owner + GetInsnLen(_chunk_owner))
                                        if not _chunk_owners_include_us:
                                            printi("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x}".format(slvars.startLoc, _chunk_start, _chunk_end))
                                            idc.append_func_tail(slvars.startLoc, _chunk_start, _chunk_end)
                                    if GetChunkNumber(_chunk_start, _chunk_owner) > 0:
                                        if not idc.remove_fchunk(_chunk_owner, _chunk_start):
                                            ZeroFunction(_chunk_owner)
                                            if _chunk_owner in GetChunkOwners(_chunk_start()):
                                                msg = "couldn't fix chunk 0x{:x}".format(idc.next_head(ea))
                                                if 'slvars' in globals(): sprint(ChunkFailure(msg))
                                                raise ChunkFailure(msg)

                                    else:
                                        msg = "couldn't fix chunk 0x{:x}".format(idc.next_head(ea))
                                        if 'slvars' in globals(): sprint(ChunkFailure(msg))
                                        raise ChunkFailure(msg)


                                if GetChunkNumber(ea) == -1 and GetChunkNumber(ea, slvars.startLoc) > 0:
                                    printi("Chunks are really messed up, this chunk 0x{:x} is ghost owned by 0x{:x}".format(ea, slvars.startLoc))
                                if len(GetChunkOwners(ea, includeOwner=1)) != 1:
                                    sprint("[bad chunk] slvars.rsp_diff was none between 0x%x and 0x%x: (%s, %s)" % (
                                        ea, idc.next_head(ea), GetDisasm(idc.next_head(ea)), dii(idc.next_head(ea))))
                                    result = 0
                                    if SmartAddChunk(ea, ea):
                                        result += 1
                                    if SmartAddChunk(idc.next_head(ea), ea):
                                        result += 1
                                    if result:
                                        printi("Added chunk")
                                        #  raise RelocationPatchedError("Extended chunk")
                                        # raise RelocationPatchedError(slvars.cbuffer)
                                    else:
                                        # Couldn't extend
                                        msg = "[bad chunk] No spdiff at 0x{:x}".format(idc.next_head(ea))
                                        if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
                                        raise RelocationTerminalError(msg)
                            elif slvars.rsp_diff == 2:
                                SetSpDiff(idc.next_head(ea), 0)
                                slvars.rsp_diff = 0

            # MakeCodeAndWait(ea)
            mnem = idc.print_insn_mnem(ea)
            # disasm = GetDisasm(ea)
            #  disasm = kp.ida_get_disasm(ea, fixup=1)
            disasm = diida(ea)
            ida_disasm = string_between(';', '', idc.GetDisasm(ea), inclusive=1, repl='').rstrip()
            inslen = MyGetInstructionLength(ea)
            bytes = []
            for i in range(inslen):
                bytes.append(Byte(ea + i))

            # byteArray.append(bytes)
            # disasm.append(bytes)

            bytesHex = " ".join([("%02x" % x) for x in bytes])

            # insnHex = ' '.join(["{:02x}".format(idc.get_wide_byte(ea + a)) for a in range(GetInsnLen(ea))])
            # byteHexArray.append(bytesHex)

            if not mnem:
                if Byte(ea) == 0xcc:
                    line = output("\t; END OF INSTRUCTIONS")
                else:
                    line = output("\t; END OF VALID INSTRUCTIONS")
                break
                msg = "0x%x: no mnem: %s" % (ea, disasm)
                if 'slvars' in globals(): sprint(Exception(msg))
                raise Exception(msg)
            #  mov     [slvars.rsp+var_8], rbx
            opType0 = GetOpType(ea, 0)  # 4
            opType1 = GetOpType(ea, 1)  # 1
            if 0:
                if opType0:
                    opText0 = GetOpnd(ea, 0)
                    if ~opText0.find('rsp') and (~opText0.find('arg_') or ~opText0.find('var_')):
                        pass  # OpNumber(ea, 0)
                if opType1:
                    opText1 = GetOpnd(ea, 1)
                    if ~opText1.find('rsp') and (~opText1.find('arg_') or ~opText1.find('var_')):
                        OpNumber(ea, 1)
            #  disasm = GetDisasm(ea)
            # Sleep(200)
            # for chunk in idautils.Chunks(LocByName(GetFunctionName(ea()))): output(Name(chunk[0]))
            fnName = GetFunctionName(ea)
            fnLoc = LocByName(fnName)
            fnFlags = ida_bytes.get_flags(fnLoc)
            slvars.name = Name(ea)
            if isAnyJmpOrCall(ea):
                target = GetTarget(ea) # target = GetOperandValue(ea, 0)
                if not ida_funcs.func_does_return(target):
                    printi("*** {:x} non-returning function: {}".format(ea, describe_target(target)))
            else:
                target = False
            # GetParamLong
            # INF_BINPREF: 8
            # INF_INDENT: 16
            # INF_COMMENT: 40
            # INF_MARGIN: 70
            # INF_MAXREF: 16
            # INF_XREFNUM: 8
            # INF_XREFS: 15
            # INF_LENXREF: 80
            #
            # 000 |---- 30 (MAXREF*3)--- |loc_7FF70688EF31:                       ; CODE XREF: sub_7FF70688ED3C+72j
            # 000 00 00 00 00 00          |-- 4 (INDENT)-||------- 24 -----------|; sub_7FF70688ED3C+1DF

            #  lineFmt = ".text:%x %3s #%3i %-30s%-4s%s%-24s%s"
            # for elem in lineFmtObj:
                
            #  lineFmt = "{segment}:{ea} {rsp: > 3x} {func:16} {hex} {filler:{indent}}\t{disasm} {cmt}"
            lineFmt = "{segment}:{ea:x} {rsp:> 4x} {spd:>4} {func:16} {hex:<30}{label}\t{disasm} {cmt}"

            #  lineFmt = ".text:%x %-33s      %-30s%-4s%s%-48s %s"
            #  lineFmt = .text: % x  % -33s % -18s % -4s   % s      % -48s ; % s
            #  lineFmt fields:  % ea % slvars.rsp  % hex  % bytes % slvars.indent % label  % disasm % comment

                #  line = output(lineFmt % (
                    #  ea, rspTextCode + ' ' + GetFunctionName(ea)[-16:],           bytesHex, '',                getIndent(), disasm,                                   comment))
                #  line = output(lineFmt % (
                    #  ea, rspText + ' ' + GetFunctionName(GetFuncStart(ea))[-16:], '',       slvars.name + ':', getIndent(), '',                                       ''))
                #  line = output(lineFmt % (
                    #  ea, rspText + ' ' + GetFunctionName(GetFuncStart(ea))[-16:], '',       '',                getIndent(), "jmp {} ; forceJump".format(slvars.name), ''))

            rspText = "        "
            rspTextCode = rspTextLabel = rspText
            spd = '???'
            spd_next = spd_this = None

            if not ida_funcs.get_func(slvars.startLoc):
                if len(slvars.justVisited) == 0:
                    if ea != slvars.justVisited:
                        sprint("[warn] slvars.startLoc != ea {:x} {:x}".format(slvars.startLoc, ea))
                    ForceFunction(ea)
                    idc.auto_wait()

                
            _ref_func = ea or slvars.startLoc
            if ida_funcs.get_func(_ref_func):
                spd_this = idc.get_sp_delta(ea)
                spd_next = idc.get_sp_delta(ea + InsnLen(ea))

            #  if slvars.rsp == None:
                #  pass
            #  if idc.get_spd(ea) is None and len(slvars.justVisited) == 0:
                #  ForceFunction(ea)
            if spd_this is None:
                msg = sprint("GetSpd(ea) is None: 0x%x" % ea)
                if not vim or vim == -1: raise RelocationStackError(msg)

                # rspTextCode = rspTextLabel = rspText = ("%03x    " % slvars.rsp)
            else:
                slvars.minSp = min(slvars.minSp, slvars.rsp)
                slvars.maxSp = max(slvars.maxSp, slvars.rsp)

                if spd_next == 0:
                    spd = ""
                elif not spd_next:
                    spd = ""
                else:
                    spd = "{: 4x}".format(spd_next)

                # so ugly
                if False:
                    if not IsFlow(ea) and spd_this:
                        spd += "({:x})".format(spd_this)

                rspText = "%03x %4s" % (slvars.rsp, '')
                rspTextCode = "%03x %4s" % (slvars.rsp, spd)

            if forceJump:
                if reloc:
                    line = output("\tjmp {}".format(slvars.name))
                else:
                    line = output(lineFmt.format(
                        segment = idc.get_segm_name(ea),
                        ea = ea,
                        rsp = slvars.rsp,
                        spd = '',
                        func = idc.get_func_name(ea)[-16:],
                        hex = '',
                        label = '',
                        disasm = 'jmp {}'.format(slvars.name),
                        cmt = '; forceJmp'
                    ))


                    #  line = output(lineFmt % (
                        #  ea, rspText + ' ' + GetFunctionName(GetFuncStart(ea))[-16:], '', '', getIndent(),
                        #  "jmp {} ; forceJump".format(slvars.name), ''))

                forceJump = None
                # TODO: keep a record of RSPs for other branches and check they match instead of just zeroing
                if not ignoreStack and forceJump and slvars.rsp != forceJumpRsp:
                    msg = "forceJump target {:x} rsp {:x} does not match current {:x} rsp {:x}".format(forceJump, forceJumpRsp, ea, slvars.rsp)
                    if 'slvars' in globals(): sprint(RelocationStackError(msg))
                    raise RelocationStackError(msg)
                    
                slvars.rsp = 0
                break

            if len(slvars.name):
                # line = output(".text:%x %s #%3i %-24s %s%s:" % (ea, rspText, counter, '', getIndent(-4), shortName(slvars.name)))
                if reloc:
                    # line = output(re.sub(r'[^_a-zA-Z0-9]+', '', slvars.name) + ':')
                    line = output(slvars.name + ':')
                else:
                    line = output(lineFmt.format(
                        segment = idc.get_segm_name(ea),
                        ea = ea,
                        rsp = slvars.rsp,
                        spd = '',
                        func = idc.get_func_name(ea)[-16:],
                        hex = '',
                        label = slvars.name + ':',
                        disasm = '',
                        cmt = ''
                    ))
                    #  line = output(lineFmt % (
                        #  ea, rspText + ' ' + GetFunctionName(GetFuncStart(ea))[-16:], '', slvars.name + ':', getIndent(),
                        #  '',
                        #  ''))

                if plan:
                    ida_auto.reanalyze_callers(ea, 0)
                counter += 1
                # line = re.sub('7ff79', '', line, 0, re.IGNORECASE)
                if not showComments:
                    line = output(cleanLine(line))
                else:
                    line = output(line)
                line = ""
            # line = output(".text:%x %s #%3i %-24s %s%s" % (ea, rspText, counter, bytesHex, getIndent(), disasm))
            spdList.append( (ea, slvars.rsp) )
            #  It turned out that comments were always available, and we were filtering them out in cleanLine.
            #
            #  But now we can use this extra comment getting code with Keypatch.
            comments = []
            if showComments:
                with Commenter(ea, 'line') as c:
                    comments += [comment for comment in _.flatten(list(c.cm.values())) if
                                 comment.find("[TEST]") == -1 and comment.find("[obfu::comb]") == -1]
            #  c = Commenter(ea, repeatable = 1)
            #  comments += c.comments
            #  comments = filter(lambda x: x, comments)
            if len(comments):
                comment = '\t; ' + ", ".join(comments)
            else:
                comment = ''
            # This would be a good place to check for a + in the disassembly, correct loc_123+5 jumps, and get rid of var_8
            if GetSize(ea) < 10:
                pass
                # OpHex(ea, -1)
                # ida_bytes.clr_op_type(ea, -1)

            # kp.ida_resolve(kp.ida_get_disasm(ERROREA()))
            mnem = idc.print_insn_mnem(ea)
            mnem_next = idc.print_insn_mnem(idc.next_head(ea))
            ea_next = idc.next_head(ea)
            #  if reloc: line = output(disasm + "\n")
            #
            #  So -- diasm was originally created with
            #      kp.ida_get_disasm(ERROREA(), fixup=1)
            #  Which gives us middling strange results. TO compare:

            #  GetDisasm(ERROREA())                                       mov [rbp+180h+ProcessInformationReturnLength], edx
            #  dii(ERROREA())                                             LEA RBP, [RSP+0x30]
            #  dii(ERROREA())                                             MOV RAX, [RIP-0x35afd2c]
            #  dii(ERROREA())                                             MOV [RBP+0x174], EDX
            #  dinjasm(ERROREA())                                         jmp 0x14460982b
            #  dinjasm(ERROREA())                                         mov [rbp+0x174], edx
            #  dinjasm(ERROREA())                                         mov rax, [0x141051309]
            #  kp.ida_get_disasm(ERROREA())                               jmp loc_14460982B
            #  kp.ida_get_disasm(ERROREA())                               mov [rbp+180h+ProcessInformationReturnLength], edx
            #  kp.ida_get_disasm(ERROREA(), fixup=0)                      mov rax, cs:off_141051309
            #  kp.ida_get_disasm(ERROREA(), fixup=1)                      jmp loc_14460982B
            #  kp.ida_get_disasm(ERROREA(), fixup=1)                      mov dword ptr [rbp+180h+ProcessInformationReturnLength], edx
            #  kp.ida_get_disasm(ERROREA(), fixup=1)                      mov rax, qword ptr cs:[off_141051309]

            # honestly, we have no good reason to use keypatch, and the version we do use
            # had to be modified to work correctly. it does come in useful for some cvt
            # instructions that require `dword` size specifiers (for some wierd reason)
            if distorm or reloc:  # (reloc and (~disasm.find(' ptr ') and not ~disasm.find('cvt'))):
                disasm = dinjasm(ea)
            else:
                # disasm = re.sub(r' \w+ ptr ', ' ', disasm)
                disasm = re.sub(r' (cs:|ds:)', ' ', disasm)
                if reloc and disasm.find('cvt') > -1:
                    disasm = re.sub(r' ptr', '', disasm)

            if skipNops and (mnem == "nop" or Word(ea) == 0x9066):
                line = ''
            elif reloc:
                line = output(getIndent() + disasm.ljust(32) + comment)
            else:
                line = output(lineFmt.format(
                    segment = idc.get_segm_name(ea),
                    ea = ea,
                    rsp = slvars.rsp,
                    spd = spd,
                    func = idc.get_func_name(ea)[-16:],
                    hex = bytesHex,
                    label = '',
                    disasm = disasm,
                    cmt = comment
                ))
                #  line = output(lineFmt % (
                    #  ea, rspTextCode + ' ' + GetFunctionName(ea)[-16:], bytesHex, '', getIndent(), disasm, comment))

            flags = ida_bytes.get_flags(ea)
            if flags & FF_FUNC:
                if flags & FF_REF:
                    if isSegmentInXrefsTo(ea, '.pdata'):
                        line = output('; RVA')
                    else:
                        line = output('; leaf')


            if mnem.startswith("int"):
                if ignoreInt:
                    line = output("\t; ignoring int")
                    ea = AdvanceHead(ea) # , ea + GetInsnLen(ea))
                    continue
                    #  continue
                else:
                    slvars.rsp = 0
                    line = output("\t; Can't follow interrupt")
                    break



            # mov edx, dword ptr cs:loc_140A68C50+2
            # add rdx, cs:qword_140D6A430+0A0h
            ida_disasm = string_between(';', '', idc.GetDisasm(ea), inclusive=1, repl='').rstrip()
            # see also fix_loc_offset(badLabel)
            #  m = re.search(r'(\w*word ptr)? cs:([a-z]+_[A-F0-9]+\+[A-F0-9]+)h?', ida_disasm)
            fix_location_plus_2(ea)

            if 0:
                # Arxan re-enabledment
                if isUnconditionalJmp(mnem) and opType0 == o_near and idc.get_wide_byte(ea) == 0xe9 and not Commenter(ea).match(r'\[ARXAN-'):
                    if ida_bytes.get_original_byte(ea) == 0xe8:
                        UnPatch(ea, ea + 5)
                        idc.auto_wait()
                        mnem = "call"
                        LabelAddressPlus(ea, "possible_arxan_intercept")
                    if stopAtJmp:
                        line = output("\nstopAtJmp: found Jmp 0x%x (%s)" % (ea, disasm))
                        break

            if slvars.rsp < 0:
                line = output("; rsp is negative")
                if not vim:
                    # break
                    pass

            #  if slvars.rsp > 0:
                #  line = output("rsp was positive")
                #  break

            target = GetTarget(ea)

            # first check for "call"
            if isCall(mnem):
                if GetOpType(ea, 0) == idc.o_near and idc.get_func_flags(target) & idc.FUNC_FAR:
                    # sprint("[info] removed FUNC_FAR from {:x} called by {:x}".format(target, ea))
                    SetFuncFlags(target, lambda f: f & ~(idc.FUNC_FAR | idc.FUNC_USERFAR))
                    SetSpDiff(ea + GetInsnLen(ea), 0)
                    slvars.rsp_diff = 0

                # Find obfu arxan
                if GetOpType(ea, 0) in (idc.o_near, idc.o_far):
                    while True:
                        if target == ida_search.find_binary(target, target + 32, "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 e9 ?? ?? ?? ??", 16, SEARCH_CASE | SEARCH_DOWN | SEARCH_NOSHOW):
                            if obfu._patch(target)[0]:
                                if isCall(target):
                                    target = GetTarget(target)
                                    continue
                        break
                    

            isArxan = False
            thisIsArxan = False
            # if isCall(mnem) and opType0 in (o_near, o_mem, o_reg):
            if isCall(mnem) and opType0 in (o_near,): # o_mem
                # if idc.get_spd(ea) and (idc.get_spd(ea) % 16) == 0:
                # TODO: queue this to happen AFTER, because sometimes we need to de-obfu a (parent?) func into a call first
                if not IsFuncHead(target):
                    isArxan = True
                    if debug: sprint("forcing function for call target {:x}".format(target))
                    ForceFunction(target)
                if ea == slvars.startLoc and ida_funcs.func_does_return(target) : # slvars.rsp == 0 and len(slvars.addresses) == 0: # (slvars.rsp % 16) == 0:
                    balanceCalls, balanceLoc, balanceName = CountConsecutiveCalls(ea)
                    balanceCallCount = len(balanceCalls)
                    if balanceCallCount > 2: 
                        thisIsArxan = True
                    else:
                        if depth + 1 < max_depth:
                            SetFuncFlags(target, lambda f: f & ~(idc.FUNC_NORET))
                            printi("\ngoing deeper to {:x} ({})".format(target, depth + 1))
                            EaseCode(target, forceStart=1)
                            retrace(target, adjustStack=adjustStack, depth=depth + 1, max_depth=max_depth)
                            #  print("Have to restart, slvars sullied")
                            #  return 1
                            isArxan = True
                        else:
                            # need to stop processing at this point, since we're probably looking at:
                            # call x -- arxan 
                            # jmp y  -- never reach
                            
                            printi("skipping arxan rabbit hole (depth: {})".format(depth))
                            raise Exception("Must do something about rabbit hole")
                else:
                    if debug: sprint("0x{:x} [spd:{:x}] #{} call {:x} Nice: {}".format(ea, slvars.rsp, len(slvars.addresses), target, IsNiceFunc(target)))


                    
                # TODO: non-returning functions screw us, need to find why
                # ida_funcs.func_does_return
                #  if Commenter(ea).match(r'\[ARXAN-'):
                    #  line = output("\nArxan call to 0x%x at 0x%x (1st check)" % (target, ea))
                    #  slvars.rsp = 0
                    #  break

                if depth == 0 and depth + 1 < max_depth:
                    if ida_funcs.get_func(target) and GetJumpTarget(ea) and not force and not ida_funcs.func_does_return(target):
                        if False:
                            if 'norets' in globals():
                                globals()['norets'].append(target)
                            _targetName = idc.get_func_name(target)
                            if 'Arxan' in _targetName:
                                SetFuncFlags(target, lambda f: f & ~(idc.FUNC_NORET))
                            else:
                                line = output("\nnon-returning call to 0x%x at 0x%x (1st check)" % (target, ea))
                                slvars.rsp = 0
                                break
                    
                    # check for arxan leaders
                    # Check all calls in a function to find repeated nested calls.
                    # Skip through all the calls in a function, then down the
                    # function with all the pushes, to the first (only) call - to
                    # the actual Arxan meat. Grab the (seemingly always first) line that
                    # sets one of the return addresses on the stack, grab the function address
                    # from the offset it uses, and paste that over the original call, as a jmp.
                    balanceCalls, balanceLoc, balanceName = CountConsecutiveCalls(ea)
                    balanceCallCount = len(balanceCalls)
                    if balanceCallCount > 2:
                        if balanceCallCount > 3:
                            arxanJmpOrCall = "call"
                        else:
                            arxanJmpOrCall = "jmp"
                        Commenter(ea).add(sprint("ArxanLeader to " + hex(balanceLoc)[2:] + ", " + str(balanceCallCount) + " calls, target " + str(balanceName)))
                        #  ida_funcs.set_noret_insn(ea, 1)
                        #  SetFuncFlags(target, lambda f: f | idc.FUNC_NORET)
                        labels = "TheJudge TheWitch TheCorpsegrinder TheInvestigator".split(" ")
                        # labels = "ArxanIntercept ArxanLeader ArxanRelayOne ArxanRelayTwo ArxanRelayThree".split(" ")
                        for i, a in enumerate(balanceCalls):
                            Commenter(ea).add("{:x} {}".format(a, labels[i % len(labels)]))
                            LabelAddressPlus(a, labels[i % len(labels)])
                            printi("{:x} {}".format(a, labels[i % len(labels)]))
                            if i > 0:
                                if isCall(a):
                                    ForceFunction(a)
                                    SetFuncEnd(a, a + GetInsnLen(a))
                                    SetFuncFlags(a, lambda f: f & ~(idc.FUNC_NORET))



                        Commenter(ea).add("{:x} {}".format(balanceLoc, "TheBalancer"))
                        printi("{:x} {}".format(balanceLoc, "TheBalancer"))
                        assert IsCode_(balanceLoc), hex(balanceLoc)

                        push_count, new_ea, unused2 = CountConsecutiveMnem(balanceLoc, ["push", "pushf", "pushfq"])
                        #  Commenter(ea).add(sprint("ArxanStackBalance: push_count: " + str(push_count)))
                        if push_count > 8 or diida(new_ea) == 'test rsp, 0xf':
                            if not HasUserName(balanceLoc):
                                LabelAddressPlus(balanceLoc, "ArxanBalance")
                            #  with DebugMode(0):
                            printi("Tracing ArxanBalance: {:x}".format(balanceLoc))
                            retrace(balanceLoc, depth=depth+1, max_depth=max_depth, once=1)

                            _extra = process_balance(balanceLoc)
                            assert _extra, hex(balanceLoc)
                            if 'extra' in _extra and _extra['extra']:
                                _extra = _extra['extra']
                                setglobal('_extra', _extra)
                                _extra = AdvanceInsnList(ea=balanceLoc, insns=_extra, start_ea=balanceLoc, byte_count=_.sum(_extra, lambda v, *a: len(v)))
                                if _extra.insns[-1].insn.startswith('ret'):
                                    printi("removing trailing ret from _extra")
                                    _extra.insns.pop()
                                Commenter(ea).add("ArxanBalance EXTRA: {}".format("; ".join(
                                    _extra.values()
                                    #  _.pluck(_extra.insns, 'insn')
                                )))
                            else:
                                Commenter(ea).add("ArxanBalance NO-EXTRA")
                                _extra = None

                            addrs = []
                            skipped_insn_count, callLoc, unused = AdvanceToMnem(new_ea, "call", addrs)
                            if skipped_insn_count > 1:
                                if False:
                                    balanceSpd = idc.get_spd(GetChunkEnd(balanceLoc)-1) // -8
                                else:
                                    __spd = idc.get_spd(GetChunkEnd(balanceLoc)-1)
                                    if __spd is None:
                                        raise AdvanceFailure("No SPD at {:x}".format(balanceLoc))

                                balanceSpd = __spd // -8

                                mainLoc = SkipJumps(GetTarget(callLoc))
                                sprint("ArxanStackBalance calls 0x" + hex(mainLoc)[2:] + ", after " + str(skipped_insn_count) + " instructions, spd: " + str(balanceSpd))
                                mainName = 'BADADDR'
                                if mainLoc != idc.BADADDR:
                                    sprint("ArxanCheck, " + str(hex(mainLoc)) + ", " + str(get_name_by_any(mainLoc)))
                                    Commenter(ea).add("{:x} {}".format(mainLoc, "TheChecker"))
                                    Commenter(ea).add(sprint("ArxanFunction " + str(idc.get_name(mainLoc)) + " at " + hex(balanceLoc)[2:] + ", " + str(skipped_insn_count + 1) + " calls away"))
                                    _stackMut = None
                                    if HasUserName(mainLoc) and idc.get_func_name(mainLoc).startswith('Arxan') \
                                            and IsFuncSpdBalanced(mainLoc):
                                                _stackMut = FindStackMutators(mainLoc, depth=depth+1, path=[ea]+balanceCalls)
                                                if not len(_stackMut) > 2:
                                                    _stackMut = None
                                    if not _stackMut:
                                        if not HasUserName(mainLoc) or not get_name_by_any(mainLoc).startswith("Arxan"):
                                            LabelAddressPlus(mainLoc, "ArxanCheck")
                                        printi("Tracing ArxanCheck: {:x}".format(mainLoc))
                                        retrace(mainLoc, depth=depth+1, max_depth=max_depth, once=1)
                                        FixFarFunc(mainLoc)
                                        idc.SetType(mainLoc, 'void func(__int64 a1);')
                                        _stackMut = FindStackMutators(mainLoc, depth=depth+1)

                                    printi("FindStackMutators(0x{:x}):\n{}".format(mainLoc, pfh(_stackMut)))
                                    if _stackMut:
                                        sprint("ArxanStuff, found " + str(len(_stackMut)) + " returns")
                                        # [(0x2f, 0x143e929c9, 0x20, 0x90),
                                        #  (0x30, 0x140d38c01, 0x20, 0x90),
                                        #  (0x31, 0x140a60ce7, 0x20, 0x90)]

                                        #  results: 4800000080858948, 30, 88, b0 ([0, 1, 2, 3])
                                        #  [   ('0x4800000080858948', '0x30', '0x88', '0xb0'),
                                            #  ('0x895045034c458bfc', '0x30', '0x88', '0xb0'),
                                            #  ('0x8b0000000000841f', '0x32', '0x88', '0xb0'),
                                            #  ('0x95e9fc9ae8390d8d', '0x31', '0x88', '0xb0'),
                                            #  ('0xc30000000000841f', '0x31', '0x88', '0xb0'),
                                            #  ('0xcccc00a741f9e9e5', '0x32', '0x88', '0xb0')]
                                        #  0x143fee8f6: 0x143fee8f6: 0 0 ArxanStuff, found 6 returns
                                        null_count = 0
                                        cont_count = 0
                                        start_num = 0
                                        last_num = 0
                                        # because each return stack fiddle must balance to a call
                                        #  returnAddresses = [None] * balanceCallCount
                                        returnAddresses = []
                                        printi("[Arxan] balanceCalls: {} (ea:{:x} depth:{})".format(hex(balanceCalls), ea, depth))
                                        if isCall(ea) and ea not in balanceCalls:
                                            balanceCalls.insert(0, ea)
                                            printi("[Arxan] adjusted balanceCalls: {}".format(hex(balanceCalls)))

                                        while len(balanceCalls) > len(_stackMut):
                                            balanceCalls = balanceCalls[1:]
                                            printi("[Arxan] adjusted balanceCalls: {}".format(hex(balanceCalls)))
                                        balanceCallCount = len(balanceCalls)
                                        if balanceCallCount > len(_stackMut):
                                            printi("[Arxan] balanceCalls > return adjustments ({} > {})".format(hex(balanceCalls), len(_stackMut)))
                                        for r in _stackMut:
                                            call_num, call_return, stkvar1, stkvar2 = r.offset, r.location, r.arg, r.align
                                            if ida_ida.cvar.inf.min_ea < call_return < ida_ida.cvar.inf.max_ea and 32 < call_num < 64:
                                                #  consec_calls, targ, unused = CountConsecutiveCalls(call_return, isUnconditionalJmpOrCall)
                                                #  call_num = len(consec_calls)
                                                #  if not start_num:
                                                    #  start_num = call_num
                                                #  num = call_num - start_num
                                                # dprint("[returnAddresses] len(returnAddresses), num")
                                                
                                                num = len(returnAddresses)
                                                returnAddresses.append(call_return)

                                                if not IsCode_(call_return):
                                                    forceCode(call_return)

                                                if idc.print_insn_mnem(call_return).startswith("ret"):
                                                    sprint("ArxanContinuation: " + str(call_num) + " (" + str(call_num - balanceSpd) + ") " + str(hex(call_return)) + ": ret")
                                                    null_count += 1
                                                else:
                                                    sprint("ArxanContinuation: " + str(call_num) + " (" + str(call_num - balanceSpd) + ") " + str(hex(call_return)) + ": " + str(idc.print_insn_mnem(call_return)))
                                                    cont_count += 1

                                            
                                        if _.indexOf(returnAddresses, None) == -1:
                                            count = 0
                                            balanceCalls.reverse()

                                            for call_loc, retn_loc in _.zip(balanceCalls, returnAddresses):
                                                count += 1
                                                if retn_loc is None:
                                                    printi("[arxan] retn_loc is None")
                                                else: 
                                                    Commenter(ea).add("Arxan Return {}: {:x} {} {}".format(count, retn_loc, idc.print_insn_mnem(SkipJumps(retn_loc)), idc.get_name(retn_loc)))

                                            count = -1
                                            if cont_count == 0:
                                                if _extra:
                                                    raise ArxanFailure("No effective returns, but extra code after balance present")
                                                Commenter(ea).add("Arxan Leader with no effective returns")
                                                Commenter(ea).add("[ARXAN-PATCHED]")
                                                #  nassemble(target, "retn", apply=1)
                                                if arxanJmpOrCall == 'call':
                                                    PatchNops(ea, GetInsnLen(ea), 'Arxan with no returns')
                                                else:
                                                    nassemble(ea, 'retn', apply=1)

                                            elif cont_count == 1 and _extra is None:
                                                skip_next = 0
                                                for call_loc, retn_loc in _.zip(balanceCalls, returnAddresses):
                                                    count += 1
                                                    if skip_next:
                                                        skip_next = 0
                                                        continue

                                                    if idc.print_insn_mnem(SkipJumps(retn_loc)).startswith('ret'):
                                                        printi("[arxan] skipping retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                        # skip_next = 1
                                                        continue

                                                    if not IsValidEA(call_loc):
                                                        printi("call_loc was invalid '{}'".format(call_loc))
                                                        call_loc = ea
                                                    if not IsValidEA(retn_loc):
                                                        printi("retn_loc was invalid '{}'".format(retn_loc))
                                                    printi("[arxan] using retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                    nassemble(call_loc, "{} {:#x}".format(arxanJmpOrCall, retn_loc), apply=1)
                                                    ForceFunction(retn_loc)
                                                    if not HasUserName(retn_loc):
                                                        LabelAddressPlus(retn_loc, slvars.startFnName + "::ArxanSkip")
                                                    Commenter(ea).add("Arxan Leader with single return redirected from {:x} to {:x}".format(target, retn_loc))
                                                    Commenter(call_loc).add("Arxan Leader with single return redirected from {:x} to {:x}".format(target, retn_loc))
                                                    Commenter(call_loc).add("[ARXAN-PATCHED]")
                                                    SkipJumps(ea, apply=1)
                                                    continue
                                            else:
                                                with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
                                                    Commenter(ea).add("Arxan Leader with complex returns at {:x}".format(mainLoc))
                                                    Commenter(ea).add("[ARXAN-TEST]")
                                                    #  ...
                                                    cave_end = GetChunkEnd(balanceLoc)
                                                    ZeroFunction(balanceLoc, 1)
                                                    printi("[Cave] {:x} - {:x}".format(balanceLoc, cave_end))
                                                    # asm = nassemble(balanceLoc, "push rcx; push rdx; push 0x10; call 0x{:x}; add rsp, 0x18; retn".format(GetTarget(callLoc)))
                                                    asm = nassemble(balanceLoc, "call 0x{:x}; int3".format(mainLoc), apply=0)
                                                    asm_len = len(asm)
                                                    cave_start = balanceLoc + asm_len
                                                    remaining = cave_end - cave_start
                                                    cave_pos = cave_start

                                                    _locations = SkipJumps(_.pluck(
                                                                        _.sortBy(
                                                                            #  _.filter(_stackMut, lambda x, *a: not x['mnem'].startswith('ret')), 
                                                                            _stackMut,
                                                                        lambda x, *a: x['offset']), 
                                                                    'location'), skipNops=1)

                                                    #  _locations = _.sortBy(_stackMut, lambda x, *a: x['offset'])
                                                    #  _locations_used = _.map(_locations, lambda x, *a: not x['mnem'].startswith('ret')) 
                                                    #  _locations = _.pluck(_locations, 'location')
                                                    #  # _.filter(_stackMut, lambda x, *a: not x['mnem'].startswith('ret')), 
                                                    
                                                    printi("*#*# not_retracing {}".format(hex(_locations)))
                                                    #  _retrace = [retrace(addr, depth=depth+1, max_depth=depth+1) for addr in _locations]
                                                    #  printi("[Target Retracings] {}".format(pfh(_retrace)))
                                                    #  r2 = _.sortBy(_.filter(_stackMut, lambda x, *a: not x['mnem'].startswith('ret')), lambda x, *a: x['offset'])

                                                    sections = []
                                                    if _extra:
                                                        sections = [_extra]
                                                        printi("[Section-Extra] {}".format("; ".join(_extra.values())))
                                                    elif False and len(_locations) == 1:
                                                        printi("[ArxanQuickJump] {:x} -> {:x}".format(ea, _locations[0]))
                                                        Commenter(ea, 'line').add("[ArxanQuickJump] {:x} -> {:x}".format(ea, _locations[0]))
                                                        nassemble(ea, "{} 0x{:x}".format(arxanJmpOrCall, _locations[0]), apply=1)
                                                        continue



                                                    setglobal('_sections', sections)
                                                    sections.extend([AdvanceToMnemEx(addr) for addr in _locations])
                                                    printi("[Sections] {}".format(pfh(_.pluck(sections, 'ea'))))
                                                    setglobal('_sections', sections)
                                                    sizes = [getattr(x, 'byte_count') for x in _sections]
                                                    printi("[Target Sizes] {}".format(pfh(sizes)))
                                                    #    r2 = [
                                                    #            (addr, nassemble(addr, "\n".join(AdvanceToMnemEx(addr).insns))) 
                                                    #                for addr in 
                                                    #            _.pluck(
                                                    #                _.sortBy(
                                                    #                    _.filter(_stackMut, lambda x, *a: not x['mnem'].startswith('ret')), 
                                                    #                lambda x, *a:  x['offset']), 
                                                    #            'location')]
                                                    #    sizes = [len(x[1]) for x in r2]

                                                    if 5 + sum(sizes) < remaining:
                                                        printi("[ArxanFiller] can fit all 0x{:x} bytes in cave".format(sum(sizes)))
                                                        # this should probably only be used for 4-deep (call) arxan routines, since it returns at the end
                                                        _filler = _.flatten(_.pluck(sections, 'labeled_values')) + ['retn']
                                                        # _filler = _.filter(_filler, lambda x, *a: not re.match('\s*jmp \w*(locret|nullsub)', x))
                                                        printi("[Cave Assembling] {}".format(pfh(_filler)))
                                                        printi("[Cave Location] {:x}".format(cave_pos))
                                                        setglobal('debug', 1)
                                                        asm2 = nassemble(cave_pos, _filler, apply=0)
                                                        asm2_len = len(asm2)
                                                        idc.del_items(balanceLoc, idc.DELIT_EXPAND, asm_len + asm2_len)
                                                        printi("[ArxanFiller] assembled 0x{:x} bytes: {}".format(asm2_len, listAsHex(asm2)))
                                                        # EaseCode(cave_pos, forceStart=1)
                                                        #  idc.add_func(cave_pos, cave_pos + asm_len)
                                                        PatchBytes(cave_pos, asm2, 'Cave for destination of original Arxan Function')
                                                        printi("[Cave Preserve] {}".format(diida(cave_pos, length=asm2_len)))
                                                        PatchBytes(balanceLoc, asm, 'Marker for original Arxan function')
                                                        printi("[Cave Preserve] {}".format(diida(balanceLoc, length=asm_len)))
                                                        #  idc.add_func(balanceLoc, cave_pos)
                                                        printi("[BalanceLoc] {:x}".format(balanceLoc))
                                                        # idc.auto_wait()
                                                        # EaseCode(balanceLoc)
                                                        # idc.auto_wait()
                                                        setglobal('debug', 0)
                                                        # PatchBytes(cave_start, _.flatten([x[1] for x in r2]), 'ArxanReturnCode')
                                                        # dprint("[cave_pos] cave_pos, sum(sizes), sizes")
                                                        cave_pos += asm_len
                                                        printi("[cave_pos] cave_pos:{:x}, sum(sizes[0:-1]) sizes:{}".format(cave_pos, sum(sizes[0:-1]), sizes))

                                                    elif 5 + sum(sizes[0:-1]) < remaining:
                                                        printi("[ArxanFiller] can fit some 0x{:x} bytes in cave".format(sum(sizes)))
                                                        _filler = _.flatten(_.pluck(sections[0:-1], 'labeled_values')) + ["{} 0x{:x}".format(arxanJmpOrCall, sections[-1].ea)]
                                                        _filler = _.filter(_filler, lambda x, *a: not re.match('\s*jmp \w*(locret|nullsub)', x))
                                                        printi("[Cave Assembling] {}".format(pfh(_filler)))
                                                        printi("[Cave Location] {:x}".format(cave_pos))
                                                        setglobal('debug', 1)
                                                        asm2 = nassemble(cave_pos, _filler, apply=0)
                                                        asm2_len = len(asm2)
                                                        idc.del_items(balanceLoc, idc.DELIT_EXPAND, asm_len + asm2_len)
                                                        printi("[ArxanFiller] assembled 0x{:x} bytes: {}".format(asm2_len, listAsHex(asm2)))
                                                        # EaseCode(cave_pos, forceStart=1)
                                                        #  idc.add_func(cave_pos, cave_pos + asm_len)
                                                        PatchBytes(cave_pos, asm2, 'Cave for destination of original Arxan Function')
                                                        printi("[Cave Preserve] {}".format(diida(cave_pos, length=asm2_len)))
                                                        PatchBytes(balanceLoc, asm, 'Marker for original Arxan function')
                                                        printi("[Cave Preserve] {}".format(diida(balanceLoc, length=asm_len)))
                                                        #  idc.add_func(balanceLoc, cave_pos)
                                                        printi("[BalanceLoc] {:x}".format(balanceLoc))
                                                        # idc.auto_wait()
                                                        # EaseCode(balanceLoc)
                                                        # idc.auto_wait()
                                                        setglobal('debug', 0)
                                                        # PatchBytes(cave_start, _.flatten([x[1] for x in r2]), 'ArxanReturnCode')
                                                        # dprint("[cave_pos] cave_pos, sum(sizes), sizes")
                                                        cave_pos += asm_len
                                                        printi("[cave_pos] cave_pos:{:x}, sum(sizes[0:-1]) sizes:{}".format(cave_pos, sum(sizes[0:-1]), sizes))


                                                        #  PatchBytes(cave_start, _.flatten([x[1] for x in r2[0:len(r2)-1]]), 'ArxanReturnCode')
                                                        #  forceCode(cave_start, cave_start + sum([sizes[0:len(sizes)-1]]))
                                                        #  cave_pos += sum([sizes[0:len(sizes)-1]])
                                                        #  cave_pos += len(nassemble(cave_pos, "jmp 0x{:x}".format(r2[-1][0]), apply=1))

                                                    else:
                                                        raise ArxanFailure("Couldn't fit all this arxan shit in")

                                                    # this was a rubbish idea
                                                    #   if len(sizes) > 2 and sizes[-1] == 0:
                                                    #       arxanJmpOrCall = 'call'
                                                    nassemble(ea, "{} 0x{:x}".format(arxanJmpOrCall, cave_start), apply=1)
                                                    SkipJumps(ea, apply=1)
                                                    SetFuncEnd(ea, ea + 5)
                                                    # cave_pos += len(nassemble(cave_pos, "ret", apply=1))
                                                    # SetFuncEnd(balanceLoc, cave_start);
                                                    idc.del_func(balanceLoc)
                                                    MyMakeUnknown(balanceLoc, cave_end)
                                                    # forceCode(balanceLoc, cave_pos)
                                                    # idc.add_func(balanceLoc, cave_start)
                                                    # idc.add_func(cave_start, cave_pos)
                                                    LabelAddressPlus(balanceLoc, "ArxanBalanceFillerBunnyOri")
                                                    LabelAddressPlus(cave_start, "ArxanBalanceFillerBunnyCave")
                                                    #  ForceFunction(balanceLoc)
                                                    ForceFunction(cave_start)
                                                    Commenter(cave_start).add("Arxan Code Cave for 0x{:x}".format(ea))

                                                    continue



    #  
                                                #  asm = ''
                                                #  skip_next = 0
                                                #  patch_target = 0
    #  
                                                #  for call_loc, retn_loc in _.zip(balanceCalls, returnAddresses):
                                                    #  count += 1
                                                    #  printi("[arxan] call_loc {} of {}.{}".format(count, len(balanceCalls), len(returnAddresses)))
    #  
                                                    #  if skip_next:
                                                        #  skip_next = 0
                                                        #  patch_target = 1
                                                        #  continue
                                                    #  elif patch_target == 1:
                                                        #  patch_target = call_loc
    #  
                                                    #  if idc.print_insn_mnem(SkipJumps(retn_loc)).startswith('ret'):
                                                        #  printi("[arxan] skipping retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                        #  skip_next = 1
                                                        #  continue
    #  
                                                    #  printi("[arxan] adding retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                    #  asm += '; '.join(AdvanceToMnemEx(SkipJumps(retn_loc), 'retn', inclusive=0)[1])
                                                    #  asm = re.sub(r';\s*jmp [^;].*$', '; ', asm)
                                                    #  skip_next = 1
                                                    #  continue
    #  
                                                #  printi("[arxan] asm: {} for {:x}".format(asm, cave_start))
                                                #  assembled = nassemble(cave_start, asm + "; retn")
                                                #  asm_len = len(assembled)
                                                #  if cave_start + asm_len > cave_end:
                                                    #  raise Exception("[arxan] exceeded fillerbunny cave size")
                                                #  PatchBytes(cave_start, assembled, "ArxanContinuation for {} {:x}".format(idc.get_name(ea), ea))
                                                #  forceCode(cave_start)
                                                #  printi("[arxan] patch_target: {:x}".format(patch_target))
                                                #  printi("[arxan] balanceCalls[-1]: {:x}".format(balanceCalls[-1]))
                                                #  if patch_target < 2:
                                                    #  patch_target = balanceCalls[-1]
                                                #  assembled = nassemble(patch_target, "jmp 0x{:x}".format(cave_start))
                                                #  printi("[arxan] rewriting first call: {}".format(assembled))
                                                #  PatchBytes(patch_target, assembled, "ArxanRemoval")
                                                #  Commenter(patch_target).add("[ARXAN-PATCHED]")
    #  
                                                #  ea = ReverseHead(ea)
                                                #  continue
                                        else:
                                            pp(returnAddresses)
                                            Commenter(ea).add("(B) Arxan Leader with complex returns at {:x}".format(mainLoc))
                                            raise ObfuFailure("can't handle {} arxan returns with {} balance calls".format(len(_stackMut), balanceCallCount))

                                        arxan_comments[ea] = "Avoided Arxan function at {:x}".format(mainLoc)

                                        #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"ArxanIntercept to {balanceName} at {balanceLoc:x}, {balanceCallCount} calls")) # , 5000)
                                                                    #  #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"ArxanFunction {mainName} at {mainLoc:x}, {balanceCallCount + 1} calls")) # , 5100)
                                                                    #  #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"{ea:x}: Avoided Arxan function at {mainLoc:x}")) # , 5200)
                                        mnem = arxanJmpOrCall
    # XXX  
    #  
                            #  skipped_insn_count, callLoc, unused = AdvanceToMnem(new_ea, "call")
                            #  if skipped_insn_count > 1:
                                #  balanceSpd = idc.get_spd(GetChunkEnd(balanceLoc)-1) // -8
                                #  sprint(f"ArxanStackBalance Call, {skipped_insn_count} instructions, spd: {balanceSpd} at {(GetChunkEnd(ERROREA())-1) // -8:x}")
                                #  mainLoc = GetTarget(callLoc)
                                #  mainName = 'BADADDR'
                                #  if mainLoc != idc.BADADDR:
                                    #  sprint(f"ArxanStuff, {hex(mainLoc)}, {get_name_by_any(balanceLoc)}")
                                    #  Commenter(ea).add(sprint(f"ArxanFunction {idc.get_name(mainLoc)} at {balanceLoc:x}, {skipped_insn_count + 1} calls away"))
                                    #  if not HasUserName(mainLoc):
                                        #  LabelAddressPlus(mainLoc, "ArxanStuff")
                                    #  mainName = idc.get_name(mainLoc)
                                    #  retrace(mainLoc)
                                    #  FixFarFunc(mainLoc)
                                    #  idc.SetType(mainLoc, 'void func(__int64 a1);')
                                    #  _stackMut = FindStackMutators(mainLoc)
                                    #  if _stackMut:
                                        #  sprint(f"ArxanStuff, found {len(_stackMut)} returns")
                                        #  # [(0x2f, 0x143e929c9, 0x20, 0x90),
                                        #  #  (0x30, 0x140d38c01, 0x20, 0x90),
                                        #  #  (0x31, 0x140a60ce7, 0x20, 0x90)]
    #  
                                        #  #  results: 4800000080858948, 30, 88, b0 ([0, 1, 2, 3])
                                        #  #  [   ('0x4800000080858948', '0x30', '0x88', '0xb0'),
                                            #  #  ('0x895045034c458bfc', '0x30', '0x88', '0xb0'),
                                            #  #  ('0x8b0000000000841f', '0x32', '0x88', '0xb0'),
                                            #  #  ('0x95e9fc9ae8390d8d', '0x31', '0x88', '0xb0'),
                                            #  #  ('0xc30000000000841f', '0x31', '0x88', '0xb0'),
                                            #  #  ('0xcccc00a741f9e9e5', '0x32', '0x88', '0xb0')]
                                        #  #  0x143fee8f6: 0x143fee8f6: 0 0 ArxanStuff, found 6 returns
                                        #  null_count = 0
                                        #  cont_count = 0
                                        #  start_num = 0
                                        #  last_num = 0
                                        #  returnAddresses = [None] * balanceCallCount
                                        #  for r in _stackMut:
                                            #  call_num, call_return, stkvar1, stkvar2, *a = r.offset, r.location, r.arg, r.align
                                            #  if ida_ida.cvar.inf.min_ea < call_return < ida_ida.cvar.inf.max_ea and 32 < call_num < 64:
                                                #  #  consec_calls, targ, unused = CountConsecutiveCalls(call_return, isUnconditionalJmpOrCall)
                                                #  #  call_num = len(consec_calls)
                                                #  if not start_num:
                                                    #  start_num = call_num
                                                #  num = call_num - start_num
                                                #  returnAddresses[num] = call_return
    #  
                                                #  if not IsCode_(call_return):
                                                    #  forceCode(call_return)
    #  
                                                #  if idc.print_insn_mnem(call_return).startswith("ret"):
                                                    #  sprint(f"ArxanContinuation: {call_num} ({call_num - balanceSpd}) {hex(call_return)}: ret")
                                                    #  null_count += 1
                                                #  else:
                                                    #  sprint(f"ArxanContinuation: {call_num} ({call_num - balanceSpd}) {hex(call_return)}: {idc.print_insn_mnem(call_return)}")
                                                    #  cont_count += 1

                                            
                                        #  if _.indexOf(returnAddresses, None) == -1:
                                            #  count = -1
                                            #  balanceCalls.reverse()
                                            #  if cont_count == 1:
                                                #  skip_next = 0
                                                #  for call_loc, retn_loc in _.zip(balanceCalls, returnAddresses):
                                                    #  count += 1
                                                    #  if skip_next:
                                                        #  skip_next = 0
                                                        #  continue
    #  
                                                    #  if idc.print_insn_mnem(SkipJumps(retn_loc)).startswith('ret'):
                                                        #  printi("[arxan] skipping retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                        #  skip_next = 1
                                                        #  continue
    #  
                                                    #  nassemble(call_loc, "jmp {:#x}".format(retn_loc), apply=1)
                                                    #  Commenter(ea).add("Arxan Leader with single return redirected to {} at {:x}".format(idc.get_name(retn_loc), retn_loc))
                                            #  else:
                                                #  cave_end = GetChunkEnd(balanceLoc)
                                                #  asm = nassemble(balanceLoc, "push rcx; push rdx; push 0x10; call 0x{:x}; add rsp, 0x18; retn".format(GetTarget(callLoc)))
                                                #  asm_len = len(asm)
                                                #  cave_start = balanceLoc + asm_len
                                                #  ida_funcs.del_func(balanceLoc)
                                                #  MyMakeUnknown(balanceLoc, cave_end - balanceLoc)
                                                #  PatchBytes(balanceLoc, asm, "ArxanBalanceFillerBunny")
                                                #  MyMakeFunction(balanceLoc, balanceLoc + asm_len)
                                                #  LabelAddressPlus(balanceLoc, "ArxanBalanceFillerBunny")
    #  
                                                #  asm = ''
                                                #  skip_next = 0
                                                #  patch_target = 0
    #  
                                                #  for call_loc, retn_loc in _.zip(balanceCalls, returnAddresses):
                                                    #  count += 1
                                                    #  printi("[arxan] call_loc {} of {}.{}".format(count, len(balanceCalls), len(returnAddresses)))
    #  
                                                    #  if skip_next:
                                                        #  skip_next = 0
                                                        #  patch_target = 1
                                                        #  continue
                                                    #  elif patch_target == 1:
                                                        #  patch_target = call_loc
    #  
                                                    #  if idc.print_insn_mnem(SkipJumps(retn_loc)).startswith('ret'):
                                                        #  printi("[arxan] skipping retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                        #  skip_next = 1
                                                        #  continue
    #  
                                                    #  printi("[arxan] adding retn_loc {} {:x} (call_loc {:x})".format(count, retn_loc, call_loc))
                                                    #  asm += '; '.join(AdvanceToMnemEx(SkipJumps(retn_loc), 'retn', inclusive=0)[1])
                                                    #  asm = re.sub(r';\s*jmp [^;].*$', '; ', asm)
                                                    #  skip_next = 1
                                                    #  continue
    #  
                                                #  printi("[arxan] asm: {} for {:x}".format(asm, cave_start))
                                                #  assembled = nassemble(cave_start, asm + "; retn")
                                                #  asm_len = len(assembled)
                                                #  if cave_start + asm_len > cave_end:
                                                    #  raise Exception("[arxan] exceeded fillerbunny cave size")
                                                #  PatchBytes(cave_start, assembled, "ArxanContinuation for {} {:x}".format(idc.get_name(ea), ea))
                                                #  forceCode(cave_start)
                                                #  printi("[arxan] patch_target: {:x}".format(patch_target))
                                                #  printi("[arxan] balanceCalls[-1]: {:x}".format(balanceCalls[-1]))
                                                #  if patch_target < 2:
                                                    #  patch_target = balanceCalls[-1]
                                                #  assembled = nassemble(patch_target, "jmp 0x{:x}".format(cave_start))
                                                #  printi("[arxan] rewriting first call: {}".format(assembled))
                                                #  PatchBytes(patch_target, assembled, "ArxanRemoval")
                                                #  Commenter(patch_target).add("[ARXAN-PATCHED]")
    #  
                                                #  ea = ReverseHead(ea)
                                                #  continue
                                        #  else:
                                            #  pp(returnAddresses)
                                            #  Commenter(ea).add("complex arxan unsolved")
                                            #  raise ObfuFailure("can't handle {} arxan returns with {} calls".format(len(returnAddresses), balanceCallCount))
    #  
                                        #  arxan_comments[ea] = "Avoided Arxan function at {:x}".format(mainLoc)

                                        #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"ArxanIntercept to {balanceName} at {balanceLoc:x}, {balanceCallCount} calls")) # , 5000)
                                                                    #  #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"ArxanFunction {mainName} at {mainLoc:x}, {balanceCallCount + 1} calls")) # , 5100)
                                                                    #  #  setTimeout(lambda *a: \
                                        #  Commenter(ea).add(sprint(f"{ea:x}: Avoided Arxan function at {mainLoc:x}")) # , 5200)
                                        # mnem = "jmp"

                                    #  raise ObfuFailure('Arxan Error - FindStackMutator')
                                #  raise ObfuFailure('Arxan Error')
                            #  raise ObfuFailure('Arxan Error')
                        # raise ObfuFailure('Not enough pushes for an Arxan Stack Balance')
                    #  else: codeRefsTo.add(target)



            if debug: printi("line 133")
            # if isCall(mnem) and opType0 in (o_mem, o_near, o_reg) and GetJumpTarget(ea):
            if isCall(mnem) and opType0 in (o_near,) and GetJumpTarget(ea): # o_mem
                if False and ida_funcs.get_func(target) and not ida_funcs.func_does_return(target):
                    line = output("\nnon-returning call to 0x%x at 0x%x (2nd check)" % (target, ea))
                    slvars.rsp = 0
                    break

                # line = output("\t; Skipping o_mem/o_near call")
                line = output("\t; Skipping o_near call")
                if opType0 == o_near:

                    if target not in later2 and not IsUnknown(target) and idc.get_func_attr(GetJumpTarget(ea), idc.FUNCATTR_FLAGS) & FUNC_LIB == 0:
                        later_pending.add(GetJumpTarget(ea))
                try:
                    ea = AdvanceHead(ea)
                    continue
                except AdvanceFailure as e:
                    line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                    break

            if debug: printi("line 134")
            # first check for "jmp"
            if labelNextCall:
                if isUnconditionalJmpOrCall(mnem):
                    target = GetTarget(ea) # target = GetOperandValue(ea, 0)
                    if (isUnconditionalJmp(mnem) and Name(target).find('sub_') == 0) or (isCall(mnem)):
                        newFunctionName = labelNextCall
                        if newFunctionName[0] >= '0' and newFunctionName[0] <= '9':
                            newFunctionName = '_' + newFunctionName
                        if LocByName(newFunctionName) < BADADDR and target != LocByName(newFunctionName):
                            newFunctionName = newFunctionName + "_2"
                        sprint("0x%x: Labelling function: %s" % (target, newFunctionName))
                        LabelAddress(target, newFunctionName)
                        labelNextCall = False

            if isConditionalJmp(mnem):
                fnLoc = GetTarget(ea) # target = GetOperandValue(ea, 0)
                if not is_real_func(ea, fnLoc):
                    if modify or appendChunks:
                        if debug: sprint("ShowAppendFchunk 2182")
                        ShowAppendFchunk(slvars.startLoc, target, EndOfFlow(target, soft=ignoreInt), ea)

                    ida_auto.auto_wait()

                    if modify:
                        if delsp:
                            SetSpDiffEx(ea, 0)

            if applySkipJumps and isAnyJmp(ea):
                SkipJumps(ea, apply=1, skipNops=1)


            if isUnconditionalJmpOrCall(mnem):
                target = GetTarget(ea) # target = GetOperandValue(ea, 0)
                if not ida_ida.cvar.inf.min_ea < target < ida_ida.cvar.inf.max_ea:
                    line = output("\t; invalid target {:x}".format(target))
                    if isCall(mnem):
                        ea = AdvanceHead(ea)
                        continue
                    break
                if target == limit:
                    line = output("\t; hit preset limit")
                    if isCall(mnem):
                        ea = AdvanceHead(ea)
                        continue
                    else:
                        break
                if GetFunctionName(target).find("FatalError") > -1:
                    line = output("\t; fatal error")
                    fatal = True
                    break
                    # output("e: %s" % line)
                if isUnconditionalJmp(mnem) and slvars.rsp == 0 and not IsSameFunc(ea, target):
                    if debug: sprint("[debug] slvars.rspHist.items:{}".format(slvars.rspHist.items))
                    
                    if not "allow_tail_calls":
                        if slvars.rspHist and max(slvars.rspHist)[1] > 0 and slvars.rspHist[-2][1] > 0:
                            with Commenter(ea) as c:
                                if not isRet(SkipJumps(ea, skipNops=1)) and not c.match("\[ALLOW JMP]"): 
                                    c.add("[TAIL-CALL]")
                                    line = output("\t; assuming tail-call jmp")
                                    break
                    # ea = AdvanceHead(ea, FollowTarget(ea, target))

                # if isUnconditionalJmp(mnem) and opType0 in (o_mem, o_near, o_reg): # and (removeFuncs or addFuncs):
                if isUnconditionalJmp(mnem) and opType0 in (o_near,): # o_mem, and (removeFuncs or addFuncs):
                    # This doesn't seem to get called when we need it, obfu::comb gets first hit
                    #  0x140cb33f1: slowtrace::mainloop
                    #  0x140cb33f1: obfu::_patch
                    #  0x140cb33f1: obfu::comb: length:150
                    #
                    isRealFunc = is_real_func(ea, GetTarget(ea))
                    if isRealFunc:
                        break

                # end of `if removeFuncs`

                if addComments:
                    add_comment = addComments
                    # sprint("0x%x: Adding add_comment: %s" % (ea, add_comment))
                    Commenter(target, repeatable=1).add(add_comment)

            if isAnyJmp(mnem):
                target = GetTarget(ea) # target = GetOperandValue(ea, 0)
                if target == idc.BADADDR:
                    raise AdvanceFailure("Couldn't advance from ea (should be jump) (0x{:x})".format(ea))

                #  o_void     = ida_ua.o_void      # No Operand                           ----------
                #  o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
                #  o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
                #  o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
                #  o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
                #  o_imm      = ida_ua.o_imm       # Immediate Value                      value
                #  o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
                #  o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
                if debug:
                    if opType0 == o_mem: sprint("{} opType {}".format(disasm, "o_mem"))
                    if opType0 == o_reg: sprint("{} opType {}".format(disasm, "o_reg"))
                    if opType0 == o_phrase: sprint("{} opType {}".format(disasm, "o_phrase"))
                    if opType0 == o_displ: sprint("{} opType {}".format(disasm, "o_displ"))
                    if opType0 == o_imm: sprint("{} opType {}".format(disasm, "o_imm"))
                    if opType0 == o_far: sprint("{} opType {}".format(disasm, "o_far"))
                    if opType0 == o_void: sprint("{} opType {}".format(disasm, "o_void"))
                    if opType0 == o_near: sprint("{} opType {}".format(disasm, "o_near"))
                    if opType0 == o_far: sprint("{} opType {}".format(disasm, "o_far"))

                if opType0 == o_near or opType0 == o_mem:
                    if not SegName(target).startswith(".text"):
                        line = output("\t; Strange jump target (invalid segment: %s)" % idc.get_segm_name(target))

                    targetString = idc.print_operand(ea, 0)
                    if debug: sprint("targetString: {}".format(targetString))
                    targetStringByName = Name(target)
                    if debug: sprint("targetStringByName: {}".format(targetStringByName))
                    if isCall(mnem) and not IsFuncHead(target) and addFuncs:
                        ForceFunction(target)
                    if targetStringByName and targetString != targetStringByName:
                        line = line.replace(targetString, targetStringByName)
                    #
                    #  if re.search(r"^[$a-z0-9_:.]+(?:[-+][0-9a-f]+h)$", targetString, re.I):
                    #  parts = re.split(r'([-+])', targetString)
                    #  if len(parts) == 3:
                    #  value = LocByName(parts[0])
                    #  if value < BADADDR:
                    #  offset = int(parts[1] + parts[2][:-1], 16)
                    #  value += offset
                    #  if value != target:
                    #  sprint("0x%x: we fucked up" % ea)
                    #  else:
                    #  newTargetString = Name(value)
                    #  if newTargetString is not None:
                    #  renameOperand0 = newTargetString
                    #  line.replace(targetString, newTargetString)

                    if not idc.is_code(ida_bytes.get_flags(target)):
                        if not forceCode(target):
                            sprint("0x%x: Jump target %x not recognised as code" % (ea, target))

                # if opType0 not in (o_mem, o_near, o_reg):
                if opType0 not in (o_near,): # o_mem
                    # line = output("\t; Can't follow opType0 " + (", ".join(opTypeAsName(opType0))))
                    # output("e: %s" % line)
                    if isCall(mnem):
                        # ea = AdvanceHead(ea)
                        try:
                            ea = AdvanceHead(ea)
                            continue
                        except AdvanceFailure as e:
                            line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                            break
                        # continue
                    else:
                        break
                elif target in slvars.justVisited and isCall(mnem):
                    line = output("\t; already slvars.justVisited")
                    skipAddRsp = True
                    #  ea = AdvanceHead(ea)
                    #  continue
                    try:
                        ea = AdvanceHead(ea)
                        continue
                    except AdvanceFailure as e:
                        line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                        break
                    # break
                    # output("e: %s" % line)
                elif target in slvars.justVisited and isUnconditionalJmp(mnem):
                    line = output("\t; already slvars.justVisited")
                    skipAddRsp = True
                    break

                #  elif jcFirst and isUnconditionalJmp(mnem) or isConditionalJmp(mnem):
                #  _pos = pushBranch(target)
                #  continue

                elif isUnconditionalJmp(mnem):
                    target = GetTarget(ea)
                    if not IsCode_(target):
                        printi("[warn] target !IsCode_(0x{:x}) from {:x}".format(target, ea))
                    if SegName(target) == "":
                        line = output("\t; Invalid target ")
                        break
                    ea = AdvanceHead(ea, FollowTarget(ea, target))

                    # jmp     near ptr qword_7FF708A39960+11h; jumping to 7ff708a39971
                    # line = output("\t; _jumping to %x" % target)
                    # output("e: %s" % line)
                    continue

                elif isConditionalJmp(mnem):
                    if not is_real_func(ea, GetTarget(ea)):
                        #  if disasm.find('locret_') > -1:
                        #  line = output("\t; would trigger RETN")
                        # output("e: %s" % line)
                        if SegName(target) == "":
                            line = output("\t; Invalid target ")
                        elif target in slvars.justVisited:
                            line = output("\t; Not pushing branch, already slvars.justVisited")
                        else:
                            # slvars.rsp_diff = -8
                            _pos = pushBranch(target)
                            if _pos:
                                line = output("\t; Pushing to branch stack (%x)" % _pos)
                            else:
                                line = output("\t; already visited")

                elif isCall(mnem):
                    if GetFunctionFlags(target) & FUNC_LIB == FUNC_LIB:
                        line = output("\t; library function")
                        #  ea = idc.next_head(ea)
                        #  continue
                    if target in slvars.justVisited:
                        skipAddRsp = True
                        line = output("\t; already slvars.justVisited (2)")
                        #  ea = AdvanceHead(ea)
                        #  continue
                        try:
                            ea = AdvanceHead(ea)
                            continue
                        except AdvanceFailure as e:
                            line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                            break
                    elif SegName(target) == "":
                        line = output("\t; Invalid target ")
                        break
                    elif callStack.__len__() < depth:
                        slvars.rsp_diff = -8
                        callStack.append(idc.next_head(ea))
                        rspStack.append(slvars.rsp)
                        mnemStack.append(mnem)
                        pushState()
                        line = output("\t; pushing callStack to " + ("%d" % len(callStack)))
                        # line = output("\t; jumping to 0x%x" % target)
                        # output("e: %s" % line)
                        ea = AdvanceHead(ea, FollowTarget(ea, target))
                        continue
                    else:
                        line = output("\t; Call would exceed depth, skipping")
                        try:
                            ea = AdvanceHead(ea)
                            continue
                        except AdvanceFailure as e:
                            line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                            break
                        # output("e: %s" % line)

            if not ignoreExtraStack and not IsStackOperand(ea, ignoreLeaDisplacement=0):

                n = idc.get_sp_delta(ea_next)
                if idc.is_flow(ida_bytes.get_flags(ea_next)) and not isFlowEnd(ea) and n:
                    ida_disasm_next = string_between(';', '', idc.GetDisasm(ea_next), inclusive=1, repl='').rstrip()

                    if not '__alloca_probe' in ida_disasm and not Commenter(ea, "line").match(r'\[.*SPD=', re.I): #  and not Commenter(ea_next, "line").match(r'\[.*SPD=', re.I):
                        sprint("fixing unexpected stack change from: {} | {}".format(ida_disasm, ida_disasm_next))
                        # user stkpnt will stay around, auto stkpnt will quickly disappear
                        SetSpDiffEx(ea, None)
                        SetSpDiff(ea_next, 0)
                        idc.add_user_stkpnt(ea_next, 0)

            if not ignoreStack and IsStackOperand(ea, ignoreLeaDisplacement=0):
                # n = idc.get_sp_delta(ea_next)
                n = None
                na = GetSpDiffEx(ea)
                if na:
                    n = na[-1]
                    # printi(hex(ea), n)
                if n is not None:
                    stk = n
                    sp_correct = None

                    if mnem in ("push", "pushfq", "pushfd", "pushf"):
                        sp_correct = -8
                    elif mnem in ("pop", "popfq", "popfd", "popf"):
                        if idc.print_operand(ea, 0) != 'rsp':
                            sp_correct = 8
                        else:
                            sp_correct = None
                    elif mnem == "lea":
                        m = re.match(r"""lea rsp, \[rsp([-+][0-9a-fxh]+)]""", diida(ea))
                        if m:
                            _delta = int(m.group(1).rstrip('h'), 0)
                            sp_correct = _delta 
                        else:
                            if debug: printi("[info] {:x} should instruction affect stack: {}? spdelta: 0x{:x}".format(ea, diida(ea), n))
                            if diida(ea).startswith('lea esp'):
                                raise RelocationUnpatchRequest('lea esp', ea)
                            line = output("\t; [info] should instruction affect stack?")
                    elif mnem == "sub" or mnem == "add":
                        m = re.match(r"""(sub|add) rsp, (-?[0-9a-fxh]+)""", diida(ea))
                        if m:
                            _delta = int(m.group(2).rstrip('h'), 16)
                            if m.group(1) == 'sub':
                                _delta = 0 - _delta
                            sp_correct = _delta 
                        else:
                            m = re.match(r"""add rsp, \[rsp([-+][0-9a-fxh]+)]""", diida(ea))
                            if m:
                                # tricky push 10, 18 pop *rsp bullshit
                                pass
                            else:
                                printi("[warn] {:x} instruction should affect stack: {}".format(ea, diida(ea)))
                                line = output("\t; [warn] instruction should affect stack")


                    if sp_correct is not None and stk != sp_correct:
                        # if adjustStack == 2:
                            # idc.add_user_stkpnt(...
                        if adjustStack:
                            #  if mnem == "sub":
                            #  slvars.rsp_diff = 0 - GetOperandValue(ERROREA(), 1)
                            #  if mnem == "push":
                            #  slvars.rsp_diff = GetOperandValue(ERROREA(), 1)
                            slvars.rsp_diff = sp_correct
                            idc.add_user_stkpnt(ea_next, slvars.rsp_diff)
                                #  if 'slvars' in globals(): sprint(RelocationStackError("0x%x: 18 Don't know how to adjust SpDiff for %s" % (ea, diida(ea))))
                                #  raise RelocationStackError("0x%x: 18 Don't know how to adjust SpDiff for %s" % (ea, diida(ea)))
                        elif extremeStack:
                            # idc.del_func(slvars.startLoc)
                            if 'slvars' in globals(): sprint(\
                                    RelocationStackError("0x%x: 19 Missing SpDiff for %s" % (ea, diida(ea))))
                            raise  \
                                    RelocationStackError("0x%x: 19 Missing SpDiff for %s" % (ea, diida(ea)))
                        elif fatalStack:
                            if 'slvars' in globals(): sprint(RelocationInvalidStackError("0x%x: 12 stackop %s with incorrect SpDiff %i at 0x%x" % (ea, mnem, stk, ea_next)))
                            raise RelocationInvalidStackError("0x%x: 13 stackop %s with incorrect SpDiff %i at 0x%x" % (ea, mnem, stk, ea_next))
                        elif adjustStackFake:
                            fakedAddresses = slowtrace2(fnLoc, silent=1, ignoreStack=1, fakesp=1)
                            r = GenericRanger(fakedAddresses, sort=True)
                            for i in r:
                                MyMakeUnknown(i.start, i.length_sub_1, DOUNK_NOTRUNC)
                            #  MyMakeUnkn(fnLoc, DOUNK_EXPAND | DOUNK_NOTRUNC)
                            ida_auto.auto_wait()
                            if debug: sprint('MakeFunction3209')
                            MyMakeFunction(fnLoc, noMakeFunction)
                            ida_auto.auto_wait()
                            for i in r:
                                if debug: sprint("ShowAppendFchunk 2706")
                                ShowAppendFchunk(slvars.startLoc, i["start"], i["start"] + i["length"], ea)

                            slowtrace2(fnLoc, silent=1, ignoreStack=1)
                            #  if 'slvars' in globals(): sprint(RelocationStackError())
                            #  raise RelocationStackError()
                            if 'slvars' in globals(): sprint(RelocationInvalidStackError("0x%x: 18 stackop %s with incorrect SpDiff %i at 0x%x" % (ea, mnem, stk, ea_next)))
                            raise RelocationInvalidStackError("0x%x: 27 stackop %s with incorrect SpDiff %i at 0x%x" % (ea, mnem, stk, ea_next))
                        else:
                            sprint("stackop %s with incorrect SpDiff 0x%x at 0x%x : 0x%x %s | %s" % (mnem, stk, ea_next, ea + GetInsnLen(ea), idc.print_insn_mnem(ea), GetSpDiffEx(ea)))

                        #  if mnem == "sub":
                        #  slvars.rsp_diff = 0 - GetOperandValue(ERROREA(), 1)
                        #  if mnem == "push":
                        #  slvars.rsp_diff = GetOperandValue(ERROREA(), 1)
                        #  if mnem == "push":
                        #  slvars.rsp_diff = -8
                        #  SetSpDiff(ea_next, slvars.rsp_diff)
                        #  ida_auto.auto_wait()
                        #  elif mnem == "pop":
                        #  slvars.rsp_diff = 8
                        #  SetSpDiff(ea_next, slvars.rsp_diff)
                        #  ida_auto.auto_wait()
                        #  else:
                        #  sprint("0x%x: confused about stackop '%s'" % (ea, mnem))

            if mnem == "retn" or mnem == "ret":
                if slvars.rsp is None:
                    slvars.rsp = -9999
                if not skipAddRsp:
                    if not silent or slvars.rsp: sprint("%s: adding retn rsp of 0x%x" % (ida_disasm, slvars.rsp))
                    slvars.retSps.add(slvars.rsp)
                if len(callStack) < 1:
                    line = output("\t; call stack is empty; END OF BRANCH")
                    break
                else:
                    slvars.rsp_diff = +8
                    if slvars.rsp is None:
                        slvars.rsp = 0
                    rsp_effective = slvars.rsp - slvars.rsp_diff
                    popped_mnem = ""
                    while popped_mnem != "call" and len(callStack):
                        target = callStack.pop()
                        slvars.previousHead = None
                        # dprint("poptarget1 ")
                        if debug: sprint("poptarget1")
                        ea = PopTarget(ea, target)
                        retn_rsp = rspStack.pop()
                        popped_mnem = mnemStack.pop()
                        poppedState = popState()
                    #  if len(callStack) == 0:
                    #  line = output("\t; call stack is empty; END OF BRANCH")
                    #  break
                    line = output("\t; from %s @ %0x" % (" ".join(poppedState.disasm.split()), poppedState.ea))
                    if retn_rsp != rsp_effective:
                        if retn_rsp is not None and rsp_effective is not None:
                            line = output("\t; slvars.rsp slippage: got %0x, expected %0x" % (rsp_effective, retn_rsp))
                        else:
                            line = output("\t; slvars.rsp slippage: lost track of slvars.rsp (reanalyse?)")
                    continue  # dont want to do a idc.next_head, or do we?
                    # Well we would have to push current address to callStack

            # If no interesting mnem was found, default here:

            target1 = idc.next_head(ea)
            target2 = idc.next_not_tail(ea)
            if not ignoreInt and idc.get_wide_byte(target2) == 0xcc:
                line = output("\t; 0xCC")
                # in this case, we should check if previous statement was
                # a condition jump, and if so, immediately resume that branch.
                # sprint("0x%x: couldn't continue, hit 0xCC" % ea)
                break

            try:
                ea = AdvanceHead(ea)
                if debug: print("line 139a")
                continue
            except AdvanceFailure as e:
                if debug: print("line 139b")
                next_insn = ea + GetInsnLen(ea)
                line = output("\nCouldn't advance past 0x%x (%s)" % (ea, str(e)))
                #  raise InvalidInstruction("Couldn't advance past {} due to invalid instruction at {}: {} ({})".format(
                    #  hex(ea),
                    #  hex(next_insn),
                    #  generate_disasm_line_unspaced(next_insn, 0),
                    #  generate_disasm_line_unspaced(next_insn, idc.GENDSM_FORCE_CODE)))
                break


            if debug: print("line 139c")

            # if not idc.is_code(ida_bytes.get_flags(target2)):
            # forgeAheadWithCode(target2)
            # ea = target
            # if not idc.is_code(ida_bytes.get_flags(ea)):
            # sprint("0x%x: can't advnce, not code" % ea)

        # line = re.sub('7ff79', '', line, 0, re.IGNORECASE)

        line = output("\t; BREAK")
        if not showComments:
            line = output(cleanLine(line))
        else:
            line = output(line)

        if not fatal and len(slvars.retSps) == 0:
            if slvars.rsp is None:
                slvars.rsp = -9999
            if not skipAddRsp:
                next_ea = ea + GetInsnLen(ea)

                if not silent or slvars.rsp: sprint(("0x%x: break - adding retn slvars.rsp of 0x%x: {}" % (ea, slvars.rsp)).format(diida(next_ea)))
                slvars.retSps.add(slvars.rsp)

        aborted = -1
        while len(slvars.branchStack):
            if len(slvars.branchNumber):
                output("\n; First chance: resuming from branch stack (%s)\n" % (slvars.branchNumber[0]))
                slvars.branchNumber.pop(0)
            else:
                printi("branchNumber was shorter than branchStack: {} < {}".format(len(slvars.branchNumber), len(slvars.branchStack)))
            aborted = 0
            # output("; checking branchStrack::len")
            branch = slvars.branchStack.pop(0)
            if branch.target in slvars.justVisited or branch.target in slvars.justVisited:
                output("; aborting branch to already slvars.justVisited location")
                aborted = 1
                continue
            aborted = 2
            break

        if aborted == -1: break
        if aborted == 1: break
        if aborted == 2:
            if debug: sprint("isBranchRestore")
            # extract(branch.state)
            slvars2.previousHeads.clear()
            slvars.indent = branch.state.indent
            slvars.name = branch.state.name
            # callStack = branch.state.callStack
            # rspStack = branch.state.rspStack
            if debug: sprint("ShowAppendFchunk 2830")
            ShowAppendFchunk(branch.source, branch.target, EndOfFlow(branch.target, soft=ignoreInt), "branchRestore")
            isBranchRestore = 1

            for k in _.keys(branch.state):
                v = getattr(slvars, k, None)
                b = branch.state[k]
                if k == 'ea':
                    pass
                if k == 'startLoc':
                    pass
                if k == 'startFnName':
                    pass
                elif k == 'instructions':
                    if debug: sprint("rewrote slvars2.instructions with {} entries".format(len(b)))
                    slvars2[k].clear()
                    slvars2[k].extend(b)
                elif k == 'justVisited' and isBranchRestore:
                    pass
                #  elif k == 'rspHist':
                    #  print("rsp_...")
                elif k == 'addresses':
                        if debug: sprint("rewrote slvars.addresses with {} entries".format(len(b)))
                        slvars[k].clear()
                        for x in b:
                            slvars[k].add(x)
                        #  slvars[k] == set([x for x in b])
                elif k not in slvars:
                    #  printi("Reversing: would be adding field {} to slvars".format(k))
                    v = None
                elif isinstance(v, list):
                    #  printi("copying2 {} {}".format(k, v))
                    v.clear()
                    v.extend(b)
                elif isinstance(v, set):
                    #  printi("copying2 {} {}".format(k, v))
                    v.clear()
                    for x in b:
                        v.add(x)
                elif callable_m(v, 'copy'):
                    #  printi("copying1 {} {}".format(k, v))
                    setattr(slvars, k, v.copy())
                    #  v.clear()
                    #  v.extend(b)
                elif isinstance(b, integer_types):
                    slvars[k] = b
                elif isinstance(b, string_types):
                    slvars[k] = b
                else:
                    #  printi(f"Reversing {k} {ahex(v)} -> {ahex(b)}")
                    printi("popping jmp stack: unhandled type: {} {}".format(k, type(b)))
                    slvars[k] = b

            isBranchRestore = 0


            # dprint("poptarget2 ")
            if debug: sprint("poptarget2")
            ea = PopTarget(ea, branch.target)
            # disasm = branch.state.disasm
            # mnemStack = branch.state.mnemStack
            # mnem = branch.state.mnem
            # slvars.rsp = branch.state.rsp

            output("\n; Second change resuming from branch stack\n")
            counter += 1






    if len(slvars.fakedAddresses):
        return slvars.fakedAddresses
    if returnResult:
        return slvars2.appendLines + slvars2.outputLines
    r = [str(x) for x in slvars2.outputLines]
    s = "\n".join(r)

    if regexPatch:
        pattern = r'^(.*\t+jmp (loc_[0-9a-fA-F]+).*\n.*\2:.*\n)'
        s = re.sub(pattern, r'', s, 0, re.MULTILINE | re.IGNORECASE)

    if not showComments:
        pattern = r'^(\s+nop)'
        s = re.sub(pattern, r';\1', s, 0, re.MULTILINE | re.IGNORECASE)

    if vim:
        if vim == -1:
            if not slvars.retSps:
                if 'slvars' in globals(): sprint(RelocationInvalidStackError("Function ended without RETN"))
                return RelocationInvalidStackError("Function ended without RETN")

            return _.reduce(list(slvars.retSps), lambda memo, value, index: memo + abs(value), 0)
        VimEdit(slvars.startLoc, s)
        return

    if regexPatch and not patches:
        r = obfu_regex(slvars.startLoc, s.split("\n"))
        if r:
            sprint("Found regex patch")
            msg = "Found regex patch"
            if 'slvars' in globals(): sprint(RelocationPatchedError(msg))
            raise RelocationPatchedError(msg)

    if not patches or force:
        if reloc:
            if not force:
                if patches:
                    sprint("Patches were applied, please re-run.")
                    msg = slvars.cbuffer
                    if 'slvars' in globals(): sprint(RelocationPatchedError(msg))
                    raise RelocationPatchedError(msg)
                rs = slvars.retSps
                if len(rs) and (min(rs) != 0 or max(rs) != 0):
                    msg = "0x%x: Function has unbalanced stack, please fix. %s" % (slvars.startLoc, rs)
                    sprint(msg)
                    if regexPatch:
                        obfu_regex(slvars.startLoc, slvars2.outputLines)
                    msg = msg
                    if 'slvars' in globals(): sprint(RelocationStackError(msg))
                    raise RelocationStackError(msg)
                if slvars.minSp < 0:
                    msg = ("0x%x: Function has positive stack offset, please fix. %s, %s" % (slvars.startLoc, slvars.minSp, slvars.maxSp))
                    sprint(msg)
                    if regexPatch:
                        obfu_regex(slvars2.outputLines)
                    msg = msg
                    if 'slvars' in globals(): sprint(RelocationStackError(msg))
                    raise RelocationStackError(msg)
                if not len(rs):
                    msg = ("0x%x: Function has no retrn. TODO" % slvars.startLoc)
                    sprint(msg)
                    msg = msg
                    if 'slvars' in globals(): sprint(RelocationTerminalError(msg))
                    raise RelocationTerminalError(msg)

            if noJunk:
                pattern = r'^(\s+jmp (\w+).*\n\2:)'
                # s = re.sub(pattern, r';\U\1', s, 0, re.MULTILINE | re.IGNORECASE)
                s = re.sub(pattern, r';\1', s, 0, re.MULTILINE | re.IGNORECASE)

            if not showComments:
                pattern = r'^(\s+nop).*'
                s = re.sub(pattern, r';\1', s, 0, re.MULTILINE | re.IGNORECASE)

            #  re_labeluse = r'^.+(##LABEL##)'

            labelSet = set()
            #  labelUsed = set()
            # re_labels = r'^(\w[a-zA-Z0-9_:]+):'
            re_labels = r'^(\w+):'  # [a-zA-Z0-9_:]+):'
            matches = re.finditer(re_labels, s, re.MULTILINE)
            for matchNum, match in enumerate(matches, start=1):
                labelSet.add(match.group(1))

            if debug: sprint("labelSet: %s" % labelSet)

            for label in labelSet:
                loc = idc.get_name_ea_simple(label)
                if loc == BADADDR:
                    printi("Couldn't get address for label '{}'".format(label))
                    if 'slvars' in globals(): sprint(RelocationAssemblerError("Couldn't get address for label '{}'".format(label)))
                    raise RelocationAssemblerError()
                    # this shouldn't be needed if we are outputting valid labels
                    loc = LocByName(label.replace('__', '::', 1))
                    if loc == BADADDR:
                        printi("0x%x: Can't find label %s" % (slvars.startLoc, label))
                        msg = "No message"
                        if 'slvars' in globals(): sprint(RelocationAssemblerError(msg))
                        raise RelocationAssemblerError(msg)
                s = re.sub("0x%x" % loc, label, s, 0, re.IGNORECASE)
                # we can remove this label from the list of labels we need to replace
                global name_addr_map
                if label in name_addr_map:
                    del name_addr_map[label]


            s = re.sub(r';.*', '', s, 0, re.MULTILINE)
            s = re.sub(r'\s+$', '', s, 0, re.MULTILINE)
            s = re.sub(r'^$\n', '', s, 0, re.MULTILINE)

            #  sprint("Labels: %s" % labelUsed)

            printi("---[b4good]---")
            printi(s)

            good = "\n".join(relocPrefix)
            pattern = r'^((?:\w[^ ]+:\n)+)((?:\t.*\n)*)'
            matches = re.finditer(pattern, s + "\n", re.MULTILINE)
            labelParse = set()
            for matchNum, match in enumerate(matches, start=1):
                labels = [x.strip(':') for x in match.group(1).splitlines()]
                seen = False
                lastLabel = ""
                for label in labels:
                    lastLabel = label
                    if label in labelParse:
                        seen = True
                    else:
                        labelParse.add(label)
                        good += label + ":\n"

                if not seen:
                    good += s[match.start(2):match.end(2)]
                else:
                    good += "\tjmp " + lastLabel + "\n"

            if relabel:
                labelCount = 0
                for label in labelParse:
                    if label.startswith("loc_"):
                        good = good.replace(label, "label{}".format(labelCount))
                        labelCount += 1

                # sprint(("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group())))

                # for groupNum in range(0, len(match.groups())+1):
                #   sprint(("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum))))

            s = good + "\n"
            #  printi("---[aftergood]---")
            printi(s)
            printi("---[end]---")

            if noJunk:
                regex = r"^\s+jmp (\w+)\n\1:"
                s = re.sub(regex, r'\1:', s, 0, re.MULTILINE | re.IGNORECASE)

            if not silent:
                printi("---[after_jmp_removal]---")
                printi(s)
                printi("---[end]---")

            if vimedit:
                s = VimEdit(ea, s, wait=1)
            else:
                origin = LocByName("next_relocation")

            # disabling this until we remove the labels that shouldn't be translated
            # (think this should be fixed now)
            if 1:
                #  global name_addr_map
                for name_v, slvars.name, loc in name_addr_map.values():
                    printi("Replacing" + re.escape(name_v) + "with" + str(loc))
                    s = re.sub("(?<=[^\w]){}(?=[^:\w])".format(re.escape(name_v)), hex(loc).rstrip('L'), s)

            retry = 1
            while retry:
                retry = 0
                printi("Assembling " + hex(origin))
                # this will have to be changed to a new function
                raise RuntimeError("out of date code")
                happy, o = NasmAssemble(origin, s, Name(slvars.startLoc))
                if happy:
                    name_addr_map.clear()
                else:
                    sprint("Error compiling: %s" % o)
                    for sym in re.findall(r"undefined symbol `([^']+)", o["output"]):
                        repl = hex(idc.get_name_ea_simple(sym)).rstrip('L')
                        printi("Replacing " + sym + re.escape(sym) + "with" + repl)
                        s = re.sub("(?<=[^\w]){}(?=[^\w])".format(re.escape(sym)), repl, s)
                        retry = 1
                        continue

                    if not retry:
                        msg = "No message"
                        if 'slvars' in globals(): sprint(RelocationAssemblerError(msg))
                        raise RelocationAssemblerError(msg)
            sprint("Happy")
            if happy and type(o) is bytearray and len(o):
                length = len(o)
                lengthPlus = (length + 0x200) & 0xffffffffffffff00
                if debug: sprint("got %i bytes from assembler" % length)
                fnEnd = origin + length
                nextRelocation = origin + lengthPlus
                for i in range(lengthPlus):
                    ida_bytes.revert_byte(origin + i)
                MyMakeUnknown(origin, lengthPlus, DELIT_DELNAMES | DOUNK_NOTRUNC)
                #  PatchBytes(origin, [0x00] * (lengthPlus) )
                #  analyze(origin, origin + lengthPlus)
                globals()['o'] = o
                PatchBytes(origin, o)
                forceAllAsCode(origin, length)
                #  analyze(origin, origin + length)
                if not MyMakeFunction(origin, origin + length, noMakeFunction):
                    sprint("couldn't make function at 0x%x" % origin)
                    msg = "couldn't make function at 0x%x" % origin
                    if 'slvars' in globals(): sprint(RelocationAssemblerError(msg))
                    raise RelocationAssemblerError(msg)

                #  slowtrace2(origin, silent=1, modify=0)

                if not vimedit:
                    if not MakeNameEx(origin, reloc_name(slvars.startLoc), idc.SN_NOWARN):
                        sprint("Couldn't set slvars.name %s at 0x%x" % (reloc_name(slvars.startLoc), origin))
                        PatchBytes(origin, [0xCC] * (1 + length))
                        msg = reloc_name(slvars.startLoc)
                        if 'slvars' in globals(): sprint(RelocationDupeError(msg))
                        raise RelocationDupeError(msg)
                    gap = nextRelocation - fnEnd
                    if gap:
                        MakeAlign(fnEnd, gap, 0)

                if vimedit:
                    return

                LabelAddressPlus(nextRelocation, "next_relocation", force=1)
                if LocByName("next_relocation") != nextRelocation:
                    msg = "next relocation was put down wrong"
                    if 'slvars' in globals(): sprint(Exception(msg))
                    raise Exception(msg)
                sprint("Wrote %i bytes to 0x%x from 0x%x" % (length, origin, slvars.startLoc))
                c = Commenter(origin, "func")
                c.add("relocated from {} at 0x{:x}".format(idc.get_func_name(slvars.startLoc), slvars.startLoc))
                if adjustCallers:
                    for ea in set(slvars.startLoc, slvars.realStartLoc):
                        Commenter(ea, 'line', repeatable=1).add('[RELOCED:{}]'.format(idc.get_name(origin)))
                        fix_links_to_reloc(ea, origin)

                msg = GetFunctionName(origin)
                if 'slvars' in globals(): sprint(RelocationDupeError(msg))
                raise RelocationDupeError(msg)
            else:
                sprint("Error compiling (unknown)")
                if 'slvars' in globals(): sprint(RelocationAssemblerError)
                raise RelocationAssemblerError

        if not slvars.retSps:
            msg = "Function ended without RETN"
            if 'slvars' in globals(): sprint(RelocationInvalidStackError(msg))
            raise RelocationInvalidStackError(msg)

        rv = _.reduce(list(slvars.retSps), lambda memo, value, index: memo + abs(value), 0)
        if debug: sprint("slowtrace2 returning: {} ({})".format(rv, type(rv)))
        if rv == 0:
            for addr in later_pending:
                if addr not in later2:
                    later.add(addr)
                    later2.add(addr)
            #  later = later.union(later_pending)
            #  later2 = later2.union(later_pending)
        if rv == 0 or forceRemoveChunks:
            _chunks = [x for x in idautils.Chunks(slvars.startLoc)]
            chunks = GenericRanger([GenericRange(x[0], trend=x[1])           for x in _chunks],            sort = 1)
            keep   = GenericRanger([GenericRange(a, trend=a + GetInsnLen(a)) for a in slvars.justVisited], sort = 1)
            if debug: sprint("chunks: {}".format(keep))
            if debug: sprint("keep: {}".format(keep))
            remove = difference(chunks, keep)
            if debug:
                sprint("remove: {}".format(remove))
                globals()["_keep"] = keep
                globals()["_remove"] = remove
                globals()["__chunks"] = _chunks
                globals()["_chunks"] = chunks
                for ea1, ea2 in [x.chunk() for x in remove]:
                    sprint("remove: {:x}-{:x}".format(ea1, ea2))

            modify_chunks(slvars.startLoc, chunks, keep, remove)



        return rv
    return patches


def fasttrace(ea=None, reloc=0, silent=1):
    pass



def TraceAllFunctions():
    for ea in idautils.Functions():
        fnName = GetFunctionName(ea)
        if SegName(ea) == '.text':
            start = traceBackwards(ea)
            refs = list(idautils.CodeRefsTo(ea, flow=0))
            if refs:
                # printi("Tracing %s" % fnName)
                slowtrace2(ea, "/dev/null", 20)
            else:
                # printi("Ignoring function %s, no CodeRefsTo." % fnName)
                pass



def retrace_native_registration():
    for ea in AllRefsTo(idc.get_name_ea_simple('register_impl'))['allRefs']:
        # retraced sections will have function names starting with _
        # skip them
        if ea > 0x140000000 and not GetTrueName(ea).startswith('_'):
            ForceFunction(ea+5)
            try:
                retrace(ea+5, silent=1, noObfu=1)
            except:
                pass
            printi("retrace_native_registration" + hex(ea))

def retrace_native_registration_2(l = None):
    if l is None:
        l = [
        0x140CD9C70,
        0x140D73144,
        0x140CE0D44,
        0x140A89768,
        0x140CEA9DC,
        0x140D80494,
        0x140A8719C,
        0x140CE3090,
        0x140A8EC74,
        0x140A8B88C,
        0x140D12134,
        0x140CE226C,
        0x140A8EEE0,
        0x140D1298C,
        0x140CE877C,
        0x140CE8114,
        0x140A8CC54,
        0x140D77AAC,
        0x140D813C0,
        0x140D129FC,
        0x140D76AB4,
        0x140D737A0,
        0x140CD9914,
        0x140CE28D4,
        0x140D12738,
        0x140A8C1C8,
        0x140A8CAD4,
        0x140A8BAB4,
        0x140D742B0,
        0x140D73620,
        0x140CEA790,
        0x140A8E62C,
        0x140A898E8,
        0x140D7A2C4,
        0x140D12874,
        0x140A8E468,
        0x140D802F4,
        0x140D154A8,
        0x140A8C964,
        0x140D0DE3C,
    ]
    for ea in l:
        # retraced sections will have function names starting with _
        # skip them
        if ea > 0x140000000 and ea < BADADDR and not GetTrueName(ea).startswith('_'):
            ZeroFunction(ea)
            ea = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(ea))[0]
            fnLoc = idc.get_operand_value(ea + 4, 1)
            fnName = idc.get_name(fnLoc)
            namespace = string_between('', '::', fnName) or string_between('', '__', fnName)
            if namespace:
                LabelAddressPlus(ea, 'register_namespace_%s' % namespace.lower())
            # retrace(ea, silent=1, noObfu=1)
            # reloc(ea)
            printi("retrace_native_registration_2" + hex(ea))


def retrace_native_registration_1365():
    l = [
        0x140CC6C54,
        0x140D1FC58,
        0x140CCB3A4,
        0x140A75A00,
        0x140CD1648,
        0x140D27C58,
        0x140A742B8,
        0x140CCC910,
        0x140A78F04,
        0x140A76EC8,
        0x140A7DB44,
        0x140CCBFF8,
        0x140A79084,
        0x140A7E044,
        0x140CD0078,
        0x140CCFC7C,
        0x140A77B50,
        0x140D22798,
        0x140D285EC,
        0x140A7E090,
        0x140D21D80,
        0x140D2008C,
        0x140A74438,
        0x140CC6A24,
        0x140CCC420,
        0x140A7DEBC,
        0x140A774B0,
        0x140A77A6C,
        0x140A77030,
        0x140D207B8,
        0x140D1FF90,
        0x140CD14C8,
        0x140A78BB8,
        0x140A75AFC,
        0x140D24078,
        0x140A7DF8C,
        0x140A78A90,
        0x140D27B48,
        0x140A7FB80,
        0x140CC6FF8,
        0x140A7795C,
        0x140A7B0F4
    ]
    retrace_native_registration_2(l)


def retrace_all():
    refresh_start()
    TruncateThunks()
    FixAllChunks()
    refresh_natives()
    check_pdata(label=1, func=1, color=1)
    globals()['m'] = m
    retrace_list(m)
    idc.save_database('')
    for ea in m:
        UnpatchFunc(ea)
    retrace_list(m)
    idc.save_database('')
    refresh_natives()
    check_pdata(label=1)
    globals()['l'] = l
    retrace_list(l)
    idc.save_database('')
    for ea in l:
        UnpatchFunc(ea)
    retrace_list(l)
    idc.save_database('')
    refresh_natives()
    check_pdata(func=0, color=1, label=1)
    check_pdata(tails=1)
    # check_pdata()


# store default arguments for slowtrace2
try:
    r2 = inspect.getfullargspec(slowtrace2)
    slowtrace2.defaults = zip(r2[0], r2[3])
except AttributeError:
    r2 = inspect.getargspec(slowtrace2)
    slowtrace2.defaults = zip(r2[0], r2[3])

idc.set_inf_attr(INF_AF, 0xdfe6300d)

if getglobal('refresh_obfu', None):
    refresh_obfu()

"""
for ea in a[:]:
    if 'RemoveVectoredExceptionHandler' in ' '.join([x[1] for x in all_xrefs_from(ea)]):
        a.remove(ea)
retrace_list(a, redux=1)
"""

