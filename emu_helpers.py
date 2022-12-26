# pip install distorm3 string-between

import pickle, os
import idc, idaapi, ida_ida, ida_funcs, ida_bytes, idautils
from bisect import bisect_left, bisect_right, bisect
from collections import defaultdict
from hashwords import words_to_long, long_to_words
# _from('underscore import _')
#  try:
    #  from mergedeep import merge, Strategy
#  except ModuleNotFoundError:
    #  raise ModuleNotFoundError("pip install mergedeep")

import lzma
import re
from glob import glob
execfile('superglobals')

try:
    from exectools import execfile, make_refresh
    refresh_emu_helpers = make_refresh(os.path.abspath(__file__))
    refresh = make_refresh(os.path.abspath(__file__))
except ModuleNotFoundError:
    pass

try:
    from string_between import string_between_splice, string_between
except ModuleNotFoundError:
    print("please run: pip install string-between distorm3")
    raise ModuleNotFoundError('string-between')

from choose_multi import *
# from di import diInsns, MyGetInstructionLength
# from file_get_contents import *

def unhashword(fn):
    if isinstance(fn, int):
        return "{:x}".format(fn)
    return re.sub(r'\b([a-z]+_[a-z_]+[a-z]+)\b', lambda match: "{:x}".format(ida_ida.cvar.inf.min_ea + words_to_long(match.group(1))), fn)

def file_get_contents_bin_spread(fn):
    fn = smart_path(fn)
    if fn.endswith('.bin'):
        if not file_exists(fn) and not re.match(r'/\d\d/\d\d/', fn):
            fn = spread_filename(fn)
    if not file_exists(fn):
        return None
    return open(fn, 'rb').read()

def parseHex(string, _default = None):
    if string.startswith('0x'):
        string = string[2:]
    #  string = string.lstrip('0x')
    if not string:
        print('empty string')
    try:
        return int(string, 16)
    except ValueError:
        print("ValueError: parseHex: {}".format(string))
        raise

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


def get_name_by_any(address):
    """
    returns the name of an address (and if address is
    a string, looks up address of string first).

    an easy way to accept either address or name as input.
    """

    if address is None:
        return 'None'
    if not isinstance(address, int):
        address = eax(address)
    #  if isinstance(address, str):
        #  address = idc.get_name(idc.get_name_ea_simple(address))
    r = idc.get_name(address)
    if not r:
        return hex(address)
    return r


def eax(*args):
    return get_ea_by_any(*args)

class _MyChoose(idaapi.Choose):
    def __init__(self, items, title, cols, icon=-1):
        idaapi.Choose.__init__(self, title, cols, flags=idaapi.Choose.CH_MODAL | idaapi.Choose.CH_MULTI, icon=icon)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


def differences(a, b):
    if len(a) != len(b):
        raise ValueError("Lists of different length.")
    return sum(i != j for i, j in zip(a, b))

def unpatch_emu_glob(*args, **kwargs):
    r = read_emu_glob(*args, **kwargs, dryRun=1, trim=False)
    if isIterable(args[0]):
        r = _.flatten(r, 1)
    for ea1, ea2 in [(x[0], x[0] + x[1][1]) for x in r if x[1][1]]:
        print('unpatching {:#x} - {:#x} {}'.format(ea1, ea2, diida(ea1, ea2)))
        unpatch(ea1, ea2)

def read_emu_glob(fn, subdir='*', path=None, **kwargs):
    if path is None and match_emu._path is None:
        guess = os.path.abspath(os.path.dirname(get_idb_path()))
        print("Guessing database path as {}".format(guess))
        path = guess

    if path is not None:
        match_emu._files.clear()
        emu_path(path)

    if isinstance(fn, list):
        return _.flatten([read_emu_glob(x, subdir=subdir, **kwargs) for x in fn], 1)

    if not match_emu._path:
        print("No path set")
        return

    uhw = unhashword(fn)
    try:
        if ida_ida.cvar.inf.min_ea <= int(uhw, 16) < ida_ida.cvar.inf.max_ea:
            fn = '*_{}*'.format(uhw)
    except ValueError:
        raise
        pass
    try:
        fns = os.path.normpath(os.path.join(match_emu._path, subdir, '*', '*', fn))
    except TypeError as e:
        print("{}: {}: {}".format(e.__class__.__name__, str(e), str([match_emu._path, subdir, '*', '*', fn])))
        raise
    globbed = list(glob(fns))
    print('globbed {} files. kwargs: {}'.format(len(globbed), kwargs))
    return [x for x in read_emu(globbed, **kwargs) if x[1][1] > 0]

def make_native_patchfile(ea=None, outFilename=None, noImport=False, width=76):
    import base64
    """ 
    eg: read_emu(glob('r:/data/memcpy/*_PackerFunction_140000000.bin'))

    @param fn: filename or [fn1, fn2, ...]

    """
    if not noImport:
        result = [
                "def base64_patch_tmp():",
                "    import idc, ida_ida, idautils, idaapi",
                "    from base64 import b64decode as b",
                "    from ida_bytes import put_bytes, patch_bytes",
                "    from lzma import decompress as d",
                "    chunks = []",
                "    def expand_chunklist(c):",
                "        l = iter(c); x = unbase(next(l)); yield (x[0], x[0] + x[1]); j, k = x",
                "        for x in [unbase(x) for x in l]:",
                "            x = (x[0] + j, x[0] + j + x[1])",
                "            j, k = x; yield x",
                "    def nativ(ea, lbl, c):",
                "        ea = unbase(ea); lbl = re.sub(r'\s+', '_', lbl)",
                "        base64_patch_tmp.ea = ea",
                "        print(\"{:#x} {}\".format(ea, lbl))",
                "        chunks.clear(); chunks.extend(list(expand_chunklist(c)))",
                "        for cs, ce in chunks:",
                "            for head in idautils.Heads(cs, ce):",
                "                if cs != ea: idc.remove_fchunk(head, head)",
                "            idaapi.del_items(cs, 1, ce - cs)",
                "        idc.del_func(ea)",
                "        idc.set_name(ea, lbl, idc.SN_NOWARN)",
                "    def fspd(l):",
                "        def fsc(l):",
                "            l.sort()",
                "            for i, x in enumerate(l):",
                "                csp, asp, ad = x[1], idc.get_spd(",
                "                        x[0]), idc.get_sp_delta(x[0])",
                "                if asp is None or ad is None: return",
                "                adj = csp - asp; nd = adj + ad",
                "                if asp != csp:",
                "                    print(\"{:4} -- {:x} adjspd {:6x} to {:6x}     \"",
                "                            \"({:>6x})\".format(i, x[0], ad, nd, csp))",
                "                    idc.add_user_stkpnt(x[0], nd)",
                "                    idc.auto_wait(); return True",
                "        ea = l[0][0]; [idc.create_insn(x) for x, y in l]; idc.add_func(ea)",
                "        [idc.append_func_tail(ea, cs, ce) for cs, ce in chunks[1:]]",
                "        for r in range(1000):",
                "            if not fsc(l): break",
                "    def expand_spdlist(c):",
                "        l = iter(c); x = next(l); yield tuple(unbase(x))",
                "        j, k = unbase(x)",
                "        for x in [unbase(x) for x in l]: x = (x[0] + j, x[1] + k); j, k = x; yield x",
                "    def spds(l): fspd(list(expand_spdlist(l)))",
                "    min_ea = ida_ida.cvar.inf.min_ea & ~0xffff",
                "    max_ea = (ida_ida.cvar.inf.max_ea + 1) & ~0xffff",
                "    def unbase(a):",
                "        if isinstance(a, int): a = [a]",
                "        if len(a) > 1: return [ea - {:#x} + min_ea for ea in a]".format(ida_ida.cvar.inf.min_ea),
                "        else: return a[0] - {:#x} + min_ea".format(ida_ida.cvar.inf.min_ea),
                "    put64  = lambda ea, b64: patch_bytes(unbase(ea), b(b64))",
                "    lzp64  = lambda ea, b64: patch_bytes(unbase(ea), d(b(b64)))",
                "    cmt64  = lambda ea, b64: idc.set_func_cmt(unbase(ea), b(b64).decode('utf-8'), 0)",
                "    lzc64  = lambda ea, b64: idc.set_func_cmt(unbase(ea), d(b(b64)).decode('utf-8'), 0)",
                "",
                ]
    else:
        result = []
    

    if not noImport and not isinstance(ea, list):
        ea = [ea]
    if isinstance(ea, list):
        [ result.extend(make_native_patchfile(x, noImport=1, width=width)) for x in ea if IsFuncHead(x) ]
        result.extend([
            "",
            "base64_patch_tmp()"
            ])
        if outFilename:
            return file_put_contents(outFilename, "\n".join(result))
        return result

    bout = ('    nativ(0x{:x}, """{}""", {})'.format(ea, idc.get_name(ea, 0).replace('_', ' '), re.sub(r'\d\d+', lambda m: hex(m[0]) if len(hex(m[0])) <= (1 + len(m[0])) else m[0], str(list(compact_chunklist(idautils.Chunks(ea))))).replace("'", '').replace("'", "")))
    result.extend(indent(8, bout, width=width, joinWith=None, skipFirst=False, firstIndent=0))
    for base, end in idautils.Chunks(ea):
        b = ida_bytes.get_bytes(base, end - base)
        cmd = 'put64'
        if len(b) > 96:
            c = lzma.compress(b)
            if len(c) < len(b):
                b = c
                cmd = 'lzp64'
        if b:
            b64 = base64.b64encode(b).decode('raw_unicode_escape')
            if len(b64) < (width - 22 - 4):
                bout = '    {}(0x{:x}, "{}")'.format(cmd, base, b64)
                result.append(bout)
            else:
                bout = '    {}(0x{:x}, """'.format(cmd, base) + b64
                bout = indent(8, bout, width=width, joinWith=None, skipFirst=True)
                result.extend(bout)
                if len(result[-1]) < (width - 3 - 4):
                    result[-1] += '""")'
                else:
                    result.append('        """)')
            #  result.append('')

            bout = '    spds({})'.format(re.sub(r'\d\d+', lambda m: hex(m[0]) if len(hex(m[0])) <= (1 + len(m[0])) else m[0], str(list(compact_spdlist(GetAllSpds(ea, address=1)))).replace("'", "")))
    result.extend(indent(8, bout, width=width, joinWith=None, skipFirst=False, firstIndent=0))

    b = idc.get_func_cmt(ea, 0)
    if b:
        b = asBytes(b)
        cmd = 'cmt64'
        if len(b) > 32:
            c = lzma.compress(b)
            if len(c) < len(b):
                b = c
                cmd = 'lzc64'
        b64 = base64.b64encode(b).decode('raw_unicode_escape')
        if len(b64) < (width - 22 - 4):
            bout = '    {}(0x{:x}, "{}")'.format(cmd, base, b64)
            result.append(bout)
        else:
            bout = '    {}(0x{:x}, """'.format(cmd, base) + b64
            bout = indent(8, bout, width=width, joinWith=None, skipFirst=True)
            result.extend(bout)
            if len(result[-1]) < (width - 3 - 4):
                result[-1] += '""")'
            else:
                result.append('        """)')
    return result 

def make_emu_patchfile(fn=None, outFilename=None, noImport=False, width=76):
    import base64
    """ 
    eg: read_emu(glob('r:/data/memcpy/*_PackerFunction_140000000.bin'))

    @param fn: filename or [fn1, fn2, ...]

    """
    if not noImport:
        result = [
                "def base64_patch_tmp():",
                "    from base64 import b64decode", 
                "    from ida_bytes import put_bytes",
                "    from lzma import decompress",
                "    min_ea = ida_ida.cvar.inf.min_ea & ~0xffff",
                "    max_ea = (ida_ida.cvar.inf.max_ea + 1) & ~0xffff",
                "    unbase = lambda ea: ea - ida_ida.cvar.inf.min_ea + min_ea",
                "    put64 = lambda ea, b64: put_bytes(unbase(ea), b64decode(b64))",
                "    lzp64 = lambda ea, b64: put_bytes(unbase(ea), decompress(b64decode(b64)))",
                ""
                ]
    else:
        result = []
    

    if not noImport and not isinstance(fn, list):
        fn = [fn]
    if isinstance(fn, list):
        [ result.extend(make_emu_patchfile(x, noImport=1, width=width)) for x in fn ]
        result.extend([
            "",
            "base64_patch_tmp()"
            ])
        if outFilename:
            return file_put_contents(outFilename, "\n".join(result))
        return result


    base = parseHex(string_between('_', '_', os.path.basename(fn)))
    if base > ida_ida.cvar.inf.min_ea and base < ida_ida.cvar.inf.max_ea:
        b = file_get_contents_bin_spread(fn)
        cmd = 'put64'
        if len(b) > 128:
            b = lzma.compress(b)
            cmd = 'lzp64'
        if b:
            b64 = base64.b64encode(b).decode('raw_unicode_escape')
            if len(b64) < (width - 22 - 4):
                bout = '    {}(0x{:x}, "{}")'.format(cmd, base, b64)
                result.append(bout)
            else:
                bout = '    {}(0x{:x}, """'.format(cmd, base) + b64
                bout = indent(8, bout, width=width, joinWith=None, skipFirst=True)
                result.extend(bout)
                if len(result[-1]) < (width - 3 - 4):
                    result[-1] += '""")'
                else:
                    result.append('        """)')
            #  result.append('')

    return result 

def read_emu_walk(path):
    for root, dirs, files in os.walk(path):
        for _file in files:
            if _file.endswith('.bin'):
                _fnb = os.path.join(root, _file)
                print(_fnb)
                read_emu(_fnb)

def compare_bytes(ea, buf):
    """
    Return the specified number of bytes that differ from the buffer

    @param ea: linear address

    @param buf: (C++: const void *) buffer with new values of bytes

    @return: count of differing bytes
    """
    if isinstance(ea, list):
        return [compare_bytes(x) for x in ea]

    ea = eax(ea)
    b = idc.get_bytes(ea, len(buf))
    count = 0
    for i in range(len(buf)):
        if b[i] != buf[i]:
            count += 1

    return count
    
def make_all_patchfile(outFilename=None, noImport=False, width=76):
    import base64
    """ 
    @param outFilename: filename or [fn1, fn2, ...]
    """
    if not noImport:
        result = [
                "def base64_patch_tmp():",
                "    import idc, ida_ida, idautils, idaapi, pickle",
                "    from base64 import b64decode as b",
                "    from ida_bytes import put_bytes, patch_bytes",
                "    from lzma import decompress as d",
                "    min_ea = ida_ida.cvar.inf.min_ea & ~0xffff",
                "    max_ea = (ida_ida.cvar.inf.max_ea + 1) & ~0xffff",
                "    def unbase(a):",
                "        if isinstance(a, int): a = [a]",
                "        if len(a) > 1: return [ea - {:#x} + min_ea for ea in a]".format(ida_ida.cvar.inf.min_ea),
                "        else: return a[0] - {:#x} + min_ea".format(ida_ida.cvar.inf.min_ea),
                "    def lzp64(b64):",
                "        for ea, p in pickle.loads(d(b(b64))).items():",
                "            patch_bytes(unbase(ea), bytes(p))"
                "",
                ]
    else:
        result = []
    
    p = get_patches()
    b = pickle.dumps(p)
    c = lzma.compress(b)
    b = c
    cmd = 'lzp64'
    if b:
        b64 = base64.b64encode(b).decode('raw_unicode_escape')
        if len(b64) < (width - 9 - 4):
            bout = '    {}("{}")'.format(cmd, b64)
            result.append(bout)
        else:
            bout = '    {}("""'.format(cmd) + b64
            bout = indent(8, bout, width=width, joinWith=None, skipFirst=True)
            result.extend(bout)
            if len(result[-1]) < (width - 3 - 4):
                result[-1] += '""")'
            else:
                result.append('        """)')
        #  result.append('')

    result.extend([
        "",
        "base64_patch_tmp()"
        ])
    if outFilename:
        return file_put_contents(outFilename, "\n".join(result))
    else:
        return result


@static_vars(_nulls=set())
def read_emu(fn=None, dryRun=False, skipFuncs=False, put=False, trim=True):
    """ 
    read_emu: read a file / list of files into patches
    eg: read_emu(glob('r:/data/memcpy/*_PackerFunction_140000000.bin'))
    fn: ./balance/25/44/written_7ffe0014_4_BalanceFunc_1432ff09a.bin

    @param fn: filename or [fn1, fn2, ...]

    """
    if isinstance(fn, list):
        # print(fn)
        return [(parseHex(string_between('_', '_', os.path.basename(x))), read_emu(x, dryRun=dryRun, skipFuncs=skipFuncs, put=put, trim=trim)) for x in fn]
    base = parseHex(string_between('_', '_', os.path.basename(fn)))

    bn = os.path.basename(fn)
    _prefix       = string_between('', '_', bn)
    _addr,  bn    = string_between_splice('_',   '_', bn, repl='')
    _size, bn     = string_between_splice('__',  '_', bn, repl='')
    _packer, bn   = string_between_splice('___', '.', bn, repl='', greedy=1)
    _packer_addr  = string_between('_', '', _packer) or _packer
    try:
        _packer_words = long_to_words(-ida_ida.cvar.inf.min_ea + int(_packer_addr, 16))
    except ValueError as e:
        # dprint("[read_emu] bn, _prefix, _addr, _size, _packer, _packer_addr")
        print("[read_emu] bn: {}, _prefix: {}, _addr: {}, _size: {}, _packer: {}, _packer_addr: {}".format(bn, _prefix, _addr, _size, _packer, _packer_addr))
        
        raise

    if not IsValidEA(base):
        print("[debug] base: {}".format(ahex(base)))
        return '', -2, -2
    # dprint("[debug] base")
    

    b = file_get_contents_bin_spread(fn)
    if trim and len(b) == 1:
        return '', 0, 0
    if b and len(b) > 3 and _.all(b, lambda v, *a: v == 0):
        print("skipping {} x null".format(len(b)))
        Commenter(base, 'line').add("skipped {} null bytes from {} {}".format(len(b), _packer_words, ean(_packer_addr)))
        read_emu._nulls.add((base, len(b)))
        return '', 0, 0
    if trim and b.endswith(bytes([0, 0, 0])):
        b = b.rstrip(b'\0')
    if not b:
        return '', 0, 0
    if b:
        if trim:
            dec = deCode(b)
            good = bad = 0
            for d in dec:
                if d.rawFlags == 0xffff:
                    bad += 1
                else:
                    good += 1
            total = good + bad
            if (bad / total) > 0.9:
                # TODO: might be multiple offset blocks
                if len(b) == 8 and IsValidEA(struct.unpack('Q', b)):
                    print('not ignoring offset block {:#x} (points to {:#x})'.format(base, struct.unpack('Q', b)))
                else:
                    print('ignoring {:3.0f}% bad block {:#x} (len {} bytes)'.format(100 * bad / total, base, len(b)))
                    return '', 0, 0
        #  if rv:
            #  idc.jumpto(base)

        #  if b[0] == 0 and _.sum(b) == 0:
            #  return fn.split('_', 3)[3], len(b), -1
        #  o = idc.get_bytes(base, len(b))
        #  diffs = differences(o, b)
        #  if diffs:
        #  _was_code = IsCode_(base)
        Commenter(base, 'line').add("{}: {:#x}-{:#x}".format(_packer_words, base, base + len(b)))
        differ = compare_bytes(base, b)
        if dryRun:
            return fn.split('_', 3)[3], len(b), differ
            # iccode(b, base)
        else:
            if skipFuncs and IsFunc_(base):
                if debug: print("skipping func at {:#x}".format(base))
            else:
                if debug: 
                    if skipFuncs:
                        print("not func at {:#x}".format(base))
                    else:
                        print("nobody asked us to skip")
                if put or differ:
                    if put:
                        # print("putting {} bytes at {:#x}".format(len(b), base))
                        ida_bytes.put_bytes(base, b)
                    else:
                        ida_bytes.patch_bytes(base, b)
            return fn.split('_', 3)[3], len(b), differ

    # return base, len(b), differ # diffs
    return fn.split('_', 3)[3], len(b), differ

def read_emu_fn_split(fn):
    bn = os.path.basename(fn)
    _prefix       = string_between('', '_', bn)
    _addr,  bn    = string_between_splice('_',   '_', bn, repl='')
    _size, bn     = string_between_splice('__',  '_', bn, repl='')
    _packer, bn   = string_between_splice('___', '.', bn, repl='', greedy=1)
    _packer_addr  = string_between('_', '', _packer)
    _packer_words = long_to_words(-ida_ida.cvar.inf.min_ea + int(_packer_addr, 16))
    return SimpleAttrDict(
            prefix = _prefix,
            addr = _addr,
            size = _size,
            packer = _packer,
            packer_addr = _packer_addr,
            packer_words = _packer_words
    )

def read_emu_id(fn=None, nulls=None, patches=None):
    """ 
    read_emu_id: attempt to uniquely identify a patch file(s)
    eg: read_emu_id(glob('r:/data/memcpy/*_PackerFunction_140000000.bin'))

    @param fn: filename or [fn1, fn2, ...]

    """
    patches = A(patches)
    nulls = A(nulls)
    if isinstance(fn, list):
        # print(fn)
        [read_emu_id(x, nulls=nulls, patches=patches) for x in fn]
        return

    base = parseHex(string_between('_', '_', os.path.basename(fn)))

    bn = os.path.basename(fn)
    _prefix       = string_between('', '_', bn)
    _addr,  bn    = string_between_splice('_',   '_', bn, repl='')
    _size, bn     = string_between_splice('__',  '_', bn, repl='')
    _packer, bn   = string_between_splice('___', '.', bn, repl='', greedy=1)
    _packer_addr  = string_between('_', '', _packer)
    _packer_words = long_to_words(-ida_ida.cvar.inf.min_ea + int(_packer_addr, 16))

    nulls = []
    if ida_ida.cvar.inf.min_ea <= base < ida_ida.cvar.inf.max_ea:
        b = file_get_contents_bin_spread(fn)
        if b and len(b) > 3 and _.all(b, lambda v, *a: v == 0):
            nulls.append(len(b))
        elif b:
            patches.append(b)

def read_emu_id_walk(subdir='balance', path=None):
    work = defaultdict(list)
    for root, dirs, files in os.walk(os.path.join(match_emu._path, subdir) if path is None else path):
        for _file in files:
            if _file.endswith('.bin'):
                _fnb = os.path.join(root, _file)
                _spl = read_emu_fn_split(_fnb)
                work[_spl.packer_words].append(_fnb)

    results = []
    for ofn, files in work.items():
        nulls = []
        patches = []
        # dprint("[read_emu_id_walk] ofn, files")
        #  print("[read_emu_id_walk] ofn:{}, files:{}".format(ofn, files))
        
        read_emu_id(files, nulls=nulls, patches=patches)
        v = (_.sort(_.filter([di_generic(p) for p in patches])))
        print("{}: {}; {}".format(ofn.strip('*_'), '', v))
        #  for p in patches:
            # v = _.uniq(_.sort([hash(di_generic(x)) & 0xffffffffffffffff for x in p]))
            # v = patches
        results.append((ofn, v))
    return results

def read_emu_id_match(_a, _b):
    a = _a.copy()
    b = _b.copy()
    b = _.filter(b, lambda v: v[1])
    old = _.object(a)
    new = _.object(b)
    del a
    del b
    best_matches = dict()
    for ka, a in old.items():
        best_match = None, 0, 8**8, -0.01, -1, -1, 99
        matched = unmatched = 0
        lena = len(a)
        for kb, x in new.items():
            b = x.copy()
            lenb = len(b)
            lendiff = abs((lena / lenb) - 1.0)
            for aa in a:
                if aa in b:
                    b.remove(aa)
                    matched += 1
                else:
                    unmatched += 1
                
            total = matched + unmatched
            match_percent = matched / total
            if lendiff < best_match[6] or lendiff == best_match[6] and match_percent > best_match[3]:
                best_match = kb, matched, unmatched, match_percent, lena, lenb, lendiff
        best_matches[ka] = best_match

    return best_matches



def read_emu_id_glob(fn, subdir='*', path=None, **kwargs):
    if path is None and match_emu._path is None:
        guess = os.path.abspath(os.path.dirname(get_idb_path()))
        print("Guessing database path as {}".format(guess))
        path = guess

    if path is not None:
        match_emu._files.clear()
        emu_path(path)

    if isinstance(fn, list):
        return [read_emu_id_glob(x, subdir=subdir, **kwargs) for x in fn]

    if not match_emu._path:
        print("No path set")
        return

    ofn = fn
    uhw = unhashword(fn)
    try:
        if ida_ida.cvar.inf.min_ea <= int(uhw, 16) < ida_ida.cvar.inf.max_ea:
            fn = '*_{}*'.format(uhw)
    except ValueError:
        raise
        pass
    try:
        fns = os.path.normpath(os.path.join(match_emu._path, subdir, '*', '*', fn))
    except TypeError as e:
        print("{}: {}: {}".format(e.__class__.__name__, str(e), str([match_emu._path, subdir, '*', '*', fn])))
        raise
    globbed = list(glob(fns))
    print('globbed {} files. kwargs: {}'.format(len(globbed), kwargs))
    nulls = []
    patches = []
    read_emu_id(globbed, nulls=nulls, patches=patches)
    v = (_.sort(_.filter([di_generic(p) for p in patches])))
    print("{}: {}; {}".format(ofn.strip('*_'), '', v))
    #  for p in patches:
        # v = _.uniq(_.sort([hash(di_generic(x)) & 0xffffffffffffffff for x in p]))
        # v = patches
    return ofn, v


def emu_path(pn=None):
    if pn is not None:
        match_emu._files.clear()
        match_emu._keys.clear()
        match_emu._path = smart_path(pn)
    return match_emu._path

@static_vars(_files = dict(), _keys = dict(), _path = None, _subdirs = None)
def match_emu(ea=None, size=None, path=None, retnAll=False):
    """
    match_emu: Find possible Packer patches for the given address
    range [ea, ea + size)

    @param ea: start address
    @param size: number of octets to end address
    @param path: root path to packer patch data
    @param retnAll: return all information on each patch
    """

    if match_emu._subdirs is None:
        match_emu._subdirs = [os.path.basename(os.path.dirname(os.path.dirname(p))) for p in glob(os.path.join(os.path.dirname(get_idb_path()), "*", "01", "01"))]

    if path is None and match_emu._path is None:
        guess = os.path.abspath(os.path.dirname(get_idb_path()))
        print("Guessing database path as {}".format(guess))
        path = guess

    if path is not None:
        # if match_emu._path != path:
        match_emu._files.clear()
        path = path.replace("\\", "/")
        print("Saving path {}".format(path))
        match_emu._path = emu_path(path)


    # compile list of files
    if not match_emu._files:
        if path is None:
            raise KeyError("please supply path argument on initial call")
        for subdir in match_emu._subdirs:
            match_emu._files[subdir] = dict()
        match_emu._files["maxsize"] = 0

        min_ea = ida_ida.cvar.inf.min_ea & ~0xffff
        max_ea = (ida_ida.cvar.inf.max_ea + 1) & ~0xffff

        # check if previously compiled list exists
        if not dir_exists(path):
            print("{} is not a path".format(path))
            return

        pickle_fn = "{}/files.pickle".format(path.rstrip('/'))
        if file_exists(pickle_fn):
            _pickle_time = os.stat(os.path.abspath(pickle_fn)).st_mtime
            match_emu._files = pickle.loads(file_get_contents_bin(pickle_fn))
            for _subdir in match_emu._subdirs:
                idc.msg("{}... ".format(_subdir))
                _jfn = "{}/{}/files.json".format(path.rstrip('/'), _subdir)
                if file_exists(_jfn):
                    _jfn_time = os.stat(os.path.abspath(_jfn)).st_mtime
                    if _pickle_time > _jfn_time:
                        continue
                    else:
                        # dprint("[match_emu] _pickle_time, _jfn_time")
                        print("[match_emu] _pickle_time:{}, _jfn_time:{}".format(_pickle_time, _jfn_time))
                        
                    
                    _jfn = json_load(_jfn)
                    #  _jfn = file_get_contents(_jfn)
                    #  _jfn = re.sub(r'"([0-9]+)"', r'\1', _jfn)
                    #  _jfn = json.loads(_jfn)
                    #  _.extendDeep(match_emu._files, _jfn, lambda v, k, a: (int(k) if isIntString(k) else None, None))
                    #  _.extend(match_emu._files, _jfn)
                    for _subdir, v in _jfn.items():
                        match_emu._files[_subdir] = dict()
                        for addr, v2 in v.items():
                            addr = int(addr)
                            match_emu._files[_subdir][addr] = dict()
                            for length, v3 in v2.items():
                                length = int(length)
                                if 'length' not in match_emu._files[_subdir][addr]:
                                    match_emu._files[_subdir][addr][length] = []
                                    #  print(v3)
                                match_emu._files[_subdir][addr][length].extend(v3)
                    #  os.unlink("{}/{}/files.json".format(path.rstrip('/'), _subdir))
                    #  merge(match_emu._files, _jfn, Strategy.ADDITIVE)

        else:
            if True:
                print("database being generated, this only happens once, but may take a few minutes...")
                # generate new list
                counter = 0
                p = ProgressBar(64 * len(match_emu._subdirs))
                for _subdir in match_emu._subdirs:
                    print("{}...".format(_subdir))
                    for level1 in range(64):
                        counter = counter + 1
                        p.update(counter)
                        basepart = os.path.join(path, "{}/{:02}/*/*.bin".format(_subdir, level1))
                        for fn in glob(basepart):
                            bn = os.path.basename(fn)
                            prefix    = string_between('', '_', bn)
                            addr,  bn = string_between_splice('_',   '_', bn, repl='')
                            _size, bn = string_between_splice('__',  '_', bn, repl='')
                            packer, bn = string_between_splice('___', '.', bn, repl='', greedy=1)

                            try:
                                addr = parseHex(addr, 0)
                                _size = parseHex(_size, 0)
                            except ValueError:
                                print("Ignoring file: {} {}".format(escape_c(fn), (prefix, addr, _size, packer, bn)))
                                continue

                            if min_ea <= addr <= max_ea and _size > 0:
                                match_emu._files["maxsize"] = max(match_emu._files["maxsize"], _size)
                                if addr not in match_emu._files[_subdir]:
                                    match_emu._files[_subdir][addr] = defaultdict(list)
                                match_emu._files[_subdir][addr][_size].append((prefix, packer))

        print("pickling files")
        file_put_contents_bin(pickle_fn, pickle.dumps(match_emu._files))

        for _subdir in match_emu._subdirs:
            if _subdir in match_emu._files:
                match_emu._keys[_subdir] = list(match_emu._files[_subdir].keys())
                match_emu._keys[_subdir].sort()

    # don't return results if all we received was a path
    if path is not None and ea is None and size is None:
        return

    ea = eax(ea)
    if ea:
        if size is not None and size > ea:
            size = size - ea
        elif size is None:
            size = MyGetInstructionLength(ea)
    else:
        return

    ea2 = ea + size

    results = dict()
    for _subdir in match_emu._subdirs:
        if not _subdir in match_emu._files:
            continue
        left  = bisect_left(match_emu._keys[_subdir], ea - match_emu._files["maxsize"])
        right = bisect_right(match_emu._keys[_subdir], ea2)
        
        results[_subdir] = []
        for l in match_emu._keys[_subdir][max(0, left - 1):right + 1]:
            for length in match_emu._files[_subdir][l]:
                r = l + length
                if                    \
                        l  < ea2 and  \
                        ea < r:
                    if retnAll:
                        for x in match_emu._files[_subdir][l][length]:
                            results[_subdir].append((l, length, x))
                    else:
                        results[_subdir].extend(match_emu._files[_subdir][l][length])


    return results

@static_vars(chosen=getglobal('emu_helper_check_emu_chosen', [], list, True))
def check_emu(ea=None, size=None, path=None, auto=None, xxd=False):
    """
    check_emu: Find possible Packer patches for the given address
    range [ea, ea + size) and show disassembly

    @param ea: start address
    @param size: number of octets to end address
    @param path: root path to packer patch data
    """

    if isinstance(ea, list):
        return [check_emu(x) for x in ea]

    if ea is None:
        ea, end_ea = get_selection_or_ea()
        size = end_ea - ea
        if size < GetInsnLen(ea):
            size = GetInsnLen(ea)

    results = dict()
    ea = eax(ea)
    res = match_emu(ea, size, path=path, retnAll=True)

    p = []
    p2 = []
    # {'read': 
    #     {0x1446ee605: 
    #         {0xb: [('written', 'CheckFunc_143a6598b')]}}}
    # {
    #     'written':[(0x140017f19, 0x59, ('written', 'XXXX-XXXX2.1-original-fixed_dump.exe'))],
    #     'read':   [(0x140017f30, 0x7,  ('written', 'CheckFunc_143e28478')), (0x140017f30, 0x7, ('written', 'CheckFunc_143e5775f'))],
    #     'memcpy': [(0x140017f30, 0x7,  ('memcpy', 'PackerChecksumActual3_188')), (0x140017f30, 0x7, ('memcpy', 'PackerChecksumActual3_177'))]
    # }
    for _subdir, r in res.items():
        if auto:
            pph(r)
            r = _.filter(r, lambda x, *a: unhashword(auto) in x[2][1] and x[0] <= ea < (x[0] + x[1]))
            if r:
                print("auto: {}".format(pfh(r)))
        results[_subdir] = dict()
        if r:
            for base, length, base_and_fn in r:
                if isinstance(base_and_fn, (tuple, list)):
                    prefix, fn = base_and_fn
                else:
                    print("errant entry: {}".format(base_and_fn))
                    prefix = _subdir
                    fn = fn
                fullfn = '{}/{}/{}_{:x}_{:x}_{}.bin'.format(
                        match_emu._path.rstrip('/'), _subdir, prefix, 
                        base, length, 
                        fn)
                #  print("would check: {}".format(fn))
                #  continue
                try:
                    if xxd:
                        asm = listAsHex(file_get_contents_bin_spread(fullfn)[0:64])
                    else:
                        asm = '; '.join([x[2] for x in diInsns(
                            file_get_contents_bin_spread(fullfn)[0:64], ea=base)])
                        asm = re.sub(r'0x[0-9a-fA-F]{8,}', lambda x, *a: get_name_by_any(x[0]), asm)
                    results[_subdir][asm] = "{:x} - {:x} {} {}".format(base, base + length, fn, asm)
                    fn = re.sub(r'^(?:CheckFunc|BalanceFunc)_([0-9a-fA-F]{9})$', lambda match: long_to_words(-ida_ida.cvar.inf.min_ea + int(match.group(1), 16)), fn)
                    if fn in check_emu.chosen:
                        favourite = '* '
                    else:
                        favourite = ''
                    p.append((_subdir, fn, hex(base), "({}) ".format(length) + hex(base + length), favourite + asm[0:128]))
                    p2.append(fullfn)
                except FileNotFoundError:
                    print("File Not Found: " + fullfn)
                    raise
        
        if debug and results[_subdir]:
            for line in results[_subdir].values():
                print(line)

    if not p:
        return
    if not auto:
        #  p = _.sortBy(p, lambda v, *a: v[1] not in check_emu.chosen)
        variable_chooser = MyChoose(
            p,
            "Select Patch",
            [["Type", 8], ["Function", 25], ["Start", 16], ["End", 16], ["Disassembly", 128]]
        )
        row = variable_chooser.Show(modal=True)
    else:
        row = 0
        b = file_get_contents_bin_spread(p2[row])
        ida_bytes.patch_bytes(eax(p[row][2]), b)
        if 'Commenter' in globals():
            Commenter(eax(p[row][2]), 'line').add("Patched by: " + p[row][1])
        end1 = EaseCode(eax(p[row][2]), forceStart=1)
        end2 = eax(p[row][2]) + len(b)
        return min(end1, end2)


    if row != -1:
        print("Chose {}: {}".format(row, p[row][1]))
        check_emu.chosen.append(p[row][1])

        ida_bytes.patch_bytes(eax(p[row][2]), file_get_contents_bin_spread(p2[row]))
        EaseCode(eax(p[row][2]), forceStart=1)
        if 'Commenter' in globals():
            Commenter(eax(p[row][2]), 'line').add("Patched by: " + p[row][1])
        #  idc.set_cmt(eax(p[row][2]), '\n'.join(idc.get_cmt(eax(p[row][2]), 0).split('\n') + ["Patched by: " + p[row][1]]), False)
        idc.create_insn(eax(p[row][2]))
        if 'EaseCode' in globals():
            try:
                EaseCode(eax(p[row][2]))
            except AdvanceFailure:
                pass


def check_emu_follow(ea=None, auto=None):
    """
    check_emu_follow

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [check_emu_follow(x) for x in ea]

    visited = set()
    ea = eax(ea)
    while ea:
        if ea in visited:
            print("{:x} visited".format(ea))
            return
        visited.add(ea)
        tgt = check_emu(ea, 1, auto=auto)
        if not tgt:
            print("{:x} check_emu returned no matches for {}".format(ea, auto))
            return
        print("{:x} check_emu -> {:x}".format(ea, tgt))
        ea = tgt
        jump(ea - 1)
        tgt = GetTarget(idc.get_item_head(ea - 1))
        if tgt == idc.BADADDR:
            print("{:x} no target".format(ea))
            return
        else:
            print("{:x} target -> {:x}".format(ea, tgt))
        ea = tgt
        print("jumping to {:x}".format(ea))
        jump(ea)

def check_emu_follow_r(r=None, auto=None):
    visited = set()
    for ea in [x[0] for x in r if IsData(x[0]) or IsUnknown(x[0]) or (IsCode_(x[0]) and isUnlikely(x[0]))]: #  or IsTail(x[0])
        jump(ea)
        print("following {:x}".format(ea))
        check_emu_follow(ea=ea, auto=auto)

def comment_emu(funcea=None, path=None):
    """
    comment_emu: Add comments to function chunks that are modified by Packer
    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [comment_emu(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    for cs, ce in idautils.Chunks(funcea): 
        _r = match_emu(cs, ce, path=path)
        for _type, r in _r.items():
            if r:
                comments = []
                for fn in r:
                    comments.append("{:x} - {:x} {} by {}".format(cs, ce, _type, fn))
                if comments:
                    idc.set_cmt(cs, '\n'.join(idc.get_cmt(cs, 0).split('\n') + comments), False)

class jenkins:
    def __init__(self, seed):
        self.hash = seed


    def update_bytes(self, data):
        result = self.hash

        for value in data:
            result = (result + value) * 1025 & 0xFFFFFFFF
            result = (result >> 6 ^ result)

        self.hash = result


    def update_string(self, string):
        self.update_bytes(string.encode('utf-8'))


    def update_lower(self, string):
        self.update_string(string.lower())


    def digest(self):
        result = self.hash

        result = (result * 9) & 0xFFFFFFFF
        return (result >> 11 ^ result) * 32769 & 0xFFFFFFFF


def joaat(string, seed = 0):
    hasher = jenkins(seed)
    hasher.update_lower(string)
    return hasher.digest()

def spread_filename(path):
    dn = os.path.dirname(path)
    bn = os.path.basename(path)
    subdirs = []
    hash = joaat(bn);
    for i in range(2):
        part = hash & (64 - 1)
        hash >>= 6
        subdirs.append("{:02}".format(part))
    dstpath = os.path.join(dn, os.sep.join(subdirs))
    return os.path.join(dstpath, bn)

def spread_files(path):
    if isinstance(path, list):
        return [spread_files(x) for x in path]
    dn = path
    if not dir_exists(dn):
        dn = os.path.dirname(path)
    if not dir_exists(dn):
        print("Error - dir does not exist")
        return
    count = len(os.listdir(path))
    p = ProgressBar(count, count)
    good = bad = 0
    for fn in os.listdir(path):
        p.update(good, bad)
        if fn.endswith(".bin"):
            subdirs = []
            hash = joaat(fn);
            for i in range(2):
                part = hash & (64 - 1)
                hash >>= 6
                subdirs.append("{:02}".format(part))
            dstpath = os.path.join(dn, os.sep.join(subdirs)).replace('written2', 'written')
            os.makedirs(dstpath, exist_ok=True)
            dstname = os.path.join(dstpath, fn)
            srcname = os.path.join(path, fn)
            if not file_exists(dstname):
                good += 1
                os.rename(srcname, dstname)
            else:
                bad += 1
                os.unlink(srcname)
        else:
            bad += 1

# force laod of database
match_emu(ea=0x13fffffff)

if not getglobal('emu_stacks', None):
    for fn in glob(os.path.join(os.path.dirname(idc.get_idb_path()), 'gtasc-*balance.txt')):
        emu_stacks = read_uc_emu_stack(fn)



