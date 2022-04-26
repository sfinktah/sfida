import pickle, os
import idc, idaapi, ida_ida, ida_funcs, ida_bytes
from bisect import bisect_left, bisect_right, bisect
from choose_multi import *
from execfile import execfile, make_refresh
refresh_emu = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
import lzma
import re

try:
    from string_between import string_between_splice, string_between
except ModuleNotFoundError:
    print("please run: pip install string-between")
    raise ModuleNotFoundError('string-between')

from di import diInsns, MyGetInstructionLength
from file_get_contents import *


def file_get_contents_bin_spread(fn):
    fn = smart_path(fn)
    if fn.endswith('.bin'):
        if not file_exists(fn) and not re.match(r'/\d\d/\d\d/', fn):
            fn = spread_filename(fn)
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

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

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

def read_emu_glob(fn, path=None):
    if path is not None:
        match_emu._files.clear()
        emu_path(path)

    if isinstance(fn, list):
        return [read_emu_glob(x) for x in fn]

    from glob import glob
    if not match_emu._path:
        print("No path set")
        return

    fns = os.path.normpath(os.path.join(match_emu._path, 'memcpy/*/*/*' + fn + '*.bin'))
    globbed = list(glob(fns))
    print('globbing... {}'.format(fns)
    fns = os.path.normpath(os.path.join(match_emu._path, 'written/*/*/*' + fn + '*.bin'))
    globbed.extend(list(glob(fns)))
    print('globbing... {}'.format(fns)
    print('globbed: {}'.format(globbed))
    read_emu(globbed)

def make_emu_patchfile(fn=None, noImport=False, width=76):
    import base64
    """ 
    eg: read_emu(glob('r:/data/memcpy/*_ArxanFunction_140000000.bin'))

    @param fn: filename or [fn1, fn2, ...]

    """
    if not noImport:
        result = [
                "def base64_patch_tmp():",
                "    from base64 import b64decode", 
                "    from ida_bytes import put_bytes",
                "    from lzma import decompress",
                "    put64 = lambda ea, b64: put_bytes(ea, b64decode(b64))",
                "    lzp64 = lambda ea, b64: put_bytes(ea, decompress(b64decode(b64)))",
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
        return result

    base = parseHex(string_between('_', '_', fn))
    if base > 0x140000000 and base < 0x150000000:
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

def read_emu(fn=None):
    """ 
    read_emu: read a file / list of files into patches
    eg: read_emu(glob('r:/data/memcpy/*_ArxanFunction_140000000.bin'))

    @param fn: filename or [fn1, fn2, ...]

    """
    if isinstance(fn, list):
        return [(parseHex(string_between('_', '_', x)), read_emu(x)) for x in fn]
    base = parseHex(string_between('_', '_', fn))
    if base > 0x140000000 and base < 0x150000000:
        b = file_get_contents_bin_spread(fn)
        if b:
            #  if rv:
                #  idc.jumpto(base)

            o = idc.get_bytes(base, len(b))
            diffs = differences(o, b)
            if diffs:
                patch_bytes(base, b)

            return fn.split('_', 3)[3], len(b), diffs

    return 0

def emu_path(pn=None):
    if pn is not None:
        match_emu._files.clear()
        match_emu._keys.clear()
        match_emu._path = smart_path(pn)
    return match_emu._path

@static_vars(_files = dict(), _keys = dict(), _path = None)
def match_emu(ea=None, size=None, path=None, retnAll=False):
    """
    match_emu: Find possible Arxan patches for the given address
    range [ea, ea + size)

    @param ea: start address
    @param size: number of octets to end address
    @param path: root path to arxan patch data
    @param retnAll: return all information on each patch
    """

    subdirs = ["written", "read", "memcpy"]

    if path is None and match_emu._path is None:
        guess = os.path.dirname(get_idb_path())
        print("Guessing database path as {}".format(guess))
        path = guess

    if path is not None:
        # if match_emu._path != path:
        match_emu._files.clear()
        match_emu._path = emu_path(path)

    # compile list of files
    if not match_emu._files:
        if path is None:
            raise KeyError("please supply path argument on initial call")
        match_emu._files["written"] = dict()
        match_emu._files["read"]    = dict()
        match_emu._files["memcpy"]  = dict()
        match_emu._files["maxsize"] = 0

        min_ea = ida_ida.cvar.inf.min_ea & ~0xffff
        max_ea = (ida_ida.cvar.inf.max_ea + 1) & ~0xffff

        # check if previously compiled list exists
        if not dir_exists(path):
            print("{} is not a path".format(path))
            return

        pickle_fn = "{}/files.pickle".format(path.rstrip('/'))
        if file_exists(pickle_fn):
            match_emu._files = pickle.loads(file_get_contents_bin_spread(pickle_fn))
        else:
            # generate new list
            for _subdir in subdirs:
                for fn in glob("{0}/{1}/*/*/*.bin".format(path.rstrip('/'), _subdir)):
                    bn = os.path.basename(fn)
                    addr,  bn = string_between_splice('_',   '_', bn, repl='')
                    size,  bn = string_between_splice('__',  '_', bn, repl='')
                    arxan, bn = string_between_splice('___', '.', bn, repl='')

                    addr = parseHex(addr, 0)
                    size = parseHex(size, 0)

                    if min_ea <= addr <= max_ea and size > 0:
                        match_emu._files["maxsize"] = max(match_emu._files["maxsize"], size)
                        if addr not in match_emu._files[_subdir]:
                            match_emu._files[_subdir][addr] = defaultdict(list)
                        match_emu._files[_subdir][addr][size].append(arxan)

            print("pickling files")
            file_put_contents_bin(pickle_fn, pickle.dumps(match_emu._files))

        for _subdir in subdirs:
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
    for _subdir in subdirs:
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

def check_emu(ea=None, size=None, path=None, auto=None):
    """
    check_emu: Find possible Arxan patches for the given address
    range [ea, ea + size) and show disassembly

    @param ea: start address
    @param size: number of octets to end address
    @param path: root path to arxan patch data
    """

    if isinstance(ea, list):
        return [check_emu(x) for x in ea]

    results = dict()
    ea = eax(ea)
    res = match_emu(ea, size, path=path, retnAll=True)

    p = []
    p2 = []
    for _subdir, r in res.items():
        if auto:
            r = _.filter(r, lambda x, *a: re.search(auto, x[2]))
            pp(r)
        results[_subdir] = dict()
        if r:
            for base, length, fn in r:
                fullfn = '{}/{}/{}_{:x}_{:x}_{}.bin'.format(
                        match_emu._path.rstrip('/'), _subdir, _subdir, base, length, fn)
                #  print("would check: {}".format(fn))
                #  continue
                try:
                    asm = '; '.join([x[2] for x in diInsns(
                        file_get_contents_bin_spread(fullfn), ea=base)])
                    asm = re.sub(r'0x[0-9a-fA-F]{8,}', lambda x, *a: get_name_by_any(x[0]), asm)
                    results[_subdir][asm] = "{:x} - {:x} {} {}".format(base, base + length, fn, asm)
                    pph((_subdir, fn, hex(base), hex(base + length), asm))
                    p.append((_subdir, fn, hex(base), hex(base + length), asm))
                    p2.append(fullfn)
                except FileNotFoundError:
                    printi("File Not Found: " + fullfn)
                    raise
        
        if results[_subdir]:
            for line in results[_subdir].values():
                print(line)

    pp(p)
    if not p:
        return
    if not auto:
        variable_chooser = MyChoose(
            p,
            "Select Patch",
            [["Type", 8], ["Function", 25], ["Start", 16], ["End", 16], ["Disassembly", 128]]
        )
        row = variable_chooser.Show(modal=True)
    else:
        row = 0
        ida_bytes.patch_bytes(eax(p[row][2]), file_get_contents_bin_spread(p2[row]))
        Commenter(eax(p[row][2]), 'line').add("Patched by: " + p[row][1])
        return eax(p[row][2]), eax(p[row][3])

    if row != -1:
        print("Chose {}: {}".format(row, p2[row]))
        ida_bytes.patch_bytes(eax(p[row][2]), file_get_contents_bin_spread(p2[row]))
        Commenter(eax(p[row][2]), 'line').add("Patched by: " + p[row][1])
        #  idc.set_cmt(eax(p[row][2]), '\n'.join(idc.get_cmt(eax(p[row][2]), 0).split('\n') + ["Patched by: " + p[row][1]]), False)
        idc.create_insn(eax(p[row][2]))
        EaseCode(eax(p[row][2]))

def comment_emu(funcea=None, path=None):
    """
    comment_emu: Add comments to function chunks that are modified by Arxan
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

    for cs, ce in Chunks(funcea): 
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
    for fn in os.listdir(path):
        if fn.endswith(".bin"):
            subdirs = []
            hash = joaat(fn);
            for i in range(2):
                part = hash & (64 - 1)
                hash >>= 6
                subdirs.append("{:02}".format(part))
            dstpath = os.path.join(dn, os.sep.join(subdirs))
            os.makedirs(dstpath, exist_ok=True)
            if not file_exists(os.path.join(dstpath, fn)):
                os.rename(os.path.join(path, fn), os.path.join(dstpath, fn))
