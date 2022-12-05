import os
import idaapi

from exectools import make_refresh, make_auto_refresh, execfile
refresh_hexrayfucker = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
#  check_for_update = make_auto_refresh(os.path.abspath(__file__))

_import("from columns import MakeColumns")
_import("from underscoretest import _")
_import("from split_paren import *")
_import("from attrdict1 import SimpleAttrDict")
#  ```
#  Python> sid = idc.get_frame_id(idc.get_func_name(idc.BADADDR, 'sub_5450'))
#  Python> print(list(idautils.StructMembers(sid)))
# (offset, name, size)

class FuncArg(object):
    """Docstring for FuncArg """

    def __init__(self, type=None, indirections=None, name=None):
        """@todo: to be defined

        :type: @todo
        :indirections: @todo
        :name: @todo

        """
        self._type = type or ''
        self._indirections = indirections or ''
        self._name = name or ''
        if not name and not indirections:
            self.parse(type)

    # https://stackoverflow.com/questions/40828173/how-can-i-make-my-class-pretty-printable-in-python/66250289#66250289
    def __pprint_repr__(self, **kwargs):
        if isinstance(kwargs, dict):
            if 'indent' in kwargs:
                _indent = kwargs['indent']
        result = {}
        props = self.items().items()
        for (k, v) in props:
            result[k] = v

        return result

    def items(self):
        return {
            'type': self._type,
            'indirections': self._indirections,
            'name': self._name,
        }

    def parse(self, arg):
        arg = arg.strip()
        if not arg:
            raise ValueError("Empty Argument")

        stars = ''
        lhs = string_between('', ' ', arg, greedy=1).replace('__struct_ptr', '').replace('__hidden', '').strip()
        rhs = string_between('', ' ', arg, greedy=1, repl='').strip()
        if rhs and not lhs:
            lhs, rhs = rhs, lhs
        while rhs and rhs[0] in ('*', '&'):
            stars += rhs[0]
            rhs = rhs[1:]
        while lhs and lhs[-1] in ('*', '&'):
            stars += lhs[-1]
            lhs = lhs[0:-1]

        lhs = lhs.replace('const', '')

        lhs = lhs.strip()
        rhs = rhs.strip()

        # still working on it
        # for x, y in zip(["type", "indirection", "name"], [lhs, stars, rhs]):

        self._type = lhs
        self._indirections = stars
        self._name = rhs
        return True

        
class FuncArgs:
    regex = r"(.*?) ?(?:(\((?:(?:__[a-z]+ ?)*)\*+[^ )]*\))|(?:(?:__[a-z]+ ?)*)?([^* ]*?))(\(.*\))"

    def __init__(self, text=None):
        self.returnType = ''
        self.fnPtr = ''
        self.fnName = 'fn'
        self.fnArgs = []
        if text:
            self.parse(text)

    # https://stackoverflow.com/questions/40828173/how-can-i-make-my-class-pretty-printable-in-python/66250289#66250289
    def __pprint_repr__(self, **kwargs):
        if isinstance(kwargs, dict):
            if 'indent' in kwargs:
                _indent = kwargs['indent']
        result = {}
        props = self.items().items()
        for (k, v) in props:
            result[k] = v

        return result

    def items(self):
        return {
            'rtype': self.returnType,
            'indirections': self.fnPtr,
            'name': self.fnName,
            'args': self.fnArgs
        }

    def parse(self, decl):
        re_res = None
        for found in re.findall(self.regex, decl):
            re_res = found
            break

        if re_res:
            returnType, fnPtr, fnName, fnArgs = re_res
            
            if fnName and not returnType:
                fnName, returnType = returnType, fnName

            if fnPtr:
                print("[FuncArgs::parse] We have a void (__fastcall *name)(__int64 a1, ...) situation: {}".format(re_res))
                decl = "{} {}{}".format(returnType, string_between('*', ')', fnPtr).strip('*'), fnArgs)
                return

            # remove wrapping brackets around args
            # .. should we swap the order of these checks?
            if fnArgs.endswith('()'):
                fnArgs = fnArgs[0:-2]
            fnArgs = fnArgs[1:-1]
            
            args = paren_multisplit(fnArgs, ",")

            for arg in args:
                self.fnArgs.append(FuncArg(arg))

            stars = ''
            while returnType and returnType[-1] in ('*', '&'):
                stars += returnType[-1]
                returnType = returnType[0:-1]

            self.returnType = FuncArg(returnType, stars)
            self.fnName = fnName


first_use = dict()
used_colors = set()
pal_colors = [197, 162, 127, 92, 55, 22, 202, 167, 132, 97, 62, 27, 207, 172, 137, 102, 67, 32, 212, 177, 142, 107, 72, 37, 217, 182, 147, 112, 77, 42, 222, 187, 152, 117, 82, 47, 227, 192, 157, 122, 87]
#  pal_colors[24] = 197
#  pal_colors[8] = 197

def vt100_color(match, i):
    """

1: ['SCOLOR_DEFAULT',    'Default.'],                                
2: ['SCOLOR_REGCMT',     'Regular comment.'],                        
3: ['SCOLOR_RPTCMT',     'Repeatable comment (defined not here)'],   
4: ['SCOLOR_AUTOCMT',    'Automatic comment.'],                      
5: ['SCOLOR_INSN',       'Instruction.'],                            
6: ['SCOLOR_DATNAME',    'Dummy Data Name.'],                        
7: ['SCOLOR_DNAME',      'Regular Data Name.'],                      
8: ['SCOLOR_DEMNAME',    'Demangled Name.'],                                   8: 'qword_142F133F0'
9: ['SCOLOR_SYMBOL',     'Punctuation.'],                                      9: '{',
10: ['SCOLOR_CHAR',      'Char constant in instruction.'],           
11: ['SCOLOR_STRING',    'String constant in instruction.'],         
12: ['SCOLOR_NUMBER',    'Numeric constant in instruction.'],                 12: '// \x01\x0cside_comment',
13: ['SCOLOR_VOIDOP',    'Void operand.'],                                    13: 'v1',
14: ['SCOLOR_CREF',      'Code reference.'],                         
15: ['SCOLOR_DREF',      'Data reference.'],                         
16: ['SCOLOR_CREFTAIL',  'Code reference to tail byte.'],            
17: ['SCOLOR_DREFTAIL',  'Data reference to tail byte.'],            
18: ['SCOLOR_ERROR',     'Error or problem.'],                                18: 'JUMPOUT'}
19: ['SCOLOR_PREFIX',    'Line prefix.'],                            
20: ['SCOLOR_BINPREF',   'Binary line prefix bytes.'],               
21: ['SCOLOR_EXTRA',     'Extra line.'],                             
22: ['SCOLOR_ALTOP',     'Alternative operand.'],                    
23: ['SCOLOR_HIDNAME',   'Hidden name.'],                                     23: '_QWORD *' | '__int64 v1',
24: ['SCOLOR_LIBNAME',   'Library function name.'],                           24: '[rsp+24h] [rbp+4h]' | 24: 'rbx'
25: ['SCOLOR_LOCNAME',   'Local variable name.'],                             25: '"kernel32.dll"'
26: ['SCOLOR_CODNAME',   'Dummy code name.'],                        
27: ['SCOLOR_ASMDIR',    'Assembler directive.'],                    
28: ['SCOLOR_MACRO',     'Macro.'],                                  
29: ['SCOLOR_DSTR',      'String constant in data directive.'],      
30: ['SCOLOR_DCHAR',     'Char constant in data directive.'],        
31: ['SCOLOR_DNUM',      'Numeric constant in data directive.'],     
32: ['SCOLOR_KEYWORD',   'Keywords.'],                                        32: '0i64' | 'if'
33: ['SCOLOR_REG',       'Register name.'],                                   33: 'void f\x01\t(\x02\tint a\x01\t)\x02\t'
34: ['SCOLOR_IMPNAME',   'Imported name.'],                                   34: 'LoadLibraryA'
35: ['SCOLOR_SEGNAME',   'Segment name.'],                           
36: ['SCOLOR_UNKNAME',   'Dummy unknown name.'],                     
37: ['SCOLOR_CNAME',     'Regular code name.'],                      
38: ['SCOLOR_UNAME',     'Regular unknown name.'],                   
39: ['SCOLOR_COLLAPSED', 'Collapsed line.'],                         
40: ['SCOLOR_ADDR',      'Hidden address mark.'],                    


    """
    scolors = {
        1: ['SCOLOR_ON',         'Escape character (ON)'],
        2: ['SCOLOR_OFF',        'Escape character (OFF)'],
        3: ['SCOLOR_ESC',        'Escape character (Quote next character)'],
        4: ['SCOLOR_INV',        'Escape character (Inverse colors)'],
        1: ['SCOLOR_DEFAULT',    'Default.'],
        2: ['SCOLOR_REGCMT',     'Regular comment.'],
        3: ['SCOLOR_RPTCMT',     'Repeatable comment (defined not here)'],
        4: ['SCOLOR_AUTOCMT',    'Automatic comment.'],
        5: ['SCOLOR_INSN',       'Instruction.'],
        6: ['SCOLOR_DATNAME',    'Dummy Data Name.'],
        7: ['SCOLOR_DNAME',      'Regular Data Name.'],
        8: ['SCOLOR_DEMNAME',    'Demangled Name.'],
        9: ['SCOLOR_SYMBOL',     'Punctuation.'],
        10: ['SCOLOR_CHAR',      'Char constant in instruction.'],
        11: ['SCOLOR_STRING',    'String constant in instruction.'],
        12: ['SCOLOR_NUMBER',    'Numeric constant in instruction.'],
        13: ['SCOLOR_VOIDOP',    'Void operand.'],
        14: ['SCOLOR_CREF',      'Code reference.'],
        15: ['SCOLOR_DREF',      'Data reference.'],
        16: ['SCOLOR_CREFTAIL',  'Code reference to tail byte.'],
        17: ['SCOLOR_DREFTAIL',  'Data reference to tail byte.'],
        18: ['SCOLOR_ERROR',     'Error or problem.'],
        19: ['SCOLOR_PREFIX',    'Line prefix.'],
        20: ['SCOLOR_BINPREF',   'Binary line prefix bytes.'],
        21: ['SCOLOR_EXTRA',     'Extra line.'],
        22: ['SCOLOR_ALTOP',     'Alternative operand.'],
        23: ['SCOLOR_HIDNAME',   'Hidden name.'],
        24: ['SCOLOR_LIBNAME',   'Library function name.'],
        25: ['SCOLOR_LOCNAME',   'Local variable name.'],
        26: ['SCOLOR_CODNAME',   'Dummy code name.'],
        27: ['SCOLOR_ASMDIR',    'Assembler directive.'],
        28: ['SCOLOR_MACRO',     'Macro.'],
        29: ['SCOLOR_DSTR',      'String constant in data directive.'],
        30: ['SCOLOR_DCHAR',     'Char constant in data directive.'],
        31: ['SCOLOR_DNUM',      'Numeric constant in data directive.'],
        32: ['SCOLOR_KEYWORD',   'Keywords.'],
        33: ['SCOLOR_REG',       'Register name.'],
        34: ['SCOLOR_IMPNAME',   'Imported name.'],
        35: ['SCOLOR_SEGNAME',   'Segment name.'],
        36: ['SCOLOR_UNKNAME',   'Dummy unknown name.'],
        37: ['SCOLOR_CNAME',     'Regular code name.'],
        38: ['SCOLOR_UNAME',     'Regular unknown name.'],
        39: ['SCOLOR_COLLAPSED', 'Collapsed line.'],
        40: ['SCOLOR_ADDR',      'Hidden address mark.'],
    }
    global used_colors
    global first_use
    global pal_colors
    group = match.groups()
    o = ord(group[0][0])
    #  if o != 9: 
    used_colors.add(o)
    t = _.indexOf(list(used_colors), o)
    w = len(used_colors) + 31
    t = t + 31
    if t > 37:
        t += 3
    text = group[1]
    rest = group[2]
    ignore = ''
    #  if o not in first_use:
        #  first_use[o] = text
    #  if o == 12:
        #  if text.startswith('//'):
            #  text = text.replace('//', '#')
    #  if o == 9 and text.startswith((';','{', '}')):
        #  if text.startswith(';'):
            #  pass
        #  else:
            #  ignore += text
        #  text = ''

    result = ''
    if text:
        if i == 0 or o in (12, ):
            result += "\x1b[38;5;{}m{}\x1b[39m".format(pal_colors[o], text)
        elif i == 1:
            result += "\x1b[48;5;{};4m{}\x1b[49;24m".format(pal_colors[o], text)
        # result += "\x1b[{}m{}\x1b[0m".format(t, text)
    if rest:
        result += rest
        # result += "\x1b[48;5;{}m{}\x1b[0m".format(o, rest)
        # result += "\x1b[{};2m{}\x1b[0m".format(w, rest)
    if ignore:
        result += ignore

    return result

#  def colorize_sub(s):
    #  return re.sub(r"\x01(.)(.*?)\x02\1", vt100_color, re.sub(r"\x04\x04|\x01\([0-9a-fA-F]{16}", '', s))

def _process_citems():
    cf = vu.cfunc; 
    # '\x01(0000000000000051\x01\x08EnumProcessModules_0\x02\x08'
    # '\x01(0000000000000005\x01\x18kernel32\x02\x18'
    # '\x01(0000000000000075\x01\x08sub_1414E78F8\x02\x08'
    # '\x01(000000000000003E\x01"GetProcAddress\x02"'
    ida_lines.tag_remove( cf.treeitems[81].print1(cf) )

def colorize_sub(s, i=0):
    # vu = get_pseudocode_vu(EA(), vu); pc2 = genAsList(vu.cfunc.get_pseudocode()); clear(); print("\n".join([colorize_sub(colorize_sub(x.line), 1) for x in pc2]))
    return re.sub(r"\x01(.)(.*?)\x02\1()", 
            lambda x: vt100_color(x, i), 
            re.sub(r"\x04\x04", '', 
                re.sub(r"\x01\([0-9A-F]{16}", 
                    lambda x: "<<{}>>".format(parseHex(x.group(0)[2:])),
                    s)))
    # return re.sub(r"\x01(.)([^\x01-\x02]+)\x02\1([^\x01-\x04]*)", vt100_color, re.sub(r"\x04\x04|\x01\([0-9A-F]{16}", '', s))

def count_indent(s):
    return re.sub(r"\u2015( *)", lambda m: "\u2015{}\u2015".format(len(m.group(1))), s)

def colorize(vu):
    s = [x.line for x in genAsList(vu.cfunc.get_pseudocode())]
    for l in s:
        if "__stdcall" in l:
            print("Comment: {}".format(bytearray(l.encode('raw_unicode_escape'))))
    s = "\n\u2015".join(s)
    #  s = re.sub(r'\x01\([0-9A-F]{16}', '\x01', s)
    #  print(s)
    #  return s
    # s = re.sub(r'\x01\x09;\x02\x09(\x01\x28[0-9A-F]\{16})', '', s, re.M)
    s = re.sub(r'\x01\t;\x02\t\x01\(.{16}', '', s)
    s = re.sub(r'\x01 else\x02  *\x01 if\x02 ', 'elif', s)
    s = re.sub(r'\x01 else\x02  *\x01 if\x02 ', 'elif', s)
    s = s.replace("\x04\x04\x01\x09}\x02\x09", "") # "\u2016")
    s = s.replace(" \x01\x09(\x02\x09 ", " \x01\x09(\x02\x09 ")
    s = s.replace(" \x01\x09)\x02\x09 ", " \x01\x09)\x02\x09 ")
    #  s = s.split("\x04")
    #  s = "\n".join(s)
    s = s.replace("\x01\x0c//", "# ")
    s = s.replace("\x02\t //", "\x02\t # ")
    s = s.replace("::", ".")
    s = s.replace("\x01\t->\x02\t", "\x01\t.\x02\t")
    s = s.replace("\x01\t:\x02\t\x01\t:\x02\t", "\x01\t.\x02\t")
    s = colorize_sub(colorize_sub(s))
    s = count_indent(s)
    # \x01\x08VEHICLE::CREATE_VEHICLE_ACTUAL_0\x02\x08
    s = re.sub(r'\n\u2015\d+\u2015\{', ':', s)
    s = re.sub(r'\u2015(\d+)\u2015', lambda m: '  ' * int(m.group(1)), s)
    s = s.split("\n")
    s = "\n".join([x for x in s if x.strip()])
    s = s.replace("\n\x02\x0c", "\n  ")
    #  s = re.sub(r'\x1b\[\d+m', '', s)
    # print(s)
    return(s)

def get_min_spd(ea = None):
    ea = eax(ea)
    minspd_ea = idc.get_min_spd_ea(ea)
    if minspd_ea == idc.BADADDR:
        return False
    return idc.get_spd(minspd_ea)

def GetMinSpdStackCorrection(funcea):
    if isinstance(funcea, ida_funcs.func_t):
        func = funcea
    else:
        func = ida_funcs.get_func(funcea)
    return (func.frsize + func.frregs + idc.get_spd(idc.get_min_spd_ea(func.start_ea)))

def get_stkoff_from_lvar(lvar, debug=1):
    ea = idc.get_item_head(lvar.defea)
    func = ida_funcs.get_func(ea)
    if not func:
        return idc.BADADDR

    for n in range(2):
        if idc.get_operand_type(ea, n) == idc.o_displ:
            offset = idc.get_operand_value(ea, n) + func.frsize - func.fpd

            if debug:
                lvar_name = lvar.name
                sid = idc.get_frame_id(func.start_ea)
                frame_name = idc.get_member_name(sid, offset)
                print("[debug] offset:0x{:x}, lvar_name:{}, frame_name:{}"
                        .format(offset, lvar_name, frame_name))

            return offset

    # resort to other measures, as sometimes .defea points to a condition jmp

    return lvar.get_stkoff() + GetMinSpdStackCorrection(func)


def dump_stkvars(ea = None, iteratee=None, stkzero=0, spdoffset=0):
    _import("from columns import MakeColumns")
    def get_member_tinfo(sid, offset):
        s = ida_struct.get_struc(sid)
        m = ida_struct.get_member(s, offset)
        tif = ida_typeinf.tinfo_t()
        try:
            if ida_struct.get_member_tinfo(tif, m):
                return tif
        except TypeError as e:
            print("s, m, tif", type(s), type(m), type(tif))
            print("Exception: {}".format(pprint.pformat(e)))
        return None

    ea = eax(ea)
    c = MakeColumns()
    results = []
    sid = idc.get_frame_id(GetFuncStart(here()))
    for member in idautils.StructMembers(sid):
        o = SimpleAttrDict()
        o.offset, o.name, o.size = member
        o.offset += spdoffset
        o.zeroed = o.offset + stkzero
        o.mid   = idc.get_member_id(sid,    o.offset)
        o.name  = idc.get_member_name(sid,  o.offset)
        o.size  = idc.get_member_size(sid,  o.offset)
        o.flags = idc.get_member_flag(sid,  o.offset)
        # o.strid = idc.get_member_strid(sid, o.offset)
        tif   = get_member_tinfo(sid,     o.offset)
        o.tifname = str(tif) if tif else ''

        c.addRow(o)
        o.sid = sid
        if callable(iteratee):
            iteratee(o)
        results.append(o)
    print(c)
    return results

def rename_stkvar(src, dst, ea=None):
    def fn_rename(o, *args):
        if o.name == src:
            idc.set_member_name(o.sid, o.offset, dst)
    dump_stkvars(ea, fn_rename)

def label_stkvar(offset, name, ea=None, vu=None):
    ea = get_ea_by_any(ea or vu)
    
    sid = idc.get_frame_id(ea)
    old_name = idc.get_member_name(sid, offset)
    if old_name:
        if old_name == name:
            return old_name
        print("renaming {} to {}".format(old_name, name))
        if idc.set_member_name(sid, offset, name):
            return old_name
    else:
        print("couldn't get name from sid {:x}".format(sid))



#  2. Get the existing variable id.
#
#  ```
#  Python> var_id = idc.get_member_id(sid, 12)
#  ```
#
#  If I needed a new variable, I would have used `add_struc_member(sid, 'var_name', var_offset, FF_DATA | FF_BYTE, -1, 1)` first.
#
#  3. Use `apply_type` in order to turn the variable into an array.
#
#  ```
#  Python> apply_type(var_id, parse_decl('int[2]', 0))
#  True
#  ```
#
#  Somehow `MakeArray` did not work:
#
#  ```
#  Python> MakeArray(var_id, 2)
#  False
#  ```

class Pseudocode(object):
    def __init__(self, ea):
        self.addr = ea

    def __enter__(self):
        func = idaapi.get_func(self.addr)
        if func:
            self.vu = idaapi.open_pseudocode(func.start_ea, 0)
            return self.vu
        raise RuntimeError("Couldn't open_pseudocode")

    def __exit__(self, exc_type, exc_value, traceback):
        self.vu = None

def _Pseudocode_example():
    with Pseudocode(here()) as vu:
        arrays = get_lvars(here(), vu=vu, tif_filter=lambda tif: tif.is_array())
        for array in arrays:
            tif = array.tif
            tif.remove_ptr_or_array()
            vu.set_lvar_type(array, tif)

def contents(o, types):
    
    return _(A(o))                           \
            .chain()                         \
            .countBy(lambda x, *a: type(x))  \
            .pairs()                         \
            .sortBy(lambda v, *a: v[1])      \
            .reverse()                       \
            .first()                         \
            .first()                         \
            .value() in types
    #  return _.first(_.first(_.reverse(_.sortBy(_.pairs(_.countBy(o, lambda x, *a: type(x))), lambda v, *a: v[1])))) in types
    #  t = next(iter(A(o)))
    #  return isinstance(t, types)

def decompile_function_as_cfunc(funcea):
    try:
        cfunc = idaapi.decompile(funcea, hf=None, flags=idaapi.DECOMP_WARNINGS)
        if cfunc:
            return cfunc
    except idaapi.DecompilationFailure:
        pass
    logger.warn("IDA failed to decompile function at 0x{:x}".format(funcea))

def get_func_stkoff_delta(funcea):
    cfunc = decompile_function_as_cfunc(funcea)
    if cfunc:
        return cfunc.get_stkoff_delta()

def get_pseudocode_vu(ea, vu=None):
    func = idaapi.get_func(ea)
    if func:
        return idaapi.open_pseudocode(func.start_ea, 0)

def get_lvar_real_stkoff(ea, name='', vu=None):
    r = foreach_lvars(ea, vu=vu, iteratee= \
            lambda _lvar, _i, _vu, *a: (_lvar, _lvar.get_stkoff() - _vu.cfunc.get_stkoff_delta()))
    for _lvar, _offset in r:
        print("lvar name: {:32s} offset: 0x{:3x}".format(_lvar.name, _offset))
    return r

def get_func_rettype(ea):
    cfunc = decompile_function_as_cfunc(ea)
    func_tinfo = idaapi.tinfo_t()
    cfunc.get_func_type(func_tinfo)
    rettype = func_tinfo.get_rettype()
    return rettype


def foreach_lvars(ea, iteratee=None, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    lvars = get_lvars(ea=ea, vu=vu)
    if lvars:
        if callable(iteratee):
            for i, n in enumerate(vu.cfunc.lvars):
                # dprint("[foreach_lvars] n, i, vu")
                print("[foreach_lvars] n:{}, i:{}, vu:{}".format(n, i, vu))
                iteratee(n, i, vu) 
            return
        return [n for n in vu.cfunc.lvars]
    return False
    # foreach_lvars(EA(), lambda n, i, vu: vu.rename_lvar(n, lvd[i][0], 1), vu=vu)
    # foreach_lvars(EA(), lambda n, i, vu: vu.set_lvar_type(n, get_tinfo_by_parse(lvd[i][1])), vu=vu)

#  if you want to use an existing view:
#      widget = ida_kernwin.find_widget('Pseudocode-AU')
#      vu = vu or ida_hexrays.get_widget_vdui(widget)
def get_lvars(ea, tif_filter=None, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    if vu:
        if callable(tif_filter):
            return [n for n in vu.cfunc.lvars if tif_filter(n.tif)]
        return [n for n in vu.cfunc.lvars]
    return False

def group_lvars_by_type(ea=None, vu=None):
    return _.groupBy(get_lvars(ea, vu=vu), lambda x, *a: str(x.tif))

def map_lvars_by_type(ea=None, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    action = list()
    g = group_lvars_by_type(ea, vu)
    for tname, lvars in g.items():
        g2 = _.groupBy(lvars, lambda x, *a: x.get_reg1())
        for r, lvars2 in g2.items():
            _sorted = _.sortBy(lvars2, lambda x, *a: len(x.name))
            _sorted.reverse()
            name = _sorted[0].name
            for t in lvars2:
                if t.name:
                    print("type: {} reg: {} name: {} - {}".format(tname, t.get_reg1(), t.name, name))
                    if t.name != name:
                        action.append([t.name, name])
    for x in action:
        map_lvar(x[0], x[1], ea=ea, vu=vu)

def retype_lvars_by_type(ea=None, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    action = list()
    g = group_lvars_by_type(ea, vu)
    for tname, lvars2 in g.items():
        signed = False
        name = tname[:]
        if name.startswith('unsigned __'):
            signed = False
            name = name[9:]
        if name.startswith('signed __'):
            name = name[7:]
            signed = True
        if name.startswith('__'):
            name = name.replace('__', '' if signed else 'u', 1)
            if ' ' in name:
                name = name.replace(' ', '_t', 1)
            else:
                name = name + '_t'

        if name.startswith('_'):
            name = name[1:]

        if name == 'int':
            name = 'int32_t'

        if 'uintptr_t' in name:
            name = name.replace('uintptr_t', 'uint64_t')

        if 'DWORD' in name:
            name = name.replace('DWORD', 'uint32_t')

        if 'QWORD' in name:
            name = name.replace('QWORD', 'uint64_t')

        name = name.replace('unsigned int', 'uint32_t')

        for t in lvars2:
            if t.name:
                print("type: {} name: {} newtype: {}".format(tname, t.name, name))
                if tname != name:
                    action.append([t.name, name])
    for x in action:
        set_lvar_type(x[0], x[1], ea=ea, vu=vu)

def get_pseudocode_vu(ea, vu):
    if vu:
        return vu
    # dprint("[get_pseudocode_vu] reloading vu")
    if debug:
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        print((" -> ".join(stk)))
    print("[get_pseudocode_vu] reloading vu")
    
    func = idaapi.get_func(eax(ea))
    if func:
        return idaapi.open_pseudocode(func.start_ea, 0)

def _rename_lvar(old, new, ea, uniq=0, vu=None):
    if old is None or new is None:
        print("return_if: old is None or new is None")
        return 
    
    def make_unique_name(name, taken):
        if name not in taken:
            return name
        fmt = "%s_%%i" % name
        for i in range(3, 1<<10):
            name = fmt % i
            if name not in taken:
                return name

    if isinstance(old, str):
        old = old.strip()
    new = new.strip()
    if old == new:
        return True
    vu = get_pseudocode_vu(ea, vu)
    names = [n.name for n in vu.cfunc.lvars]
    if new in names:
        if uniq:
            return False
        new = make_unique_name(new, names)
    if isinstance(old, int):
        lvars = [vu.cfunc.lvars[old]]
    else:
        lvars = [n for n in vu.cfunc.lvars if n.name == old]
    if lvars:
        lvar = lvars[0]
        if lvar.is_stk_var():
            offset = lvar.get_stkoff() - vu.cfunc.get_stkoff_delta()
            old_name = label_stkvar(offset, new, ea=ea, vu=vu)
            if old_name:
                print("renamed stack variable {} to {}".format(old_name, new))
        else:
            print("lvar {} is not a stack variable, skipping stack rename".format(lvar.name))
        return vu.rename_lvar(lvar, new, 1)
    else:
        print("[_rename_lvar] couldn't find var '{}'".format(old))

def label_stkvar(offset, name, ea=None, vu=None):
    ea = get_ea_by_any(ea or vu)
    
    sid = idc.get_frame_id(ea)
    old_name = idc.get_member_name(sid, offset)
    if old_name:
        if old_name == name:
            return old_name
        print("renaming {} to {}".format(old_name, name))
        if idc.set_member_name(sid, offset, name):
            return old_name
    else:
        print("couldn't get name from sid {:x}".format(sid))

def get_type_tinfo(t):
    type_tuple = idaapi.get_named_type(None, t, 1)
    tif = idaapi.tinfo_t()
    tif.deserialize(None, type_tuple[1], type_tuple[2])
    return tif

def get_lvar_type(src, ea, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    if vu:
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("type of {} is {}".format(lvars[0].name, lvars[0].tif))
            return str(lvars[0].tif)
        else:
            print("[get_lvar_type] couldn't find var '{}'".format(src))
    return False

def set_lvar_name_type_so(ea, src, name, t, vu=None):
    """
    Change the name or type of a local variable 

    @param ea: address of function
    @param src: current name of variable
    @param name: new name (or None to leave as is)
    @param t: new type (str, tinfo_t, or None to leave as is)
    @param v: handle to existing pseudocode window (vdui_t, or None)

    @note
    Will not work with function arguments or global variables
    """
    # m = [ea for ea in [pprev(ea, 1) for ea in l if GetFuncName(ea)] if ea]
    def get_tinfo_elegant(name):
        ti = ida_typeinf.tinfo_t()
        til = ti.get_til()
        # get_named_type(self, til, name, decl_type=BTF_TYPEDEF, resolve=True, try_ordinal=True)
        if ti.get_named_type(til, name, ida_typeinf.BTF_STRUCT, True, True):
            return ti
        return None

    def get_pseudocode_vu(ea, vu=None):
        func = idaapi.get_func(ea)
        if func:
            return idaapi.open_pseudocode(func.start_ea, 0)

    if isinstance(t, str):
        tif = get_tinfo_elegant(t)
        if not tif:
            raise ValueError("Couldn't get tinfo_t for type '{}'".format(t))
        t = tif
    elif isinstance(t, ida_typeinf.tinfo_t) or t is None:
        pass
    else:
        raise TypeError("Unknown type for t '{}'".format(type(t)))

    vu = get_pseudocode_vu(ea, vu)
    if vu:
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("changing name/type of {}/{} to {}/{}".format(lvars[0].name, lvars[0].type(), name, str(t)))
            if t:
                vu.set_lvar_type(lvars[0], t)
            if name:
                vu.rename_lvar(lvars[0], name, 1)
        else:
            print("[set_lvar_name_type] couldn't find var {}".format(src))
    return False

def set_lvar_name_type(ea, src, name, t, vu=None):
    """
    l = FindInSegments("65 48 8B 04 25 58 00 00 00")
    forceAsCode([ea for ea in l if not GetFuncName(ea)])
    m = [ea for ea in [pprev(ea, 1) for ea in l if not GetFuncName(ea)] if ea]
    retrace_list(m)
    m = [ea for ea in l if GetFuncName(ea)]
    for ea in m: 
        list(decompile_function_search(ea, r'\b(v\d+) = TlsIndex', iteratee=lambda ea, m: set_lvar_name_type(ea, m, 'tlsIndex', None)))
    """
    # m = [ea for ea in [pprev(ea, 1) for ea in l if GetFuncName(ea)] if ea]
    if src is None:
        print("return_if: src in None")
        return 
    
    if isinstance(t, str):
        tif = get_tinfo_by_parse(t)
        if not tif:
            raise ValueError("Couldn't get tinfo for type '{}'".format(t))
        t = tif
    elif isinstance(t, ida_typeinf.tinfo_t):
        pass
    elif t is None:
        pass
    else:
        raise TypeError("Unknown type for t '{}'".format(type(t)))

    vu = get_pseudocode_vu(ea, vu)
    if vu:
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("changing name/type of {}/{} to {}/{}".format(lvars[0].name, lvars[0].type(), name, str(t)))
            if t:
                vu.set_lvar_type(lvars[0], t)
            vu.rename_lvar(lvars[0], name, 1)
        else:
            print("[set_lvar_name_type] couldn't find var {}".format(src))
    return False

def set_lvar_type(src, t, ea, vu=None):
    if t is None or src is None:
        print("return_if: t is None or src in None")
        return 
    
    if isinstance(t, str):
        tif = get_tinfo_by_parse(t)
        if not tif:
            raise ValueError("Couldn't get tinfo for type '{}'".format(t))
        t = tif
    elif isinstance(t, ida_typeinf.tinfo_t):
        pass
    else:
        raise TypeError("Unknown type for t '{}'".format(type(t)))

    vu = get_pseudocode_vu(ea, vu)
    if vu:
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("changing type of {} to {}".format(lvars[0].name, t))
            return vu.set_lvar_type(lvars[0], t)
        else:
            print("[set_lvar_type] couldn't find var {}".format(src))
    return False

def map_lvar(src, dst, ea, vu=None):
    #  t = ('', '\n=\x04#\x86U', '')
    #  ti = idaapi.tinfo_t()
    #  ti.deserialize(None, t[0], t[1])
    vu = get_pseudocode_vu(ea, vu)
    if vu:
        lvars1 = [n for n in vu.cfunc.lvars if n.name == src]
        lvars2 = [n for n in vu.cfunc.lvars if n.name == dst]
        if len(lvars1) == 1 and len(lvars2) == 1:
            print("mapping {} to {}".format(lvars1[0].name, lvars2[0].name))
            # we might need to change the lvar type?
            vu.set_lvar_type(lvars1[0], lvars2[0].type())
            return vu.map_lvar(lvars1[0], lvars2[0])
        else:
            print("couldn't find one of the vars {} or {}".format(src, dst))
    return False

# ralf rolles
# It's better to do this directly, without using the user-interface class
# vdui_t. Here's a small function you can call to set the name of a local
# variable, assuming you already have the lvar_t object you want to rename:

def SetLvarName(func_ea,lvar,name):
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lvar
    lsi.name = name
    ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, lsi)

# Here's a little harness I wrote to ensure it works. It decompiles some function in my database, finds the lvar_t named "v35", and renames it to "vNewName".

def GetCfunc(ea):
    f = idaapi.get_func(ea)
    if f is None:
        return None

    # Decompile the function.
    cfunc = None
    try:
        cfunc = idaapi.decompile(f)
    finally:
        return cfunc

def SetLvarNameTest():
    cfunc = GetCfunc(0x61FE5DDE)
    if cfunc:
        mba = cfunc.mba
        for idx in xrange(mba.vars.size()):
            var = mba.vars[idx]
            if var.name == "v35":
                SetLvarName(cfunc.entry_ea,var,"vNewName")
                break

def get_flags_by_size(size):
    """ see also ida_bytes.get_flags_by_size """
    flags = [ida_bytes.byte_flag(),  ida_bytes.word_flag(),  ida_bytes.dword_flag(),
             ida_bytes.qword_flag(), ida_bytes.oword_flag(), ida_bytes.yword_flag(),
             ida_bytes.zword_flag()  ]

    if (size & (size-1)):
        raise ValueError("size is not a power of 2")

    flag = flags[log2(size)]

    # [(x >> 28) - 0x400 for x in flags] = ['0b0', '0b1', '0b10', '0b11', '0b111', '0b1110', '0b1111']
    b = 0
    for r in range(log2(size)):
        if b & 1: b <<= 1
        else: b |= 1
        # handle annoying miss in pattern
        if b == 6: b += 1
        if debug: print("b: {}".format(bin(b)))

    flag2 = (b << 28) + (1 << 10)

    # dprint("[get_data_flag] size, flag, flag2")
    print("[get_data_flag] size:{}, flag:{:x}, flag2:{:x}".format(size, flag, flag2))



def show_lvars_to_stk(ea, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    func = idaapi.get_func(ea)
    # DONE: replace with idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # stkzero = ida_frame.frame_off_retaddr(func) - 8
    stkzero = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # dprint("[sync_lvars_to_stk] stkzero, stkzero2")
    #  print("[sync_lvars_to_stk] stkzero:{}, stkzero2:{}".format(stkzero, stkzero2))

    vu_offset_fix = GetMinSpdStackCorrection(func)
    stkvars = _.indexBy(dump_stkvars(ea, stkzero=-stkzero), 'offset')
    lvars = []
    if vu and func:
        #  opi = ida_nalt.opinfo_t()
        # ida_bytes.get_opinfo(opi, EA(), 1, GetOpType(EA(), 1))
        stk_lvars = [(
            n.name, 
            n.tif.get_size(),
            n.location.stkoff(), #  - func.frregs - func.frsize,
            n.location.stkoff() + vu_offset_fix,
            ) \
                for n in vu.cfunc.lvars if n.location.is_stkoff()]
        #  [ (x.name, x.tif.get_size(), hex( x.location.stkoff() - ida_frame.frame_off_retaddr(func) - 8 ) ) \
            #  for x in n if x.location.is_stkoff()
        #  ]

        c = MakeColumns()
        for name, size, offset1, offset2 in stk_lvars:
            o = SimpleAttrDict()
            o.update({
                'name': name,
                'size': size,
                'lvar_offset': offset1,
                'lvar_offset_fix': offset2
                #  'stk_name1': stkvars[-offset1],
                #  'stk_name2': stkvars[-offset2],
                })
            c.addRow(o)
            lvars.append(o)
        print(c)
    lvars = _.indexBy(lvars, 'lvar_offset_fix')

    c = MakeColumns()
    lvar_offsets = lvars.keys()
    for offset in lvar_offsets:
        if offset in stkvars:
            c.addRow({
                'lname': lvars[offset].name,
                'sname': stkvars[offset].name,
                'lvar_offset': lvars[offset].lvar_offset_fix,
                'stk_offset': stkvars[offset].offset,
                'zero_offset': stkvars[offset].zeroed,
            })
    # dprint("[] func.frregs, func.frsize, func.fpd, ida_frame.frame_off_retaddr, ida_frame.frame_off_lvars, ida_frame.frame_off_args, ida_frame.frame_off_savregs")
    print("")
    print("{:28}: {}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n"
            .format(
                "func.flags",                  " | ".join(debug_fflags(func, quiet=1)),
                "func.frregs",                 func.frregs,
                "func.frsize",                 func.frsize,
                "func.fpd",                    func.fpd,
                "vu_offset_fix",               vu_offset_fix,
                "ida_frame.frame_off_retaddr", ida_frame.frame_off_retaddr(func),
                "ida_frame.frame_off_lvars",   ida_frame.frame_off_lvars(func),
                "ida_frame.frame_off_args",    ida_frame.frame_off_args(func),
                "ida_frame.frame_off_savregs", ida_frame.frame_off_savregs(func),
                ))

    print(c)

            # check we have a power of 2
            #  if size & (size-1) == 0 and size < 32:
                #  flags = ida_bytes.get_flags_by_size(size)
            #  ida_frame.define_stkvar(func, name, offset, flags, opi, size)


def sync_lvars_to_stk(ea, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    func = idaapi.get_func(ea)
    # DONE: replace with idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # stkzero = ida_frame.frame_off_retaddr(func) - 8
    stkzero = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # dprint("[sync_lvars_to_stk] stkzero, stkzero2")
    #  print("[sync_lvars_to_stk] stkzero:{}, stkzero2:{}".format(stkzero, stkzero2))

    vu_offset_fix = GetMinSpdStackCorrection(func)
    stkvars = _.indexBy(dump_stkvars(ea, stkzero=-stkzero), 'name')
    lvars = []
    if vu and func:
        #  opi = ida_nalt.opinfo_t()
        # ida_bytes.get_opinfo(opi, EA(), 1, GetOpType(EA(), 1))
        stk_lvars = [(
            n.name, 
            n.tif.get_size(),
            n.location.stkoff(), #  - func.frregs - func.frsize,
            n.location.stkoff() + vu_offset_fix,
            str(n.tif)
            ) \
                for n in vu.cfunc.lvars if n.location.is_stkoff()]
        #  [ (x.name, x.tif.get_size(), hex( x.location.stkoff() - ida_frame.frame_off_retaddr(func) - 8 ) ) \
            #  for x in n if x.location.is_stkoff()
        #  ]

        c = MakeColumns()
        for name, size, offset1, offset2, _type in stk_lvars:
            o = SimpleAttrDict()
            o.update({
                'name': name,
                'size': size,
                'type': _type,
                'lvar_offset': offset1,
                'lvar_offset_fix': offset2
                #  'stk_name1': stkvars[-offset1],
                #  'stk_name2': stkvars[-offset2],
                })
            c.addRow(o)
            lvars.append(o)
        print(c)
    else:
        print('no vu, or no func')
    lvars = _.indexBy(lvars, 'name')

    c = MakeColumns()
    lvar_names = lvars.keys()
    for name in lvar_names:
        if name in stkvars:
            c.addRow({
                'name': name,
                'lvar_offset': lvars[name].lvar_offset_fix,
                'stk_offset': stkvars[name].offset,
                'zero_offset': stkvars[name].zeroed,
            })
    # dprint("[] func.frregs, func.frsize, func.fpd, ida_frame.frame_off_retaddr, ida_frame.frame_off_lvars, ida_frame.frame_off_args, ida_frame.frame_off_savregs")
    print("")
    print("{:28}: {}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n"
            .format(
                "func.flags",                  " | ".join(debug_fflags(func, quiet=1)),
                "func.frregs",                 func.frregs,
                "func.frsize",                 func.frsize,
                "func.fpd",                    func.fpd,
                "vu_offset_fix",               vu_offset_fix,
                "ida_frame.frame_off_retaddr", ida_frame.frame_off_retaddr(func),
                "ida_frame.frame_off_lvars",   ida_frame.frame_off_lvars(func),
                "ida_frame.frame_off_args",    ida_frame.frame_off_args(func),
                "ida_frame.frame_off_savregs", ida_frame.frame_off_savregs(func),
                ))

    print(c)

            # check we have a power of 2
            #  if size & (size-1) == 0 and size < 32:
                #  flags = ida_bytes.get_flags_by_size(size)
            #  ida_frame.define_stkvar(func, name, offset, flags, opi, size)

def dump_lvars_and_stk(ea, vu=None):
    vu = get_pseudocode_vu(ea, vu)
    func = idaapi.get_func(ea)
    # DONE: replace with idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # stkzero = ida_frame.frame_off_retaddr(func) - 8
    stkzero = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    # dprint("[sync_lvars_to_stk] stkzero, stkzero2")
    #  print("[sync_lvars_to_stk] stkzero:{}, stkzero2:{}".format(stkzero, stkzero2))

    vu_offset_fix = GetMinSpdStackCorrection(func)
    stkvars = _.indexBy(dump_stkvars(ea, stkzero=-stkzero), 'name')
    lvars = []
    if vu and func:
        #  opi = ida_nalt.opinfo_t()
        # ida_bytes.get_opinfo(opi, EA(), 1, GetOpType(EA(), 1))
        stk_lvars = [(
            n.name, 
            n.tif.get_size(),
            n.location.stkoff(), #  - func.frregs - func.frsize,
            n.location.stkoff() + vu_offset_fix,
            str(n.tif),
            n.get_reg1() if n.is_reg_var() else "",
            n.get_stkoff() - vu.cfunc.get_stkoff_delta() if n.is_stk_var() else "",
            n.get_stkoff() - vu.cfunc.get_stkoff_delta() - stkzero if n.is_stk_var() else "",
            n.is_mapdst_var,
            n.is_automapped()
            ) \
                for n in vu.cfunc.lvars ] # if n.location.is_stkoff()
        #  [ (x.name, x.tif.get_size(), hex( x.location.stkoff() - ida_frame.frame_off_retaddr(func) - 8 ) ) \
            #  for x in n if x.location.is_stkoff()
        #  ]

        c = MakeColumns()
        for name, size, offset1, offset2, _type, reg, stk_off, stk_zeroed, mapped, automapped in stk_lvars:
            o = SimpleAttrDict()
            o.update({
                'name': name,
                'size': size,
                'type': _type,
                'stk': stk_off,
                'stk_0': stk_zeroed,
                'offset': offset1,
                'offsetfix': offset2,
                'reg': reg,
                'map': mapped,
                'amap': automapped
                #  'stk_name1': stkvars[-offset1],
                #  'stk_name2': stkvars[-offset2],
                })
            c.addRow(o)
            lvars.append(o)
        print(c)
    else:
        print('no vu, or no func')
    lvars = _.indexBy(lvars, 'name')

    c = MakeColumns()
    lvar_names = lvars.keys()
    for name in lvar_names:
        if name in stkvars:
            c.addRow({
                'name': name,
                'lvar_offset': lvars[name].lvar_offset_fix,
                'stk_offset': stkvars[name].offset,
                'zero_offset': stkvars[name].zeroed,
            })
    # dprint("[] func.frregs, func.frsize, func.fpd, ida_frame.frame_off_retaddr, ida_frame.frame_off_lvars, ida_frame.frame_off_args, ida_frame.frame_off_savregs")
    print("")
    print("{:28}: {}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n{:28}: {:3x}\n"
            .format(
                "func.flags",                  " | ".join(debug_fflags(func, quiet=1)),
                "func.frregs",                 func.frregs,
                "func.frsize",                 func.frsize,
                "func.fpd",                    func.fpd,
                "vu_offset_fix",               vu_offset_fix,
                "ida_frame.frame_off_retaddr", ida_frame.frame_off_retaddr(func),
                "ida_frame.frame_off_lvars",   ida_frame.frame_off_lvars(func),
                "ida_frame.frame_off_args",    ida_frame.frame_off_args(func),
                "ida_frame.frame_off_savregs", ida_frame.frame_off_savregs(func),
                ))

    print(c)



def decompile_arxan_getnextrange(ea):
    sid = idc.get_struc_id('arxan_range')
    if sid == idc.BADADDR:
        strucText = """
            typedef BYTE uint8_t;
            typedef DWORD uint32_t;
            typedef int int32_t;
            struct arxan_range
            {
              uint32_t start;
              uint32_t len;
            };
        """
        if idc.parse_decls(strucText, idc.PT_SILENT) != 0:
            print("StrucInfo: Error re-parsing structure: {}\n{}".format(name, strucText))

    idc.SetType(ea, "void __fastcall ArxanChecksumWorker(uint8_t **guide, arxan_range *range);")
    mapping = [ 'accum', 'v7', 'v4', 'shift', 'v5', 'v6', 'ptr', 'v2', 'v3' ]
    for n, x, y in chunk_tuple(mapping, 3):
        if map_lvar(x, y, ea) and              \
           set_lvar_type(y, 'int32_t', ea) and \
           _rename_lvar(y, n, ea):
                print("set {}".format(n))

def stripped_lines(source_code):
    result = list()

    lines = str(source_code).split("\n")
    for line in lines:
        s = line.strip()
        if len(s) == 0:
            continue
        result.append(s)

    return result

def find_in_path(name, paths=None):
    if paths is None:
        paths = os.environ['PATH'].split(os.pathsep)
    elif not isinstance(paths, list):
        paths = [paths]
    for path in paths:
        if os.path.isfile(os.path.join(path, name)):
            return os.path.join(path, name)

#  # And this will find all matches:
#  
#  def find_all_in_path(name, path):
    #  result = []
    #  for root, dirs, files in os.walk(path):
        #  if name in files:
            #  result.append(os.path.join(root, name))
    #  return result
#  
#  # And this will match a pattern:
#  
#  def find_pattern_in_path(pattern, path):
    #  import fnmatch
    #  result = []
    #  for root, dirs, files in os.walk(path):
        #  for name in files:
            #  if fnmatch.fnmatch(name, pattern):
                #  result.append(os.path.join(root, name))
    #  return result



#  find('*.txt', '/path/to/dir')

#  def find(name, path):
    #  # https://stackoverflow.com/questions/1724693/find-a-file-in-python
    #  _path = os.environ['PATH'].split(os.path.sep)
    #  for root, dirs, files in os.walk(path):
        #  if name in files:
            #  return os.path.join(root, name)
def clangformat(source_code):
    #  idc.batch(0)
    import glob
    #  clang_paths = glob.glob(r"C:\Program Files (x86)\Microsoft Visual Studio\20*\*\Common7\IDE\VC\vcpackages\clang-format.exe")
    #  if not clang_paths:
    clang_path = find_in_path("clang-format.exe")
    if not clang_path:
        clang_paths = glob.glob(r"C:\Program Files (x86)\Microsoft Visual Studio\20*\*\Common7\IDE\VC\vcpackages\clang-format.exe") + \
                glob.glob(r"C:\Program Files\Microsoft Visual Studio\*\Community\VC\Tools\Llvm\x64\bin\clang-format.exe")
        if clang_paths:
            if len(clang_paths) > 1:
                print("{} possible locations for clang-format found:".format(len(clang_paths)))
                for i, clang_path in enumerate(clang_paths):
                    print("\t[{}] {}".format(i, clang_path))
                print("picking one at random:")
                clang_paths.shuffle()
                print("selecting:  {}".format(clang_path))
            clang_path = clang_paths[0]
    if not clang_path:
        # No clang, just return input
        return source_code

    # change directory to project dir, to pick up any
    # .clang-format files (maybe should specify as arg)
    cwd_path = os.getcwd()
    idb_path = idc.get_idb_path()
    idb_path = idb_path[:idb_path.rfind(os.sep)]
    os.chdir(idb_path)

    clang_args = [clang_path];
    #  clang_args.append("--argname=option")
    #  and so forth, and so on... if necessary

    err = ''
    out = ''
    try:
        phandle = subprocess.Popen(clang_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        out, err = phandle.communicate(source_code.encode("utf-8"))

        if err:
            print("clang-format error: {}".format(err))

    except Exception as err:
        print("Exception executing clang-format: {}".format(str(err)))
        return None

    finally:
        os.chdir(cwd_path)

    return out.decode("utf-8")


def decompile_function(ea):
    try:
        d = str(ida_hexrays.decompile(ea))
    except ida_hexrays.DecompilationFailure:
        print("Couldn't decompile function: %s" % hex(ea))
        return None
    # print("decompiled_function_type: after decompile", type(d))
    e = clangformat(d)
    # print("decompiled_function_type: after clang-format", type(e))
    f = e.split("\n")
    # print("decompiled_function_type: line_split", type(f))
    return f

#  list(
#  decompile_function_search( 
    #  [x for x in GetFuncStart(xrefs_to(eax('AddBonusCheck'))) if x < idc.BADADDR], 
    #  r'AddBonusCheck.*', 
    #  iteratee=lambda ea, n: LabelAddressPlus(ea, "init_AnotherFishyElement_{}".format(string_between('ACID_', ')', n) ))
#  ))
def decompile_function_search(ea, regex, iteratee=None, flags = 0):
    if not isinstance(ea, list):
        ea = [ea]
    for addr in ea:
        try:
            cfunc = str(idaapi.decompile(GetFuncStart(addr)))
            if isinstance(cfunc, str):
                m = re.findall(regex, cfunc, flags)
                for x in m:
                    if iteratee:
                        print("iteratee({:#x}, '{}')".format(addr, x))
                        iteratee(addr, x)
                    yield x
        except ida_hexrays.DecompilationFailure:
            pass
    # decompile_function_search(
    #   EA(), 
    #   r'(qword_[0-9A-F]+) =.*\)(\w+)', 
    #   lambda ea, m: LabelAddressPlus(eax(m[0]), m[1] + "_Prologue")
    # )

def decompile_SetRandHash():
    r = []
    for n in decompile_function_search(
            xrefs_to('SetRandHash'), 
            r'SetRandHash\(.*\);'): 
        r.extend( 
                [x[6:] for x in paren_multisplit(
                    string_between('(', ')', n, greedy=1), ',') 
                    if x.startswith('(Hash)')] 
        )
    print(' '.join(
        _.uniq(
            _.flatten(
                [x for x in r if x[0] in ('0 1 2 3 4 5 6 7 8 9 -'.split(' '))
            ])
        )
    ))
    return [mega.Lookup(int(x)) for x in _.uniq( _.flatten( [x for x in r if x[0] in ('0 1 2 3 4 5 6 7 8 9 -'.split(' ')) ]))]


def decompile_hashes(ea=None):
    """
    decompile_hashes

    @param ea: linear address
    """
    if isinstance(ea, list):
        return [decompile_hashes(x) for x in ea]

    ea = eax(ea)
    if not getglobal('mega', None):
        execfile('e:/git/gta5utilities/megahash.py')
    return \
            [mega.Lookup(int(x, 16)) for x in re.findall(r'\b0x[0-9A-F]{5,8}', str(decompile(ea)))] + \
            [mega.Lookup(int(x, 10)) for x in re.findall(r' -?[1-9][0-9]{6,10}\b', str(decompile(ea)))]

def decompile_hashes_regex(ea=None, regex=None):
    """
    decompile_hashes

    @param ea: linear address
    """
    if regex is None and isString(ea):
        ea, regex = regex, ea
    elif isinstance(ea, list):
        return [decompile_hashes_regex(x) for x in ea]

    ea = eax(ea)
    return [mega.Lookup(int(x, 16)) for x in re.findall(regex, str(decompile(ea)))]



def decompile_function_for_subs(ea, recurse = 0, parents=None):
    parents = A(parents)
    if recurse < 0:
        return

    def measure_indent(s):
        for i, c in enumerate(s):
            if c != ' ':
                return i

    print("decompile: {}, {}".format(", ".join(parents), idc.get_name(ea, 0)))

    fnName = idc.get_name(ea);
    pattern_sub  = re.compile(r'(.)([a-zA-Z0-9_:]+)\(')
    subs = set()
    last_indent = 0
    case_label = None
    switch_subject = None
    switch_indent = None
    case_indent = None
    for line in decompile_function(ea):
        indent = measure_indent(line)
        for (s) in re.findall(r'switch \(([^)]+)\)', line):
            switch_subject = s
            switch_indent = indent
        for (s) in re.findall(r'case ([^:]+):', line):
            case_label = s
            case_indent = indent
        if indent < case_indent:
            case_indent = None
            case_label = None
        if indent < switch_indent:
            switch_indent = None
            switch_subject = None
            case_indent = None
            case_label = None

        #   *v7 = &CNetObjBike::`vftable';
        m = re.match(r'\s+\*(\w+) = &(CNetObj\w+)::.vftable', line)
        if m:
            print("m: ", m.groups())
            LabelAddressPlus(ea, '{}::__construct'.format(m.groups()[1]))
            return
        m = re.match(r'\s+(\w+) = (CNetObj\w+)::__construct', line)
        if m:
            if 'getEmptyPoolSlot' in subs:
                LabelAddressPlus(ea, 'get{}'.format(m.groups()[1]))
        for (pre, sub) in re.findall(pattern_sub, line):
            if pre == '>':
                continue
            if idc.get_name_ea_simple(sub) == BADADDR:
                continue
            if idc.get_name_ea_simple(sub) == ea:
                continue
            if len(parents) == 0 and sub in subs:
                continue
            if case_label:
                decompile_function_for_subs(idc.get_name_ea_simple(sub), recurse - 1, parents + [idc.get_name(ea), "case {} == {}".format(switch_subject, case_label)])
                continue

            decompile_function_for_subs(idc.get_name_ea_simple(sub), recurse - 1, parents + [idc.get_name(ea)])
            subs.add(sub)
            #  print("sub: {}".format(sub))
            # print("decompile_function: {}".format("\n".join(decompile_function(idc.get_name_ea_simple(sub)))))


def reby_simple(chunk_size, matches):
    """ helper function for chunking regex
    matches with multiple alternatives
    """
    if matches:
        for match in matches:
            #  match = match[1:]
            for item in chunk_tuple(match, chunk_size):
                if item[0]:
                    yield item
def reby(chunk_size, matches):
    """ helper function for chunking regex
    matches with multiple alternatives
    """
    if matches:
        for match in matches:
            match = match[1:]
            for item in chunk_tuple(match, chunk_size):
                if item[0]:
                    yield item

def wrap_pattern(pattern, split=None):
    pattern = pattern                                                     \
        .replace(r'\x',                             r'[0-9a-fA-F]')       \
        .replace(r'\w\+',                           r'\w+')               \
        .replace(r' += ',                           r' \+= ')             \
        .replace(r' ^ ',                            r' \^ ')              \
        .replace(r'[::reinterpret_pointer_cast::]', r'(?:\*\([^)]+\*\))') \
        .replace(r'[::pointer_cast::]',             r'(?:\([^)]+\*\))')   \
        .replace(r'[::static_cast::]',              r'(?:\([^)]+\))')     \
        .replace(r'[::reference_cast::]',           r'(?:\([^)]+\)&)')    \
        .replace(r'[::reinterpet_cast::]',          r'(?:\*\([^)]+\)&)')  \
        .replace(r'[::deref_static_cast::]',        r'(?:\*\([^)]+\))')   \
        .replace(r'[::v::]',                        r'(?:v\d+)')          \
        .replace(r'[::number::]',                   r'(?:(?:0x)?[0-9a-fA-F]+)')
    if split:
        return pattern.split(split)
    if pattern.startswith(('^', '\\')):
        pattern = '(' + pattern + ')'
    else:
        pattern = r'(^\s+' + pattern.rstrip(';') + r';|\(' + pattern.rstrip(';') + r'\))'
    #  print('wrap_pattern: {}'.format(pattern))
    return pattern

def wrap_compile(pattern, flags=0):
    return re.compile(wrap_pattern(pattern), flags)


    
def decompile_function_for_common_renames(funcea=None, recurse=0, parents=None):
    """
    decompile_function_for_common_renames

    @param funcea: any address in the function
    """
    parents = A(parents)
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        ea = func.start_ea

    if recurse < 0:
        return

    fnName = idc.get_name(ea);

    def wrap_pattern(pattern):
        new_pattern = r'(^\s+' + pattern + r';|\(' + pattern + r'\))'
        return new_pattern


    #  if ((flags & PHANDLE_END) != 0 || ((flags & PHANDLE_READING) == 0 ? (v6 = pHandle->MaxWriteSize) : (v6 = pHandle->MaxSize), pHandle->Offset + 15 > v6 || !pHandle::readDword(pHandle, &data, 14) || data != 12870 || !pHandle::readDword(pHandle, &data, 1))) {
    #  [('(v6 = pHandle->MaxWriteSize)', '', '', '', '', 'v6', 'pHandle', '->', 'MaxWriteSize'),
    #   ('(v6 = pHandle->MaxSize)', '', '', '', '', 'v6', 'pHandle', '->', 'MaxSize')]

    # renaming an lvar to match a struct fieldname, e.g.
    # v1 = struct->member;
    pattern_sub  = wrap_compile(r'(v\d+) = (\w+)(->)(\w+)')

    # renaming an lvar to match a struct fieldname, e.g.
    # struct->member = v1;
    pattern_sub2 = wrap_compile(r'(\w+)(->)(\w+) (=|\+=|-=) (v\d+)')

    # renaming (and retyping) the return value from a function call, e.g.
    # v1 = (optional cast&*)(function)(
    pattern_call = wrap_compile(r'^\s+(v\d+) (=|\+=|-=) [::static_cast::]*(\w+)\(')

    # renaming an lvar to match another
    # v1 = name
    pattern_opeq = wrap_compile(r'(v\d+) (=) (\w+)')

    pattern_floating_dword = wrap_compile(r'\*\(float\*\)&(dword_\x+)')
    pattern_floating_lodword = wrap_compile(r'(dword_142D5A834) = LODWORD\(([::v::])\)')

    lines = decompile_function(ea)
    if not lines:
        return

    for line in lines:
        for (var, struc, indir, member) in reby(4, re.findall(pattern_sub, line)):
            # we are specifically limiting the named members of any struct
            # **named** pHandle (not necessary of the right type).
            if struc == 'pHandle':
                if member == 'Offset':
                    _rename_lvar(var, 'offset', ea)
                if member == 'Flags':
                    _rename_lvar(var, 'flags', ea)
                if member in ('MaxSize', 'MaxReadSize', 'MaxWriteSize'):
                    _rename_lvar(var, 'maxSize', ea)

        for (struc, indir, member, operator, var) in reby(5, re.findall(pattern_sub2, line)):
            # this is essential the same as above, but matches when a->b = c
            # instead of c = a->b
            if struc == 'pHandle':
                if member == 'Offset':
                    _rename_lvar(var, 'offset', ea)
                if member == 'Flags':
                    _rename_lvar(var, 'flags', ea)

        for (var, operator, func) in reby(3, re.findall(pattern_call, line)):
            # matching v1 = function(...), and:
            # just changing the name
            if func.endswith('joaat'):
                _rename_lvar(var, 'hash', ea)
            if func == 'GetGameScriptHandler_fivem':
                _rename_lvar(var, 'pScrThread', ea)
            # braving some general rules
            if re.match('get.*count', func, re.I):
                _rename_lvar(var, 'count', ea)

            # or changing the name and type to match the function return
            m = (re.match(r'getEntityAddressIf([A-Z][a-z]+)', func))
            if m:
                _type = m[1]
                rettype = get_tinfo_by_parse('C' + _type + ' *')
                #  rettype = get_func_rettype(get_ea_by_any(func))
                set_lvar_type(var, rettype, ea)
                _rename_lvar(var, 'p{}'.format(_type), ea)
            if func == 'getOnlinePlayerInfo':
                rettype = get_func_rettype(get_ea_by_any(func))
                set_lvar_type(var, rettype, ea)
                _rename_lvar(var, 'pOnlineInfo', ea)

        for (dst, operator, src) in reby(3, re.findall(pattern_opeq, line)):
            # this renames lvars assigned to pPointerOfSomething
            if src.startswith('p') and src[1].upper() == src[1]:
                _rename_lvar(dst, src, ea)

        for (addr,) in reby(1, re.findall(pattern_floating_dword, line)):
            # dprint("[float] line")
            print("[float] line:{}".format(line))
            
            SetType(eax(addr), 'float')
            LabelAddressPlus(eax(addr), addr.replace('dword', 'float'))

        for (addr, src) in reby(2, re.findall(pattern_floating_lodword, line)):
            # dprint("[float] line")
            print("[lodword-float] line:{}".format(line))
            
            t = get_lvar_type(src, ea)
            if t == 'float':
                SetType(eax(addr), 'float')
                LabelAddressPlus(eax(addr), addr.replace('dword', 'float'))

def _end_():
    pass

def rename_lvar_factory(*args, **kwargs):
    """
    @brief rename_lvar_factory

    @param indexes [optional,iterable] index(es) to use from array of names
    @param names [iterable] name(s) matched by (usually a regex)
    @param uniq [default:0] only perform replace once
    @param type [default:None]

    @return list of returns from set_lvar_type
    """
     #  |  set_lvar_type(self, *args) -> 'bool'
     #  |      Set variable type Note: this function does not modify the idb, only
     #  |      the lvar instance in the memory. For permanent changes see
     #  |      modify_user_lvars() Also, the variable type is not considered as final
     #  |      by the decompiler and may be modified later by the type derivation. In
     #  |      some cases set_final_var_type() may work better, but it does not do
     #  |      persistent changes to the database neither.#

    named_args = dict()
    for arg in args:
        if len(named_args) in (0,) and contents(arg, (int,)):
            named_args['indexes'] = A(arg)
        elif len(named_args) in (0,1):
            if contents(arg, (str, type(None))):
                named_args['names'] = A(arg)
                if 'indexes' not in named_args:
                    named_args['indexes'] = range(len(named_args['names']))
            else:
                raise ValueError("unknown type in: {}".format(arg))

    named_args['uniq'] = 0
    named_args['type'] = None
    named_args.update(kwargs)

    from operator import itemgetter
    indexes, names, types, uniq = itemgetter('indexes', 'names', 'type', 'uniq')(named_args)

    if types is None:
        types = [None] * len(names)
    elif isinstance(types, str):
        types = (types,)
    elif not isinstance(types, tuple):
        types = tuple(types)

    callables = []
    if 'then' in named_args:
        callables.extend(A(named_args['then']))


    def replace_subpatterns(name, m):
        if name is None:
            print("return_if: name is None")
            return 
        
        # dprint("[replace_subpatterns] m")
        print("[replace_subpatterns] name:{} m:{}, type(m):{}".format(name, m, type(m)))
        return re.sub(r'\\(\d+)', lambda x: m[int(x[0][1:])], name)
        

    def fn_rename_lvar(*args, **kwargs):
        ea = kwargs['ea']
        vu = kwargs['vu']
        if len(args) > len(names):
            if args[1] in args[0] and len(args) - len(names) == 1:
                args = args[1:]
            else:
                skip_first = 1
                print("args:   {}".format(indent(8, args,  skipFirst=1, stripLeft=1)))
                print("names:  {}".format(indent(8, names, skipFirst=1, stripLeft=1)))
                for r in range(1, len(args)):
                    if not args[r] in args[0]:
                        skip_first = 0
                if skip_first:
                    args = args[1:]

        for index, name, _type in zip(indexes, names, types):

            # dprint("[fn_rename_lvar] index, name, _type")
            print("[fn_rename_lvar] index:{}, name:{}, _type:{}".format(index, name, _type))
            
            if _type:
                set_lvar_type(args[index], _type, ea, vu=vu)
            if _type is None and isinstance(name, str):
                old_name = args[index]
                fnLoc = get_ea_by_any(old_name)
                LabelAddressPlus(fnLoc, name)

            if isinstance(name, int):
                old_name = args[index]
                fnLoc = get_ea_by_any(old_name)
                tag_string = TagGetTagSubstring(old_name)
                old_name = TagRemoveSubstring(old_name)
                new_name = string_between('', '_', old_name) + "_" + string_between('_', '', TagRemoveSubstring(idc.get_name(ea))) + tag_string
                # dprint("[debug] old_name, new_name")
                print("[debug] old_name:{}, new_name:{}".format(old_name, new_name))
                
                LabelAddressPlus(fnLoc, new_name, force=1)
            else:
                _rename_lvar(args[index], replace_subpatterns(name, args), ea, uniq=uniq, vu=vu)

    return fn_rename_lvar


def decompile_native(ea = None):
    ea = eax(ea)
    ea = GetFuncStart(ea)
    fnName = idc.get_name(ea);
    idc.SetType(ea, "void __fastcall func(native args);")
    idc.auto_wait()
    decompile_function_for_common_renames(ea)
    nn = get_latest_native_names(cacheOnly=1)
    fnNameSplit = string_between('', '_ACTUAL', fnName.upper(), retn_all_on_fail=1).replace('::', '__').split('__', maxsplit=1)
    if len(fnNameSplit) == 2:
        _bestMatch = None
        _bestLength = 9999
        namespace, name = fnNameSplit
        nameLen = len(name)
        for n in nn.values():
            n = SimpleAttrDict(n)
            _nnameLen = len(n.name)
            if name in n.name:
                _diffLen = _nnameLen - nameLen
                if _diffLen >= 0:
                    if _diffLen < _bestLength:
                        _bestLength = _diffLen
                        _bestMatch = n

        if _bestMatch:
            _params = ''
            for _p in _bestMatch.params:
                pn, pt = _p['name'], _p['type']
                pt = pt.replace('Vector', 'WVector')
                _params += "{} {}, ".format(pt, pn)
            _params = _params.rstrip(", ")
            Commenter(ea).add('[NATIVE PARAMS] {}'.format(_params))

            

    # SetFuncFlags(ea, lambda f: (f & ~0x22) | 0x10 )
    with Pseudocode(ea) as vu:
        rules = [
                #   v7 = args->pArgs;
                (wrap_compile(r'([::v::]) = args->pArgs'), 2, 
                    rename_lvar_factory(0, 'pArgs')),

                #  v1 = v7->p1.Any != 0;
                (wrap_compile(r'([::v::]) = \w+->(p\d+)\.\w+ != 0'), 3,
                    rename_lvar_factory((r'\1', None), type=('bool', None))),

        ]

        arrays = get_lvars(ea, vu=vu, tif_filter=lambda tif: tif.is_array())
        for array in arrays:
            tif = array.tif
            tif.remove_ptr_or_array()
            vu.set_lvar_type(array, tif)

        #  lines = decompile_function(ea)
        while True:
            lines = [ida_lines.tag_remove(x.line) for x in genAsList(vu.cfunc.get_pseudocode())]
            if not lines:
                print("return_unless: lines")
                return

            sti = CircularList(8)
            for line in lines:
                # print("line", line)
                sti.append(line)
                for rule in rules:
                    if isinstance(rule[0], list):
                        matches = sti.multimatch(rule[0])
                        if matches: print("line", "\nline ".join(sti.as_list()))
                    else:
                        matches = re.findall(rule[0], line)
                        if matches: print("\nline", line)
                    if matches:
                        print("match:  {}\ngroups: {}\nfnargs: {}".format(string_between('re.compile(\'', '\')', str(rule[0]), greedy=1), matches[0], rule[1]))
                    if matches and rule[2] and callable(rule[2]):
                        if rule[1]:
                            for g in reby_simple(rule[1], matches):
                                rule[2](*g, ea=ea, vu=vu)
                        else:
                            print("multimatch: {}".format(matches))
                            results = _.flatten([x for x in [x.groups() for x in matches] if x])
                            rule[2](*results, ea=ea, vu=vu)

                        continue
            break

def decompile_rand(ea = None):
    # https://docs.microsoft.com/en-us/search/?scope=Desktop&terms=GetCurrentProcess
    ea = eax(ea)
    ea = GetFuncStart(ea)
    fnName = idc.get_name(ea);
    # SetFuncFlags(ea, lambda f: (f & ~0x22) | 0x10 )
    with Pseudocode(ea) as vu:
        def rename_lvar_factory(*args, **kwargs):
            """
            @brief rename_lvar_factory

            @param indexes [optional,iterable] index(es) to use from array of names
            @param names [iterable] name(s) matched by (usually a regex)
            @param uniq [default:0] only perform replace once
            @param type [default:None]

            @return list of returns from set_lvar_type
            """
            # dprint("[debug] args, kwargs")

            nargs = dict()
            for arg in args:
                if len(nargs) in (0,):
                    if contents(arg, (int,)):
                        nargs['indexes'] = A(arg)
                if len(nargs) in (0,1):
                    if contents(arg, (str,)):
                        nargs['names'] = A(arg)
                        if 'indexes' not in nargs:
                            nargs['indexes'] = range(len(nargs['names']))

            nargs['uniq'] = 0
            nargs['type'] = None
            nargs.update(kwargs)
            from operator import itemgetter
            d = nargs

            indexes, names, types, uniq = itemgetter('indexes', 'names', 'type', 'uniq')(d)
            if types is None:
                types = [None] * len(names)
            elif isinstance(types, str):
                types = (types,)
            elif not isinstance(types, tuple):
                types = tuple(types)

            def fn_rename_lvar(*args):
                if len(args) > len(names):
                    skip_first = 1
                    print("args:   {}".format(args))

                    for r in range(1, len(args)):
                        if not args[r] in args[0]:
                            skip_first = 0
                    if skip_first:
                        args = args[1:]

                for index, name, _type in zip(indexes, names, types):
                    print('i,n,t: {}, {}, {}'.format(index, name, _type))
                    if _type is None and isinstance(name, str) and eax(args[index]):
                        old_name = args[index]
                        fnLoc = get_ea_by_any(old_name)
                        LabelAddressPlus(fnLoc, name)
                    if _type:
                        set_lvar_type(args[index], _type, ea, vu=vu)
                    if isinstance(name, int):
                        old_name = args[index]
                        fnLoc = get_ea_by_any(old_name)
                        tag_string = TagGetTagSubstring(old_name)
                        old_name = TagRemoveSubstring(old_name)
                        new_name = string_between('', '_', old_name) + "_" + string_between('_', '', TagRemoveSubstring(idc.get_name(ea))) + tag_string
                        # dprint("[debug] old_name, new_name")
                        print("[debug] old_name:{}, new_name:{}".format(old_name, new_name))
                        
                        LabelAddressPlus(fnLoc, new_name, force=1)
                    else:
                        _rename_lvar(args[index], name, ea, uniq=uniq, vu=vu)

            return fn_rename_lvar

        pattern_subs = [
                # v56 = data_2->rand_base64_decoded_len.MatchingBits & data_2->rand_base64_decoded_len.Key | data_2->rand_base64_decoded_len.NonMatchingBits & ~data_2->rand_base64_decoded_len.Key;
                # v57 = das                                          & data_2->rand_base64_decoded_len.Key | data_2->rand_base64_decoded_len.NonMatchingBits & ~data_2->rand_base64_decoded_len.Key;
                # v54 = data_2->rand_base64_decoded_len.MatchingBits & data_2->rand_base64_decoded_len.Key | dans_4                                          & ~data_2->rand_base64_decoded_len.Key;
                (wrap_compile(r'^\s+(v\d+) = .*(?:das\w*|MatchingBits) & .*Key \| .*(?:dans\w*|NonMatchingBits) & .*Key;'),                 2 , rename_lvar_factory(0, 'data')),
                #     v37 = base64_decoded_len & prngSeed;
                #     v38 = base64_decoded_len & ~prngSeed;

                (wrap_compile(r'^\s+(v\d+) = \w+ & prngSeed;'),                 2 , rename_lvar_factory(0, 'das')),
                (wrap_compile(r'^\s+(v\d+) = \w+ & ~prngSeed;'),                 2 , rename_lvar_factory(0, 'dans')),
                #     v34 = ~prngSeed;
                (wrap_compile(r'^\s+(v\d+) = ~prngSeed;'),                 2 , rename_lvar_factory(0, 'ns')),
                #  (wrap_compile(r'^\s+(v\d+) [\^]= \*[::static_cast::]*(\w+);'),                                       3 , fn_vortex_1),
                #  (wrap_compile(r'\b(o_|off_14[0-9A-F]{7})\b'),                                                        2 , fn_offset_1),
                #  (wrap_compile(r'\b(o_+\d*)\b'),                                                                      2 , fn_offset_1),
                #  (wrap_compile(r'^\s+if \( !([::v::]) && Zero \)'),                                                   1 , rename_lvar_factory(0, 'misdirection')),
                #  (wrap_compile(r'^\s+(\w+)\(ptr, ([::v::]), [::static_cast::]?([::v::])\);'),                         4 , rename_lvar_factory(('ArxanMemcpy', 'src', 'length'), type=(None, 'uint8_t*', 'uint32_t'), uniq=1)),
                #  (wrap_compile(r'^\s+(\w+)\(ptr, \w+, [::static_cast::]?\w+\);'),                                     3 , rename_lvar_factory(('ArxanMemcpy'), type=(None), uniq=1)),
                #  (wrap_compile(r'^\s+(v\d+) = 0i64;'),                                                                2 , rename_lvar_factory(0, '_align', uniq=1)),
                #  (wrap_compile(r'^\s+([::v::]) = [::pointer_cast::]ArxanCheckFunction_\w+ - [::pointer_cast::]\w+;'), 2 , rename_lvar_factory(0, 'Zero', uniq=1)),
                #  (wrap_compile(r'^\s+([::v::]) = \w+_\x+ ^ \*\(_DWORD \*\)([::v::]);'),                               3 , rename_lvar_factory(('buf', 'ciphered'), type=('uint32_t', 'uint32_t *'))),
                #  (wrap_compile(r'^\s+(dword_\x+) = \*\(_DWORD \*\)(\w+_1402FAE33);'),                                 3 , lambda all, dst, src: MakeDword(eax(src))),
                #  (wrap_compile(r'^\s+(dword_\x+) = (dword_\x+);'),                                                    3 , rename_lvar_factory(('arxan_done_dst_{}'.format(suffix), 'arxan_done_src_{}'.format(suffix)), type=(None, None))),
                #  (wrap_compile(r'^\s+(v\d+) = 0i64;'),                                                                2 , rename_lvar_factory(0, 'Zero', uniq=1)),
                #  (wrap_compile(r'^\s+([::v::]).start = 0;'),                                                          2 , rename_lvar_factory(0, 'range', uniq=1)),
                #  (wrap_compile(r'^\s+([::v::]) = &ImageBase\[range.start\];'),                                        2 , rename_lvar_factory(0, 'ptr')),
                #  (wrap_compile(r'^\s+(Zero|v\d+) (=) 1i64;'),                                                         2 , rename_lvar_factory(0, '_align', uniq=1)),
                #  (wrap_compile(r'^\s+(v\d+) = [::static_cast::]*\w+imagebase', re.I),                                 2 , rename_lvar_factory(0, 'ImageBase', type='uint8_t *', uniq=1)),
                #  # guide = (uint8_t *)&unk_1439B9746;
                #  (wrap_compile(r'^\s+(?:guide\w*) = [::reference_cast::]*(\w+);', re.I),                              2 , rename_lvar_factory(('guide_{}'.format(suffix)), type=(None))),
                #  (wrap_compile(r'^\s+(v\d+) = a1;'),                                                                  2 , rename_lvar_factory(0, '_arg_0', uniq=1)),
                #  (wrap_compile(r'^\s+if \((v\d+) == (24)\)'),                                                         2 , rename_lvar_factory(0, '_stack_padding', uniq=1)),
                #  (wrap_compile(r'^\s+if \((v\d+) == (24)\)'),                                                         2 , rename_lvar_factory(0, '_stack_padding', uniq=1)),
                #  (wrap_compile(r'([::v::]) = __ROL4__\(\2, ([::v::])\)'),                                             2 , rename_lvar_factory(('roll_amt', 'rolling_code') )),
                #  (wrap_compile(r'([::v::]) += rolling_code ^ roll_amt'),                                              1 , rename_lvar_factory(0, 'hash')),
                #  (wrap_compile(r'^\s+(\w+)\([::static_cast::]*&(\w+), [::static_cast::]*&(\w+)\);'),                  4 , rename_lvar_factory(('ArxanGetNextRange_{}'.format(suffix), 'guide', 'range'), type=(None, 'uint8_t*', 'arxan_range'), uniq=1)),
                #  (wrap_compile(r'^\s+(ArxanMemcpy[^(), ]+)\(&?(\w+), &?(\w+), &?(\w+)\);'),                           5 , rename_lvar_factory((ea, 'dst', 'p_B0', 'len'), uniq=1)),
                #  (wrap_compile(r'([::v::]) = [::reinterpet_cast::]ImageBase\[[::deref_static_cast::]([::v::])\]'),    3 , rename_lvar_factory(('acid_bath', 'acid_offset'), type=('uint64_t', 'uint32_t*'), uniq=1)),
                #  (wrap_pattern(r"""Zero = 0i64;
    #  ImageBase = .*
    #  .*_arg_0 \+ _align.*
    #  (v\d+) = [::static_cast::]*&?\w+;
    #  (v\d+) = [::static_cast::]*&(v\d+);
    #  (v\d+|p_B0) = [::static_cast::]*&(v\d+);
    #  (v\d+) = 0;
    #  (v\d+) = 0;""", split="\n"), 0, test_multimatch),

                # *(_QWORD *)GetCurrentProcess_0 = GetProcAddress(pKernel32, "GetCurrentProcess");
                #  (wrap_compile(r'\*\(_QWORD \*\)(\w\+) = GetProcAddress\((\w\+), "(\w\+)"\)')), 4, None),
                #  # NtQueryVirtualMemory = (__int64)GetProcAddress(v1, "NtQueryVirtualMemory");
                #  (wrap_compile(r'(\w\+) = \([^)]+\)GetProcAddress\((\w\+), "(\w\+)"\)')), 3, fn_process_handle_1),
                #  # GetModuleFileNameA_0 = (DWORD (__stdcall *)(HMODULE, LPSTR, DWORD))GetProcAddress(pKernel32, "GetModuleFileNameA");
                #  #  match1                  ^^ match2 ..........................  ^^                 ^match3      ^match4
                #  (wrap_compile(r'(\w+) = \(([^(]+\([^)]+\)[^)]+\))\)GetProcAddress\((\w+), "(\w+)"\)')), 4, None),
                #  # pKernel32 = GetModuleHandleA("kernel32.dll");
                #  (wrap_compile(r'(\w+) = GetModuleHandle[AW]?\("(\w+).dll"\);')), 2, fn_module_handle),
                #  # wrap_compile(r'')),
        ]

        while True:
            lines = [ida_lines.tag_remove(x.line) for x in genAsList(vu.cfunc.get_pseudocode())]
            if not lines:
                print("return_unless: lines")
                return

            sti = CircularList(8)
            for line in lines:
                # print("line", line)
                sti.append(line)
                for psub in pattern_subs:
                    if isinstance(psub[0], list):
                        matches = sti.multimatch(psub[0])
                        if matches: print("line", "\nline ".join(sti.as_list()))
                    else:
                        matches = re.findall(psub[0], line)
                        if matches: print("\nline", line)
                    if matches:
                        print("match:  {}\ngroups: {}\nfnargs: {}".format(string_between('re.compile(\'', '\')', str(psub[0]), greedy=1), matches[0], psub[1]))
                    if matches and psub[2] and callable(psub[2]):
                        if psub[1]:
                            for g in reby_simple(psub[1], matches):
                                psub[2](*g)
                        else:
                            print("multimatch: {}".format(matches))
                            results = _.flatten([x for x in [x.groups() for x in matches] if x])
                            psub[2](*results)

                        continue
            break


def decompile_arxan(ea = None):
    # https://docs.microsoft.com/en-us/search/?scope=Desktop&terms=GetCurrentProcess
    ea = eax(ea)
    ea = GetFuncStart(ea)
    fnName = idc.get_name(ea);
    idc.SetType(ea, "void __fastcall func(__int64 a1);")
    idc.auto_wait()
    # SetFuncFlags(ea, lambda f: (f & ~0x22) | 0x10 )
    with Pseudocode(ea) as vu:
        def fn_vortex_1(all, lhs, rhs):
            # dprint("[fn_vortex] dst, src")
            #  print("[fn_vortex] args:{}".format(a))
            #  return
            
            _rename_lvar(lhs, 'hash', ea, vu)
            _rename_lvar(rhs, 'vortex', ea, vu)

        def fn_offset_1(all, dst, *a):
            offLoc = get_ea_by_any(dst)
            if offLoc is None:
                # dprint("[fn_offset_1] dst, a")
                print("[fn_offset_1] dst:{}, a:{}".format(dst, a))
                
            deref = idc.get_qword(offLoc)
            # dprint("[deref] deref")
            print("[deref] deref:{} = {:x} = {:x}".format(dst, offLoc, deref))
            
            if deref == ida_ida.cvar.inf.min_ea:
                MemLabelAddressPlus(offLoc, 'o_imagebase')
                return
            ida_auto.plan_and_wait(deref, EndOfContig(deref))
            name = idc.get_name(deref)
            try:
                if not name or not IsCode_(deref):
                    ForceFunction(deref)
                    idc.auto_wait()
                    name = idc.get_name(deref)
            except AdvanceFailure:
                print("Invalid retn destination: {:x}".format(deref))
            MemLabelAddressPlus(offLoc, "o_" + name.lower())

        def rename_lvar_factory(*args, **kwargs):
            """
            @brief rename_lvar_factory

            @param indexes [optional,iterable] index(es) to use from array of names
            @param names [iterable] name(s) matched by (usually a regex)
            @param uniq [default:0] only perform replace once
            @param type [default:None]

            @return list of returns from set_lvar_type
            """
            # dprint("[debug] args, kwargs")

            nargs = dict()
            for arg in args:
                if len(nargs) in (0,):
                    if contents(arg, (int,)):
                        nargs['indexes'] = A(arg)
                if len(nargs) in (0,1):
                    if contents(arg, (str,)):
                        nargs['names'] = A(arg)
                        if 'indexes' not in nargs:
                            nargs['indexes'] = range(len(nargs['names']))

            nargs['uniq'] = 0
            nargs['type'] = None
            nargs.update(kwargs)
            from operator import itemgetter
            d = nargs
            # stmt = str(', '.join(d.keys())) + " = itemgetter(" + str(', '.join([repr(x) for x in d.keys()])) + ")(d)"
            # print("exec: {}".format(stmt))
            # rv = exec(stmt)
            # print("rv {}".format(rv))

            indexes, names, types, uniq = itemgetter('indexes', 'names', 'type', 'uniq')(d)
            if types is None:
                types = [None] * len(names)
            elif isinstance(types, str):
                types = (types,)
            elif not isinstance(types, tuple):
                types = tuple(types)

            def fn_rename_lvar(*args):
                if len(args) > len(names):
                    skip_first = 1
                    print("args:   {}".format(args))

                    for r in range(1, len(args)):
                        if not args[r] in args[0]:
                            skip_first = 0
                    if skip_first:
                        args = args[1:]

                for index, name, _type in zip(indexes, names, types):
                    print('i,n,t: {}, {}, {}'.format(index, name, _type))
                    if _type is None and isinstance(name, str) and eax(args[index]):
                        old_name = args[index]
                        fnLoc = get_ea_by_any(old_name)
                        LabelAddressPlus(fnLoc, name)
                    if _type:
                        set_lvar_type(args[index], _type, ea, vu=vu)
                    if isinstance(name, int):
                        old_name = args[index]
                        fnLoc = get_ea_by_any(old_name)
                        tag_string = TagGetTagSubstring(old_name)
                        old_name = TagRemoveSubstring(old_name)
                        new_name = string_between('', '_', old_name) + "_" + string_between('_', '', TagRemoveSubstring(idc.get_name(ea))) + tag_string
                        # dprint("[debug] old_name, new_name")
                        print("[debug] old_name:{}, new_name:{}".format(old_name, new_name))
                        
                        LabelAddressPlus(fnLoc, new_name, force=1)
                    else:
                        _rename_lvar(args[index], name, ea, uniq=uniq, vu=vu)

            return fn_rename_lvar

        def test_multimatch(*args):
            # dprint("[test_multimatch] args")
            print("[test_multimatch] args:{}".format(args))

        def test_multimatch(cipher_text, p_B4, B4, p_B0, B4a, B4b, remain):
            _rename_lvar(cipher_text, 'cipher_text', ea, vu)
            _rename_lvar(p_B4, 'p_B4', ea, vu)
            _rename_lvar(B4a, 'B4', ea, vu)
            _rename_lvar(p_B0, 'p_B0', ea, vu)
            _rename_lvar(remain, 'remain', ea, vu)


        suffix = re.sub(r'^[a-zA-Z]+', '', idc.get_name(ea))
        pattern_subs = [
                #  (wrap_compile(r'^\s+((?:ArxanGetNextRange|ArxanChecksumWorker)[^(), ]+)\([::static_cast::]*&(\w+), [::static_cast::]*&(\w+)\);') , 4 ,
                    #  rename_lvar_factory((ea, 'guide', 'range'), type=(None, 'uint8_t*', 'arxan_range'), uniq=1)),
                # v13 ^= *(unsigned __int8 *)i
                # v13 ^= *(unsigned __int8*)i;
                #[::static_cast::]*
                (wrap_compile(r'^\s+(v\d+) [\^]= \*[::static_cast::]*(\w+);'),                                       3 , fn_vortex_1),
                (wrap_compile(r'\b(o_|off_14[0-9A-F]{7})\b'),                                                        2 , fn_offset_1),
                (wrap_compile(r'\b(o_+\d*)\b'),                                                                      2 , fn_offset_1),
                (wrap_compile(r'^\s+if \( !([::v::]) && Zero \)'),                                                   1 , rename_lvar_factory(0, 'misdirection')),
                (wrap_compile(r'^\s+(\w+)\(ptr, ([::v::]), [::static_cast::]?([::v::])\);'),                         4 , rename_lvar_factory(('ArxanMemcpy', 'src', 'length'), type=(None, 'uint8_t*', 'uint32_t'), uniq=1)),
                (wrap_compile(r'^\s+(\w+)\(ptr, \w+, [::static_cast::]?\w+\);'),                                     3 , rename_lvar_factory(('ArxanMemcpy'), type=(None), uniq=1)),
                (wrap_compile(r'^\s+(v\d+) = 0i64;'),                                                                2 , rename_lvar_factory(0, '_align', uniq=1)),
                (wrap_compile(r'^\s+([::v::]) = [::pointer_cast::]ArxanCheckFunction_\w+ - [::pointer_cast::]\w+;'), 2 , rename_lvar_factory(0, 'Zero', uniq=1)),
                (wrap_compile(r'^\s+([::v::]) = \w+_\x+ ^ \*\(_DWORD \*\)([::v::]);'),                               3 , rename_lvar_factory(('buf', 'ciphered'), type=('uint32_t', 'uint32_t *'))),
                (wrap_compile(r'^\s+(dword_\x+) = \*\(_DWORD \*\)(\w+_1402FAE33);'),                                 3 , lambda all, dst, src: MakeDword(eax(src))),
                (wrap_compile(r'^\s+(dword_\x+) = (dword_\x+);'),                                                    3 , rename_lvar_factory(('arxan_done_dst_{}'.format(suffix), 'arxan_done_src_{}'.format(suffix)), type=(None, None))),
                (wrap_compile(r'^\s+(v\d+) = 0i64;'),                                                                2 , rename_lvar_factory(0, 'Zero', uniq=1)),
                (wrap_compile(r'^\s+([::v::]).start = 0;'),                                                          2 , rename_lvar_factory(0, 'range', uniq=1)),
                (wrap_compile(r'^\s+([::v::]) = &ImageBase\[range.start\];'),                                        2 , rename_lvar_factory(0, 'ptr')),
                (wrap_compile(r'^\s+(Zero|v\d+) (=) 1i64;'),                                                         2 , rename_lvar_factory(0, '_align', uniq=1)),
                (wrap_compile(r'^\s+(v\d+) = [::static_cast::]*\w+imagebase', re.I),                                 2 , rename_lvar_factory(0, 'ImageBase', type='uint8_t *', uniq=1)),
                # guide = (uint8_t *)&unk_1439B9746;
                (wrap_compile(r'^\s+(?:guide\w*) = [::reference_cast::]*(\w+);', re.I),                              2 , rename_lvar_factory(('guide_{}'.format(suffix)), type=(None))),
                (wrap_compile(r'^\s+(v\d+) = a1;'),                                                                  2 , rename_lvar_factory(0, '_arg_0', uniq=1)),
                (wrap_compile(r'^\s+if \((v\d+) == (24)\)'),                                                         2 , rename_lvar_factory(0, '_stack_padding', uniq=1)),
                (wrap_compile(r'^\s+if \((v\d+) == (24)\)'),                                                         2 , rename_lvar_factory(0, '_stack_padding', uniq=1)),
                (wrap_compile(r'([::v::]) = __ROL4__\(\2, ([::v::])\)'),                                             2 , rename_lvar_factory(('roll_amt', 'rolling_code') )),
                (wrap_compile(r'([::v::]) += rolling_code ^ roll_amt'),                                              1 , rename_lvar_factory(0, 'hash')),
                (wrap_compile(r'^\s+(\w+)\([::static_cast::]*&(\w+), [::static_cast::]*&(\w+)\);'),                  4 , rename_lvar_factory(('ArxanGetNextRange_{}'.format(suffix), 'guide', 'range'), type=(None, 'uint8_t*', 'arxan_range'), uniq=1)),
                (wrap_compile(r'^\s+(ArxanMemcpy[^(), ]+)\(&?(\w+), &?(\w+), &?(\w+)\);'),                           5 , rename_lvar_factory((ea, 'dst', 'p_B0', 'len'), uniq=1)),
                (wrap_compile(r'([::v::]) = [::reinterpet_cast::]ImageBase\[[::deref_static_cast::]([::v::])\]'),    3 , rename_lvar_factory(('acid_bath', 'acid_offset'), type=('uint64_t', 'uint32_t*'), uniq=1)),
                (wrap_pattern(r"""Zero = 0i64;
    ImageBase = .*
    .*_arg_0 \+ _align.*
    ({m}v\d+) = [::static_cast::]*&?\w+;
    ({m}v\d+) = [::static_cast::]*&({m}v\d+);
    ({m}v\d+|p_B0) = [::static_cast::]*&({m}v\d+);
    ({m}v\d+) = 0;
    ({m}v\d+) = 0;""", split="\n"), 0, test_multimatch), #  def test_multimatch({m}cipher_text, p_B4, B4, p_B0, B4a, B4b, remain):

                # *(_QWORD *)GetCurrentProcess_0 = GetProcAddress(pKernel32, "GetCurrentProcess");
                #  (wrap_compile(r'\*\(_QWORD \*\)(\w\+) = GetProcAddress\((\w\+), "(\w\+)"\)')), 4, None),
                #  # NtQueryVirtualMemory = (__int64)GetProcAddress(v1, "NtQueryVirtualMemory");
                #  (wrap_compile(r'(\w\+) = \([^)]+\)GetProcAddress\((\w\+), "(\w\+)"\)')), 3, fn_process_handle_1),
                #  # GetModuleFileNameA_0 = (DWORD (__stdcall *)(HMODULE, LPSTR, DWORD))GetProcAddress(pKernel32, "GetModuleFileNameA");
                #  #  match1                  ^^ match2 ..........................  ^^                 ^match3      ^match4
                #  (wrap_compile(r'(\w+) = \(([^(]+\([^)]+\)[^)]+\))\)GetProcAddress\((\w+), "(\w+)"\)')), 4, None),
                #  # pKernel32 = GetModuleHandleA("kernel32.dll");
                #  (wrap_compile(r'(\w+) = GetModuleHandle[AW]?\("(\w+).dll"\);')), 2, fn_module_handle),
                #  # wrap_compile(r'')),
        ]

        arrays = get_lvars(ea, vu=vu, tif_filter=lambda tif: tif.is_array())
        if isListlike(arrays):
            for array in arrays:
                tif = array.tif
                tif.remove_ptr_or_array()
                vu.set_lvar_type(array, tif)

        #  lines = decompile_function(ea)
        if not vu:
            print("no vu: {:#x}".format(ea))
            return
        while True:
            lines = [ida_lines.tag_remove(x.line) for x in vu.cfunc.get_pseudocode() if x]
            if not lines:
                print("return_unless: lines")
                return

            sti = CircularList(8)
            for line in lines:
                # print("line", line)
                sti.append(line)
                for psub in pattern_subs:
                    if psub[1] == 0 or isinstance(psub[0], list):
                        matches = sti.multimatch(psub[0])
                        if matches: 
                            print("multimatch line", "\nline ".join(sti.as_list()))
                            print("multimatch matches", matches)
                    else:
                        matches = re.findall(psub[0], line)
                        if matches: print("\nfindall line", line)
                    if matches and len(psub) > 1:
                        try:
                            print("match:  {}\ngroups: {}\nfnargs: {}".format(string_between('re.compile(\'', '\')', str(psub[0]), greedy=1), _.first(matches), psub[1]))
                        except KeyError:
                            # dprint("[keyError] psub, matches")
                            print("[keyError] psub:{}, matches:{}".format(psub, matches))
                            raise
                            
                    if matches and psub[2] and callable(psub[2]):
                        if psub[1]:
                            for g in reby_simple(psub[1], matches):
                                psub[2](*g)
                        else:
                            print("debug multimatch: {}, type({})".format(matches, type(matches)))
                            results = _.flatten([x for x in [x.groups() for x in matches] if x])
                            # results = [x for x in matches.default]
                            psub[2](*results)

                        continue
            break


def decompile_arxans(l):
    for ea in l:
        for r in range(4):
            if IsFuncStart(ea):
                decompile_arxan(ea)

def decompile_function_for_library_prologue_copies(ea):
    # https://docs.microsoft.com/en-us/search/?scope=Desktop&terms=GetCurrentProcess

    ea = GetFuncStart(ea)
    fnName = idc.get_name(ea);

    def wrap_pattern(pattern):
        pattern = pattern.replace(r'\x', r'[0-9a-fA-F]').replace(r'\w\+', r'\w+')
        new_pattern = r'(^\s+' + pattern.rstrip(';') + r';|\(' + pattern.rstrip(';') + r'\))'
        if debug: print('wrap_pattern: {}'.format(new_pattern))
        return new_pattern


    def fn_prologue_sample(sample_loc, source_ptr):
        LabelAddressPlus(get_ea_by_any(sample_loc), "prologue_%s" % source_ptr)

    def fn_process_handle_1(dst, module, source_ptr):
        LabelAddressPlus(get_ea_by_any(dst), "p%s" % source_ptr)

    def fn_module_handle(lv, module_name):
        _rename_lvar(lv, "ptr_%s" % module_name, ea)


    pattern_subs = [
            #  qword_142D3B4A0 = *(_QWORD *)LocalFree_0;
            (wrap_compile(r'(qword_\x+|o[A-Z]\w+) = \*\(_QWORD\s?\*\)(\w\+);'), 3, fn_prologue_sample),
            # *(_QWORD *)GetCurrentProcess_0 = GetProcAddress(pKernel32, "GetCurrentProcess");
            (wrap_compile(r'\*\(_QWORD \*\)(\w\+) = GetProcAddress\((\w\+), "(\w\+)"\)'), 5, None),
            # NtQueryVirtualMemory = (__int64)GetProcAddress(v1, "NtQueryVirtualMemory");
            (wrap_compile(r'(\w\+) = \([^)]+\)GetProcAddress\((\w\+), "(\w\+)"\)'), 4, fn_process_handle_1),
            # GetModuleFileNameA_0 = (DWORD (__stdcall *)(HMODULE, LPSTR, DWORD))GetProcAddress(pKernel32, "GetModuleFileNameA");
            #  match1                  ^^ match2 ..........................  ^^                 ^match3      ^match4
            (wrap_compile(r'(\w+) = \(([^(]+\([^)]+\)[^)]+\))\)GetProcAddress\((\w+), "(\w+)"\)'), 5, None),
            # pKernel32 = GetModuleHandleA("kernel32.dll");
            (wrap_compile(r'(\w+) = GetModuleHandle[AW]?\("(\w+).dll"\);'), 3, fn_module_handle),
            # wrap_compile(r'')),
    ]

    lines = decompile_function(ea)
    if not lines:
        print("return_unless: lines")
        return

    for line in lines:

        for psub in pattern_subs:
            matches = re.findall(psub[0], line)
            if matches:
                print("line", line)
                print("matched {}".format(psub[0]))
            if matches and psub[2] and callable(psub[2]):
                for g in reby(psub[1], matches):
                    psub[2](*g)

counter = 0
def decompile_shv_nativeInit(ea):
    # LABEL_124:
    #         v49 = 0;
    #         v50 = qword_180095550;
    #         while ( *v50 != nativeHash )
    #         {
    #           ++v49;
    #           v50 += 2;
    #           if ( (unsigned __int64)v49 >= 0x151E )
    #             goto LABEL_130;
    #         }
    #         if ( qword_180095550[2 * v49 + 1] )
    #           nativeHash = qword_180095550[2 * v49 + 1];
    # LABEL_130:

    def get_versions():
        versions = ["VER_STEAM_ORI", "VER_NOSTEAM_ORI"]
        version_strings_ea = ProtectScan("15 ?? ?? ?? ?? 48 8d 05").add(-0x2 + 0xa).rip(4).ea()
        while True:
            s = idc.get_strlit_contents(idc.get_qword(version_strings_ea), -1, idc.STRTYPE_C)
            if s and s.startswith(b'VER_'):
                print("version: {}".format(asString(s)))
                versions.append(asString(s))
                version_strings_ea += 8
            else:
                return versions



    ea = GetFuncStart(ea)
    fnName = idc.get_name(ea);
    vu = get_pseudocode_vu(ea, None)
    versions = get_versions()

    def fn_native_group(m, ea, vu):
        global counter
        #  v50
        #  180095550
        #  v49
        #  LABEL_130
        if True: # This is very slow
            if counter == 0:
                if m['ptr'].startswith("v"):
                    _rename_lvar(m['ptr'], "ptr", ea, vu=vu)
                if m['counter'].startswith("v"):
                    _rename_lvar(m['counter'], "counter", ea, vu=vu)
                if m['index'].startswith("v"):
                    _rename_lvar(m['counter'], "index", ea, vu=vu)
            else:
                if m['ptr'].startswith("v"):
                    map_lvar(m['ptr'], "ptr", ea, vu=vu)
                if m['counter'].startswith("v"):
                    map_lvar(m['counter'], "counter", ea, vu=vu)
                if m['index'].startswith("v"):
                    map_lvar(m['index'], "index", ea, vu=vu)

        print("counter: {} {}".format(counter, int(m[4], 0)))
        counter += 1
    


    pattern_subs = [
        #  (re.compile(
            #  r"""((?:v\d+)) = qword_([0-9a-fA-F]+);\s+while \(\*\1 != nativeHash\)\s+{\s+\+\+((?:v\d+));\s+\1 \+= 2;\s+if \((?:\([^)]+\))\3 >= (?:(?:0x)?[0-9a-fA-F]+)\)\s+goto (LABEL_\d+);\s+}\s+if \(qword_\2\[2 \* \3 \+ 1]\)\s+nativeHash = qword_\2\[2 \* \3 \+ 1];""", re.S), 
            #  fn_native_group
        #  ),
        #  (re.compile(
            #  r"""(v\d+) = &?\w+_([0-9a-fA-F]+);\s+while \( \*\1 != nativeHash \)\s+{\s+\+\+(v\d+);\s+\1 \+= 25;\s+if \( (v\d+) >= ([0-9a-fA-Fx]+) \)\s+goto (LABEL_\d+);\s+}\s+(v\d+) = 25i64 \* \4;\s+if \( \w+_([0-9a-fA-F]+)\[\7 \+ (\d+)\] \)\s+nativeHash = \w+_([0-9a-fA-F]+)\[\7 \+ (\d+)\];""", re.S), 
            #  fn_native_group
        #  ),
        #  (re.compile(
            #  r"""(\w+) = &?\w+_([0-9a-fA-F]+);\s+while \( \*\1 != nativeHash \)\s+{\s+\+\+(\w+);\s+\1 \+= 25;\s+if \( \3 >= ([0-9a-fA-Fx]+) \)\s+goto (LABEL_\d+);\s+}\s+(\w+) = 25i64 \* \3;\s+if \( \w+_([0-9a-fA-F]+)\[\6 \+ (\d+)\] \)\s+nativeHash = \w+_([0-9a-fA-F]+)\[\6 \+ \8\];""", re.S), 
            #  fn_native_group
        #  )
        
        # """
        #     [
        #       [
        #         { "groupNum": 1, "groupName": "ptr",         "content": "v375"       },
        #         { "groupNum": 2, "groupName": "nativehash",  "content": "nativeHash" },
        #         { "groupNum": 3, "groupName": "counter",     "content": "v332"       },
        #         { "groupNum": 4, "groupName": "mapcount",    "content": "25"         },
        #         { "groupNum": 5, "groupName": "nativecount", "content": "0x190E"     },
        #         { "groupNum": 6, "groupName": "nextlabel",   "content": "LABEL_739"  },
        #         { "groupNum": 7, "groupName": "index",       "content": "v376"       },
        #         { "groupNum": 8, "groupName": "hashlist",    "content": "18002E8A0"  },
        #         { "groupNum": 9, "groupName": "offset",      "content": "15"         }
        #       ]
        #     ]
        # """
        (re.compile(
            r"""
                (?P<ptr>\w+) \s = \s &?\w+_(?:[0-9a-fA-F]+)(?:\[\d+\])?; \s+ 
                while \s \( \s \*(?P=ptr) \s != \s (?P<nativehash>\w+) \s \) \s+ 
                { \s+ \+\+(?P<counter>\w+); \s+ 
                    (?P=ptr) \s \+= \s (?P<mapcount>\d+); \s+ 
                    if \s \( \s (?P=counter) \s >= \s (?P<nativecount>[0-9a-fA-Fx]+) \s \) \s+ 
                        goto \s (?P<nextlabel>LABEL_\d+); \s+ 
                } \s+ (?P<index>\w+) \s = \s (?P=mapcount)(?:i64)? \s \* \s (?P=counter); \s+ 
                if \s \( \s \w+_(?P<hashlist>[0-9a-fA-F]+)\[(?P=index) \s \+ \s (?P<offset>\d+)\] \s \) \s+ 
                    (?P=nativehash) \s = \s \w+_(?P=hashlist)\[(?P=index) \s \+ \s (?P=offset)\];
            """, re.VERBOSE), fn_native_group)
    ]

    #  lines = "\n".join(decompile_function(ea))
    lines = str(get_cfunc_by_any(ea))
    if not lines:
        print("return_unless: lines")
        return

    for psub in pattern_subs:
        for matches in re.finditer(psub[0], lines):
            print("matched {}".format(matches[0]))
            if matches and psub[1] and callable(psub[1]):
                psub[1](matches, ea, vu)

def dump_shv(ea=0x18002E8A0, natives=6414, groups=25):
    """ get location, native count and groups from `nativeInit` 

        ptr = &qword_18002E920;
        while ( *ptr != nativeHash )
        {
          ++smth;
          ptr += 25;
          if ( smth >= 6414 )
            goto LABEL_1647;
        }
        v835 = 25i64 * smth;
        if ( qword_18002E8A0[v835 + 17] )
          nativeHash = qword_18002E8A0[v835 + 17];
    """
    builds = [ 335, 350, 372, 393, 463, 505, 573, 617, 678, 757, 791, 877, 944,
               1032, 1103, 1180, 1290, 1365, 1493, 1604, 1737, 1868, 2060, 2245,
               2372 ]
    l = defaultdict(list)
    ptr = ea
    for n in range(natives):
        for g in range(groups):
            l[g].append(idc.get_qword(ptr))
            ptr += 8
    for i, g in l.items():
        file_put_contents('hashmap-{:04}.txt'.format(builds[i]), 
                '\n'.join(["0x{:016X}".format(x) for x in g]))

    return l


def decompile_function_xrefs_for_common_renames(func):
    with BatchMode(1):
        for e in idautils.CodeRefsTo(get_ea_by_any(func), 1):
            decompile_function_for_common_renames(e)

from idaapi import *
def get_func_args(funcea=None):
    """
    get_func_args per https://reverseengineering.stackexchange.com/a/8876/16770

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        print("not func")
        return 0
    else:
        funcea = func.start_ea

    tif = idaapi.tinfo_t()
    if idaapi.get_tinfo(tif, funcea):
        funcdata = idaapi.func_type_data_t()
        if tif.get_func_details(funcdata):
            size = funcdata.size()
            # dprint("[debug] size")
            print("[get_func_args] size:{}".format(size))
            results = []
            
            for i in range(size):
                print("Arg %d: %s (of type %s, and of location: %s)" % (i, funcdata[i].name, print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''), funcdata[i].argloc.atype()))
                # t = tif.copy()
                # t.remove_ptr_or_array()
                # t.clr_const()
                results.append((funcdata[i].type.copy(), funcdata[i].name))
            return results
        else: print("tif.get_func_details failed")
    else: print("get_tinfo failed")

def get_func_args_lame(funcea=None):
    cfunc = decompile_function_as_cfunc(eax(funcea))
    func_tinfo = idaapi.tinfo_t()
    cfunc.get_func_type(func_tinfo)

    nargs = func_tinfo.get_nargs()
    for i in range(0, nargs):
        print("{} {}".format(cfunc.lvars[i].tif, cfunc.lvars[i].name))

def FuncGuessType(funcea=None):
    """
    FuncGuessType

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [FuncGuessType(x) for x in funcea]

    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    if not idc.get_type(funcea):
        decomp = decompile_function(funcea)[0]
        SetType(funcea, decomp)

    return idc.get_type(funcea)
    
    
#  def paren_split(subject, separator=",", lparen="(", rparen=")", strip=" "):
    #  # https://stackoverflow.com/questions/42070323/split-on-spaces-not-inside-parentheses-in-python/42070578#42070578
    #  nb_brackets=0
    #  subject = subject.strip(strip or separator) # get rid of leading/trailing seps
#  
    #  l = [0]
    #  for i, c in enumerate(subject):
        #  if c == lparen:
            #  nb_brackets += 1
        #  elif c == rparen:
            #  nb_brackets -= 1
        #  elif c == separator and nb_brackets == 0:
            #  l.append(i + 1) # skip seperator
        #  # handle malformed string
        #  if nb_brackets < 0:
            #  raise Exception("Syntax error (unmatch rparen)")
#  
    #  l.append(len(subject))
    #  # handle missing closing parentheses
    #  if nb_brackets > 0:
        #  raise Exception("Syntax error (unmatched lparen)")
#  
#  
    #  return([subject[i:j].strip(strip or separator) for i, j in zip(l, l[1:])])
#  
#  def escape_backslash(subject, position):
    #  c = subject[position]
    #  last_escape = next_escape = None
    #  previous_escapes = 0
    #  p = position
    #  last_escape = subject.rfind('\\', 0, p)
    #  while ~last_escape and last_escape == p - 1:
        #  previous_escapes += 1
        #  p -= 1
        #  last_escape = subject.rfind('\\', 0, last_escape)
#  
    #  
    #  # dprint("[last_] last_escape, next_escape")
    #  #  print("[escape_backslash] {} s:'{}' last_escape:{}, previous_escapes:{}".format(position, subject[0:position+1], last_escape, previous_escapes))
#  
    #  return (previous_escapes % 2) != 0
                    #  
#  def paren_multisplit(subject, separator=",", lparen="([{'\"", rparen=[")", "]", "}", "'", '"'], strip=None, escape=escape_backslash):
    #  s = r"""POP {DUP {DUP (2) INDEX [2] \} } (7) }"""
    #  s = r"""POP {DUP {DUP (2) INDEX [2] } } (7)"""
    #  s = r"""POP\ {DUP {DUP (2) INDEX [2] } } (7)"""
    #  s = r"""POP\ {DUP {DUP (2) INDEX [\{2\}] } } (7)"""
    #  s = r"""POP\ {DUP {DUP (2) INDEX [\{2] } } (7)"""
#  
    #  # https://stackoverflow.com/questions/42070323/split-on-spaces-not-inside-parentheses-in-python/42070578#42070578
    #  lparen = list(lparen)
    #  rparen = list(rparen)
    #  paren_len = len(lparen)
    #  if len(rparen) != paren_len:
        #  raise Exception("len(rparen) != len(lparen)")
    #  brackets=[0] * paren_len
    #  stack = []
#  
    #  subject = subject.strip(strip or separator) # get rid of leading/trailing seps
#  
    #  l = [0]
    #  for i, c in enumerate(subject):
        #  if c in lparen and not escape(subject, i):
            #  index = lparen.index(c)
            #  brackets[index] += 1
            #  stack.append(c)
        #  elif c in rparen and not escape(subject, i):
            #  index = rparen.index(c)
            #  brackets[index] -= 1
            #  if brackets[index] < 0:
                #  raise Exception("Syntax error (unbalanced '{}' at '{}')".format(c, subject[0:i+1]))
            #  if stack[-1] != lparen[index]:
                #  raise Exception("Syntax error (unbalanced '{}' stack: '{}')".format(c, stack))
            #  stack.pop()
        #  elif c == separator and sum(brackets) == 0 and not escape(subject, i):
            #  l.append(i + 1) # skip seperator
        #  # handle malformed string
        #  if _.any(brackets, lambda x, *a: x < 0):
            #  raise Exception("Syntax error (unmatch rparen)")
#  
    #  l.append(len(subject))
    #  # handle missing closing parentheses
    #  if _.any(brackets, lambda x, *a: x < 0):
        #  raise Exception("Syntax error (unmatch rparen) final")
    #  elif _.any(brackets, lambda x, *a: x < 0):
        #  raise Exception("Syntax error (unmatch lparen) final")
#  
    #  return([subject[i:j].strip(strip or separator) for i, j in zip(l, l[1:])])


def get_decl_args(decl):
    #  check_for_update()

    # strings tilib.exe | grep __
    # __array_ptr __bad_cc __builtin_va_list __cdecl __closure __clrcall
    # __const__ __cplusplus __cppobj __declspec __export __far __fastcall
    # __gnuc_va_list __hidden __high __huge __imp_ __import __interrupt __near
    # __noreturn __org_arrdim __org_typedef __pascal __pure __restrict
    # __return_ptr __seg __spoils __stdcall __struct_ptr __thiscall __thread
    # __unaligned __unnamed __usercall __userpurge __va_list_tag 

    # get_decl_args('void __fastcall(__int64 a1, void (__fastcall ***a2)(_QWORD, __int64))')
    #  void __fastcall(
            #  __int64 a1, void (__fastcall ***a2)(_QWORD, __int64)
        #  )
    # regex = r"(.*?) ?(__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge)? ?([^* ]*?)\((.*)\)"
    # regex = r"(.*?) ?((\(__fastcall \*+[^ )]+\))|(__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge)? ?([^* ]*?))\((.*)\)"
    # regex = r"(.*?) ?((\((?:(?:__\w+ ?)*)\*+[^ )]+\))|(?:(?:__\w+ ?)*)?([^* ]*?))\((.*)\)"
    # regex = r"(.*?) ?((\(__\w+ \*+(\w*)\))\((.*)\))|((__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge)? ?([^* ]*?))\((.*)\)"
    # regex = r"(.*?) ?((\((?:(?:__\w+ ?)*)\*+[^ )]*\))|(?:(?:__\w+ ?)*)?([^* ]*?))\((.*)\)"
    # https://regex101.com/r/KZK0x7/1
    regex = r"(.*?) ?(?:(\((?:(?:__[a-z]+ ?)*)\*+[^ )]*\))|(?:(?:__[a-z]+ ?)*)?([^* ]*?))(\(.*\))"

    # Python>idc.get_type(eax('SetSomeCrashFunction'))
    # __int64 (*__fastcall(__int64 (*a1)(void)))(void)
    # __int64 (*__fastcall(__int64 (*a1)(void)))(void)
    # [get_decl_args] decl:__int64 (*__fastcall(__int64 (*a1)(void)))(void)
    # ('__int64', '', '', '(*__fastcall(__int64 (*a1)(void)))(void)')
    # [get_decl_args] returnType:__int64, fnPtr:, fnName:, fnArgs:(*__fastcall(__int64 (*a1)(void)))(void)

    if debug: print("[get_decl_args] {}".format(decl))
    while True:
        failed = []
        # dprint("    [get_decl_args] decl")
        #  returnType:, callTypeAndName:, fnName:void, fnArgs:__int64 a1, ... 
        re_res = None
        if debug: print("    [get_decl_args] re.findall({})".format(regex))
        for found in re.findall(regex, decl):
            for x, y in zip(["returnType", "fnPtr", "fnName", "fnArgs"], found):
                if debug: print("        [get_decl_args] {:12} {}".format(x + ':', y or '(none)'))


            re_res = found
            break
            # '__int64', '', 'au_re_rand_8', '(__int64 a1)'
        if re_res:
            returnType, fnPtr, fnName, fnArgs = re_res
            # dprint("    [get_decl_args] returnType, callTypeAndName, fnPtr, fnName, fnArgs")
            #  print("    [get_decl_args] returnType:{}, fnPtr:{}, fnName:{}, fnArgs:{}".format(returnType, fnPtr, fnName, fnArgs))
            
            if fnName and not returnType:
                fnName, returnType = returnType, fnName

            if fnPtr:
                print("    We have a void (__fastcall *name)(__int64 a1, ...) situation...")
                decl = "{} {}{}".format(returnType, string_between('*', ')', fnPtr).strip('*'), fnArgs)
                continue

            # remove wrapping brackets around args
            if fnArgs.endswith('()'):
                fnArgs = fnArgs[0:-2]
            fnArgs = fnArgs[1:-1]
            
            #  print("    [get_decl_args] paren_split('{}')".format(fnArgs))
            try:
                args = paren_multisplit(fnArgs, ",")
            except Exception:
                failed = _.uniq(failed)
                if 'void' in failed:
                    failed.remove('void')
                if '...' in failed:
                    failed.remove('...')
                return failed

            # TODO: move out the splitting part to allow re-entrancy
            arglist = []
            for arg in args:
                arg = arg.strip()
                if not arg:
                    continue
                # dprint("        [debug] arg")
                if debug: print("    [get_decl_args] {}".format(arg))
                
                if '(' in arg:
                    continue
                stars = ''
                lhs = string_between('', ' ', arg, greedy=1).replace('__struct_ptr', '').replace('__hidden', '').strip()
                rhs = string_between('', ' ', arg, greedy=1, repl='').strip()
                if rhs and not lhs:
                    lhs, rhs = rhs, lhs
                while rhs and rhs[0] in ('*', '&'):
                    stars += rhs[0]
                    rhs = rhs[1:]
                while lhs and lhs[-1] in ('*', '&'):
                    stars += lhs[-1]
                    lhs = lhs[0:-1]

                lhs = lhs.replace('const', '')

                lhs = lhs.strip()
                rhs = rhs.strip()

                # dprint("            [get_decl_args] lhs, stars, rhs")
                #
                for x, y in zip(["type", "indirection", "name"], [lhs, stars, rhs]):
                    if debug: print("        [get_decl_args] {:12} {}".format(x + ':', y or '(none)'))

                if get_tinfo_by_parse(lhs):
                    # dprint("            [tinfo-ok] lhs")
                    if debug: print("        [get_decl_args] [tinfo-ok] lhs:{}".format(lhs))
                else:
                    # dprint("            [tinfo-ok] lhs")
                    if debug: print("        [get_decl_args] [tinfo-fail] lhs:{}".format(lhs))
                    failed.append(lhs)
            stars = ''
            while returnType and returnType[-1] == '*':
                stars += returnType[-1]
                returnType = returnType[0:-1]
            returnType = returnType.strip()
            if not get_tinfo_by_parse(returnType):
                    # dprint("    [tinfo-ok] returnType")
                    if debug: print("    [get_decl_args] [tinfo-fail] returnType: {}".format(returnType))
                    failed.append(returnType)

        break

    failed = _.uniq(failed)
    if 'void' in failed:
        failed.remove('void')
    if '...' in failed:
        failed.remove('...')
    return failed

def get_ctree_item_t_var(vu, name):
    cfunc = vu.cfunc
    su = cfunc.pseudocode
    for y, i in enumerate(su):
        line = ida_lines.tag_remove(i.line)
        m = re.search(r'\b' + re.escape(name) + r'\b', line)
        if m:
            #  for x in range(0, len(i.line)):
            x = m.span(0)[0]
            phead = ctree_item_t()
            ptail = ctree_item_t()
            pitem = ctree_item_t()
            if cfunc.get_line_item(i.line, x, 1, phead, ptail, pitem):
                if phead.e:
                    print('he: {}'.format(phead.e))
                if pitem.e:
                    print('ie: {}'.format(pitem.e))
                if ptail.e:
                    print('te: {}'.format(ptail.e))
                #  print('line: {}'.format(line))
                lvar = ptail.get_lvar()
                if lvar:
                    print('name: {}'.format(lvar.name))
                    # index = list(cfunc.get_lvars()).index(lvar)
                    # result = VariableObject(lvar, index)
                    if ptail.e:
                        print('e: {}'.format(ptail.e))
                    else:
                        print('no e')

                if ptail.citype == idaapi.VDI_EXPR:
                    print("everything is a go")
                    return ptail
                #  else:
                    #  print('citype == {}'.format(ptail.citype))
            
retrace_me = []
def scan_variable(name, ea, vu=None, regex=False):
    global retrace_me
    if regex:
        try:
            m = decompile_function_search(name, ea)
        except ida_hexrays.DecompilationFailure:
            retrace_me.append(ea)
            return
        if m:
            name = m.groups()[-1]
        else:
            print("couldn't match regex: {}".format(name))
            return

    vu = get_pseudocode_vu(ea, vu)
    set_lvar_type(name, 'uintptr_t', ea, vu=vu)
    m = sys.modules['HexRaysPyTools']
    widget = vu.ct
    # widget = ida_kernwin.find_widget('Pseudocode-AU') 
    ctx = SimpleAttrDict({'widget': widget})
    #  vu = ida_hexrays.get_widget_vdui(widget)
    item = get_ctree_item_t_var(vu, name)
    if item:
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        hx_view.item = item
        for action_index in [-9, -8]:
            o = m.callbacks.action_manager._ActionManager__actions[action_index]
            o.activate(ctx)
        return True
    else:
        print("couldn't find item '{}'".format(name))

  # usage:
  # ll = GetFuncStart(xrefs_to(LocByAnyName('g_pool_CEventNetwork')))
  # for ea in ll: scan_variable(r'\s\s(v\d+) = .*g_pool_CEventNetwork', ea, None, True)
  #

def close_windows():
    for w in ['Functions', 'Names', 'Strings', 'Patched bytes', 'Local Types']:
        widget = ida_kernwin.find_widget(w + ' window') or ida_kernwin.find_widget(w)
        if widget:
            print("closing %s tab to increase performance" % w)
            ida_kernwin.close_widget(widget, 0)
    for w in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'AA', 'AB', 'AC', 'AD', 'AE', 'AF', 'AG', 'AH', 'AI', 'AJ', 'AK',
            'AL', 'AM', 'AN', 'AO', 'AP', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AV',
            'AW', 'AX', 'AY', 'AZ', 'BA', 'BB', 'BC', 'BD', 'BE', 'BF', 'BG',
            'BH', 'BI', 'BJ', 'BK', 'BL', 'BM', 'BN', 'BO', 'BP', 'BQ', 'BR',
            'BS', 'BT', 'BU', 'BV', 'BW', 'BX', 'BY', 'BZ', 'CA', 'CB', 'CC',
            'CD', 'CE', 'CF', 'CG', 'CH', 'CI', 'CJ', 'CK', 'CL', 'CM', 'CN',
            'CO', 'CP', 'CQ', 'CR', 'CS', 'CT', 'CU', 'CV', 'CW', 'CX', 'CY',
            'CZ' ]:
        widget = ida_kernwin.find_widget('Pseudocode-' + w)
        if widget:
            print("closing %s tab to increase performance" % w)
            ida_kernwin.close_widget(widget, 0)

def hx_set_user_cmt(ea=None, cmt=None, itp=idaapi.ITP_BLOCK1):
    """
    hx_set_user_cmt

    see: https://reverseengineering.stackexchange.com/a/12891/16770

    @param ea: linear address
    @param cmt: comment (string)
    @param itp: ITP_EMPTY ITP_ARG1 ITP_ARG64 ITP_BRACE1 ITP_INNER_LAST ITP_ASM
        ITP_ELSE ITP_DO ITP_SEMI ITP_CURLY1 ITP_CURLY2 ITP_BRACE2 ITP_COLON
        ITP_BLOCK1 ITP_BLOCK2 ITP_CASE ITP_SIGN
    """
    if ea is None and cmt is not None:
        if not eax(ea):
            ea, cmt = cmt, ea

    if isinstance(ea, list):
        return [hx_set_user_cmt(x) for x in ea]

    ea = eax(ea)
    cfunc = idaapi.decompile(ea)
    tl = idaapi.treeloc_t()
    tl.ea = ea
    tl.itp = itp
    if cmt:
        cfunc.set_user_cmt(tl, cmt)
        cfunc.save_user_cmts() 
    elif cmt is None:
        return cfunc.get_user_cmt(tl, True)
    elif cmt == "":
        cfunc.set_user_cmt(tl, cmt)
        cfunc.save_user_cmts() 

def remove_prng_seeds():
    for ea in FindInSegments('8b 05 ?? ?? ?? ?? 69 c0 fd 43 03 00 44 01 e8 89 05 ?? ?? ?? ??'):
        PatchNops(ea, 21)
        nassemble(ea, 'call PrngNext', apply=1)
    for ea in FindInSegments('8b 0d ?? ?? ?? ?? 69 c9 fd 43 03 00 44 01 e9 89 0d ?? ?? ?? ??'):
        PatchNops(ea, 21)
        nassemble(ea, 'call PrngNext; mov ecx, eax', apply=1)

    """
    PrngNext: 
        push r13
        mov r13d, 0x269ec3
        mov eax, [rel prngSeed]
        imul eax, eax, 0x343fd
        add eax, r13d
        pop r13
        mov [rel prngSeed], eax
        retn
    """


