import re
from itertools import islice

import ida_hexrays
import idaapi
import idautils
import idc


def map_lvar(src, dst, ea):
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
        vu = idaapi.open_pseudocode(ea, 0)

        lvars1 = [n for n in vu.cfunc.lvars if n.name == src]
        lvars2 = [n for n in vu.cfunc.lvars if n.name == dst]
        if len(lvars1) == 1 and len(lvars2) == 1:
            print("mapping {} to {}".format(lvars1[0].name, lvars2[0].name))
            # we might need to change the lvar type?
            vu.set_lvar_type(lvars1[0], lvars2[0].type())
            vu.map_lvar(lvars1[0], lvars2[0])
        else:
            print("couldn't find one of the vars {} or {}".format(src, dst))


def rename_lvar(src, dst, ea):
    def make_unique_name(name, taken):
        if name not in taken:
            return name
        fmt = "%s_%%i" % name
        for i in range(3, 1024):
            tmpName = fmt % i
            if tmpName not in taken:
                return tmpName
        return "i_give_up"

    #  if you want to use an existing view:
    #      widget = ida_kernwin.find_widget('Pseudocode-Y')
    #      vu = ida_hexrays.get_widget_vdui(widget)
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
        vu = idaapi.open_pseudocode(ea, 0)
        names = [n.name for n in vu.cfunc.lvars]
        if dst in names:
            dst = make_unique_name(dst, names)
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("renaming {} to {}".format(lvars[0].name, dst))
            vu.rename_lvar(lvars[0], dst, 1)
            # how to close the view without a widget object?
            #     idautils.close_pseudocode (nope)
            #     ida_kerwin.close_widget   (nope)
        else:
            print("couldn't find var {}".format(src))


def set_lvar_type(src, t, ea):
    #  t = ('', '\n=\x04#\x86U', '')
    #  ti = idaapi.tinfo_t()
    #  ti.deserialize(None, t[0], t[1])
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
        vu = idaapi.open_pseudocode(ea, 0)
        #  names = [n.name for n in vu.cfunc.lvars]
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("changing type of {} to {}".format(lvars[0].name, t))
            vu.set_lvar_type(lvars[0], t)
        else:
            print("couldn't find var {}".format(src))


def get_func_rettype(ea):
    def decompile_function_as_cfunc(address):
        try:
            cfunc = idaapi.decompile(address)
            if cfunc:
                return cfunc
        except idaapi.DecompilationFailure:
            pass
        print("IDA failed to decompile function at 0x{address:08X}".format(address=address))

    cfunc = decompile_function_as_cfunc(ea)
    func_tinfo = idaapi.tinfo_t()
    cfunc.get_func_type(func_tinfo)
    rettype = func_tinfo.get_rettype()
    return rettype


def stripped_lines(source_code):
    result = list()

    lines = str(source_code).split("\n")
    for line in lines:
        s = line.strip()
        if len(s) == 0:
            continue
        result.append(s)

    return result


def decompile_function(ea):
    try:
        d = str(ida_hexrays.decompile(ea))
    except ida_hexrays.DecompilationFailure:
        print("Couldn't decompile function: %s" % hex(ea))
        return None
    return d.split("\n")
    # e = clangformat(d)
    # f = r.split("\n")
    # return f


def reby(chunk_size, matches):
    """ helper function for chunking regex 
    matches with multiple alternatives
    """

    def chunk_tuple(it, size):
        """Yield successive n-sized tuples from lst."""
        it = iter(it)
        return iter(lambda: tuple(islice(it, size)), ())

    if matches:
        for match in matches:
            match = match[1:]
            for item in chunk_tuple(match, chunk_size):
                if item[0]:
                    yield item


def decompile_function_for_common_renames(ea, recurse=0, parents=[]):
    if recurse < 0:
        return

    def wrap_pattern(pattern):
        new_pattern = r'(^\s+' + pattern + r';|\(' + pattern + r'\))'
        return new_pattern

    # renaming an lvar to match a struct fieldname, e.g.
    # v1 = struct->member;
    pattern_sub = re.compile(wrap_pattern(r'(v\d+) = (\w+)(->)(\w+)'))

    # renaming an lvar to match a struct fieldname, e.g.
    # struct->member = v1;
    pattern_sub2 = re.compile(wrap_pattern(r'(\w+)(->)(\w+) (=|\+=|-=) (v\d+)'))

    # renaming (and retyping) the return value from a function call, e.g.
    # v1 = (optional cast&*)(function)(
    pattern_call = re.compile(r'^\s+(v\d+) (=|\+=|-=) (?:\([^)]+\))*(\w+)\(')

    # renaming an lvar to match another
    # v1 = name
    pattern_opeq = re.compile(wrap_pattern(r'(v\d+) (=) (\w+)'))

    lines = decompile_function(ea)
    if not lines:
        return

    for line in lines:
        for (var, struc, indir, member) in reby(4, re.findall(pattern_sub, line)):
            # we are specifically limiting the named members of any struct
            # **named** pHandle (not necessary of the right type).
            if struc == 'pHandle':
                if member == 'Offset':
                    rename_lvar(var, 'offset', ea)
                if member == 'Flags':
                    rename_lvar(var, 'flags', ea)
                if member in ('MaxSize', 'MaxReadSize', 'MaxWriteSize'):
                    rename_lvar(var, 'maxSize', ea)

        for (struc, indir, member, operator, var) in reby(5, re.findall(pattern_sub2, line)):
            # this is essential the same as above, but matches when a->b = c 
            # instead of c = a->b
            if struc == 'pHandle':
                if member == 'Offset':
                    rename_lvar(var, 'offset', ea)
                if member == 'Flags':
                    rename_lvar(var, 'flags', ea)

        for (var, operator, func) in re.findall(pattern_call, line):
            # matching v1 = function(...), and:
            # just changing the name
            if func.endswith('joaat'):
                rename_lvar(var, 'hash', ea)
            if func == 'GetGameScriptHandler_fivem':
                rename_lvar(var, 'pScrThread', ea)
            # braving some general rules
            if re.match('get.*count', func, re.I):
                rename_lvar(var, 'count', ea)

            # or changing the name and type to match the function return
            if func == 'getEntityAddressIfVehicle':
                rettype = get_func_rettype(idc.get_name_ea_simple(func))
                set_lvar_type(var, rettype, ea)
                rename_lvar(var, 'pVehicle', ea)
            if func == 'getOnlinePlayerInfo':
                rettype = get_func_rettype(idc.get_name_ea_simple(func))
                set_lvar_type(var, rettype, ea)
                rename_lvar(var, 'pOnlineInfo', ea)

        for (dst, operator, src) in reby(3, re.findall(pattern_opeq, line)):
            # this renames lvars assigned to pPointerOfSomething
            if src.startswith('p') and src[1].upper() == src[1]:
                rename_lvar(dst, src, ea)


def decompile_function_xrefs_for_common_renames(func):
    """
    a way to apply bulk transforms without getting silly
    :param func: a common function returning a known type you want to rename
    """
    for e in idautils.CodeRefsTo(func, 1):
        decompile_function_for_common_renames(e)
