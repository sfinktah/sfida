print("start.py loaded")
import os, sys, re
import sys
#  sys.modules["__main__"].IDAPYTHON_COMPAT_695_API = True
# from sfida.sf_is_flags import *
from exectools import unload
unload('execfile')
from exectools import execfile, make_refresh, make_auto_refresh, _import, _from

ida_modules = [
        'ida_idaapi', 'idaapi', 'idc', 'ida_allins', 'ida_auto', 'ida_bytes',
        'ida_dbg', 'ida_diskio', 'ida_entry', 'ida_enum', 'ida_expr',
        'ida_fixup', 'ida_fpro', 'ida_frame', 'ida_funcs', 'ida_gdl',
        'ida_graph', 'ida_hexrays', 'ida_ida', 'ida_idc', 'ida_idd', 'ida_idp',
        'ida_kernwin', 'ida_lines', 'ida_loader', 'ida_moves', 'ida_nalt',
        'ida_name', 'ida_netnode', 'ida_offset', 'ida_pro', 'ida_problems',
        'ida_range', 'ida_registry', 'ida_search', 'ida_segment',
        'ida_segregs', 'ida_strlist', 'ida_struct', 'ida_tryblks',
        'ida_typeinf', 'ida_ua', 'ida_xref', 'idc',
]

unload('ida_idaapi')
import ida_idaapi
for m in ida_modules:
    ida_idaapi.require(m)

from idc import BADADDR
from superglobals import *
from underscoretest import _
from pprint import PrettyPrinter
from mypprint import MyPrettyPrinter
#  _import("from sfida.sf_is_flags import *")
pp = MyPrettyPrinter(indent=4).pprint
pf = MyPrettyPrinter(indent=4).pformat

def pfh(o):
    return re.sub(r"((?:, +|: +|\n +|\( *|\[ *|\{ *)-?)(\d\d+)(?=[:,)}\]])", lambda m: m.group(1) + hex(m.group(2)), pf(o))

def pph(o):
    print(pfh(o))

debug = 0
obfu_debug = 0


# _import("from circularlist import CircularList")
#  from circularlist import CircularList
# pprint = MyPrettyPrinter(indent=4).pprint
# &")

_cwd = os.path.dirname(os.path.realpath(os.curdir))
_ourname = sys.argv[0]
_basename = os.path.dirname(os.path.realpath(_ourname))

#  print("start.py...")
#  print("__file__:   %s" % __file__)
#  print("_basename:  %s" % _basename)
#  print("_cwd:       %s" % _cwd)
#  print("_ourname:   %s" % _ourname)
print("""
          _____╭╌╌╮      ╭╌╌╮     __         ╭╌╌╮     
  .______╱ ____╲__| ____ |  | ___╱  |______  |  l__   
 ╱  ___╱╲   __╲|  |╱    ╲|  |╱ ╱╲   __╲__  ╲ |     ╲  
 ╲___ ╲  |  |  |  ┃   ┃  ╲    <  |  |  ╱ __ ╲|  ╰╮  ╲ 
╱____  ) |  |  |__┃___┃  ╱__┃_ ╲ |  | (____  ╱___|  ╱ 
     ╲╱  ╰╌╌╯obfukungfu╲╱     ╲╱ ╰╌╌╯idapro╲╱     ╲╱  
        """)

scriptDir = os.path.dirname(__file__)
#  if os.path.exists('e:/git/ida'):
    #  scriptDir = "e:/git/ida"
#  else:
    #  scriptDir = "f:/git/ida"

home = scriptDir

try:
    import __builtin__ as builtins
    integer_types = (int, long)
    string_types = (str, unicode)
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


# with open(scriptDir + os.sep + 'refresh.py', 'r') as f: exec(compile(f.read().replace('__BASE__', os.path.basename(__file__).replace('.py', '')).replace('__FILE__', __file__), __file__, 'exec'))
refresh_start = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
debug = 0

filenames = [
            "static_vars.py",
            "idc695.py",
            "attrdict1.py",
            "superglobals.py",
            "circularlist.py",
            "bitwise.py",
            "perftimer.py",
            "slowtrace_helpers.py",
            "sfida/sf_is_flags.py",
            "iced.py",
            "di.py",
            "nasm.py",
            "sfida/sf_common.py",
            "braceexpand.py",
            "JsonStoredList.py",
            "keypatch.py",
            "file_get_contents.py",
            "slowtrace2.py",
            "hotkey_utils.py",
            "helpers.py",
            "fflags.py",
            "MakeNativeHashBuckList.py",
            "sfcommon.py",
            "sftools.py",
            "hex.py",
            #  "function_address_export.py",
            "structmaker.py",
            "classmaker.py",
            "membrick.py",
            "commenter.py",
            "ranger.py",
            "BatchMode.py",
            "hexrayfucker.py",
            "load_alloc_dump.py",
            #  "obfu_helpers.py",
            #  "obfu_class.py",
            #  "obfu_generators.py",
            #  "obfu_patches.py",
            "obfu.py",
            "func_tails.py",
            "get_pdata.py",
            "progress.py",
            "DebugMode.py",
            "idarest.py",
            "idarest_client.py",
            "MegaHash.py",
            "emu_helpers.py",
            #  "tmp.py",
            #  "m.py",
            #  "emu.py"
            "initFishyElements.py",
            "nttest.py",
    ]

def append_if_file_exists(l, fn):
    if os.path.exists(fn) and os.path.isfile(fn):
        l.append(fn)
        return True
    return False

for fn in ['natives.py']:
    if append_if_file_exists(filenames, os.path.join(os.path.dirname(idc.get_idb_path()), fn)):
        filenames.append('process_natives.py')

def import_item(name):
    """Import and return ``bar`` given the string ``foo.bar``.

    Calling ``bar = import_item("foo.bar")`` is the functional equivalent of
    executing the code ``from foo import bar``.

    Parameters
    ----------
    name : string
      The fully qualified name of the module/package being imported.

    Returns
    -------
    mod : module object
       The module that was imported.
    """

    # adapted from IPython
    parts = name.rsplit('.', 1)
    if len(parts) == 2:
        # called with 'foo.bar....'
        package, obj = parts
        # module = __import__(package, fromlist=[obj])
        module = _require(package)
        try:
            pak = getattr(module, obj)
        except AttributeError:
            raise ImportError('No module named %s' % obj)
        return pak
    else:
        # called with un-dotted string
        # return __import__(parts[0])
        return _require(parts[0])

#  def execfile(filepath, _globals=None, locals=None):
    #  print("start-execfile: {}...".format(filepath))
    #  if _globals is None:
        #  _globals = globals()
    #  _globals.update({
        #  "__file__": filepath,
        #  "__name__": "__main__",
    #  })
    #  with open(filepath, 'r') as file:
        #  exec(compile(file.read(), filepath, 'exec'), _globals, locals)

# ipyida
# ipython_kernel_iteration -> do_one_iteration -> flush -> _handle_recv -> _run_callback -> dispatcher -> dispatch_shell -> execute_request -> do_execute -> run_cell -> run_cell -> _run_cell -> _pseudo_sync_runner -> run_cell_async -> run_ast_nodes -> run_code -> <module> -> retrace -> slowtrace2
ScreenEA = idc.get_screen_ea
LocByName = idc.get_name_ea_simple
MakeNameEx = idc.set_name
Wait = idc.auto_wait
SegName = idc.get_segm_name
Demangle = idc.demangle_name
Qword = idc.get_qword
GetTrueName = idc.get_name
Name = lambda x: idc.get_name(x, ida_name.GN_VISIBLE)

def do_start():
    if str(type(execfile)) == "<class 'module'>":
        unload('execfile')
    for fn in filenames:
        home = scriptDir
        fnfull = os.path.abspath(os.path.join(home, fn))
        if os.path.exists(fnfull) and os.path.isfile(fnfull):
            idc.msg("[{}] ".format(os.path.basename(fnfull)))
            #  exec(open(fnfull).read())

            if str(type(execfile)) == "<class 'module'>":
                raise TypeError("cannot call execfile, is defined as module")
            try:
                execfile(fnfull, globals())
                if str(type(execfile)) == "<class 'module'>":
                    raise TypeError("{} redefined execfile as a module".format(fnfull))
            except:
                print("[error]")
                raise
        else:
            print("\nNo such file: %s" % fnfull)

    print("")

    try:
        ir = get_ir()
    except NameError:
        print("couldn't load get_ir")

# this didn't seem to stick, might need to be entered manually into ida console
debug = 0

do_start()
