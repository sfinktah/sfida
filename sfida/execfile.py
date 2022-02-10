import os, sys, inspect, re
from datetime import datetime, timedelta
import traceback

try:
    import __builtin__ as builtins
except:
    import builtins

class ExecFileError(Exception): pass

def _A(o):
    if o is None:
        return []
    elif isinstance(o, list):
        return o
    else:
        return [o]

def _find(filenames, test=os.path.isfile):
    for filename in _A(filenames):
        if os.path.isabs(filename):
            if test(filename):
                return filename
        else:
            for dir in ['.'] + sys.path:
                fn = os.path.join(dir, filename)
                if test(fn):
                    return fn
    raise ExecFileError("Can't _find file {}".format(filename))

def _extend(obj, *args):
    """
    adapted from underscore-py
    Extend a given object with all the properties in
    passed-in object(s).
    """
    args = list(args)
    for src in args:
        obj.update(src)
        for k, v in src.items():
            if v is None:
                del obj[k]
    return obj


def unload(pattern):
    for x in [x for x in sys.modules.keys() if re.match(pattern, x)]:
        print("unloading {}".format(x))
        del sys.modules[x]

def module_match(pattern):
    return [x for x in sys.modules.keys() if re.match(pattern, x)]

def find_in_modules(pattern):
    return [x[1] for x in [(hasattr(sys.modules[m], pattern), m) for m in sys.modules] if x[0]]

def unload_from_all_modules(pattern, module_regex=None):
    for x in [x for x in sys.modules.keys() if not module_regex or re.match(module_regex, x)]:
        m = sys.modules[x]
        for sub in dir(m):
            if re.match(pattern, sub):
                print("{}::{}".format(x, sub))
                if sys.version_info.major >= 3:
                    import importlib
                    importlib.reload(m)

def _isflattenable(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'isalnum')

# def _make_execfile():
#     def _execfile(filename, _globals=None, args=[]):
#         if _isflattenable(filename):
#             return [_execfile(x, _globals, args) for x in filename]
# 
#         filenames = [filename]
#         fn, ext = os.path.splitext(filename)
#         if not ext:
#             filenames.append(os.path.extsep.join([fn, 'py']))
# 
#         full_path = _find(filenames)
# 
#         # ensure consistency
#         full_path = os.path.abspath(full_path)
# 
#         #  if getattr(builtins, 'execfile', 0):
#             #  if _globals:
#                 #  return builtins.execfile(full_path, _globals)
#             #  return builtins.execfile(full_path)
# 
#         argv = sys.argv
#         sys.argv = [ full_path ]
#         sys.argv.extend(args)
# 
#         if _globals is None:
#             _globals = dict(inspect.getmembers(
#                 inspect.stack()[1][0]))["f_globals"]
#         _ori_globals = {k: _globals.get(k, None) for k in ('__file__', '__name')}
# 
#         
#         if hasattr(builtins, 'execfile'):
#             return builtins.execfile(full_path, _extend(_globals, {  "__file__": full_path }))
#         try:
#             with open(full_path, "rb") as file:
#                 raw = file.read()
#             encoding = "UTF-8" # UTF-8 by default: https://www.python.org/dev/peps/pep-3120/
# 
#             encoding_pat = re.compile(r'\s*#.*coding[:=]\s*([-\w.]+).*')
#             for line in raw.decode("ASCII", errors='replace').split("\n"):
#                 match = encoding_pat.match(line)
#                 if match:
#                     encoding = match.group(1)
#                     break
# 
#             code = compile(raw.decode(encoding), full_path, 'exec')
#             exec(code, _extend(_globals, {  "__file__": full_path,
#                                            "__name__": "__main__" }))
# 
#         except Exception as e:
#             print("%s\n%s" % (str(e), traceback.format_exc()))
#         finally:
#             sys.argv = argv
#             _extend(_globals, _ori_globals)
#     return _execfile
# 
# execfile = _make_execfile()

def execfile(filename, _globals=None, args=[]):
    if _isflattenable(filename):
        return [_execfile(x, _globals, args) for x in filename]

    filenames = [filename]
    fn, ext = os.path.splitext(filename)
    if not ext:
        filenames.append(os.path.extsep.join([fn, 'py']))

    full_path = _find(filenames)

    # ensure consistency
    full_path = os.path.abspath(full_path)

    #  if getattr(builtins, 'execfile', 0):
        #  if _globals:
            #  return builtins.execfile(full_path, _globals)
        #  return builtins.execfile(full_path)

    argv = sys.argv
    sys.argv = [ full_path ]
    sys.argv.extend(args)

    if _globals is None:
        _globals = dict(inspect.getmembers(
            inspect.stack()[1][0]))["f_globals"]
    _ori_globals = {k: _globals.get(k, None) for k in ('__file__', '__name')}

    
    if hasattr(builtins, 'execfile'):
        return builtins.execfile(full_path, _extend(_globals, {  "__file__": full_path }))
    try:
        with open(full_path, "rb") as file:
            raw = file.read()
        encoding = "UTF-8" # UTF-8 by default: https://www.python.org/dev/peps/pep-3120/

        encoding_pat = re.compile(r'\s*#.*coding[:=]\s*([-\w.]+).*')
        for line in raw.decode("ASCII", errors='replace').split("\n"):
            match = encoding_pat.match(line)
            if match:
                encoding = match.group(1)
                break

        code = compile(raw.decode(encoding), full_path, 'exec')
        exec(code, _extend(_globals, {  "__file__": full_path,
                                       "__name__": "__main__" }))

    except Exception as e:
        print("%s\n%s" % (str(e), traceback.format_exc()))
    finally:
        sys.argv = argv
        _extend(_globals, _ori_globals)

def make_refresh(_file, _globals = None):
    if _globals is None:
        _globals = dict(inspect.getmembers(
            inspect.stack()[1][0]))["f_globals"]
    def refresh_fn():
        print("refreshing " + _file)
        execfile(_file, _globals)
    return refresh_fn

def make_auto_refresh(_file, _globals = None):
    """ still conceptual, not for production use """
    if _globals is None:
        _globals = dict(inspect.getmembers(
            inspect.stack()[1][0]))["f_globals"]

    def check_for_update():
        # @static: last_load_time
        if 'last_load_time' not in check_for_update.__dict__:
            check_for_update.last_load_time = datetime.today()
        file_mod_time = datetime.fromtimestamp(os.stat(os.path.abspath(_file)).st_mtime)  # This is a datetime.datetime object!
        now = datetime.today()
        max_delay = timedelta(seconds=10)

        if file_mod_time - check_for_update.last_load_time > max_delay:
            #  print("CRITICAL: {} last modified on {}. Threshold set to {} minutes.".format(_file, file_mod_time, max_delay.seconds/60))
            execfile(_file, _globals)
            check_for_update.last_load_time = datetime.today()
        else:
            pass
            #  print("OK. {} hasn't been modified for {} minutes".format(_file, (now-file_mod_time).seconds/60))
    return check_for_update



def _require(modulename, package=None):
    """
    @param modulename:
    @return module:


        Load, or reload a module.

        When under heavy development, a user's tool might consist of multiple
        modules. If those are imported using the standard 'import' mechanism,
        there is no guarantee that the Python implementation will re-read
        and re-evaluate the module's Python code. In fact, it usually doesn't.
        What should be done instead is 'reload()'-ing that module.

        This is a simple helper function that will do just that: In case the
        module doesn't exist, it 'import's it, and if it does exist,
        'reload()'s it.

        The importing module (i.e., the module calling require()) will have
        the loaded module bound to its globals(), under the name 'modulename'.
        (If require() is called from the command line, the importing module
        will be '__main__'.)

        For more information, see: <http://www.hexblog.com/?p=749>.
    """
    frame_obj, filename, line_number, function_name, lines, index = inspect.stack()[1]
    parent_module = inspect.getmodule(frame_obj)
    if parent_module is None: # No importer module; called from command line
        parent_module = sys.modules['__main__']

    if modulename in sys.modules.keys():
        m = sys.modules[modulename]
        if sys.version_info.major >= 3:
            import importlib
            importlib.reload(m)
        else:
            reload(m)
        m = sys.modules[modulename]
    else:
        import importlib
        m = importlib.import_module(modulename, package)
        sys.modules[modulename] = m
    # this fucks up our `_import('from package import ....') by writing the module to globals
    # setattr(parent_module, modulename, m)
    return m

def _funcname():
    return inspect.currentframe(1).f_code.co_name

def _import(import_stmt, default_cmd='import', global_depth=0):
    """
    import_stmt     ::= "import" module ["as" name] ( "," module ["as" name] )*
                    | "from" relative_module "import"     identifier ["as" name] ( "," identifier ["as" name] )*
                    | "from" relative_module "import" "(" identifier ["as" name] ( "," identifier ["as" name] )* [","] ")"
                    | "from" module "import" "*"
    module          ::= (identifier ".")* identifier
    relative_module ::= "."* module | "."+
    name            ::= identifier

    TODO: relative_modules or just things with '.' in them
          (though this generally seems to work, though not exhaustively tested)
          see: https://docs.python.org/3/tutorial/modules.html#packages
    """
    debug = 1
    if debug: print("*** {} ***".format(import_stmt))
    debug = 0
    if default_cmd not in import_stmt:
        # lazy invocation: `_import('module')`
        if debug: print("inserting '{}' prefix".format(default_cmd))
        import_stmt = default_cmd + ' ' + import_stmt
    rflags = 0
    re_list = [
        # testing: import multiple, modules [as name]
        re.compile(r'import (?P<importcsv>.*,.*)', rflags),                                   # importcsv
        # import single [as name]
        re.compile(r'import (?P<module>\S+)(?: as (?P<as>\w+))?', rflags),                    # module and not name
        # testing: from single import multiple, modules [as name]
        re.compile(r'from (?P<module>\S+) import (?P<fromcsv>.*,.*)', rflags),                # fromcsv
        # from single import *
        re.compile(r'from (?P<module>\S+) import (?P<asterisk>[*])', rflags),                 # asterisk
        # from single import single [as name]
        re.compile(r'from (?P<module>\S+) import (?P<identifier>\w+)(?: as (?P<as>\w+))?', rflags), # module and identifier
    ]

    # standardise whitespace following commas
    import_stmt = ', '.join(import_stmt.split(','))
    # remove excess whitespace (including that generated by the comma thing above
    import_stmt = ' '.join(filter(lambda x: x, import_stmt.split(' ')))
    # remove leading and trailing whitespace
    import_stmt = import_stmt.strip()

    # allow custom global space, else default to callee's
    _globals = dict(inspect.getmembers(
                inspect.stack()[global_depth + 1][0]))["f_globals"]
    result = {}
    # check each pattern (order is important!) to find correct parser
    for pattern in re_list:
        matches = re.match(pattern, import_stmt)
        if debug: print(pattern, matches)
        if matches:
            d = matches.groupdict()
            k = d.keys()
            if 'importcsv' in k:
                # testing: import foo, bar as baz
                for module, _as, name in [x.partition(' as ') for x in d['fromcsv'].split(', ')]:
                    if debug: print("importing " + str(module) + " as " + str(name or module))
                    result[name or module] = _require(module)
                _extend(_globals, result)
                return result
            elif 'fromcsv' in k:
                # from x import foo, bar as baz
                o = _require(d['module'])
                for identifier, _as, name in [x.partition(' as ') for x in d['fromcsv'].split(', ')]:
                    result[name or identifier] = getattr(o, identifier)
                _extend(_globals, result)
                return result
            elif 'asterisk' in k:
                # from x import *
                # (there must be a importlib way to import all, surely?)
                o = _require(d['module'])
                members = inspect.getmembers(o)
                for key in [x[0] for x in members if not x[0].startswith('__')]:
                    result[key] = getattr(o, key)
                _extend(_globals, result)
                return result
            elif 'identifier' in k:
                # from x import y [as z]
                p = _require(d['module']) # from <p>
                id = d['identifier'] # import <_as>
                if not hasattr(p, id):
                    print("execfile::_import('{}'): module '{}' has no method named '{}'".format(import_stmt, d['module'], id))
                    print("methods: {}".format(p.__dict__))
                    return
                o = getattr(p, id)

                if d['as']:
                    id = d['as'] # as <_as>
                    # #  if debug: print(f"imported {d['module']}.{d['identifier']} as {d['as']}")
                else:
                    pass
                    # #  if debug: print(f"imported {d['module']}.{d['identifier']} as {d['identifier']}")
                result[id] = o
                _extend(_globals, result)
                return result
            elif 'as' in k:
                # simple import x as y
                o = _require(d['module'])
                if d['as']:
                    result[d['as']] = o
                    # if debug: print(f"imported {d['module']} as {d['as']}")
                else:
                    # no need to write to _globals, _require will do this by default
                    result[d['module']] = o
                    # if debug: print(f"imported {d['module']} as itself")
                _extend(_globals, result)
                return result
            elif 'module' in k:
                # vanila import
                # if debug: print(f"imported {d['module']} (vanilla)")
                result[d['module']] = _require(d['module'])
                _extend(_globals, result)
                return result

    raise ImportError("Couldn't interpret '{}'".format(import_stmt))

def _from(import_stmt):
    # inspect.currentframe().f_code.co_name
    return _import(import_stmt, default_cmd="from", global_depth=1)

