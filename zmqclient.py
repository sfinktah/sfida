import re
import idc
import idaapi
#  import Commenter

#  Commenter = commenter.Commenter
# from commenter import Commenter
from idc import *
import idautils, os, sys, re, json, zmq
import socket as Socket
import zmq
from datetime import datetime
import time
from exectools import execfile, make_refresh
from superglobals import getglobal
from underscoretest import _

# requirements
# from itertools import islice
# sf_is_flags

abort_file = os.path.dirname(os.path.abspath(__file__)) + '/.abort'
refresh_zmqclient = make_refresh(os.path.abspath(__file__))

pending_functions = []

def days_between(d1, d2):
    d1 = datetime.strptime(d1, "%Y-%m-%d")
    d2 = datetime.strptime(d2, "%Y-%m-%d")
    return abs((d2 - d1).days)
# Commenter = _require("commenter").Commenter

zmqfake = False
port = "5558"
host = "gf.local"
host = "localhost"
context = zmq.Context()
remote_version = ''
local_version = idc.GetIdbPath().split('\\')[2]
if not zmqfake:
    print("Connecting to server...")
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://%s:%s" % (host, port))
    socket.RCVTIMEO = 90000
    socket.SNDTIMEO = 30000
    remote_version = 'unknown'
else:
    remote_version = 'fake'

def EA():
    return ScreenEA()

def GetFuncStart(ea):
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = idaapi.get_func(ea)
    if not func:
        return BADADDR
    return func.start_ea

def GetFuncEnd(ea):
    """
    Determine a new function boundaries
    
    @param ea: address inside the new function
    
    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = idaapi.get_func(ea)
    if not func:
        return BADADDR
    return func.endEA


def VtableRefsTo(ea):
    result = []
    for xref in XrefsTo(ea, 0):
        if isinstance(xref.frm, int):
            if get_segm_name(xref.frm) == '.rsrc':
                result.append(xref.frm)
        #  print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
    return result


def GetFuncSize(ea):
    return GetFuncEnd(ea) - GetFuncStart(ea)

def IsChunked(ea):
    #  return idc.get_fchunk_attr(address, FUNCATTR_START) < BADADDR
    return len(list(idautils.Chunks(ea))) > 1

def mark(ea, comment):
    c = Commenter(ea, 'func')
    if not c.exists(comment):
        c.add(comment)

def check(ea, comment):
    c = Commenter(ea, 'func')
    return c.exists(comment)

def check_re(ea, comment):
    c = Commenter(ea, 'func')
    return [c for c in c.matches(comment)]

def byteify(input):
    """
    Turns JSON data into ASCII
    """
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.items()}
    elif isinstance(input, (list, set, tuple)):
        return [byteify(element) for element in input]
    elif isString(input):
        return asBytesRaw(input)
    else:
        return input

def unbyteify(input):
    """
    Turns JSON data into ASCII
    """
    if isinstance(input, dict):
        return {unbyteify(key): unbyteify(value)
                for key, value in input.items()}
    elif isinstance(input, (list, set, tuple)):
        return [unbyteify(element) for element in input]
    elif isBytes(input):
        return asStringRaw(input)
    else:
        return input

def zrequest_exists(j):
    global zmqfake
    if zmqfake:
        return False
    request = asString(json.dumps(j)) # .encode('ascii')
    retries = 4
    while retries:
        try:
            socket.send_string(request, zmq.NOBLOCK)
        except KeyboardInterrupt:
            print("W: interrupt received, stopping")
            sys.exit()
        except zmq.error.Again:
            print(("Resource Temporarily Unavailable... %i" % retries))
            try:
                Sleep(10000)
            except KeyboardInterrupt:
                print("W: interrupt received, stopping")
            except KeyboardInterrupt:
                print("W: interrupt received, stopping")
                sys.exit()

            retries = retries - 1
            continue
        #  except Exception as e:
            #  print("Exception!!!!")
            #  print(str(e))
            #  return 0
        break

    if retries:
        retries = 3
        while retries:
            try:
                message = socket.recv()
                #  print("Received reply: [ %s ]" % message)
            except zmq.error.Again:
                print(("Resource Temporarily Unavailable... %i" % retries))
                Sleep(10000)
                retries = retries - 1
                continue
            except KeyboardInterrupt:
                print("W: interrupt received, stopping")
                sys.exit()
            #  except Exception as e:
                #  print("Exception!!!!")
                #  print(str(e))
                #  return 0
            break


        try:
            try:
                p = json.loads(message)
                if isinstance(p, str):
                    p = json.loads(p)
                return p
            except json.decoder.JSONDecodeError as e:
                print("JSONDecodeError: {} reading {} @{}".format(e.msg, e.doc, e.pos))
                raise e
            #  p = byteify(json.loads(message.decode('ascii')))
            #  print(p)
            #  if type(p['exists']) is int:
                #  return p['version']
        except:
            pass

    return False

if 'pf' not in globals():
    def pf(a):
        return a
    pfh = pf

def zrequest(j):
    request = asBytes(json.dumps(j).replace('Concurrency::details::HardwareAffinity', 'void')) # .encode('ascii')
    retries = 10
    while retries:
        retries = retries - 1
        try:
            print("retry #{} message:\n{}\n".format(retries, pfh(asString(request))))
            socket.send(request, zmq.NOBLOCK)
        except zmq.error.Again:
            print(("Resource Temporarily Unavailable... %i" % retries))
            Sleep(10000)
            continue
        #  except Exception as e:
            #  print("Exception!!!!")
            #  print(str(e))
            #  return 0
        except zmq.error.InterruptedSystemCall as e:
            print("interupted system call");
            print((str(e)))
        except zmq.error.Again as e:
            print("again");
            print((str(e)))
            continue
        except zmq.error.ContextTerminated as e:
            print("context terminated");
            print((str(e)))
        except zmq.error.ZMQError as e:
            print("zmqerror");
            print((str(e)))
        except KeyboardInterrupt:
            print("W: interrupt received, stopping")
            sys.exit()
        break

    if retries:
        retries = 10
    while retries:
        retries = retries - 1
        print("waiting for response")
        try:
            message = socket.recv()
        except zmq.error.Again as e:
            print("again");
            print((str(e)))
            continue
        #  print("Received reply: [ %s ]" % message)
        try:
            try:
                p = json.loads(message)
            except json.decoder.JSONDecodeError as e:
                print("JSONDecodeError: {} reading {} @{}".format(e.msg, e.doc, e.pos))
                raise e
            #  print(p)
            #  if type(p['label']) is str:
                #  mark(ea, "[PATTERN;AKA:%s] '%s'" % (p['version'], p['label']));
                #  #  c = Commenter(p, 'func')
                #  #  commentMarker = "aka: %s" % name
                #  #  if not c.exists(commentMarker):
                    #  #  c.add(commentMarker)
            #  if type(p['decl']) is str:
                #  mark(ea, "[PATTERN;DECL:%s] '%s'" % (p['version'], p['decl']));
            return p
            #  if type(p['matches']) is int:
                #  return p['matches']
                #  if p['matches'] > 1:
                    #  return p['matches']
        except KeyboardInterrupt:
            print("W: interrupt received, stopping")
            sys.exit()
        #  except:
            #  print("exception sending")
            #  pass
        return 0
    else:
        return -1

def ignore_function_name(fnName):
    if False                                                                 \
        or  not fnName                                                       \
        or  len(fnName) < 2                                                  \
        or  re.match(r".*arxan", fnName, re.I)                               \
        or  re.match(r".*_BACK_", fnName)                                    \
        or  fnName.find('::m_') > -1                                         \
        or  fnName.find( "$" ) > -1                                          \
        or  fnName[0] == "$"                                                 \
        or  fnName[0] == "_"                                                 \
        or  fnName[0] == "?"                                                 \
        or  fnName[0:2] == "j_"                                              \
        or  fnName.find('unknown_libname_') > -1                             \
        or  re.match(r"^jJSub", fnName)                                      \
        or  re.match(r"\?", fnName)                                          \
        or  re.match(r"(::_0x|___0x)", fnName)                               \
        or  len(VtableRefsTo(eax(fnName))) > 0                               \
        or  (idc.get_type(eax(fnName)) and '#' in idc.get_type(eax(fnName))) \
        or  re.match(r".*_impl[_0-9]+$", fnName, re.IGNORECASE):
            return True
    return False

def has_uniq_sig(ea=None):
    """
    has_uniq_sig

    @param ea: linear address
    """
    ea = eax(ea)
    fnStart = GetFuncStart(ea)
    fnEnd = GetFuncEnd(ea)
    if IsChunked(fnStart):
        return False
    pattern = " ".join(make_sig(get_bytes_chunked(fnStart, fnEnd, 128), fnStart))
    #  pattern = pattern[0:(3*64)-1]
    if isInt(sig_reducer(pattern, quick=1)):
        return False
    return True

def prepend_search(ea):
    global pending_functions
    pending_functions.append(ea)

def add_alt_matches(ea):
    subs = []
    for x in xrefs_to(ea):
        if HasUserName(x) and has_uniq_sig(x):
            prepend_search(x)
            break
    if len(subs):
        # This doesn't guarantee it will be picked up later, but it might be
        return

    for x in xrefs_to(ea):
        if not HasUserName(x) and has_uniq_sig(x):
            prepend_search(x)
            subs.append(x)
            break



def sig_maker_auto_zmq(ea, colorise=False, force=False, special=False):
    global remote_version
    _exists = 0
    ignore_existing_pattern = 0
    fnName = GetFunctionName(ea)
    fnStart = LocByName(fnName)
    fnEnd = FindFuncEnd(fnStart)
    fnFlags = idaapi.get_flags(fnStart)
    pattern = ""
    # if idaapi.has_dummy_name(fnFlags) or not idaapi.has_any_name(fnFlags) or fnName.find('::') > -1 or fnName.find('NATIVES') == 0 or fnName[0] == "$" or fnName[0] == "?" or fnName.find('_BACK_') > -1 or fnName.find('unknown_libname_') > -1 or re.match(r"^jJSub", fnName) != None:
    if not force:
        # dprint("[sigmaker] fnName")
        print("[sigmaker] fnName:{}".format(fnName))
        
        if not special:
            if idaapi.has_dummy_name(fnFlags)            \
                or  not idaapi.has_any_name(fnFlags)     \
                or  IsChunked(fnStart)                   \
                or  ignore_function_name(fnName):
                    #  print("%s: skipping" % (fnName))
                    return
        if len(VtableRefsTo(ea)) > 0:
            print(("%s: skipping vtable functions" % fnName))
            return
    if Byte(ea) == 0xe9:
        print(("%s: skipping thunk" % fnName))
        return

    #  if check(ea, "[PATTERN;MULTIPLE]"):
        #  print("%s: skipping marked multiple" % fnName)
        #  if colorise:
            #  SetColor(fnStart, CIC_FUNC, DEFCOLOR)
        #  return
    if colorise:
        if check_re(ea, r"\[PATTERN;UNMATCHED:" + remote_version):
            SetColor(fnStart, CIC_FUNC, 0x0088ff)
            print(("%s: skipping unmatched" % fnName))
            return
        return
    #  if check_re(ea, r"\[PATTERN;(EXISTS|MULTIPLE|UNMATCHED):" + remote_version):
    #  if check_re(ea, r"\[PATTERN;UNMATCHED:" + remote_version):
        #  print("%s: skipping unmatched" % fnName)
        #  return
    
        #  if check_re(ea, r"\[PATTERN;(XXXXXX|MULTIPLE|UNMATCHED):" + remote_version):
            #  print("%s: skipping previously tried" % fnName)
            #  return

    pattern = ""
    rv = check_re(ea, r"\[PATTERN;SHORTEST:")
    for r in rv:
        print(("found existing pattern comment: %s" % r))
        m = re.match(r"\[PATTERN;SHORTEST:\w+] '(.*)'", r)
        if m:
            pattern = m.group(1)
            print(("found existing pattern: %s" % pattern))
            break

        #  print("%s: skipping previously processed" % fnName)
        #  return
    # XXX
    if remote_version and False:
        if check_re(ea, r"\[PATTERN[^]]+:" + remote_version):
            print("comment says sent; skipping")
            return
    #  if not remote_version and not special:
    if True:
        desc = TagRemoveSubstring(fnName)
        rv = zrequest_exists({'cmd':'aob', 'pattern':[], 'description':desc, 'address':ea, 'decl':''})
        if rv and isinstance(rv, object):
            if 'pp' in globals():
                pp(rv)
            # (b'{"cmd": "aob", "pattern": [], "description": "pureVirtualFunctionPtr", 
            # "address": 5368713216, "decl": "", "_exists": 1}')
            if 'version' in rv:
                remote_version = rv['version']
            # XXX
            if 'exists' in rv and rv['exists'] == 1 and 'address' in rv:
                _address = rv['address']
                print("type address: {}".format(type(_address)))
                _exists = _address
                print("type address: {}".format(type(_exists)))
                print("_exists: {:x} {:x}".format(rv['address'], _exists))
                print(("\n\n\n%s: already _exists on target" % fnName))
                # XXX
                #  mark(ea, "[PATTERN;EXISTS:%s]" % (remote_version));

    if not _exists:
        # XXX
        #  return
        if check_re(ea, r"\[PATTERN;MULTIPLE"):
            for c in check_re(ea, r"\[PATTERN;MULTIPLE"):
                qualifier = string_between(':', ']', c)
                elapsed = ''
                version = ''
                if qualifier:
                    try:
                        r = time.strptime(qualifier, '%Y-%m-%d')
                        elapsed = (datetime.now() - datetime(r[0], r[1], r[2])).total_seconds() / 86400
                    except ValueError:
                        pass

                    if not elapsed:
                        version = qualifier

                print("pattern;multiple: {}, {}".format(elapsed, version))
            return

        # return
    #  pattern = " ".join(make_sig(get_bytes_chunked(fnStart, fnEnd, 24), fnStart, fnEnd))
    #  pattern = pattern[0:(3*64)-1]
    #  if len(pattern) < (3 * 6) or pattern[0:2] == "e9":
        #  return
    #  rv = zrequest({'cmd':'aob', 'pattern':pattern, 'description':fnName, 'address':ea})
    #  if rv == 0:
        #  raise Exception("error")
    #  if rv > 1:
    _old_globals=[]
    _subs = []
    _globals = []
    if not _exists and (ignore_existing_pattern or len(pattern) == 0):
        print(("%s: making pattern" % fnName))
        # this will make subs or globals or smth
        #  get_instructions_chunked(fnStart, fnEnd, 1024, _globals = _old_globals)
        #  _subs = sig_subs(fnStart, filter=lambda fnLoc, fnName: not ignore_function_name(fnName))
        _globals = sig_globals(fnStart, fullFuncTypes=True)

        pattern = " ".join(make_sig(get_bytes_chunked(fnStart, fnEnd, 128), fnStart))
        #  pattern = pattern[0:(3*64)-1]
        pattern = sig_reducer(pattern, quick=1)
        if isinstance(pattern, str):
            mark(ea, "[PATTERN;SHORTEST:%s] '%s'" % (time.strftime('%Y-%m-%d'), pattern));
        elif isinstance(pattern, int):
            if pattern != 1:
                print(("%s: multiple matches (%d)" % (fnName, pattern)))
                add_alt_matches(fnStart)
                return
                #  rl = []
                #  for r in [24, 36, 48]:
                    #  res = sig_maker_ex(ea, chunk=r, quick=0, comment=1)
                    #  if res:
                        #  rl.extend(res)
                #  if not rl: # res:
                    #  mark(ea, "[PATTERN;MULTIPLE:%s]" % time.strftime('%Y-%m-%d'));
                    #  return
                #  pattern = rl
            else:
                print(("%s: %s: make_sig returned: %s (probably no matches)" % (ea, fnName, pattern)))
        else:
            print(("%s: %s: make_sig returned unexpected type: %s" % (ea, fnName, type(pattern))))

    if zmqfake:
        return
    
    #  ea = idaapi.get_screen_ea()
    if _exists:
        pattern = ''
    try:
        cfunc = idaapi.decompile(ea) 
        func_def = str(cfunc).split("\n")
        decl = [x for x in func_def if len(x) and not x[0] == '/'][0]
        # dprint("[decl] decl")
        print("[decl] decl:{}".format(decl))
        
        #  if len(pattern) < (3 * 6) or pattern[0:2] == "e9":
            #  return
        export_types = ''
        while True:
            # dprint("[debug] _globals")
            print("[debug] _globals:{}".format(_globals))
            if special and not HasUserName(ea) and idc.get_func_name(ea).startswith('sub_'):
                desc = "_" + idc.get_func_name(ea)
            else:
                desc = TagRemoveSubstring(fnName)
            _globals = sig_globals(fnStart, fullFuncTypes=True)
            # added to try and stop SetType(ea, 'int __fastcall(arg, arg') -- i.e. no func name
            # # untested
            for _g in _globals:
                if _g['type'].endswith(')'):
                    _g['type'] = _g['type'].replace('void (*)(', 'void (*) fn(')
                    # dprint("[sig_maker_auto_zmq] _g")
                    print("[sig_maker_auto_zmq] _g:{}".format(_g))
                    

            req = {'cmd':'aob', 'version':local_version,
                'pattern':pattern, 'description':desc, 'address':_exists or ea,
                'decl':decl, 'globals':_globals, 'subs':[],
                'types':export_types}
            pp(req)
            rv = zrequest(req)
            if not isinstance(rv, dict):
                print(("typeof rv is %s" % type(rv)))
                byteify(rv)
                raise Exception("error")
            matches = rv['matches']
            remote_version = rv['version']
            print(("%s: %i matches" % (fnName, matches)))
            if 'request_type' in rv:
                types = rv['request_type']
                print("remove has request type definitions for: {}".format(types))
                if types:
                    for t in _.uniq(types):
                        if t != 'void':
                            et = my_print_decls(t)
                            if not et:
                                print("**** Type Error ****\n{}\n".format(t))
                                return
                            try:
                                export_types += my_print_decls(t)
                            except TypeError:
                                print("**** Type Error ****\n{}\n".format(t))
                                return
                    continue

            if matches == 0:
                mark(ea, "[PATTERN;UNMATCHED:%s]" % (remote_version))
            elif matches == 1:
                mark(ea, "[PATTERN;EXISTS:%s]" % (remote_version))
            elif matches > 1:
                mark(ea, "[PATTERN;MULTIPLE:%s]" % (remote_version))
            break

    except KeyboardInterrupt:
        print("W: interrupt received, stopping")
        sys.exit()
    except ida_hexrays.DecompilationFailure :
        print(("%s: DecompilationFailure: 0x0%0x" % (fnName, ea)))



def sig_maker_all(pattern=None, colorise=False):
    global pending_functions
    skip = 0
    numLocs = len(list(idautils.Functions()))
    count = 0
    lastPercent = 0
    print(("locs: %i" % numLocs))

    iter = idautils.Functions() # idc.get_segm_attr(EA(, SEGATTR_START)), idc.get_segm_attr(EA(, SEGATTR_END))):
    while True:
        special = 0
        if pending_functions:
            ea = pending_functions.pop()
            special = 1
        else:
            if pattern:
                fnName = ''
                while pattern and not re.match(pattern, fnName):
                    ea = next(iter)
                    fnName = idc.get_func_name(ea)
                print('matched pattern with {}'.format(fnName))
            else:
                ea = next(iter)
            if getglobal('m', None, list) and getglobal('l', None, list):
                if ea in globals()['m'] or ea in globals()['l']:
                    continue

        if idc.get_segm_name(ea) != '.text':
            continue
        if os.path.exists(abort_file):
            print("Aborted due to presence of {}".format(abort_file))
            raise Exception("Aborted")
        count = count + 1
        fnName = GetTrueName(ea)
        if fnName == "DeleteCriticalSection":
            skip = 0
        if skip:
            #  print("skipping: %s" % fnName)
            continue
        fnFlags = idaapi.get_flags(ea)
        if not special and (idc.get_segm_name(ea) != '.text' or IsChunked(ea) or GetFuncSize(ea) < 6 or idaapi.has_dummy_name(fnFlags) or not idaapi.has_any_name(fnFlags)): #  or "_impl" in fnName or fnName.startswith("implsub"): # fnName.find('::') > -1 or fnName.find('__') > -1 or fnName.find('BACK') > -1:
            # print("skipping: %s" % fnName)

            pass
        else:
            percent = (100 * count) // numLocs
            # if percent > lastPercent:
            # print("%i%%" % percent)
            lastPercent = percent

            # print("\n%s (%i%%)" % (fnName, percent))
            sig_maker_auto_zmq(ea, colorise=colorise, special=special)

def testport():
    with Socket.socket(Socket.AF_INET, Socket.SOCK_STREAM) as s:
        result = s.connect_ex((host, port))

        if result == 0:
            print('socket is open')
        else:
            print('socket is closed, error: {}'.format(result))
        
    return result

def test(port = 5558):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://{}:{}".format(host, port))
    socket.RCVTIMEO = 5000
    socket.SNDTIMEO = 5000
    socket.send_string("test", zmq.NOBLOCK)
    message = socket.recv()
    print(("%s" % message))

def term(port = 5558):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://{}:{}".format(host, port))
    socket.RCVTIMEO = 5000
    socket.SNDTIMEO = 5000
    socket.send(asBytes('{"cmd":"term"}'))
    message = socket.recv()
    print(("%s" % message))

def ping(port = 5558):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://{}:{}".format(host, port))
    socket.RCVTIMEO = 5000
    socket.SNDTIMEO = 5000
    socket.send(asBytes('{"cmd":"ping"}'))
    message = socket.recv()
    print(("%s" % message))

def zmclient(pattern=None, _host=None, _port=None):
    global host
    if _host:
        host = _host
    global port
    if _port:
        port = _port

    ping()
    ping()
    ping()
    sig_maker_all(pattern)
