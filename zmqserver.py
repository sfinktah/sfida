#  from commenter import Commenter
from idc import *
import idautils
import socket as Socket
import os, sys, re, json, time, traceback, zmq

count_found = 0
count_notfound = 0
count_multiple = 0
count_exists = 0
local_version = idc.GetInputFilePath().split('\\')[2]
local_version = idc.GetIdbPath().split('\\')[2]
remote_version = 'unknown'
host, port = ("0.0.0.0", 5558)

from exectools import execfile
# execfile('autopatterns')
_file = os.path.abspath(__file__)
abort_file = os.path.dirname(os.path.abspath(__file__)) + '/.abort'
noExists = 1
zmlog = None

def refresh():
    execfile(_file)

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

class ZmLog:
    """
    Logging shim
    """

    def __init__(self):
        pass

    def write(self, s, *args):
        print("zmlog: {}".format(str(s).rstrip()))
        if args:
            print("zmlog-args: {}".format(args))

def OurLabelAddress(ea, name):
    global zmlog
    if HasUserName(ea):
        zmlog.write("mem({:#x}).name('{}') # old\n".format(ea, ean(ea)))
        zmlog.write("mem({:#x}).name('{}') # new\n".format(ea, name))
        return LabelAddress(ea, name)

def OurSetType(ea, type):
    global zmlog
    zmlog.write("mem({:#x}).type('{}') # old\n".format(ea, str(idc.get_type(ea))))
    zmlog.write("mem({:#x}).type('{}') # new\n".format(ea, str(type)))
    return idc.SetType(ea, type)



    # response = ZmqLabelPattern(request, request['description'], request['pattern'], request['address'], request['decl'])
def ZmqLabelPattern(j, name, pattern, address, decl = ''):
    global local_version
    global remote_version
    """
    Label function described by 'pattern' with name 'name'.
    [enabled]  If existing function with matching name exists, will return 'exists'
    [disabled] Checks for duplicate names and automatically generates _%i style
               unique names where required.

    pattern: in the IDA form (single or double question marks)
    """
    # dprint("[debug] j")
    
    # j:{'cmd': 'aob', 'pattern': [], 'description': 'alloc_max_2', 'address': 5368713300, 'decl': ''}
    if not pattern and address and not decl:
        if not noExists and idc.get_name_ea_simple(name) < BADADDR:
            print("exists? yes: {}".format(name))
            if not IsFuncHead(eax(name)):
                idc.add_func(idc.get_name_ea_simple(name))
            globals()['count_exists'] += 1
            j['result'] = 'ok'
            j['exists'] = 1
            j['matches'] = 1
            j['address'] = idc.get_name_ea_simple(name);
            return j
        j['result'] = 'fail'
        j['exists'] = 0
        j['address'] = 0
        return j

    base = idc.get_name_ea_simple("__ImageBase")
    if base == BADADDR:
        base = 0

    # pattern = replaceSingleQueryWithDoubleQuery(pattern)
    patternsFound = list()

    found = base
    foundEnd = BADADDR
    if eax(name) == address:
        patternsFound = [address]
        add = 1
    elif address == ida_search.find_binary(address, address + len(pattern), pattern, 16, SEARCH_CASE | SEARCH_DOWN | SEARCH_NOSHOW):
        print("Found {} at supplied address {:x}".format(name, address))
        add = 1
        patternsFound = [address]
    else:
        print("Searching for: %s" % name)
        patternsFound = FindInSegments(pattern, limit = 2)

    j['matches'] = len(patternsFound)
    if j['version'] and isinstance(j['version'], str):
        remote_version = j['version']
    j['version'] = local_version
    j["label"] = ''
    if (len(patternsFound) == 1):
        p = patternsFound[0]
        #  idc.add_func(p)
        Wait()
        j['address'] = p
        globals()['count_found'] += 1

        add = 1
        if IsFuncHead(p) and HasUserName(p):
            add = 0
            j['label'] = idc.get_name(p)
        else:
            ForceFunction(p)

        c = Commenter(p, 'func')
        c.add("[PATTERN;REMOTE:%s] '%s'" % (remote_version, pattern))
        c.add("[NAME;REMOTE:%s] '%s'" % (remote_version, name))
        if len(decl):
            c.add("[DECL;REMOTE:%s] '%s'" % (remote_version, decl))
            if add:
                needed_types = []
                if not OurSetType(p, decl):
                    if idc.get_type(p) != decl:
                        print("SetType(0x{:x}, '{}') failed".format(p, decl))
                        # XXX: changing this from needed_type = get_decl_args(decl) 
                        #      will probably cause errors when get_decl_args returns a non-list
                        needed_types.extend(get_decl_args(decl))
                    # dprint("[debug] needed_types")
                    print("[debug] needed_types:{}".format(needed_types))
                    
                    j['request_type'] = needed_types
                else:
                    print("SetType(0x{:x}, '{}') worked".format(p, decl))
        c.commit()
        if add:
            ForceFunction(p)
            j['label'] = OurLabelAddress(p, name);

        print("(%i) found, (%i) notfound, (%i) multiple, (%i) existed" % ( globals()['count_found'], globals()['count_notfound'], globals()['count_multiple'], globals()['count_exists']))
    
    else:
        if len(patternsFound) > 1:
            globals()['count_multiple'] += 1
        else:
            globals()['count_notfound'] += 1

    
    return j
    #  result = json.dumps(j) # .encode('ascii')
    #  return result

def send(msg):
    try:
        socket.send(msg, zmq.NOBLOCK)
        return 1
    except:
        print("send failed")
        return 0

def byteify(input):
    """
    Turns JSON data into ASCII
    """
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.items()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, bytes):
        return input.encode('utf-8')
    else:
        return input

def mb_perform(perform_log, m, method, arg):
    global zmlog

    m = getattr(m, method)(arg)
    perform_log.append((not m.in_error(), m.ea, method, arg))
    return m

def zmserver():
    global context, socket, zmlog
    if hasattr(globals(), 'context') and not globals()['context'].closed:
        context.destroy()
    zmq.Context().destroy()
    #  if socket:
        #  socket.close()
    context = zmq.Context()
    zmserver.context = context
    socket = context.socket(zmq.REP)
    socket.bind("tcp://{}:{}".format(host, port))
    socket.RCVTIMEO = 1000
    socket.SNDTIMEO = 1000
    socket.setsockopt(zmq.LINGER, 1000)
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN) # POLLIN for recv, POLLOUT for send
    cached_path_funcs = set()

    # with file_put_context('zmq.log', 'a') as _zmlog:
    zmlog = ZmLog()
    while True:
        if os.path.exists(abort_file):
            print("Aborted due to presence of {}".format(abort_file))
            raise Exception("Aborted")
        try:
            evts = poller.poll(1000)
            if len(evts):
                message = socket.recv()
                # print("Received request: %s" % message)

                request = byteify(json.loads(message.decode('ascii')))

                if request['cmd'] == 'term':
                    socket.send(asBytes('{"response":"ok"}'), zmq.NOBLOCK)
                    context.destroy()
                    return

                if request['cmd'] == 'ping':
                    socket.send(asBytes('{"response":"pong"}'), zmq.NOBLOCK)
                    continue

                failed_types = []
                if request['cmd'] == "aob":
                    if type(request['decl']) is str:
                        pass
                    else:
                        request['decl'] = ''
                    if 'types' in request and request['types']:
                        print("\n***TYPES***\n{}\n".format(request['types']))
                        _errors = idc.parse_decls(request['types'], idc.PT_SILENT)
                        if _errors:
                            print("*** ERROR PARSING {}".format(request['types']))

                    response = ZmqLabelPattern(request, request['description'], request['pattern'], request['address'], request['decl'])
                    """
                    {
                        "globals": [{
                            "ea": 5393363700,
                            "name": "DeleteFileW",
                            "path": [
                                ["offset", 97],
                                ["rip", 4],
                                ["name", "DeleteFileW"],
                                ["type", "BOOL __stdcall(LPCWSTR lpFileName)"]
                            ],
                            "sub": false,
                            "type": "BOOL __stdcall(LPCWSTR lpFileName)"
                        }],
                        "types": ""
                    }
                    """

                    if 'globals' in response and response['globals']:
                        if isinstance(response['globals'], list):
                            for item in response['globals']:
                                #  if item['type']:
                                    #  # dprint("[zmserver] item['type']")
                                    #  print("[zmserver] item['type']: {}".format(item['type']))
                                    #  print("[zmserver json] {}".format(json.dumps(response, indent=4)))
                                    #  
                                    #  failed_types.extend(get_decl_args(item['type']))

                                # offset, rip, name, _type
                                ea, name, path, sub, _type = item.values()
                                ea = response['address']
                                # ea = get_ea_by_any(name)
                                if IsValidEA(ea):
                                    if not IsFuncHead(ea):
                                        idc.add_func(ea)
                                    #  print("skipping sub {}".format(name))
                                    #  continue
                                if response["matches"] == 1:
                                    print("{:x}: {:32} {:x}".format(response["address"], name, ea))
                                    m = mb(response["address"])
                                    perform_log = []
                                    new_func = False
                                    _name = None
                                    for step in item["path"]:
                                        if m.in_error():
                                            print("m.in_error: {}".format(m.errors))
                                            break
                                        if not IsValidEA(m.ea):
                                            print("m.ea is invalid: {}".format(ahex(m.ea)))
                                            break
                                        method, arg = step
                                        # print("mb(): {}".format(m))
                                        if arg or isinstance(arg, integer_types):
                                            # print("mb: {} {}".format(method, arg))
                                            if method in ('name', 'type'):
                                                if method in ('name',):
                                                    if not IsValidEA(m.ea):
                                                        break
                                                    if arg in cached_path_funcs:
                                                        print("skipping cached_path_funcs: {}".format(arg))
                                                        break

                                                    if item["sub"]: 
                                                        if not IsFuncHead(m.value()):
                                                            idc.add_func(m.value()) or ForceFunction(m.value())
                                                            new_func = True

                                                    if not HasUserName(m.value()):
                                                        new_func = True

                                                if m.value():
                                                    if method == 'name':
                                                        _name = arg
                                                        zmlog.write("mem({:#x}).name('{}') # old\n".format(m.ea, m.name()))
                                                        m = mb_perform(perform_log, m, method, arg)
                                                        zmlog.write("mem({}).name('{}') # new\n".format(ahex(m.ea), m.name()))
                                                    elif method == 'type':
                                                        zmlog.write("mem({:#x}).type('{}') # old\n".format(m.ea, str(m.type())))
                                                        m = mb_perform(perform_log, m, method, arg)
                                                        if m.in_error():
                                                            failed_types.extend(get_decl_args(arg))
                                                        else:
                                                            cached_path_funcs.add(_name)
                                                        zmlog.write("mem({}).type('{}') # new\n".format(ahex(m.ea), str(m.type())))
                                            else:
                                                m = mb_perform(perform_log, m, method, arg)

                    if failed_types:
                        if 'request_type' in response and isinstance(response['request_type'], list):
                            response['request_type'].extend(remove_known_types(failed_types))
                        else:
                            response['request_type'] = remove_known_types(failed_types)
                        print("\n***\nREQUEST_TYPE_SENT: {}\n".format(response['request_type']))

                else:
                    response['response'] = "unknown"

                #  if ('decl' in request and request['decl'] != ''):
                #  print("\nSending response: \n%s\n" % response)
                socket.send(asBytes(json.dumps(response)), zmq.NOBLOCK)
        except KeyboardInterrupt:
            print("W: interrupt received, stopping")
            break
        except:
            traceback.print_exc()
            socket.send(b"Exception", zmq.NOBLOCK)
            break

    context.destroy(linger=1)

def testport():
    s = Socket.socket(Socket.AF_INET, Socket.SOCK_STREAM)
    result = s.connect_ex((host, 5558))

    if result == 0:
        print('socket is open')
    else:
        print('socket is closed')
        
    s.close()

zmserver()
