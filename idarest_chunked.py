from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from queue import Queue
import cgi
import ida_idaapi
import ida_kernwin
import idaapi
import idautils
import idc
import json
import re
import threading
import time
import traceback
import urllib.parse as urlparse


API_PREFIX = '/ida/api/v1.0'
API_PORT = 8901
API_HOST = '127.0.0.1'
API_DEBUG = False

class HTTPRequestError(BaseException):
    def __init__(self, msg, code):
        self.msg = msg
        self.code = code

class UnknownApiError(HTTPRequestError):
    pass

class HTTPRequestHandler(BaseHTTPRequestHandler):
    routes = {}
    docs = {}
    prefns = {}
    postfns = {}
    uid = 0

    @staticmethod
    def _get_params(f):
        print(inspect.getsource(ir.handler.routes['call'][1]))

    @staticmethod
    def set_result(uid, value):
        #  HTTPRequestHandler.idarest_queue
        if API_DEBUG: idaapi.msg("[set_result] {}: {}\n".format(uid, value))
        HTTPRequestHandler.idarest_queue.put(value)
        return uid

    @staticmethod
    def get_next(value):
        try:
            v = next(value)
            print("next value: {}".format(v))
            HTTPRequestHandler.set_result(0, v)
        except StopIteration as e:
            HTTPRequestHandler.set_result(0, e)

    @staticmethod
    def wrapped_iter(value):
        while True:
            ida_kernwin.execute_sync(lambda: HTTPRequestHandler.get_next(value), ida_kernwin.MFF_WRITE)
            yield HTTPRequestHandler.get_result(0)
        yield None

    @staticmethod
    def get_result(uid):
        #  global idarest_queue
        try:
            value = HTTPRequestHandler.idarest_queue.get(timeout=8)
            if str(type(value)) == "<class 'generator'>":
                print("[get_result] return wrapped_iter")
                return HTTPRequestHandler.wrapped_iter(value)
        except Exception as e:
            value = {'code': 500, 'msg': 'Unhandled Exception: ({}) {}'.format(type(e), str(e)),
                    "error_trace": traceback.format_exc()}
        except:
            value = "timeout"
        if API_DEBUG: idaapi.msg("[get_result] {}: {}\n".format(uid, value))
        return value 

    @staticmethod
    def build_route_pattern(route):
        return re.compile("^{0}$".format(route))

    @staticmethod
    def route(route_str):
        def decorator(f):
            print("[route] {}: {}".format(route_str, f.__doc__))
            route_path = API_PREFIX + '/' + route_str + '/?'
            route_pattern = HTTPRequestHandler.build_route_pattern(route_path)
            HTTPRequestHandler.routes[route_str] = (route_pattern, f)
            HTTPRequestHandler.docs[route_str] = f.__doc__
            # HTTPRequestHandler.params[route_str] = HTTPRequestHandler._get_params(f)
            return f
        return decorator

    def add_route(self, route_str, f):
        route_path = API_PREFIX + '/' + route_str + '/?'
        route_pattern = self.build_route_pattern(route_path)
        self.routes[route_str] = (route_pattern, f)
        self.docs[route_str] = f.__doc__
        return f

    def remove_route(self, route_str):
        if route_str in self.routes:
            self.routes.pop(route_str)
            return True
        return False


    @staticmethod
    def prefn(route_str):
        def decorator(f):
            HTTPRequestHandler.prefns.setdefault(route_str, []).append(f)
            return f
        return decorator

    @staticmethod
    def postfn(route_str):
        def decorator(f):
            HTTPRequestHandler.postfns.setdefault(route_str, []).append(f)
            return f
        return decorator

    def _get_route_match(self, path):
        for (key, (route_pattern, view_function)) in self.routes.items():
            m = route_pattern.match(path)
            if m:
                return key, view_function
        return None

    def _get_route_prefn(self, key):
        try:
            return self.prefns[key]
        except:
            return []

    def _get_route_postfn(self, key):
        try:
            return self.postfns[key]
        except:
            return []

    def _serve_route(self, args):
        path = urlparse.urlparse(self.path).path
        route_match = self._get_route_match(path)
        if route_match:
            key, view_function = route_match
            # these won't run in the main thread, so could cause issues if they try to interact with the idb
            for prefn in self._get_route_prefn(key):
                args = prefn(self, args)
            
            ida_kernwin.execute_sync(lambda: HTTPRequestHandler.set_result(0, view_function(self, args)), ida_kernwin.MFF_WRITE)
            results = HTTPRequestHandler.get_result(0)
            #  results = view_function(self, args)
            print("initial results: {}".format(results))
            return results
            #  while results != 'timeout':
                #  yield results
                #  results = HTTPRequestHandler.get_result(0)
                #  print("next results: {}".format(results))
            
            # these won't run in the main thread, so could cause issues if they try to interact with the idb
            for postfn in self._get_route_postfn(key):
                results = postfn(self, results)

            return results
        else:
            raise UnknownApiError('Route "{0}" has not been registered'.format(path), 404)

    def _serve(self, args):
        try:
            it = self._serve_route(args)
            # it = _sleep({}, {})
            print("it is iterable: {}".format(isIterable(it)))
            print("it is iterator: {}".format(isIterator(it)))
            iterable = False
            if str(type(it)) == "<class 'generator'>":
                iterable = True

            response = {
                'code' : 200,
                'msg'  : 'OK',
                'iterable' : 'start',
                'data' : None,
            }
            if isinstance(response['data'], dict):
                if 'error' in response['data']:
                    response['msg'] = 'FAIL'
        except UnknownApiError as e:
            self.send_error(e.code, e.msg)
            return
        except HTTPRequestError as e:
            response = {'code': e.code, 'msg' : e.msg}
        except ValueError as e:
            response = {'code': 400, 'msg': 'ValueError: ' + str(e)}
        except KeyError as e:
            response = {'code': 400, 'msg': 'KeyError: ' + str(e)}
        except StopIteration as e:
            response = {'code': 400, 'msg': 'StopIteration: ' + str(e)}
        except Exception as e:
            response = {'code': 500, 'msg': 'Unhandled Exception: ({}) {}'.format(type(e), str(e)),
                    "error_trace": traceback.format_exc()}

        jsonp_callback = self._extract_callback()
        if jsonp_callback:
            content_type = 'application/javascript'
            response_fmt = jsonp_callback + '({0});'
        else:
            content_type = 'application/json'
            response_fmt = '{0}'

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        try:
            while True:
                r = response_fmt.format(response).encode('utf-8')
                l = len(r)
                self.wfile.write(asBytes('{:X}\r\n{}\r\n'.format(l, r)))

                print("wrote: {}".format(r))
                data = next(it)
                if data is None:
                    break
                if isinstance(data, StopIteration):
                    break
                response = {
                    'code' : 200,
                    'msg'  : 'OK',
                    'data' : data,
                }
                if isinstance(response['data'], dict):
                    if 'error' in response['data']:
                        response['msg'] = 'FAIL'
        except StopIteration:
            pass

        response = {
            'code' : 200,
            'msg'  : 'OK',
            'iterable' : 'stop',
            'data' : None,
        }
        r = response_fmt.format(response).encode('utf-8')
        l = len(r)
        self.wfile.write(asBytes('{:X}\r\n{}\r\n'.format(l, r)))
        self.wfile.write(asBytes('0\r\n\r\n'))

    def _extract_post_map(self):
        content_type, _t = cgi.parse_header(self.headers.get('content-type'))
        if content_type != 'application/json':
            raise HTTPRequestError(
                    'Bad content-type, use application/json',
                    400)
        length = int(self.headers.get('content-length'))
        try:
            return json.loads(self.rfile.read(length))
        except ValueError as e:
            raise HTTPRequestError(
                    'Bad or malformed json content',
                    400)

    def _extract_query_map(self):
        query = urlparse.urlparse(self.path).query
        qd = urlparse.parse_qs(query)
        args = {}
        for k, v in qd.items():
            if len(v) != 1:
                raise HTTPRequestError(
                    "Query param specified multiple times : " + k,
                    400)
            args[k.lower()] = v[0]
        return args

    def _extract_callback(self):
        try:
            args = self._extract_query_map()
            return args['callback']
        except:
            return ''

    def do_POST(self):
        try:
            args = self._extract_post_map() 
        except TypeError as e:
            # thrown on no content, just continue on
            args = '{}'
        except HTTPRequestError as e:
            self.send_error(e.code, e.msg)
            return
        self._serve(args)

    def do_GET(self):
        try:
            args = self._extract_query_map() 
        except HTTPRequestError as e:
            self.send_error(e.code, e.msg)
            return
        self._serve(args)


"""
API handlers for IDA

"""
def check_ea(f):
    def wrapper(self, args):
        if 'ea' in args:
            try:
                ea = int(args['ea'], 16)
            except ValueError:
                raise IDARequestError(
                        'ea parameter malformed - must be 0xABCD', 400)
            if ea > idc.MaxEA():
                raise IDARequestError(
                        'ea out of range - MaxEA is 0x%x' % idc.MaxEA(), 400)
            args['ea'] = ea
        return f(self, args)
    return wrapper

def check_color(f):
    def wrapper(self, args):
        if 'color' in args:
            color = args['color']
            try:
                color = color.lower().lstrip('#').rstrip('h')
                if color.startswith('0x'):
                    color = color[2:]
                # IDA Color is BBGGRR, we need to convert from RRGGBB
                color = color[-2:] + color[2:4] + color[:2]
                color = int(color, 16)
            except:
                raise IDARequestError(
                        'color parameter malformed - must be RRGGBB form', 400)
            args['color'] = color
        return f(self, args)
    return wrapper

# this doesn't seem to work at all
def require_params(*params):
    def decorator(f):
        def require_params_wrapper(self, args):
            for x in params:
                if x not in args:
                    raise IDARequestError('missing parameter {0}'.format(x), 400)
            return f(self, args)
        require_params_wrapper.__doc__ = f.__doc__
        return require_params_wrapper
    return decorator

class IDARequestError(HTTPRequestError):
    pass

class IDARequestHandler(HTTPRequestHandler):
    @staticmethod
    def _hex(v):
        return hex(v).rstrip('L')

    @staticmethod
    def _from_hex(v):
        if re.match(r'0x[0-9a-fA-F]+$', v):
            return int(v, 16)
        return v

    @staticmethod
    def superglobals():
        _globals = dict(inspect.getmembers(
                    inspect.stack()[len(inspect.stack()) - 1][0]))["f_globals"]
        return _globals

    @staticmethod
    def _dotted(key):
        pieces = key.split('.')
        return pieces

    @staticmethod
    def _ensure_path(_dict, path):
        if not path:
            if API_DEBUG: idaapi.msg("[_ensure_path] empty path\n")
            return None
        for piece in path:
            try: 
                if piece in _dict:
                    _dict = _dict[piece]
            except TypeError:
                if hasattr(_dict, piece):
                    _dict = getattr(_dict, piece)
                else:
                    return None
        return _dict


    @staticmethod
    def _getplus(key):
        _globals = IDARequestHandler.superglobals()

        if isinstance(key, list):
            path = key
        else:
            path = _dotted(key)

        base = IDARequestHandler._ensure_path(_globals, path)
        return base

    @staticmethod
    def error(e):
        if issubclass(e.__class__, Exception):
            _class = str(type(e))            \
                    .replace("<class '", "") \
                    .replace("'>", "")
            _message = str(e)
            result = {
                    "error": "{}: {}".format(_class, _message),
                    "error_trace": traceback.format_exc(),
            }
        else:
            result = {
                    "error": e,
            }
        return result


    @HTTPRequestHandler.route('info')
    def info(self, args):
        # No args, Return everything we can meta-wise about the ida session
        # file crcs
        result = {
                'md5' : idc.GetInputMD5(),
                'idb_path' : idc.GetIdbPath(),
                'file_path' : idc.GetInputFilePath(),
                'ida_dir' : idc.GetIdaDirectory(),
                'min_ea' : self._hex(idc.MinEA()),
                'max_ea' : self._hex(idc.MaxEA()),
                'segments' : self.segments({})['segments'],
                # idaapi.cvar.inf
                'procname' : idc.GetLongPrm(idc.INF_PROCNAME),
            }
        return result

    @HTTPRequestHandler.route('query')
    def query(self, args):
        # multiple modes
        # with address return everything about that address
        # with name, return everything about that name
        idc.jumpto(ida_ida.cvar.inf.min_ea)
        return idc.here()


    @HTTPRequestHandler.route('cursor')
    @check_ea
    def cursor(self, args):
        # XXX - Doesn't work
        #if 'window' in args:
        #    tform = idaapi.find_tform(args['window'])
        #    if tform:
        #        idaapi.switchto_tform(tform, 1)
        #    else:
        #        raise IDARequestError(
        #            'invalid window - {0}'.format(args['window']), 400)
        result = {}
        if 'ea' in args:
            success = idc.jumpto(ea)
            result['moved'] = success
        else:
            result['error'] = "missing argument: ea"
        result['ea'] = self._hex(idc.here())
        return result

    def _get_segment_info(self, s):
        return {
            'name' : idaapi.get_true_segm_name(s),
            'ida_name' : idaapi.get_segm_name(s),
            'start' : self._hex(s.startEA),
            'end' : self._hex(s.end_ea),
            'size' : self._hex(s.size())
        }

    @HTTPRequestHandler.route('segments')
    @check_ea
    def segments(self, args):
        if 'ea' in args:
            s = idaapi.getseg(args['ea'])
            if not s:
                raise IDARequestError('Invalid address', 400)
            return {'segment': self._get_segment_info(s)}
        else:
            m = {'segments': []}
            for i in range(idaapi.get_segm_qty()):
                s = idaapi.getnseg(i)
                m['segments'].append(self._get_segment_info(s))
            return m

    @HTTPRequestHandler.route('call')
    @require_params('cmd')
    def call(self, args):
        """run callable and return result

        :param cmd: callable
        :param args: [optional] comma seperated list of positional arguments
        :param *: [optional] keyword arguments

        $ wget 'http://127.0.0.1:8901/ida/api/v1.0/eval?cmd=type=idc.GetType(0x1412E9E98)&return=type' -O - -q
        {
            'code': 200,
            'msg': 'OK',
            'data': 'void __fastcall(uint8_t *buffer, uint32_t data, uint32_t bits, int32_t offset)'
        }

        """
        if API_DEBUG: idaapi.msg("[call]\n")
        try:
            if not 'cmd' in args:
                return IDARequestHandler.error('missing parameter \'cmd\'')
            cmd = args.pop('cmd')
            _args = []
            _kwargs = {}
            if 'args' in args:
                _args = args.pop('args').split(',')
                _args = [ IDARequestHandler._from_hex(x) for x in _args ]
                if API_DEBUG: idaapi.msg('_args: {}\n'.format(_args))
            for k, v in args.items():
                _kwargs[k] = IDARequestHandler._from_hex(v)
                if API_DEBUG: idaapi.msg('_kwarg: {}: {}\n'.format(k, v))
            fn = IDARequestHandler._getplus(cmd)
            pp({
                'cmd': cmd,
                'fn': fn,
                'args': _args,
                'kwargs': _kwargs,
            })
            if fn is None:
                return IDARequestHandler.error(NameError("name '{}' is not defined".format(cmd)))
            if not callable(fn):
                return IDARequestHandler.error(NameError("name '{}' is not callable".format(cmd)))
            result = fn(*_args, **_kwargs)
            if API_DEBUG: idaapi.msg('result: {}\n'.format(result))
            return result

        except Exception as e:
            return IDARequestHandler.error(e)
        except:
            return IDARequestHandler.error("Unknown Exception")

    @HTTPRequestHandler.route('eval')
    @HTTPRequestHandler.route('exec')
    @require_params('cmd')
    def eval(self, args):
        """evaluate expression via python exec()

        :param cmd: string to evaluate
        :param return: [optional] name of variable to return

        $ wget 'http://127.0.0.1:8901/ida/api/v1.0/eval?cmd=type=idc.GetType(0x1412E9E98)&return=type' -O - -q
        {
            'code': 200,
            'msg': 'OK',
            'data': 'void __fastcall(uint8_t *buffer, uint32_t data, uint32_t bits, int32_t offset)'
        }

        """
        idaapi.msg("Hello Eval\n")
        try:
            if not 'cmd' in args:
                return IDARequestHandler.error('missing parameter \'cmd\'')
            cmd = args['cmd']   
            if API_DEBUG: idaapi.msg('cmd: {}\n'.format(cmd))
            exec(cmd, IDARequestHandler.superglobals())
            if 'return' in args:
                return getglobal(args['return'], None)
        except Exception as e:
            return IDARequestHandler.error(e)

"""
Threaded HTTP Server and Worker

Use a worker thread to manage the server so that we can run inside of
IDA Pro without blocking execution.

"""
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True


class Worker(threading.Thread):
    def __init__(self, host=API_HOST, port=API_PORT):
        threading.Thread.__init__(self)
        self.httpd = ThreadedHTTPServer((host, port), IDARequestHandler)

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        idaapi.msg("httpd shutdown...\n")
        self.httpd.shutdown()
        idaapi.msg("httpd server_close...\n")
        self.httpd.server_close()

"""
IDA Pro Plugin Interface

Define an IDA Python plugin required class and function.
"""

# 
MENU_PATH = 'Edit/Other'
# class idarest_plugin_t(ida_idaapi.plugin_t):
class idarest_plugin_t(object):
    flags = 0
    comment = "Interface to IDA Rest API"
    help = "IDA Rest API for basic RE tool interoperability"
    wanted_name = "IDA Rest API"
    wanted_hotkey = ""

    def init(self):
        super(idarest_plugin_t, self).__init__()

        idaapi.msg("Initializing {}\n".format(self.wanted_name))
        self.state = None
        #  new_ctx1 = ida_kernwin.add_hotkey("Alt-7", lambda *a: self.start())
        #  new_ctx2 = ida_kernwin.add_hotkey("Alt-8", lambda *a: self.stop())
        #  new_ctx2 = ida_kernwin.add_hotkey("Alt-9", lambda *a: self.term())
        #  self.ctxs = [new_ctx1, new_ctx2]
        self.worker = None
        self.port = API_PORT
        self.host = API_HOST
        #  ret = self._add_menus()
        idaapi.msg("Init done\n")
        self.start()
        return idaapi.PLUGIN_KEEP

    def start(self, *args):
        idaapi.msg("Starting IDARest\n")
        if self.worker and self.worker.is_alive():
            idaapi.msg("Already running\n")
            return

        try:
            self.worker = Worker(self.host, self.port)
        except Exception as e:
            idaapi.msg("Error starting worker : \n" + str(e) + "\n")
            return ida_idaapi.PLUGIN_UNL

        self.worker.start()
        idaapi.msg("Worker running\n")
        return ida_idaapi.PLUGIN_KEEP

    def stop(self, *args):
        if self.worker and not self.worker.is_alive():
            idaapi.msg("IDARest worker is not running\n")
            return

        idaapi.msg("Stopping IDARest\n")
        self.worker.stop()
        self.worker.join()
        idaapi.msg("IDARest stopped\n")

    @property
    def handler(self):
        return self.worker.httpd.RequestHandlerClass

    def add_route(self, route_pattern, f):
        self.handler.add_route(self.handler, route_pattern, f)

    def remove_route(self, route_pattern):
        self.handler.remove_route(self.handler, route_pattern)

    def run(self, arg):
        pass

    def term(self):
        idaapi.msg("Terminating %s\n" % self.wanted_name)
        try:
            self.stop()
        except:
            pass
        #  for ctx in self.ctxs:
            #  ida_kernwin.del_hotkey(ctx)

HTTPRequestHandler.idarest_queue = Queue()

#  def PLUGIN_ENTRY():
    #  return idarest_plugin_t()

if __name__ == "__main__":
    if 'ir' in globals() and str(type(globals().get('ir'))).find('idarest_plugin_t') > -1:
        globals()['ir'].term()

    ir = idarest_plugin_t()
    ir.init()
    
    ### example route
    def names(self, args):
        """return all extant names and addresses"""
        m = {'names' : []}
        for n in idautils.Names():
            yield {n[1]: self._hex(n[0])}

    def _sleep(self, args):
        for r in range(5):
            print("[_sleep] {}".format(r))
            yield r
            time.sleep(1)

    ir.add_route('names', names)
    ir.add_route('sleep', _sleep)
    ### end example route

    def relist(self, args):
        return iter_retrace_list(q, once=1)

    ir.add_route('list', relist)
