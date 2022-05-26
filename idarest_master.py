import socket, atexit
from underscore3 import _
try:
    from .idarest_mixins import IdaRestConfiguration, IdaRestLog
except:
    from idarest_mixins import IdaRestConfiguration, IdaRestLog

#  idarest_master_plugin_t.config['master_debug'] = False
#  idarest_master_plugin_t.config['master_info'] = False
#  idarest_master_plugin_t.config['api_prefix'] = '/ida/api/v1.0'
#  idarest_master_plugin_t.config['master_host'] = "127.0.0.1"
#  idarest_master_plugin_t.config['master_port'] = 28612 # hash('idarest75') & 0xffff
MENU_PATH = 'Edit/Other'

try:
    import idc
    import ida_idaapi
    import ida_kernwin
    import idaapi
    import idautils
    from PyQt5 import QtWidgets
except:
    class idc:
        @staticmethod
        def msg(s):
            if idarest_master_plugin_t.config['master_debug']: print(s)

    class ida_idaapi:
        plugin_t = object
        PLUGIN_SKIP = PLUGIN_UNL = PLUGIN_KEEP = 0

class idarest_master_plugin_t(IdaRestConfiguration, IdaRestLog, ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "IDA Rest API Master Controller"
    help = "Keeps track of idarest75 clients"
    wanted_name = "idarest75 master"
    wanted_hotkey = ""

    def init(self):
        super(idarest_master_plugin_t, self).__init__()
        self.load_configuration()
        if idarest_master_plugin_t.config['master_info']: print("[idarest_master_plugin_t::init]")
        self.master = None

        if not idarest_master_plugin_t.test_bind_port(idarest_master_plugin_t.config['master_port']):
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master_plugin_t::init] skipping (port is already bound)")
            return idaapi.PLUGIN_SKIP

        self.master = idarest_master()
        idarest_master_plugin_t.instance = self

        #  def cleanup():
            # TODO: make master able to clean up! ffs
            #  self.log("**master.atexit** cleanup")
            #  if worker and worker.is_alive():
                #  self.log("[idarest_master_plugin_t::start::cleanup] stopping..\n")
                #  worker.stop()
                #  self.log("[idarest_master_plugin_t::start::cleanup] joining..\n")
                #  worker.join()
                #  self.log("[idarest_master_plugin_t::start::cleanup] stopped\n")
#  
            #  if timer and timer.is_alive() and not timer.stopped():
                #  self.log("[idarest_master_plugin_t::start::cleanup] stopping..\n")
                #  timer.stop()
                #  self.log("[idarest_master_plugin_t::start::cleanup] joining..\n")
                #  timer.join()
                #  self.log("[idarest_master_plugin_t::start::cleanup] stopped\n")

        #  print('[idarest_master_plugin_t::start] registered atexit cleanup')

        #  atexit.register(cleanup)
        return idaapi.PLUGIN_KEEP

    def run(*args):
        pass

    def term(self):
        if self.master:
            self.master.stop()
        pass

    @staticmethod
    def test_bind_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((idarest_master_plugin_t.config['master_host'], port))
            except socket.error as e:
                return False
        return True

def idarest_master():
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    import threading
    import urllib.request, urllib.error, urllib.parse as urlparse
    import requests
    import json
    import time
    import re

    def asBytes(s):
        if isinstance(s, str):
            return s.encode('utf-8')
        return s

    class HTTPRequestError(BaseException):
        def __init__(self, msg, code):
            self.msg = msg
            self.code = code

    class Handler(BaseHTTPRequestHandler):
        hosts = dict()

        def log_message(self, format, *args):
            return

        def register(self, args):
            host, port = args['host'], args['port']
            key = host + ':' + port
            if key in self.hosts:
                if idarest_master_plugin_t.config['master_debug']: print("[idarest_master::Handler::register] replacing existing host {}".format(key))
            self.hosts[key] = value = dict({
                    'host': args['host'],
                    'port': args['port'],
                    'idb': args['idb'],
                    'alive': time.time(),
                    'failed': 0,
            })
            return value

        def unregister(self, args):
            host, port = args['host'], args['port']
            key = host + ':' + port
            if key in self.hosts:
                if idarest_master_plugin_t.config['master_debug']: print("[idarest_master::Handler::unregister] removing existing host {}".format(key))
                value = self.hosts.pop(key)
            else:
                value = dict({
                    'host': args['host'],
                    'port': args['port'],
                    'error': 'not registered',
                })
                    

            return value

        @staticmethod
        def get_json(hosts, args, readonly=False):
            #  r = requests.post(self.url, data=self.args)
            results = dict()
            start = time.time()
            if readonly:
                for k, host in hosts.items():
                    if idarest_master_plugin_t.config['master_debug']: print("alive: {}".format(start - host['alive']))
                    if start - host['alive'] < 90:
                        results[host['idb']] = 'http://{}:{}{}/'.format(host['host'], host['port'], idarest_master_plugin_t.config['api_prefix'])
                    #  else:
                        #  results[host['idb']] = start - host['alive']
                return results

            for k, host in hosts.copy().items():
                start = time.time()
                url = 'http://{}:{}{}/echo'.format(host['host'], host['port'], idarest_master_plugin_t.config['api_prefix'])
                try:
                    connect_timeout = 10
                    read_timeout = 10
                    r = requests.get(url, params=args, timeout=(connect_timeout, read_timeout))
                    if r.status_code == 200:
                        hosts[k]['alive'] = start
                        hosts[k]['rtime'] = r.elapsed.total_seconds()
                        #  hosts[k]['info'] = r.json()
                        results[k] = host
                except Exception as e:
                    results[k] = str(type(e))
                    hosts[k]['failed'] += 1
                    if hosts[k]['failed'] > 4:
                        hosts.pop(k)

            return results


        def show(self, args):
            return self.get_json(self.hosts, {'ping': time.time()}, readonly=True)

        def fail(self, args):
            if 'idb' not in args:
                raise HTTPRequestError("idb param not specified", 400)
            found = _.find(self.hosts, lambda x, *a: x['idb'] == args['idb'])
            print("[fail] found:{}, type(found):{}".format(found, type(found)))
            keys = [x for x, y in self.hosts.items() if y == found]
            if keys:
                for key in keys:
                    if idarest_master_plugin_t.config['master_debug']: print("[idarest_master::Handler::unregister] removing existing host {}".format(key))
                    value = self.hosts.pop(key)
            else:
                value = dict({
                    'host': args['host'],
                    'port': args['port'],
                    'error': 'not registered',
                })
                    

            return value


            return self.get_json(self.hosts, {'ping': time.time()}, readonly=True)

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
                if idarest_master_plugin_t.config['master_debug']: print('args["{}"]: "{}"'.format(k.lower(), v[0]))
            return args

        def send_origin_headers(self):
            if self.headers.get('Origin', '') == 'null':
                self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin'))
            self.send_header('Vary', 'Origin')

        def do_GET(self):
            try:
                args = self._extract_query_map()
            except HTTPRequestError as e:
                self.send_error(e.code, e.msg)
                return

            path = re.sub(r'.*/', '', urlparse.urlparse(self.path).path)
            if path == 'register':
                message = self.register(args)
            elif path == 'unregister':
                message = self.unregister(args)
            elif path == 'show':
                message = self.show(args)
            elif path == 'fail':
                message = self.fail(args)
            elif path == 'term':
                globals()['instance'].term()
            elif path == 'restart':
                # TODO: actually restart
                globals()['instance'].term()
            else:
                self.send_error(400, "unknown route: " + path)
                return

            self.send_response(200)
            self.send_origin_headers()
            self.end_headers()
            self.wfile.write(asBytes(json.dumps(message)))
            return

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        allow_reuse_address = True

    # https://stackoverflow.com/questions/323972/is-there-any-way-to-kill-a-thread
    class Timer(threading.Thread):
        def __init__(self,  *args, **kwargs):
            super(Timer, self).__init__(*args, **kwargs)
            self._stop_event = threading.Event()

        def run(self):
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::run] started")
            while True:
                if self._stop_event.wait(60.0):
                    break
                result = Handler.get_json(Handler.hosts, {'ping': time.time()})
                if idarest_master_plugin_t.config['master_debug']: print("[idarest_master::Timer::run] {}".format(result))
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::run] stopped")

            #  if not self.running:
                #  self.running = True
                #  while self.running:
                    #  time.sleep(60.0 - ((time.time() - self.starttime) % 60.0))
                    #  if idarest_master_plugin_t.config['master_debug']: print(Handler.get_json(Handler.hosts, {'ping': time.time()}))
                #  if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::run] stopped")

        def stop(self):
            if self.is_alive():
                if self.stopped():
                    if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::stop] already stopping...")
                else:
                    if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::stop] stopping...")
                    self._stop_event.set()
            else:
                if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Timer::stop] not running")

        def stopped(self):
            return self._stop_event.is_set()

    class Worker(threading.Thread):
        def __init__(self, host, port):
            threading.Thread.__init__(self)
            self.httpd = ThreadedHTTPServer((host, port), Handler)
            self.host = host
            self.port = port

        def run(self):
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Worker::run] master httpd starting...")
            self.httpd.serve_forever()
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Worker::run] master httpd started (well stopped now, i guess)")

        def stop(self):
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Worker::stop] master httpd shutdown...")
            self.httpd.shutdown()
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Worker::stop] master httpd server_close...")
            self.httpd.server_close()
            if idarest_master_plugin_t.config['master_info']: print("[idarest_master::Worker::stop] master httpd stopped")

    class Master:
        def __init__(self):
            self.worker = Worker('127.0.0.1', 28612)
            self.worker.start()
            self.test_worker = Timer()
            self.test_worker.start()

        def stop(self):
            self.worker.stop()
            self.test_worker.stop()

    def main():
        if idarest_master_plugin_t.config['master_info']: print("[idarest_master::main] starting master")
        master = Master()
        #  main.master = master
        return master

    return main()

def PLUGIN_ENTRY():
    globals()['instance'] = idarest_master_plugin_t()
    return globals()['instance']

if __name__ == "__main__":
    master = idarest_master()
