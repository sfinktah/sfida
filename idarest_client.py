import urllib.request, urllib.error, urllib.parse
import requests
import json
from superglobals import *
from underscoretest import _
execfile('underscoretest')

try:
    from .idarest_mixins import IdaRestConfiguration
except:
    from idarest_mixins import IdaRestConfiguration


#  IdaRestClient.config['master_port'] = 28612 # hash('idarest75') & 0xffff
#  IdaRestClient.config['master_host'] = '127.0.0.1'
#  IdaRestClient.config['api_prefix'] = '/ida/api/v1.0'
#  IdaRestClient.config['api_debug'] = True
#  IdaRestClient.config['api_info'] = True

class _MyChoose(idaapi.Choose):
    def __init__(self, items, title, cols, icon=-1):
        idaapi.Choose.__init__(self, title, cols, flags=idaapi.Choose.CH_MODAL, icon=icon)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class HttpResponseError(Exception):
    pass

class IdaRestClient(IdaRestConfiguration, object):
    def __init__(self):
        self.hosts = {}
        self.master_host = IdaRestClient.config['master_host']
        self.master_port = IdaRestClient.config['master_port']
        self.connect_timeout = IdaRestClient.config['client_connect_timeout']
        self.read_timeout = IdaRestClient.config['client_read_timeout']
        self.update_hosts_timeout = IdaRestClient.config['client_update_hosts_timeout']

    def host_failed(self, url):
        # http://127.0.0.1:2012/ida/api/v1.0/get_type
        idb = _.findKey(self.hosts, lambda x, *a: x.startswith(url))
        if idb:
            request_url = 'http://{}:{}{}/fail?idb={}'.format(self.master_host, self.master_port, IdaRestClient.config['api_prefix'], urllib.parse.quote(idb))

            try:
                request = requests.get(request_url, timeout=self.update_hosts_timeout)
            except requests.exceptions.ReadTimeout:
                print("MasterReadTimeout: {}".format(url + route))
            except requests.exceptions.ConnectTimeout:
                print("MasterConnectTimeout: {}".format(url + route))
            if request.status_code != 200:
                print("MasterHttpResponseError attempting to inform host about slow client: {}".format(r.status_code))

    def terminate_master(self):
        # http://127.0.0.1:2012/ida/api/v1.0/get_type
        request_url = 'http://{}:{}{}/term'.format(self.master_host, self.master_port, IdaRestClient.config['api_prefix'])
        r = requests.get(request_url, timeout=self.update_hosts_timeout)
        if r.status_code != 200:
            print("HttpResponseError attempting to inform host about slow client: {}".format(r.status_code))

    def update_hosts(self):
        request_url = 'http://{}:{}{}/show'.format(self.master_host, self.master_port, IdaRestClient.config['api_prefix'])
        r = requests.get(request_url, timeout=self.update_hosts_timeout)
        if r.status_code != 200:
            raise HttpResponseError(r.status_code)
        # dprint("[debug] request_url, r.content")
        # print("[debug] request_url:{}, r.content:{}".format(request_url, r.content))
        
        if not r.content:
            if self.config['client_debug']: print("[IdaRestClient::update_hosts] master returned no data")
            return
        j = r.json()

        # we need to remove ourself from the list of available hosts, else we
        # will deadlock when trying to self-query
        
        # check if idarest is loaded as a plugin
        ir = getglobal('sys.modules.__plugins__idarest.instance', None)
        # check if idarest is loaded as a module
        ir = ir or getglobal('sys.modules.idarest.instance', None)
        # check if idarest is loaded in global context
        ir = ir or getglobal('idarest_main.instance', None)
        if ir and hasattr(ir, 'host'):
            skip = "http://{}:{}/".format(ir.host, ir.port)
        else:
            skip = None

        self.hosts.clear()
        if isinstance(j, dict):
            for idb, url in j.items():
                if self.config['client_debug']: print("idb: {} url: {}".format(idb, url))
                if not skip or not url.startswith(skip):
                    self.hosts[idb] = url
            return self.hosts
        else:
            if self.config['client_debug']: print("[IdaRestClient::update_hosts] master returned invalid data: {}".format(j))

    def get_json(self, route, host=None, **kwargs):
        """Get the result of an eval query from every active host (except ourselves)"""
        self.update_hosts()
        results = dict()
        if host is not None:
            url = 'http://{}/ida/api/v1.0/'.format(host)
            try:
                request = requests.get(url + route, params=kwargs, timeout=(self.connect_timeout, self.read_timeout))
                if request.status_code != 200:
                    raise HttpResponseError(request.status_code)
                return request
            except requests.exceptions.ReadTimeout:
                print("ReadTimeout: {}".format(url + route))
                self.host_failed(url)
            except requests.exceptions.ConnectTimeout:
                print("ConnectTimeout: {}".format(url + route))
            return

        for idb, url in self.hosts.items():
            try:
                request = requests.get(url + route, params=kwargs, timeout=(self.connect_timeout, self.read_timeout))
                if request.status_code != 200:
                    raise HttpResponseError(request.status_code)
                results[idb] = request.json()
            except requests.exceptions.ReadTimeout:
                print("ReadTimeout: {}".format(url + route))
                self.host_failed(url)
                continue
            except requests.exceptions.ConnectTimeout:
                print("ConnectTimeout: {}".format(url + route))
                continue
        # print("get_json: results: {}".format(results))
        return results

    def GetDecls(self, memcmd='mem("8d 04 11 c3")'):
        results = self.get_json('eval', cmd=memcmd + ".type()")
        print("results: {}".format(results))
        f = _.filterObject(results, lambda v, k, *a: v['msg'] == 'OK' and v['data'] and not v['data'].startswith('False'))
        # o = _.mapObject(f, lambda v, k, *a: (string_between('/', '', k, rightmost=1), _.pick(v, 'data')))
        o = _.mapObject(f, lambda v, k, *a: (
            # key
            string_between('/', '', k, rightmost=1), 
            # value
            string_between("'", "'", v['data'], greedy=1)
        ))
        p = _.pairs(o)
        variable_chooser = _MyChoose(
            p,
            "Select Function",
            [["Database", 25], ["Function", 16]]
        )
        row = variable_chooser.Show(modal=True)
        if row != -1:
            print("Chose {}: {}".format(row, ": ".join(p[row])))
            SetType(EA(), p[row][1].replace('(', ' fn('))

    def eval(self, cmd):
        """ eval(cmd) eval a command on all clients """
        results = self.get_json('eval', cmd=cmd)
        f = _.filterObject(results, lambda v, k, *a: v['msg'] == 'OK' and v['data'] and not v['data'].startswith('False'))
        # o = _.mapObject(f, lambda v, k, *a: (string_between('/', '', k, rightmost=1), _.pick(v, 'data')))
        o = _.mapObject(f, lambda v, k, *a: (
            # key
            string_between('/', '', k, rightmost=1), 
            # value
            string_between("'", "'", v['data'], greedy=1)
        ))
        p = _.pairs(o)
        return p

    def GetNames(self, memcmd='mem("8d 04 11 c3")'):
        results = self.get_json('eval', cmd=memcmd + ".name()")
        f = _.filterObject(results, lambda v, k, *a: v['msg'] == 'OK' and v['data'] and not v['data'].startswith('False'))
        # o = _.mapObject(f, lambda v, k, *a: (string_between('/', '', k, rightmost=1), _.pick(v, 'data')))
        o = _.mapObject(f, lambda v, k, *a: (
            # key
            string_between('/', '', k, rightmost=1), 
            # value
            string_between("'", "'", v['data'], greedy=1)
        ))
        p = _.pairs(o)
        variable_chooser = _MyChoose(
            p,
            "Select Function",
            [["Database", 25], ["Function", 16]]
        )
        row = variable_chooser.Show(modal=True)
        if row != -1:
            print("Chose {}: {}".format(row, ": ".join(p[row])))
            LabelAddressPlus(EA(), p[row][1])

    def GetTypes2(self, types='Hash', ask=False, flags=None):
        if flags is not None:
            results = self.get_json('get_type', type=types, flags=flags)
        else:
            results = self.get_json('get_type', type=types)
        f = _.filterObject(results, lambda v, k, *a: v['msg'] == 'OK' and 'data' in v and v['data'] and 'data' in v['data'][0])
        # o = _.mapObject(f, lambda v, k, *a: (string_between('/', '', k, rightmost=1), _.pick(v, 'data')))
        o = _.mapObject(f, lambda v, k, *a: (
            # key
            string_between('/', '', k, rightmost=1), 
            # value
            v['data'][0]['data']
        ))
        p = _.pairs(o)
        variable_chooser = _MyChoose(
            p,
            "Select Function",
            [["Database", 25], ["Function", 16]]
        )
        row = variable_chooser.Show(modal=True)
        if row != -1:
            cdecl_typedef = p[row][1]
            if ask:
                cdecl_typedef = idaapi.ask_text(0x10000, cdecl_typedef, "The following new type will be created")
                if not cdecl_typedef:
                    return
            print("Parsing decls {}: {}".format(row, cdecl_typedef))
            idc.parse_decls(cdecl_typedef)


    @staticmethod
    def GetTypes(types, decls={}):
        """
        An example of how to request type decls from all hosts and then
        select only one
        :param types: a typename or list of types
        :param decls: dict which will contain {typename: decl} items
        :returns: number of hosts which returned decls, or 0 if none
        """
        def asList(l):
            if not isinstance(l, list):
                return [l]
            return l

        count = 0
        q = IdaRestClient()
        
        response = q.get_json('get_type', type=','.join(asList(types)))
        if isinstance(response, dict):
            for idb, r in response.items():
                if r['msg'] == 'OK':
                    if isinstance(r['data'], list):
                        for t in r['data']:
                            if t['msg'] == 'OK':
                                name = t['name']
                                data = t['data']
                                if q.config['client_debug']: print("received definition for type '{}': {}".format(name, data))
                                if name not in decls:
                                    decls[name] = data
                                else:
                                    if len(data.split('\n')) >= len(decls[name].split('\n')):
                                        decls[name] = data
                                        if q.config['client_debug']: print("using second definition for type '{}'".format(name))
                                    else:
                                        if q.config['client_debug']: print("using first definition for type '{}'".format(name))
                                count += 1
        else:
            print("Unexpected return type: {}".format(type(response)))
            #  if r['msg'] == 'OK':
                #  if isinstance(r['data'], list):
                    #  for t in r['data']:
                        #  if t['msg'] == 'OK':
                            #  name = t['name']
                            #  data = t['data']
                            #  if q.config['client_debug']: print("received definition for type '{}': {}".format(name, data))
                            #  decls[name] = data
                            #  count += 1

        return count

IdaRestClient.load_configuration()
irc = IdaRestClient()
# irc.read_timeout = 2
# irc.update_hosts_timeout = 2
