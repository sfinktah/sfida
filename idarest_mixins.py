import os
import sys
import json
import pydoc
from queue import Full
from superglobals import *

try:
    import idaapi
    import idc
except:
    class idaapi:
        def get_user_idadir(): return '.'
    class idc:
        def get_idb_path(): return '.'

class Namespace(object):
    pass

class IdaRestLog:
    PROJECT_LOG_FILE = os.path.join( os.path.dirname( idc.get_idb_path() ), "idarest.log" )

    @staticmethod
    def log(msg):
        with open(IdaRestLog.PROJECT_LOG_FILE, 'a') as f:
            f.write(msg.rstrip() + "\n")



class IdaRestConfiguration:

    CFG_FILE = os.path.join(idaapi.get_user_idadir(), "idarest.cfg")
    PROJECT_CFG_FILE = os.path.join( os.path.dirname( idc.get_idb_path() ), "idarest.cfg" )
    config = {
       'api_host':     '127.0.0.1',
       'api_port':     2000,

       'master_host':  '127.0.0.1',
       'master_port':  28612,

       'api_prefix':   '/ida/api/v1.0',

       'api_verbose':  False,
       'api_debug':    False,
       'api_info':     True,
       'master_debug': False,
       'master_info':  False,
       'client_debug': False,
       'client_info':  True,

       'client_connect_timeout': 2,
       'client_read_timeout': 2,
       'client_update_hosts_timeout': 2,

       'api_queue_result_qget_timeout': 10,
    }

    @staticmethod
    def _each(obj, func):
        """
        iterates through _each item of an object
        :param: obj object to iterate
        :param: func iterator function

        underscore.js:
        Iterates over a list of elements, yielding each in turn to an iteratee
        function.  Each invocation of iteratee is called with three arguments:
        (element, index, list).  If list is a JavaScript object, iteratee's
        arguments will be (value, key, list). Returns the list for chaining.
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                func(value, key, obj)
        else:
            for index, value in enumerate(obj):
                r = func(value, index, obj)
        return obj

    @staticmethod
    def _defaults(obj, *args):
        """ Fill in a given object with default properties.
        """
        ns = Namespace()
        ns.obj = obj

        def by(source, *a):
            for i, prop in enumerate(source):
                if prop not in ns.obj:
                    ns.obj[prop] = source[prop]

        IdaRestConfiguration._each(args, by)

        return ns.obj

        
    @classmethod
    def load_configuration(self):
       # default
  
        # load configuration from file
        saved_config = {}
        try:
            f = open(self.CFG_FILE, "r")
            self.config.update(json.load(f))
            saved_config = self.config.copy()
            f.close()
            print("[IdaRestConfiguration::load_configuration] loaded global config file")
        except IOError:
            print("[IdaRestConfiguration::load_configuration] failed to load global config file, using defaults")
        except Exception as e:
            print("[IdaRestConfiguration::load_configuration] failed to load global config file: {0}".format(str(e)))
   
        # use default values if not defined in config file
        #  self._defaults(self.config, {
           #  'api_host':     '127.0.0.1',
           #  'api_port':     2000,
#  
           #  'master_host':  '127.0.0.1',
           #  'master_port':  28612,
#  
           #  'api_prefix':   '/ida/api/v1.0',
#  
           #  'api_verbose':    False,
           #  'api_debug':    False,
           #  'api_info':     True,
           #  'master_debug': False,
           #  'master_info':  False,
           #  'client_debug': True,
           #  'client_info':  True,
#  
           #  'api_queue_result_qget_timeout': 10,
        #  })

        if self.config != saved_config:
            try:
                json.dump(self.config, open(self.CFG_FILE, "w"), indent=4)
                print("[IdaRestConfiguration::load_configuration] global configuration saved to {0}".format(self.CFG_FILE))
            except Exception as e:
                print("[IdaRestConfiguration::load_configuration] failed to save global config file, with exception: {0}".format(str(e)))

        if os.path.exists(self.PROJECT_CFG_FILE):
            print("[IdaRestConfiguration::load_configuration] loading project config file: {0}".format(self.PROJECT_CFG_FILE))
            try:
                f = open(self.PROJECT_CFG_FILE, "r")
                self.config.update(json.load(f))
                f.close()
                print("[IdaRestConfiguration::load_configuration] loaded project config file: {0}".format(self.PROJECT_CFG_FILE))
            except IOError:
                print("[IdaRestConfiguration::load_configuration] failed to load project config file, using global config")
            except Exception as e:
                print("[IdaRestConfiguration::load_configuration] failed to load project config file: {0}".format(str(e)))
   

class BorrowStdOut:

    @staticmethod
    def is_default_stdout(out):
        return out.__class__.__name__ == 'IDAPythonStdOut'

    class IDARestStdOutTee:
        def __init__(self, out1, out2):
            self.out1 = out1
            self.out2 = out2

        def write(self, text):
            # NB: in case 'text' is Unicode, msg() will decode it
            # and call msg() to print it
            # self.queue.put(text)
            self.out1.write(text)
            self.out2.write(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    class IDARestStdOutQueue(object):
        def __init__(self, queue):
            self.queue = queue

        def write(self, text):
            # NB: in case 'text' is Unicode, msg() will decode it
            # and call msg() to print it
            # self.queue.put(text)
            try:
                self.queue.put_nowait(text)
            except Full:
                pass

        def flush(self):
            pass

        def isatty(self):
            return False

    class IDARestStdOut:
        """
        Dummy file-like class that receives stout and stderr
        """
        def __init__(self, buffer=[]):
            self.buffer = buffer
            #  self.buffer = ''

        def write(self, text):
            # NB: in case 'text' is Unicode, msg() will decode it
            # and call msg() to print it
            self.buffer.append(text)

        def flush(self):
            pass

        def isatty(self):
            return False

    def get_output_class(self, t):
        if t.__class__.__name__ == 'Queue':
            return self.IDARestStdOutQueue
        elif isinstance(t, list):
            return self.IDARestStdOut

    def __init__(self, stdout=None, stderr=None, is_help=False):
        self.stdout_list = stdout
        self.stderr_list = stderr
        self.is_help = is_help

        #  self.stdout = None
        #  self.stderr = None
        self.help = None

    def __enter__(self):
        self.stdout, self.stderr = sys.stdout, sys.stderr
        _cls = self.get_output_class(self.stdout_list)
        # sys.stdout, sys.stderr = self.IDARestStdOut(self.stdout_list), self.IDARestStdOut(self.stderr_list)
        sys.stdout, sys.stderr = _cls(self.stdout_list), _cls(self.stderr_list)
        if self.is_help:
            self.help = setglobal('help', pydoc.Helper())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        global help
        sys.stdout, sys.stderr = self.stdout, self.stderr
        if self.help:
            setglobal('help', self.help)
        if self.stdout_list.__class__.__name__ == 'Queue':
            self.stdout_list.put(None)
