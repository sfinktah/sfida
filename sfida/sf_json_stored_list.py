# see: https://stackoverflow.com/questions/865115/how-do-i-correctly-clean-up-a-python-object/865272#865272
#
# with JsonStoredList('filename.json') as alist:
#     print("length: %i" % len(alist))
import json
import tempfile
import os
import sys
from collections import defaultdict

# requires https://pypi.org/project/pyosreplace/ on python2.7 under windows
if sys.version_info >= (3, 3):
    from os import replace
elif sys.platform == "win32":
    from osreplace import replace
else:
    # POSIX rename() is always atomic
    from os import rename as replace

with open(os.path.dirname(__file__) + os.sep + 'refresh.py', 'r') as f:    \
    exec(compile(f.read().replace('__BASE__',                              \
        os.path.basename(__file__).replace('.py', '')).replace('__FILE__', \
            __file__), __file__, 'exec'))

def json_load(_fn, _default=[]):
    try:
        with open(_fn, 'r') as f:
            return json.load(f)
    except IOError:
        print("file not found '{}' or some such, making empty object".format(os.path.realpath(_fn)))
        return _default

def json_save_safe(dst, json_object):
    dirname, basename = os.path.split(dst)
    try:
        #  with tempfile.NamedTemporaryFile(prefix=basename, dir=dirname, delete=False) as filename:
            #  try:
                #  print("NamedTemporaryFile", filename)
                #  json.dump(json_object, filename)
                #  filename.close()
                #  replace(filename.name, filename)
            #  except:
                #  print("error dumping data to json")
        with tempfile.NamedTemporaryFile(prefix=basename, mode='w', dir=dirname, delete=False) as filename:
            #  {   '__str__': <method-wrapper '__str__' of file object at 0x000002453E54EAE0>,
            #  'close_called': False,
            #  'delete': True,
            #  'file': <open file '<fdopen>', mode 'w+b' at 0x000002453E54EAE0>,
            #  'name': 'e:\\appdatalocaltmp\\tmpbnt2ko'}
            #  try:
                filename.file.write(json.dumps(json_object))
                filename.file.close()
                print("replace({}, {})".format(filename.name, dst))
                print("file_exists", os.path.exists(filename.name))
                replace(filename.name, dst)
                if os.path.exists(filename.name):
                    os.unlink(filename.name)

            #  except:
                #  print("error dumping data to json")
    except IOError:
        print("file not writable or some such")


class JsonStoredList(object):
    def __init__(self, _fn):
        cwd = GetIdbPath()
        cwd = cwd[:cwd.rfind(os.sep)] + os.sep # + GetInputFile()
        self.fn = cwd + _fn

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()

    def save(self):
        try:
            if hash(tuple(self.d)) != self.hash_value:
                json_save_safe(self.fn, list(self.d))
        except TypeError:
            json_save_safe(self.fn, list(self.d))

    def load(self):
        self.d = self.loadjson(self.fn)
        try:
            self.hash_value = hash(tuple(self.d))
        except TypeError:
            self.hash_value = 0
    
    def loadjson(self, _fn):
        try:
            with open(_fn, 'r') as f:
                return json.load(f)
        except IOError:
            print("file not found '{}' or some such, making empty list".format(os.path.realpath(_fn)))
            return []

class JsonStoredSet(JsonStoredList):
    def __init__(self, _fn):
        cwd = GetIdbPath()
        cwd = cwd[:cwd.rfind(os.sep)] + os.sep # + GetInputFile()
        self.fn = cwd + _fn

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()

    def save(self):
        if hash(tuple(self.d)) != self.hash_value:
            json_save_safe(self.fn, list(self.d))

    def load(self):
        self.d = set(self.loadjson(self.fn))
        self.hash_value = hash(tuple(self.d))
    
class JsonStoredDict(object):
    def __init__(self, _fn):
        self.fn = _fn

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()

    def save(self):
        json_save_safe(self.fn, self.d)

    def load(self):
        self.d = self.loadjson(self.fn)
    
    def loadjson(self, _fn):
        try:
            with open(_fn, 'r') as f:
                return json.load(f)
        except IOError:
            print("file not found '{}' or some such, making empty dict".format(os.path.realpath(_fn)))
            return dict()

class JsonStoredDefaultDictList(object):
    def __init__(self, _fn):
        self.fn = _fn

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()

    def save(self):
        json_save_safe(self.fn, self.d)

    def load(self):
        self.d = defaultdict(list)
        data = self.loadjson(self.fn)
        for k, v in data.items():
            self.d[k].extend(v)
    
    def loadjson(self, _fn):
        try:
            with open(_fn, 'r') as f:
                return json.load(f)
        except IOError:
            print("file not found '{}' or some such, making empty dict".format(os.path.realpath(_fn)))
            return defaultdict(list)


print("JsonStoredList loaded")

"""
with JsonStoredDict('demangled1.json') as dm:
    for f in Functions():
        fn = GetFunctionName(f)
        dm[fn] = [demangle_name(fn, get_inf_attr(INF_SHORT_DN)), demangle_name(fn, get_inf_attr(INF_LONG_DN))]

"""
