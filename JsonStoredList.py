# see: https://stackoverflow.com/questions/865115/how-do-i-correctly-clean-up-a-python-object/865272#865272
#
# with JsonStoredList('filename.json') as alist:
#     print("length: %i" % len(alist))
import json
import tempfile
import os
import sys
import requests
import urllib
from collections import defaultdict

# requires https://pypi.org/project/pyosreplace/ on python2.7 under windows
if sys.version_info >= (3, 3):
    from os import replace
elif sys.platform == "win32":
    from osreplace import replace
else:
    # POSIX rename() is always atomic
    from os import rename as replace

from execfile import make_refresh
refresh_JsonStoredList = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))


def json_load(_fn, _default=None):
    if _fn.startswith("http"):
        return json.loads(requests.get(_fn).text)
    try:
        with open(_fn, 'r') as f:
            return json.load(f)
    except IOError:
        if not _default:
            raise IOError
        print("file not found '{}' or some such, making empty object".format(os.path.realpath(_fn)))
        return _default

def json_save_safe(dst, json_object):
    dirname, basename = os.path.split(dst)
    try:
        with tempfile.NamedTemporaryFile(prefix=basename, mode='w', dir=dirname, delete=False) as filename:
                filename.file.write(json.dumps(json_object))
                filename.file.close()
                print("replace({}, {})".format(filename.name, dst))
                print("file_exists", os.path.exists(filename.name))
                replace(filename.name, dst)
                if os.path.exists(filename.name):
                    os.unlink(filename.name)
    #  except IOError:
        #  print("file not writable or some such")
    except Exception as e:
        print("**EXCEPTION** {}: {}".format(e.__class__.__name__, str(e)))


class JsonStoredList(object):
    def __init__(self, _fn):
        #  cwd = GetIdbPath()
        #  cwd = cwd[:cwd.rfind(os.sep)] + os.sep # + GetInputFile()
        self.fn = os.path.abspath(_fn)

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        json_save_safe(self.fn, list(self.d))
        print(str(__class__) + "::__exit__, " + str(exc_type) + ", " + str(exc_value) + ", " + str(traceback))

    def _hash(self):
        return hash(tuple(self.d))

    def save(self):
        try:
            new_hash = self._hash()
            if new_hash != self._hash():
                json_save_safe(self.fn, list(self.d))
                self.hash_value = new_hash
            else:
                print(str(__class__) + "::save -- hash didn't change, saving anyway")
                json_save_safe(self.fn, list(self.d))

        except TypeError:
            print(str(__class__) + "::save -- typeerror, saving anyway")
            json_save_safe(self.fn, list(self.d))

    def load(self):
        self.d = self.loadjson(self.fn)
        try:
            self.hash_value = self._hash()
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
        #  cwd = GetIdbPath()
        #  cwd = cwd[:cwd.rfind(os.sep)] + os.sep # + GetInputFile()
        #  self.fn = cwd + _fn
        self.fn = os.path.abspath(_fn)

    def __enter__(self):
        self.load()
        return self.d

    def __exit__(self, exc_type, exc_value, traceback):
        self.save()

    def save(self):
        new_hash = self._hash()
        if new_hash != self.hash_value:
            json_save_safe(self.fn, list(self.d))
            self.hash_value = new_hash

    def load(self):
        self.d = set(self.loadjson(self.fn))
        self.hash_value = self._hash()
    
class JsonStoredDict(object):
    def __init__(self, _fn):
        url = urllib.parse.urlparse(_fn)
        if not url[0].startswith('http'):
            self.fn = os.path.abspath(_fn)
        else:
            self.fn = _fn
        pass

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
        return json_load(_fn, dict())

class JsonStoredDefaultDictList(object):
    def __init__(self, _fn):
        #  self.fn = _fn
        self.fn = os.path.abspath(_fn)

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
