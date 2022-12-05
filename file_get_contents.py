import os
import re

def smart_path(pn):
    if os.path.sep == '\\':
        m = re.match(r'((?:/cygwin)?)/(\w)/(.*)', pn)
        if m:
            pn = "{}:/{}".format(m.group(2), m.group(3))

    pn = os.path.abspath(pn).replace("\\", "/")
    return pn


#  def file_size(fn):
    #  fn = smart_p
    #  return os.path.getsize(fn)
#  
#  def file_exists(fn):
    #  return os.path.exists(fn) and os.path.isfile(fn)
#  
#  def dir_exists(fn):
    #  return os.path.exists(fn) and os.path.isdir(fn)
#  
#  
#  def file_get_contents(fn):
    #  return open(fn, encoding='utf-8', newline=None).read()
#  
#  def file_get_contents_bin(fn):
    #  return open(fn, 'rb').read()
#  
#  
#  def file_put_contents(fn, data):
    #  with open(fn, 'w') as f:
        #  f.write(data)
    #  return os.path.abspath(fn)
#  
#  def file_put_contents_bin(fn, data):
    #  with open(fn, 'wb') as f:
        #  f.write(data)
    #  return os.path.abspath(fn)


def file_size(fn):
    fn = smart_path(fn)
    return os.path.getsize(fn)

def file_exists(fn):
    fn = smart_path(fn)
    return os.path.exists(fn) and os.path.isfile(fn)

def dir_exists(fn):
    fn = smart_path(fn)
    return os.path.exists(fn) and os.path.isdir(fn)


def file_get_contents(fn):
    fn = smart_path(fn)
    return open(os.path.normpath(fn), encoding='utf-8', newline=None).read()

def file_get_lines(fn):
    """ reads all lines into memory and returns array """
    fn = smart_path(fn)
    return open(os.path.normpath(fn), encoding='utf-8', newline=None).readlines()

def file_get_filtered(fn, predicate=None):
    """ reads 1 line at a time from file and filters """
    fn = smart_path(fn)
    fr = open(os.path.normpath(fn), encoding='utf-8', newline=None)
    for line in filter(predicate, fr):
        yield line[0:-1]

def file_enumerate_lines(fn, index=0, encoding='utf-8'):
    """ reads 1 line at a time from file """
    fn = smart_path(fn)
    fr = open(os.path.normpath(fn), encoding=encoding, newline=None)
    count = index
    for line in fr:
        yield count, line[0:-1]
        count += 1


def file_get_contents_bin(fn):
    fn = smart_path(fn)
    return open(os.path.normpath(fn), 'rb').read()


def file_put_contents(fn, data):
    fn = smart_path(fn)
    with open(os.path.normpath(fn), 'w') as f:
        f.write(data)
    return os.path.abspath(fn)

def file_put_contents_bin(fn, data):
    fn = smart_path(fn)
    with open(os.path.normpath(fn), 'wb') as f:
        f.write(data)
    return os.path.abspath(fn)

class file_put_context(object):
    """Docstring for file_put_context """

    def __init__(self, file, mode='w', buffering=-1, encoding=None, *args, **kwargs):
        """
        opens a file in a context
        """
        self._file = smart_path(file)
        self._mode = mode
        self._buffering = buffering
        self._encoding = encoding
        self._args = args
        self._kwargs = kwargs
        self._filehandle = None

    def __enter__(self):
        self._filehandle = open(os.path.normpath(self._file), mode=self._mode, buffering=self._buffering,
                encoding=self._encoding, *self._args, **self._kwargs)
        return self._filehandle
    
    def __exit__(self, exc_type, exc_value, traceback):
        self._filehandle.close()

        


