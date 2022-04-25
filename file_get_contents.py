import os

def smart_path(pn):
    if os.path.sep == '\\':
        m = re.match(r'((?:/cygwin)?)/(\w)/(.*)', pn)
        if m:
            pn = "{}:/{}".format(m.group(2), m.group(3))

    pn = os.path.abspath(pn)
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

def file_enumerate_lines(fn, index=0):
    """ reads 1 line at a time from file """
    fn = smart_path(fn)
    fr = open(os.path.normpath(fn), encoding='utf-8', newline=None)
    count = index
    for line in fr:
        yield count, line
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

