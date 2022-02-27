import os

def file_size(fn):
    return os.path.getsize(fn)

def file_exists(fn):
    return os.path.exists(fn) and os.path.isfile(fn)

def dir_exists(fn):
    return os.path.exists(fn) and os.path.isdir(fn)


def file_get_contents(fn):
    return open(fn, encoding='utf-8', newline=None).read()

def file_get_contents_bin(fn):
    return open(fn, 'rb').read()


def file_put_contents(fn, data):
    with open(fn, 'w') as f:
        f.write(data)
    return os.path.abspath(fn)

def file_put_contents_bin(fn, data):
    with open(fn, 'wb') as f:
        f.write(data)
    return os.path.abspath(fn)


