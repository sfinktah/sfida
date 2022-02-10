import inspect
import sys

def _isString(o):
    return isinstance(o, str)

class _NotFound:
    pass

def superglobals():
    """
    returns what `globals()` would return from __main__ context
    """
    _globals = dict(inspect.getmembers(
                inspect.stack()[len(inspect.stack()) - 1][0]))["f_globals"]
    return _globals

def _dotted(key):
    if isinstance(key, list):
        return key

    key = key.replace(r'\.', 'PSIOUFJRHPRIUENG')
    pieces = key.split('.')
    return [x.replace('PSIOUFJRHPRIUENG', '.') for x in pieces]

def _oget(obj, key, default=None):
    """Get attribute or dictionary value of object
    Parameters
    ----------
    obj : object
        container with optional dict-like properties
    key : str
        key
    default : any
        value to return on failure

    Returns
    -------
    any
        similar to obj[key] or getattr(obj, key)

    Examples
    --------
    >>> _oget(sys.modules, '__main__') #doctest: +ELLIPSIS
    <module '...' ...>
    """
    if not _isString(key):
        raise TypeError("_oget(): attribute ('{}') name must be string".format(key))
    try:
        return obj[key] if key in obj else default
    except TypeError:
        # TypeError: 'module' object is not subscriptable
        return getattr(obj, key, default)

def _ohas(obj, key):
    """Return whether the object has an attribute/dictionary key with the given name."""
    r = _oget(obj, key, _NotFound)
    return r != _NotFound

def _odel(obj, key):
    """Delete attribute or dictionary value of object
    Parameters
    ----------
    obj : object
        container with optional dict-like properties
    key : str
        key

    Returns
    -------
    bool
        True if key existed and was deleted

    Examples
    --------
    >>> d = {'a': 1, 'b': 2}
    >>> _odel(d, 'a')
    True
    >>> d
    {'b': 2}


    """
    if not _isString(key):
        raise TypeError("_oget(): attribute ('{}') name must be string".format(key))
    default = _NotFound
    try:
        if key in obj:
            del obj[key]
            return True

    except TypeError:
        # TypeError: argument of type 'sometype' is not iterable
        if hasattr(obj, key):
            delattr(obj, key)
            return True

    return False

def _oset(obj, key, value):
    """Set attribute or dictionary value of object
    Parameters
    ----------
    obj : object
        container with optional dict-like properties
    key : str
        key
    value : any
        value

    Returns
    -------
    any
        previous value or None

    Examples
    --------
    >>> d = {'a': 1, 'b': 2}
    >>> _oset(d, 'c', 3)
    >>> d
    {'a': 1, 'b': 2, 'c': 3}


    """
    if not _isString(key):
        raise TypeError("_oget(): attribute ('{}') name must be string".format(key))
    default = _NotFound
    rv = None
    try:
        if key in obj:
            rv = obj[key]
        obj[key] = value

    except TypeError:
        # TypeError: argument of type 'sometype' is not iterable
        if hasattr(obj, key):
            rv = getattr(obj, key)
        setattr(obj, key, value)

    return rv

def _ensure_path(_dict, path, create_path=False):
    """
    >>> d = dict()
    >>> _ensure_path(d, 'i.c.k', create_path=True)
    {}
    >>> d['i']['c']['k']
    {}
    """
    for piece in _dotted(path):
        try:
            if piece in _dict:
                _dict = _dict[piece]
            elif create_path:
                _dict[piece] = dict()
                _dict = _dict[piece]
            else:
                return None

        except TypeError:
            if hasattr(_dict, piece):
                _dict = getattr(_dict, piece)
            elif create_path:
                setattr(_dict, piece, dict())
                _dict = getattr(_dict, piece)
            else:
                return None

    return _dict


def _base(path, create_path=False, limit=-1):
    return _ensure_path(superglobals(), _dotted(path)[0:limit], create_path=create_path)

def _full(path, create_path=False):
    return _ensure_path(superglobals(), _dotted(path), create_path=create_path)

def hasglobal(key):
    """
    hasglobal(name) -> bool

    Return whether the global variable `key` exists

    >>> hasglobal('builtins.slice') or hasglobal('__builtins__.slice')
    True
    """
    path = _dotted(key)
    base = _base(path)
    if base is not None:
        return _ohas(base, path[-1])

def getglobal(path, default=None, _type=None):
    """
    getglobal(key[, default]) -> value
    
    Return the value for key if key is in the global dictionary, else default.
    """
    if hasglobal(path):
        result = _full(path)
        if _type is None:
            return result
        if isinstance(result, _type):
            return result
            #            fail = True
            #            _types = None
            #            if isinstance(_type, tuple):
            #                fail = False
            #                _types = _type
            #                for t in _types:
            #                    if _type._class__.__name__ != 'type':
            #                        fail = True
            #            elif _type._class__.__name__ == 'type':
            #                _types = (_type,)
            #                fail = False
            #            if fail:
            #                raise TypeError('_type must be a type or tuple of types')

    return default

def setglobal(key, value):
    """Set `key` from global dictionary

    :param key (str): key
    :param value (any): value
    :raise TypeError: if a heirachical dotted key string's path was invalid
    :return any: previous value or None

    >>> _ = removeglobal('test')
    >>> _ = setglobal('test.deep.global.value', 7)
    >>> test = getglobal('test')
    >>> test['deep']['global']['value']
    7
    """
    path = _dotted(key)
    base = _base(path, create_path=True)
    if base is None:
        raise TypeError("globals::{} was not accessible".format('.'.join(key[0:-1])))
    return _oset(base, path[-1], value)

def removeglobal(key, quiet=False):
    """Remove `key` from global dictionary

    :param key (str): key
    :param quiet (bool): fail silently
    :return: True if the key existed
    :raise TypeError: if a heirachical dotted key string's path did not exist
    """
    path = _dotted(key)
    base = _base(path)
    if base is None:
        return False
    return _odel(base, path[-1])

def defaultglobal(key, value):
    """
    defaultglobal(key, value)

    Set the value of global variable `key` if it is not otherwise set and
    return the new/existing contents of the global variable
    """
    if not hasglobal(key):
        setglobal(key, value)
    result = getglobal(key, _NotFound)
    if result == _NotFound:
        raise RuntimeError("Couldn't setglobal(\"{}\", \"{}\")".format(key, value))
    return result
