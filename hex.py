from collections import Sequence
import six
from six.moves import builtins


def isgenerator(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'__len__')
def isflattenable(iterable):
    return hasattr(iterable,'__iter__') and not isinstance(iterable, six.string_types)

# https://stackoverflow.com/questions/42095393/python-map-a-function-over-recursive-iterables
def recursive_map(seq, func):
    for item in seq:
        #  if isinstance(item, six.string_types):
            #  yield func(long(item, 0))
        #  if str(type(item)) in ("<class 'generator'>", "<class 'range'>") and getattr(item, '__iter__', None):
        if isgenerator(item) or isinstance(item, (six.moves.range)):
            # print("recurse_map isgen")
            yield func([x for x in item])
        elif isinstance(item, six.string_types):
            yield func(item)
        elif isinstance(item, Sequence):
            # print("recurse_map {} {}".format(item, type(item)))
            yield type(item)(recursive_map(item, func))
        else:
            yield func(item)


def _makeSequenceMapper(f, pre=None, post=None):
    def _identity(o): 
        return o
    pre = pre or _identity
    post = post or _identity
    def fmap(seq, func):
        return recursive_map(seq, func)
    def function(item):
        # if str(type(item)) in ("<class 'generator'>", "<class 'range'>"):
        if isgenerator(item) or isinstance(item, (six.moves.range,)):
            # print("_makeSequenceMapper isgen")
            return post(type([])(fmap(item, f)))
            #  return [f(x) for x in item]
        elif isinstance(item, six.string_types):
            return post(f(item))
        elif isinstance(item, Sequence):
            return post(type(item)(fmap(item, f)))
        return post(f(item))
    return function

def hexmap(seq):
    return recursive_map(seq, hex)

def hex_callback(item):    
    """
    hex(...)
        hex([number|list]) -> string
        
        Return the hexadecimal representation of [list of] integer or long integer.
    """
    def builtin_hex(number):
        result = builtins.hex(number)
        return result.rstrip('L')

    if isinstance(item, six.string_types):
        try:
            result = builtin_hex(six.integer_types[-1](item, 0))
            return result
        #  except TypeError: return item
        except ValueError:
            return item
    elif isinstance(item, six.integer_types):
        return builtin_hex(item)
    #  if isgenerator(item) or isinstance(item, (six.moves.range, range)):
        #  return [hex(x) for x in item]
    #  if isinstance(item, set):
        #  return type(item)(hexmap(list(item)))
    #  if isinstance(item, Sequence):
        #  return type(item)(hexmap(item))
    else:
        return item


def ahex(item):
    if isinstance(item, six.integer_types):
        if item > 9:
            return hex(item)
    return str(item)

def listComp(item):
    return [x for x in item] if isgenerator(item) or isinstance(item, (six.moves.range, range)) else item

_asList = _makeSequenceMapper(listComp, pre=None) # , post=A)
def asList(o):
    l = []
    if isIterable(o):
        l = genAsList(o)
    else:
        l = _asList(o)

    if not isinstance(l, list) or len(l) == 1 and l[0] == o:
        return [o]
    return l

hex = _makeSequenceMapper(hex_callback)

def asHexList(o):
    return [hex(x) for x in asList(o)]

