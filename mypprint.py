from pprint import PrettyPrinter
from underscoretest import _
from itertools import islice

import re


def chunk_tuple(it, size):
    """Yield successive n-sized tuples from lst."""
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())


def read_everything(insn):
    result = [[method_name, getattr(insn, method_name)] for method_name in dir(insn)
              if method_name not in ('copyright', 'credits', 'parent', 'meminfo',
                                     'next', 'this', 'prev', 'head', 'tail', 'mba',
                                     'mbr')
              and hasattr(insn, method_name)
              and not method_name.startswith('_')
              and not re.match(r'.*(bound|built-in) method', str(getattr(insn, method_name)), re.I)
              and not issubclass(type(getattr(insn, method_name)), (Exception, BaseException))
              # and getattr(insn, method_name, False)
              ]
    if result:
        #  nicer = []
        #  for l, r in result:
        #  if str(r).startswith('<'):
        #  sb = string_between('<', ';', str(r))
        #  if sb:
        #  r = sb
        #  nicer.append([l, r])
        return _.omit(_.zipObject(result), 'parent')
    return insn


class MyPrettyPrinter(PrettyPrinter):
    if getattr(PrettyPrinter, '_dispatch', None):
        _dispatch = PrettyPrinter._dispatch.copy()

    def _format(self, object, stream, indent, allowance, context, level):
        # check for pprint compatible object
        _pprint_repr = getattr(type(object), '__pprint_repr__', None)
        if _pprint_repr:
            return PrettyPrinter._format(self, _pprint_repr(object, stream=stream,
                                                            indent=indent, allowance=allowance, context=context,
                                                            level=level),
                                         stream, indent, allowance, context, level)
        if repr(object).startswith('<') and repr(object).endswith('>') and level < 8:
            return PrettyPrinter._format(self, read_everything(object),
                                         stream, indent, allowance, context, level)

        # else check for alternate _pprint method (if supported ~ python 3.3)
        if getattr(PrettyPrinter, '_dispatch', None):
            _repr = type(object).__repr__
            _pprint = getattr(type(object), '__pprint__', None)
            _exists = self._dispatch.get(_repr, None)
            if not _exists and _pprint:
                self._dispatch[_repr] = _pprint

        return PrettyPrinter._format(self, object, stream, indent, allowance, context, level)

    #    def isreadable(*args, **kwargs): return super(MyPrettyPrinter, self).isreadable(*args, **kwargs)
    #    def isrecursive(*args, **kwargs): return super(MyPrettyPrinter, self).isrecursive(*args, **kwargs)
    #    def pformat(*args, **kwargs): return super(MyPrettyPrinter, self).pformat(*args, **kwargs)
    #    def pprint(*args, **kwargs): return super(MyPrettyPrinter, self).pprint(*args, **kwargs)
    #    def re(*args, **kwargs): return super(MyPrettyPrinter, self).re(*args, **kwargs)
    #    def saferepr(*args, **kwargs): return super(MyPrettyPrinter, self).saferepr(*args, **kwargs)
