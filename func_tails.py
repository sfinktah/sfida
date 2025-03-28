# For making a quick copy of a function
# func_tails(ea, dict)
# for k, v in dict.items():
#     ida_bytes.patch_bytes(int(k), v)
#     forceCode(int(k), len(v))

#  from exectools import make_refresh
import os
import re
import sys
import ida_funcs, idc, ida_bytes, idautils
from collections import defaultdict
from collections import deque

if not idc:
    from idb.idapython import idautils
    from di import diida
    from exectools import make_refresh
    #  from function_address_export import _node_format
    from helpers import UnPatch
    from python3.idc_bc695 import GetFunctionName
    from sfcommon import GetFuncStart, forceCode
    from sfida.sf_is_flags import IsFlow
    from sfida.sf_string_between import string_between
    from sftools import eax
    from slowtrace_helpers import GetInsnLen, isConditionalJmp, isAnyJmp, GetTarget, isNop, isRet, isCall, \
        GetChunkOwners, CreateInsns
    from underscoretest import _

refresh_func_tails = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

class recursion_depth:
    def __init__(self, limit):
        self.limit = limit
        self.default_limit = sys.getrecursionlimit()
    def __enter__(self):
        sys.setrecursionlimit(self.limit)
    def __exit__(self, type, value, traceback):
        sys.setrecursionlimit(self.default_limit)

def _node_format(ea):
    if isinstance(ea, int):
        if HasUserName(ea):
            return idc.get_name(ea, idc.calc_gtn_flags(ea, ea))
        return hex(ea).replace('0x', '')
    return ea

#  check_for_update = make_auto_refresh(os.path.abspath(__file__.replace('2', '_helpers')))


def skip_first(gen):
    for i, n in enumerate(gen):
        if i == 0:
            continue

        yield n


class FuncTailsError(object):
    def __init__(self):
        pass

    def __str__(self):
        return "{}: {}".format(
            self.__class__.__name__,
            ", ".join(
                    ["{}: {}".format(k, ahex(getattr(self, k))) for k in dir(self) if str(k)[0] != '_']
                ))



    # https://stackoverflow.com/questions/40828173/how-can-i-make-my-class-pretty-printable-in-python/66250289#66250289
    def __pprint_repr__(self, *args, **kwargs):
        if isinstance(kwargs, dict):
            if 'indent' in kwargs:
                _indent = kwargs['indent']
                if _indent:
                    return self.__str__()
                #  if _indent: return self._toText()
        # return long form output
        result = {}
        props = [x for x in dir(self) if not x.startswith('_')]
        for k in props:
            result[k] = getattr(self, k)

        return result


class FuncTailsJump(FuncTailsError):
    """External Jump"""

    def __init__(self, conditional, frm, to):
        self.conditional = conditional
        self.frm = frm
        self.to = to


class FuncTailsUnusedChunk(FuncTailsError):
    """Unused Chunk"""

    def __init__(self, chunk_ea):
        self.ea = chunk_ea


class FuncTailsNoppedChunk(FuncTailsError):
    """Unused Chunk"""

    def __init__(self, chunk_ea):
        self.ea = chunk_ea


class FuncTailsBadTail(FuncTailsError):
    """Unused Chunk"""

    def __init__(self, chunk_ea, tail_ea=None):
        self.ea = chunk_ea
        self.tail_ea = tail_ea


class FuncTailsAdditionalChunkOwners(FuncTailsError):
    def __init__(self, chunk_ea, owners):
        self.ea = chunk_ea
        self.owners = owners


class FuncTailsInvalidTarget(FuncTailsError):
    def __init__(self, ea):
        self.ea = ea


class FuncTailsNoFunc(FuncTailsError):
    def __init__(self, ea):
        self.ea = ea


class AdvanceInsnList(object):
    """Docstring for AdvanceInsnList """

    def __init__(self, ea, insns=None, insn_count=None, byte_count=None, results=None, refs_from=None, refs_to=None,
                 flow_refs_from=None, flow_refs_to=None, start_ea=None, end_ea=None):
        """@todo: to be defined
            ea
            insns
            insn_count
            byte_count
            results
            refs_from
            refs_to
            flow_refs_from
            flow_refs_to
            start_ea
            end_ea
        """
        insns = A(insns)
        results = A(results)
        refs_from = S(refs_from)
        refs_to = S(refs_to)
        flow_refs_from = S(flow_refs_from)
        flow_refs_to = S(flow_refs_to)
        #  if refs_from is None: refs_from = {}
        #  if refs_to is None: refs_to = {}
        #  if flow_refs_from is None: flow_refs_from = {}
        #  if flow_refs_to is None: flow_refs_to = {}
        if isinstance(ea, GenericRange) or isinstance(ea, tuple) and len(ea) == 2:
            _s, _e = ea[0], ea[-1]
            #  print("AdvanceInsnList: {:x} - {:x}".format(_s, _e))
            if _e < _s:
                _e += _s
            insns=[FuncTailsInsn(x) for x in idautils.Heads(_s, _e)]
            ea = start_ea = _s

        self._list_insns = insns
        self._list_insn_count = insn_count
        self._list_byte_count = byte_count
        self._list_results = results
        self._list_refs_from = refs_from
        self._list_refs_to = refs_to
        self._list_flow_refs_from = flow_refs_from
        self._list_flow_refs_to = flow_refs_to
        self._list_start_ea = start_ea
        self._list_end_ea = end_ea
        self._list_ea = ea
        self._list_prev_list = None
        self._list_next_list = None
        self._list_parents = set()
        self._list_children = set()

        if ea.__class__.__name__ == self.__class__.__name__:
            props = [x for x in dir(self) if x.startswith('_list')]
            for k in props:
                setattr(self, k, getattr(ea, k, None))

    @property
    def prev(self):
        """
        returns self._list_prev_list
        """
        return self._list_prev_list
    
    @prev.setter
    def prev(self, value):
        """ New style classes requires setters for @property methods
        """
        self._list_prev_list = value
        return self._list_prev_list

    @property
    def next(self):
        """
        returns self._list_next_list
        """
        return self._list_next_list
    
    @next.setter
    def next(self, value):
        """ New style classes requires setters for @property methods
        """
        self._list_next_list = value
        return self._list_next_list

    def addChild(self, value):
        """ New style classes requires setters for @property methods
        """
        value._list_parents.add(self)
        self._list_children.add(value)
        return value

    def removeChild(self, value):
        if value in self._list_children:
            self._list_children.remove(value)
            value._list_parents.remove(self)
        return value

    def getChildren(self):
        return list(self._list_children)

    def getParents(self):
        return list(self._list_parents)

    @property
    def insns(self):
        return self._list_insns

    @property
    def insn_count(self):
        return self._list_insn_count

    @property
    def byte_count(self):
        return self._list_byte_count

    @property
    def results(self):
        return self._list_results

    @property
    def refs_from(self):
        return self._list_refs_from

    @property
    def refs_to(self):
        return self._list_refs_to

    @property
    def flow_refs_from(self):
        return self._list_flow_refs_from

    @property
    def flow_refs_to(self):
        return self._list_flow_refs_to

    @property
    def start_ea(self):
        return self._list_start_ea

    @property
    def start(self):
        return self.ea

    @property
    def end_ea(self):
        return self._list_end_ea

    @property
    def ea(self):
        return self._list_ea

    @property
    def target(self):
        return self._list_insns[-1].target

    @property
    def targets(self):
        return list(filter(lambda v, *a: IsValidEA(v), [GetTarget(i.ea) for i in self._list_insns]))

    @property
    def bytes(self):
        return b''.join([insn.bytes for insn in self._list_insns])

    def __pprint_repr__(self, *args, **kwargs):
        if isinstance(kwargs, dict):
            if 'indent' in kwargs:
                _indent = kwargs['indent']
                if _indent:
                    return str(self.generic_range())
                #  if _indent: return self._toText()
        # return long form output
        result = {}
        props = [x for x in dir(self) if x.startswith('_list')]
        for k in props:
            result[k[6:]] = getattr(self, k)

        if self._list_insns:
            result['range'] = GenericRange(start=self._list_insns[0].ea, trend=self._list_insns[-1].ea + len(self._list_insns[-1]))

        return result

    def join(self, visited=None):
        if visited is None: visited = set()
        def unvisited(ea):
            if not isinstance(ea, int):
                ea = ea.ea
            if ea not in visited:
                if debug: print("adding chunk {:#x} to queue".format(ea))
                visited.add(ea)
                return True
            else:
                if debug: print("not adding chunk {:#x} to queue".format(ea))
            return False

        x = self
        # yield "loc_{:X}:".format(x.ea)
        #  print('yielding initial insns')
        for i in x.insns:
            if unvisited(i):
                yield i

        if True:
            _queue = [child for child in x.getChildren() if unvisited(child)]
            while _queue:
                item = _queue.pop(0)
                for i in item.insns:
                    if True or i.ea not in visited:
                        if debug: print("adding insn {:#x} to queue".format(i.ea))
                        # visited.add(i.ea)
                        yield i
                    else:
                        if debug: print("not adding insn {:#x} to queue".format(i.ea))
                _queue = [child for child in item.getChildren() if unvisited(child)] + _queue

        else:
            if isinstance(x.next, set):
                _queue = list(x.next)
                while _queue:
                    item = _queue.pop(0)
                    for i in item.insns:
                        if True or i.ea not in visited:
                            # visited.add(i.ea)
                            yield i
                    if item.next:
                        #  print('join: appending {}'.format(item.next))
                        for x in item.next:
                            _queue.append(x)

            else:
                while x.next:
                    for i in x.next.insns:
                        if i.ea not in visited:
                            visited.add(i.ea)
                            yield i
                    x = x.next


    #  def errors(self): return self._list_errors

    #  __contains__(self, key, /)
    #  __delitem__(self, key, /)
    #  __eq__(self, value, /)
    #  __ge__(self, value, /)
    #  __getattribute__(self, name, /)
    #  __getitem__(...)
    #  __gt__(self, value, /)
    #  __init__(self, /, *args, **kwargs)
    #  __iter__(self, /)
    #  __le__(self, value, /)
    #  __len__(self, /)
    #  __lt__(self, value, /)
    #  __ne__(self, value, /)
    #  __repr__(self, /)
    #  __setitem__(self, key, value, /)

    ### ---
    def __len__(self):
        return self._list_insns.__len__()

    def __getitem__(self, key):
        return self._list_insns.__getitem__(key)

    def __setitem__(self, key, value):
        self._list_insns.__setitem__(key, value)

    def __delitem__(self, key):
        self._list_insns.__delitem__(key)

    def __iter__(self):
        return self._list_insns.__iter__()

    def __reversed__(self):
        return self._list_insns.__reversed__()

    def __contains__(self, item):
        return self._list_insns.__contains__(item)

    def append(self, object):
        self._list_insns.append(object)

    def clear(self):
        self._list_insns.clear()

    def copy(self):
        return (type(self))(self._list_insns.copy())

    def count(self):
        return self._list_insns.count()

    def extend(self, iterable):
        for item in iterable:
            self.append(item)

    def index(self, value, start=0, stop=9223372036854775807):
        self._list_insns.index(value, start, stop)

    def insert(self):
        self._list_insns.insert()

    def pop(self):
        self._list_insns.pop()

    def remove(self):
        self._list_insns.remove()

    def reverse(self):
        self._list_insns.reverse()

    def sort(self):
        self._list_insns.sort()

    def insert(self, index, object):
        self._list_insns.insert(index, object)

    def pop(self, index=-1):
        return self._list_insns.pop(index)

    def remove(self, value):
        self._list_insns.remove(value)

    ### ---
    def items(self):
        for o in self._list_insns:
            yield o.ea, o.insn

    def values(self):
        return [o.insn for o in self._list_insns]

    def keys(self):
        return [o.ea for o in self._list_insns]

    def labeled_values(self):
        return [o.labeled_value for o in self._list_insns]

    def generic_range(self):
        if not self._list_insns:
            return None
        return GenericRange(start=self._list_insns[0].ea, trend=self._list_insns[-1].ea + len(self._list_insns[-1]))

    def range(self):
        if not self._list_insns:
            return None
        return range(self._list_insns[0].ea, self._list_insns[-1].ea + len(self._list_insns[-1]))

class FuncTailsInsn(object):
    """Docstring for FuncTailsInsn """

    def __init__(self, insn=None, ea=None, text=None, size=None, code=None, mnemonic=None, operands=None, comments=None, sp=None, spd=None, warnings=None,
                 errors=None, chunkhead=None, labels=None,
                 refs_from=None, refs_to=None, flow_refs_from=None, flow_refs_to=None):
        """@todo: to be defined

        :insn_text: @todo
        :insn_ea: @todo
        :insn_di: @todo
        :insn_sp: @todo
        :insn_comments: @todo
        :insn_warnings: @todo
        :insn_errors: @todo

        """
        labels = A(labels)
        if insn is None or isinstance(insn, int):
            if ea is None:
                ea = insn
            insn=diida(ea)
            text=insn
            size=MyGetInstructionLength(ea)
            #  refs_to=set(xrefs_to(ea, filter=lambda x, *a: x.type != fl_F))

            
        if not labels and HasAnyName(ea):
            labels.append(idc.get_name(ea))

        self._insn_text = text
        self._insn_ea = ea
        self._insn_sp = sp
        self._insn_spd = spd
        self._insn_comments = comments
        self._insn_warnings = warnings
        self._insn_errors = errors
        self._insn_code = code
        self._insn_operands = operands
        self._insn_mnemonic = mnemonic
        self._insn_chunkhead = chunkhead
        self._insn_labels = labels
        self._insn_insn = insn
        self._insn_size = size

        self._insn_refs_from = S(refs_from)
        self._insn_refs_to = S(refs_to)
        self._insn_flow_refs_from = S(flow_refs_from)
        self._insn_flow_refs_to = S(flow_refs_to)

        self._insn_target = None

        self._insn_skip = False
        self._insn_hide_label = False
        self._insn_hide_insn = False


        # self._insn_target = GetTarget(ea, failnone=True)
        if (isAnyJmpOrCall(ea)):
            self._insn_target = GetTarget(ea)
        if insn_match(ea, idaapi.NN_mov, idc.o_reg, idc.o_imm):
            self._insn_target = GetTarget(ea, failnone=True)

    def __str__(self):
        return self._insn_text

    @property
    def bytes(self):
        return ida_bytes.get_bytes(self.ea, len(self))


    #  def __eq__(self, other):
    #  if isinstance(other, str):
    #  return self._insn_text == other

    def __add__(self, *args, **kwargs):
        return str(self).__add__(*args, **kwargs)

    def __contains__(self, *args, **kwargs):
        return str(self).__contains__(*args, **kwargs)

    def __eq__(self, *args, **kwargs):
        return str(self).__eq__(*args, **kwargs)

    def __format__(self, *args, **kwargs):
        return str(self).__format__(*args, **kwargs)

    def __ge__(self, *args, **kwargs):
        return str(self).__ge__(*args, **kwargs)

    #  def __getattribute__(self, *args, **kwargs):
    #  return str(self).__getattribute__(*args, **kwargs)
    #
    #  def __getitem__(self, *args, **kwargs):
    #  return str(self).__getitem__(*args, **kwargs)
    #
    def __gt__(self, *args, **kwargs):
        return str(self).__gt__(*args, **kwargs)

    def __hash__(self, *args, **kwargs):
        return str(self).__hash__(*args, **kwargs)

    def __iter__(self, *args, **kwargs):
        return str(self).__iter__(*args, **kwargs)

    def __le__(self, *args, **kwargs):
        return str(self).__le__(*args, **kwargs)

    #  def __len__(self, *args, **kwargs):
    #  return str(self).__len__(*args, **kwargs)

    def __lt__(self, *args, **kwargs):
        return str(self).__lt__(*args, **kwargs)

    def __mod__(self, *args, **kwargs):
        return str(self).__mod__(*args, **kwargs)

    def __mul__(self, *args, **kwargs):
        return str(self).__mul__(*args, **kwargs)

    def __ne__(self, *args, **kwargs):
        return str(self).__ne__(*args, **kwargs)

    def __repr__(self, *args, **kwargs):
        return str(self).__repr__(*args, **kwargs)

    def __rmod__(self, *args, **kwargs):
        return str(self).__rmod__(*args, **kwargs)

    def __rmul__(self, *args, **kwargs):
        return str(self).__rmul__(*args, **kwargs)

    def capitalize(self, *args, **kwargs):
        return str(self).capitalize(*args, **kwargs)

    def casefold(self, *args, **kwargs):
        return str(self).casefold(*args, **kwargs)

    def center(self, *args, **kwargs):
        return str(self).center(*args, **kwargs)

    def count(self, *args, **kwargs):
        return str(self).count(*args, **kwargs)

    def encode(self, *args, **kwargs):
        return str(self).encode(*args, **kwargs)

    def endswith(self, *args, **kwargs):
        return str(self).endswith(*args, **kwargs)

    def expandtabs(self, *args, **kwargs):
        return str(self).expandtabs(*args, **kwargs)

    def find(self, *args, **kwargs):
        return str(self).find(*args, **kwargs)

    def format(self, *args, **kwargs):
        return str(self).format(*args, **kwargs)

    def format_map(self, *args, **kwargs):
        return str(self).format_map(*args, **kwargs)

    def index(self, *args, **kwargs):
        return str(self).index(*args, **kwargs)

    def ljust(self, *args, **kwargs):
        return str(self).ljust(*args, **kwargs)

    def lower(self, *args, **kwargs):
        return str(self).lower(*args, **kwargs)

    def lstrip(self, *args, **kwargs):
        return str(self).lstrip(*args, **kwargs)

    def partition(self, *args, **kwargs):
        return str(self).partition(*args, **kwargs)

    def replace(self, *args, **kwargs):
        return str(self).replace(*args, **kwargs)

    def rfind(self, *args, **kwargs):
        return str(self).rfind(*args, **kwargs)

    def rindex(self, *args, **kwargs):
        return str(self).rindex(*args, **kwargs)

    def rjust(self, *args, **kwargs):
        return str(self).rjust(*args, **kwargs)

    def rpartition(self, *args, **kwargs):
        return str(self).rpartition(*args, **kwargs)

    def rsplit(self, *args, **kwargs):
        return str(self).rsplit(*args, **kwargs)

    def rstrip(self, *args, **kwargs):
        return str(self).rstrip(*args, **kwargs)

    def split(self, *args, **kwargs):
        return str(self).split(*args, **kwargs)

    def splitlines(self, *args, **kwargs):
        return str(self).splitlines(*args, **kwargs)

    def startswith(self, *args, **kwargs):
        return str(self).startswith(*args, **kwargs)

    def strip(self, *args, **kwargs):
        return str(self).strip(*args, **kwargs)

    def swapcase(self, *args, **kwargs):
        return str(self).swapcase(*args, **kwargs)

    def title(self, *args, **kwargs):
        return str(self).title(*args, **kwargs)

    def translate(self, *args, **kwargs):
        return str(self).translate(*args, **kwargs)

    def upper(self, *args, **kwargs):
        return str(self).upper(*args, **kwargs)

    def zfill(self, *args, **kwargs):
        return str(self).zfill(*args, **kwargs)

    @property
    def text(self):
        return self._insn_text

    @property
    def ea(self):
        return self._insn_ea

    @property
    def sp(self):
        return self._insn_sp

    @property
    def spd(self):
        return self._insn_spd

    @property
    def comments(self):
        return self._insn_comments

    @property
    def warnings(self):
        return self._insn_warnings

    @property
    def errors(self):
        return self._insn_errors

    @property
    def chunkhead(self):
        return self._insn_chunkhead

    @property
    def operands(self):
        return self._insn_operands

    @property
    def code(self):
        return self._insn_code


    @property
    def mnemonic(self):
        return self._insn_mnemonic


    @property
    def labels(self):
        return self._insn_labels

    @property
    def insn(self):
        return self._insn_insn

    def __len__(self):
        return self._insn_size

    def add_label(self, label):
        self._insn_labels.append(label)

    def settext(self, text):
        self._insn_text = text

    @property
    def refs_from(self):
        return self._insn_refs_from

    @property
    def refs_to(self):
        return self._insn_refs_to

    @property
    def flow_refs_from(self):
        return self._insn_flow_refs_from

    @property
    def flow_refs_to(self):
        return self._insn_flow_refs_to

    @property
    def target(self):
        return self._insn_target

    @property
    def label(self):
        if self.labels:
            return self.labels[-1]
        return ''

    @property
    def skip(self):
        """
        returns self._insn_skip
        """
        return self.hide_label and self.hide_insn
    
    @skip.setter
    def skip(self, value):
        """ New style classes requires setters for @property methods
        """
        self.hide_label = self.hide_insn = value
    
    
    @property
    def hide_label(self):
        """
        returns self._insn_hide_label
        """
        return self._insn_hide_label
    
    @hide_label.setter
    def hide_label(self, value):
        """ New style classes requires setters for @property methods
        """
        self._insn_hide_label = value
        return self._insn_hide_label
    
    @property
    def hide_insn(self):
        """
        returns self._insn_hide_insn
        """
        return self._insn_hide_insn
    
    @hide_insn.setter
    def hide_insn(self, value):
        """ New style classes requires setters for @property methods
        """
        self._insn_hide_insn = value
        return self._insn_hide_insn
    
    

    @property
    def force_labeled_value(self):
        _label = None
        if self._insn_labels:
            _label = self._insn_labels[0]
        if not _label:
            _label = ean(self._insn_ea)
        if not _label:
            _label = "lab_{:X}".format(self._insn_ea)
        return "{}: {}".format(_label, self._insn_insn)

    @property
    def force_labeled_indented(self):
        _label = None
        if self._insn_labels:
            _label = self._insn_labels[0]
        if not _label:
            _label = ean(self._insn_ea)
        if not _label:
            _label = "lab_{:X}".format(self._insn_ea)
        return "{}:\n    {}".format(_label, self._insn_insn)

    @property
    def labeled_value(self):
        if len(self._insn_refs_to) or len(self._insn_labels):
            _label = None
            if self._insn_labels:
                _label = self._insn_labels[0]
            if not _label:
                _label = ean(self._insn_ea)
            return "{}: {}".format(_label, self._insn_insn)
        return "{}".format(self._insn_insn)

    @property
    def labeled_indented(self):
        if len(self._insn_refs_to) or len(self._insn_labels):
            _label = None
            if self._insn_labels:
                _label = self._insn_labels[0]
            if not _label:
                _label = ean(self._insn_ea)
            return "{}:\n    {}".format(_label, self._insn_insn)
        return "    {}".format(self._insn_insn)

    @property
    def indented(self):
        result = []
        if self.skip:
            return ''

        if not self.hide_label and self.label:
            result.append("{}:".format(self.label))
        if not self.hide_insn:
            result.append("    {}".format(self._insn_insn))

        return '\n'.join(result)

    @property
    def unlabeled_indented(self):
        return "    {}".format(self._insn_insn)

    # https://stackoverflow.com/questions/40828173/how-can-i-make-my-class-pretty-printable-in-python/66250289#66250289
    def __pprint_repr__(self, *args, **kwargs):
        if isinstance(kwargs, dict):
            if 'indent' in kwargs:
                _indent = kwargs['indent']
                if _indent:
                    return self.labeled_value
                #  if _indent: return self._toText()
        # return long form output
        result = {}
        props = [x for x in dir(self) if x.startswith('_insn')]
        for k in props:
            result[k[6:]] = getattr(self, k)

        result['labeled_value'] = self.labeled_value

        return result


def func_tails(funcea=None, returnErrorObjects=False, returnOutput=False, returnPretty=False,
               code=True, patches=None, dead=False, showEa=False, 
               showUnused=False, ignoreInt=False, showNops=False, output=None,
               quiet=False, removeLabels=True, disasm=False, externalTargets=None,
               returnAddrs=False, returnFormat=None, fmt=None, fmtLabel=None,
               showComments=True, **kwargs):
    """
    func_tails

    @param funcea: any address in the function
    @param dead: dead code removal
    """
    #  check_for_update()
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return [FuncTailsNoFunc(funcea)] if returnErrorObjects else ["[error] nofunc at 0x{:x}".format(funcea)]
    else:
        funcea = func.start_ea

    if fmt is None:
        fmt = '    {}'
    if fmtLabel is None:
        fmt_label = '{}:'
    else:
        fmt_label = fmtLabel
    errors = []
    errorObjects = []
    decompiled = []
    pretty = []
    decompiled_heads = defaultdict(list)
    relabel = dict()

    #  decompiled_insns = []

    def relabel_line(line):
        for search, replace in relabel.items():
            # dprint("[outi] search, replace")
            #  print("[outi] search: {}, replace: {}".format(search, replace))
            
            line = line.replace(search, replace)
        return line

    def outi(line):
        r = []
        if line:
            for l in line.split('\n'):
                if l.strip().startswith('nop'):
                    continue
                r.append(relabel_line(l))
            if returnPretty:
                pretty.extend(r)
            else:
                [printi(x) for x in r]

    def out(line, head=None, ft_insn=None):
        if head:
            if ft_insn:
                ft_insn.settext(line)
            decompiled_heads[head].append(ft_insn if ft_insn else line)
        else:
            if not quiet:
                pass

            if isListlike(decompiled):
                pass
                #  decompiled.append(line)
                #  decompiled_insns.append(line)

        l = string_between('; [', '', line)
        if l and output:
            output.append("[" + l)

        return line

    def remove_labels(decompiled):
        labels = []
        if isListlike(decompiled):
            tmp = "\n".join(decompiled)
            globals()['decompiled'] = tmp
            for r in range(3):
                count = defaultdict(list)
                remove_r = list()
                remove = list()
                for loc in skip_first(re.findall(r'^\w+(?=:)', tmp, re.M)):
                    labels.append(loc)
                for label in labels:
                    for loc in re.findall(re.escape(label), tmp):
                        count[loc].append(loc)
                for loc, v in count.items():
                    if len(v) == 1:
                        tmp = tmp.replace(loc + ':\n', '')
                    elif len(v) == 2:
                        tmp = tmp.replace('    jmp ' + loc + '\n' + loc + ':\n', '')  # re.sub(loc, 'JMP REMOVED', tmp)
                    if len(v) > 1:
                        tmp = tmp.replace('    jmp ' + loc + '\n' + loc + ':', loc + ':')

            decompiled = tmp.split('\n')
            return decompiled

    if not quiet:
        printi("\nFuncTails: 0x{:x} ({})".format(funcea, GetFuncName(funcea)))

    # q = [x for x in m if func_tails(SkipJumps(x), quiet=1)]
    funcStart = GetFuncStart(funcea)
    idc.get_func_name(funcea)
    chunkheads_visited = dict()
    chunkheads = dict()
    chunkheads_bad = dict()
    chunkheads_badtails = dict()
    chunkheads_perm = dict()
    chunkrefs_from = defaultdict(list)
    chunktails = defaultdict(list)
    chunkrefs_to = defaultdict(list)
    chunkowners = defaultdict(list)
    _chunks = []
    comments = defaultdict(list)
    allheads = []
    nopheads = []
    badtails = []
    badjumps = []
    conditional_jumps = []
    unconditional_jumps = []
    mnemonics = list()

    """
    class BasicBlock(builtins.object)
     |  BasicBlock(id, bb, fc)
     |  
     |  Basic block class. It is returned by the Flowchart class
     |  
     |  Methods defined here:
     |  
     |  __init__(self, id, bb, fc)
     |      Initialize self.  See help(type(self)) for accurate signature.
     |  
     |  preds(self)
     |      Iterates the predecessors list
     |  
     |  succs(self)
     |      Iterates the successors list
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors defined here:
     |  
     |  __dict__
     |      dictionary for instance variables (if defined)
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  end_ea
     |  
     |  startEA
    """

    blockcache = dict()

    def get_cached(x, _chunkheads):
        key = x[0]
        if key in blockcache:
            return blockcache[key]
        blockcache[key] = Block(x, _chunkheads)
        return blockcache[key]

    class Block(object):# {{{

        """Docstring for Block. """

        def __init__(self, _chunkhead, _chunkheads):
            """TODO: to be defined1. """
            self.start_ea = _chunkhead[0]
            self.end_ea = _chunkhead[-1]
            self.id = _chunkhead[0]
            self._chunkheads = _chunkheads
            #  pp(chunkheads_perm)
            #  pp(chunkrefs_to)
            if self.id not in chunkheads_perm:
                printi("[func_tails::Block::__init__] Hmmm, {:x} not in chunkheads_perm".format(self.id))
            #  self.successors = [get_cached(x, _chunkheads) for x in [chunkheads_perm[y] for y in chunkrefs_from[self.id]]]
            #  self.predecessors = [get_cached(x, _chunkheads) for x in [chunkheads_perm[y] for y in chunkrefs_to[self.id]]]

        def succs(self, found_bbs=None):
            found_bbs = A(found_bbs)

            try:
                l = _.uniq([chunkheads_perm[y] for y in chunkrefs_to[self.id] if y in chunkheads_perm])
                v = [Block(x, self._chunkheads) for x in l]
                if len(v) > 1 and found_bbs:
                    #  v = _.sortBy(v, lambda x, *a: GetTarget(found_bbs[-1]) == x.id)
                    e = self.end_ea
                    e = GetTarget(e)
                    if e != self.end_ea:
                        t = [x for x in v if x.id == e]
                        t.extend([x for x in v if x.id != e])
                        v = t

                w = [y for y in chunkrefs_to[self.id] if y not in chunkheads_perm]
                if w:
                    printi("[func::tails::Block::succs] unknown heads: {}".format(hex(w)))
            except KeyError as e:

                printi("[func::tails::Block::succs] No such key 0x{:x}".format(e.args[0]))

            #  return self.successors
            return v
            pass

    def get_block(blocks, bb):
        for x in blocks:
            if x.id == bb:
                return x

    def print_basic_blocks_dfs_bfs():
        blocks = [Block(x, chunkheads_perm) for x in _.values(chunkheads_perm)]
        #  function = idaapi.get_func(fva)
        #  blocks = idaapi.FlowChart(function)
        if not quiet:
            printi("Function {} starting at 0x{:x} consists of {} chunks".format(idc.get_func_name(funcea), funcea,
                                                                                 len(blocks)))

        start_bb = get_start_bb(blocks)
        return dfs_bbs(start_bb, [])

    def get_start_bb(blocks):
        for bb in blocks:
            if bb.start_ea == funcea:
                return bb

    def dfs_bbs(start_bb, found_bbs=None):
        found_bbs = A(found_bbs)
        if start_bb.id in found_bbs:
            return found_bbs
        found_bbs.append(start_bb.id)
        for w in [x for x in start_bb.succs(found_bbs)]:
            dfs_bbs(w, found_bbs)
        return found_bbs

    def dfs_bbs_2(start_bb, found_bbs, already_found_bbs):
        found_bbs.append(start_bb.id)
        r = start_bb.succs(found_bbs)
        _next = [x for x in r if x.id not in found_bbs]
        if len(_next) == 1:
            rv = dfs_bbs_2(_next[0], found_bbs, already_found_bbs)
            if len(rv) > 1:
                return rv
        elif len(_next) > 1:
            return _next
        else:
            return []
        return []
        #  return _.without(found_bbs, *already_found_bbs)

    def bfs_bbs(start_bb, found_bbs):
        q = deque([start_bb])
        while len(q) > 0:
            current_bb = q.popleft()
            if current_bb.id not in found_bbs:
                found_bbs.append(current_bb.id)
                # pf("{current_bb.id} ")
                _next = current_bb.succs(found_bbs)
                # pf("next: {_next} ")
                if len(_next) == 0:
                    continue
                if len(_next) == 1:

                    q.append(_next.pop())
                elif len(_next) > 1:

                    for i, n in enumerate(_next):
                        br = dfs_bbs_2(n, found_bbs, found_bbs[:])

                        if br:
                            for ea in br:
                                if ea.id not in chunkheads_perm:
                                    printi("[func_tails::bfs_bbs] {:x} not in chunkheads_perm".format(ea.id))
                                else:
                                    q.append(ea)
            else:
                printi("[func_tails::bfs_bbs] bfs_bbs ignoring: {:x}".format(current_bb.id))
        return found_bbs

    def format_bb(bb):
        return "start_ea: 0x{:x}  end_ea: 0x{:x}  last_insn: {}".format(bb.start_ea, bb.end_ea, GetDisasm(bb.end_ea))# }}}

    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    _chunks = list(split_chunks(idautils.Chunks(funcea), ignoreInt=ignoreInt))
    start = funcea
    q = [start]
    for (startea, endea) in _chunks:
        # EaseCode(startea)
        if disasm:
            GetDisasm(startea)
        if code:
            try:
                if not CreateInsns(startea, endea - startea)[0]:
                    badtails.append("    ; [error] invalid code in chunk {:x}".format(startea))
            except AdvanceFailure:
                badtails.append("    ; [error] invalid code in chunk {:x}".format(startea))
        chunkowners[startea].extend([GetFunctionName(x) for x in GetChunkOwners(startea) if x != funcStart])
        heads = []
        for head in idautils.Heads(startea, endea):
            if dead and not len(heads) and isNop(head):
                nopheads.append(head)
                allheads.append(head)
                continue
            heads.append(head)

            # dprint("[format_bb] head, idc.get_operand_type(head)")
            # print("[format_bb] head:{}, idc.get_operand_type(head):{}".format(head, idc.get_operand_type(head, 0)))
            
            if isAnyJmp(head) and idc.get_operand_type(head, 0) in (idc.o_near, ):
                target = GetTarget(head)
                ctarget = OurGetChunkStart(target, _chunks)
                jump_info = [head, IdaGetMnem(head), GetTarget(head)]

                if isConditionalJmp(head):

                    conditional_jumps.append(jump_info)
                    #  chunkrefs_to[startea].append(ctarget)
                    #  chunkrefs_from[ctarget].append(startea)
                else:

                    unconditional_jumps.append(jump_info)
                    #  chunkrefs_to[startea].append(ctarget)
                    #  chunkrefs_from[ctarget].append(startea)
                    #  chunkrefs_to[startea].append(target)
                    #  chunkrefs_from[target].append(startea)

        if patches:
            patches[str(startea)] = ida_bytes.get_bytes(startea, endea - startea)
            continue

        if not heads:
            continue
        tail = heads[-1]
        target = GetTarget(tail, flow=1)
        #  tail_insn = diida(tail)

        if isCall(tail) and idc.get_func_flags(GetTarget(tail)) & idc.FUNC_NORET:
            call_noret = 1
        else:
            call_noret = 0
        if not isAnyJmp(tail) and not isRet(tail) and not call_noret:
            if _.all(heads, lambda x, *a: isNop(x)):
                badtails.append("    ; [warn] chunkhead {:x} is entirely nopped".format(startea))
                errorObjects.append(FuncTailsNoppedChunk(startea))

            if False and isInterrupt(tail) and not ignoreInt:
                badtails.append(
                    '    ; [error] badtail {} {} {}'.format(_node_format(startea), diida(tail), _node_format(target)))
                chunkheads_badtails[startea] = True
                errorObjects.append(FuncTailsBadTail(startea, tail))

        chunkheads[startea] = heads
        chunkheads_perm[startea] = heads
        allheads.extend(heads)
        chunktails[startea].append(tail)

        #  ctarget = GetChunkStart(target)
        #  if ctarget != idc.BADADDR:
        #  chunkrefs_to[startea].append(ctarget)
        #  chunkrefs_from[ctarget].append(startea)

    # allheads = _.uniq(_.flatten(list(_.values(chunkheads))))
    # alltargets = _.uniq(_.flatten(list(_.values(chunkrefs_to))))
    if patches:
        return patches

    if 'debug' in globals() and globals()['debug']:
        printi(re.sub(r"\b[0-9]{8,}\b", lambda x, *a: hex(x.group(0)),
                      "[debug] chunktails:{}, chunkrefs_to:{}, chunkrefs_from:{}".format(
                          pf(chunktails), pf(chunkrefs_to), pf(chunkrefs_from))))

    # now starting with the start of the function...
    refs = dict()
    _externalTargets = list()
    ordered = list()
    nonheadtargets = set()
    append_later = list()

    while len(q):
        start = q.pop(0)
        if start not in chunkheads:
            if start in chunkheads_visited:
                continue
            if start in chunkheads_bad:
                printi("[func_tails::format_bb] q shouldn't try to jump to chunkheads_bad")
                continue
            printi("[func_tails::format_bb] %x not in chunkheads" % start)
            nonheadtargets.add(start)
            continue
        badtail = start in chunkheads_badtails
        heads = chunkheads.pop(start)
        chunkheads_visited[start] = heads[:]
        cstart = heads[0]
        for head in heads:
            #  comments[head].append('chunkhead: {}'.format(get_name_by_any(cstart)))
            # TODO: this look very dangerous if the head doesn't end on a jmp 
            if not IsCode_(head):
                cmt = '    ; [error] 0x{:x} raw bytes: {}'.format(head, idc.GetDisasm(head))
                comments[head].append(cmt)
                errors.append(cmt)
                break
            mnem = IdaGetMnem(head)

            if IsRef(head):

                refs[head] = idc.get_name(head)
                r = xrefs_to_ex(head)
                for ref in [x for x in r if not IsSameFunc(funcea, x.frm)                                 \
                                            and x.frm_seg == '.text'                                      \
                                            and string_between('', ' ', x.frm_insn).startswith('j')       \
                                            and not string_between('', ' ', x.frm_insn).startswith('jmp') \
                                            and GetInsnLen(x.frm) > 4
                            ]:

                    ejmp = False
                    with Commenter(head, 'line') as c:
                        if c.match("\[ALLOW EJMP]"):
                            ejmp = True
                    if not ejmp and GetTarget(ref.frm) == head:
                        cmt = '    ; [error] 0x{:x} external reference from {} 0x{:x}: {}'.format(head,
                                                                                                  GetFuncName(ref.frm),
                                                                                                  ref.frm, ref.frm_insn)
                        comments[head].append(cmt)
                        errors.append(cmt)

            if head in chunkowners and chunkowners[head]:
                comment = '    ; [warn] additional chunk owner(s) {} for chunk at {:x}'.format(hex(chunkowners[head]),
                                                                                               head)
                # fix_dualowned_chunk(head)
                badtails.append(comment)
                errorObjects.append(FuncTailsAdditionalChunkOwners(head, chunkowners[head]))
                comments[head].append(comment)

            if isCall(head):
                _externalTargets.append(SkipJumps(head))
            if isAnyJmpOrCall(head) and idc.get_operand_type(head, 0) in (o_near, ):
                conditional = isConditionalJmp(head)
                iscall = isCall(head)
                target = GetTarget(head)
                ejmp = False
                with Commenter(target, 'line') as c:
                    if c.match("\[ALLOW EJMP]"):
                        ejmp = True
                ctarget = OurGetChunkStart(target, _chunks)

                optype = idc.get_operand_type(head, 0)
                if optype in (o_near, o_mem) and not IsValidEA(target):
                    msg = '[error] {}: invalid target: {}'.format(get_name_by_any(head), idc.print_operand(head, 0))
                    comments[head].append((msg))
                    errorObjects.append(FuncTailsInvalidTarget(head))
                    errors.append(msg)

                elif ctarget in chunkheads or ctarget in chunkheads_visited:

                    _cs = OurGetChunkStart(head, _chunks)
                    chunkrefs_to[_cs].append(ctarget)
                    chunkrefs_from[ctarget].append(_cs)

                    # if ctarget != cstart:
                    if isConditionalJmp(head):
                        #  append_later.append(ctarget)
                        #  append_later.append(ctarget)
                        q.append(ctarget)
                        if debug: printi("{:x} appending later {} {:x}".format(head, mnem, ctarget))
                        #  badjumps.append([head, ctarget])
                    else:
                        q.insert(0, ctarget)
                        if debug: printi("{:x} appending {} {:x}".format(head, mnem, ctarget))
                        #  badjumps.append([head, ctarget])

                elif not (Commenter(target, 'line').exists("[DENY JMP]") or isPdata(target)):
                    _externalTargets.append(SkipJumps(head))
                    if not ejmp:
                        if conditional:
                            if target != idc.BADADDR:
                                if not IsFunc_(target):
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head),
                                                                                               describe_target(target))
                                    errorObjects.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                elif not IsFuncHead(target):
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head),
                                                                                               describe_target(target))
                                    errorObjects.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                else:
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head),
                                                                                               describe_target(target))
                                    errorObjects.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)

                            # q.append(ctarget)
                        if not conditional and not iscall:
                            if target != idc.BADADDR:
                                if IsExtern(target):
                                    msg = '[info] {}: external jump to extern {}'.format(get_name_by_any(head),
                                                                                         describe_target(target))
                                    comments[head].append((msg))
                                elif not IsFunc_(target):
                                    msg = '[error] {}: external jump to {}'.format(get_name_by_any(head),
                                                                                   describe_target(target))
                                    errorObjects.append(FuncTailsJump(False, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                elif not IsFuncHead(target):
                                    msg = '[error] {}: external jump to {}'.format(get_name_by_any(head),
                                                                                   describe_target(target))
                                    errorObjects.append(FuncTailsJump(False, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                else:
                                    msg = '[info] {}: external jump to {}'.format(get_name_by_any(head),
                                                                                  describe_target(target))
                                    comments[head].append((msg))
                                    #  errors.append(msg)

                            #  q.append(ctarget)

        ordered.extend(heads)

        if not len(q) and append_later:
            q.extend(append_later)

    disasm = []
    for ea in ordered:
        mnemonics.append(IdaGetMnem(ea))

        insn_text = diida(ea)
        # (insn_text, insn_addr, insn_di, insn_sp, insn_comment, insn_warnings, insn_errors, insn_chunkhead):
        disasm.append(
                FuncTailsInsn(insn_text, ea, insn_text, size=MyGetInstructionLength(ea),
                                    # refs_to=set(xrefs_to(ea, filter=lambda x, *a: x.type != fl_F)),
                                    comments=comments[ea] if ea in comments else None)
                )

    idis = _.mapObject(disasm, lambda v, *a: (v.ea, v))
    label_count = 0
    for ea, fti in idis.items():
        target = GetTarget(ea)
        if IsValidEA(target) and target in ordered:
            # dprint("[debug] ea, target")
            #  print("[debug] ea: {}, target: {}".format(ahex(ea), ahex(target)))
            
            idis[target].refs_to.add(ea)
            idis[ea].refs_from.add(target)
            label_count += 1
            new_label = "label_{}".format(label_count)
            relabel[idc.get_name(target)] = new_label
            idis[target].add_label(new_label)

            # if insn_match(ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp loc_141898018')


    assert idis[disasm[0].ea] == disasm[0]



        #  if ea in comments:
        #  disasm.append({'insn': diida(ea), 'ea': ea,
        #  'comment': comments[ea]})
    #
    #  else:
    #  disasm.append({'insn': diida(ea), 'ea': ea})
    #
    #  disasm = [dinjasm(x) for x in ordered]

    # now we have `ordered` which is a list of addresses, and
    # `disasm` which is a list of instructions.  we need to match
    # the local refs with local labels, leaving the {}: external (to
    # this function) refs alone.

    # now lets put it all together
    l = len(disasm) - 1
    for n, o in enumerate(disasm):
        insn = o.text
        addr = o.ea
        comments = o.comments

        _chunkhead = OurGetChunkStart(addr, _chunks)
        #  _chunkhead = None
        #  for chead, caddresses in chunkheads_perm.items():
        #  if addr in caddresses:
        #  _chunkhead = addr
        #  break

        if n < l and ordered[n + 1] in refs:
            # a label is about to hit
            label = refs[ordered[n + 1]]
            #  if 0 and insn == 'jmp %s' % label and not ordered[n] in refs: continue
        if ordered[n] in refs:
            out(fmt_label.format(refs[ordered[n]]), _chunkhead, o)
        if showNops or not insn.startswith('nop'):
            fmt_insn = fmt.format(insn, addr)
            if showComments and comments:
                insn_width = len(fmt_insn)
                comment = ' ; ' + comments.pop(0)
                out(fmt_insn + comment, _chunkhead, o)
                for c in comments:
                    comment = ' ; ' + c
                    out(' ' * insn_width + comment, _chunkhead, o)
            else:
                out(fmt_insn, _chunkhead, o)

    #  pp(decompiled_heads)
    #  if 'retn' not in mnemonics and mnemonics[-1] != 'jmp':
    #  out('    ; [error] noret')

    # fn = file_put_contents('function.asm', '\n'.join(errors))

    #  refresh_func_tails()

    #  for k in _.sort(_.keys(decompiled_heads)):
    #  for line in decompiled_heads[k]:

    chunkheads = chunkheads_perm.copy()
    chunkheads_visited = dict()
    bb = None
    with recursion_depth(4000):
        bb = print_basic_blocks_dfs_bfs()
    #  d = []
    addrs = []
    for x in bb:
        start, end = x, OurGetChunkEnd(x, _chunks)
        for ip in idautils.Heads(start, end):
            d = de(ip)
            if d:
                de_flags = obfu._makeFlagFromDi(d[0])
            else:
                de_flags = 0
            addrs.extend([(y, de_flags) for y in range(ip, ip + InsnLen(ip))])

        for line in decompiled_heads[x]:
            decompiled.append(line)

        if x in chunkheads:
            chunkheads_visited[x] = chunkheads.pop(x)
        #  else:
        #  if x in chunkheads_visited:

        #  else:

    #  decompiled = remove_labels(decompiled) if removeLabels else decompiled
    decompiled = _.uniq(decompiled, lambda o, *a: o.ea)
    if not quiet:
        skip = 0
        for count, two_lines in enumerate(stutter_chunk(decompiled, 2, 1)):
            line, next_line = two_lines
            if showEa:
                printi("0x{:x} {}".format(line.ea, line.labeled_value))
            else:
                no_label = 0
                if skip:
                    skip = 0
                    no_label = 1

                if next_line                                      \
                        and next_line.refs_to                     \
                        and insn_match(line.ea, idaapi.NN_jmp, (idc.o_near, 0), comment='jmp rel32'):
                            if len(next_line.refs_to) == 1        \
                                    and _.first(next_line.refs_to) == line.ea:
                                        skip = 1
                                        #  continue
                            else:
                                line.skip = 1
                                #  print("continue")
                                continue

                if count == 0:
                    #  outi("{}".format(line.force_labeled_indented))
                    pass
                elif not no_label and skip and line.refs_to: 
                    line.skip = 0
                    line.hide_insn = 1
                    #  outi("{}:".format(line.label))
                    pass
                elif not skip:
                    line.hide_label = 1
                    #  outi("{}".format(line.unlabeled_indented))
                else:
                    line.skip = 1

                outi(line.indented)


    for bt in badtails:
        errors.append(out(bt))
    for bj in badjumps:
        src, dst = bj
        if dst == idc.BADADDR:
            errors.append(out("    ; bad jmp {:x} {:x}".format(src, dst)))
            target = GetTarget(src)

            while isNop(target):
                if UnPatch(target, GetInsnLen(target)):
                    target += GetInsnLen(target)

                else:
                    break

    #  if chunkheads:
        #  if not kwargs.get('ignoreInt', None):
            #  chunkheads = _.filter(chunkheads, lambda x, *a: not isInterrupt(x))

    if chunkheads:
        errors.append(
            out('    ; [warn] unusedchunks {} {}'.format(len(chunkheads), asHexList(chunkheads)))
        )
        errorObjects.extend([FuncTailsUnusedChunk(x) for x in chunkheads])
        if showUnused:
            for head in chunkheads:
                for insn in AdvanceToMnemEx(head, ignoreInt=ignoreInt):
                    print("{}".format(insn.labeled_indented))
    if nonheadtargets:
        errors.append(
            out('    ; [info] non-chunkhead targets: {}'.format([hex(x) for x in nonheadtargets]))
        )
    #  try:
    #  for head, heads in chunkheads.items():
    #  out('    ; [bb] {:x} unusedchunk: {}'.format(head, hex(heads)))
    #  #  RemoveThisChunk(head)
    #  except TypeError:

    #  raise TypeError("see above")

    #  try:
    #  if isinstance(output, list):
    #  output[:] = [x.text for x in decompiled]
    #  except TypeError:

    #  if not errors:
    if isinstance(externalTargets, set):
        externalTargets.update(_externalTargets)
    elif isinstance(externalTargets, list):
        externalTargets.extend(_externalTargets)
    if returnAddrs:
        return addrs
    if returnOutput:
        if debug: printi("[format_bb] returning output")
        if returnOutput == 'buffer':
            sti = CircularList(len(decompiled))
            for i, o in enumerate(_.uniq(decompiled, lambda o, *a: o.ea)):
                if True:  # line.startswith(' '):
                    # line = re.sub(';.*', '', line).strip()
                    if returnFormat:
                        line = returnFormat(o)
                    else:
                        line = o.text
                    sti.append(line)
            return sti
        else:
            return decompiled
    if returnPretty:
        return pretty


    return errorObjects if returnErrorObjects else errors


def AdvanceToMnemEx(ea, term='retn', iteratee=None, ignoreInt=False, **kwargs):
    start_ea = ea
    insn_count = 1
    byte_count = 0
    insns = []
    private = SimpleAttrDict()
    opt = SimpleAttrDict(kwargs)
    if callable(term):
        term_callback = term
    else:
        term_callback = None
    term = A(term)
    #  ignore_flow = 1
    labels = dict()
    current_labels = []
    refs_from = defaultdict(set)
    refs_to = defaultdict(set)
    flow_refs_to = defaultdict(set)
    flow_refs_from = defaultdict(set)
    pending = set([ea])
    visited = set()
    final_loop = 0
    results = []
    while pending:
        ignore_flow = 1
        ea = pending.pop()
        if getattr(opt, 'ease', 0):
            if debug: print('ease option, calling easecode')
            EaseCode(ea, forceStart=1, noExcept=1)
        while ea not in visited and IsCode_(ea) and (
                IsFlow(ea) or ignore_flow or (
                    ignoreInt and isInterrupt(idc.prev_not_tail(ea))
                    )
                ):
            label = ''
            visited.add(ea)
            insn = diida(ea)
            mnem = diida(ea, mnemOnly=1)
            size = GetInsnLen(ea)
            is_call = isCall(ea)
            is_follow_call = is_call and getattr(opt, 'follow_calls', 0) and GetTarget(ea, flow=0,
                                                                                       calls=1) != idc.BADADDR
            is_any_jmp = isAnyJmp(ea) and idc.get_operand_type(ea, 0) != o_displ
            is_unc_jmp = is_any_jmp and isUnconditionalJmp(ea)
            is_con_jmp = is_any_jmp and not is_unc_jmp

            if (is_any_jmp or is_follow_call) and GetTarget(ea) != BADADDR:
                target = GetTarget(ea)
                #  target = SkipJumps(ea, skipNops=True)
                if not IsValidEA(target):
                    UnPatch(ea)
                    target = GetTarget(ea)
                    if not IsValidEA(target):
                        msg = "Invalid target: {:x} {}".format(ea, GetDisasm(ea))
                        raise AdvanceFailure(msg)
            else:
                target = None
            if is_any_jmp:
                refs_from[ea].add(target)
                refs_to[target].add(ea)

            if IsFlow(ea):
                # might need to check for out-of-chunk flow
                flow_refs_to[ea].add(idc.prev_head(ea))

            if term_callback and term_callback(ea) or not term_callback and mnem in (term):
                if insns:
                    if insns[-1].target == ea:
                        insns.pop(-1)
                if getattr(opt, 'inclusive', 0):
                    final_loop = 1
                else:
                    break
            insn_de = de(ea)[0]
            if IsRef(ea):
                label = idc.get_name(ea)
                if label.startswith("0x"):
                    label = "loc_" + string_between('0x', '', label, inclusive=1)
                labels[ea] = label
            else:
                label = ''

            for r in range(5):
                #  EaseCode(ea)
                idc.generate_disasm_line(ea, 0)
                next_head = idc.next_head(ea)
                next_insn = ea + GetInsnLen(ea)
                if next_insn == next_head:
                    break
                if next_insn < next_head:
                    if not isUnconditionalJmp(ea) and not isRet(ea):
                        forceCode(next_insn)
                        continue
                    else:
                        next_insn = next_head = 0
                        break
                if next_insn > next_head:
                    if not IsHead(ea):
                        print('{:x} not head'.format(ea))
                    raise RuntimeError(
                        '{:x} somehow next_insn > next_head {:x} != {:x}'.format(ea, next_insn, next_head))

            if next_insn != next_head:
                raise RuntimeError(
                    '{:x} {:x} next_insn != next_head {:x} != {:x}'.format(start_ea, ea, next_insn, next_head))

            is_next_flow = next_insn and IsFlow(next_insn)

            if iteratee:
                response = \
                    iteratee(SimpleAttrDict({'label': label,
                                             'insn': insn.strip(),
                                             'mnem': mnem,
                                             'insn_de': insn_de,
                                             'ea': ea,
                                             'size': size,
                                             'branch': is_any_jmp and not is_unc_jmp,
                                             'call': is_call,
                                             'label': label,
                                             'next': next_insn if is_next_flow else target,
                                             'target': target,
                                             'chunk': GetChunkNumber(ea),
                                             'bytes': bytearray([idc.get_wide_byte(x) for x in range(ea, ea + size)]),
                                             'private': private}))

                if isinstance(response, dict):
                    if 'result' in response:
                        results.append(response['result'])

            if label:
                current_labels.append(label)
                #  if len(insns) and re.match(r'\s*j\w+ ' + re.escape(label), insns[-1]):
                #  insns.pop()
                #  insns.append("{}:".format(label))

            if mnem not in (['nop']):
                insns.append(FuncTailsInsn(insn, ea, "{}".format(insn), labels=[label] if label else [],
                                           refs_from=refs_from[ea], refs_to=refs_to[ea],
                                           size=GetInsnLen(ea)))
                current_labels.clear()
                #  insns.append("    {}".format(insn))
                insn_count += 1
                byte_count += size

            if label:
                if len(insns) > 1:
                    if insns[-2].target == ea:
                        insns.pop(-2)

            ignore_flow = 0

            if target and is_follow_call:
                ea = target
                if getattr(opt, 'ease', 0):
                    if debug: print('ease option, calling easecode')
                    EaseCode(ea)
                ignore_flow = 1
                continue

            if target and is_any_jmp:
                if is_unc_jmp:
                    ea = target
                    if getattr(opt, 'ease', 0):
                        if debug: print('ease option, calling easecode')
                        EaseCode(ea, forceStart=1)
                    ignore_flow = 1
                    continue
                else:
                    pending.add(target)

            ea += size
            if final_loop:
                break

    for _to, _from in flow_refs_to.items():
        for _src in _from:
            flow_refs_from[_src].add(_to)

    for _to, _from in refs_to.items():
        for _ea in _from:
            refs_from[_ea].add(_to)

    unvisited = pending - visited
    if unvisited:
        unvisited_str = "[warn] unvisited: {}".format(hex(unvisited))
        globals()['warn'] += 1
        print(unvisited_str)
        insns.append("; {}".format(unvisited_str))

    return AdvanceInsnList(
        ea=start_ea,
        insns=insns,
        insn_count=insn_count,
        byte_count=byte_count,
        results=results,
        refs_from=refs_from,
        refs_to=refs_to,
        flow_refs_from=flow_refs_from,
        flow_refs_to=flow_refs_to,
        start_ea=start_ea,
        end_ea=ea,
    )

if hasglobal('PerfTimer'):
    func_tails = PerfTimer.bind(func_tails)
    PerfTimer.bindmethods(AdvanceInsnList)
    PerfTimer.bindmethods(FuncTailsInsn)

#  \C\<\(chunkhead\|comments\|ea\|errors\|flow_refs_from\|flow_refs_to\|insn\|labeled_value\|labels\|op\|refs_from\|refs_to\|sp\|spd\|text\|warnings\)\>()
