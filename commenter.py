import os, re
import idc, idaapi
#  from sfida.sf_common import get_ea_by_any
from sfida.sf_string_between import string_between
#  from sftools import A
from collections import defaultdict

from execfile import execfile, _import, _require, make_refresh
_import('from underscoretest import _')
refresh_commenter = make_refresh(os.path.abspath(__file__))

class CommenterRange(object):
    def __init__(self, r):
        r = genericRange(r)

    def __enter__(self):
        self.funcset = set([x for x in idautils.Heads(self.r.start, self.r.end) if IsFuncHead(x)])
        self.lineset = set(idautils.Heads(self.r.start, self.r.end))
        self.line_comments = [Commenter(ea, 'line', commit=0) for ea in self.lineset]
        self.func_comments = [Commenter(ea, 'func', commit=0) for ea in self.lineset]

        return self

    def add(self, comment):
        for cmt in self.line_comments:
            cmt.add(comment)

    def remove(self, comment):
        for cmt in self.line_comments:
            cmt.remove(comment)

    def fadd(self, comment):
        for cmt in self.func_comments:
            cmt.add(comment)

    def fremove(self, comment):
        for cmt in self.func_comments:
            cmt.remove(comment)

    def __exit__(self, exc_type, exc_value, traceback):
        for cmt in self.func_comments + self.line_comments:
            cmt.commit()




class Commenter(object):
    """Manage multiline comments?
    c=Commenter(idc.get_screen_ea())
    c.add(newComment)

    or

    with Commenter(ea) as c:
        if not c.match('[MARK]'):
            c.add('[MARK]')
            c.remove('[OLDMARK]')
    """
    def __init__(self, ea=None, ctype=None, repeatable=False, commit=True):
        """ read comment string and turn into array """
        self.fnGetters = []
        self.fnSetters = []
        self.repeatable = repeatable
        self.cm = dict() 
        self.map = dict()
        self.auto_commit = commit
        self.ea = get_ea_by_any(ea)
        if ctype is None:
            ctype = 'regular'
            f = idc.get_full_flags(ea)
            if f & idc.FF_FUNC:
                ctype = 'func'
        if ctype is not None:
            for ctype in A(ctype):
                c = 'ctype_' + ctype.lower()
                fn = getattr(self, c)
                fn()
                comments = self.fnGet(ea, repeatable)
                if comments and isinstance(comments, str):
                    self.split(comments)
                else:
                    self.comments = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.commit()

    def ctype_line(self):
        return self.ctype_regular()
    def ctype_regular(self):
        self.fnGetters.append(idc.get_cmt)
        self.fnSetters.append(idc.set_cmt)
        self.cm[str(idc.get_cmt)] = list()
        self.map[str(idc.set_cmt)] = str(idc.get_cmt) 
    def ctype_func(self):
        f = idc.get_full_flags(self.ea)
        if f & idc.FF_FUNC:
            self.fnGetters.append(idc.get_func_cmt)
            self.fnSetters.append(idc.set_func_cmt)
            self.cm[str(idc.get_func_cmt)] = list()
            self.map[str(idc.set_func_cmt)] = str(idc.get_func_cmt) 
    def ctype_struc(self):
        self.fnGetters.append(idc.get_struc_cmt)
        self.fnSetters.append(idc.set_struc_cmt)
        self.cm[str(idc.get_struc_cmt)] = list()
        self.map[str(idc.set_struc_cmt)] = str(idc.get_struc_cmt) 
    def ctype_member(self):
        self.fnGetters.append(idc.get_member_cmt)
        self.fnSetters.append(idc.set_member_cmt)
        self.cm[str(idc.get_member_cmt)] = list()
        self.map[str(idc.set_member_cmt)] = str(idc.get_member_cmt) 
    def ctype_enum(self):
        self.fnGetters.append(idc.get_enum_cmt)
        self.fnSetters.append(idc.set_enum_cmt)
        self.cm[str(idc.get_enum_cmt)] = list()
        self.map[str(idc.set_enum_cmt)] = str(idc.get_enum_cmt) 

    def fnGet(self, ea, repeatable = 0):
        for getter in self.fnGetters:
            self.cm[str(getter)] = getter(ea, repeatable)
            if not self.cm[str(getter)]:
                self.cm[str(getter)] = []
            else: self.cm[str(getter)] = self.cm[str(getter)].split("\n")

    def fnSet(self, ea, repeatable = 0):
        for setter in self.fnSetters:
            setter("\n", self.cm[self.map[str(setter)]], repeatable)

    def indexOf(self, comment):
        return self.cm[str(self.fnGetters)].indexOf(comment)

    def exists(self, comment):
        return comment in _.flatten([self.cm[str(getter)] for getter in self.fnGetters])

    def contains(self, comment):
        return self.exists(comment)

    def remove(self, comment):
        for getter in self.fnGetters:
            if comment in self.cm[str(getter)]:
                self.cm[str(getter)].remove(comment)
                self.maybe_commit()

    def string_between(self, left, right, *args, **kwargs):
        for getter in self.fnGetters:
            for c in self.cm[str(getter)]:
                sb = string_between(left, right, c, *args, **kwargs)
                if sb and len(sb):
                    yield sb

    def clear(self):
        for getter in self.fnGetters:
            self.cm[str(getter)].clear()
        self.maybe_commit()

    def match(self, pattern, flags=0):
        for getter in self.fnGetters:
            for c in self.cm[str(getter)]:
                if re.match(pattern, c, flags) is not None:
                    return True
        return False

    def matches_iter(self, pattern):
        for getter in self.fnGetters:
            for c in self.cm[str(getter)]:
                if re.match(pattern, c) is not None:
                    yield c

    def matches(self, pattern):
        return list(self.matches_iter(pattern))

    def startswith(self, pattern):
        for getter in self.fnGetters:
            for c in self.cm[str(getter)]:
                if c.startswith(pattern):
                    yield c

    def remove_matching(self, pattern):
        delme = list()
        for getter in self.fnGetters:
            for c in self.cm[str(getter)]:
                if re.match(pattern, c) is not None:
                    delme.append(c)
            for d in delme:
                self.cm[str(getter)].remove(d)
        self.maybe_commit()

    def add(self, comment):
        for setter in self.fnSetters:
            l = self.cm[self.map[str(setter)]]
            if comment not in l:
                l.append(comment)
        self.maybe_commit()
        return self

    def maybe_commit(self):
        if self.auto_commit:
            self.commit()

    def commit(self):
        for setter in self.fnSetters:
            setter(self.ea, "\n".join(self.cm[self.map[str(setter)]]), self.repeatable)

