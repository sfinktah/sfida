#!/usr/bin/env python
""" python3 -m doctest -v doctest_hashed_values_tests.py """
import itertools
import re, os
try:
    from attrdict import AttrDict
except:
    pass
# requires py > 3.6
# from typing import Pattern

try:
    from execfile import make_refresh
    refresh_sf_string_between = make_refresh(os.path.abspath(__file__))
    refresh = make_refresh(os.path.abspath(__file__))
except ImportError:
    pass

try:
    import __builtin__ as builtins
    string_types = (str, unicode)
    string_type = unicode
    byte_type = str
except:
    import builtins
    string_types = (str, bytes)
    byte_type = bytes
    string_type = str

_re_pattern = re.compile(r'.')
def _isre(e):
    return type(e) == type(_re_pattern)

def _isIterable(o):
    return hasattr(o, '__iter__') and not hasattr(o, 'ljust')

def _string_find(S, sub, start=0, end=None):
    if isinstance(sub, str):
        return len(sub), S.find(sub, start, end)
    if _isre(sub):
        for m in re.finditer(sub, S):
            __start, __end = m.span()
            if __start > start and (end is None or __end < end):
                return __end - __start, __start
        return -1, -1

def _string_rfind(S, sub, start=0, end=None):
    if isinstance(sub, str):
        return len(sub), S.rfind(sub, start, end)
    # if isinstance(sub, Pattern):
    if _isre(sub):
        _start, _end = -1, -2
        for m in re.finditer(sub, S):
            __start, __end = m.span()
            if __start > start and (end is None or __end < end):
                _start, _end = __start, __end
        return _end - _start, _start

class StringBetweenResult:
    """result of string_between operation"""

    def __init__(self, start, end, subject, retn_class, result = None):
        self.start = start
        self.end = end
        self.subject = subject
        self.retn_class = retn_class
        self.result = result

    def ret(self, result, l=None, r=None):
        self.result = result
        if l is not None:
            self.start = l
        if r is not None:
            self.end = r
        # on failure return empty string but store None
        if result is None:
            result = ''
        return self if self.retn_class else result

    def found(self):
        if self.result is not None and \
                self.start is not None and self.start != -1 and \
                self.end is not None and self.end != -1:
                    return True
        return False

def string_between(left, right, subject, *args, **kwargs):
    """
    string_between(left, right, subject, [,start [,end]] [,greedy=False] [,inclusive=False] [,repl=None] [,retn_all_on_fail=False] [,retn_class=False] [,rightmost=False]) -> str


    Return the substring sub delineated by being between the
    strings `left` and `right`, and such that sub is contained
    within subject[start:end].  Optional default_arguments start and
    end are interpreted as in slice notation.
    
    Return the string between `left` and `right` or empty string on failure

    @param left str|re|list: left anchor, or '' for start of subject; regex must be compiled
    @param right str|re|list: right anchor, or '' for end of subject; regex must be compiled
    @param subject: string to be searched
    @param start: start index for search
    @param end: start and end are interpreted as in slice notation.
    @param greedy: match biggest span possible
    @param inclusive: include anchors in result
    @param repl [str|callable]: replace span with string (or callable)
    @param retn_all_on_fail: return original string if match not made
    @param retn_class: return result as StringBetweenResult object
    @param rightmost: match rightmost span possible by greedily searching for `left`; implies `greedy`
    @return matched span | modified string | original string | empty StringBetweenResult object
    
    Note: regular expressions must be compiled

    If left and right are lists, then string_between() takes a value from
    each list and uses them as left and right on subject. If right has
    fewer values than left, then an empty string is used for the rest of
    replacement values. The converse applies. If left is a list and right 
    is a string, then this replacement string is used for every value of left. 
    The converse also applies.

    Examples:
    ---------

    >>> s = 'The *quick* brown [fox] jumps _over_ the **lazy** [dog]'
    >>> string_between('[', ']', s)
    'fox'

    >>> string_between('[', ']', s, inclusive=True)
    '[fox]'

    >>> string_between('[', ']', s, rightmost=True)
    'dog'

    >>> string_between('[', ']', s, inclusive=True, greedy=True)
    '[fox] jumps _over_ the **lazy** [dog]'

    """
    # get kwargs into variables
    default_arguments = [
            ('start',            0),
            ('end',              None),
            ('repl',             None),
            ('inclusive',        False),
            ('greedy',           False),
            ('rightmost',        False),
            ('retn_all_on_fail', False),
            ('retn_class',       False)]
    # regex for manipulating named variables
    # start|end|inclusive|greedy|rightmost|repl|retn_all_on_fail|retn_class|
    # left, right, subject, start=0, end=None, inclusive=False, greedy=False, rightmost=False, repl=None, retn_all_on_fail=False, retn_class=False
    # vim regex for above: s/\(\w\+\)=\([^ ,]\+\)/.../g
    v = AttrDict(kwargs)
    for _key, _value in zip(['start', 'end'], args):
        v[_key] = _value
    for _key, _value in default_arguments:
        if _key not in v:
            v[_key] = _value

    # Handle `left` or `right` being a list
    _list = None
    if _isIterable(left):
        _list = []
        if not _isIterable(right):
            _list = [(x, right) for x in left]
        else:
            for x, y in itertools.zip_longest(left, right, fillvalue=''):
                _list.append((x, y))
    elif _isIterable(right):
        _list = [(left, x) for x in right]

    if _list:
        _old_retn_class = v.retn_class
        v.retn_class = True
        _result = []
        for _l, _r in _list:
            _rv = string_between(_l, _r, subject, **v)
            if _rv.found():
                _result.append(_rv if _old_retn_class else _rv.result)
        v.retn_class = _old_retn_class 
        if v.retn_class:
            return _result
        return _result[0] if _result else ''


    # regular processing starts here
    
    r = len(subject) - v.start

    l = -2
    if v.rightmost:
        v.greedy = True
        if not right:
            llen, l = _string_rfind(subject, left, v.start, v.end)

    if l == -2:
        llen, l = _string_find(subject, left, v.start, v.end)
    
    result = StringBetweenResult(l, None, subject, v.retn_class)
    if not ~l:
        if v.repl is not None or v.retn_all_on_fail: return result.ret(subject, l)
        return result.ret(None, l)

    #  llen = string_len(left) 
    #  rlen = string_len(right) 
    if right:
        if v.greedy:
            rlen, r = _string_rfind(subject, right, v.start, v.end)
            if v.rightmost and ~r:
                llen, l = _string_rfind(subject, left, v.start, r)
        else:
            rlen, r = _string_find(subject, right, l + llen, v.end)
    else:
        rlen = 0

    
    if not ~r or r < l + llen:
        if v.repl is not None or v.retn_all_on_fail: return result.ret(subject, l, r)
        return result.ret('', l, r)
    if v.inclusive and r:
        r += rlen
    else:
        l += llen
    if v.repl is None:
        return result.ret(subject[l:r], l, r)
    if callable(v.repl):
        return result.ret(subject[0:l] + v.repl(subject[l:r]) + subject[r:], l, r)
    return result.ret(subject[0:l] + v.repl + subject[r:], l, r)

def _without(o, *values):
    """
    Return a version of the array that does not contain the specified
    value(s), or object that doesn't contain the specified key(s)
    """
    if isinstance(o, dict):
        newlist = {}
        for k in o:
            if k not in values:
                newlist[k] = o[k]
    else:
        newlist = []
        for v in o:
            if v not in values:
                newlist.append(v)
    return newlist

def string_between_all(left, right, subject, start=0, limit=512, **kwargs):
    results = []
    result = False
    s = subject
    while limit > 0:
        limit -= 0
        result = string_between(left, right, s, start, retn_class=1, **(_without(kwargs, 'start', 'retn_class')))

        # result.start == result.end should be ok if it was an empty match
        # result.end == 0 **might** be okay, but not sure, leaving it as end-of-results for now, as it will cause looping issues
        if result.start < 0 or result.end < 1 or result.end < result.start:
            break

        results.append(result)


        start = result.end

        if result and not result.end < len(result.subject):
            break

    if kwargs.get('retn_class', False):
        return results
    return [x.result for x in results]

def string_between_splice(left, right, subject, inclusive=False, greedy=False, repl=None, *args, **kwargs):
    """ A splice variant of string_between
    Since Python does not support passing strings by reference, both
    the removed section and the new string are returned in a tuple.

    @param left str|re|list: left anchor, or '' for start of subject; regex must be compiled
    @param right str|re|list: right anchor, or '' for end of subject; regex must be compiled
    @param subject: string to be searched
    @param greedy: match biggest span possible
    @param inclusive: include anchors in result
    @param repl [str|callable]: replace span with string (or callable)

    :return: tuple(matched, modifed_string)

    Example Usage:
    --------------

    >>> s = "mov lea, [rbp+10h]"
    >>> needle, s = string_between_splice('[', ']', s, repl='rsp')
    >>> needle, s
    ('rbp+10h', 'mov lea, [rsp]')

    """
    needle = string_between(left, right, subject, inclusive=inclusive, greedy=greedy)
    if needle:
        return needle, string_between(left, right, subject, inclusive=inclusive, greedy=greedy, repl=repl)
    return '', subject


def _test_string_between_1():
    def recurse(s, debt=0):
        s = s[1:-1].strip()
        if s:
            t = s[1:].strip('() ').split(' ')
            (a, b) = (t[0], int(t.pop()))
            b += debt
            print("""# {0} << {1}
                bool {0}() const {{
                    return (this->btProofs_188 >> {1}) & 1;
                }}
                auto* {0}(uint32_t enabled) {{
                    this->btProofs_188 &= ~(1 << {1});
                    this->btProofs_188 |= enabled << {1};
                    return this;
                }}
            """.format(a, b))
            return string_between('| (', ')', s, inclusive=1, greedy=1, repl=lambda x: recurse(x, b))
        return ''

    s = '((bulletProof | (fireProof | (collisionProof | (meleeProof | (explosionProof | (steamProof | (drownProof << 1)) << 4) << 4) << 1) << 1) << 1) << 4)'
    print(string_between('(', ')', s, inclusive=1, greedy=1, repl=recurse))

def _test_string_between():
    def test_assert(stmt):
        if not stmt:
            raise RuntimeError('test_assert failed')

    s = '...'
    lhs = string_between('', ' ', s, greedy=1)
    rhs = string_between('', ' ', s, greedy=1, repl='')
    test_assert(lhs == '')
    test_assert(rhs == '...')

def _test_ce_pointer_parse():
    subject = "[[[[5+5]+10]+20]+2]+1"
    resolve = []

    def solve(r):
        try:
            # code = compile(r, '', 'exec')
            return eval(r)
        except:
            print(r)
            raise Exception("template error")

    def ptr_parse_recursive(subject, initial=False):
        string = string_between("[", "]", subject, greedy=1, inclusive=1, repl='')
        needle = ''
        
        subject = string_between("[", "]", subject, greedy=1, inclusive=0, retn_all_on_fail=0)
        print("subject: {}".format(subject))
        #  if initial and not subject.endswith("]"):
            #  return subject
        #  else:
        r = string_between("[", "]", subject[0:], repl=ptr_parse_recursive, greedy=1, inclusive=1)
        print("r: {}".format(r))
        solved = solve(r)
        resolve.append(solved)
        if string:
            resolve.append(solve("{} {}".format(solved, string)))
        #  resolve.append(solve(r))
        return r

    print("result: {}".format(ptr_parse_recursive(subject, initial=1)))
    print("resolve: {}".format(resolve))

