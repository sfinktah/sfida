#!/usr/bin/env python
import re, os

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


def _A(o):
    if o is None:
        return []
    elif isinstance(o, list):
        return o
    else:
        return list([o])

_re_pattern = re.compile(r'.')
def isre(e):
    return type(e) == type(_re_pattern)

def sfind(s, *args):
    return str.find(s, *args)

def sfind_(haystack, needle, offset = 0, greedy = False, index = None):
    if isinstance(needle, list):
        if index is not None:
            needle = needle[index]

    for i, needle in enumerate(_A(needle)):
        start = -1
        length = 0
        if isre(needle):
            while True:
                m = re.search(needle, haystack[offset:])
                if not m:
                    break
                
                pos, end = m.span()
                length = end - pos
                start = pos + offset
                offset = start + 1

                if not greedy:
                    break
        else:
            if greedy:
                start = haystack.rfind(needle, offset)
            else:
                start = haystack.find(needle, offset)
            length = len(needle)

        if start > -1:
            return start, length, i
    return start, length, -1

class String:
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
        return self if self.retn_class else result

def string_between(left, right, subject, start=0, end=None, inclusive=False, greedy=False, rightmost=False, repl=None, retn_all_on_fail=False, retn_class=False, repeat="TODO"):
    """
    Return the substring sub delineated by being between the
    strings `left` and `right`, and such that sub is contained
    within subject[start:end].  Optional arguments start and
    end are interpreted as in slice notation.
    
    Return the string between `left` and `right` or empty string on failure

    :param left [str|re|list]: left anchor, or '' for start of subject; lists are shoddy; TODO: regex
    :param right [str|re|list]: right anchor, or '' for end of subject; lists are shoddy; TODO: regex
    :param subject: string to be searched
    :param start: start index for search
    :param end: start and end are interpreted as in slice notation.
    :param inclusive: include anchors in result
    :param greedy: match biggest span possible
    :param rightmost: match rightmost span possible by greedily searching for `left`; implies `greedy`
    :param repl [str|callable]: replace span with string (or callable)
    :param retn_all_on_fail: return original string if match not made
    :param retn_class: return result as String object
    :return: str: matched span | modified string | original string | String object
    
    Note: regular expressions must be compiled

    If left and right are lists, then string_between() takes a value from
    each list and uses them as left and right on subject. If right has
    fewer values than left, then an empty string is used for the rest of
    replacement values. If left is a list and right is a string, then
    this replacement string is used for every value of left. The converse
    would not make sense, though.

    """
    if isinstance(left, list):
        if isinstance(right, list):
            if len(right) < len(left):
                right.extend([''] * len(left) - len(right))
        else:
            right = [right] * len(left)
        for l, r in zip(left, right):
            result = string_between(l, r, subject=subject, inclusive=inclusive, greedy=greedy, repl=repl, retn_all_on_fail=retn_all_on_fail, retn_class=retn_class, repeat=repeat)
            if result:
                return result
        return ''

        
    #  Maybe it will work on lists, who knows
    #  if not isinstance(subject, string_types):
        #  return None
    llen = len(left)
    rlen = len(right)
    r = len(subject) - start
    #  rlen = 0
    #  if isre(left):
        #  m = re.search(left, match)
        #  if m:
            #  l, llen = m.span()
            #  llen -= l
        #  else:
            #  l = -1
    #  else:
    if rightmost:
        greedy = True
        if not right:
            l = subject.rfind(left, start, end)

    l = subject.find(left, start, end)
    
    #  l, llen, i = sfind(subject, left)
    result = String(l, r, subject, retn_class)
    if not ~l:
        if repl is not None or retn_all_on_fail: return result.ret(subject)
        return result.ret('')

        #  if not greedy:
            #  r = subject.find(right, l + llen)
    if right:
        # TODO: this will fuck up if there is an empty elemnt in list, and greedy is not True
        #  r, rlen, i = sfind(subject, right, l + llen, greedy, i)
        #  else:
        if greedy:
            r = subject.rfind(right, start, end)
            if rightmost and ~r:
                l = subject.rfind(left, start, r)
        else:
            r = subject.find(right, l + llen, end)
    if not ~r or r < l + llen:
        if repl is not None or retn_all_on_fail: return result.ret(subject, r=r)
        return result.ret('', r=r)
    if inclusive and r:
        r += rlen
    else:
        l += llen
    if repl is None:
        return result.ret(subject[l:r], l=l, r=r)
    if callable(repl):
        return result.ret(subject[0:l] + repl(subject[l:r]) + subject[r:], l=l, r=r)
    return result.ret(subject[0:l] + repl + subject[r:], l=l, r=r)


string_between_repl = string_between

def without(o, *values):
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
        result = string_between(left, right, s, start, retn_class=1, **(without(kwargs, 'start', 'retn_class')))

        # result.start == result.end should be ok if it was an empty match
        # result.end == 0 **might** be okay, but not sure, leaving it as end-of-results for now, as it will cause looping issues
        if result.start < 0 or result.end < 1 or result.end < result.start:
            break

        # print("[debug] result:{}".format(pf(read_everything(result))))

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

    Example Usage:
    (needle, str) = string_between_splice('[', ']', str, repl = 'replaced')

    :return: tuple(matched, modifed_string)
    """
    needle = string_between_repl(left, right, subject, inclusive, greedy)
    if needle:
        return needle, string_between_repl(left, right, subject, inclusive, greedy, repl)
    return '', subject


def string_between_test():
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

class escape_lut(object):
    data = """
        (:close=),esc=\\
        [:close=],esc=\\
        {:close=},esc=\\
        \"\"\":close=\"\"\"),esc=\\
        ''':close=''',esc=\\
        ':close=',esc=\\
        ":close=",esc=\\
    """


def test_string_between():
    def test_assert(stmt):
        if not stmt:
            raise RuntimeError('test_assert failed')

    s = '...'
    lhs = string_between('', ' ', s, greedy=1)
    rhs = string_between('', ' ', s, greedy=1, repl='')
    test_assert(lhs == '')
    test_assert(rhs == '...')

def test_ce_pointer_parse():
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
        # dprint("[debug] needle, string")
        print("[debug] needle:{}, string:{}".format(needle, string))
        
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

#  test_ce_pointer_parse()

# string_between_test()
