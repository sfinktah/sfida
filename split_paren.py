import re

def _each(o, func):
    """
    iterates through each item of an object

    underscore.js:
    Iterates over a list of elements, yielding each in turn to an iteratee
    function. The iteratee is bound to the context object, if one is
    passed. Each invocation of iteratee is called with three arguments:
        (element, index, list). 
    If list is a JavaScript object, iteratee's arguments will be (value,
    key, list). Returns the list for chaining.
    """
    if callable(getattr(o, 'items', None)):
        for key, value in o.items():
            r = func(value, key, o)
            if r is "breaker":
                break
    else:
        for index, value in enumerate(o):
            r = func(value, index, o)
            if r is "breaker":
                break
    return o

def _any(o, func=None):
    """
    Determine if at least one element in the object
    matches a truth test.
    """
    if func is None:
        func = lambda x, *args: x

    antmp = False

    def testEach(value, index, *args):
        if func(value, index, *args) == True:
            antmp = True
            return "breaker"

    _each(o, testEach)
    return antmp

def paren_split(subject, separator=",", lparen="(", rparen=")", strip=" ", rtrim=False):
    # https://stackoverflow.com/questions/42070323/split-on-spaces-not-inside-parentheses-in-python/42070578#42070578
    nb_brackets=0
    subject = subject.strip(strip or separator) # get rid of leading/trailing seps

    l = [0]
    for i, c in enumerate(subject):
        if c == lparen:
            nb_brackets += 1
        elif c == rparen:
            nb_brackets -= 1
        elif c == separator and nb_brackets == 0:
            l.append(i + 1) # skip seperator
        # handle malformed string
        if nb_brackets < 0:
            if rtrim:
                subject = subject[0:i]
                # print("retrying with: {}".format(subject))
                return paren_split(subject, separator, lparen, rparen, strip)
            else:
                raise Exception("Syntax error (unmatch rparen)")

    l.append(len(subject))
    # handle missing closing parentheses
    if nb_brackets > 0:
        raise Exception("Syntax error (unmatched lparen)")


    return([subject[i:j].strip(strip or separator) for i, j in zip(l, l[1:])])

def escape_backslash(subject, position):
    c = subject[position]
    last_escape = next_escape = None
    previous_escapes = 0
    p = position
    last_escape = subject.rfind('\\', 0, p)
    while ~last_escape and last_escape == p - 1:
        previous_escapes += 1
        p -= 1
        last_escape = subject.rfind('\\', 0, last_escape)

    
    # dprint("[last_] last_escape, next_escape")
    #  print("[escape_backslash] {} s:'{}' last_escape:{}, previous_escapes:{}".format(position, subject[0:position+1], last_escape, previous_escapes))

    return (previous_escapes % 2) != 0
                    
def func(ea=None):
    """
    func

    @param ea: linear address
    """

    ea = eax(ea)
    


def paren_multisplit(subject, separator=",", lparen="([{'\"", rparen=[")", "]", "}", "'", '"'], strip=None, escape=escape_backslash, noEmpty=False, limit=None):
    if isinstance(subject, list):
        return [paren_multisplit(x, separator, lparen, rparen, strip, escape, noEmpty) for x in subject]

    def _is_separator(s, sep):
        if type(sep) == type(subject):
            if s.startswith(sep):
                return len(sep)
        elif isinstance(sep, re.Pattern):
            m = re.match(sep, s)
            if m:
                # dprint("[debug] m.span(0), m.group(0), len(m.group(0)), m.span(0)[1] - m.span(0)[0]")
                #  print("[debug] m.span(0):{}, m.group(0):{}, len(m.group(0)):{}, m.span(0)[1] - m.span(0)[0]:{}".format(m.span(0), m.group(0), len(m.group(0)), m.span(0)[1] - m.span(0)[0]))
                return m.span(0)[1] - m.span(0)[0]
        elif callable(sep):
            m = sep(s)
            if m:
                if isinstance(m, int): return m
                return len(m)
        return 0

    def is_separator(i):
        s = subject[i:]
        if isinstance(separator, list):
            for sep in separator:
                m = _is_separator(s, sep)
                if m:
                    return m
            return 0

        return _is_separator(s, separator)

    # https://stackoverflow.com/questions/42070323/split-on-spaces-not-inside-parentheses-in-python/42070578#42070578
    lparen = list(lparen)
    rparen = list(rparen)
    paren_len = len(lparen)
    if len(rparen) != paren_len:
        raise Exception("len(rparen) != len(lparen)")
    brackets=[0] * paren_len
    stack = []

    if strip is not None:
        subject = subject.strip(strip) # get rid of leading/trailing seps

    l = [0]
    skip = 0
    #  if limit: limit -= 1
    if limit is not None and limit <= 0:
        return [subject]

    # dprint("[debug] subject")
    #  print("[debug] subject:{}".format(subject))
    
    for i, c in enumerate(subject):
        if skip > 0:
            # dprint("[debug] skip, i")
            #  print("[debug] skip:{}, i:{}".format(skip, i))
            
            skip -= 1
            continue

        if c in lparen and not escape(subject, i):
            deal = False
            index = lparen.index(c)
            if rparen[index] == c:
                # dealing with symetrical things like ' or "
                if stack and stack[-1] == c:
                    brackets[index] -= 1
                    stack.pop()
                    deal = True
            if not deal:
                brackets[index] += 1
                stack.append(c)
        elif c in rparen and not escape(subject, i):
            index = rparen.index(c)
            brackets[index] -= 1
            if brackets[index] < 0:
                raise Exception("Syntax error (unbalanced '{}' at '{}')".format(c, subject[0:i+1]))
            if stack[-1] != lparen[index]:
                raise Exception("Syntax error (unbalanced '{}' stack: '{}')".format(c, stack))
            stack.pop()
        # `escape` will need some work to properly work with separators other than single characters
        elif sum(brackets) == 0 and not escape(subject, i):
            m = is_separator(i)
            if m:
                l.append(i + m)
                skip = m - 1
                if limit is not None and len(l) > limit:
                    break

                if noEmpty:
                    ii = i + m
                    mm = True
                    while mm:
                        mm = is_separator(ii)
                        # dprint("[debug] ii, mm")
                        #  print("[debug] ii:{}, mm:{}".format(ii, mm))
                        if mm:
                            ii += mm
                    # dprint("[debug] ii, i, ii - i")
                    skip = ii - i - 1
                    #  print("[debug] ii:{}, i:{}, ii - i:{}, skip:{}".format(ii, i, ii - i, skip))

                    

    # handle malformed string
    if _any(brackets, lambda x, *a: x < 0):
        raise Exception("Syntax error (unmatch rparen)")

    l.append(len(subject) + 1)
    # handle missing closing parentheses
    if _any(brackets, lambda x, *a: x < 0):
        raise Exception("Syntax error (unmatch rparen) final")
    elif _any(brackets, lambda x, *a: x < 0):
        raise Exception("Syntax error (unmatch lparen) final")

    result = [subject[i:j-1].strip(strip) for i, j in zip(l, l[1:])]
    #  print("result: {}".format(result))

    return result
