COMB_NOP = 0x4
COMB_CALL = 0x8
COMB_RET = 0x10
COMB_UNC_BRANCH = 0x40
COMB_CND_BRANCH = 0x80

#  _base = os.path.abspath(__file__.replace('_class.py', ''))
#  check_for_updates = [
        #  make_auto_refresh(_base + '.py'),
        #  make_auto_refresh(_base + '_patches.py'),
        #  make_auto_refresh(_base + '_helpers.py'),
        #  make_auto_refresh(_base + '_generators.py'),
#  ]
#  check_for_update = lambda: (x() for x in check_for_updates)

def _to_string(o):
    return str(o)

class BasicPattern(object):
    pass

class PatternResult(object):
    """Docstring for PatternResult """

    def __init__(self, pat, result):
        """@todo: to be defined

        :pat: @todo
        :result: @todo

        """
        self.pat = pat
        self.result = result
        
class PatternGroup(object):
    def __init__(self, *items, **options):
        self.container = items
        self.options = options

    def __len__(self):
        return self.container.__len__()
    
    def __getitem__(self, key):
        return self.container.__getitem__(key)
    
    def __setitem__(self, key, value):
        self.container.__setitem__(key, value)
    
    def __delitem__(self, key):
        self.container.__delitem__(key)
    
    def __iter__(self):
        return self.container.__iter__()
    
    def __reversed__(self):
        return self.container.__reversed__()
    
    def __contains__(self, item):
        return self.container.__containers__(item)
    
    def append(self, object):
        self.container.append(object)
    
    def clear(self):
        self.container.clear()
    
    def copy(self):
        return (type(self))(self.container.copy())
    
    def count(self):
        return self.container.count()
    
    def extend(self, iterable):
        for item in iterable:
            self.append(item)
    
    def index(self, value, start=0, stop=9223372036854775807):
        self.container.index(value, start, stop)
    
    def insert(self):
        self.container.insert()
    
    def pop(self):
        self.container.pop()
    
    def remove(self):
        self.container.remove()
    
    def reverse(self):
        self.container.reverse()
    
    def sort(self):
        self.container.sort()
    
    def insert(self, index, object):
        self.container.insert(index, object)
    
    def pop(self, index=-1):
        return self.container.pop(index)
    
    def remove(self, value):
        self.container.remove(value)
    

class Pattern(BasicPattern):

    # @param notes Text description, and copy of output from dissasembly with offsets usually goes here.
    # @param brief a short description of the patch
    # @param search list of lines to match
    # @param repl list of replacement lines; or
    # @param replFunc function to perform replacements
    # @param safe if True, doesn't require backtracking
    # @param group predicate to speed lookups
    def __init__(self, notes='', brief='', search=None, repl=None, replFunc=None, safe=False, group=None, **kwargs):
        self.notes = notes
        self.brief = brief
        self.search = search
        self.repl = A(repl)
        self.replFunc = replFunc
        self.safe = safe
        self.group = group
        self.priority = 4
        self.options = SimpleAttrDict(kwargs)
        for k, v in kwargs.items():
            if k not in ('resume', 'reflow', 'then', 'priority', 'label'):
                printi("set pattern.options.{} to {} in {}".format(k, v, brief))
            

class BitwisePattern(BasicPattern):
    def __init__(self, search, mask, replFunc, brief, safe, **kwargs):
        self.brief = brief
        self.search = search
        self.mask = mask
        self.replFunc = replFunc
        self.safe = safe
        self.options = SimpleAttrDict(kwargs)
        for k, v in kwargs.items():
            if k not in ('resume', 'reflow', 'then', 'priority', 'label'):
                printi("set bitwisepattern.options.{} to {} in {}".format(k, v, brief))

    def as_list(self):
        return [self.search, self.mask, self.replFunc, self.brief, self.safe, self.options]

    def __len__(self):
        return 6
    
    def __getitem__(self, key):
        return self.as_list()[key]
    
    #  def __setitem__(self, key, value):
        #  pass
    #  
    #  def __delitem__(self, key):
        #  pass
    
    def __iter__(self):
        return self.as_list().__iter__()
    
    #  def __reversed__(self):
        #  pass
    #  
    #  def __contains__(self, item):
        #  pass

def bytepatch(b, address):
    return list(b)

def make_bitwise_patch(bm):
    def patch(search, _unused_replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        a = [addressList[x] for x in range(len(search))]
        b = [original[x] for x in range(len(search))] #  [Byte(x) for x in a]
        c = bm.pattern
        # d = [idc.get_wide_byte(x) for x in a]
        r = bm.sub(b)
        # dprint("[make_bitwise_patch] b, r")
        if obfu_debug: printi("[make_bitwise_patch] a:{}\nb:{}\nc:{}\nr:{}".format(listAsHex(a), binlist(b), c, listAsHex(r)))
        
        return len(search), r
    return patch

class Obfu(object):
    # Copyright 2016 Orwellophile LLC. MIT License.
    #
    # Useful notes for future development maybe:
    # https://reverseengineering.stackexchange.com/questions/14815/how-can-i-call-ida-pros-makecode-for-one-instruction-at-a-time
    #
    # https://reverseengineering.stackexchange.com/questions/13101/set-register-to-specific-value-for-use-in-autoanalysis-in-ida-pro-6-9/13105

    FlowControlFlags = [
        # Indicates the instruction is not a flow-control instruction.
        "FC_NONE",
        # Indicates the instruction is one of: CALL, CALL FAR.
        "FC_CALL",
        # Indicates the instruction is one of: RET, IRET, RETF.
        "FC_RET",
        # Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
        "FC_SYS",
        # Indicates the instruction is one of: JMP, JMP FAR.
        "FC_UNC_BRANCH",
        # Indicates the instruction is one of:
        # JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        "FC_CND_BRANCH",
        # Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
        "FC_INT",
        # Indicates the instruction is one of: CMOVxx.
        "FC_CMOV",
        # Indicates the instruction is HLT.
        "FC_NOP",
        "FC_REF",
    ]
    (
        CALL,  # 1
        RET,  # 2
        SYS,  # 3
        UNC_BRANCH,  # 4
        CND_BRANCH,  # 5
        INT,  # 6
        CMOV,  # 7
        NOP,  # 8
        REF,  # 9
    ) = [1 << x for x in range(0, 9)]

    def _makeFlagFromDi(self, insn):
        meta = insn.meta & 0xff
        flag = 0
        if meta > 7:
            # we're re-purposing these
            meta = 0
        if meta == 4: # unc_jmp
            if insn.operands[0].type != 'Immediate':
                meta ^= 4
        if insn.opcode == 581:  # nop
            meta = 8
        if meta:
            flag |= 1 << (meta - 1)
        if IsRef(insn.address):
            flag |= 1 << (9 - 1)

        return flag

    def __init__(self):
        self.quiet = False
        self._depth = 0
        self.combed = []
        self.default_comb_len = 2048
        self.stage2 = True
        self.AnalyzeQueue = []
        self.start = 0
        self.end = BADADDR
        self.eip = self.start
        self.patterns = []
        self.patterns_bitwise = []
        self.patternSet = set()
        self.searchSets = sets = [set() for __ in range(10)]
        self.longestPattern = 0
        self.groups = None
        self.labels = dict()
        self.triggers = {}

        self.slow_patterns = []
        self.slow_patterns_bitwise = []
        self.slow_patternSet = set()
        self.slow_searchSets = sets = [set() for __ in range(10)]
        self.slow_longestPattern = 0

        self.visited = set()
        #  self.searchSets = list()

    def add(self, pat, **kwargs):
        if not isinstance(pat, Pattern):
            raise Exception("Obfu.add can only accept Patterns")

        pst = _to_string(pat.search)
        if pst in self.patternSet:
            # printi("type(self.patterns)", type(self.patterns))

            found = _.find(self.patterns, lambda v, k, l: _to_string(v.search) == pst)
            if found:
                printi("Obfu Duplicate Search Pattern:\n{}\n{}".format(pfh(pat), pfh(found)))
                return
                raise ObfuFailure("Duplicate search pattern")
        setLen = len(self.searchSets)
        searchLen = len(pat.search)
        if searchLen > self.longestPattern:
            self.longestPattern = searchLen
        searchIndex = []
        for i in range(searchLen):
            searchIndex.append(i)
            if i < setLen:
                self.searchSets[i].add(pat.search[i])
        pat.searchIndex = searchIndex
        if searchLen < setLen:
            self.searchSets = self.searchSets[0:searchLen]
            # for i in xrange(searchLen, setLen):
            #    printi("self.searchSets[i] del: %s" % i)
            #    del self.searchSets[i]
        #  while len(repl) and repl[len(repl)-1] == 0xcc:
        #  printi("removed %02x from pattern %s" % (repl.pop(), brief))
        #  printi("%s: length: %d" % (_to_string(repl), len(repl)))
        self.patterns.append(pat)  # [search, repl, replFunc, searchIndex, brief, safe, notes])
        self.patternSet.add(_to_string(pat.search))
        # ' '.join([bin(x) for x in [x[0] for x in obfu.patterns][0]]).repl('0b', '')
        label = getattr(pat.options, 'label', None)
        #  printi("label: {}".format(label))
        if label:
            if label not in self.labels:
                if debug: printi("[add] label: {}".format(label))
                self.labels[label] = []
            self.labels[label].append(pat)


    def __repr__(self):
        return 'Obfu(%s patterns)' % len(self.patterns)

    def __len__(self):
        return len(self.patterns)

    def reset(self):
        """resets scan eip to start location
        :returns: None

        """
        self.eip = self.start

    def dump(self):
        for x in self.patterns:
            printi("dump:", x)

    def range(self, start, end):
        self.start = start
        self.end = end
        self.eip = start

    def prep_groups(self):
        if not self.groups:
            self.groups = _.groupBy(self.patterns, lambda x, *a: x.group.firstn(6))
            if obfu_debug: printi("[Obfu::prep_groups] {} pattern groups: {}".format(len(self.groups), [type(x) for x in self.groups]))

    ##
    # @brief append obfu pattern to database
    #
    # @param notes Text description, and copy of output from dissasembly with offsets usually goes here.
    # @param brief a short description of the patch
    # @param search list of lines to match
    # @param repl list of replacement lines; or
    # @param replFunc function to perform replacements
    # @param safe if True, doesn't require backtracking
    # @param group predicate to speed lookups
    #
    # @return None
    def append(self, notes='', brief='', search=None, repl=None, replFunc=None, safe=False, group=None, trigger=None, **kwargs):
        #  printi("append: \"{}\", <<{}>>, <<{}>>, {}".format(brief, search, repl, replFunc))
        if repl is None:
            repl = A(repl) 
        if trigger:
            self.triggers[trigger] = replFunc

        if isinstance(search, PatternGroup):
            for item in search:
                self.append(notes=notes, brief=brief, search=item, repl=repl, replFunc=replFunc, safe=safe, group=group, **kwargs)
            return

        if group is None:
            if isString(search):
                #  group = search
                raise RuntimeError("unexpected string for obfu search-term")
            elif isinstance(search, BitwiseMask):
                group = search
            else:
                with BitwiseMask() as bm:
                    bm.add_list(search)
                    group = bm

        if isinstance(search, BitwiseMask):
            if obfu_debug: printi("[Obfu::append] BitwiseMask: {}".format(str(brief)))
            if replFunc:
                self.append_bitwise(search=search.value, mask=search.mask, replFunc=replFunc, brief=brief, safe=safe, group=group, **kwargs)
            elif isinstance(repl, BitwiseMask):
                self.append_bitwise(search=search.value, mask=search.mask, replFunc=make_bitwise_patch(repl), brief=brief, safe=safe, group=group, **kwargs)
            else:
                printi("[Obfu::append] Don't understand replacement method for BitwiseMask {}, repl is {}, replFunc is {}".format(str(brief), type(repl), type(replFunc)))
            return

        self.add(
            Pattern(
                notes=notes,
                brief=brief,
                search=search,
                repl=repl,
                replFunc=replFunc,
                safe=safe,
                group=group,
                **kwargs
            ), **kwargs
        )

    def append_bitwise(self, search, mask, replFunc, brief='unlabeled', safe=False, group=None, **kwargs):
        #  printi("append: \"{}\", <<{}>>, <<{}>>, {}".format(brief, search, repl, replFunc))
        if str(search) in self.patternSet:
            found = _.find(self.patterns, lambda v, k, l: v.search == search)
            if found:
                printi(("Possible Obfu Duplicate Search Pattern (mask): {}\n{}".format(found.brief, search)))
                raise ObfuFailure("Duplicate search pattern")

        searchLen = len(search)
        if searchLen > self.longestPattern:
            self.longestPattern = searchLen

        self.patterns_bitwise.append(BitwisePattern(search, mask, replFunc, brief, safe, **kwargs))


    def process_replacement(self, search, repl, addressList, patternComment, addressListWithNops, addressListFull, pat=None, context=None, length=None):
        assemble = nassemble
        if obfu_debug: printi("[process_replacement] repl:{}".format(listAsHex(repl)))
        if isinstance(repl, list):
            #  printi("addressList")
            #  pp(addressList)
            if isinstance(repl[0], str):
                #  length = length or sum(_.map(repl, lambda x, *a: len(assemble(x, addressList[0]))))
                length = length or len(search)
                repl = length, repl
            else:
                printi("{:x} non-str repl:Search: {}\n                   Replace: {}\n                   Comment: {}"
                        .format(addressList[0], 
                            listAsHex(repl), 
                            ahex(repl), 
                            patternComment)) # listAsHex(search), 
                repl = (length or len(repl), repl)

        if isinstance(repl, tuple) and len(repl) == 2:
            _search, _repl = repl
            try:
                _search = list(_search)
            except TypeError as e:
                pass
                #  printi("[ignore] exception: {}: {} [_search:{}]".format(e.__class__.__name__, str(e), _search))
                #  raise

            try:
                _repl = list(_repl)
            except TypeError as e:
                printi("obfu exception: {}: {} [_repl:{}]".format(e.__class__.__name__, str(e), _repl))
                raise

            # dprint("[process_replacement] _search, _repl")
            if obfu_debug: printi("[process_replacement] tuple: _search:{}, _repl:{}".format(listAsHexIfPossible(_search), listAsHexIfPossible(_repl)))

            if -1 in _repl:
                for i in range(len(search)):
                    #  if _search[i] == -1 and _repl[i] == -1:
                        #  _repl[i] = idc.get_wide_byte(addressList[i])

                    if _search[i] == -1:
                        _search[i] = idc.get_wide_byte(addressList[i])
                    if _repl[i] == -1:
                        _repl[i] = _search[i]

            


            # TODO: we can expand this to include a bigger range, both by adding
            # the 1 octet removed by using _search[:-1] and further by checking for
            # nops ahead

            #  why was this here, it didn't work
            #  addressListWithNops = [x for x in it.takewhile(lambda x: x != _search[:-1], addressListWithNops)]
            usedRanges = []

            # we need to translate the position in addressList with the equiv. position in addressListWithNops

            if isinstance(_search, int):
                _end = _search
            else:
                _end = len(_search)

            if _end > len(addressList):
                raise IndexError("_end is greater than the length of address list")
            #  elif _end == len(addressList):
            #  printi("shortening _end by 1")
            #  _end -= 1

            try:
                _end_address = addressList[_end - 1]
            except IndexError:
                # dprint("[IndexError] _end, len(addressList)")
                printi("[IndexError] _end:{}, len(addressList):{}, _search:{}".format(_end, len(addressList), _search))
                printi("[hm] _end:{}, addressList:{}, addressListWithNops:{}".format(_end, addressList,
                                                                                    addressListWithNops))
                raise IndexError("pfft")

            _nop_end_index = addressListWithNops.index(_end_address)
            if _nop_end_index == -1:
                raise RuntimeError("couldn't match addressListWithNops to addressList")
            else:
                _nop_end_index += 1

            # dprint("[hm] _end, _nop_end_index, addressList, addressListWithNops, addressListFull")

              
            is_int3 = False

            # XXX
            usedAddresses = set()
            targetRanges = GenericRanger(addressListWithNops[0:_nop_end_index], sort=0, outsort=0)
            if isinstance(_repl, list) and isinstance(_repl[0], str) and _repl[-1] == 'int3' \
                    or \
                    isinstance(_repl, list) and isinstance(_repl[0], int) and _repl[-1] == 'cc':
                        is_int3 = True
                        if obfu_debug: printi("obfu_class: extending targetRanges... locating longest range...")
                        sortedRanges = _.sortBy(targetRanges, lambda x, *a: len(x))
                        sortedRanges.reverse()

                        for r in targetRanges:
                            if r.start == sortedRanges[0].start:
                                if obfu_debug: printi("r.last: {:x}".format(r.last))
                                # disabled because it was causing overruns into the next chunk (when there were two jmps)
                                # now attempting to curtail it by checking for end of flow
                                # that only seems to work sometimes... (flow doesn't end at 143a659cb clc)
                                # back to disabling!
                                if False and (not isFlowEnd(r.last) or isJmp(r.last) and not isFlowEnd(r.last+1)):
                                    if obfu_debug: printi("flow doesn't end at {:x} {}".format(r.last, diida(r.last)))
                                    #  if True and not isFlowEnd(r.last + 1) and isJmp(r.last + 1) and not isFlowEnd(idc.get_item_head(r.last)) isJmp(idc.get_item_head(r.last)):
                                    r.last += GetInsnLen(r.last + 1)
                                    if obfu_debug: printi("r.last (+new): {:x}".format(r.last))
                                else:
                                    if obfu_debug: printi("flow ends at {:x} {}".format(r.last, diida(r.last)))
            _targetRanges = format(targetRanges)
            if obfu_debug: printi("targetRanges: {}".format(targetRanges))

            # if obfu_debug: printi("targetRanges", targetRanges)

            if isinstance(_repl, list):
                if isinstance(_repl[0], int):
                    # dprint("[process_replacement] _repl")
                    if obfu_debug: printi("[process_replacement] _repl:{}".format(_repl))
                    
                    _repl = [(bytearray().fromhex(x[3])) for x in diInsnsIter(_repl)]
                    assemble = bytepatch
                if isinstance(_repl[0], (str, bytearray)):
                    #  for asm in _repl:
                    #  length = assemble(asm, address)
                    #  if not length:
                    #  raise ObfuFailure("assemble: " + asm)
                    #  length = len(length)
                    #  MakeCode(address)
                    # pp(targetRanges)

                    # assemble for length
                    address = targetRanges[0].start
                    test_assembled = [assemble(x, address) for x in _repl]
                    # this isn't a particualr good check
                    if not isinstance(test_assembled, (bytearray, list)):
                        if obfu_debug: printi("couldn't assemble (for length) '%s': %s" % ("; ".join(_repl), test_assembled))
                        raise ObfuFailure("assemble: {}".format(asm))
                    else:
                        if obfu_debug: printi("test_assembled (for length [{}]) '{}': {}".format(
                                        [len(x) for x in test_assembled], 
                                        "; ".join(_repl) if isinstance(_repl, str) else 'bytearray', 
                                        listAsHex(test_assembled))
                                  )
                    total_length = sum([len(x) for x in test_assembled])
                    length = total_length

                    # run the whole thing through a test
                    targetLengths = [x.length for x in targetRanges]
                    for raw, nxt in stutter_chunk(test_assembled, 2, 1):
                        length = len(raw)
                        if len(targetLengths) == 0:
                            printi("ran out of ranges to fill")
                            raise ObfuFailure("ran out of ranges to fill")
                            # get the [perhaps approximate] length of insn
                            found = _.find(lengths, lambda v, *a: v >= length)
                            if found is None:
                                raise ObfuFailure("ran out of room for {}".format(listAsHex(raw)))
                            idx = targetLengths.index(found)
                            targetLengths[idx] -= length
                            #  r.length -= length;
                            if idx > 0:
                                targetLengths = targetLengths[idx:]

                    #  printi("test assembled with remaining lengths: {}".format(targetLengths))

                    found = None
                    for asm in _repl:
                        if len(targetRanges) == 0:
                            printi("ran out of ranges to fill")
                            raise ObfuFailure("ran out of ranges to fill")
                        # get the [perhaps approximate] length of insn
                        try:
                            length = len(assemble(asm, targetRanges[0].start))
                            if found is not None and asm == "int3":
                                addr = eax(found)
                                if GetChunkNumber(addr) > 0:
                                    SetChunkEnd(addr, addr)
                                elif GetChunkNumber(addr) == 0:
                                    SetFuncEnd(addr, addr)
                                continue

                            found = _.find(targetRanges, lambda v, *a: v.length >= length)
                            if found is None:
                                #  if asm == "int3" or asm == [0xcc]:
                                    #  continue
                                raise ObfuFailure("ran out of room assembling {}".format(asm))
                            idx = targetRanges.index(found)
                            r = targetRanges[idx]
                            assembled = assemble(asm, r.start)
                            if not isinstance(assembled, list):
                                if obfu_debug: printi(("assemble failed '%s': %s" % (asm, assembled)))
                                raise ObfuFailure("assemble: {}".format(asm))
                            else:
                                if obfu_debug: printi(("assemble (0x%x) '%s': %s" % (r.start, asm, listAsHex(assembled))))
                            length = len(assembled)
                            PatchBytes(r.start, assembled, code=1, comment="{} {}".format(patternComment, _targetRanges))
                            for _addr in range(r.start, r.start + len(assembled)):
                                usedAddresses.add(_addr)

                            forceCode(r.start)
                            if not IsCode_(r.start):
                                if obfu_debug: printi("0x%x: Couldn't MakeCode" % r.start)
                            # we could also leave the generic ranges in place with
                            # modificiations to indication not to use, then erase over
                            # them later... but remember, the reason we are ejecting them
                            # is because we need to avoid out-of-order code
                            r.start += length;
                            #  r.length -= length;
                            if idx > 0:
                                usedRanges.extend(targetRanges[0:idx])
                                targetRanges = targetRanges[idx:]
                            #  no need to do this
                            #  # yes, this is safe and works. r is like an magic c++ iterator
                            #  if r.length < 1:
                            #  usedRanges = targetRanges[:1]
                            #  targetRanges = targetRanges[1:]

                            # pp(hex(targetRanges))

                        except KeyboardInterrupt:
                            raise KeyboardInterrupt()
                        #  except ValueError:
                            #  printi(("couldn't find room for '%s' in %s" % (asm, _targetRanges)))
                            #  raise ObfuFailure("assemble: {}".format(asm))

                    #  if not is_int3:
                        #  usedRanges.extend(targetRanges)
                    if obfu_debug:
                        printi("usedRanges: {}".format(pf(usedRanges)))
                    for r in usedRanges:
                        start, last, length = r.start, r.last, r.length
                        if length > 0:
                            ## ZeroCode(start, length)
                            if obfu_debug:
                                printi("usedRangesNopping: {:x}, {:x}, {}".format(start, length, patternComment))
                            PatchNops(start, length, patternComment)
                    remainingRanges = GenericRanger(usedAddresses, sort=1, outsort=0)
                    for r in difference(targetRanges, remainingRanges): # usedRanges
                        start, last, length = r.start, r.last, r.length
                        if length > 0:
                            ## ZeroCode(start, length)
                            if obfu_debug:
                                printi("remainingRangesNopping: {:x}, {:x}, {}".format(start, length, patternComment))
                            PatchNops(start, length, patternComment)
                    return True
        else:
            printi(("ProcessReplacement: Unexpected type (exected tuple): %s" % type(repl)))
            pp(repl)
        return False

    # def replace_pattern_bitwise(self, search, mask, replFunc, patternComment, addressList, ea, addressListWithNops, safe):
    def replace_pattern_bitwise(self, pat, ea, addressList, addressListWithNops, addressListFull, context=None):
            # result = self.replace_pattern_bitwise(pattern[0], pattern[1], pattern[2], pattern[3], list(addressList), ea, list(addressListWithNops), pattern[4], pattern[5])
            # result = self.replace_pattern_bitwise(pattern, ea, list(addressList), list(addressListWithNops))
        #  printi(json.dumps(searchIndex))
        search, mask, replFunc, brief = pat.search, pat.mask, pat.replFunc, pat.brief
        searchLen = len(search)
        if len(addressList) < searchLen:
            return False

        for i in range(searchLen):
            if not (Byte(addressList[i]) & mask[i] == search[i]):
                return False

        if replFunc:
            original = [idc.get_wide_byte(x) for x in addressList]
            repl = replFunc(search, search, original, ea, addressList, brief,
                            addressListWithNops=addressListWithNops, addressListFull=addressListFull)
            if repl:
                if debug: printi("Replace bitwise with {}:".format(pfh(repl)))
                # pp(repl)
                if self.process_replacement(search, repl, addressList, brief, addressListWithNops, addressListFull, pat=pat, context=context):
                    return {'addressList': addressList, 'pattern': pat}

        return False

    def replace_pattern_ex(self, search, repl, replFunc, searchIndex, patternComment, addressList, ea,
                           addressListWithNops, addressListFull, safe, pat=None, context=None):
        # inslen = MyGetInstructionLength(ea)
        # buf = GetManyBytes(ea, ItemSize(ea))
        #  printi(json.dumps(searchIndex))

        if not isInt(ea):
            raise ValueError("ea is {}".format(ea))

        if obfu_debug: printi("replace_pattern_ex")

        searchLen = len(search)
        if len(addressList) < searchLen:
            if obfu_debug: printi("addressList too short ({} < {})".format(len(addressList), searchLen))
            return False

        failed = 0
        for i in searchIndex:
            if search[i] == -1 or Byte(addressList[i]) == search[i]:
                pass
            else:
                failed = 1
                if obfu_debug:
                    printi("returning, no match at index {} (wanted: {:x} found: {:x} at {:x})".format(i, search[i], idc.get_wide_byte(addressList[i]), addressList[i]))
                    printi("search string: {}".format(listAsHex(search)))
                    printi("values       : {}".format(listAsHex([idc.get_wide_byte(addressList[i]) for i in searchIndex])))
                    if i == 12:
                        printi("12", Byte(addressList[i]), search[i])
                break

        if failed:
            return False

        # del addressList[searchLen:]
        if replFunc:
            if not isInt(ea):
                raise ValueError("ea is {}".format(ea))

            original = [idc.get_wide_byte(x) for x in addressList]

            repl = replFunc(search, repl, original, ea, addressList, patternComment,
                            addressListWithNops=addressListWithNops, addressListFull=addressListFull, pat=pat, context=context)
            if not repl:
                return False
            # printi("Replace:")
            # pp(repl)

            # 141057f05 Search|Replace (A): 21|('0x15', ['<generator object recursive_map at 0x0000021AAAFC8F48>', '<generator object recursive_map at 0x0000021AAAFC8F48>'])
            #          jmp via push rbp, xchg, lea rsp, jmp rsp-8
            if not self.quiet:
                printi("{:x} replFunc:    Search: {}\n                   Replace: {}\n                   Comment: {}"
                        .format(ea, 
                            listAsHex(search), 
                            ahex(repl), 
                            patternComment)) # listAsHex(search), 

            if self.process_replacement(search, repl, addressList, patternComment, addressListWithNops, addressListFull, length=len(search), pat=pat, context=context):
                return {'addressList': addressList, 'safe': safe}
        elif repl:
            #  printi("{:x} Search|Replace (B): {}|{}\n          {}".format(ea, listAsHex(search), ahex(repl), patternComment))
            if not self.quiet:
                printi("{:x} repl:        Search: {}\n                   Replace: {}\n                   Comment: {}"
                        .format(ea, listAsHex(search), 
                            ahex(repl), 
                            patternComment)) # listAsHex(search), 
            if self.process_replacement(search, (search, repl), addressList, patternComment,
                                        addressListWithNops, addressListFull, pat=pat, context=context):
                return {'addressList': addressList, 'safe': safe}
        elif not repl:
            printi(("0x%x: No replacement for patch %s" % (ea, patchComment)))
            return False
        else:
            printi("repl but could not process_replacement")
            return False
            #  requiredLen = len(repl)
        #
        #  if 1: # not safe:
        #  translatedAddressList = []
        #  for i in range(searchLen):
        #  translatedAddressList.append(addressList[i])
        #
        #  if obfu_debug:
        #  printi("requiredLen: %i\nsearchLen: %i" % (requiredLen, searchLen))
        #  printi(listAsHexWith0x(translatedAddressList))
        #
        #  target = BADADDR
        #  r = searchLen - requiredLen + 1
        #  if obfu_debug:
        #  printi("range: %i" % r)
        #  for i in range(r):
        #  if (addressList[i + requiredLen - 1] - addressList[i] == requiredLen - 1):
        #  target = i
        #  break
        #
        #  if obfu_debug:
        #  printi("target: %i" % target)
        #
        #  if target == BADADDR:
        #  printi("0x%x: %i contiguous bytes not found at target with addressList for %s" % (ea, requiredLen, patternComment))
        #  printi("requiredLen: %i\nsearchLen: %i" % (requiredLen, searchLen))
        #  printi(listAsHexWith0x(translatedAddressList))
        #  return False
        #
        #  if i:
        #  result = []
        #  if obfu_debug: printi("Making %i nops" % i)
        #  nopAddresses = [addressList[n] for n in range(i)]
        #  nopRanges = GenericRanger(nopAddresses)
        #  for r in nopRanges:
        #  if obfu_debug: printi("%i nops" % r.length)
        #  result += MakeNops(r.length)
        #
        #  result.extend(repl)
        #  repl = result
        #  replaceLen = len(repl)

        if obfu_debug: printi(("0x%x: %s: repl: %s" % (ea, patternComment, listAsHex(repl))))
        replaceLen = len(repl)

        #  printi("0x%x: XXX: %s [%s]" % (ea, GetDisasm(ea), patternComment))
        #  GetDisasm(ea)

        replace_locs = []
        for i in range(replaceLen):
            replace_locs.append(addressList[i])
            if idc.is_code(idc.get_full_flags(ItemHead(addressList[i]))):
                if obfu_debug: printi("[debug] MyMakeUnknown({:x}, {}, DELIT_EXPAND | DELIT_NOTRUNC".format(addressList[i],
                                                                                                      InsnLen(
                                                                                                          addressList[
                                                                                                              i])))
                MyMakeUnknown(addressList[i], InsnLen(addressList[i]), DELIT_EXPAND | DELIT_NOTRUNC)
            # SetSpDiff(addressList[i], 0)
            idaapi.patch_byte(addressList[i], repl[i])
        gr = GenericRanger(replace_locs, sort=0)
        printi("replace_locs: {}".format(pf(gr)))
        MakeCode(addressList[0])

        if obfu_debug: printi(("0x%x: Making %i comments" % (addressList[0], replaceLen)))
        commentAddresses = [addressList[n] for n in range(replaceLen)]
        commentRanges = GenericRanger(commentAddresses, sort=0, outsort=0)
        if obfu_debug: printi(("commentRanges: %s" % str(commentRanges)))
        for r in commentRanges:
            if obfu_debug: printi(("commentRange: %s" % str(r)))
            if obfu_debug: printi(("0x%x: %i comments" % (r.start, r.length)))
            lastHead = BADADDR

            for a in range(r.start, r.start + r.length):
                h = ItemHead(a)
                if h != lastHead:
                    lastHead = h
                    Commenter(ea, "line").add("[PATCH] %s" % patternComment)

        if False:
            d = {}
            for i in range(replaceLen):
                d[i] = addressList[i]

            patchAddresses = [v for k, v in list(d.items())]
            rangeLookup = {v: k for k, v in list(d.items())}
            addressRanges = GenericRanger(patchAddresses, sort=0, outsort=0)
            for r in addressRanges:
                l = []
                for i in range(r.start, r.start + r.length):
                    l.append(repl[rangeLookup[i]])
                PatchBytes(r.start, l, patternComment, code=1)
            # printi("0x%x: 0x%x: Patched %i bytes: %s for %s" % (ea, r.start, r.length, hex(l), patternComment))

            # MyMakeUnknown(addressList[i], 1, 0)

        #  Wait()
        #  Commenter(addressList[0]).add("[PATCH] %i bytes: %s" % (replaceLen, patternComment))
        #  Commenter(addressList[i], 'line').add("[PATCH] %i bytes: %s" % (replaceLen, patternComment))
        #  Wait()

        ## We can fill the unused space with 0xCC, but if there are multiple xrefs to
        ## a location within the patch, we want to be able to detect them later.
        # fillAddresses = [lambda x: addressList[x], xrange(replaceLen, searchLen)]

        Wait()
        MakeCodeAndWait(ea, comment=GetFunctionName(ea))
        #  printi("0x%x: patched %i bytes: %s" % (ea, replaceLen, patternComment))
        #  printi("0x%x: XXX: %s [%s]" % (ea, GetDisasm(ea), patternComment))
        GetDisasm(ea)
        Commenter(ea, "line").remove("[PATCH] %s" % patternComment)
        Commenter(ea, "line").add("[PATCH] %i bytes: %s" % (replaceLen, patternComment))

        # How MakeNops writes comments (no problems with these comments)
        #  PatchBytes(nopStart, MakeNops(contigCount))
        #  MyMakeUnknown(nopStart, contigCount, 0)
        #  Wait()
        #  MakeCodeAndWait(nopStart)
        #  Wait()
        #  Commenter(nopStart).add("[PATCH-NOP] %i bytes: %s" % (contigCount, patternComment))
        #  Wait()

        nopping = replaceLen
        while nopping < searchLen:
            for i in range(nopping, searchLen):
                if i == nopping:
                    contigCount = 1
                elif addressList[i] - addressList[i - 1] == 1:
                    contigCount += 1
                else:
                    break

            ## Nop contigCount bytes
            nopStart = addressList[nopping]
            nopLength = contigCount
            nopping += contigCount
            if contigCount > 0:
                ## ZeroCode(nopStart, nopLength)
                PatchNops(nopStart, nopLength, patternComment)
                Wait()
                #  MakeCodeAndWait(addressList[nopping], force = 1)
                #  Commenter(addressList[nopping], 'line').add("[PATCH-NOP] %i bytes: %s" % (contigCount, patternComment))

        Wait()
        #  self.comb(addressList[0], replaceLen)

        # return not safe
        return True

    def AnalyzeArea(self, start, end):
        self.AnalyzeQueue.append([start, end])

    def comb(self, ea, length, recursion=0, nops=False, comment="", limit=None, debugComments=False):
        if obfu_debug: printi(("0x%x: obfu::comb: length:%i" % (ea, length)))
        # Make sure all the instructions disassembled, and break up the JMPs
        fnFlags = idc.get_full_flags(ea)
        fnEnd = FindFuncEnd(ea)
        nextAny = NextNotTail(ea)
        allRefs = set(idautils.CodeRefsFrom(ea, 1))
        jmpRefs = set(idautils.CodeRefsFrom(ea, 0))
        flowRefs = allRefs - jmpRefs
        hitFnEnd = nextAny == fnEnd

        if idc.is_tail(fnFlags):
            if not MyMakeUnkn(ea, 0):
                printi(("0x%x: MyMakeUnkn: failed" % ea))
            #  Wait()
            MakeCodeAndWait(ea, force=1, comment=GetFunctionName(ea))
            fnFlags = idc.get_full_flags(ea)
        if idc.is_tail(fnFlags):
            raise ObfuFailure("0x%x: attempted to start comb on tail byte: " % ea)
        if fnEnd < BADADDR and len(flowRefs) == 1 and hitFnEnd:
            # Expand Function
            SetFunctionEnd(ea, NextNotTail(fnEnd))
            Wait()
        ip = ea
        count = 0
        addressList = []
        visited = set()
        while count < length and ip != limit:
            if idc.get_color(ip, CIC_ITEM) == 0xffffffff:
                idc.set_color(ip, CIC_ITEM, 0x113311)
                # idaapi.set_item_color(ip, 0x113311)
            flags = idc.get_full_flags(ip)
            if idc.is_unknown(flags) and idc.is_flow(flags) and MyGetInstructionLength(ip):
                MakeCodeAndWait(ip)
            #  if obfu_debug: printi("0x%x: 0x%x: obfu::comb: %i" % (ea, ip, count))

            # TODO: add these to lists where we need to maximise available bytes to write to
            if Byte(ip) == 0xcc:  # int3
                if debugComments: Commenter(ip, "line").add("[obfu::comb] int3")
                break
            insLen = MakeCodeAndWait(ip, 1, comment=GetFunctionName(ea))
            if idc.is_tail(flags) or not idc.is_code(flags):
                printi(("0x%x: comb: is tail: 0x%x" % (ea, ip)))
                insLen = MakeCodeAndWait(ip, force=1, comment=GetFunctionName(ea))
            else:
                pass

            if idc.is_tail(flags) or not idc.is_code(flags):
                #  Jump(ip)
                MyMakeUnkn(idc.prev_head(idc.next_head(ea)), 1)
                printi(("0x%x: 0x%0x: comb: still at tail, should AnalyseArea" % (ea, ip)))
                #  AnalyseArea(ip, 1)
                insLen = MakeCodeAndWait(ip, force=1, comment=GetFunctionName(ea))
                if idc.is_tail(flags) or not idc.is_code(flags):
                    MyMakeUnkn(idc.prev_head(idc.next_head(ea)), 1)
                    raise ObfuFailure("0x%x: comb: still at tail: 0x%x" % (ea, ip))
            else:
                if ip in self.visited or ip in visited:
                    if debugComments: Commenter(ip, "line").add("[obfu::comb] already visited")
                    break

            # idaapi.set_item_color(ip, 0x222222)
            Wait()
            visited.add(ip)
            # insLen = MakeCodeAndWait(ip, force = True)
            count += insLen
            if not insLen:
                printi(("0x%x: 0x%x: Couldn't make any more code... %s" % (ea, ip, GetDisasm(ip))))
                # raise ObfuFailure("Couldn't make more stuff...")
                if debugComments: Commenter(ip, "line").add("[obfu::comb] End of code")
                break

                #  while not insLen and count < 15: # and idc.next_head(ip) != NextNotTail(ip):
                #  count += 1
                #  MyMakeUnknown(ip, count, 0)
                #  Wait()
                #  insLen = MakeCodeAndWait(ip)
                #  printi("0x%x: making unknown %i bytes: 0x%x (insLen now %i)" % (ea, count, ip, insLen))

                #  if not insLen:
                #  if recursion < 5:
                #  MyMakeUnknown(ea, 1, DELIT_EXPAND | DELIT_NOTRUNC)
                #  Wait()
                #  return self.comb(ea, length, recursion + 1)
                #  printi("0x%x: Couldn't qassemble instruction at 0x%x" % (ea, ip))
                #  raise ObfuFailure("0x%x: Couldn't qassemble instruction at 0x%x" % (ea, ip))

            mnem = GetMnem(ip)
            b = Byte(ip)
            w = Word(ip)

            if b == 0xc2 or b == 0xc3 or mnem == "retn":  # retn
                #  printi("Adding %x" % b)
                addressList += list(range(ip, ip + insLen))
                if debugComments: Commenter(ip, "line").add("[obfu::comb] retn")
                break


            elif b == 0xe8 or mnem == "call":  # ff 15 xx xx xx xx
                addressList += list(range(ip, ip + insLen))
                if debugComments: Commenter(ip, "line").add("[obfu::comb] call")
                ip += insLen
                continue

            elif mnem == "jmp":  # b == 0xe9 or b == 0xeb or mnem == "jmp":
                #  addressList += range(ip, ip + insLen)
                if debugComments: Commenter(ip, "line").add("[obfu::comb] unconditional jump")
                oldIp = ip
                if b == 0xe9:
                    ip += idaapi.as_signed(Dword(ip + 1), 32) + 5
                elif b == 0xeb:
                    ip += idaapi.as_signed(Byte(ip + 1), 8) + 2
                elif b == 0xff or w >= 0xff40 and w <= 0xff4f:
                    # add a silly jump into our address list, because it's at
                    # the end of a sequence anyway, and it will be matched
                    # against certain patterns for disguising retn
                    addressList += list(range(ip, ip + insLen))
                    if debugComments: Commenter(ip, "line").add("[obfu::comb] silly jump")
                    break
                else:
                    raise ObfuFailure("0x%x: unknown jump type %02x (%s)" % (ip, b, mnem))

                if flags == 0:
                    if debugComments: Commenter(oldIp, "line").add("[obfu::comb] invalid jump")
                    break
                continue

            elif mnem == 'nop' or w == 0x9066:  # 0x9066 is `xchg ax, ax` a 2 byte nop
                if nops: addressList += list(range(ip, ip + insLen))
                ip += insLen
                continue

            addressList += list(range(ip, ip + insLen))
            ip += insLen
            continue
            # count += insLen
            # ip += insLen

            allRefs = set(idautils.CodeRefsFrom(ip, 1))
            jmpRefs = set(idautils.CodeRefsFrom(ip, 0))
            flowRefs = allRefs - jmpRefs

            if not len(allRefs):
                if debugComments: Commenter(ip, "line").add("[obfu::comb] end of all flow")
                break
            if not len(flowRefs):
                ip = list(jmpRefs)[0]
                if idc.get_full_flags(ip) == 0:
                    if debugComments: Commenter(ip, "line").add("[obfu::comb] Invalid Jump")
                    break
            else:
                ip = list(flowRefs)[0]

        if obfu_debug: printi(("0x%x: 0x%x: obfu::comb::end: %i" % (ea, ip, count)))
        return addressList

    def combEx(self, ea, length=20000, callsAsJumps=False,
               includeCode=True, includeNops=False, includeJumps=False,
               oneChunk=False, unpatch=False,
               removeEmptyChunks=False, fromChunkHead=False,
               fromFuncHead=False):
        instructions = []
        addresses = []
        nopset = set()
        jmps = set()
        jccs = []
        visited = set()
        if fromChunkHead:
            ea = GetChunkStart(ea)
        if fromFuncHead:
            ea = GetFuncStart(ea)
        nextIp = ip = ea
        size = 0
        chunkStart = ip
        chunkEnd = 0
        chunkRef = 0
        chunkInstructions = 0
        while length > 0:
            if size > 0 and nextIp != ip + size and oneChunk:
                break
            ip = nextIp
            if ip in visited:
                break

            if unpatch:
                pb = ip
                while ida_bytes.get_original_qword(pb) != Qword(pb):
                    UnPatch(pb, pb + 4)
                    pb += 4

            i = idautils.DecodeInstruction(ip)
            if i is None:
                break

            size = i.size
            # length -= size
            d = de(ip)
            if d:
                de_flags = self._makeFlagFromDi(de(ip)[0])
            else:
                de_flags = 0

            visited.add((ip, size, de_flags))

            if not size:
                printi(("0x%x: 0x%0x: combEx: couldn't decode instruction" % (ea, ip)))
                raise ObfuFailure("0x%x: comb: still at tail: 0x%x" % (ea, ip))

            nextIp = ip + size
            instructions.append((ip, size, de_flags))
            for x in range(size):
                addresses.append(ip + x)

            if i.itype in (idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni, idaapi.NN_jmpshort):
                if i.Op1.type == o_near:
                    target = i.Op1.addr
                    if target and target != BADADDR:
                        jmps.add((ip, size, de_flags))
                        nextIp = target
                        _end = _start = 0
                        if idc.get_fchunk_attr(ip, FUNCATTR_END) == ip + size:
                            #  printi("At chunk end: {:x}".format(ip))
                            chunkEnd = ip + size
                            _end = 1
                        if idc.get_fchunk_attr(target, FUNCATTR_START) == target:
                            if removeEmptyChunks and _end and chunkInstructions == 0 and chunkRef and chunkStart and GetInsLen(
                                    chunkRef) == 5:
                                printi(
                                    "Will jump to chunk start: {:x} from chunk end: {:x} having counted {} instructions".format(
                                        target, ip, chunkInstructions))
                            #  else:
                            #  printi("Will jump to chunk start: {:x}".format(target))
                            _start = 1
                            if removeEmptyChunks and _end and not chunkInstructions and chunkRef and chunkStart and GetInsLen(
                                    chunkRef) == 5:
                                qassemble('jmp {:x}h'.format(target), chunkRef, apply=1)
                                # remove_fchunk(ea, chunkStart)
                                printi("Removed chunk {:x}-{:x}, patched {:x}".format(chunkStart, chunkEnd, chunkRef))
                            else:
                                # don't advance chunkRef now, we might hit another empty chunk
                                pass
                            chunkRef = ip
                            chunkStart = target
                            chunkInstructions = 0

                else:
                    break

            if callsAsJumps and i.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                if i.Op1.type == o_near:
                    target = i.Op1.addr
                    if target and target != BADADDR:
                        jmps.add((ip, size, de_flags))

            if i.itype in (idaapi.NN_ja, idaapi.NN_jae, idaapi.NN_jb, idaapi.NN_jbe, idaapi.NN_jc, idaapi.NN_jcxz,
                           idaapi.NN_jecxz, idaapi.NN_jrcxz, idaapi.NN_je, idaapi.NN_jg, idaapi.NN_jge, idaapi.NN_jl,
                           idaapi.NN_jle,
                           idaapi.NN_jna, idaapi.NN_jnae, idaapi.NN_jnb, idaapi.NN_jnbe, idaapi.NN_jnc, idaapi.NN_jne,
                           idaapi.NN_jng,
                           idaapi.NN_jnge, idaapi.NN_jnl, idaapi.NN_jnle, idaapi.NN_jno, idaapi.NN_jnp, idaapi.NN_jns,
                           idaapi.NN_jnz,
                           idaapi.NN_jo, idaapi.NN_jp, idaapi.NN_jpe, idaapi.NN_jpo, idaapi.NN_js, idaapi.NN_jz):
                if i.Op1.type == o_near:
                    target = i.Op1.addr
                    if target and target != BADADDR:
                        jccs.append((ip, size, target))


            elif i.itype in (idaapi.NN_retn, idaapi.NN_int, idaapi.NN_int3):
                break
            elif i.itype == idaapi.NN_nop or Word(ip) == 0x9066:
                nopset.add((ip, size, de_flags))
            else:
                length -= size
                chunkInstructions += 1

        jmps = jmps.intersection(visited)
        if includeCode:
            if includeNops and not includeJumps:
                clean = [x for x in instructions if x not in jmps]
            elif not includeNops and not includeJumps:
                clean = [x for x in instructions if x not in nopset and x not in jmps]
            elif includeJumps and not includeNops:
                clean = [x for x in instructions if x not in nopset]
            elif includeJumps and includeNops:
                clean = [x for x in instructions]
            else:
                printf("Unknown combination of includeNops and includeJumps")
        else:
            if includeJumps and not includeNops:
                clean = [x for x in instructions if x in jmps]
            else:
                printf("Unknown combination of includeNops and includeJumps")

        jccs_unvisited = [x for x in jccs if x[0:2] not in visited]
        addresses = []
        for x, y, f in clean:
            for z in range(y):
                addresses.append(x + z)

        flaggedAddresses = []
        for x, y, f in instructions:
            for z in range(y):
                flaggedAddresses.append((x + z, f))

        return addresses, clean, instructions, nopset, jmps, jccs_unvisited, flaggedAddresses

    def trigger(self, ea, name, **kwargs):
        if name in self.triggers:
            return self.triggers[name](ea=ea, **kwargs, trigger=True)

    def _patch(self, ea, length=None, context=None, depth=0):
        self._depth = depth
        self.prep_groups()
        # check_for_update()
        if length is None:
            length = self.default_comb_len
        if not isInt(ea):
            raise ValueError("ea is {}".format(ea))

        # obfu_read_patches()
        #  if obfu_debug: printi("0x%x: obfu::_patch" % (ea))
        self.start = ea
        # colorise_xor(idaapi.cmd)

        comb_results_all = None

        tmp = [x[0] for x in self.combed]
        index = _.indexOf(tmp, ea)
        if -1 < index < self.default_comb_len - 150:
            # if obfu_debug: printi("[_patch] cached: {:x} ({} < {})".format(ea, index, len(tmp)))
            index = _.indexOf(tmp, ea)
            comb_results_all = self.combed[index:]
        else:
            if obfu_debug: printi("[_patch] {:x} recombing ({} < {})".format(ea, index, len(tmp)))
            self.combed = self.combEx(ea, length)[6]
            comb_results_all = self.combed[:]

        comb_results_nops = [x for x in comb_results_all if x[1] & 8 == 0]
        comb_results = [x for x in comb_results_nops if x[1] & 128 == 0]

        addressList = [x[0] for x in comb_results]  # self.longestPattern)
        #  addressListWithNops = self.combEx(ea, length, includeNops=True)[0]
        #  addressListFull = self.combEx(ea, length, includeNops=True, includeJumps=True)[0]
        addressListWithNops = [x[0] for x in comb_results_nops]
        addressListFull = [x[0] for x in comb_results_all]

        #  return 0
        count = 0
        results = []
        matched = []
        for pattern in self.patterns_bitwise:
            # self.patterns_bitwise.append([search, mask, replFunc, notes, safe])
            # result = self.replace_pattern_bitwise(pattern[0], pattern[1], pattern[2], pattern[3], list(addressList), ea, list(addressListWithNops), pattern[4], pattern[5])
            result = self.replace_pattern_bitwise(pattern, ea, list(addressList), list(addressListWithNops), list(addressListFull))
            if result:
                Wait()
                matched.append(pattern.brief)
                self.combed.clear()
                count += 1
                if obfu_debug: printi("found bitwise pattern")
                #  Jump(ea)
                return PatternResult(pattern, result)

        searches = 0
        groups_matched = 0

        if obfu_debug: printi("[_patch] {:x}".format(ea))


        addrLen = len(addressList)
        for group in self.groups:
            if count:
                break
            if addrLen < len(group):
                #  if obfu_debug: printi("{}: addrLen < len(group)".format(group.pattern))
                continue
            if not group.match_addresses(addressList):
                #  if obfu_debug: printi("{}: not group.match_addresses".format(group.pattern))
                continue

            groups_matched += 1
            if obfu_debug: printi("[Obfu::_patch] group:    {} group._size: {}".format(group, group._size))
            for pat in _.sortBy(self.groups[group], 'priority'):
                if obfu_debug: printi("[Obfu::_patch] checking: {}".format(pat.brief))
                searches += 1

                q = [pat]
                results = []
                while q and not count:
                    pat = q.pop(0)
                    if obfu_debug: printi("len(addressList): {}".format(addrLen))
                    if obfu_debug: printi("addressList: {}".format(hex(addressList)))

                    result = self.replace_pattern_ex(tuple(pat.search), tuple(pat.repl), pat.replFunc, pat.searchIndex, pat.brief,
                                                     list(addressList), ea, list(addressListWithNops), list(addressListFull), pat.safe, pat=pat, context=context)
                    if result:
                        count += 1
                        if obfu_debug:
                            printi("result! count: {}".format(count))
                        self.combed.clear()
                        results.append(PatternResult(pat, result))
                        matched.append(pat)
                        then = getattr(pat.options, 'then', None)
                        if not then:
                            break
                        _q = []
                        for p in asList(then):
                            if not p in self.labels:
                                printi("[_patch] then-label '{}' not found in {})".format(p, self.labels.keys()))
                                break
                            for nextpat in self.labels[p]:
                                #  printi("[_patch] then-label '{}' found in {})".format(p, self.labels.keys()))
                                _q.append(nextpat)
                        if _q:
                            q.extend(_.sortBy(_q, 'priority'))
                    
                if count:
                    self.combed.clear()
                    return results
                    #  Jump(ea)
                # only perform 1 matching pattern
                # TODO: relax this if all patterns were marked 'resume'
                #  break  # continue
                # continue

                        # forceAsCode(ea, len(pattern[0]))
                        # end = ea + len(pattern[0])
                        # forceAsCode(ea, end - ea)
                        # AnalyzeArea(ea, end)
                        # while ea < end and idc.is_code(idc.get_full_flags(ea)):
                        # ea = idc.next_head(ea)
                        # if Byte(ea) == 0xcc and not idc.is_code(idc.get_full_flags(ea)):
                        # hideRepeatedBytes(ea)
                        # forceAsCode(start, ea - start, hard = 1)
                        # return 1
        if obfu_debug and (searches or groups_matched):
            printi("searches: {} groups_matched: {}".format(searches, groups_matched));
            printi("matched: {}".format([x.brief for x in matched]));

        if results:
            self.combed.clear()
        return results

    def get_next_instruction(self):
        eip = self.eip
        end = self.end
        while eip <= end:
            if obfu_debug: printi(("0x%x: obfu::get_next_instruction" % ea))

            yield [eip, self._patch(eip)]
            # self.eip += ItemSize(self.eip)
            while 1:
                eip = NextNotTail(eip)
                break
                if idc.is_code(idc.get_full_flags(eip)) or eip >= end: break
