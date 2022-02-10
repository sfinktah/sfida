# For making a quick copy of a function
# func_tails(ea, dict)
# for k, v in dict.items():
#     ida_bytes.patch_bytes(int(k), v)
#     forceCode(int(k), len(v))

#  from execfile import make_refresh
import os
import re
import ida_funcs, idc, ida_bytes, idautils
from collections import defaultdict
from collections import deque

if not idc:
    from idb.idapython import idautils
    from di import diida
    from execfile import make_refresh
    from function_address_export import node_format
    from helpers import UnPatch
    from python3.idc_bc695 import GetFunctionName
    from sfcommon import GetFuncStart, forceCode
    from sfida.sf_is_flags import IsFlow
    from sfida.sf_string_between import string_between
    from sftools import eax
    from slowtrace_helpers import GetInsnLen, isConditionalJmp, isAnyJmp, GetTarget, isNop, isRet, isCall, GetChunkOwners, CreateInsns
    from underscoretest import _

refresh_func_tails = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
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
        if hasattr(self, 'to'):
            return self.to.__str__()

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

    def __init__(self, chunk_ea, tail_ea = None):
        self.ea = chunk_ea   
        self.tail_ea = tail_ea
    
class FuncTailsAdditionalChunkOwners(FuncTailsError):
    def __init__(self, chunk_ea, owners):
        self.ea     = chunk_ea
        self.owners = owners

class FuncTailsInvalidTarget(FuncTailsError):
    def __init__(self, ea):
        self.ea     = ea

class FuncTailsNoFunc(FuncTailsError):
    def __init__(self, ea):
        self.ea     = ea




    
def func_tails(funcea=None, returnErrorObjects=False, returnOutput=False,
        code=True, patches=None, dead=False, showNops=False, output=None,
        quiet=False, removeLabels=True, disasm=False, externalTargets=None,
        returnAddrs=False, extra_args=dict()):
    """
    func_tails

    @param funcea: any address in the function
    @param dead: dead code removal
    """
    #  check_for_update()
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return [FuncTailsNoFunc(funcea)] if returnErrorObjects else ["[error] nofunc"]
    else:
        funcea = func.start_ea

    errors = []
    errorl = []
    decompiled = []
    decompiled_heads = defaultdict(list)

    def out(line, head=None):
        if head:
            decompiled_heads[head].append(line)
        else:
            if not quiet:
                print(line)
            if isinstance(decompiled, list):
                decompiled.append(line)

        l = string_between('; [', '', line)
        if l and output:
            output.append("[" + l)

        return line

    def remove_labels(decompiled):
        labels = []
        if isinstance(decompiled, list):
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
                        tmp = tmp.replace('    jmp ' + loc + '\n' + loc + ':\n', '') # re.sub(loc, 'JMP REMOVED', tmp)
                    if len(v) > 1:
                        tmp = tmp.replace('    jmp ' + loc + '\n' + loc + ':', loc + ':')

            decompiled = tmp.split('\n')
            return decompiled

    if not quiet:
        print("\nFuncTails: 0x{:x} ({})".format(funcea, GetFuncName(funcea)))

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
     |  endEA
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

    class Block(object):

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
                print("[func_tails::Block::__init__] Hmmm, {:x} not in chunkheads_perm".format(self.id))
            #  self.successors = [get_cached(x, _chunkheads) for x in [chunkheads_perm[y] for y in chunkrefs_from[self.id]]]
            #  self.predecessors = [get_cached(x, _chunkheads) for x in [chunkheads_perm[y] for y in chunkrefs_to[self.id]]]

        def succs(self, found_bbs = []):
            # dprint("[debug] self.id, chunkrefs_from[self.id]")
            #  print("[debug] self.id:{}, chunkrefs_from[self.id]:{}".format(self.id, chunkrefs_to[self.id]))
            
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
                    print("[func::tails::Block::succs] unknown heads: {}".format(hex(w)))
            except KeyError as e:
                # dprint("[type(e.args)] ")
                print("[func::tails::Block::succs] No such key 0x{:x}".format(e.args[0]))

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
            print("Function {} starting at 0x{:x} consists of {} chunks".format(idc.get_func_name(funcea), funcea, len(blocks)))
                
        start_bb = get_start_bb(blocks)
        return dfs_bbs(start_bb, [])



    def get_start_bb(blocks):
        for bb in blocks:
            if bb.start_ea == funcea:
                return bb


    def dfs_bbs(start_bb, found_bbs=[]):
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
                    #  print("next == 1")
                    q.append(_next.pop())
                elif len(_next) > 1:
                    #  print("next == {}".format(len(_next)))
                    for i, n in enumerate(_next): 
                        br = dfs_bbs_2(n, found_bbs, found_bbs[:])
                        # dprint("[bfs_bbs] br")
                        #  print("[bfs_bbs] br:{}".format(hex([x.id for x in br]))
                        
                        if br:
                            for ea in br:
                                if ea.id not in chunkheads_perm:
                                    print("[func_tails::bfs_bbs] {:x} not in chunkheads_perm".format(ea.id))
                                else:
                                    q.append(ea)
            else:
                print("[func_tails::bfs_bbs] bfs_bbs ignoring: {:x}".format(current_bb.id))   
        return found_bbs


    def format_bb(bb):
        return "start_ea: 0x{:x}  end_ea: 0x{:x}  last_insn: {}".format(bb.start_ea, bb.end_ea, GetDisasm(bb.end_ea))

    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    _chunks = list(split_chunks(idautils.Chunks(funcea)))
    start = funcea
    q = [start]
    for (startea, endea) in _chunks:
        # EaseCode(startea)
        if disasm:
            [GetDisasm(startea)]
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

            if isAnyJmp(head):
                target = GetTarget(head)
                ctarget = OurGetChunkStart(target, _chunks)
                jump_info = [head, idc.print_insn_mnem(head), GetTarget(head)]
                #  print("[func_tails:debug] isAnyJmp(0x{:x}) jump_info: {}".format(head, hex(jump_info)))
                if isConditionalJmp(head):
                    #  print("[func_tails:debug] isConditionalJmp(0x{:x})".format(head))
                    conditional_jumps.append(jump_info)
                    #  chunkrefs_to[startea].append(ctarget)
                    #  chunkrefs_from[ctarget].append(startea)
                else:
                    #  print("[func_tails:debug] not isConditionalJmp(0x{:x})".format(head))
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
                errorl.append(FuncTailsNoppedChunk(startea))

            if isInterrupt(tail) and not extra_args.get('ignoreInt', None):
                badtails.append('    ; [error] badtail {} {} {}'.format(node_format(startea), diida(tail), node_format(target)))
                chunkheads_badtails[startea] = True
                errorl.append(FuncTailsBadTail(startea, tail))

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

    # dprint("[debug] conditional_jumps")
    #  print("[debug] conditional_jumps:{}".format(conditional_jumps))
    
    if 'debug' in globals() and globals()['debug']:
        # dprint("[debug] chunktails, chunkrefs_to, chunkrefs_from")
        print(re.sub(r"\b[0-9]{8,}\b", lambda x, *a: hex(x.group(0)), "[debug] chunktails:{}, chunkrefs_to:{}, chunkrefs_from:{}".format(
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
                #  print("q skipping visited chunkhead {:x}".format(start))
                continue
            if start in chunkheads_bad:
                print("[func_tails::format_bb] q shouldn't try to jump to chunkheads_bad")
                continue
            print("[func_tails::format_bb] %x not in chunkheads" % start)
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
            mnem = idc.print_insn_mnem(head)

            if IsRef(head):
                #  print("added ref to head {:x}".format(head))
                refs[head] = idc.get_name(head)
                r = xrefs_to_ex(head)
                for ref in [x for x in r if not IsSameFunc(funcea, x.frm) and x.frm_seg == '.text' \
                        and string_between('', ' ', x.frm_insn).startswith('j') \
                        and not string_between('', ' ', x.frm_insn).startswith('jmp') \
                        and GetInsnLen(x.frm) > 4
                        ]:

                    ejmp = False
                    with Commenter(head, 'line') as c:
                        if c.match("\[ALLOW EJMP]"): 
                            ejmp = True
                    if not ejmp and GetTarget(ref.frm) == head:
                        cmt = '    ; [error] 0x{:x} external reference from {} 0x{:x}: {}'.format(head, GetFuncName(ref.frm), ref.frm, ref.frm_insn)
                        comments[head].append(cmt)
                        errors.append(cmt)

            
            if head in chunkowners and chunkowners[head]:
                comment = '    ; [warn] additional chunk owner(s) {} for chunk at {:x}'.format(hex(chunkowners[head]), head)
                # fix_dualowned_chunk(head)
                badtails.append(comment)
                errorl.append(FuncTailsAdditionalChunkOwners(head, chunkowners[head]))
                comments[head].append(comment)

            if isCall(head):
                _externalTargets.append(SkipJumps(head))
            if isJmpOrCall(head):
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
                    errorl.append(FuncTailsInvalidTarget(head))
                    errors.append(msg)

                elif ctarget in chunkheads or ctarget in chunkheads_visited:
                    # dprint("[debug] GetChunkStart(head), ctarget")
                    #  print("[debug] GetChunkStart(head):{:x}, ctarget:{:x}".format(GetChunkStart(head), ctarget))
                    
                    _cs = OurGetChunkStart(head, _chunks)
                    chunkrefs_to[_cs].append(ctarget)
                    chunkrefs_from[ctarget].append(_cs)

                    # if ctarget != cstart:
                    if isConditionalJmp(head):
                        #  append_later.append(ctarget)
                        #  append_later.append(ctarget)
                        q.append(ctarget)
                        if debug: print("{:x} appending later {} {:x}".format(head, mnem, ctarget))
                        #  badjumps.append([head, ctarget])
                    else:
                        q.insert(0, ctarget)
                        if debug: print("{:x} appending {} {:x}".format(head, mnem, ctarget))
                        #  badjumps.append([head, ctarget])

                else:
                    _externalTargets.append(SkipJumps(head))
                    if not ejmp:
                        if conditional:
                            if target != idc.BADADDR:
                                if not IsFunc_(target):
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    errorl.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                elif not IsFuncHead(target):
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    errorl.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                else:
                                    msg = '[error] {}: external conditional jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    errorl.append(FuncTailsJump(True, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                            # print("{:x} appending later {} {:x} to function {} {:x}".format(head, mnem, target, get_name_by_any(head), idc.get_func_name(target), GetFuncStart(target)))
                            # q.append(ctarget)
                        if not conditional and not iscall:
                            if target != idc.BADADDR:
                                if IsExtern(target):
                                    msg = '[info] {}: external jump to extern {}'.format(get_name_by_any(head), describe_target(target))
                                    comments[head].append((msg))
                                elif not IsFunc_(target):
                                    msg = '[error] {}: external jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    errorl.append(FuncTailsJump(False, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                elif not IsFuncHead(target):
                                    msg = '[error] {}: external jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    errorl.append(FuncTailsJump(False, head, describe_target(target)))
                                    comments[head].append((msg))
                                    errors.append(msg)
                                else:
                                    msg = '[info] {}: external jump to {}'.format(get_name_by_any(head), describe_target(target))
                                    comments[head].append((msg))
                                    #  errors.append(msg)
                            #  print("{:x} appending {} {:x} to function {} {:x}".format(head, mnem, target, idc.get_func_name(target), GetFuncStart(target)))
                            #  q.append(ctarget)

            
        #  print("finished last head for chunk {:x}, qlen: {}".format(cstart, len(q)))
        #  print("adding heads to ordered: {}".format(hex(heads)))
        ordered.extend(heads)
        if not len(q) and append_later:
            q.extend(append_later)

    disasm = []
    for ea in ordered:
        mnemonics.append(MyGetMnem(ea))
        if ea in comments:
            disasm.append({'insn': diida(ea), 'ea': ea,
                           'comment': comments[ea]})

        else:
            disasm.append({'insn': diida(ea), 'ea': ea})
#
    #  disasm = [dinjasm(x) for x in ordered]

    # now we have `ordered` which is a list of addresses, and
    # `disasm` which is a list of instructions.  we need to match
    # the local refs with local labels, leaving the {}: external (to
    # this function) refs alone.

    # now lets put it all together
    l = len(disasm) - 1
    for n, o in enumerate(disasm):
        insn = o['insn']
        head = o['ea']
        comments = o.get('comment', '')

        _chunkhead = OurGetChunkStart(head, _chunks)
        #  _chunkhead = None
        #  for chead, caddresses in chunkheads_perm.items():
            #  if head in caddresses:
                #  _chunkhead = head
                #  break

        if n < l and ordered[n + 1] in refs:
            # a label is about to hit
            label = refs[ordered[n + 1]]
            if 0 and insn == 'jmp %s' % label and not ordered[n] in refs:
                continue
        if ordered[n] in refs:
            out("%s:" % refs[ordered[n]], _chunkhead)
        if showNops or not insn.startswith('nop'):
            fmt_insn   = '    {}'.format(insn)
            if comments:
                insn_width = len(fmt_insn)
                comment = ' ; ' + comments.pop(0)
                out(fmt_insn + comment, _chunkhead)
                for c in comments:
                    comment = ' ; ' + c
                    out(' ' * insn_width + comment, _chunkhead)
            else:
                out(fmt_insn, _chunkhead)




    #  pp(decompiled_heads)
    #  if 'retn' not in mnemonics and mnemonics[-1] != 'jmp':
        #  out('    ; [error] noret')

    # fn = file_put_contents('function.asm', '\n'.join(errors))
    # print("NasmFromFile(0x{:x}, {!r})".format(funcea, os.path.abspath(fn)))

    #  refresh_func_tails()

    #  print('\n'.join([x for x in decompiled if x]))
    #  for k in _.sort(_.keys(decompiled_heads)):
        #  for line in decompiled_heads[k]:
            #  print(line)
    chunkheads = chunkheads_perm.copy()
    chunkheads_visited = dict()
    bb = print_basic_blocks_dfs_bfs()
    d = []
    addrs = []
    for x in bb:
        start, end = x, OurGetChunkEnd(x, _chunks)
        for ip in idautils.Heads(start, end):
            d = de(ip)
            if d:
                de_flags = obfu._makeFlagFromDi(de(ip)[0])
            else:
                de_flags = 0
            addrs.extend( [(y, de_flags) for y in range(ip, ip + InsnLen(ip))] )

        for line in decompiled_heads[x]:
            d.append(line)
            decompiled.append(line)

        if x in chunkheads:
            #  print("bb 0x{:x} in chunkheads".format(x))
            chunkheads_visited[x] = chunkheads.pop(x)
        #  else:
            #  if x in chunkheads_visited:
                #  print("bb 0x{:x} in chunkheads_visited".format(x))
            #  else:
                #  print("bb 0x{:x} not in chunkheads or chunkheads_visited".format(x))

    decompiled = remove_labels(decompiled) if removeLabels else decompiled
    if not quiet:
        for line in decompiled:
            print(line)

    for bt in badtails:
        errors.append(out(bt))
    for bj in badjumps:
        src, dst = bj
        if dst == idc.BADADDR:
            errors.append(out("    ; bad jmp {:x} {:x}".format(src, dst)))
            target = GetTarget(src)
            # dprint("[debug] target")
            #  print("[debug] target:{:x}".format(target))
            
            while isNop(target):
                if UnPatch(target, GetInsnLen(target)):
                    target += GetInsnLen(target)
                    #  print("[debug] target:{:x}".format(target))
                else:
                    break
                # dprint("[debug] target")

    if chunkheads:
        chunkheads = _.filter(chunkheads, lambda x, *a: not isInterrupt(x))

    if chunkheads:
        errors.append(
                out('    ; [warn] unusedchunks {} {}'.format(len(chunkheads), asHexList(chunkheads)))
        )
        errorl.extend([FuncTailsUnusedChunk(x) for x in chunkheads])
    if nonheadtargets:
        errors.append(
            out('    ; [info] non-chunkhead targets: {}'.format([hex(x) for x in nonheadtargets]))
        )
    #  try:
        #  for head, heads in chunkheads.items():
            #  out('    ; [bb] {:x} unusedchunk: {}'.format(head, hex(heads)))
            #  #  RemoveThisChunk(head)
    #  except TypeError:
        #  print("TypeError iterating chunkheads.items(): {}".format(chunkheads))
        #  raise TypeError("see above")

    try:
        if isinstance(output, list):
            output[:] = decompiled
    except TypeError:
        print("[func_tails] decompiled was {} ({})".format(decompiled, type(decompiled)))
    #  if not errors:
    if isinstance(externalTargets, set):
        externalTargets.update(_externalTargets)
    elif isinstance(externalTargets, list):
        externalTargets.extend(_externalTargets)
    if returnAddrs:
        return addrs
    if returnOutput:
        if debug: print("[format_bb] returning output")
        return "\n".join(decompiled)
    return errorl if returnErrorObjects else errors
