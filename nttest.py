# r = read_emu_glob('ArxanChecksumActual3_422')
# r = read_emu_glob('CheckFunc_143a54309')
# r = read_emu_glob('CheckFunc_143dbd576')
# execfile('nttest')
# s = _.map(r, lambda v, *a: GenericRange(v[0], length=v[1][1]))
# [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s, lambda v, *a: v.start)];
# [idc.set_color(x.start, idc.CIC_ITEM, 0x280128) for x in _.sortBy(s, lambda v, *a: v.start)];
# s2 = [asList(split_chunks(x.start, x.trend)) for x in s]
# s3 = []
# for x in s2: s3.extend(x)
# s4 = _.map(s3, lambda v, *a: GenericRange(v[0], trend=v[1])) 
# [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s4, lambda v, *a: v.start)];
# [idc.set_color(x.start, idc.CIC_ITEM, 0x200100) for x in _.sortBy(s4, lambda v, *a: v.start)];
# t = [AdvanceInsnList(x) for x in s4]
# j = find_joins(t)
# k = assemble_joined(j)
# b = ["\n".join(_.pluck(x, 'labeled_indented')) for x in k]
# clear(); print("\n----\n".join(b))
#
# [EaseCode(x, forceStart=1) for x in t if not IsCode_(x.ea)]
# EaseCode([x.ea for x in t if len(x)==0], forceStart=1, noExcept=1)

import os
from exectools import make_refresh
refresh_nttest = make_refresh(os.path.abspath(__file__))


def find_joins(t, joined=None, unjoined=None):
    joined = A(joined)
    unjoined = A(unjoined)
    for x in t:
        x.next = set()
        x.prev = set()
    # lut = _.mapObject(t, lambda v, *a: (v.ea, v))
    lut = {}
    for v in t:
        if v.range():
            for ea in range(v.range().start, v.range().stop):
                lut[ea] = v
    # t[0].range().start

    def prepend_to(after, before):
        joined.append(before.ea)
        joined.append(after.ea)
        before.next.add(after)
        after.prev.add(before)
        before.addChild(after)

        if after in unjoined:
            unjoined.remove(after)
        if before in unjoined:
            unjoined.remove(before)
        # print("{:x} -> {:x}".format(before.ea, after.ea))

    failed = []
    setglobal('failed', failed)
    for chunk in t:
        if chunk._list_insns:
            #  target = chunk.target
            for target in chunk.targets:
                if target in lut:
                    prepend_to(lut[target], chunk)
                elif target and target != BADADDR:
                    print("chunk {:x} target not in lut: {:#x} {}".format(chunk.ea or 0, target or 0, ean(target) ))
                    failed.append(chunk)
                #  targets = chunk.targets
                #  print("len(targets) for {:x}: {}".format(chunk.ea, len(targets)))
                #  for target in targets:
                    #  if target in lut:
                        #  print("prepend_to({:x}, {:x})".format(lut[target].ea, chunk.ea))
                        #  prepend_to(lut[target], chunk)
                        #  break

    # return [x for x in t if not getattr(x, 'prev', None) and getattr(x, 'next', None)] # + failed
    return [x for x in t if not x.getParents() and x.getChildren()]

def assemble_joined(l, visited=None):
    if visited is None: visited = set()
    out = []
    for x in l:
        out.append(asList(x.join(visited)))
        # out.append("\n".join(_.pluck(result, 'labeled_indented')))
    return out

#  _ease = 0
#  _chunks = [x for x in idautils.Chunks(eax('very_chunked_function'))]
#  chunks = GenericRanger([GenericRange(x[0], trend=x[1])           for x in _chunks],            sort = 1)
#  s = chunks
def emujoin(r, color1=0x280128, color2=0x1F1D00):
    """
    color2 alt 0x001f00
    """
    _conditional_allins = list(range(ida_allins.NN_ja, ida_allins.NN_jz + 1))
    _jump_allins = _conditional_allins + [ida_allins.NN_jmp]
    _ease = 1
    _nofuncs = 1
    f = _.filter(r, lambda v, *a: v[1][1])
    s = _.map(f, lambda v, *a: GenericRange(v[0], length=v[1][1]))
    m = _.mapObject(f, lambda v, *a: (GenericRange(v[0], length=v[1][1]), v[1][2]))
    if _ease: 
        print("easecode #1")
        if _nofuncs:
            [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s, lambda v, *a: v.start) if not IsFunc_(x)];
        else:
            [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s, lambda v, *a: v.start)];
    print("finding micro-chunks")
    p = ProgressBar(len(s))
    p.always_print = False
    s2 = []
    # s2 = _.uniq([list(split_chunks(x[0], x[-1])) for x in s if len(x)])
    for i, x in enumerate(s):
        p.update(i)
        if len(x):
            # print("big chunk: {} {:#x} - {:#x}".format(len(x), x[0], x[-1]))
            s2.extend(list(split_chunks(x[0], x[-1])))
    print("sorting micro-chunks")
    s2.sort()
    print("uniqing micro-chunks")
    s3 = _.uniq(s2, 1)
    s4 = _.map(s3, lambda v, *a: GenericRange(v[0], trend=v[1])) 
    if _ease:
        print("easecode #2")
        if _nofuncs:
            [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s4, lambda v, *a: v.start) if not IsFunc_(x)];
        else:
            [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s4, lambda v, *a: v.start)];
        c = [(a.start, a.trend) for a in _.sortBy(s4, lambda v, *a: v.start)]
        print("coloring #1")
        for x in s:
            for y in idautils.Heads(x.start, x.trend):
                idc.set_color(y, idc.CIC_ITEM, color1)
        print("coloring #2")
        for start, tu in r:
            if tu[2]:
                for ea in idautils.Heads(start, start + tu[1]):
                    idc.set_color(ea, idc.CIC_ITEM, color2)

        #  for a, b in c:
            #  for ea in idautils.Heads(a, b):
                #  for x, y in m.items():
                    #  if ea in x:
                        #  if y:
                            #  idc.set_color(ea, idc.CIC_ITEM, 0x1F1D00)
                        #  break
        #  [idc.set_color(x.start, idc.CIC_ITEM, 0x1F1D00) for x in _.sortBy(s4, lambda v, *a: v.start)];
    print("advance insn list")
    t = [AdvanceInsnList(x) for x in s4]
    print("finding joins")
    joined = []
    j = find_joins(t, joined)
    setglobal('j', j)
    setglobal('t', t)
    print("assembling joins")
    visited = set()
    k = assemble_joined(j, visited)
    #  print("visited: {}".format(hex(visited)))
    print("prepping output")
    c = []
    results = []
    #  s = []
    for xx in _.reverse(_.sortBy(k, lambda v, *a: len(v))):
        #  s.append(_.first(xx)[0].ea)
        #  if xx:
            #  s.append(xx[0].ea)
        #  c.append("{}, {}".format(len(x.getParents()), len(x.getChildren())))
        for i, x in enumerate(xx):
            _pdata = ''
            if get_pdata_fnStart(x.ea) == x.ea:
                _pdata = ' <pdata>'
            # dprint("[emujoin] x.ea, _pdata")
            #  print("[emujoin] x.ea:{}, _pdata:{}".format(hex(x.ea), _pdata))
            
            if IsValidEA(GetTarget(x.ea)):
                add_xrefs(x.ea)

            if not i:
                results.append(x)
                c.append(x.force_labeled_value.replace(': ', _pdata + ':\n    '))
            else:
                c.append(x.labeled_indented.replace(': ', _pdata + ':\n    '))
        if c[-1] != "---":
            c.append("---")

    c.append("---unjoined---")

    uj = [x for x in t if x not in joined and not x.getChildren() and not x.getParents()]
    for xx in uj:
        #  s.append(_.first(xx))
        for i, x in enumerate(xx):
            if x.ea not in visited:
                visited.add(x.ea)
                if not i:
                    c.append(x.force_labeled_value.replace(': ', ':\n    '))
                else:
                    c.append(x.labeled_indented.replace(': ', ':\n    '))
        if c[-1] != "---":
            c.append("---")

    #  b = ["\n".join(_.pluck(x, 'labeled_indented')) for x in _.reverse(_.sortBy(k, lambda v, *a: len(v)))]
    #  clear(); print("\n----\n".join(b))
    # clear(); 
    print("\n".join(c))
    return results + [x[0] for x in f if IsCode_(x[0])]

def chunkjoin():
    global t
    global s
    global s2
    global s3
    global s4
    global j
    global uj
    global k
    global c
    ea = GetFuncStart(EA())
    _ease = 1
    s = _.map(idautils.Chunks(ea), lambda v, *a: GenericRange(v[0], trend=v[1]+1))
    if _ease: 
        print("easecode #1")
        [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s, lambda v, *a: v.start)];
        print("coloring #1")
        [idc.set_color(x.start, idc.CIC_ITEM, 0x280128) for x in _.sortBy(s, lambda v, *a: v.start)];
    print("finding micro-chunks")
    s2 = [list(split_chunks(x[0], x[-1])) for x in s if len(x)]
    s3 = []
    for x in s2: s3.extend(x)
    s4 = _.map(s3, lambda v, *a: GenericRange(v[0], trend=v[1]+1)) 
    if _ease:
        print("easecode #2")
        [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s4, lambda v, *a: v.start)];
        print("coloring #2")
        [idc.set_color(x.start, idc.CIC_ITEM, 0x200100) for x in _.sortBy(s4, lambda v, *a: v.start)];
    print("advance insn list")
    t = [AdvanceInsnList(x) for x in s4]
    print("finding joins")
    joined = []
    j = find_joins(t, joined, uj)
    print("finding unjoined")
    uj = [x for x in t if not x.getChildren() and not x.getParents()]
    print("assembling joins")
    k = assemble_joined(j)
    print("prepping output")
    c = []
    s = []
    for xx in _.reverse(_.sortBy(k, lambda v, *a: len(v))):
        #  s.append(_.first(xx)[0].ea)
        if xx:
            s.append(xx[0].ea)
        for i, x in enumerate(xx):
            if not i:
                c.append(x.force_labeled_value.replace(': ', ':\n    '))
            else:
                c.append(x.labeled_indented.replace(': ', ':\n    '))
        #  c.append("---")

    #  c.append("---unjoined---")
#  
    #  for xx in uj:
        #  #  s.append(_.first(xx))
        #  for i, x in enumerate(xx):
            #  if not i:
                #  c.append(x.force_labeled_value.replace(': ', ':\n    '))
            #  else:
                #  c.append(x.labeled_indented.replace(': ', ':\n    '))
        #  c.append("---")

    clear(); print("\n".join(c))

def nreg1(ea):
    return insn_mmatch(ea, [(idaapi.NN_lea, (idc.o_reg, 2), (idc.o_mem, 5)), (idaapi.NN_mov, (idc.o_reg, 1), (idc.o_imm, 0)), (idaapi.NN_jmp, (idc.o_near, 0))])

def nreg2(ea):
    return insn_mmatch(ea, [(idaapi.NN_call, (idc.o_near, 0)), (idaapi.NN_nop, (idc.o_void, 0), (idc.o_void, 0)), (idaapi.NN_jmp, (idc.o_near, 0))]) or \
            insn_mmatch(ea, [(idaapi.NN_mov, (idc.o_displ, 4), (idc.o_reg, 5)), (idaapi.NN_lea, (idc.o_reg, 4), (idc.o_displ, 4)), (idaapi.NN_lea, (idc.o_reg, 5), (idc.o_mem, 5)), (idaapi.NN_jmp, (idc.o_near, 0))]) or \
            insn_mmatch(ea, [(idaapi.NN_mov, (idc.o_phrase, 4), (idc.o_reg, 5)), (idaapi.NN_lea, (idc.o_reg, 5), (idc.o_mem, 5)), (idaapi.NN_xchg, (idc.o_reg, 5), (idc.o_phrase, 4)), (idaapi.NN_jmp, (idc.o_near, 0))])

def nreg_start(ea):
    return insn_mmatch(ea, [(idaapi.NN_sub, (idc.o_reg, 4), (idc.o_imm, 0)), (idaapi.NN_lea, (idc.o_reg, 2), (idc.o_mem, 5)), (idaapi.NN_mov, (idc.o_reg, 1), (idc.o_imm, 0)), (idaapi.NN_jmp, (idc.o_near, 0))])

def nreg_jmp(ea):
    return insn_mmatch(ea, [(idaapi.NN_jmp, (idc.o_near, 0))])

def nreg_tail1(ea):
    return insn_mmatch(ea, [(idaapi.NN_lea, (idc.o_reg, 2), (idc.o_mem, 5)), (idaapi.NN_mov, (idc.o_reg, 1), (idc.o_imm, 0)), (idaapi.NN_add, (idc.o_reg, 4), (idc.o_imm, 0))]) or \
            insn_mmatch(ea, [(idaapi.NN_lea, (idc.o_reg, 4), (idc.o_displ, 4)), (idaapi.NN_lea, (idc.o_reg, 5), (idc.o_mem, 5)), (idaapi.NN_xchg, (idc.o_reg, 5), (idc.o_phrase, 4)), (idaapi.NN_lea, (idc.o_reg, 4), (idc.o_displ, 4)), (idaapi.NN_jmp, (idc.o_near, 0))]) or \
            insn_mmatch(ea, [(idaapi.NN_lea, (idc.o_reg, 5), (idc.o_mem, 5)), (idaapi.NN_xchg, (idc.o_reg, 5), (idc.o_phrase, 4)), (idaapi.NN_lea, (idc.o_reg, 4), (idc.o_displ, 4)), (idaapi.NN_jmpni, (idc.o_displ, 4))]) or\
            insn_mmatch(ea, [(idaapi.NN_mov, (idc.o_reg, 1), (idc.o_imm, 0)), (idaapi.NN_add, (idc.o_reg, 4), (idc.o_imm, 0))])


#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 14), (idc.o_mem, 5), comment='mov r14, [rel qword_14278B698]')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 5), (idc.o_imm, 0), comment='mov rbp, loc_14389EB8B')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 1), (idc.o_mem, 5), comment='mov ecx, [rel dword_141E4CCD8]')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 1), (idc.o_mem, 5), comment='mov ecx, [rel dword_141E4CCD8]')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 1), (idc.o_mem, 5), comment='mov ecx, [rel dword_141E4CCD8]')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 5), (idc.o_imm, 0), comment='mov rbp, loc_1433ACD6D')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 3), (idc.o_imm, 0), comment='mov rbx, loc_14106883D')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 1), (idc.o_imm, 0), comment='mov rcx, loc_141067FBF')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 5), (idc.o_imm, 0), comment='mov rbp, loc_141067FCF')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 3), (idc.o_imm, 0), comment='mov rbx, loc_141068853')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 5), (idc.o_imm, 0), comment='mov rbp, loc_141068CF2')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 0), (idc.o_imm, 0), comment='mov rax, loc_1413BA246')
#  insn_match(ea, idaapi.NN_mov, (idc.o_reg, 0), (idc.o_mem, 5), comment='mov eax, [rel dword_142D1F7B8]')
