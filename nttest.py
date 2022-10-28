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

def find_joins(t, joined=[]):
    for x in t:
        x.next = set()
        x.prev = set()
    lut = _.mapObject(t, lambda v, *a: (v.ea, v))

    def prepend_to(after, before):
        joined.append(before)
        before.next.add(after)
        after.prev.add(before)
        # print("{:x} -> {:x}".format(before.ea, after.ea))

    failed = []
    for chunk in lut.values():
        if chunk._list_insns:
            target = chunk.target
            if target in lut:
                prepend_to(lut[target], chunk)
            else:
                print("chunk {:x} target not in lut: {:x}".format(chunk.ea or 0, target or 0 ))
                failed.append(chunk)
            #  targets = chunk.targets
            #  print("len(targets) for {:x}: {}".format(chunk.ea, len(targets)))
            #  for target in targets:
                #  if target in lut:
                    #  print("prepend_to({:x}, {:x})".format(lut[target].ea, chunk.ea))
                    #  prepend_to(lut[target], chunk)
                    #  break

    return [x for x in t if not getattr(x, 'prev', None)] # + failed

def assemble_joined(l, visited=set()):
    out = []
    for x in l:
        out.append(asList(x.join(visited)))
        # out.append("\n".join(_.pluck(result, 'labeled_indented')))
    return out

#  _ease = 0
#  _chunks = [x for x in idautils.Chunks(eax('very_chunked_function'))]
#  chunks = GenericRanger([GenericRange(x[0], trend=x[1])           for x in _chunks],            sort = 1)
#  s = chunks
def emujoin(r):
    _ease = 1
    s = _.map(r, lambda v, *a: GenericRange(v[0], length=v[1][1]))
    if _ease: 
        print("easecode #1")
        [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s, lambda v, *a: v.start)];
        print("coloring #1")
        [idc.set_color(x.start, idc.CIC_ITEM, 0x280128) for x in _.sortBy(s, lambda v, *a: v.start)];
    print("finding micro-chunks")
    s2 = [list(split_chunks(x[0], x[-1])) for x in s if len(x)]
    s3 = []
    for x in s2: s3.extend(x)
    s4 = _.map(s3, lambda v, *a: GenericRange(v[0], trend=v[1])) 
    if _ease:
        print("easecode #2")
        [EaseCode(x.start, x.trend, forceStart=1, noExcept=1, verbose=0) for x in _.sortBy(s4, lambda v, *a: v.start)];
        print("coloring #2")
        [idc.set_color(x.start, idc.CIC_ITEM, 0x200100) for x in _.sortBy(s4, lambda v, *a: v.start)];
    print("advance insn list")
    t = [AdvanceInsnList(x) for x in s4]
    print("finding joins")
    joined = []
    j = find_joins(t, joined)
    print("finding unjoined")
    uj = [x for x in t if x not in j]
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
            _pdata = ''
            if get_pdata_fnStart(x.ea) == x.ea:
                _pdata = ' <pdata>'
            # dprint("[emujoin] x.ea, _pdata")
            #  print("[emujoin] x.ea:{}, _pdata:{}".format(hex(x.ea), _pdata))
            
            if not i:
                c.append(x.force_labeled_value.replace(': ', _pdata + ':\n    '))
            else:
                c.append(x.labeled_indented.replace(': ', _pdata + ':\n    '))
        c.append("---")

    c.append("---unjoined---")

    for xx in uj:
        #  s.append(_.first(xx))
        for i, x in enumerate(xx):
            if not i:
                c.append(x.force_labeled_value.replace(': ', ':\n    '))
            else:
                c.append(x.labeled_indented.replace(': ', ':\n    '))
        c.append("---")

    #  b = ["\n".join(_.pluck(x, 'labeled_indented')) for x in _.reverse(_.sortBy(k, lambda v, *a: len(v)))]
    #  clear(); print("\n----\n".join(b))
    # clear(); 
    print("\n".join(c))

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
    j = find_joins(t, joined)
    print("finding unjoined")
    uj = [x for x in t if x not in joined]
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
