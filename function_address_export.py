from idc import *
import idautils, os, sys, re
from collections import defaultdict

from exectools import make_refresh
refresh_function_address_export = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
funclist = dict()

def byteify(input):
    """
    Turns JSON data into ASCII
    """
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def save():
    try:
        with open('e:\\git\\pokey\\bin\\QuickRelease\\functions.json', 'w') as f:
            json.dump(funclist, f)
        #  with open('e:\\git\\pokey\\bin\\QuickRelease\\names.json', 'w') as f:
            #  json.dump(_.zipObject([(y, x-ida_ida.cvar.inf.min_ea) for x, y in Names()]), f)
    except IOError:
        print("file not writable or some such")

def save_uc():
    json_save_functions()
    try:
        with open(os.path.join(os.path.dirname(GetIdbPath()), os.path.splitext(os.path.basename(GetIdbPath()))[0] + '.funcs.json'), 'w') as f:
            json.dump(funclist, f)
        with open(os.path.join(os.path.dirname(GetIdbPath()), os.path.splitext(os.path.basename(GetIdbPath()))[0] + '.names.json'), 'w') as f:
            json.dump(_.zipObject([(y, x-ida_ida.cvar.inf.min_ea) for x, y in Names() if HasUserName(x)]), f)
    except IOError:
        print("file not writable or some such")


def under14pair(p):
    return [x - ida_ida.cvar.inf.min_ea for x in p]


def my_add_func(ea, chunks):
    fnName = idc.get_func_name(ea)
    funclist[fnName] = [under14pair(x) for x in chunks]


def get_enum_front_back(enum):
    for i, value in enumerate(enum):
        if i == 0:
            front = value
        back = value
    return (front, back)

def node_format(ea):
    if isinstance(ea, int):
        if HasUserName(ea):
            return idc.get_name(ea, idc.calc_gtn_flags(ea, ea))
        return hex(ea).replace('0x', '')
    return ea

def trim_func_tails(funcea):
    functionName = idc.get_func_name(funcea)
    chunkheads = dict()
    chunkends = dict()
    chunkcallers = defaultdict(list)
    chunktails = defaultdict(list)
    chunktargets = defaultdict(list)
    chunklabels = dict()
    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    start = idc.get_func_name(functionName)
    q = [start]
    _chunks = [x for x in idautils.Chunks(funcea)]
    for (startea, endea) in _chunks:
        heads = []
        for head in idautils.Heads(startea, endea):
            heads.append(head)
        tail = heads[-1]
        target = GetTarget(tail)
        #  tail_insn = diida(tail)
        chunk_label = "{}\\n{} insns".format(node_format(startea), len(heads))
        if startea == funcea:
            chunk_label += "\\n{} chunks".format(len(_chunks))
        chunklabels[str(startea)] = chunk_label
        graph.append('"{}" [ label="{}" style="filled" ];'.format(node_format(startea), chunk_label))
        if not isJmp(tail):
            mnem = idc.print_insn_mnem(tail)
            print('tail', node_format(startea), diida(tail), node_format(target))
            graph.append('"{0}" -> "{1}" [ headlabel=" {2} " taillabel=" {2} " labelfontcolor="#8f2020" labelfontname="Roboto" fillcolor="0.2 0.4 1" style=solid ];'.format(node_format(startea), node_format(target), mnem))
            graph.append('"{}" [ fillcolor="0.2 0.4 1" style="filled" ];'.format(node_format(startea)))
        else: 
            graph.append('"{}" -> "{}";'.format(node_format(startea), node_format(target)))
            graph.append('"{}" [ fillcolor="#eeeeee" style="filled" ];'.format(node_format(startea)))
        chunkheads[startea] = heads
        chunktails[startea].append(tail)
        chunktargets[startea].append(target)
        chunkcallers[target].append(startea)



    # now starting with the start of the function...
    refs = dict()
    ordered = list()
    #  while len(q):
    for start in q:
        #  start = q.pop()
        if start not in chunkheads:
            print("%x not in chunkheads" % start)
            continue
        heads = chunkheads.pop(start)
        cstart = heads[0]
        append_later = list()
        for head in heads:
            # TODO: this look very dangerous if the head doesn't end on a jmp 
            mnem = idc.print_insn_mnem(head)
            if isAnyJmp(head):
                target = GetTarget(head)
                if target != cstart:
                    if isConditionalJmp(head):
                        append_later.append(target)
                        graph.append('"{}" -> "{}" [ taillabel=" {} "labelfontname="Roboto" fillcolor="0.2 0.4 1" color="#2222aa" ];'.format(node_format(cstart), node_format(target), mnem))
                    else:
                        q.append(target)
                        graph.append('"{}" -> "{}";'.format(node_format(cstart), node_format(target)))
            if IsRef(head):
                refs[head] = idc.get_name(head)
            
        q.extend(append_later)
        ordered.extend(heads)

    print('any chunks left?', len(chunkheads))
    pp([hex(x) for x in chunkheads])

    graph.sort()
    graph = _.uniq(graph)
    global __DOT
    dot = __DOT.replace('%%MEAT%%', '\n'.join(graph))
    dot_draw(dot, name = idc.get_name(funcea, ida_name.GN_VISIBLE))
    
    disasm = [dinjasm(x) for x in ordered]

    # now we have `ordered` which is a list of addresses, and
    # `disasm` which is a list of instructions.  we need to match
    # the local refs with local labels, leaving the nonheadtargets (to
    # this function) refs alone.

    label_number = 1
    labels = []
    disasm2 = []
    output = []

    def out(line):
        print(line)
        output.append(line)

    def make_label(address):
        #  global labels
        #  global ordered
        if address in ordered:
            labels.append(address)
            return "label_%d" % len(labels)
        return "0x%x" % address

    for insn in disasm:
        disasm2.append(re.sub(r'(0x[0-9a-fA-F]{7,})', lambda x: make_label(int(x.group(1), 16)), insn))

    # now lets put it all together
    l = len(disasm2) - 1
    for n, insn in enumerate(disasm2):
        if n < l and ordered[n + 1] in refs:
            # a label is about to hit
            label = refs[ordered[n + 1]]
            if insn == 'jmp %s' % label:
                continue
        if ordered[n] in refs:
            out("%s:" % refs[ordered[n]])
            if 0:
                for k, address in enumerate(labels):
                    if address == ordered[n]:
                        label = "label_%d" % (k + 1)
                        out("%s:" % label)
        if insn != 'nop':
            out('    ' + insn)

    file_put_contents('function.asm', '\n'.join(output))
    print("NasmFromFile(0x%x, 'function.asm')" % funcea)


    if 0:
        disasm = list()
        for x in ordered:
            if x in refs:
                disasm.append(refs[x])
            d = diida(x)
            if d == 'nop':
                pass
            else:
                disasm.append('    ' + d)
        
def get_func_heads_chunk_order(funcea, tailCheck=None):
    functionName = idc.get_func_name(funcea)
    chunkheads = dict()
    chunkends = dict()
    chunkcallers = defaultdict(list)
    chunktails = defaultdict(list)
    chunktargets = defaultdict(list)
    chunklabels = dict()
    # The first chunk will be the start of the function, from there -- they're sorted in 
    # order of location, not order of execution.
    #
    # Lets gather them all up first, then untangle them
    start = idc.get_name_ea_simple(functionName)
    q = [start]
    graph = []
    _chunks = asList(Chunks(funcea))
    for (startea, endea) in _chunks:
        heads = []
        for head in Heads(startea, endea):
            heads.append(head)
        tail = heads[-1]
        target = GetTarget(tail)
        #  tail_insn = diida(tail)
        if not isJmp(tail) and not isRet(tail):
            mnem = idc.print_insn_mnem(tail)
            if tailCheck is not None:
                tailCheck.append(tail)
            print('tail', node_format(startea), diida(tail), node_format(target))

        chunkheads[startea] = heads
        chunktails[startea].append(tail)
        chunktargets[startea].append(target)
        chunkcallers[target].append(startea)

    if tailCheck is not None:
        return len(tailCheck) == 0


    # now starting with the start of the function...
    refs = dict()
    ordered = list()
    nonheadtargets = set()
    #  while len(q):
    for start in q:
        #  start = q.pop()
        if start not in chunkheads:
            print("%x not in chunkheads" % start)
            nonheadtargets.add(start)
            continue
        heads = chunkheads.pop(start)
        cstart = heads[0]
        append_later = list()
        for head in heads:
            # TODO: this look very dangerous if the head doesn't end on a jmp 
            mnem = idc.print_insn_mnem(head)
            if isAnyJmp(head):
                target = GetTarget(head)
                if target != cstart:
                    if isConditionalJmp(head):
                        append_later.append(target)
                    else:
                        q.append(target)
            if IsRef(head):
                refs[head] = idc.get_name(head)
            
        q.extend(append_later)
        ordered.extend(heads)

    if chunkheads:
        print('[warn] chunks left: {}', len(chunkheads))

    disasm = [dinjasm(x) for x in ordered]

    # now we have `ordered` which is a list of addresses, and
    # `disasm` which is a list of instructions.  we need to match
    # the local refs with local labels, leaving the nonheadtargets (to
    # this function) refs alone.

    label_number = 1
    labels = []
    disasm2 = []
    output = []

    def out(line):
        print(line)
        output.append(line)

    def make_label(address):
        #  global labels
        #  global ordered
        if address in ordered:
            labels.append(address)
            return "label_%d" % len(labels)
        return "0x%x" % address

    for insn in disasm:
        disasm2.append(re.sub(r'(0x[0-9a-fA-F]{7,})', lambda x: make_label(int(x.group(1), 16)), insn))

    # now lets put it all together
    l = len(disasm2) - 1
    for n, insn in enumerate(disasm2):
        if n < l and ordered[n + 1] in refs:
            # a label is about to hit
            label = refs[ordered[n + 1]]
            if insn == 'jmp %s' % label:
                continue
        if ordered[n] in refs:
            out("%s:" % refs[ordered[n]])
            if 0:
                for k, address in enumerate(labels):
                    if address == ordered[n]:
                        label = "label_%d" % (k + 1)
                        out("%s:" % label)
        if insn != 'nop':
            out('    ' + insn)

    out('    ; non-chunkhead targets: {}'.format([hex(x) for x in nonheadtargets]))

    file_put_contents('function.asm', '\n'.join(output))
    print("NasmFromFile(0x%x, 'function.asm')" % funcea)


    if 0:
        disasm = list()
        for x in ordered:
            if x in refs:
                disasm.append(refs[x])
            d = diida(x)
            if d == 'nop':
                pass
            else:
                disasm.append('    ' + d)
        


    
def json_save_names(fn = 'e:\\git\\pokey\\bin\\QuickRelease\\names.json'):
    skip = 0
    numLocs = len(list(idautils.Names()))
    count = 0
    lastPercent = 0

    for x in Segments():
        #  if SegName(x) != ".text": continue

        for ea, fnName in idautils.Names():
            count = count + 1

            #  if not HasName(ea): continue
            #  fnName = idc.get_name(ea, ida_name.GN_VISIBLE)
            ## need to re-run from 0 to getNearestPlayerToEntity
            #  if fnName == "getNearestPlayerToEntity":
            if fnName == "networkEarnFromJob":
                skip = 0
            if skip:
                #  print("skipping: %s" % fnName)
                continue
            #  chunks = list(idautils.Chunks(ea))

            funclist[fnName] = ea - ida_ida.cvar.inf.min_ea;
            
            percent = (100 * count) // numLocs
            # if percent > lastPercent:
            # print("%i%%" % percent)
            if percent > lastPercent:
                lastPercent = percent
                print("0x%0x: %s (%i%%)" % (ea, fnName, percent))

    json_save_safe(fn, funclist)


def json_save_functions():
    skip = 0
    numLocs = len(list(idautils.Functions()))
    count = 0
    lastPercent = 0

    for x in Segments():
        if SegName(x) != ".text":
            continue

        for ea in idautils.Functions(): # idc.get_segm_attr(x, SEGATTR_START), idc.get_segm_attr(x, SEGATTR_END)):
            count = count + 1
            if GetMnem(ea) == "jmp" and GetFuncSize(ea) > 5:
                SetFunctionEnd(ea, idc.next_head(ea))
                continue

            #  if not HasName(ea): continue
            fnName = idc.get_func_name(ea)
            ## need to re-run from 0 to getNearestPlayerToEntity
            #  if fnName == "getNearestPlayerToEntity":
            if fnName == "networkEarnFromJob":
                skip = 0
            if skip:
                #  print("skipping: %s" % fnName)
                continue
            chunks = list(idautils.Chunks(ea))

            my_add_func(ea, chunks)
            
            percent = (100 * count) // numLocs
            # if percent > lastPercent:
            # print("%i%%" % percent)
            if percent > lastPercent:
                lastPercent = percent
                print("0x%0x: %s (%i%%)" % (ea, fnName, percent))


print("json_save_functions()")
print("save()")
print("json_save_names()")
