from __future__ import print_function
import re
import timeit
import flare_emu
import itertools
from braceexpand import braceexpand
from collections import defaultdict
from exectools import make_refresh
from attrdict1 import SimpleAttrDict
import pickle
import ida_dbg

refresh_emu = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
base = ida_ida.cvar.inf.min_ea

# ddir = getglobal('ddir', string_between('\\', '\\', GetIdbDir(), rightmost=1))
ddir = getglobal('ddir', idautils.GetIdbDir())
if not dir_exists(os.path.join(ddir, 'memcpy')):
    os.mkdir(os.path.join(ddir, 'memcpy'))
if not dir_exists(os.path.join(ddir, 'written')):
    os.mkdir(os.path.join(ddir, 'written'))
if not dir_exists(os.path.join(ddir, 'read')):
    os.mkdir(os.path.join(ddir, 'read'))

max_count = count = last_count = last_memcpy = last_written = last_read = 0
functions = set()
called_functions = defaultdict(int)
called_functions_short = defaultdict(int)
last_function = ''
last_called_function = ''
abort = 0
written_set = set()
read_set = set()

checked_by = globals().get('checked_by', defaultdict(set))
emu_output = globals().get('emu_output', [])
healed_by = globals().get('healed_by', defaultdict(set))
memcpy = globals().get('memcpy', dict())
natives = globals().get('natives', dict())
reshow_regs = globals().get('reshow_regs', [])
show_regs = globals().get('show_regs', False)
single_step = globals().get('single_step', 0)
step_output = globals().get('step_output', [])
transposition = globals().get('transposition', dict())
visited = set()
skip = False

writtento = set()
after_output = []
call_stack = list()
last_regs = dict()
readfrom = set()
reshow_bits = dict()
initialFnName = ''
register_lut = dict()
sp_writes = []


def str_startswith(s, prefixlist, icase=False, start=None, end=None):
    if icase:
        s = s.lower()
    for st in prefixlist:
        if icase:
            st = st.lower()
        if s.startswith(st, start, end):
            return True
    return False


def emu_pickle():
    pass
    # file_put_contents_bin('e:/git/ida/memcpy.pickle', pickle.dumps(memcpy))
    # file_put_contents_bin('e:/git/ida/read_set.pickle', pickle.dumps(read_set))
    # file_put_contents_bin('e:/git/ida/checked_by.pickle', pickle.dumps(checked_by))
    # file_put_contents_bin('e:/git/ida/healed_by.pickle', pickle.dumps(healed_by))
    # file_put_contents('e:/git/ida/emu_output.txt', '\n'.join(emu_output))
    # file_put_contents('e:/git/ida/step_output.txt', '\n'.join(step_output))


def out(s, silent=0):
    emu_output.append(s)
    if not silent:
        print(s)
    return


def after(s, silent=0):
    global after_output
    if not silent:
        after_output.append(s)


def show_after():
    global after_output
    for s in after_output:
        out(s)
    after_output.clear()


def stepout(s):
    step_output.append(s)
    print(s)
    return


def xor_range(key, start, end):
    start = eax(start)
    end = eax(end)
    if end == BADADDR:
        return
    while start < end:
        dw = idc.get_wide_dword(start)
        dw ^= key
        idc.patch_dword(start, dw)
        start += 4


def braceexpandlist(be):
    return list(braceexpand(be))


def make_reg_list():
    # @static: reglist
    if 'reglist' not in make_reg_list.__dict__:
        br64 = "r{{a,c,d,b}x,{s,b}p,{s,d}i,{8..15}}"
        br32 = "{e{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}d}"
        br16 = "{{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}w}"
        br8 = "{{{a,c,d,b}l,{s,b}pl,{s,d}il},r{8..15}b,{a,c,d,b}h}"

        make_reg_list.reglist = SimpleAttrDict({
            'r64': braceexpandlist(br64),  # 16
            'r32': braceexpandlist(br32),  # 16
            'r16': braceexpandlist(br16),  # 16
            'r8': braceexpandlist(br8)})  # 20

    return make_reg_list.reglist


regnames = _.flatten(list(make_reg_list().values()))
rbits = _.flatten(list(make_reg_list().values()))


def reshow_add(reg):
    global reshow_regs
    global reshow_bits

    if reg not in rbits:
        print('{} not in rbits'.format(reg))
        return
    if reg not in reshow_regs:
        i = rbits.index(reg)
        if i > -1:
            lsb = i & 0xf
            msb = i >> 4
            #  print('reshow reg:{} lsb:{:x} msb:{:x}'.format(reg, lsb, msb))
            if lsb in reshow_bits:
                if msb < reshow_bits[lsb]:
                    _remove = rbits[lsb | (reshow_bits[lsb] << 4)]
                    if _remove in reshow_regs:
                        reshow_regs.remove(_remove)
                    else:
                        print('{} not in reshow_regs'.format(_remove))

            reshow_bits[lsb] = msb
            reshow_regs.append(reg)

        else:
            print("couldn't find {} in rbits".format(reg))


def find_all_regs(s):
    # @static: pattern
    if 'pattern' not in find_all_regs.__dict__:
        find_all_regs.pattern = re.compile( \
            r"(\[)?\b(" + \
            '|'.join(_.flatten(list(make_reg_list().values()))) + \
            r")\b(?(1)(])|)")

    m = re.findall(find_all_regs.pattern, s)
    if m:
        return _.uniq(_.map(m, lambda v, *a: _.reduce(v, lambda memo, v, *a: memo + v.strip(' []'), '')))
    return []


if "helper" not in globals():
    out("constructing helper")
    emu_helper = flare_emu.EmuHelper()
else:
    out("using existing helper")


# .text:00000001438DD3AA 0A8 48 8B 45 58                     mov     rax, [rbp+80h+vortex]
# .text:00000001438DD3AE 0A8 0F B6 00                        movzx   eax, byte ptr [rax]
# .text:00000001438C2F43 0B8 48 8B 45 48                     mov     rax, [rbp+90h+vortex]
# .text:00000001438C2F47 0B8 8B 00                           mov     eax, [rax]


def checkForVortex(unicornObject, address, instructionSize, userData):
    ea = address
    mnem = IdaGetMnem(ea)  # 'mov'
    op1 = idc.print_operand(ea, 0)  # 'rax'
    op2 = idc.print_operand(ea, 1)  # '[rbp+80h+vortex]'
    # 'movzx', 'eax', 'byte ptr [rax]'
    insn = "{} {}, {}".format(mnem, op1, op2).rstrip(', ')
    if re.match(r'mov rax, \[rbp.*]', insn):
        return 1
    elif re.match(r'mov\w* eax, (byte ptr )?\[rax]', insn):
        return 2
    else:
        return 0


def match_reg_by_val(reg, val):
    global register_lut
    global transposition
    r = register_lut.get(val, '')
    if r and r != transposition[reg]:
        transposition[reg] = r
        return "{} = {}".format(reg, r)
    elif r and r == reg:
        return "original value"
    return ''


def insnHook(unicornObject, address, instructionSize, userData):
    global abort
    global after_output
    global call_stack;
    global called_functions
    global count
    global functions
    global last_count
    global last_function
    global last_memcpy
    global last_read
    global last_regs
    global last_written
    global memcpy
    global reshow_regs
    global single_step
    global visited

    # if "breakpoints" not in userData:
    #     userData['breakpoints'] = set([0x14022232b])  # 2b
    #  if address in userData["breakpoints"]:
        #  out("{:x} Breakpoint!".format(address))
        #  userData["EmuHelper"].stopEmulation(userData)

    if abort:
        userData["EmuHelper"].stopEmulation(userData)

    visited.add(address)

    fnName = GetFuncName(address) or hex(address)
    fnName = string_between('_$', '', fnName, inclusive=1, repl='')
    if single_step:
        isFunc = IsFunc_(address)
        if isFunc:
            if fnName != last_function:
                stepout("; === {} ===".format(fnName))
            last_function = fnName
            if fnName not in functions:
                functions.add(fnName)
                # out("function: {} ({})".format(fnName, len(functions)))
                if len(functions) > 500:
                    out("aborting")
                    userData["EmuHelper"].stopEmulation(userData)

    if ida_dbg.exist_bpt(address):
        out("; === BREAKPOINT AT 0x{:x} ===".format(address))
        userData["EmuHelper"].stopEmulation(userData)
        return

    count += 1
    if count - last_count > 299999:
        if os.path.exists(scriptDir + '/stop'):
            userData["EmuHelper"].stopEmulation(userData)
            # raise Exception("insnHook: abort due to presence of /stop")
            abort = 1
            return
        memcpy_count = sum([len(x) for x in memcpy.values()])
        out("{}... in {} ({}) at {:x} (memcpy:{} read_set:{} written_set:{})".format(count, fnName, called_functions[fnName], address,
                                                                     memcpy_count, len(read_set), len(written_set)))
        if False and len(written_set) - last_written < 256 and memcpy_count - last_memcpy < 128:
            print("aborting (written_set < 256 and memcpy < 128)")
            userData["EmuHelper"].stopEmulation(userData)
        #  if memcpy_count - last_memcpy < 128:
            #  print("aborting (memcpy < 128)")
            #  userData["EmuHelper"].stopEmulation(userData)
        if False and len(read_set) - last_read < 256:
            print("aborting (read_set < 256)")
            userData["EmuHelper"].stopEmulation(userData)

        last_count = count
        last_memcpy = memcpy_count
        last_read = len(read_set)
        last_written = len(written_set)
    #  if count > 1000000:
        #  single_step = 1
    #  if single_step and count > 1001000:
        #  single_step = 0

    #  helper = userData["EmuHelper"]
    #  uc = helper.uc
    #  ah = helper.analysisHelper
    if single_step:
        fnNameLower = fnName.lower()

        if 'ArxanMemcpy' in fnName or 'ArxanChecksumWorker' in fnName:
            pass
        else:
            #  if fnName:
            #  stepout("{}:".format(fnName))
            try:
                #  insn = diida(address)
                insn = GetDisasm(address)
            except IndexError:
                insn = "** INVALID **"
            helper = userData["EmuHelper"]
            # dprint("[debug] regs")
            #  print("[debug] reshow_regs:{}".format(reshow_regs))
            if show_regs:
                for reg in reshow_regs:
                    # helper.getEmuPtr()
                    try:
                        val = helper.getRegVal(reg)
                    except KeyError:
                        continue
                    if reg not in last_regs:
                        last_regs[reg] = val
                    if last_regs[reg] != val:
                        stepout("               {:>4}={:x} {}".format(reg, val, match_reg_by_val(reg, val)))
                        last_regs[reg] = val
                        reshow_regs.remove(reg)
                # regs = [x for x in find_all_regs(insn) if x[0] != '[' and x != 'rsp']
                regs = [x for x in find_all_regs(insn) if x != 'rsp']
                # _.without(find_all_regs(insn), 'rsp')
                # dprint("[debug] regs")
                #  print("[debug] regs:{}".format(regs))

                #  reshow_regs = []
                for reg in regs:
                    reshow_add(reg)
                    # helper.getEmuPtr()
                    #  try:
                    #  val = helper.getRegVal(reg)
                    #  reshow_regs.append(reg)
                    #  except KeyError:
                    #  continue
                    #  stepout("               {:3} {:16x} {}".format(reg, val, match_reg_by_val(reg, val)))
            extra = ''
            reg = string_between(', ', '', string_between(';', '', insn, inclusive=1, repl=''))
            if reg in regnames:
                try:
                    extra = "  ; 0x{:x}".format(helper.getRegVal(reg))
                except KeyError:
                    extra = "  ; flare-emu failed on register " + reg
            stepout("{:x} {:5x} {:32} {}{}".format(address, helper.getRegVal('rsp') - 0x11000, fnName, insn, extra))

            show_after()

    if False:
        userData['state'] = checkForVortex(unicornObject, address, instructionSize, userData)
        if 'readlocs' not in userData:
            userData['readlocs'] = userData.get('readlocs', [])

def callHook(address, arguments, fnName, userData):
    helper = userData["EmuHelper"]

    global functions
    global last_function
    global called_functions
    global called_functions_short
    global last_called_function
    global natives;
    global abort
    global skip
    global abort
    global memcpy

    fnName = string_between('$', '', fnName, inclusive=1, repl='').rstrip('_')

    called_functions[fnName] += 1

    totalCalls = sum(called_functions.values())
    totalFuncs = len(called_functions.values())

    if totalCalls % 1000 == 0:
        memcpy_count = sum([len(x) for x in memcpy.values()])
        # out("memcpy_count: {:,} totalCalls: {:,} totalFuncs: {}, funcs: {}".format(memcpy_count, totalCalls, totalFuncs, ', '.join(called_functions.keys())), silent=0)
        out("memcpy_count: {:,} totalCalls: {:,} totalFuncs: {}, funcs: {}".format(memcpy_count, totalCalls, totalFuncs, called_functions), silent=0)
        if False and totalCalls > 10000 and memcpy_count < 50:
            print("=== stopping, lame ===")
            helper.stopEmulation(userData)

    args = helper.getArgv()[0:3]

    if os.path.exists(scriptDir + '/stop'):
        abort = 1
        helper.stopEmulation(userData)
        raise Exception("callHook: abort due to presence of /stop")
    if abort:
        helper.stopEmulation(userData)
        return

    if 'ArxanMemcpy' in fnName:
        #  out("{} {:x}: {}, {}".format(fnName, userData["currAddr"], hex(helper.getArgv()[0:3]), hex(helper.getEmuPtr(helper.getRegVal("rdx")) & ((1 << ((args[2]  * 8))) - 1))))
        # helper.writeEmuMem(args[0], intAsBytes(helper.getEmuPtr(helper.getRegVal("rdx")), args[2]))
        #  print("{} {:x}, {:x}, {}".format(fnName, args[0], args[1], args[2]))
        if args[0] > ida_ida.cvar.inf.min_ea:
            if arg[0] > 0x145000000:
                print("invalid write to {:x}".format(arg[0]))
                abort = 1
                helper.stopEmulation(userData)
            else:
                memcpy[args[0]] = helper.getEmuBytes(args[1], args[2])
        #  helper.writeEmuMem(args[0], helper.getEmuBytes(args[1], args[2]))
        #  if len(memcpy.keys()) % 100 == 0:
            #  memcpy_count = sum([len(x) for x in memcpy.values()])
            #  out("memcpy: {:,}".format(memcpy_count), silent=1)
        #  #  healer_src[args[0]] = address
        #  helper.skipInstruction(userData)
    elif 'ArxanGetNextRange' in fnName:
        _guide, _range = ArxanGetNextRange(helper.getRegVal("rcx"), arxan_range(rdx=helper.getRegVal("rdx")))
        helper.uc.reg_write(helper.regs["rcx"], _guide.ea)
        helper.uc.reg_write(helper.regs["rdx"], _range.asQword())
        helper.skipInstruction(userData)
    elif fnName == last_function:
        out("{:x} re-entrant function call detected".format(address))
        helper.stopEmulation(userData)

    if fnName != last_called_function or called_functions[fnName] % 100 == 0:
        after("; === {:x} calling function: {} ({}) ({})".format(userData["currAddr"], fnName,
                                                                 called_functions[fnName], hex(args)))
        last_called_function = fnName

    if False:
        if 'ArxanGetNextRange' in fnName:
            #  out("{}: guide: 0x{:x}".format(fnName, helper.getEmuPtr(helper.getRegVal("rcx"))))
            userData["breakpoints"].add(userData["currAddr"] + userData["currAddrSize"])
            userData["arxan_range"] = helper.getRegVal("rdx")

    if fnName == 'j_smth_NativeRegistrationTable':
        args = helper.getArgv()[0:2]
        print(args)
        natives[args[0]] = args
        helper.skipInstruction(userData)

    if fnName == 'register_native':
        args = helper.getArgv()[1:3]
        print(args)
        natives[args[0]] = args
        helper.skipInstruction(userData)
    #  eh.analysisHelper.setComment(address, s, False)


def memHook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):
    global written_set
    global read_set
    global sp
    global sp_writes





    if False and (accessType & 1) and memAccessSize == 8 and (sp + 0x48) < memAccessAddress < (sp + 0x320):
        spd = memAccessAddress - sp
        out("; [{:05x}] SP+{:04x}={:09x}".format(emu_helper.getRegVal("rsp"), spd, emu_helper.getEmuPtr(memAccessAddress)))
        sp_writes.append("0x{:x},0x{:x},0x{:x}".format(sp, memAccessAddress, emu_helper.getEmuPtr(memAccessAddress)))
    elif memAccessAddress >= ida_ida.cvar.inf.min_ea and memAccessAddress < 0x150000000:
        if accessType & 1 == 0:
            #  out("memAccessHook: RIP: {:9x} state {} {:9x} ({:x})".format(userData['currAddr'], state, memAccessAddress, memAccessSize))
            #  userData['readlocs'].extend(list(range(memAccessAddress, memAccessAddress + memAccessSize)))
            read_set.update(list(range(memAccessAddress, memAccessAddress + memAccessSize)))
        if accessType & 1:
            written_set.update(list(range(memAccessAddress, memAccessAddress + memAccessSize)))

def checksummer1(fn):
    global initialFnName
    global functions
    global emu_helper
    global count
    global last_count
    global max_count
    global called_functions
    global visited
    global abort
    global register_lut
    global reshow_regs
    global transposition
    global last_memcpy
    global last_read
    global last_written
    global sp
    global sp_writes

    read_set.clear()
    written_set.clear()
    sp_writes.clear()

    reshow_regs = []
    ea = eax(fn)
    fnName = idc.get_name(ea)
    fnName = string_between('_$', '', fnName, inclusive=1, repl='')
    fnLoc = ea
    initialFnName = GetFuncName(ea)
    called_functions = defaultdict(int)
    called_functions_short = defaultdict(int)
    visited = set()
    functions = set()
    clean = False
    idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x0) & ~0x22)
    addresses = set()

    for (startea, endea) in Chunks(ea):
        for head in Heads(startea, endea):
            addresses.add(head)

    for r in range(1): # 1000):
        if count > max_count:
            max_count = count
        count = last_count = last_read = last_written = last_memcpy = 0
        # out("emulating {:48} (last count: {:6} / max_count: {:6})".format(fnName, count, max_count))
        out("emulating {:48}".format(fnName, count, max_count))
        #  if 'breakpoints' in helper.userData:
        #  helper.userData['breakpoints'] = set()
        #  if 'arxan_range' in helper.userData:
        #  helper.userData['arxan_range'] = set()
        r64 = make_reg_list().r64
        registers = {}
        idx = 0
        register_lut = dict()
        for reg in r64:
            if not reg.endswith(('sp', 'ip')):
                idx += 0x0000111111110000
                registers[reg] = idx
                register_lut[idx] = reg
                transposition[reg] = reg
                #  print("{:3} = {:016x}".format(reg, idx))
        idx = 0
        r32 = make_reg_list().r32
        for reg in r32:
            if not reg.endswith(('sp', 'ip')):
                idx += 0x0000111111110000
                register_lut[idx & 0xffffffff] = reg
                transposition[reg] = reg

        sp = helper.getRegVal("rsp")
        rv = helper.emulateFrom(
            # helper.analysisHelper.getNameAddr(fn),
            fnLoc,
            #  registers=registers,  # {"arg1": 0xaa, "arg2": 0xbb, "arg3": 0xcc, "arg4": 0xdd},
            skipCalls=False,
            callHook=callHook,
            memAccessHook=memHook,
            instructionHook=insnHook,
            #  count=1000000
            #  count=max(max_count + 1000000, 1000000)
        )

        filename = ddir + '/stack_{}.txt'.format(fnName)
        file_put_contents(filename, "\n".join(sp_writes))

        return 0

        unvisited = addresses - visited
        extra = visited - addresses
        if len(addresses):
            percent = len(visited & addresses) / len(addresses)
            if percent < 0.25:
                break
                continue
        break

    ## file_put_contents_bin('h:/ida/gtasc-2245/unvisited_{:x}.pickle'.format(fnLoc), pickle.dumps({'visited': visited & addresses, 'unvisited': unvisited, 'extra': extra}))
    out("function {} visited {:.0%} (returned {})".format(fnName, percent, helper.getRegVal("eax")))
    if count >= 1000000:
        filename = ddir + '/limit_{}_{}.bin'.format(fnName, count)
        if not file_exists(filename):
            file_put_contents(filename, '')
    if count >= 1000000 or abort:
        out('reach max_count or abort, unclean exit')
        return helper.getRegVal("eax")

    #  if False:
        #  if percent > 0.4:
            #  for head in unvisited:
                #  Commenter(head, 'line').add('dead code').commit()
                #  #  PatchNops(head, idc.get_item_size(head), comment="emu")
            #  func_tails(ea)
            #  if retrace(ea) == 0:
                #  decompile_arxan(ea)
                #  decompile_arxan(ea)
            #  else:
                #  print("skipping decompile_arxan due to failure to retrace")

    return helper.getRegVal("eax")


def checksummers(*args, **kwargs):
    global initialFnName
    global read_set
    global written_set
    global memcpy
    global healed_by
    global checked_by
    global count
    global last_count
    global max_count
    global abort
    global skip
    global sp;
    #  read_set.clear()

    color = True
    tag = False
    comment = True
    patch = True


    max_count = 0

    fns = [idc.get_name(x) for x in FunctionsMatching(*args, **kwargs)]
    fns.sort()
    fnLocs = [eax(x) for x in fns]
    try:
        for fnLoc in fnLocs:
            if os.path.exists(scriptDir + '/stop'):
                abort = 1
            if abort:
                out("=== abort ===")
                return
            fnStart = GetFuncStart(fnLoc)
            fnName = GetFuncName(fnStart)
            fnName = string_between('_$', '', fnName, inclusive=1, repl='')
            if fnName == 'ArxanChecksumOrHealer_227':
                skip = False
            if skip:
                out("=== skipping {} ===".format(fnName))
                continue
            #  if len(glob(ddir + '/limit_{}_100*.*'.format(fnName))) == 0:
                #  out("=== skipping for lack of disk match {} ===".format(fnName))
                #  continue
            #  if len(glob(ddir + '/memcpy_*_{}.bin'.format(fnName))) == 0:
                #  out("=== skipping as this function doesn't perform memcpy {} ===".format(fnName))
                #  continue
            retn = checksummer1(fnLoc)
            if not isinstance(retn, (int, list)):
                out("=== Invalid Return ===")
                return

            read_count = 0
            written_count = 0
            memcpy_count = 0

            out("collecting results (memcpy.len: {})".format(len(memcpy)))

            #  gr = GenericRangerHealer(memcpy, sort=1)
            ## if gr:
            ## file_put_contents_bin('h:/ida/gtasc-2245/healed_{:x}.pickle'.format(fnLoc), pickle.dumps(gr))

            if memcpy:
                fheads = set()
                # print("memcpy", pfh(memcpy))
                for r in GenericRanger(memcpy, sort=1, input_filter=patchmap_filter):
                    #  out("memcpy: {} {}".format(r, GetFuncName(r.start, r.last)), silent=1)
                    if r.start > ida_ida.cvar.inf.min_ea:
                        memcpy_count += len(r)
                        healed_by[r].add(fnName)

                        filename = ddir + '/memcpy/memcpy_{:x}_{:x}_{}.bin'.format(r.start, r.length, fnName)
                        if not file_exists(filename):
                            if comment: Commenter(r.start, 'line').add("{} bytes healed by {}".format(fnName, r.length)).commit()
                            if patch: PatchBytes(r.start, emu_helper.getEmuBytes(r.start, r.length), "Patched by {}".format(fnName))
                            file_put_contents_bin(filename, emu_helper.getEmuBytes(r.start, r.length))

                            for head in idautils.Heads(r.start, r.last):
                                if IsFuncHead(head):
                                    fheads.add(head)
                                    if tag:
                                        AddTag(head, 'healed')
                            if color:
                                set_healed_col(r.start, r.trend)
                if comment:
                    for head in fheads:
                        Commenter(head).add("[ARXAN-HEALED;{:x}] by {}".format(fnStart, fnName))

            if True and read_set:
                fheads = set()
                for r in GenericRanger(read_set, sort=1):
                    out("read_set: {} {}".format(r, GetFuncName(r.start, r.last)), silent=1)
                    read_count += len(r)

                    if r.start > ida_ida.cvar.inf.min_ea:
                        filename = ddir + '/read/read_{:x}_{:x}_{}.bin'.format(r.start, r.length, fnName)
                        if not file_exists(filename):
                            if comment: Commenter(r.start, 'line').add("{} bytes read by {}".format(fnName, r.length)).commit()
                            file_put_contents_bin(filename, emu_helper.getEmuBytes(r.start, r.length))

                            for head in idautils.Heads(r.start, r.last):
                                if IsFuncHead(head):
                                    fheads.add(head)
                                    if tag:
                                        AddTag(head, 'read')
                            if color:
                                set_checked_col(r.start, r.trend)
                if comment:
                    for head in fheads:
                        Commenter(head).add("[ARXAN-CHECKED;{:x}] by {}".format(fnStart, fnName))


            if True and written_set:
                fheads = set()
                for r in GenericRanger(written_set, sort=1):
                    out("written_set: {} {}".format(r, GetFuncName(r.start, r.last)), silent=1)
                    written_count += len(r)

                    if r.start > ida_ida.cvar.inf.min_ea:
                        filename = ddir + '/written/written_{:x}_{:x}_{}.bin'.format(r.start, r.length, fnName)
                        if not file_exists(filename):
                            if comment: Commenter(r.start, 'line').add("{} bytes written by {}".format(fnName, r.length)).commit()
                            if patch: PatchBytes(r.start, emu_helper.getEmuBytes(r.start, r.length), "Patched(W) by {}".format(fnName))
                            file_put_contents_bin(filename, emu_helper.getEmuBytes(r.start, r.length))

                            for head in idautils.Heads(r.start, r.last):
                                if IsFuncHead(head):
                                    fheads.add(head)
                                    if tag:
                                        AddTag(head, 'written')
                            if color:
                                set_healed_col(r.start, r.trend)
                if comment:
                    for head in fheads:
                        Commenter(head).add("[ARXAN-WRITTEN;{:x}] by {}".format(fnStart, fnName))

            out("read_set: {:,} written_set: {:,} memcpy: {:,}".format(read_count, written_count, memcpy_count), silent=1)

            memcpy.clear()
            read_set.clear()
            written_set.clear()

    except KeyboardInterrupt:
        out("*** KeyboardInterrupt ***")
        abort = 1
        return
    #  except Exception as e:
    #  out("Exception: {}".format(e))
    #  return


def aligned_hash(s, seed=0):
    global emu_helper
    if eax('aligned_joaat'):
        helper.emulateRange(
            helper.analysisHelper.getNameAddr("aligned_joaat"),
            registers={"arg1": s, "arg2": seed},
        )
        return helper.getRegVal("eax")
    return 0;

def partial_hash(s, seed=0):
    global emu_helper
    if eax('joaat_partial'):
        helper.emulateRange(
            helper.analysisHelper.getNameAddr("joaat_partial"),
            registers={"arg1": s, "arg2": seed},
        )
        return helper.getRegVal("eax")
    return 0;


def userDataExamples():
    someUserData = {}
    for k, v in userData.items():
        if isinstance(v, (int, bool, str)):
            if isinstance(v, int) and v > 999:
                v = hex(v)
            someUserData[k] = v

    obj = {"address": address,
           "arguments": arguments,
           "functionName": functionName,
           "userData": someUserData
           }


# retrace 280c01  #010c28 
# checked 010128  #280101 
# checked 140128  #280114 
# checked 410128  #280141 
# healed  280128  #280128 
# chk+hld 3c0128  #28013c 
# chk+hld 7c0128  #28017c 
_col_checked = 0x140128
_col_healed  = 0x280128
_cols_checked = [0x010128, 0x140128, 0x410128]
_cols_healed  = [0x280128]

def eac(ea):
    if isinstance(ea, int) and not ea & ~0xffffff:
        return ea
    ea = eax(ea)
    if ea & ~0xffffff:
        return idc.get_color(ea, idc.CIC_ITEM)
    return ea

def is_healed_col(c): 
    c = hldchk_msk(eac(c))
    if not c: return False
    return _.any(_cols_healed, lambda x, *a: c & x == x)

def is_checked_col(c): 
    c = hldchk_msk(eac(c))
    if not c: return False
    return _.any(_cols_checked, lambda x, *a: c & x == x)

def is_hldchk_col(c):
    return is_checked_col(c) and is_healed_col(c)

#  def is_healed_col(c): return is_hldchk_col(eac(c)) & eac(c) >> 16 in (1, 0x14)
#  def is_checked_col(c): return is_hldchk_col(eac(c)) & eac(c) >> 16 in (1, 0x28)
#  def is_hldchk_col(c): return is_hldchk_msk(eac(c)) & eac(c) >> 16 == 1
def hldchk_msk(c): return (eac(c)) & (0x280128 | 0x140128 | 0x010128 | 0x410128)
def hldchk_invmsk(c): return (eac(c)) & ~(0x280128 | 0x140128 | 0x010128 | 0x410128)
def is_hldchk_msk(c): return hldchk_msk(c) & 0xffff == 0x128

def set_healed_col(ea, end=None):
    if end is not None:
        [idc.set_color(x, idc.CIC_ITEM, 0x280128) for x in range(ea, end)]
        return
        return [set_healed_col(x) for x in range(ea, end)]

    c = eac(ea)
    if not is_hldchk_msk(c):
        return idc.set_color(ea, idc.CIC_ITEM, _col_healed)
    nc = _col_healed
    if is_checked_col(ea):
        nc |= _col_checked
    if nc != c:
        return idc.set_color(ea, idc.CIC_ITEM, nc)

def set_checked_col(ea, end=None):
    if end is not None:
        return [set_checked_col(x) for x in range(ea, end)]

    c = eac(ea)
    if not is_hldchk_msk(c):
        return idc.set_color(ea, idc.CIC_ITEM, _col_checked)
    nc = _col_checked
    if is_healed_col(ea):
        nc |= _col_healed
    if nc != c:
        return idc.set_color(ea, idc.CIC_ITEM, nc)

if __name__ == "__main__":
    #  eh = flare_emu.EmuHelper()
    #  eh.emulateBytes(bytes(hex_pattern("66 90")))
    #  eh.iterate(eh.analysisHelper.getNameAddr("aligned_joaat"), iterateCallback)
    out("The Hash of 'a_c_cat_01' is: {:x}".format(aligned_hash([b"a_c_cat_01", 0])))
