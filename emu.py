from __future__ import print_function
import re
import timeit
import flare_emu
import itertools
from underscoretest import _
from braceexpand import braceexpand
from collections import defaultdict
from exectools import make_refresh
from attrdict1 import SimpleAttrDict
import pickle

refresh_emu = make_refresh(os.path.abspath(__file__))
refresh     = make_refresh(os.path.abspath(__file__))
base        = ida_ida.cvar.inf.min_ea
endash      = '\u2013'


# ranges = []
# healer = []
max_count = count = last_count = 0
functions = set()
called_functions = defaultdict(int)
last_function = ''
last_called_function = ''
deadcode = False
abort = 0


checked_by  = globals().get('checked_by', defaultdict(set))
emu_output  = globals().get('emu_output', [])
healed_by   = globals().get('healed_by', defaultdict(set))
healer      = globals().get('healer', dict())
natives = globals().get('natives', dict())
ranges      = globals().get('ranges', list())
reshow_regs = globals().get('reshow_regs', [])
show_regs   = globals().get('show_regs', False)
single_step = globals().get('single_step', 0)
step_output = globals().get('step_output', [])
transposition = globals().get('transposition', dict())
visited = set()

writtento = set()
after_output  = []
call_stack  = list()
last_regs = dict()
readfrom = set()
reshow_bits = dict()
stack_pointer = None

def str_startswith(s, prefixlist, icase=False, start=None, end=None):
    if icase:
        s = s.lower()
    for st in prefixlist:
        if icase:
            st = st.lower()
        if s.startswith(st):
            return True
    return False

def emu_pickle():
    pass
    ## file_put_contents_bin('e:/git/ida/healer.pickle', pickle.dumps(healer))
    ## file_put_contents_bin('e:/git/ida/ranges.pickle', pickle.dumps(ranges))
    ## file_put_contents_bin('e:/git/ida/checked_by.pickle', pickle.dumps(checked_by))
    ## file_put_contents_bin('e:/git/ida/healed_by.pickle', pickle.dumps(healed_by))
    ## file_put_contents('e:/git/ida/emu_output.txt', '\n'.join(emu_output))
    ## file_put_contents('e:/git/ida/step_output.txt', '\n'.join(step_output))

def out(s, silent=0):
    emu_output.append(s)
    if not silent:
        print(s)
    return

def after(s, silent=0):
    global after_output
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
        br64 =  "r{{a,c,d,b}x,{s,b}p,{s,d}i,{8..15}}"
        br32 = "{e{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}d}"
        br16 =  "{{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}w}"
        br8  =  "{{{a,c,d,b}l,{s,b}pl,{s,d}il},r{8..15}b,{a,c,d,b}h}"

        make_reg_list.reglist =  SimpleAttrDict({
                'r64': braceexpandlist(br64), # 16
                'r32': braceexpandlist(br32), # 16
                'r16': braceexpandlist(br16), # 16
                'r8':  braceexpandlist(br8)})  # 20

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
        if (i > -1):
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
    


if "emu_helper" not in globals():
    out("constructing helper")
    emu_helper = flare_emu.EmuHelper()
else:
    out("using existing helper")

# .text:00000001438DD3AA 0A8 48 8B 45 58                     mov     rax, [rbp+80h+vortex]
# .text:00000001438DD3AE 0A8 0F B6 00                        movzx   eax, byte ptr [rax]
# .text:00000001438C2F43 0B8 48 8B 45 48                     mov     rax, [rbp+90h+vortex]
# .text:00000001438C2F47 0B8 8B 00                           mov     eax, [rax]

def checkForVortex(unicornObject, address, instructionSize, userData):
    state = userData.get('state', 0)
    ea = address
    mnem = idc.print_insn_mnem(ea) # 'mov'
    op1 = idc.print_operand(ea, 0) # 'rax'
    op2 = idc.print_operand(ea, 1) # '[rbp+80h+vortex]'
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


insnHookTimings = CircularList(32)
badTakings = []
def insnHook(unicornObject, address, instructionSize, userData):
    try:
        start = timeit.default_timer()
        insnHookActual(unicornObject, address, instructionSize, userData)
        insnHookTimings.append(timeit.default_timer() - start)
        taken = sum(insnHookTimings)
        if taken > 0.030:
            badTakings.append(taken)
            for i in range(32):
                insnHookTimings.append(0)
            
            if len(badTakings) > 50:
                print('taken: {}'.format(taken))
                userData["EmuHelper"].stopEmulation(userData)
        else:
            if len(badTakings):
                badTakings.pop(0)
    except Exception as ex:
        print("Exception: {} {}".format(type(ex), str(ex)))
        userData["EmuHelper"].stopEmulation(userData)


def insnHookActual(unicornObject, address, instructionSize, userData):
    global reshow_regs
    global count
    global last_count
    global single_step
    global abort
    global functions
    global last_function
    global visited
    global called_functions
    global last_regs
    global after_output
    global call_stack;
    global stack_pointer;

    helper = userData["EmuHelper"]
    if "breakpoints" not in userData:
        userData['breakpoints'] = set() # [0x14022232b]) # 2b

    if not address:
        out("Jumped to unknown location (probably external library)")
        userData["EmuHelper"].stopEmulation(userData)
        
    if address in userData["breakpoints"]:
        out("{:x} Breakpoint!".format(address))
        userData["EmuHelper"].stopEmulation(userData)

    if abort:
        out("{:x} Abort!".format(address))
        userData["EmuHelper"].stopEmulation(userData)

    for ea in range(address, address + instructionSize):
        visited.add(ea)

    #  if address == 0x1421D1EFB:
        #  # .text:00000001421D1EFB 0E0 D3 85 90 00 00 00                             rol     [rbp+0B0h+rolling_code], cl
        #  if single_step:
            #  out("rol by {:x}".format(helper.getRegVal('rcx') & 0x1f))
#  
    #  if address == 0x1421D1F0C:
        #  if single_step:
            #  out("rolling_code {:x}".format(helper.getRegVal('edx')))
#  
    #  if address == 0x1402CCF1B:
        #  userData["EmuHelper"].stopEmulation(userData)


    fnName = GetFuncName(address) or hex(address)
    if single_step:
        isFunc = IsFunc_(address)

        if instructionSize < 5 and call_stack and isRet(address) and fnName == call_stack[-1]:
            stepout("; === {:x}: leaving {} rax:{:x} ===".format(address, fnName, helper.getRegVal('rax')))
            #  if fnName == "ArxanReadMemcpyRanges":
                #  #  if address == 0x1400f0f31:
                    #  #  val = helper.getEmuPtr(0x1402BAE8A) >> 32
                    #  #  val = 0x2f7637ca | (val << 32)
                    #  #  helper.writeEmuPtr(0x1402BAE8A, val)
                #  stepout("=== dword_1402BAE8A: 0x{:x},  dword_1419CA643: 0x{:x} ==="\
                        #  .format(_uint32(helper.getEmuPtr(0x1402BAE8A)),
                                #  _uint32(helper.getEmuPtr(0x1419CA643))
                #  ))
            call_stack.pop()
            if isFunc and fnName not in functions:
                functions.add(fnName)
                # out("function: {} ({})".format(fnName, len(functions)))
                if len(functions) > 500:
                    out("aborting (functions > 500)")
                    userData["EmuHelper"].stopEmulation(userData)

    count += 1
    if count - last_count > 99999:
        if os.path.exists(scriptDir + '/stop'):
            raise Exception("insnHook: abort due to presence of /stop")
            abort = 1
        #  gr = GenericRanger(visited, sort=1)
        #  out("{}... in {} ({}) at {:x} ranges: {} total addresses: {}".format(count, fnName,
            #  called_functions[fnName], address, gr, _.sum(gr, lambda x, *a: len(x))))
        out("... ({}) visited {} addresses, read {}, wrote {}".format(count, len(visited), len(readfrom), len(writtento)))
        last_count = count
    if count > 1000000:
        single_step = 1
    if single_step and count > 1001000:
        single_step = 0


    #  helper = userData["EmuHelper"]
    #  uc = helper.uc
    #  ah = helper.analysisHelper
    if single_step:
        if 0 and str_startswith(fnName, "ArxanMemcpy ArxanGetNextRange ArxanChecksumWorker".split(' '), icase=True):
            pass
        else:
            #  if fnName:
                #  stepout("{}:".format(fnName))
            try:
                insn = diida(address)
                #  insn = GetDisasm(address)
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
            reg = string_between(', ', '', string_between(';', '', insn, repl=''))
            if reg in regnames:
                try:
                    extra = "  ; 0x{:x}".format(helper.getRegVal(reg))
                except KeyError:
                    extra = "  ; flare-emu failed on register " + reg
            cmt = idc.get_extra_cmt(address, E_PREV + (0))
            if (cmt):
                stepout("{:9} {:5} {}".format('', '', ida_lines.tag_remove(cmt)))
            if stack_pointer is not None:
                _spd = helper.getRegVal('rsp') - stack_pointer
                if _spd:
                    _spd = hex(_spd)
            else:
                _spd = 'unset'
            stack_pointer = helper.getRegVal('rsp')
            stepout("{:9x} {:5x} {:16} {}{} ; spd: {}".format(address, helper.getRegVal('rsp') - 0x11000, TagRemoveSubstring(fnName), string_between('; ', '', insn, repl=''), extra, _spd))

            show_after()

    # temporarily disabled for launcher
    # userData['state'] = checkForVortex(unicornObject, address, instructionSize, userData)
    if 'readlocs' not in userData:
        userData['readlocs'] = userData.get('readlocs', [])
    #  if state:
        #  out("\ninsnHook state {}".format(state))
        #  out(helper.getEmuState())
        #  out("    {:x} RAX: {:x}".format(address, helper.getEmuPtr(helper.getRegVal('rax'))))
        #  out("    tricky stuff: {:x}".format(
            #  #  uc.mem_read(helper.analysisHelper.getOpndValue(address, 1), helper.size_pointer)
            #  #  helper.analysisHelper.getOpndValue(address, 1)
            #  #  helper.analysisHelper.getOpndValue(address, 1)
            #  # helper.regs[helper.analysisHelper.getOperand(address, 0)], , helper.analysisHelper.getOpndValue(address, 1)
            #  uc.reg_read(helper.regs['rax'])
        #  ))
        #  #  pp(obj)
    #  if "breakpoints" not in userData:
        #  userData["breakpoints"] = set()
    #  if address in userData["breakpoints"]:
        #  out("protecting:")
        #  arxan_range = list(struct.unpack("<II", helper.getEmuBytes(userData["arxan_range"], 8)))
        #  arxan_range[0] += base
        #  arxan_range[1] += arxan_range[0]
        #  out("    range: {}".format(endash.join(hex(arxan_range))))
        #  fns = set([idc.get_func_name(ea) for ea in range(*arxan_range) if IsFunc_(ea)])
        #  insns = [idii(ea) for ea in range(*arxan_range) if IsCode_(ea)]
        #  if fns:
            #  out("    functions: {}".format(fns))
        #  elif insns:
            #  out("    instructions: {}".format(insns))

def callHook(address, arguments, fnName, userData):
    #  global max_count
    #  global count
    helper = userData["EmuHelper"]

    #  if count > max_count:
        #  max_count = userData["count"]
    global functions
    global last_function
    global called_functions
    global last_called_function
    global natives;
    global abort
    global call_stack

    if not fnName:
        fnName = "0x{:X}".format(address)

    args = helper.getArgv()

    called_functions[fnName] += 1
    call_stack.append(fnName)
    if os.path.exists(scriptDir + '/stop'):
        raise Exception("callHook: abort due to presence of /stop")
        abort = 1
    if abort:
        helper.stopEmulation(userData)

    if fnName == last_function:
        out("re-entrant function call detected")
        helper.stopEmulation(userData)

    if fnName == 'ArxanMakeSectionsWritable':
        print('l === skipping function: ' + fnName)
        helper.skipInstruction(userData)
        return

    if single_step:
        called_functions[fnName] += 1
        if fnName != last_called_function or called_functions[fnName] % 100 == 0:
            after("; === {:x} calling function: {} ({}) ({})".format(userData["currAddr"], fnName, called_functions[fnName], hex(args)))
            last_called_function = fnName

    if not abort and str_startswith(fnName, ['ArxanMemcpy'], icase=True):
        #  print("ArxanMemcpy: {}".format(fnName))
        # void __fastcall ArxanMemcpy(_BYTE *dst, _BYTE *src, unsigned int size)
        #  out("{} {:x}: {}, {}".format(fnName, userData["currAddr"], hex(helper.getArgv()[0:3]), hex(helper.getEmuPtr(helper.getRegVal("rdx")) & ((1 << ((args[2]  * 8))) - 1))))
        #  rcx = helper.getRegVal("rcx")
        #  rdx = helper.getRegVal("rdx")
        a1 = args[0]
        a2 = args[1]
        #  dst = helper.getEmuPtr(helper.getRegVal("rcx"))
        #  src = helper.getEmuPtr(helper.getRegVal("rdx"))
        #  dst2 = helper.getEmuPtr(args[0])
        #  src2 = helper.getEmuPtr(args[1])
        #  # length = helper.getEmuPtr(helper.getRegVal("r8")) & 0xffffffff
        length = args[2]
        #  #  print(helper.getEmuState())
        dst = a1
        src = a2
        #  if a1 > ida_ida.cvar.inf.min_ea and a1 < 0x150000000:
            #  out("ArxanMemcpy: rcx: {:x} rdx: {:x} a1: {:x} a2: {:x} {:x} Writing {} bytes from {:x} to {:x}".format(rcx, rdx, a1, a2, address, length, src, dst))
        #  else:
            #  return
        #  return

        
        # is this right?
        # healer[args[0]] = intAsBytes(helper.getEmuPtr(helper.getRegVal("rdx")), args[2])

        if True:
            # out("{:x} Writing {} bytes from {:x} to {:x}".format(address, length, src, dst))
            filename = 'r:/ida/launcher/memcpy_{:x}_{:x}_{:x}.bin'.format(dst, src, length)  
            #  if file_exists(filename):
                #  raise Exception('File {} exists'.format(filename))
            file_put_contents_bin(filename, helper.getEmuBytes(src, length))
                    

            #  helper.skipInstruction(userData)

    #  if False:
        #  if fnName.startswith('ArxanChecksumWorker'):
            #  #  out("{}: guide: 0x{:x}".format(fnName, helper.getEmuPtr(helper.getRegVal("rcx"))))
            #  userData["breakpoints"].add(userData["currAddr"] + userData["currAddrSize"])
            #  userData["arxan_range"] = helper.getRegVal("rdx")

    if fnName == 'j_smth_NativeRegistrationTable':
        args = helper.getArgv()[0:2]
        print(args)
        natives[args[0]] = args
        helper.skipInstruction(userData)

    if fnName == 'SetReturnAddressToCallArxanCheckRangedCopy':
        raise Exception('SetReturnAddressToCallArxanCheckRangedCopy')


    if fnName == 'register_native':
        args = helper.getArgv()[1:3]
        print(args)
        natives[args[0]] = args
        helper.skipInstruction(userData)

    #  eh.analysisHelper.setComment(address, s, False)

def memHook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):
    global readfrom
    global writtento
    helper = userData["EmuHelper"]
    if single_step:
        if accessType & 1:
            writtento.add(memAccessAddress)
            _type = "write"
            if memAccessAddress >= ida_ida.cvar.inf.min_ea and memAccessAddress < 0x150000000 and memAccessAddress != 0x1402bae8a:
                out("                mem: {} [0x{:x}] {:x} {:x}b {}".format(_type, memAccessAddress, memValue, memAccessSize, idc.get_name(memAccessAddress)))
        else:
            _type = "read "
            if memAccessAddress >= ida_ida.cvar.inf.min_ea and memAccessAddress < 0x150000000 and memAccessAddress != 0x1402bae8a:
                out("                mem: {} [0x{:x}] {:x} {:x}b {}".format(_type, memAccessAddress, memValue, memAccessSize, idc.get_name(memAccessAddress)))
            readfrom.add(memAccessAddress)


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
    global deadcode

    reshow_regs = []
    ea = get_ea_by_any(fn)
    fnName = get_name_by_any(ea)
    fnLoc = ea
    initialFnName = GetFuncName(ea)
    called_functions = defaultdict(int)
    visited = set()
    functions = set()
    clean = False
    idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x0) & ~0x22)
    #  for i in range(3):
        #  if retrace(fn) == 0:
            #  clean = True
            #  break
#  
    #  if not clean:
        #  print("skipping, unclean")
        #  return
    addresses = set()

    for (startea, endea) in Chunks(ea):
        for head in Heads(startea, endea):
            addresses.add(head)

    for r in range(1000):
        if count > max_count:
            max_count = count
        count = last_count = 0
        out("emulating {:48} (last count: {:6} / max_count: {:6})".format(fnName, count, max_count))
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
                print("{:3} = {:016x}".format(reg, idx))
        idx = 0
        r32 = make_reg_list().r32
        for reg in r32:
            if not reg.endswith(('sp', 'ip')):
                idx += 0x0000111111110000
                register_lut[idx & 0xffffffff] = reg
                transposition[reg] = reg
                print("{:3} = {:08x}".format(register_lut[idx & 0xffffffff], idx & 0xffffffff))
        rv = helper.emulateFrom(
                # helper.analysisHelper.getNameAddr(fn), 
                fnLoc,
                    #  registers = registers, # {"arg1": 0xaa, "arg2": 0xbb, "arg3": 0xcc, "arg4": 0xdd},
                    skipCalls = False,
                    callHook = callHook,
                    # memAccessHook = memHook,
                    # insnHook = insnHook,
                    # count = max(max_count + 1000000, 50000000)
                )

        unvisited = addresses - visited
        extra = visited - addresses
        if len(addresses):
            percent = len(visited & addresses)/len(addresses)
            if percent < 0.25:
                break
                continue
        break

    ## file_put_contents_bin('h:/ida/gtasc-2245/unvisited_{:x}.pickle'.format(fnLoc), pickle.dumps({'visited': visited & addresses, 'unvisited': unvisited, 'extra': extra}))
    out("function {} visited {:.0%} (returned {})".format(fnName, percent, helper.getRegVal("eax")))
    if count >= 50000000 or abort:
        out('reach max_count or abort, unclean exit')
        return helper.getRegVal("eax")

    if deadcode:
        if (percent) > 0.4:
            for head in unvisited:
                PatchNops(head, MyGetInstructionLength(head))
                Commenter(head, 'line').add('dead code').commit()
                #  PatchNops(head, idc.get_item_size(head), comment="emu")
            func_tails(ea)
            #  if retrace(ea) == 0:
                #  decompile_arxan(ea)
                #  decompile_arxan(ea)
            #  else:
                #  print("skipping decompile_arxan due to failure to retrace")


    #  out("Healing:")
    #  gr = GenericRangerHealer(healer, sort=1)
    #  for k, v in gr.items():
        #  out("{}: {}".format(idc.get_name(k), v))
    #  return GenericRanger(ranges, sort=0)
    #  if helper.userData.get('readlocs', 0):
        #  out("Memory ranges read: {}".format(GenericRange(helper.userData["readlocs"], sort=0)))
    return helper.getRegVal("eax")


def checksummers(*args, **kwargs):
    global initialFnName
    global ranges
    global healer
    global healed_by
    global checked_by
    global count
    global last_count
    global max_count
    global abort
    #  ranges.clear()
    max_count = 0
    fns = [idc.get_name(x) for x in FunctionsMatching(*args, **kwargs)]
    fns.sort()
    fnLocs = [get_ea_by_any(x) for x in fns]
    try:
        for fnLoc in fnLocs:
            if abort:
                out("=== abort ===")
                return
            fnStart = GetFuncStart(fnLoc)
            fnName = GetFuncName(fnStart)
            retn = checksummer1(fnLoc)
            if not isinstance(retn, (int, list)):
                out("=== Invalid Return ===")
                return

            checked_count = 0
            healed_count = 0

            out("collecting results")

            gr = GenericRangerHealer(healer, sort=1)
            ## if gr:
                ## file_put_contents_bin('h:/ida/gtasc-2245/healed_{:x}.pickle'.format(fnLoc), pickle.dumps(gr))


            fheads = set()
            for r in GenericRanger(healer, sort=1, input_filter=patchmap_filter):
                out("healed: {} {}".format(r, GetFuncName(r.start, r.last)), silent=1)
                healed_count += len(r)
                healed_by[r].add(fnName)
                for head in idautils.Heads(r.start, r.last):
                    if IsFuncHead(head):
                        fheads.add(head)
                        AddTag(head, 'healed')
                    set_healed_col(head)
            for head in fheads:
                Commenter(head).add("[ARXAN-HEALED;{:x}] by {}".format(fnStart, fnName))


            fheads = set()
            for r in GenericRanger(ranges, sort=1):
                out("checked: {} {}".format(r, GetFuncName(r.start, r.last)))
                checked_count += len(r)
                checked_by[r].add(fnName)
                for head in idautils.Heads(r.start, r.last):
                    if IsFuncHead(head):
                        fheads.add(head)
                        AddTag(head, 'checked')
                    set_healed_col(head)
            for head in fheads:
                #  Commenter(head).remove("[ARXAN-HEALED;{:x}] by {}".format(fnStart, fnName))
                Commenter(head).add("[ARXAN-CHECKED;{:x}] by {}".format(fnStart, fnName))

            out("checked: {:,} healed: {:,}".format(checked_count, healed_count), silent=1)

            ranges.clear()
            healer.clear()

    
        #  out("uniqing ranges for restart")
        # ranges[:] = _.uniq(ranges, isSorted=True)
        #  ranges = _.uniq(ranges, 1)

        #  out("applying healing")
        #  GenericRangerHealer(healer, sort=1, apply=1)
        #  out("Memory ranges read: {}".format(GenericRanger(ranges, sort=1)))
        #  pp(_.filter(_.sort(
            #  [GetFunctionName(x.start) or 
             #  Name(x.start) or
             #  hex(x.start) for 
                #  x in GenericRanger(ranges, sort=0, outsort=1)]), 
            #  lambda x, *a: not re.match('0x|[a-z]+_14[0-9A-F]{7}', x)))

        #  gr = GenericRangerHealer(healer, sort=1)
    except KeyboardInterrupt:
        out("*** KeyboardInterrupt ***")
        abort = 1
        return
    #  except Exception as e:
        #  out("Exception: {}".format(e))
        #  return


def aligned_hash(argv):
    global emu_helper
    if eax('aligned_joaat'):
        out("emulating range")
        helper.emulateRange(
                helper.analysisHelper.getNameAddr("aligned_joaat"), 
                registers = {"arg1": argv[0], "arg2": argv[1]},
                )
        out("getting result")
        return helper.getRegVal("eax")
    else:
        return 0;
    
#  def iterateCallback(eh, address, argv, userData):
    #  s = hash(argv)
    #  out("%s: %s" % (eh.hexString(address), s))
    #  eh.analysisHelper.setComment(address, s, False)

# .text:00000001438DD3AA 0A8 48 8B 45 58                     mov     rax, [rbp+80h+vortex]
# .text:00000001438DD3AE 0A8 0F B6 00                        movzx   eax, byte ptr [rax]

def filterUserData(userData, hexlify=False):
    someUserData = SimpleAttrDict()
    for k, v in userData.items():
        if isinstance(v, (int, bool, str)):
            if hexlify and isinstance(v, int) and v > 999:
                v = hex(v)
            someUserData[k] = v
    return someUserData

def userDataExamples():
    someUserData = {}
    for k, v in userData.items():
        if isinstance(v, (int, bool, str)):
            if isinstance(v, int) and v > 999:
                v = hex(v)
            someUserData[k] = v
            
    obj = { "address": address,
            "arguments": arguments,
            "functionName": functionName,
            "userData": someUserData
    }

# healed  #28 01 28
# checked #01 01 28
# both    #14 01 28
# healed | checked #28013D
def is_healed_col(c): return is_hldchk_col(c) & c >> 16 in (1, 0x14)
def is_checkd_col(c): return is_hldchk_col(c) & c >> 16 in (1, 0x28)
def is_hldchk_col(c): return is_hldchk_msk(c) & c >> 16 == 1
def is_hldchk_msk(c): return c & 0xc2ffff == 0x000128

def set_healed_col(ea):
    c = idc.get_color(ea, idc.CIC_ITEM)
    if not is_hldchk_msk(c):
        return idc.set_color(ea, idc.CIC_ITEM, 0x280128)
    if is_healed_col(c):
        return
    if is_checkd_col(c):
        return idc.set_color(ea, idc.CIC_ITEM, 0x010128)
    return idc.set_color(ea, idc.CIC_ITEM, 0x280128)

def set_checkd_col(ea):
    c = idc.get_color(ea, idc.CIC_ITEM)
    if not is_hldchk_msk(c):
        return idc.set_color(ea, idc.CIC_ITEM, 0x140128)
    if is_checkd_col(c):
        return
    if is_healed_col(c):
        return idc.set_color(ea, idc.CIC_ITEM, 0x010128)
    return idc.set_color(ea, idc.CIC_ITEM, 0x140128)

def emu_sub(fn, steps=100, single=None, regs=None, args={}):
    global abort
    global called_functions
    global count
    global functions
    global emu_helper
    global initialFnName
    global last_count
    global last_regs
    global max_count
    global register_lut
    global reshow_regs
    global show_regs
    global single_step
    global transposition
    global visited
    global deadcode

    if single is not None:
        single_step = single

    if regs is not None:
        show_regs = regs

    reshow_regs = []
    ea = get_ea_by_any(fn)
    fnName = get_name_by_any(ea)
    fnLoc = ea
    initialFnName = GetFuncName(ea)
    called_functions = defaultdict(int)
    visited = set()
    functions = set()
    clean = False
    # idc.set_func_flags(ea, (idc.get_func_flags(ea) | 0x0) & ~0x22)

    #  if 'breakpoints' in emu_helper.userData:
        #  emu_helper.userData['breakpoints'] = set()
    #  if 'arxan_range' in emu_helper.userData:
        #  emu_helper.userData['arxan_range'] = set()
    r64 = make_reg_list().r64
    registers = {}
    idx = 0
    register_lut = dict()
    for reg in r64:
        if not reg.endswith(('sp', 'ip')):
            idx += 0x0000111111110000
            registers[reg] = idx
            last_regs[reg] = idx
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
            #  print("{:3} = {:08x}".format(register_lut[idx & 0xffffffff], idx & 0xffffffff))
            #
            #
    addresses = set()

    for (startea, endea) in Chunks(fnLoc):
        for head in Heads(startea, endea):
            addresses.add(head)

    rv = emu_helper.emulateFrom(
            # emu_helper.analysisHelper.getNameAddr(fn), 
            fnLoc,
            #  registers = registers, # {"arg1": 0xaa, "arg2": 0xbb, "arg3": 0xcc, "arg4": 0xdd},
            registers = args,
            skipCalls = False,
            callHook = callHook,
            memAccessHook = memHook,
            instructionHook = insnHook,
            count = steps
            )

    #  gr = GenericRanger(visited, sort=1)
    #  print("ranges: {}\ntotal addresses: {}".format(gr, _.sum(gr, lambda x, *a: len(x))))


    unvisited = addresses - visited
    extra = visited - addresses
    if len(addresses):
        percent = len(visited & addresses)/len(addresses)
    if deadcode:
        for head in unvisited:
            # PatchNops(head, MyGetInstructionLength(head))
            Commenter(head, 'line').add('dead code').commit()
            #  PatchNops(head, idc.get_item_size(head), comment="emu")
        func_tails(ea)
    return emu_helper.getRegVal("rax")

def calc_expr(s):
    global emu_helper
    def re_sub(m):
        reg = m.group(0)
        return str(emu_helper.getRegVal(reg))

    def repl_sub(s):
        re_regs = r'\b([re][abcd]x|[re][bs]p|[re][ds]i|r[89][dwb]?|r1[012345]9[dwb]?|[acdb][xl])\b'
        rs = re.sub(re_regs, re_sub, s)
        re_hex = r'\b[0-9a-fA-F]+h\b'
        rs = re.sub(re_hex, lambda m: str(parseHex(m.group(0).rstrip('h'))), rs)
        re_times = r'\b(\d+)\*(\d+)\b'
        rs = re.sub(re_times, lambda m: str(int(m.group(1)) * int(m.group(2))), rs)
        re_plus = r'\b(\d+)\+(\d+)\b'
        rs = re.sub(re_plus, lambda m: str(int(m.group(1)) + int(m.group(2))), rs)
        rs = re.sub(re_plus, lambda m: str(int(m.group(1)) + int(m.group(2))), rs)
        re_braced = r'\[([0-9]+)\]'
        rs = re.sub(re_braced, lambda m: '[0x{:x}]'.format(int(m.group(1))), rs)

        return rs

    braced = string_between('[', ']', s, repl=repl_sub)
    return string_between(' ', '', braced).lstrip()

    
if __name__ == "__main__":   
    #  eh = flare_emu.EmuHelper()
    #  eh.emulateBytes(bytes(hex_pattern("66 90")))
    #  eh.iterate(eh.analysisHelper.getNameAddr("aligned_joaat"), iterateCallback)
    out("The Hash of 'a_c_cat_01' is: {:x}".format(aligned_hash([b"a_c_cat_01", 0])))

    # processing an arxan range
    # list(struct.unpack("<II", helper.getEmuBytes(0x10df4, 8)))
    # helper.writeEmuMem(0x140222339, b'\x0f\x84')
    #  Python>PatchDword(0x1418865E2, Dword(0x1418865E2) ^ Dword(0x14222CBF7))
    #  Python>PatchDword(0x141FFF211, Dword(0x1402BFE90))
