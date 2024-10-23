import re, os
import flare_emu
from collections import defaultdict
import idc
from idc import *
import ida_ida
from idautils import *
import idaapi

base = ida_ida.cvar.inf.min_ea
scriptDir = os.path.dirname(__file__)

wrap_count = max_count = insn_count = last_count = 0
abort = 0

emu_output = globals().get('emu_output', [])
step_output = globals().get('step_output', [])
verbose_mode = globals().get('verbose_mode', 0)

functions = set()
called_functions = defaultdict(int)
last_function = ''
last_called_function = ''
last_address = 0
visited = set()
visited_area = set()
writtento = globals().get('writtento', set())
readfrom = globals().get('readfrom', set())

call_stack = list()
stack_pointer = None
new_address = None

module_handles = []
proc_address = (None, None)
proc_addresses = []
is_writing_proc_address = False
insn_address = False

after_output = []


def preprocessIsX(fun, arg):
    def perform(func, *args, **kwargs):
        return func(*args, **kwargs)

    if not arg:
        raise Exception("Invalid argument: {} ()".format(arg, type(arg)))
    if isinstance(arg, str):
        return perform(fun, arg)
    if isinstance(arg, int):
        mnem = IdaGetMnem(arg)
        if not mnem:
            return False
        return perform(fun, mnem)
    raise Exception("Unknown arg type: {}".format(type(arg)))
  
#  def _isAnyJmpOrCall_mnem(mnem): return mnem.startswith(("j", "call"))
#  def _isAnyJmp_mnem(mnem): return mnem.startswith("j")
#  def _isCall_mnem(mnem): return mnem.startswith("call")
#  def _isConditionalJmp_mnem(mnem): return mnem.startswith("j") and not mnem.startswith("jmp")
#  def _isFlowEnd_mnem(mnem): return mnem in ('ret', 'retn', 'jmp', 'int', 'ud2', 'leave', 'iret')
#  def _isInt(mnem): return mnem in ('int', 'ud2', 'int1', 'int3')
#  def _isJmp_mnem(mnem): return mnem.startswith("jmp")
#  def _isNop_mnem(mnem): return mnem.startswith("nop") or mnem.startswith("pop")
#  def _isOffset(mnem): return mnem.startswith(("dq offset", "dd offset"))
#  def _isPop_mnem(mnem): return mnem.startswith("pop")
#  def _isPushPop_mnem(mnem): return mnem.startswith("push") or mnem.startswith("pop")
#  def _isRet_mnem(mnem): return mnem.startswith("ret")
#  def _isUnconditionalJmpOrCall_mnem(mnem): return isUnconditionalJmp(mnem) or isCall(mnem)
#  def _isUnconditionalJmp_mnem(mnem): return mnem.startswith("jmp")
#  def isAnyJmp(arg): return preprocessIsX(_isAnyJmp_mnem, arg)
#  def isAnyJmpOrCall(arg): return preprocessIsX(_isAnyJmpOrCall_mnem, arg)
#  def isCall(arg): return preprocessIsX(_isCall_mnem, arg)
#  def isConditionalJmp(arg): return preprocessIsX(_isConditionalJmp_mnem, arg)
#  def isFlowEnd(arg): return preprocessIsX(_isFlowEnd_mnem, arg)
#  def isInterrupt(arg): return preprocessIsX(_isInt, arg)
#  def isJmp(arg): return preprocessIsX(_isJmp_mnem, arg)
#  def isOffset(arg): return preprocessIsX(_isOffset, arg)
#  def isPop(arg): return preprocessIsX(_isPop_mnem, arg)
#  def isPushPop(arg): return preprocessIsX(_isPushPop_mnem, arg)
#  def isRet(arg): return preprocessIsX(_isRet_mnem, arg)
#  def isUnconditionalJmp(arg): return preprocessIsX(_isUnconditionalJmp_mnem, arg)
#  def isUnconditionalJmpOrCall(arg): return preprocessIsX(_isUnconditionalJmpOrCall_mnem, arg)


def get_ea_by_any(val, d=object):
    """
    returns the address of a val (and if address is
    a number, looks up the val first).

    an easy way to accept either address or val as input.
    """
    if isinstance(val, list):
        return [get_ea_by_any(x, d) for x in val]

    if isinstance(val, str):
        r = idaapi.str2ea(val)
        if r and r != idc.BADADDR:
            return r

        match = re.match(r'(sub|off|loc|byte|word|dword|qword|nullsub|locret)_([0-9a-fA-F]+)$', val)
        if match:
            return int(match.group(2), 16)

        return 0 if d == object else d

    if isinstance(val, idaapi.vdui_t):
        val = val.cfunc

    if val is None:
        return idc.get_screen_ea() if d == object else d

    if isinstance(val, int):
        return val

    try:
        for attr_name in ['start_ea', 'ea', 'entry_ea', 'start', 'min_ea']:
            if hasattr(val, attr_name):
                return getattr(val, attr_name)
    except AttributeError:
        pass

    raise ValueError("Don't know how to convert {} '{}' to address".format(type(val), val))


def eax(*args):
    return get_ea_by_any(*args)


def IsFunc_(ea): return idaapi.get_func(get_ea_by_any(ea)) is not None


def isInt(o): return isinstance(o, int)


def GetFuncName(ea, end=None):
    if isinstance(ea, list):
        return [GetFuncName(x) for x in ea]
    if end is None:
        if ea is None:
            ea = idc.get_screen_ea()
        if isInt(ea):
            r = idc.get_func_name(ea)
            return r
    if isInt(end):
        if end > ea:
            fnNames = set()
            heads = Heads(ea, end)
            if heads:
                for head in Heads(ea, end):
                    fnNames.add(GetFuncName(head))
                if '' in fnNames:
                    fnNames.remove('')
                return fnNames
    return ''


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

def mask_bytes(value, num_bytes):
    mask = (1 << (num_bytes * 8)) - 1
    masked_value = value & mask
    max_width = num_bytes * 2  # Each byte is represented by 2 hex digits
    return f"{masked_value:0{max_width}x}"
    return value & mask

def bytearray_to_int(byte_array):
    return int.from_bytes(byte_array, byteorder='little')

def insnHook(unicornObject, address, instructionSize, userData):
    global insn_count
    global last_count
    global wrap_count
    global verbose_mode
    global abort
    global functions
    global last_function
    global visited
    global called_functions
    global after_output
    global call_stack
    global stack_pointer
    global last_address
    global new_address
    global visited_area
    global is_writing_proc_address
    global insn_address

    if not address:
        out("Jumped to unknown location (probably external library)")
        userData["EmuHelper"].stopEmulation(userData)
        return

    helper = userData["EmuHelper"]
    if "breakpoints" not in userData:
        userData['breakpoints'] = set([ida_ida.cvar.inf.min_ea])  # 2b
    if address in userData["breakpoints"]:
        out("{:x} Breakpoint!".format(address))
        userData["EmuHelper"].stopEmulation(userData)

    if abort:
        userData["EmuHelper"].stopEmulation(userData)

    if address not in visited:
        new_address = True
        visited.add(address)
    else:
        new_address = False

    for ea in range(address, address + instructionSize):
        visited_area.add(ea)

    if address == 0x7c7c0c:
        is_writing_proc_address = True
        insn_address = address
    else:
        is_writing_proc_address = False

    if address == 0x1421D1EFB:
        if verbose_mode:
            out("rol by {:x}".format(helper.getRegVal('rcx') & 0x1f))

    if address == 0x1421D1F0C:
        if verbose_mode:
            out("rolling_code {:x}".format(helper.getRegVal('edx')))

    if address == 0x1402CCF1B:
        userData["EmuHelper"].stopEmulation(userData)

    fnName = GetFuncName(address) or hex(address)
    if verbose_mode:
        isFunc = IsFunc_(address)

        if instructionSize < 5 and call_stack and isRet(address) and fnName == call_stack[-1]:
            stepout("; === {:x}: leaving {} eax:{:x} ===".format(address, fnName, helper.getRegVal('eax')))
            call_stack.pop()
            if isFunc and fnName not in functions:
                functions.add(fnName)
                if len(functions) > 500:
                    out("aborting, too many functions - runaway code?")
                    userData["EmuHelper"].stopEmulation(userData)

    insn_count += 1
    wrap_count += 1
    #  if len(visited) > 310:
        #  raise Exception('insnHook > 310 instructions')
    #  if address == 0xa1353c:
        #  raise Exception('0xa1353c')
    #  if address == 0x7C7B6C:
        #  raise Exception('0x7C7B6C')
    if insn_count - last_count > 99999:
        if os.path.exists(scriptDir + '/stop'):
            abort = 1
            raise Exception("insnHook: abort due to presence of /stop")

        out("... ({}) visited {} addresses, read {}, wrote {}, ip {}".format(insn_count, len(visited), len(readfrom),
                                                                      len(writtento), hex(address)))
        last_count = insn_count
    #  if wrap_count > 1000000:
        #  verbose_mode = 1
    #  if verbose_mode and wrap_count > 1001000:
        #  verbose_mode = 0
        #  wrap_count = 0
    if verbose_mode or new_address:
        #  try:
            #  insn = GetDisasm(address)
        #  except IndexError:
            #  insn = "** INVALID **"
        # insn = dii(address)
        insn = diInsn(emu_helper.getEmuBytes(address, 15), address)
        helper = userData["EmuHelper"]
        extra = ''
        cmt = idc.get_extra_cmt(address, E_PREV + 0)
        if cmt:
            stepout("{:9} {:5} {}".format('', '', ida_lines.tag_remove(cmt)))
        #  if stack_pointer is not None:
            #  _spd = helper.getRegVal('esp') - stack_pointer
        #  else:
            #  _spd = 'unset'
        #  stack_pointer = helper.getRegVal('esp')
        stepout("{:9x} {:5x} {:16} {}{}".format(address, helper.getRegVal('esp') - 0x11000,
                                                          fnName, insn, extra))

        show_after()

    last_address = address

    #  if SnstructionSize == 2 and helper.getEmuBytes(address, 1)[0] == 0x8e and helper.getEmuBytes(address + 1, 1)[0] & 0b11110000 == 0xd0:
        #  # mov Sreg, r/m16
        #  if verbose_mode or new_address:
            #  out("skipping mov Sreg... ")
        #  helper.skipInstruction(userData)
        #  return
        

def getStackArgDword():
    uc = emu_helper.uc
    sp = uc.reg_read(emu_helper.regs["sp"])
    arg = bytearray_to_int(emu_helper.getEmuBytes(sp, 4))
    sp += 4
    uc.reg_write(emu_helper.regs["sp"], sp)
    return arg

def getStackArgString():
    arg = getStackArgDword()
    if ida_ida.cvar.inf.min_ea <= arg < ida_ida.cvar.inf.max_ea:
        # Use existing IDA database
        if True:
            try:
                s = get_strlit_contents(arg).decode()
                return s
            except AttributeError:
                pass
        # Use emulated memory
        else:
            s = emu_helper.getEmuBytes(arg, 256).decode()
            try:
                z = s.index('\x00')
                s = s[0:z]
                return s
            except ValueError:
                pass
    return hex(arg)


def callHook(address, arguments, fnName, userData):
    global functions
    global last_function
    global called_functions
    global last_called_function
    global abort
    global call_stack
    global module_handles
    global proc_addresses
    global proc_address

    # fnName = get_func_name(address)
    #  fnName = get_name(address)
    helper = userData["EmuHelper"]

    if abort:
        helper.stopEmulation(userData)

    if not fnName:
        fnName = "Unknown: 0x{:X}".format(address)

    args = helper.getArgv()

    called_functions[fnName] += 1
    call_stack.append(fnName)
    if os.path.exists(scriptDir + '/stop'):
        abort = 1
        raise Exception("callHook: abort due to presence of /stop")

    if fnName == last_function:
        out("re-entrant function call detected")
        helper.stopEmulation(userData)

    if fnName == 'ArxanMakeSectionsWritable':
        print('l === skipping function: ' + fnName)
        helper.skipInstruction(userData)
        return

    if verbose_mode:
        called_functions[fnName] += 1
        if fnName != last_called_function or called_functions[fnName] % 100 == 0:
            after("; === {:x} calling function: {} ({}) ({})".format(userData["currAddr"], fnName,
                                                                     called_functions[fnName], [hex(a) for a in args]))
            last_called_function = fnName

    if fnName == 'j_GetModuleHandleA':
        s = getStackArgString()
        if s not in module_handles:
            module_handles.append(s)
        emu_helper.uc.reg_write(emu_helper.regs['eax'], module_handles.index(s))
        helper.skipInstruction(userData)
        return

    if fnName == 'j_GetProcAddress':
        handle = getStackArgDword()
        proc_name = getStackArgString()
        proc_address = (module_handles[handle], proc_name)
        proc_addresses.append(proc_address)
        emu_helper.uc.reg_write(emu_helper.regs['eax'], 0xfad30000 | len(proc_addresses) - 1)
        helper.skipInstruction(userData)
        return


    if verbose_mode:
        called_functions[fnName] += 1
        if fnName != last_called_function or called_functions[fnName] % 100 == 0:
            after("; === {:x} calling function: {} ({}) ({})".format(userData["currAddr"], fnName,
                                                                     called_functions[fnName], [hex(a) for a in args]))
            last_called_function = fnName


def memHook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):
    global readfrom
    global writtento
    global new_address
    global is_writing_proc_address
    global insn_address

    if ida_ida.cvar.inf.min_ea <= memAccessAddress < ida_ida.cvar.inf.max_ea:
        if accessType & 1:
            for ea in range(memAccessAddress, memAccessAddress + memAccessSize):
                writtento.add(ea)
            if is_writing_proc_address:
                print("{:x}: {}".format(memAccessAddress, proc_address[1]))
                LabelAddressPlus(memAccessAddress, proc_address[1])
        else:
            for ea in range(memAccessAddress, memAccessAddress + memAccessSize):
                readfrom.add(memAccessAddress)

    if verbose_mode or new_address:
        if ida_ida.cvar.inf.min_ea <= memAccessAddress < ida_ida.cvar.inf.max_ea:
            if accessType & 1:
                memValue =  mask_bytes(bytearray_to_int(emu_helper.getEmuBytes(memAccessAddress, memAccessSize)), memAccessSize) \
                        +   " => " + mask_bytes(memValue, memAccessSize)

                _type = "write"
            else:
                _type = "read "
                memValue = mask_bytes(bytearray_to_int(emu_helper.getEmuBytes(memAccessAddress, memAccessSize)), memAccessSize)

            out("                mem: {} [0x{:x}] {:s} {}".format(_type, memAccessAddress, 
                                                                        memValue,
                                                                        idc.get_name(memAccessAddress)))

def emu_commit():
    for a in GenericRanger(writtento, True):
        print("{} - {} ({})".format(hex(a.start), hex(a.last), len(a)))
        put_bytes(a.start, bytes(emu_helper.getEmuBytes(a.start, len(a))))

def emu_patch():
    for a in GenericRanger(writtento, True):
        print("{} - {} ({})".format(hex(a.start), hex(a.last), len(a)))
        put_bytes(a.start, bytes(emu_helper.getEmuBytes(a.start, len(a))))



EaseCode
def save_emu_dump():
    file_put_contents_bin('WinTraffSingle-Copy-Patch3-emu.exe', emu_helper.getEmuBytes(emu_helper.analysisHelper.getMinimumAddr(), emu_helper.analysisHelper.getMaximumAddr() - emu_helper.analysisHelper.getMinimumAddr()))

def save_ida_dump():
    file_put_contents_bin('WinTraffSingle-Copy-Patch3.exe', get_bytes(emu_helper.analysisHelper.getMinimumAddr(), emu_helper.analysisHelper.getMaximumAddr() - emu_helper.analysisHelper.getMinimumAddr()))


def emu_sub(fn, count=10000, verbose=None, registers=None, stack=None):
    if registers is None:
        registers = {}
    global abort
    global called_functions
    global functions
    global emu_helper
    global last_count
    global max_count
    global verbose_mode
    global visited
    global visited_area

    if verbose is not None:
        verbose_mode = verbose

    ea = get_ea_by_any(fn)
    fnLoc = ea
    GetFuncName(ea)
    called_functions = defaultdict(int)
    visited = set()
    visited_area = set()
    functions = set()

    emu_helper.emulateFrom(
        fnLoc,
        # registers = {"arg1": 0xaa, "arg2": 0xbb, "arg3": 0xcc, "arg4": 0xdd},
        registers=registers,
        skipCalls=False,
        callHook=callHook,
        memAccessHook=memHook,
        instructionHook=insnHook,
        count=count,
        stack=stack
    )

    return emu_helper.getRegVal("eax")


def joaat_demo(argv):
    """ demo """
    global emu_helper
    # requires a joaat function to be labelled joaat
    if eax('joaat'):
        out("emulating range")
        emu_helper.emulateRange(
            emu_helper.analysisHelper.getNameAddr("aligned_joaat"),
            registers={"arg1": argv[0], "arg2": argv[1]},
        )
        out("getting result")
        return emu_helper.getRegVal("eax")
    else:
        return 0

F_GRANULARITY = 0x8	# If set block=4KiB otherwise block=1B
F_PROT_32 = 0x4		# Protected Mode 32 bit
F_LONG = 0x2		# Long Mode
F_AVAILABLE = 0x1 	# Free Use
A_PRESENT = 0x80	# Segment active
A_PRIV_3 = 0x60		# Ring 3 Privs
A_PRIV_2 = 0x40		# Ring 2 Privs
A_PRIV_1 = 0x20		# Ring 1 Privs
A_PRIV_0 = 0x0		# Ring 0 Privs
A_CODE = 0x10		# Code Segment
A_DATA = 0x10		# Data Segment
A_TSS = 0x0		# TSS
A_GATE = 0x0		# GATE
A_EXEC = 0x8		# Executable
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2
A_DIR_CON_BIT = 0x4
S_GDT = 0x0		# Index points to GDT
S_LDT = 0x4		# Index points to LDT
S_PRIV_3 = 0x3		# Ring 3 Privs
S_PRIV_2 = 0x2		# Ring 2 Privs
S_PRIV_1 = 0x1		# Ring 1 Privs
S_PRIV_0 = 0x0		# Ring 0 Privs

def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret

def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xffff;
    to_ret |= (base & 0xffffff) << 16;
    to_ret |= (access & 0xff) << 40;
    to_ret |= ((limit >> 16) & 0xf) << 48;
    to_ret |= (flags & 0xff) << 52;
    to_ret |= ((base >> 24) & 0xff) << 56;
    return struct.pack('Q',to_ret)

def write_gdt(uc, gdt, mem):
    for idx, value in enumerate(gdt):
        offset = idx * GDT_ENTRY_SIZE
        uc.mem_write(mem + offset, value)

CODE_ADDR = 0x40000
CODE_SIZE = 0x1000
CODE = 'some code bytes here'

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

SEGMENT_ADDR = 0x5000
SEGMENT_SIZE = 0x1000


if "emu_helper" not in globals():
    import unicorn
    from unicorn.x86_const import *
    out("constructing helper")
    emu_helper = flare_emu.EmuHelper()
    uc = emu_helper.uc
    #  uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(GDT_ADDR, GDT_LIMIT)
    uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
    #  uc.mem_map(CODE_ADDR, CODE_SIZE)


    # sfink: unsure what these values should actually be
    GS_SEGMENT_ADDR = 0
    GS_SEGMENT_SIZE = 0xfffff000
    # Create the GDT entries
    gdt = [create_gdt_entry(0,0,0,0) for i in range(31)]
    gdt[15] = create_gdt_entry(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

    gdt[16] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment

    gdt[17] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_CODE | A_CODE_READABLE | A_EXEC | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Code Segment

    gdt[18] = create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment

    write_gdt(uc, gdt, GDT_ADDR)

    # Fill the GDTR register
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt)*GDT_ENTRY_SIZE-1, 0x0))

    # Set the selector
    selector = create_selector(15, S_GDT | S_PRIV_3)
    uc.reg_write(UC_X86_REG_GS, selector)
    selector = create_selector(16, S_GDT | S_PRIV_3)
    uc.reg_write(UC_X86_REG_DS, selector)
    selector = create_selector(17, S_GDT | S_PRIV_3)
    uc.reg_write(UC_X86_REG_CS, selector)
    selector = create_selector(18, S_GDT | S_PRIV_0)
    uc.reg_write(UC_X86_REG_SS, selector)
else:
    out("using existing helper")

if __name__ == "__main__":
    #  eh = flare_emu.EmuHelper()
    #  eh.emulateBytes(bytes(hex_pattern("66 90")))
    #  eh.iterate(eh.analysisHelper.getNameAddr("aligned_joaat"), iterateCallback)
    out("The Hash of 'a_c_cat_01' is: {:x}".format(joaat_demo([b"a_c_cat_01", 0])))
