from idc import *
import idaapi
import idautils
import struct
from binascii import unhexlify, hexlify
import os, sys, json
import ctypes
# from sfcommon import *
import itertools
from keypatch import Keypatch_Asm
kp = Keypatch_Asm(KS_ARCH_X86, KS_MODE_64)

from execfile import make_refresh
refresh_obfu_helpers = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))


def GetSize(ea):
    """
    Get instruction size

    @param ea: linear address of instruction

    @return: number of bytes, or None
    """
    inslen = MyGetInstructionLength(ea)
    if inslen == 0:
        return None
    return inslen

#  def MakeCodeAndWait(ea, force = False, comment = ""):
    #  """
    #  MakeCodeAndWait(ea)
        #  Create an instruction at the specified address, and Wait() afterwards.
        #  
        #  @param ea: linear address
        #  
        #  @return: 0 - can not create an instruction (no such opcode, the instruction
        #  would overlap with existing items, etc) otherwise returns length of the
        #  instruction in bytes
    #  """
#  
    #  if Byte(ea) == 0xcc:
        #  print("0x%x: %s can't make 0xCC into code" % (ea, comment))
        #  return 0
#  
    #  insLen = MakeCode(ea)
    #  if insLen == 0:
        #  if force:
            #  print("0x%x: %s %s" % (ea, comment, GetDisasm(ea)))
            #  count = 0
            #  # This should work, as long as we are not started mid-stream
            #  while not insLen and count < 16: #  and idc.next_head(ea) != NextNotTail(ea):
                #  count += 1
                #  MyMakeUnknown(ItemHead(ea), count, 0)
                #  Wait()
                #  insLen = MakeCodeAndWait(ea)
                #  #  print("0x%x: MakeCodeAndWait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
            #  if count > 0:
                #  print("0x%x: MakeCodeAndWait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, GetDisasm(ea + count)))
    #  #  print("0x%x: MakeCodeAndWait returning %i" % (ea, count))
    #  idaapi.Wait()
    #  return insLen

"""
TODO: Rewrite
1: JMP  5
5: JMP [rsp+8]

into

1: JMP [rsp+8]
"""

class ObfuFailure(Exception):
    pass

## The Generic Ranger

def GenericRangerPretty(genericRange, sort = False):
    ranges = GenericRanger(genericRange, sort = sort)
    result = ""
    for r in ranges:
        result += "0x%012x..0x%012x\n" % (r.start, r.last);
    return result


def DeleteFunctionNames():
    for fnName in idautils.Functions():
        if idaapi.has_user_name(idc.get_full_flags((fnName))):
            idaapi.del_global_name(fnName)

def DeleteCodeAndData(start = idaapi.cvar.inf.minEA, end = BADADDR):
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    ea = start

    # Brute-force nuke all info from all the heads
    count = 0
    while ea != BADADDR and ea <= end:
        count += 1
        if count > 16384:
            count = 0
            found = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, "48")
        try:
            if not idc.is_unknown(idc.get_full_flags(ea)):
                MyMakeUnknown(ea, idc.next_head(ea) - ea, 1)
            else:
                ea = idc.next_head(ea)
                continue
        except:
            pass

        idaapi.del_local_name(ea)
        idaapi.del_global_name(ea)
        func = idaapi.get_func(ea)
        if func:
            # idaapi.del_func_cmt(func, False)
            # idaapi.del_func_cmt(func, True)
            idaapi.del_func(ea)
        # idaapi.del_hidden_area(ea)
        # seg = idaapi.getseg(ea)
        # if seg:
            # idaapi.del_segment_cmt(seg, False)
            # idaapi.del_segment_cmt(seg, True)
            # idaapi.del_segm(ea, idaapi.SEGDEL_KEEP | idaapi.SEGDEL_SILENT)

        ea = idc.next_head(ea)
        # ea = idaapi.next_head(ea, idaapi.cvar.inf.maxEA)

def DeleteData(start, end):
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    ea = start

    # Brute-force nuke all info from all the heads
    while ea != BADADDR and ea <= end:
        if idc.is_data(idc.get_full_flags(ea)):
            MyMakeUnknown(ea, idc.next_head(ea) - ea, 1)
        # idaapi.del_local_name(ea)
        # idaapi.del_global_name(ea)
        # func = idaapi.get_func(ea)
        # if func:
            # idaapi.del_func_cmt(func, False)
            # idaapi.del_func_cmt(func, True)
            # idaapi.del_func(ea)
        # idaapi.del_hidden_area(ea)
        # seg = idaapi.getseg(ea)
        # if seg:
            # idaapi.del_segment_cmt(seg, False)
            # idaapi.del_segment_cmt(seg, True)
            # idaapi.del_segm(ea, idaapi.SEGDEL_KEEP | idaapi.SEGDEL_SILENT)

        ea = idc.next_head(ea)
        # ea = idaapi.next_head(ea, idaapi.cvar.inf.maxEA)

def DeleteAllHiddenAreas(ea = idaapi.cvar.inf.minEA):
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    # ea = idaapi.cvar.inf.minEA

    hidden_area = idaapi.get_next_hidden_area(ea);
    while hidden_area:
        idaapi.del_hidden_area(hidden_area.start_ea)
        hidden_area = idaapi.get_next_hidden_area(hidden_area.endEA);

    # Brute-force nuke all info from all the heads
    # while ea != BADADDR and ea <= idaapi.cvar.inf.maxEA:
        # if (ea & 0xfffff) == 0:
            # print("0x%x: Clearing hidden areas..." % ea)
        # idaapi.del_local_name(ea)
        # idaapi.del_global_name(ea)
        # func = idaapi.get_func(ea)
        # if func:
            # idaapi.del_func_cmt(func, False)
            # idaapi.del_func_cmt(func, True)
            # idaapi.del_func(ea)
        # idaapi.del_hidden_area(ea)
        # seg = idaapi.getseg(ea)
        # if seg:
            # idaapi.del_segment_cmt(seg, False)
            # idaapi.del_segment_cmt(seg, True)
            # idaapi.del_segm(ea, idaapi.SEGDEL_KEEP | idaapi.SEGDEL_SILENT)

        # ea = idaapi.next_not_tail(ea)

def hideRepeatedBytes(ea):
    # DelHiddenArea(start)
    # HideArea(start, end+1, 'Bytes nulled after de-obfu', 'obfu-start', 'obfu-end', 0)
    # SetHiddenArea(start, 0)
    start = ea
    end = ea
    count = -1
    while end < BADADDR and Byte(start) == Byte(end):
        count += 1
        end += 1
    if count > 1:
        count += 1 # Not sure why this is always short 1
        print("0x%09x - 0x%09x (%id): 0x%x" % (start, end, count, Byte(start)))
        MyMakeUnknown(start, count, DOUNK_DELNAMES)
        MakeArray(start, count)
        HideArea(start, end, ('0x%x bytes nulled after de-obfu' % count), 'obfu-start-nulled', 'obfu-end-nulled', 0)
        SetHiddenArea(start, 0)
    return count

def listAsHex(l):
    try:
        return " ".join(map(lambda x: ("%02x" % x) if isinstance(x, (integer_types, bytearray)) else x, _.flatten(list(l))))
    except TypeError as e:
        print("listasHex: TypeError: {}; l was {}".format(e, l))
        raise e

def listAsHexIfPossible(l):
    try:
        listAsHex(l)
    except TypeError as e:
        return ", ".join([str(x) for x in _.flatten([l])])

def listAsHexWith0x(l):
    return " ".join(map(lambda x: ("0x%02x" % x) if isinstance(x, (integer_types, bytearray)) else x, list(l)))

def readDword(array, offset):
    return struct.unpack_from("<I", bytearray(array), offset)[0]

def writeDword(array, offset, word):
    array[offset:offset+4] = bytearray(struct.pack("<I", word))

try:
    import __builtin__ as builtins
    integer_types = (int, long)
    string_types = (str, unicode)
    string_type = unicode
    byte_type = str
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str, bytes)
    byte_type = bytes
    string_type = str
    long_type = int

def IsCode(ea): return (idc.get_full_flags(ea) & idc.MS_CLS) == idc.FF_CODE

def PatchBytes(ea, patch=None, comment=None, code=False):
    """
    @param ea [optional]:           address to patch (or ommit for screen_ea)
    @param patch list|string|bytes: [0x66, 0x90] or "66 90" or b"\x66\x90" (py3)
    @param comment [optional]:      comment to place on first patched line

    @returns int containing nbytes patched

    Can be invoked as PatchBytes(ea, "66 90"), PatchBytes("66 90", ea),
    or just PatchBytes("66 90").
    """

    if 'record_patched_bytes' in globals():
        globals()['record_patched_bytes'].append([ea, patch, comment])

    if isinstance(ea, (list, bytearray) + string_types):
        ea, patch = patch, ea
    if ea is None:
        ea = idc.get_screen_ea()
    # was_code = idc.is_code(idc.get_full_flags(idc.get_item_head(ea)))
    was_code = code or idc.is_code(idc.get_full_flags(ea))
    was_head = code or idc.get_item_head(ea)
    was_func = ida_funcs.get_func(ea)
    if was_func:
        was_func = clone_items(was_func)

    if isinstance(patch, str):
        # unicode for py3, bytes for py2 - but "default" form for
        # passing "06 01 05" type arguments, which is all that counts.
        # -- pass a `bytearray` if you want faster service :)
        def int_as_byte(i, byte_len=0):
            # empty byte container without using
            # py3 `bytes` type
            b = bytearray()
            while byte_len > 0:
                b.append(i & 255)
                i >>= 8
                byte_len -= 1
            for b8bit in b:
                yield b8bit;
        def hex_pattern_as_bytearray(str_list, int8_list=[]): 
            for item in str_list:
                l = len(item)
                if l % 2:
                    raise ValueError("hex must be specified in multiples of 2 characters")
                int8_list.extend(int_as_byte(int(item, 16), l // 2))
            return int8_list
        def hex_pattern_as_list(s): 
            return -1 if '?' in s else int(s, 16)

        if '?' not in patch:
            #  patch = hex_pattern_as_bytearray(patch.split(' '))
            patch = bytearray().fromhex(patch)
        else:
            patch = [-1 if '?'in x else int(x, 16) for x in patch.split(' ')]

    length = len(patch)

    # deal with fixups
    fx = idaapi.get_next_fixup_ea(ea - 1)
    while fx < ea + length:
        idaapi.del_fixup(fx)
        fx = idaapi.get_next_fixup_ea(fx)

    cstart, cend = idc.get_fchunk_attr(ea, idc.FUNCATTR_START), \
                   idc.get_fchunk_attr(ea, idc.FUNCATTR_END)

    if cstart == BADADDR: cstart = ea
    if cend   == BADADDR: cend = 0

    # disable automatic tracing and such to prevent function trucation
    #  with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
    #  old_auto = ida_auto.enable_auto(False)

    #  for _ea in range(ea, ea+length):
        #  MyMakeUnknown(_ea, 1)

    #  code_heads = genAsList( NotHeads(ea, ea + length + 16, IsCode) )
    # [0x140a79dfd, 0x140a79e05, 0x140a79e09, 0x140a79e0a]
    if isinstance(patch, bytearray):
        # fast patch
        idaapi.patch_bytes(ea, byte_type(patch))
        if 'helper' in globals() and hasattr(globals()['helper'], 'writeEmuMem'):
            print("[PatchBytes] also writing to writeEmuMem")
            helper.writeEmuMem(ea, patch)
        if comment:
            Commenter(ea, 'line').add(comment)
    else:
        if comment:
            Commenter(ea, 'line').add(comment)
        # slower patch to allow for unset values
        [idaapi.patch_byte(ea+i, patch[i]) for i in range(length) if patch[i] != -1]
        if 'helper' in globals() and hasattr(globals()['helper'], 'writeEmuMem'):
            print("[PatchBytes] also writing to writeEmuMem")
            [helper.writeEmuMem(ea+i, bytearray([patch[i]])) for i in range(length) if patch[i] != -1]

    #  if was_code:
        #  if debug: print("was_code")
        #  pos = ea + length
        #  while code_heads:
            #  if code_heads[0] < pos:
                #  code_heads = code_heads[1:]
            #  else:
                #  break
        #  if code_heads:
            #  next_code_head = code_heads[0]
        #  else:
            #  next_code_head = idc.next_head(pos)
        #  if next_code_head > pos:
            #  idaapi.patch_bytes(pos, byte_type(bytearray([0x90] * (next_code_head - pos))))
#  
    if debug: print("ida_auto.plan_and_wait({:#x}, {:#x})".format(ea, ea + length))
    if was_code: EaseCode(ea, ea + length, noFlow=1, forceStart=1, noExcept=1)
    ida_auto.plan_and_wait(ea, ea + length)
        # EaseCode(ea, next_code_head)


    #  ida_auto.enable_auto(old_auto)

        # this may seem superfluous, but it stops wierd things from happening
        #  if was_code: 
            #  remain = len(patch)
            #  cpos = cstart
            #  length = idc.create_insn(cstart)
            #  while length > 0:
                #  remain -= length
                #  cpos += length
                #  if remain <= 0:
                    #  break
                #  length = idc.create_insn(cpos)


    #  if was_code:
        #  idc.auto_wait()
        #  EaseCode(ea, end=ea+length, create=1)
        
            # ida_auto.plan_and_wait(cstart, cend or (cstart + length))
    # ensures the resultant patch stays in the chunk and as code
    #  if was_code: 
        #  ida_auto.plan_and_wait(cstart, cend or (cstart + length))
        #  idc.auto_wait()


    if comment:
        # comment_formatted = "[PatchBytes:{:x}-{:x}] {}".format(ea, ea + length, str(comment))
        comment_formatted = "[PatchBytes] {}".format(str(comment))
        if 'Commenter' in globals():
            Commenter(was_head, 'line').add(comment_formatted)
        else:
            idaapi.set_cmt(was_head, comment_formatted, 0)

    return
    if was_code:
        head = was_head
        while head < ea + length:
            inslen = idc.get_item_size(head)                                  \
                    if idc.is_code(idc.get_full_flags(idc.get_item_head(ea))) \
                    else idc.create_insn(head)
            if inslen < 1:
                break
            head += inslen

    return length

def MakeNop(length):
    if 'NopList' not in MakeNop.__dict__:
        MakeNop.NopList = [ list(bytearray(unhexlify(hex)))
                for hex in [
                        '',
                        '90',
                        '6690',
                        '0f1f00',
                        '0f1f4000',
                        '0f1f440000',
                        '660f1f440000',
                        '0f1f8000000000',
                        '0f1f840000000000',   # Intel recommends these 8 NOPs
                        #  '660f1f840000000000', # AMD recommend three more:
                        #  '66660f1f840000000000',
                        #  '6666660f1f840000000000'
                ]
    ]
    return MakeNop.NopList[length]
    # PatchBytes(ea, MakeNop.NopList(length))
    # return length

def MakeNops(contigCount):
    ## Nop contigCount bytes
    result = []
    while contigCount > 0:
        nopCount = min(contigCount, 8)
        result = result + MakeNop(nopCount)
        contigCount = contigCount - nopCount
    return result

def MakeTerms(length):
    if '_list' not in dir(MakeTerms):
        MakeTerms._list = [ list(bytearray(unhexlify(hex)))
                for hex in [
                        'c3',
                        'f3c3',
                        'c20000',
                        # 'f3c20000',
                ]]
        MakeTerms._len = len(MakeTerms._list)
    result = []
    remain = length
    while remain > 0:
        result.extend(MakeTerms._list[min(remain, MakeTerms._len) - 1])
        remain = length - len(result)

    return result

def PatchNops(ea, count = None, comment="PatchNops"):
    if count is None and ea < 100000:
        ea, count = count, ea
    if ea is None:
        ea = ScreenEA()
    while count > ea:
        count = count - ea
    PatchBytes(ea, MakeNops(count), code=1, comment=comment)
    #  comment_formatted = "[PatchNops] {}".format(ea, str(comment))
    #  idc.auto_wait()
    #  if 'Commenter' in globals():
        #  Commenter(EA(), 'line').add(comment_formatted)
    #  else:
        #  idaapi.set_cmt(was_head, comment_formatted, 0)

def remove_null_sub_jmps():
    """
    Check for **jmp** to nullsub, and replaces with RETN
    """
    for i in range(5000):
        # print("Checking nullsub_%i" % i)
        for fmt in ['nullsub_%i', 'j_nullsub_%i', 'j_j_nullsub_%i']:
            loc = LocByName(fmt % i)
            if loc < BADADDR:
                refs = list(idautils.CodeRefsTo(loc, 1))
                for ref in refs:
                    if GetMnem(ref) == 'jmp' and Byte(ref) == 0xe9:
                        target = GetOperandValue(ref, 0)
                        if target != loc:
                            print("0x%x: wasn't jump to nullsub at %012x" % (ref, loc))
                            continue
                        result = [0xcc] * GetSize(ref)
                        result[0] = 0xc3 # retn
                        PatchBytes(ref, result)
                        print("0x%x: was jmp to nullsub at %012x" % (ref, loc))
                        MakeCodeAndWait(ref)
                        # MakeDword(ref + 1)
                        MakeComm(ref, "was call to nullsub at %012x" % (loc))
                    elif GetMnem(ref) == 'call':
                        # NOP_5 = list(bytearray(b"\x0f\x1f\x44\x00\x00"))
                        # PatchBytes(ref, MakeNop(5));
                        MakeComm(ref, "0x%x: was call to nullsub at %012x" % (ref, loc))
                        # MakeCodeAndWait(ref)
                        MakeComm(ref, "is call to nullsub at %012x" % (loc))
                        print("0x%x: was CALL (?!) to nullsub at %012x" % (ref, loc))
                    else:
                        print("ref %x was a %s, left it alone" % (ref, GetMnem(ref)))

def QueueClear(queue):
    count = -1
    ref = 0
    while ref < BADADDR:
        ref = idaapi.QueueGetType(queue, ref)
        idaapi.QueueDel( queue, ref)
        count += 1
    print("Cleared %i items from queue %i" % (count, queue))

def QueueClearAll():
    queues = [idaapi.Q_noBase, idaapi.Q_noName, idaapi.Q_noFop,
            idaapi.Q_noComm, idaapi.Q_noRef, idaapi.Q_jumps, idaapi.Q_disasm,
            idaapi.Q_head, idaapi.Q_noValid, idaapi.Q_lines, idaapi.Q_badstack,
            idaapi.Q_att, idaapi.Q_final, idaapi.Q_rolled, idaapi.Q_collsn,
            idaapi.Q_decimp, idaapi.Q_Qnum]
    for q in queues:
        QueueClear(q)

def check_misaligned_code(queue, ref, dry_run = 0):
    """
    Checks for misaligned code, indicated by xrefs such as:
        jmp     short near ptr loc_7FF79AB58431+3
    By searching for blah+n, or blah-n, ignoring [blah+/-n]
    Or by using:
        idaapi.QueueGetType(idaapi.Q_head, lowea)
    And now trying:
        idaapi.Q_disasm
    """
    ref = idaapi.QueueGetType(queue, ref)
    if Byte(ref) == 0xCC:
        idaapi.QueueDel( idaapi.Q_disasm, ref)
        return ref + 1

    refFlags = idc.get_full_flags(ref)
    head = ref if idc.is_head(refFlags) else ItemHead(ref)
    flags = idc.get_full_flags(head)
    if idc.is_code(flags):
        print("0x%x: (%02x): %s" % (head, ref - head, GetDisasm(head)))
    if (queue == idaapi.Q_disasm):
        forceAsCode(ref, 8)
        head = ref if idc.is_head(refFlags) else ItemHead(ref)
        flags = idc.get_full_flags(head)
    # Jump(ref)

    if idc.is_code(flags):
        # Jump(head)

        if GetOpType(head, 1) == 0:   # Check for single operand instruction
                                      # (This will be okay for jumps and calls, but
                                      # we'll hit more complex stuff like MOV/LEA)
            if GetOpType(head, 0) == o_near:
                target = GetOperandValue(head, 0)
                # Jump(target)
                if not dry_run:
                    forceAsCode(target, 8)  # 5 is an E9 JMP, the most likely command,
                                            # next most likely commands are 6 bytes
            else:
                print("0x%x" % ref)
                print("Unknown OpType %i" % GetOpType(head, 0))

        # GetDisasm(ea()).find('+')
        # GetDisasm(ea()).find('-')
        return head + MyGetInstructionLength(head)
    elif 0:
        if idc.is_data(idc.get_full_flags(ea - 1)):
            codeLen = MakeCodeAndWait(ea - 1)
            if not codeLen:
                print("0x%x Couldn't convert block into code at (head: 0x%09x)" % (ea, head))
                return None
    elif idc.is_data(flags):
        print("0x%x: Data Problem" % ref)
        return ref + 1
    elif idc.is_unknown(flags):
        print("0x%x: Unknown Problem" % ref)
        return ref + 1
    else:
        print("0x%x: REALLY Unknown Problem" % ref)
        return ref + 1

def patch_everything():
    count = 0x10000 - 2
    try:
        x = obfu.get_next_instruction()
        while True:
            result = x.next()
            count = count + 1
            if count > 0x50000:
                count = 0
                print("Scanning %012x" % result[0])
    except StopIteration:
        print("Finished patch_everything")

def MakeSigned(number, size = 32):
    number = number & (1<<size) - 1
    return number if number < 1<<size - 1 else - (1<<size) - (~number + 1)

def bitsize_unsigned(n):
    for i in [8, 16, 32, 64, 128, 256, 512, 1024]:
        if n < (1<<i) and n > (-1<<i):
            return i

def bitsize_signed(n):
    for i in [8, 16, 32, 64, 128, 256, 512, 1024]:
        if n < (1<<(i-1)) and n > (-1<<(i-1)):
            return i

def bitsize_signed_2(n):
    i = bitsize_unsigned(n)
    j = MakeSigned(n, 32)
    return bitsize_signed(j)

def patch_manual_instruction_rsp(search, replace, original, ea):
    if idc.is_code(idc.get_full_flags(ea)):
        adjustment = MakeSigned(original[len(original) - 1], 8)
        if adjustment > 0:
            SetManualInsn(ea, ("RSP += %i" % adjustment))
        else:
            SetManualInsn(ea, ("RSP -= %i" % (0 - adjustment)))
        return search
    return None

# def patch_lea_rsp_stack_diff(search, replace, original, ea):
    # if not forceAsCode(ea, len(search)):
        # return None
    # if not idc.is_code(idc.get_full_flags(idc.next_head((ea)))):
        # return None
    # if not idc.is_flow(idc.get_full_flags(idc.next_head((ea)))):
        # return None

    # adjustment = MakeSigned(original[len(original) - 1], 8)
    # originalAdjustment = GetSpDiff(idc.next_head(ea))
    # # if not originalAdjustment:
    # #     originalAdjustment = -1
    # if originalAdjustment != None:
        # if adjustment != originalAdjustment:
            # SetSpDiff(idc.next_head(ea), adjustment)
            # print("adjust stack delta from %i to %i @ 0x%09x" % (originalAdjustment, adjustment, ea))
    # return None

def patch_force_as_code(search, replace, original, ea, comment):
    MakeCodeAndWait(ea)
    # slowtrace2(ea, "0x%x" % ea, 20)
    return []

""" rsp/rbp jmp 2
000  mov     rax, [rcx+10h]        ; rax = pArg1
000  mov     ecx, [rax]            ; ecx = *(DWORD *)rax
000  lea     rsp, [rsp-8]          ; push rbp (pt1)
008  mov     [rsp+0], rbp          ; push rbp (pt 2)
008  lea     rbp, sub_7FF7431C03A8 ; rbp = sub_7FF7431C03A8
008  xchg    rbp, [rsp+0]          ; pop rbp; *rsp = sub_7FF7431C03A8
008  lea     rsp, [rsp+8]          ; pop (pt2)
000  jmp     qword ptr [rsp-8]     ; jmp *(rsp - 8) (sub_7FF7431C03A8)

0:  48 8d 2d 77 77 77 77    lea    rbp,[rip+0x77777777]        # 7777777e <_main+0x7777777e>
7:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
b:  48 8d 64 24 08          lea    rsp,[rsp+0x8]
10: e9 88 24 95 fc          jmp    loc_7FF742F88D2E
10: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]

0:  48 8d 2d 77 77 77 77    lea    rbp,[rip+0x77777777]        # 0x7777777e
7:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
b:  48 8d 64 24 08          lea    rsp,[rsp+0x8]
10: e9 77 77 77 77          jmp    0x7777778c
15: 90                      nop

10: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]
14: (bad code)
"""

def colorise_xor(cmd):
    """
    http://malwaremuncher.blogspot.com.au/2012/10/enhancing-ida-pro-part-1-highlighting.html
    """

    if cmd.itype in colorise_xor.xor_instructions:
        # check if different operands
        if cmd.Op1.type != cmd.Op2.type or cmd.Op1.reg != cmd.Op2.reg or cmd.Op1.value != cmd.Op2.value:
            idaapi.set_item_color(cmd.ea, 0xffd2f8)

colorise_xor.xor_instructions = [idaapi.NN_xor, idaapi.NN_pxor, idaapi.NN_xorps, idaapi.NN_xorpd]

# Fixes labels with offsets, eg loc_7ff7+1
def fix_loc_offset(label=None, _new_ea=None):
    """
    fix the target of a stupid jump like `jmp loc_123+1`

    @param label: label (str) or linear address (int)
    @param _new_ea: optional (and pointless) result of `label` + `offset`
    """
    old_ea = eax(string_between('', '+', label))
    new_ea = _new_ea or eax(label)
    #  if loc > ida_ida.cvar.inf.max_ea or loc < ida_ida.cvar.inf.min_ea:
        #  return

    MyMakeUnknown(old_ea, GetInsnLen(new_ea) + new_ea - old_ea)
    MakeCodeAndWait(new_ea, force = 1)
    #  else:
        #  print("0x%x: not code: " % (realLoc))

    return (old_ea, new_ea, new_ea - old_ea)
    # Jump(loc)
    # Sleep(1000)

def FixTargetLabels(ea):
    for target in [GetOperandValue(ea, 0), GetOperandValue(ea, 1)]:
        disasm = GetDisasm(ea)
        if SegName(target) == SegName(ea):
            m = re.search(r'([a-z]+_([A-F0-9]+)\+[A-F0-9]+)', disasm)
            if m:
                listedTarget = int(m.group(2), 16)
                badLabel = m.group(1)
                if listedTarget >= ida_ida.cvar.inf.min_ea:
                    rv = fix_loc_offset(badLabel)
                    Wait()
                    #  MyMakeUnkn(ea, 0)
                    disasm = GetDisasm(ea)
                    if re.search(r'[a-z]+_([A-Z0-9]+)\+', disasm):
                        print("0x%x: Failed to label offset: %s" % (ea, GetDisasm(ea)))
                        raise ObfuFailure("0x%x: Failed to label offset: %s" % (ea, GetDisasm(ea)))
                    #  MakeCodeAndWait(ea)
                    #  disasm = GetDisasm(ea)
                    print("0x%x: Fixed bad label: %s" % (ea, disasm))
                    # MyMakeUnknown(ItemHead(listedTarget), 1, DOUNK_EXPAND | DOUNK_NOTRUNC)
                    # MyMakeUnknown(listedTarget, 1 + target - listedTarget, DOUNK_EXPAND | DOUNK_NOTRUNC)
                    # MakeCodeAndWait(target)
            if not idc.is_code(idc.get_full_flags(target)):
                if not MakeCodeAndWait(target, force = 1):
                    print("0x%x: Jump target %012x not recognised as code" % (ea, target))

# push eax
#   is equiv to
# sub esp, 4
# mov [esp], eax
# http://stackoverflow.com/a/14060554/912236

patch_logs = []
# Patch factory
def generate_log():
    """
    """
    def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops):
        addressList = addressList[:len(search)]
        patch_logs.append(ea)
        print("0x%x: LOG_PATCH: ********** %s ***********" % (ea, patternComment))
    return patch

def find_contig(startIndex, length, addressList):
    nopCount = BADADDR
    for index in xrange(startIndex, len(addressList) - length):
        if (addressList[index + length - 1] - addressList[index] == length - 1):
            nopCount = index - startIndex
            break
    if nopCount == BADADDR:
        print("0x%x: %s contiguous bytes not found at nopCount" % (ea, length))
        return None

    # If initial padding with nops is needed
    result = []
    if nopCount:
        if debug: print("0x%x: Making %i nops" % (addressList[startIndex], nopCount))
        nopAddresses = [addressList[n] for n in range(startIndex, startIndex + nopCount)]
        print("nopAddresses", hex(nopAddresses))
        nopRanges = GenericRanger(nopAddresses, sort = 0, outsort = 0)
        for r in nopRanges:
            print("%i nops" % r.length)
            result += MakeNops(r.length)

    return result

def contig_ranges(addressList, startIndex = 0, length = None):
    addressLen = len(addressList)
    if not length or length > addressLen - startIndex:
        length = addressLen - startIndex
    if length < 2:
        print("COntigCount: %i: %i" % (startIndex, 1))
        return 1

    endIndex = addressLen - 1
    endRange = length

    print("addressLen: %i" % addressLen)
    print("length:     %i" % length)
    print("startIndex  %i" % startIndex)
    print("endIndex    %i" % endIndex)
    print("endRange    %i" % endRange)

    contigCount = BADADDR
    for index in range(startIndex, endRange):
        i = startIndex + index
        print("")
        print("index       %i" % index)
        print("i           %i" % i)
        diff = addressList[i] - addressList[startIndex]
        print("diff        %i" % diff)
        if (diff == index):
            contigCount = index + 1
            print("contigCount %i" % contigCount)
        else:
            break

    print("")
    print("contigCount: %i: %i" % (startIndex, contigCount))
    nextIndex =  startIndex + contigCount
    if nextIndex < endIndex:
        print("nextIndex   %i" % (startIndex + contigCount))
        print("endIndex    %i" % endIndex)
        contig_ranges(addressList, startIndex + contigCount, length - contigCount)

    if contigCount == BADADDR:
        print("0x%x: %contigCount contiguous bytes not found at contigCount" % (ea, length))
        return None

    # If initial padding with nops is needed
    result = []
    if contigCount:
        print("0x%x: Making %i nops" % (addressList[startIndex], contigCount))
        nopAddresses = [addressList[n] for n in range(startIndex, startIndex + contigCount)]
        print("nopAddresses2", str(nopAddresses))
        nopRanges = GenericRanger(nopAddresses)
        for r in nopRanges:
            print("%i nops" % r.length)
            result += MakeNops(r.length)

    return result

def kassemble(string, ea=None, apply=False, arch=None, mode=None, syntax=None):
    """ assemble with keypath
    """
    if type(ea) is str:
        ea, string = string, ea
    if ea is None:
        ea = idc.get_screen_ea()
        if ea == BADADDR:
            ea = 0
    result = kp.assemble(kp.ida_resolve(string, ea), ea, arch, mode, syntax)
    if type(result) is tuple and result[1] > 0:
        if apply:
            PatchBytes(ea, result[0])
            MakeCode(ea)
        return result[0]
    # failed
    return result

def iassemble(string, ea=None, apply=False, arch=None, mode=None, syntax=None):
    """ try to assemble with keypath, then ida, then nasm
    """
    if type(ea) is str:
        ea, string = string, ea
    if ea is None:
        ea = idc.get_screen_ea()
        if ea == BADADDR:
            ea = 0

    string = ida_resolve(string)
    result = kp.assemble(kp.ida_resolve(string, ea), ea, arch, mode, syntax)
    if type(result) is tuple and result[1] > 0:
        if apply:
            PatchBytes(ea, result[0])
            MakeCode(ea)
        return result[0]
    result = qassemble(ea, string, apply=apply)
    if type(result) is tuple and result[1] > 0:
        if apply:
            PatchBytes(ea, result[0])
            MakeCode(ea)
        return result[0]
    result = nassemble(string, ea, apply=apply)
    if type(result) is tuple and result[1] > 0:
        if apply:
            PatchBytes(ea, result[0])
            MakeCode(ea)
        return result[0]
    raise ObfuFailure("couldn't assemble %s" % ida_resolve(string))

def ida_resolve(assembly):
    def rename_if_possible(match):
        name = match.group(1)
        # dprint("[rename_if_possible] match.group(0), match.group(1)")
        if debug: print("[rename_if_possible] match.group(0):{}, match.group(1):{}".format(match.group(0), match.group(1)))
        if name.endswith(':'):
            return name
        
        ea = idc.get_name_ea_simple(name)
        if IsValidEA(ea):
            return hex(ea)
        return name

    def _resolve(assembly):
        # assembly = re.sub(r'(?<=[^\w])([a-zA-Z@$%&().?:_\[\]][a-zA-Z0-9@$%&().?:_\[\]]+)(?=[ *+-\]]|$)', rename_if_possible, assembly)
        # assembly = re.sub(r'(?<!\w)([a-zA-Z@$%&().?:_\[\]][a-zA-Z0-9@$%&().?:_\[\]]+)(?=[ *+-\]]|$)', rename_if_possible, assembly)
        assembly = re.sub(r'(?<!\w)([a-zA-Z@$%&().?:_\[\]][a-zA-Z0-9@$%&().?:_\[]+)(?=[ *+-\]]|$)', rename_if_possible, assembly)
        return assembly

    _mnem = list(assembly.partition(' '))
    if not _mnem[1]:
        return assembly
    _operands = [x for x in _mnem[2].partition(', ') if x and x != ', ']
    # _operands = [_resolve(x) for x in _operands]
    _mnem[2] = ", ".join(_operands)
    return "".join(_mnem)


def nassemble(ea, string = None, apply=None):
    """ assemble with nasm

    :param ea: target address
    :param string: assembly, seperated by ; or \\n
    :param apply: patch result to target address
    :throws RelocationAssemblerError if cannot assemble
    :returns list(int) of assembled bytes
    """
    if type(ea) in (str, list):
        ea, string = string, ea
    if ea == 1 or ea is True:
        ea, apply = apply, ea
    if ea is None:
        ea = idc.get_screen_ea()
        if ea == BADADDR:
            ea = 0

    if isinstance(string, list):
        string = "\n".join(string)
    string = "\n".join(string.split(';'))
    if len(string.strip()) == 0:
        return []
    result = nasm64(ea, ida_resolve(string))
    if obfu_debug: print("[nassemble] result:{}".format(result))
    if result[0]:
        #  r = bytes_as_hex(result[1])
        r = result[1]['output']
        # dprint("[debug] result[1]['output']")
        
        if apply:
            length = len(r)
            #  print("length: {}".format(length))
            next = ea + length
            if IsTail(next):
                #  print("idc.is_tail({:x})".format(next))
                nextInsn = idc.next_head(next)
            else:
                #  print("idc.is_not tail({:x})".format(next))
                nextInsn = next
            #  print("nextInsn: {:x}".format(nextInsn))
            #  with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
                #  MyMakeUnknown(ea, length, DOUNK_EXPAND | ida_bytes.DELIT_NOTRUNC)
            # PatchBytes(ea, r + bytes(MakeNops(nextInsn - next)))
            PatchBytes(ea, r)
                # print("PatchNops({:x}, {})".format(next, nextInsn - next))
                # PatchNops(next, nextInsn - next)
                # idc.auto_wait()
            # idc.plan_and_wait(ea, nextInsn)
            # forceCode(ea, nextInsn) # , nextInsn) # , ea + nextInsn)
            # idc.auto_wait()
            EaseCode(ea, noExcept=1, forceStart=1)
            #  forceCode(ea, nextInsn) # , nextInsn) # , ea + nextInsn)
            #  forceCode(nextInsn)
                #  for e in range(ea, nextInsn):
                    #  print("makingCode", hex(e))
                    #  ida_ua.create_insn(e)
        return hex_pattern(bytes_as_hex(r))
    raise ObfuFailure("0x%x: couldn't nassemble: '%s' - %s" % (ea, string, result[1]))
    return None

def qassemble(ea, string = None, apply=False):
    """ assemble with ida
    """
    if type(ea) is str:
        ea, string = string, ea
    if ea is None:
        ea = idc.get_screen_ea()
        if ea == BADADDR:
            ea = 0

    result = idautils.Assemble(ea, string)
    if result[0]:
        if apply:
            PatchBytes(ea, list(bytearray(result[1])))
        return list(bytearray(result[1]))
    #  raise ObfuFailure("0x%x: couldn't qassemble: %s" % (ea, string))
    return None

def assemble_contig(startIndex, length, toAssemble, addressList, clear = False):
    # clear ... idc.del_items, idc.del_value
    if len(addressList) - startIndex < length:
        raise ObfuFailure("0x%x: not enough room left for %i contiguous addresses" % (addressList[startIndex], length))
    
    # test validity of assembly
    if not iassemble(addressList[0], toAssemble):
        raise ObfuFailure("couldn't assemble '%s'" % toAssemble)

    result = find_contig(startIndex, length, addressList)
    if result is None:
        raise ObfuFailure("0x%x: couldn't find %i contiguous addresses" % (addressList[startIndex], length))
    result += iassemble(addressList[len(result) + startIndex], toAssemble)
    return result

#  # Patch factory
#  def generate_patch1(jmpTargetOffset): # , oldRip = 0, newRip = 0, jmpType = 0xE9):
    #  """
    #  Typical Input:
        #  0:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        #  5:  48 89 2c 24             mov    [rsp], rbp
        #  9:  48 8d 2d 00 00 00 00    lea    rbp, [rip+0x0]        # 0x10
        #  10: 48 87 2c 24             xchg   [rsp], rbp
        #  14: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
        #  19: ff 64 24 f8             jmp    [rsp-0x8]
#  
    #  Typical Output:
        #  0:  e9 00 00 00 00          jmp    <target>
        #  5:
#  
        #  offset of jmp target:  jmprip:  :newrip
        #  generate_patch1(0x09 + 3, 0x10, 0x05)
    #  """
    #  # replace=replaceFunction(search, replace, original, ea, addressList, patternComment)
    #  def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops):
        #  addressList = addressList[:len(search)]
        #  # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
        #  # We will fill all these
        #  # result = [0xcc] * 5
        #  # result[0] = jmpType # this might be 0xe8 for CALL
#  
        #  # We're going to cheat a lot, and convert this into a function that
        #  # will work with JMP blocks.
        #  #
        #  # This also means arguments oldRip and newRip will no longer be needed
#  
        #  # if not MakeCodeAndWait(ea):
        #  # forceAsCode(ea, idc.next_head(ea+7)- ea)
        #  i = 0
        #  length = len(search)
        #  # ip += idaapi.as_signed(Dword(ip + 1), 32) + 5
#  
        #  ip = addressList[jmpTargetOffset];
        #  if debug: print("patch: ip: 0x{:x}".format(ip))
        #  if debug: print("patch: ip signed dword: 0x{:x}".format(MakeSigned(idc.get_wide_dword(ip), 32)))
        #  ip += MakeSigned(Dword(ip), 32) + 4
        #  if debug: print("patch: ip + signed: 0x{:x}".format(ip))
        #  # fnName = GetOpnd(ItemHead(addressList[jmpTargetOffset]), 1)
        #  MakeCodeAndWait(ip, force = 1)
        #  fnName = GetTrueName(ip)
        #  if fnName:
            #  fnTarget = ip
        #  else:
            #  fnTarget = BADADDR
#  
        #  if fnTarget == BADADDR:
            #  badIp = ItemHead(addressList[jmpTargetOffset])
            #  FixTargetLabels(badIp)
            #  #  MyMakeUnkn(ip, 0)
            #  #  MakeCodeAndWait(ip)
            #  fnName = GetTrueName(ip)
            #  if fnName:
                #  fnTarget = ip
#  
        #  if fnTarget == BADADDR:
            #  MyMakeUnknown(idc.prev_head(ip), idc.next_head(ip) - idc.prev_head(ip), DOUNK_EXPAND | DOUNK_NOTRUNC)
            #  Wait()
            #  # MakeCodeAndWait(ip, force = 1)
            #  # We don't actually want a function, but we need a label fast.
            #  # (and turns out, that this won't actually give it to us)
            #  MakeCode(ip)
            #  Wait()
            #  if IsCode_(ip):
                #  fnName = ("loc_%X" % ip)
                #  #  MakeName(ip, fnName)
                #  MakeNameEx(ip, fnName, SN_NOWARN)
                #  Wait()
            #  if fnName:
                #  fnTarget = ip
#  
        #  if fnTarget == BADADDR:
            #  print("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (
                #  ea,
                #  GetDisasm(ItemHead(addressList[jmpTargetOffset])),
                #  addressList[jmpTargetOffset],
                #  fnName,
                #  fnTarget,
                #  patternComment))
            #  print("search:   %s" % listAsHex(search))
            #  print("original: %s" % listAsHex(original))
            #  raise ObfuFailure("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (ea, GetDisasm(ItemHead(addressList[jmpTargetOffset])), addressList[jmpTargetOffset], fnName, fnTarget, patternComment))
            #  # Jump(ea) # A poor way to record the location, since it will cause
            #  # IDA to steal focus
            #  return []
#  
        #  # idautils.Assemble only writes to buffer
        #  toAssemble = "jmp " + fnName
        #  #  print("DEBUG: toAssemble: jmp " + fnName)
#  
        #  result = []
        #  result += assemble_contig(0, 5, toAssemble, addressList)
#  
        #  #  print("assembled as " + listAsHex(result) + " for placement at %x" % addressList[0])
        #  #  srsly, why would it be a call - and result[0] is now not necessarily valid as we're searching for contig bytes
        #  #  result[0] = jmpType # this might be 0xe8 for CALL
#  
        #  for i in range(len(search), len(search) - len(result) - 1):
            #  Commenter(addressList[i], 'line').add("[PATCH-INT] %i bytes: %s" % (contigCount, patternComment))
            #  idaapi.del_item_color(addressList[i])
#  
        #  result.extend([0xcc] * (len(search) - len(result)))
        #  print("padded to " + listAsHex(result) + " for placement at %x" % addressList[0])
        #  # DEBUG: dont return the full patch yet, need to sort out proper placement for fragmented output
        #  #  return original
#  
        #  #      a readDword too) for dealing with endian crap.
        #  #
        #  # jmpTarget = readDword(original, jmpTargetOffset)
        #  # adjustTarget = oldRip - newRip
        #  # jmpTarget = jmpTarget + adjustTarget
        #  # result[0] = jmpType # JMP rel32off
        #  # writeDword(result, 1, jmpTarget)
#  
        #  # if len(result) != len(original):
            #  # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
        #  #  while len(result) < len(search):
            #  #  result.append(0xcc)
        #  return result
    #  return patch
#  
#  # Patch Factory
#  #  PUSH does:
#  #
#  #  ESP := ESP-8  .
#  #  MEMORY[ESP]:=<operandvalue>
#  #  POP does:
#  #
#  #  <operandtarget>:=MEMORY[ESP];
#  #  ESP:=ESP+8
#  def generate_compact_cmov_abs_patch(fn1Offset = 3, fn2Offset = 0x11, conditionOffset = 0x22):
    #  """
#  RSP    OFF CODE                            ASSEMBLY                  TRANSLATION                     SIMPLIFICATION
#  000    0:  55    v-0x03                    push   rbp                rsp[08] = rbp                   x = fn1
#  008    1:  48 bd b0 70 d6 43 01 00 00 00   movabs rbp, fn1           rbp = fn1                       ? jmp fn2
#  008    b:  48 87 2c 24                     xchg   rbp, [rsp]         rsp[08] = fn1; rbp is restored  jmp fn1
#  008    f:  50                              push   rax                rsp[10] = rax
#  010    10: 51                              push   rcx                rsp[18] = rcx
#  018    11: 48 8b 44 24 10                  mov    rax, [rsp+10h]     rax = rsp[08] = fn1
              #  v-0x18
#  018    16: 48 b9 cc 1c 14 43 01 00 00 00   movabs rcx, fn2           rcx = fn2
              #  v-0x22
#  018    20: 48 0f 4d c1                     cmovge rax,rcx            x ? rax = rcx : noop ;
#  018    24: 48 89 44 24 10                  mov    [rsp+10h], rax     rsp[08] = rax = fn1/fn2
#  018    29: 59                              pop    rcx                rcx = rsp[18]; rcx is restored
#  010    2a: 58                              pop    rax                rax = rsp[10]; rax is restored
#  008    2b: c3                              ret                       jmp rsp[08] (fn1/fn2)
#  
#  0000:0000000140CC5141 000 33 D2                                               xor     edx, edx
#  0000:0000000140CC5143 000 48 85 C0                                            test    rax, rax
#  0000:0000000140CC5146 000 55                                                  push    rbp
#  0000:0000000140CC5147 008 48 BD 47 A5 C6 40 01 00 00 00                       mov     rbp, offset loc_140C6A547
#  0000:0000000140CC5151 008 48 87 2C 24                                         xchg    rbp, [rsp]
#  0000:0000000140CC5155 008 50                                                  push    rax
#  0000:0000000140CC5156 010 51                                                  push    rcx
#  0000:0000000140CC5157 018 48 8B 44 24 10                                      mov     rax, [rsp+10h]
#  0000:0000000140CC515C 018 48 B9 4D A5 C6 40 01 00 00 00                       mov     rcx, offset loc_140C6A54D
#  0000:0000000140CC5166 018 48 0F 44 C1                                         cmovz   rax, rcx
#  0000:0000000140CC516A 018 48 89 44 24 10                                      mov     [rsp+10h], rax
#  0000:0000000140CC516F 018 59                                                  pop     rcx
#  0000:0000000140CC5170 010 58                                                  pop     rax
#  0000:0000000140CC5171 008 C3                                                  retn
    #  Conversion from cmov* to j*
    #  0:  48 0f 4d c1             cmovge rax,rcx              48 0f 4d ?? becomes 0f 8d
    #  4:  0f 8d 00 00 00 00       jge    a <_main+0xa>
#  
    #  a:  48 0f 44 c1             cmove  rax,rcx              48 0f 44 ?? becomes 0f 84
    #  e:  0f 84 00 00 00 00       je     14 <_main+0x14>
#  
    #  14: 48 0f 45 ca             cmovne rcx,rdx              48 0f 45 ?? becomes 0f 85
    #  18: 0f 85 00 00 00 00       jne    1e <_main+0x1e>
    #  """
    #  def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops):
        #  addressList = addressList[:len(search)]
        #  i = 0
        #  length = len(search)
        #  if debug:
            #  print("conditionalMnen: {}".format(GetDisasm(addressList[conditionOffset - 2])))
        #  conditionalMnem = GetDisasm(addressList[conditionOffset - 2]).split(None, 1)[0].replace("cmov", "j")
        #  conditionalByte = Byte(addressList[conditionOffset]) + 0x40;
        #  while i < length:
            #  assembled = MakeCodeAndWait(addressList[i])
            #  if not assembled:
                #  assembled = forceAsCode(addressList[i], 15)
            #  if not assembled:
                #  raise ObfuFailure("0x%x: could not codify line 0x%x" % (ea, addressList[i]))
                #  return []
            #  i += assembled
        #  # result = [0xcc]*len(search) # preallocate result with 0xcccccc...
        #  if GetMnem(addressList[1]) != 'mov' or MakeCodeAndWait(addressList[1]) != 10:
            #  raise ObfuFailure("0x%x: 0x%x: incorrectly detected compact movabs: %s" % (ea, addressList[1], GetDisasm(addressList[1])))
            #  return None
        #  target = BADADDR
#  
        #  #        for i in range(len(search) - 11):
        #  #            if (addressList[i + 11 - 1] - addressList[i] == 11 - 1):
        #  #                target = i
        #  #                break
        #  #        if target == BADADDR:
        #  #            print("0x%x: 11 contiguous bytes not found at target" % ea)
        #  #            raise ObfuFailure("0x%x: 11 contiguous bytes not found at target" % ea)
        #  #            return []
        #  #
        #  #        # If initial padding with nops is needed
        #  #        result = []
        #  #        if i:
        #  #            print("Making %i nops" % i)
        #  #            nopAddresses = [addressList[n] for n in range(i)]
        #  #            nopRanges = GenericRanger(nopAddresses)
        #  #            for r in nopRanges:
        #  #                print("%i nops" % r.length)
        #  #                result += MakeNops(r.length)
        #  #
        #  OpOff(addressList[fn1Offset - 2], 1, 0)
        #  OpOff(addressList[fn2Offset - 2], 1, 0)
        #  Wait()
#  
        #  _addr1 = Qword(addressList[fn1Offset])
        #  _addr2 = Qword(addressList[fn2Offset])
#  
        #  in1 = idc.get_item_head(addressList[fn1Offset])
        #  in2 = idc.get_item_head(addressList[fn2Offset])
#  
        #  addr1 = GetOperandValue(in1, 1)
        #  addr2 = GetOperandValue(in2, 1)
#  
        #  if addr1 != _addr1:
            #  err = "ObfuFailure: addr1 != _addr1  0x%x != 0x%x" % (addr1, _addr1)
            #  print(err)
            #  raise ObfuFailure(err)
#  
        #  if addr2 != _addr2:
            #  err = "ObfuFailure: addr2 != _addr2  0x%x != 0x%x" % (addr2, _addr2)
            #  print(err)
            #  raise ObfuFailure(err)
#  
        #  MakeCodeAndWait(addr1, 1)
        #  MakeCodeAndWait(addr2, 1)
        #  fn1 = Name(addr1)
        #  fn2 = Name(addr2)
#  
        #  #  if len(fn1) == 0:
            #  #  err = "0x%x: Couldn't parse fn1 (0x%x) at 0x%x processing pattern '%s'" % (ea, addr1, addressList[fn1Offset], patternComment)
            #  #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            #  #  print("ObfuFailure: %s" % err)
            #  #  raise ObfuFailure(err)
            #  #  return []
#  
        #  #  if len(fn2) == 0:
            #  #  err = "0x%x: Couldn't parse fn2 (0x%x) 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, addr2, (addressList[fn2Offset] - 2), GetDisasm((addressList[fn2Offset]) - 2), addressList[fn2Offset], fn1Offset, fn2Offset, conditionOffset, patternComment)
            #  #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            #  #  print("ObfuFailure: %s" % err)
            #  #  raise ObfuFailure(err)
            #  #  return []
#  
        #  toAssemble = conditionalMnem + " " + ("%xh" % addr2)
        #  print("0x%x: Assembling %s for 0x%x" % (ea, toAssemble, addressList[0]))
        #  result = assemble_contig(0, 6, toAssemble, addressList)
#  
        #  toAssemble = "jmp " + ("%xh" % addr1)
        #  print("0x%x: Assembling %s for 0x%x (offset %i)" % (ea, toAssemble, addressList[len(result)], len(result)))
        #  asm = assemble_contig(len(result), 5, toAssemble, addressList)
        #  result += asm
#  
        #  #  raise ObfuFailure("test here")
#  
        #  #        asm = qassemble(addressList[len(result)], toAssemble)
        #  #        if not asm: #  or len(asm) != 6:
        #  #            print("0x%x: Expected 2-6 byte list from assembling '%s', got: '%s'. Was intending to change conditional to '0x%02x'" % (addressList[0], toAssemble, str(asm), conditionalByte))
        #  #            raise ObfuFailure("0x%x: Expected 6 byte list from assembling '%s', got: '%s'. Was intending to change conditional to '0x%02x'" % (addressList[0], toAssemble, str(asm), conditionalByte))
        #  #            return []
        #  #
        #  #        result += asm
        #  #
        #  #        toAssemble = "jmp %s" % fn1
        #  #        asm = qassemble(addressList[len(result)], toAssemble)
        #  #        if not asm:
        #  #            print("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
        #  #            raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
        #  #            return []
        #  #
        #  #        result += asm
#  
        #  #  while len(result) < len(search):
            #  #  result.append(0xcc)
            #  #  idaapi.del_item_color(addressList[len(result)-1])
            #  #  Commenter(addressList[len(result) - 1], 'line').add("[PATCH-INT] mini-cmov")
#  
        #  for i in range(len(search), len(search) - len(result) - 1):
            #  Commenter(addressList[i], 'line').add("[PATCH-INT] %i cmov: %s" % (contigCount, patternComment))
            #  idaapi.del_item_color(addressList[i])
#  
        #  result.extend([0xcc] * (len(search) - len(result)))
#  
        #  if Byte(addressList[len(search) - 1] + 1) == 0xe9:
            #  if len(list(idautils.CodeRefsFrom(addressList[len(search) - 1] + 1, 1))) == 0:
                #  #  PatchBytes(addressList[len(search) - 1] + 1, [0xcc] * 5, patternComment)
                #  idaapi.del_item_color(addressList[len(search)-1] + 1)
                #  Wait();
                #  Commenter(addressList[len(search) - 1] + 1, 'line').add("[PATCH-INT] fake jump component of cmovz/nz")
#  
        #  return result
    #  return patch
#  # Patch factory
#  def generate_cmov_abs_patch(fn1Offset, fn2Offset, condition = "jnz"):
    #  """
    #  BEFORE                                                               AFTER
    #  0: 028 48 bd 3c 9f c6 40 01+   movabs rbp,0x140c69f3c                fn1 = Qword(0x02)
    #  a: 028 48 87 2c 24             xchg   QWORD PTR [rsp],rbp            fn2 = Qword(0x27)
    #  e: 028 48 8d 64 24 f8          lea    rsp,[rsp-0x8]                  jne j_fn1
    #  13:030 48 89 0c 24             mov    QWORD PTR [rsp],rcx            jmp fn2
    #  17:030 48 8d 64 24 f8          lea    rsp,[rsp-0x8]            j_fn1:
    #  1c:038 48 89 14 24             mov    QWORD PTR [rsp],rdx            jmp fn1
    #  20:038 48 8b 4c 24 10          mov    rcx,QWORD PTR [rsp+0x10]
    #  25:038 48 ba 21 9f c6 40 01+   movabs rdx,0x140c69f21
    #  2f:038 48 0f 45 ca             cmovne rcx,rdx
    #  33:038 48 89 4c 24 10          mov    QWORD PTR [rsp+0x10],rcx
    #  38:038 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    #  3d:030 48 8b 54 24 f8          mov    rdx,QWORD PTR [rsp-0x8]
    #  42:030 48 8b 0c 24             mov    rcx,QWORD PTR [rsp]
    #  46:030 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    #  4b:028 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    #  50:020 ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]
    #  54:    90                      nop
#  
    #  Conversion from cmov* to j*
    #  0:  48 0f 4d c1             cmovge rax,rcx              48 0f 4d ?? becomes 0f 8d
    #  4:  0f 8d 00 00 00 00       jge    a <_main+0xa>
    #  a:  48 0f 44 c1             cmove  rax,rcx              48 0f 44 ?? becomes 0f 84
    #  e:  0f 84 00 00 00 00       je     14 <_main+0x14>
    #  14: 48 0f 45 ca             cmovne rcx,rdx              48 0f 45 ?? becomes 0f 85
    #  18: 0f 85 00 00 00 00       jne    1e <_main+0x1e>
#  
        #  48 0f 42 d8             cmovb   rbx, rax
        #  0F 82 00 00 00 00       jb      near ptr sub_140A2F5AC
#  
    #  """
    #  def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops):
        #  addressList = addressList[:len(search)]
        #  i = 0
        #  length = len(search)
        #  while i < length:
            #  assembled = MakeCodeAndWait(addressList[i])
            #  if not assembled:
                #  assembled = forceAsCode(addressList[i], 15)
            #  if not assembled:
                #  raise ObfuFailure("0x%x: could not assemble line 0x%x" % (ea, addressList[i]))
                #  return []
            #  i += assembled
        #  # result = [0xcc]*len(search) # preallocate result with 0xcccccc...
        #  if GetMnem(addressList[9]) != 'mov' or MakeCodeAndWait(addressList[9]) != 10:
            #  print("0x%x: incorrectly detected movabs: 0x%x: %s" % (ea, addressList[9], GetDisasm(ea)))
            #  return None
#  
        #  # Step #1: Move the assembly code above the addressList checking
        #  #          code, as sometimes we don't even need 17 bytes (short jumps)
        #  #
        #  # Thought #1: Just calculate all the instructions as being at 0 to see
        #  # how big it's going to be using short jumps... no that won't work, as
        #  # the jumps will be to totally distance parts of the chunked code... if
        #  # it wasn't chunked, then we wouldn't have the issue with contiguous
        #  # bytes.
        #  #
        #  # Thought #2: We could use a translation of addressList to
        #  # addressListWithNops and keep the old logic.
        #  #
        #  # Thought #3: Just write the results in a list of instructions, leaving
        #  # them unresolved (not assembled) where appropriate, and figure it out
        #  # later.
        #  #
        #  # result = [0x48, 0x8d, 0x64, 0x24, 0x08, 0x75, 0x05] # lea rsp,[rsp+0x08]
#  
        #  # If initial padding with nops is needed
#  
        #  # Implementation of thought #3
        #  result = []
        #  #
        #  # Thought #4: Add the extra 9 bytes that alter lea to the pattern, and
        #  # save writing the adjustment out
        #  #
        #  #  result = result + [0x48, 0x8d, 0x64, 0x24, 0x08] # lea rsp,[rsp+8]
        #  #
        #  OpOff(addressList[fn1Offset - 2], 1, 0)
        #  OpOff(addressList[fn2Offset - 2], 1, 0)
#  
        #  addr1 = Qword(addressList[fn1Offset])
        #  addr2 = Qword(addressList[fn2Offset])
        #  #  print("fn1Offset: 0x%x" % addr1)
        #  #  print("fn2Offset: 0x%x" % addr2)
        #  Wait()
#  
        #  fn1 = Name(addr1)
        #  fn2 = Name(addr2)
#  
        #  if len(fn1) == 0:
            #  MakeCodeAndWait(addr1, 1)
            #  fn1 = Name(addr1)
        #  if len(fn2) == 0:
            #  MakeCodeAndWait(addr2, 1)
            #  fn2 = Name(addr2)
#  
        #  if len(fn1) == 0:
            #  err = "0x%x: Couldn't parse fn1 at 0x%x processing pattern '%s'" % (ea, addressList[fn1Offset], patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []
#  
        #  #  if len(fn2) == 0:
            #  #  err = "0x%x: Couldn't parse fn2 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, (addressList[fn2Offset] - 2), GetDisasm((addressList[fn2Offset]) - 2), addressList[fn2Offset], fn1Offset, fn2Offset, condition, patternComment)
            #  #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            #  #  print("ObfuFailure: %s" % err)
            #  #  raise ObfuFailure(err)
            #  #  return []
#  
        #  #  ptr = len(result)
#  
        #  toAssemble = "%s %xh" % (condition, addr2)
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
        #  #  ptr = ptr + len(buffer[1])
#  
        #  toAssemble = "jmp %s" % fn1
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
#  
        #  # End of code from below
#  
        #  requiredLen = len(result)
#  
        #  useListEx = False
        #  target = BADADDR
        #  translatedAddressList = []
        #  for i in range(len(search)):
            #  translatedAddressList.append(addressList[i])
#  
        #  #  for i in range(len(search) - requiredLen):
            #  #  if (addressList[i + requiredLen] - addressList[i] == requiredLen):
                #  #  target = i
                #  #  break
#  
        #  r = len(search) - requiredLen + 1
        #  print("range: %i" % r)
        #  for i in range(r):
            #  if (addressList[i + requiredLen - 1] - addressList[i] == requiredLen - 1):
                #  target = i
                #  break
#  
        #  print("target: %i" % target)
#  
        #  if target == BADADDR:
            #  print("0x%x: %i contiguous bytes not found at target with addressList" % (ea, requiredLen))
            #  print(listAsHexWith0x(translatedAddressList))
#  
            #  translatedAddressList = []
            #  for i in range(len(search)):
                #  translatedAddressList.append(addressListWithNops[i])
            #  for i in range(len(search) - 17):
                #  if (addressListWithNops[i + 17] - addressListWithNops[i] == 17):
                    #  target = i
                    #  break
#  
            #  if target == BADADDR:
                #  raise ObfuFailure("0x%x: %i contiguous bytes not found at target with addressListWithNops" % (ea, requiredLen))
                #  return []
#  
            #  raise ObfuFailure("0x%x: %i contiguous WERE found using addressListWithNops, but we haven't coded that yet" % (ea, requiredLen))
            #  useListEx = True
            #  # Now how the fuck are we going to cope with using a list that
            #  # includes nops, when the search patterns all rely on fixed
            #  # positions **without** nops.
            #  #
            #  # Step #1: Move the assembly code above the addressList checking
            #  #          code, as sometimes we don't even need 17 bytes (short jumps)
#  
        #  # Step #1: Move the assembly code above the addressList checking
        #  #          code, as sometimes we don't even need 17 bytes (short jumps)
        #  #
        #  # result = [0x48, 0x8d, 0x64, 0x24, 0x08, 0x75, 0x05] # lea rsp,[rsp+0x08]
#  
        #  # If initial padding with nops is needed
#  
        #  result = []
        #  if i:
            #  if debug: print("Making %i nops" % i)
            #  nopAddresses = [addressList[n] for n in range(i)]
            #  nopRanges = GenericRanger(nopAddresses)
            #  for r in nopRanges:
                #  if debug: print("%i nops" % r.length)
                #  result += MakeNops(r.length)
#  
        #  # We don't need this anymore, as we're replacing the crap that caused loading up of RSP
        #  # result = result + [0x48, 0x8d, 0x64, 0x24, 0x08] # lea rsp,[rsp+8]
        #  addr1 = Qword(addressList[fn1Offset])
        #  addr2 = Qword(addressList[fn2Offset])
        #  #  print("fn1Offset: 0x%x" % addr1)
        #  #  print("fn2Offset: 0x%x" % addr2)
#  
        #  fn1 = Name(addr1)
        #  fn2 = Name(addr2)
#  
        #  if len(fn1) == 0:
            #  MakeCodeAndWait(addr1, 1)
            #  fn1 = Name(addr1)
#  
        #  if len(fn2) == 0:
            #  MakeCodeAndWait(addr2, 1)
            #  fn2 = Name(addr2)
#  
        #  if len(fn1) == 0:
            #  err = "0x%x: Couldn't parse fn1 at 0x%x processing pattern '%s'" % (ea, addressList[fn1Offset], patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []
#  
        #  if len(fn2) == 0:
            #  err = "0x%x: Couldn't parse fn2 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, (addressList[fn2Offset] - 2), GetDisasm((addressList[fn2Offset]) - 2), addressList[fn2Offset], fn1Offset, fn2Offset, condition, patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []
#  
        #  #  ptr = len(result)
#  
        #  toAssemble = "%s %s" % (condition, fn2)
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
        #  #  ptr = ptr + len(buffer[1])
#  
        #  toAssemble = "jmp %s" % fn1
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
        #  #  while len(result) < len(search):
            #  #  result.append(0xcc)
            #  #  idaapi.del_item_color(addressList[len(result)-1])
            #  #  Commenter(addressList[len(result) - 1], 'line').add("[PATCH-INT] cmovz/nz")
#  
        #  for i in range(len(search), len(search) - len(result) - 1):
            #  Commenter(addressList[i], 'line').add("[PATCH-INT] %i cmov: %s" % (contigCount, patternComment))
            #  idaapi.del_item_color(addressList[i])
#  
        #  result.extend([0xcc] * (len(search) - len(result)))
#  
        #  if Byte(addressList[len(search) - 1] + 1) == 0xe9:
            #  if len(list(idautils.CodeRefsFrom(addressList[len(search) - 1] + 1, 1))) == 0:
                #  #  PatchBytes(addressList[len(search) - 1] + 1, MakeNops(5), patternComment)
                #  idaapi.del_item_color(addressList[len(search)-1] + 1)
                #  Wait();
                #  Commenter(addressList[len(search) - 1] + 1, 'line').add("[PATCH-INT] fake jump component of cmovz/nz")
        #  return result
    #  return patch
#  
#  def generate_mov_reg_reg_via_stack_patch():
    #  """
    #  Typical Input:
        #  0:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        #  5:  48 89 0c 24             mov    QWORD PTR [rsp],rcx
        #  9:  4c 8b 0c 24             mov    r9,QWORD PTR [rsp]
        #  d:  48 8d 64 24 08          lea    rsp,[rsp+0x8]
#  
    #  Typical Output:
        #  0:  48 89 D1                mov    rcx,rdx
        #  0:  49 89 C8                mov    r8,rcx
        #  0:  4C 89 C2                mov    rdx,r8
#  
        #  offset of jmp target:  jmprip:  :newrip
        #  generate_patch1(0x09 + 3, 0x10, 0x05)
    #  """
    #  # replace=replaceFunction(search, replace, original, ea, addressList, patternComment, addressListWithNops)
    #  def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops):
        #  addressList = addressList[:len(search)]
        #  # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
        #  # We will fill all these
        #  # result = [0xcc] * 5
        #  # result[0] = jmpType # this might be 0xe8 for CALL
#  
        #  # We're going to cheat a lot, and convert this into a function that
        #  # will work with JMP blocks.
        #  #
        #  # This also means arguments oldRip and newRip will no longer be needed
#  
        #  # if not MakeCodeAndWait(ea):
        #  # forceAsCode(ea, idc.next_head(ea+7)- ea)
        #  i = 0
        #  length = len(search)
        #  # ip += idaapi.as_signed(Dword(ip + 1), 32) + 5
#  
        #  ip = addressList[jmpTargetOffset];
        #  ip += idaapi.as_signed(Dword(ip), 32) + 4
        #  # fnName = GetOpnd(ItemHead(addressList[jmpTargetOffset]), 1)
        #  MakeCodeAndWait(ip, force = 1)
        #  fnName = GetTrueName(ip)
        #  if fnName:
            #  fnTarget = ip
        #  else:
            #  fnTarget = BADADDR
#  
        #  if fnTarget == BADADDR:
            #  badIp = ItemHead(addressList[jmpTargetOffset])
            #  FixTargetLabels(badIp)
            #  #  MyMakeUnkn(ip, 0)
            #  #  MakeCodeAndWait(ip)
            #  fnName = GetTrueName(ip)
            #  if fnName:
                #  fnTarget = ip
#  
        #  if fnTarget == BADADDR:
            #  print("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (
                #  ea,
                #  GetDisasm(ItemHead(addressList[jmpTargetOffset])),
                #  addressList[jmpTargetOffset],
                #  fnName,
                #  fnTarget,
                #  patternComment))
            #  print("search:   %s" % listAsHex(search))
            #  print("original: %s" % listAsHex(original))
            #  raise ObfuFailure("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (ea, GetDisasm(ItemHead(addressList[jmpTargetOffset])), addressList[jmpTargetOffset], fnName, fnTarget, patternComment))
            #  # Jump(ea) # A poor way to record the location, since it will cause
            #  # IDA to steal focus
            #  return []
#  
        #  # In theory (haven't checked documents) idautils.Assemble only writes
        #  # to buffer
        #  toAssemble = "jmp " + fnName
        #  result = assemble_contig(0, toAssemble, 5, addressList)
        #  if not result or len(result) < 2:
            #  # raise Exception("Expected 5 byte list from assembling '%s', got: '%s'" % (toAssemble, str(result)))
            #  raise ObfuFailure("0x%x: Expected 5 byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(result)))
            #  return []
        #  #  result[len(result) -  5] = jmpType # this might be 0xe8 for CALL
#  
        #  #  for i in range(len(search), len(search) - len(result) - 1):
            #  #  Commenter(addressList[i], 'line').add("[PATCH-INT] %i bytes: %s" % (contigCount, patternComment))
            #  #  idaapi.del_item_color(addressList[i])
#  
        #  #  result.extend([0xcc] * (len(search) - len(result)))
#  
        #  #      a readDword too) for dealing with endian crap.
        #  #
        #  # jmpTarget = readDword(original, jmpTargetOffset)
        #  # adjustTarget = oldRip - newRip
        #  # jmpTarget = jmpTarget + adjustTarget
        #  # result[0] = jmpType # JMP rel32off
        #  # writeDword(result, 1, jmpTarget)
#  
        #  # if len(result) != len(original):
            #  # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
        #  #  while len(result) < len(search):
            #  #  result.append(0xcc)
        #  return result
    #  return patch
#  
#  #unused
#  def patch_brick_jmp_jz(search, replace, original, ea, addressList):
    #  addressList = addressList[:len(search)]
    #  # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
    #  # result = [0xcc] * 5
    #  #
    #  #
    #  #
    #  # So we can read/write by offset using search and replace as char arrays
    #  # result[0] = jmpType # this might be 0xe8 for CALL
    #  #
#  
    #  # so, um, 0x02 and 0x0e to 0x11 and 0x32 for 8 bytes each.
    #  # (excercise for reader a.k.a. brick) - un maffinnify this:
#  
    #  # 0:  48 b8 11 11 11 11 11 11 01 00   movabs rax,0x1111111111111
    #  # a:  74 0a                           je     16 <skip>
    #  # c:  48 b8 22 22 22 22 22 22 02 00   movabs rax,0x2222222222222
    #  # <skip>:
    #  # 16: ff e0                   jmp    rax
#  
    #  result[0] = 0x48
    #  result[1] = 0xb8
    #  #
    #  # so, um, 0x02 and 0x0e to 0x11 and 0x32 for 8 bytes each.
    #  result[2:8] = original[0x0e:8]
#  
    #  result[0xa] = 0x74
    #  result[0xb] = 0x0a;
    #  # result[0xc] = original[0x32]
    #  # ...
    #  # result[0xc+8] = result[0x32+8]
    #  # this maybe will work
    #  result[0xc:8] = original[0x32:8]
#  
    #  # fill remainder with 0xcc
    #  #  while len(result) < len(search):
        #  #  result.append(0xcc)
#  
    #  # A nice solution would have readQWord or somesuch
    #  #  def readDword(array, offset):
        #  #  return struct.unpack_from("<I", bytearray(array), offset)[0]
    #  #
    #  #  def writeDword(array, offset, word):
        #  #  array[offset:offset+4] = bytearray(struct.pack("<I", word))
#  
    #  # jmpTarget = readDword(original, jmpTargetOffset)
    #  # writeDword(result, 1, jmpTarget)
#  
    #  # if len(result) != len(original):
        #  # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
    #  return result

# TODO
# Here's a relatively simple JMP seperated obfu
#
# Python>slowtrace2()
#
# .text:7ff742f4741d     #  0  loc_7FF742F4741D:
# .text:7ff742f4741d     #  1   RSP -= 8
# .text:7ff742f47422     #  2   jmp     loc_7FF745CD39AF; jumping to 7ff745cd39af
# .text:7ff745cd39af     #  3  loc_7FF745CD39AF:
# .text:7ff745cd39af     #  4   mov     [rsp], rbp
# .text:7ff745cd39b3     #  5   lea     rbp, loc_7FF746382755
# .text:7ff745cd39ba     #  6   jmp     loc_7FF743C9D21D; jumping to 7ff743c9d21d
# .text:7ff743c9d21d     #  7  loc_7FF743C9D21D:
# .text:7ff743c9d21d     #  8   xchg    rbp, [rsp+0]
# .text:7ff743c9d221     #  9   RSP += 8
# .text:7ff743c9d226 -08 # 10   jmp     qword ptr [rsp-8]; Can't follow opType0 o_displ; BREAK
#
#
# Remove the JMPs
#
# .text:7ff742f4741d     #  0  loc_7FF742F4741D:
# .text:7ff742f4741d     #  1   RSP -= 8
# .text:7ff745cd39af     #  4   mov     [rsp], rbp
# .text:7ff745cd39b3     #  5   lea     rbp, loc_7FF746382755
# .text:7ff743c9d21d     #  8   xchg    rbp, [rsp+0]
# .text:7ff743c9d221     #  9   RSP += 8
# .text:7ff743c9d226 -08 # 10   jmp     qword ptr [rsp-8]; Can't follow opType0 o_displ; BREAK
#
# Deobfu
#
# .text:7ff74xxxxxxx     #  0   jmp     loc_7FF746382755 (5 bytes)
#
# Where to put it?  We can replace any JMP, and since it's a JMP seperated
# obfu there's no shortage of those.  Should consider the stack pointer though.
# In this example, RSP is decrement in block 1, set in block 2, and incremened
# in block 3 (then JMP [rsp] occurs).
#
# Since the more blocks involved, the harder to coagulate the blocks, it may be
# easier to detect a shorter sig that in this case would start from instruction
# 4 or 5.  5 would probably be preferable if we are ignoring the previous value
# of RBP since in would allow us to match in cases when the JMP boundary causes
# seperation to occur inbetween instructions 4 and 5.
#
# Is the value in RBP important?  In this case, the actual target location starts
#
# .text:00007FF746382755        mov     rax, [rbp+58h]
#
# So if our goal is perfect de-obfu, then we need to keep RBP in tact.  However,
# if our goal is just to enable easy navigation and IDA control flow, we could
# trash RBP (indeed, trash RSP) and just leave a comment noting the fact.

def bit_pattern(hexLists):
    result = [ ]
    # Convert a string into a list, just so we can process it
    if not isinstance(hexLists, list):
        hexLists = [hexLists]
    for i, l in enumerate(hexLists):
        if i > 0:
            raise RuntimeError("bit_pattern can only handle 1 list item rn")

        with BitwiseMask() as bm:
            #  for pattern in braceexpand('{70..77}'):
                #  bm.add_list(bm._h_hex_pattern(pattern))
            #  for pattern in braceexpand('{70..77} 01110... 0b01110... 70/f8'):
                #  bm.add_list(bm._h_hex_pattern(pattern))
            bm.add_list(l)
            # pprint.pprint({ 'value': binlist(bm.value), 'mask ': binlist(bm.mask), '_ones': binlist(bm._set), '_zero': binlist(bm._clear), 'trnry': bm.tri})
            return bm

def braceexpandlist(be):
    return list(braceexpand(be))

def braceform(s):
    def prep(s):
        s = s.replace(',', '\\,')
        split = s.split('|')
        s = ','.join([x.strip() for x in split])
        if len(split) > 1:
            s = '{' + s + '}'
        return s

    return '; '.join([prep(x) for x in s.split('\n') if x.strip()])

# Test single replacement with:
# obfu._patch(address)

# Apply long patches via binary searches, bonus: maybe find new
# code sections! (Well, that's not true because we check if it's
# marked as code before applying the patch.
def findAndPatch(findStart = 0, foundEnd = BADADDR):# {{{
    if not findStart:
        findStart = LocByName("__ImageBase")
        if findStart == BADADDR:
            findStart = 0

    found = findStart
    print("mini-cmov")
    while found < foundEnd:
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "55 48 bd ?? ?? ?? ?? 01 00 00 00 48 87 2c 24 ?? ?? 48 8b ?? 24 10 48 ?? ?? ?? ?? ?? 01 00 00 00 48 0f ?? ?? 48 89 ?? 24 10 ?? ??")
        if not found: break
        MakeCodeAndWait(found)
        obfu._patch(found)

    return

    found = findStart
    print("patch")
    while found < foundEnd:
        # found = FindBinary(found + 1, 1, "48 8D 64 24 F8 48 89 2C 24 48 8D 2D ? ? ? ? 48 87 2C 24 48 8D 64 24 08 FF 64 24 F8")
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 F8 48 89 2C 24")
        if not found: break
        forceAsCode(found, 9)
        obfu._patch(found)

    found = findStart
    print("patch")
    while found < foundEnd:
        # found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 89 6c 24 f8 48 8d 64 24 f8 48 8d 2d ? ? ? ? 48 87 2c 24 48 8d 64 24 08 ff 64 24 f8")
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 89 6c 24 f8 48 8d 64 24")
        if not found: break
        forceAsCode(found, 9)
        obfu._patch(found)

    found = findStart
    while found < foundEnd:
        # found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 F8 48 89 2C 24 48 8D 2D ? ? ? ? 48 87 2C 24 48 8D 64 24 08 FF 64 24 F8")
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 F8")
        if not found: break
        forceAsCode(found, 5)
        obfu._patch(found)
    return

    found = findStart
    print("patch")
    while found < foundEnd:
        # This must come before the following
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 2D ?? ?? ?? ?? 48 87 2C 24 48 8D 64 24 08 e9 ?? ?? ?? ??")
        if not found: break
        obfu._patch(found)

    found = findStart
    print("patch")
    while found < foundEnd:
        # This must come after the previous
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 2D ?? ?? ?? ?? 48 87 2C 24 48 8D 64 24 08 FF 64 24 F8")
        if not found: break
        obfu._patch(found)

    found = findStart
    print("patch")
    while found < foundEnd:
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 ?? 48 8D 64 24 ??")
        if not found: break
        obfu._patch(found)

    found = findStart
    print("patch")
    while found < foundEnd:
        found = FindBinary(found + 1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 08 FF 64 24 F8")
        if not found: break
        obfu._patch(found)

    found = findStart
    print("patch")
    while found < foundEnd:
        # lea     rsp, [rsp-8]
        found = FindBinary(found+1, SEARCH_DOWN | SEARCH_CASE, "48 8D 64 24 ??")
        if not found: break
        if idc.is_code(idc.get_full_flags(found)) and idc.is_head(idc.get_full_flags(found)):
            obfu._patch(found);

    found = findStart
    print("patch")
    while found < foundEnd:
        # lea     rsp, [rsp-8]
        found = FindBinary(found+1, SEARCH_DOWN | SEARCH_CASE, "C3 8D 64 24 08 FF 64 24 F8")
        if not found: break
        obfu._patch(found);

    found = findStart
    print("searching for bytes we nulled")
    while found < foundEnd:
        # lea     rsp, [rsp-8]
        found = FindBinary(found+1, SEARCH_DOWN | SEARCH_CASE, "cc cc cc cc cc cc cc cc")
        if not found: break
        found += hideRepeatedBytes(found);# }}}

def QuickFixQueue():
    # ref = 0
    # print("")
    # print("Queue: head")
    # while ref < 1<<63: ref = check_misaligned_code( idaapi.Q_head, ref)
    ref = 0
    print("")
    print("Queue: disasm")
    while ref < 1<<63: ref = check_misaligned_code( idaapi.Q_disasm, ref)

# or uncomment next lines to patch everything:
# patch_everything()

def super_patch():
    for segment in idautils.Segments():
        segName = SegName(segment)
        print("Segment: %s" % segName)
        if segName == '.text':
            # Do find based patching first (very quick)
            # Then slog it out instruction by instruction for very little gain
            obfu.range(idc.get_segm_attr(segment, SEGATTR_START), idc.get_segm_attr(segment, SEGATTR_END))
            patch_everything()

def patch_this_segment(segment = ScreenEA()):
    obfu.range(idc.get_segm_attr(segment, SEGATTR_START), idc.get_segm_attr(segment, SEGATTR_END))
    obfu.reset() # shouldn't be required
    patch_everything()

# Usage (well, it's going to do everything anyway unless you comment out some stuff
# super_patch()

# scratchSpace = 0x7FF745385700
def slowtracepatch(ea = ScreenEA()):
    b = slowtrace2(ea)
    b2 = filter(lambda x: x[0] != 0xe9, b)
    bytes = [item for sublist in b2 for item in sublist]
    len = PatchBytes(scratchSpace, bytes)
    forceAsCode(scratchSpace, len, hard = 1)
    MakeName(scratchSpace + len, 'end')
    MyMakeUnknown(scratchSpace + len, 0x32, 0)
    obfu.start = scratchSpace
    obfu.end = scratchSpace + len
    obfu.eip = scratchSpace
    patch_everything(obfu)

def fixThunks():
    numLocs = len(list(idautils.Functions()))
    count = 0
    lastPercent = 0

    for ea in idautils.Functions(idc.get_segm_attr(EA(), SEGATTR_START), idc.get_segm_attr(EA(), SEGATTR_END)):
        count = count + 1
        fnName = GetFunctionName(ea)
        fnFlags = idaapi.get_flags(ea)
        percent = (100 * count) // numLocs
        if percent > lastPercent:
            print("%i%%" % percent)
        lastPercent = percent

        if (Byte(ea) == 0xe9):
            # We have a thunk
            print("%i%% 0x%x: Removing sub_thunk" % (percent, ea))
            MyMakeUnknown(ea, 1, 1)
            Wait()
            MakeCodeAndWait(ea)
            Commenter(ea).add("fixThunks: changed from %s" % fnName)
        #  print("0x%0x: %s (%i%%)" % (ea, fnName, percent))

def SegmentRanges(segments):
    for seg_start in idautils.Segments():
        seg_name = idc.get_segm_name(seg_start)
        if seg_name not in segments:
            continue
        seg_end = idc.get_segm_attr(seg_start, idc.SEGATTR_END)
        yield seg_start, seg_end

def truncateThunks():
    numLocs = len(list(idautils.Functions()))
    count = 0
    lastPercent = 0

    for ea in idautils.Functions(idc.get_segm_attr(idc.get_screen_ea(), SEGATTR_START), idc.get_segm_attr(idc.get_screen_ea(), SEGATTR_END)):
        count = count + 1
        fnName = GetFunctionName(ea)
        fnFlags = idaapi.get_flags(ea)
        percent = (100 * count) // numLocs
        if percent > lastPercent:
            print("%i%%" % percent)
        lastPercent = percent

        if (Byte(ea) == 0xe9):
            # We have a thunk, check for chunks
            chunks = list(idautils.Chunks(ea));
            # not sure if a function without chunks will return 0 or 1
            if len(chunks) == 0:
                print("0x%x: 0 size chunks are possible: details" % (ea))
            elif len(chunks) == 1:
                SetFunctionEnd(ea, GetInsnLen(ea))
            elif len(chunks) > 1:
                print("0x%x: Removing %i chunks" % (ea, len(chunks)))
                MyMakeUnknown(ea, 1, 1)
                Wait()
                MakeCodeAndWait(ea)
                Commenter(ea).add("was sub")
        #  print("0x%0x: %s (%i%%)" % (ea, fnName, percent))

