# This Python file uses the following encoding: utf-8

import re
import idc
from idc import *
import itertools as it
from obfu_handler import PatternMatchingRule
if not idc:
    from bitwise import BitwiseMask
    from di import diInsns, my_decode_insn, de
    from obfu_helpers import kassemble, ObfuFailure, bitsize_signed_2, hex_pattern
    from sftools import dinjasm, MyGetOperandDisplacement
    from slowtrace_helpers import GetInsnLen
    from start import isInt

FLAG_LOCK = 1<<0
FLAG_REPNZ = 1<<1
FLAG_REP = 1<<2
FLAG_HINT_TAKEN = 1<<3
FLAG_HINT_NOT_TAKEN = 1<<4
FLAG_IMM_SIGNED = 1<<5
FLAG_DST_WR  = 1<<6
FLAG_RIP_RELATIVE = 1<<7
FLAG_MASK = (1<<8) - 1
# mark_sp_factory('lea_rbp_rsp_x'))
# , [], set_sp_factory('lea_rbp_rsp_x'))


patchmarks = globals().get('patchmarks', dict())

def patch_stack_align(_search, replace, original, ea, addressList, patternComment, addressListWithNops, addressListFull, context, **kwargs):
    # this can't work because it's not being passed the latest instruction
    # circular list, and even if it were, it would still not contain
    # yet-to-be-parsed instructions required for completion
    #  if context and 'slvars2' in context and 'instructions' in context['slvars2']:
        #  sti = context['slvars2']['instructions']
#  
        #  m = sti.multimatch([
            #  #  r'({push}push.*)**',
            #  #  r'lea rsp, .*',
            #  #  r'(movupd .*)**',
            #  #  r'push 0x10',
            #  #  r'call ({call}.*)',
            #  #  r'(lea|add) rsp, .*',
            #  #  r'(movupd .*)**',
            #  #  r'lea rsp, \[rsp\+({rspdiff}[^\]]+)\]',
            #  #  r'(pop.*)**',
            #  #  r'({extra}.*)',
            #  r'({push}push.*)**',
            #  r'lea rsp, .*',
            #  r'(movupd .*)**',
            #  r'push 0x10',
            #  r'call ({call}.*)',
            #  r'(lea|add) rsp, .*',
            #  r'(movupd .*)**',
            #  r'lea rsp, \[rsp\+({rspdiff}[^\]]+)\]',
            #  r'(pop.*)**',
            #  r'({extra}.*)',
            #  ], groupiter=lambda o: o, gettext=lambda o: o.insn, predicate=lambda o: not o.insn.startswith('jmp'))
        #  
        #  if m:
            #  printi(pfh(m))
            #  if 'extra' in m and 'push' in m:
                #  if len(m.push) > 8 and len(m.extra) == 1 and m.extra[0] == 'retn':
                    #  printi("[patch_stack_align] assembling at {:x}".format(m.push[0].ea))
                    #  nassemble(m.push[0].ea,
                        #  """
                        #  push    rbp
                        #  mov     rbp, rsp
                        #  sub     rsp, 32
                        #  {}
                        #  leave
                        #  ret
                        #  """.format(m.call[0]), apply=1)
                #  else:
                    #  printi("[patch_stack_align] len(push) or len(extra) wrong")
            #  else:
                #  printi("[patch_stack_align] extra or push not in m")
            #  return []
#  
        #  else:
            #  printi("[patch_stack_align] multimatch didn't")
            #  printi(pfh(sti))
            #  setglobal('osti', sti)
#  
    #  else:
        #  printi("[patch_stack_align] no context.slvars2.instructions")

    return ["push 0x10", diida(addressList[21+3]), "add rsp, 8"]

def simple_patch_factory(s):
    """
    simple_patch_factory("push qword [{idc.get_name(idc.get_operand_value(addressList[1], 1))}]")
    would create a patch to evaluate and replace: {idc.get_name(idc.get_operand_value(addressList[1], 1))}
    """
    # regex = re.compile(r'\{([^}]+)\}')
    regex = r'\{([^}]+)\}'
    # replace=replaceFunction(search, replace, original, ea, addressList, patternComment)
    def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        def terp(m):
            return eval(m.group(1), globals(), {'addressList': addressList})

        def interpolate_inner(s):
            return re.sub(regex, terp, s)

        if isinstance(s, list):
            result = [interpolate_inner(x) for x in s]
        else:
            result = interpolate_inner(s)
        # dprint("[simple_patch_factory] result")
        printi("[simple_patch_factory] result:{}".format(result))

        return (len(search), list(result))

    return patch

def mark_sp_factory(mark):
    """
    Typical Input:
    028 -250   48 81 ec 50 02 00 00                 sub rsp, 0x250          ; won't be passed as input
    278       [48 8d 6c 24 20]                      lea rbp, [rsp+0x20]
    .....................................................
               48 8d a5 30 02 00 00                 lea rsp, [rbp+0x230]    ; will be passed as set_sp_factory input
    """
    # replace=replaceFunction(search, replace, original, ea, addressList, patternComment)
    def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        # spd = idc.get_spd(ea)  # a.k.a `ea`
        #  printi('search: {}'.format(search))

        # sometimes we get passed a context of None
        context = kwargs.get('context', None)
        context = context or dict()
        slvars = context.get('slvars', None)
        if slvars is None:
            printi("[mark_sp_factory] no context.slvars passed, using ida's spd")
            spd = idc.get_spd(ea)
        else:
            spd = -slvars.rsp
        #  try:
        if idc.get_operand_type(ea, 1) == o_displ:
            disp = MakeSigned(idc.get_operand_value(ea, 1), 64)
            #  if not spd and disp:
                #  raise RuntimeError("Is this bad?")
        else:
            disp = 0

        if disp:
            disp = MyGetOperandDisplacement(ea, 1)
        value = spd + disp
        if obfu_debug: printi("{:x} storing mark {}: {:x} = {:x} + {:x}".format(ea, mark, value, spd, disp))
        patchmarks[mark] = value
        cmt = "*[SPD={:x}] '{}' ({:x} = {:x} + {:x})".format(value, mark, value, spd, disp)
        Commenter(ea, "line").add(cmt).commit()
        #  except NameError as e:
            #  printi("[mark_sp_factory::patch] exception: NameError: {}".format(e.args))
            #  pass
        return []

    return patch


def set_sp_factory(mark, offset=0):
    """
    Typical Input:
               48 8d a5[30 02 00 00]                lea rsp, [rbp+0x230]    ; will be passed as set_sp_factory input
    """
    global slvars

    def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        context = kwargs.get('context', None)
        context = context or dict()
        slvars = context.get('slvars', None)
        if slvars is None:
            printi("[mark_sp_factory] no context.slvars passed, using ida's spd")
            spd = idc.get_spd(ea)
        else:
            spd = -slvars.rsp

        if mark not in patchmarks:
            if obfu_debug: printi("Potential SP adjustment failed due to no patchmark {:x}".format(ea))
            return []

        value = patchmarks[mark]
        disp = 0

        if isJmp(ea):
            ea += GetInsnLen(ea)
        if idc.get_operand_type(ea, 1) == o_displ:
            disp = MakeSigned(idc.get_operand_value(ea, 1), 64)

        if obfu_debug:
            printi("{:x} retrieved mark {}: {:x} + {:x}".format(ea, mark, value, disp))
            printi("{:x} adjusting spd from {:x} by {:x} to get {:x}".format(ea, spd, (value + disp) - spd, (value + disp)))
        _spd = (value + disp) - spd
        if not isinstance(_spd, int):
            # dprint("[debug] _spd value, disp, spd")
            printi("[debug] _spd:{}, value:{}, disp:{}, spd:{}".format(_spd, value, disp, spd))

        # printi("[debug] _spd:{}, value:{}, disp:{}, spd:{}".format(_spd, value, disp, spd))
        dst = idc.get_item_head(ea + len(search))
        cmt = "[SPD={:x}] '{}' ({:x} + {:x} - {:x} ({}))".format(_spd, mark, value, disp, spd, offset if offset is not None else "")
        Commenter(idc.prev_head(dst), "line").remove_matching(r'^\[SPD=')
        Commenter(idc.prev_head(dst), "line").add(cmt).commit()
        if obfu_debug: printi("dst started: {:x}".format(dst))
        move_to_next = False
        if isNop(idc.prev_head(dst)):
            while isNop(dst):
                move_to_next = True
                dst = GetTarget(dst, failnone=True) or idc.next_head(dst)

        if obfu_debug: printi("dst finished: {:x}".format(dst))
        if move_to_next:
            dst = idc.next_head(dst)
            printi("dst move to next_head: {:x}".format(dst))
        # idc.add_user_stkpnt(ea + len(search), _spd)
        idc.add_user_stkpnt(dst, _spd + offset)

        # cmt = "[SPD={}] '{}'".format( hex(_spd), mark )

    return patch

def mark_sp_reg_factory(reg):
    """
    Typical Input:
                    mov rax, rsp              48 8B C4
                    sub rsp, 0xb8
                    lea r11, [rax]
                    mov rsp, r11
                    retn
    """
    # replace=replaceFunction(search, replace, original, ea, addressList, patternComment)
    def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        # spd = idc.get_spd(ea)  # a.k.a `ea`
        context = kwargs.get('context', dict())
        slvars = context.get('slvars', None)
        if not slvars:
            printi("[mark_sp_factory] no context.slvars passed, skipping")
            return []
        spd = -slvars.rsp
        disp = idc.get_operand_value(ea, 1)
        if not spd and disp:
            return

        if disp:
            disp = MyGetOperandDisplacement(ea, 1)
        value = spd + disp
        printi("{:x} storing reg {}: {:x}".format(ea, reg, value))
        patchmarks[reg] = value
        return []

    return patch


def gen_mask(pattern, previous=[]):
    if not isinstance(previous, list):
        raise Exception("argument 'previous' was not a list (type: {})".format(type(previous)))

    if len(previous) < 2:
        sometimes = []
        always = []
        for v in pattern:
            sometimes.append(v)
            always.append(v)
        return [sometimes, always]

    sometimes = previous[0]
    always = previous[1]

    if pattern is None:
        mask = []
        for i, unused in enumerate(always):
            mask.append( ~(sometimes[i] ^ always[i]) )
        return [always, mask]

    for i, v in enumerate(pattern):
        sometimes[i] |= v
        always[i] &= v
        return [sometimes, always]

def patch_32bit_add(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    """
    replace: 48 81 c1 08 00 00 00               add rcx, 8
    with:    48 83 c1 08                        add rcx, 8
    """
    if obfu_debug: printi("patch_32bit_add")
    length = MyGetInstructionLength(ea)
    #  e = deCode(get_bytes(ea, length), ea)
    e = de(ea)
    if isinstance(e, list):
        e = e[0]
        #  pp(e.__dict__)
        globals()['e'] = e
        flags = e.rawFlags & FLAG_MASK
        if e.mnemonic == 'ADD' \
                and e.opcode == 11 \
                and flags == (FLAG_DST_WR | FLAG_IMM_SIGNED) \
                and e.operands[0].type == 'Register' \
                and e.operands[1].type == 'Immediate' \
                and e.operands[1].size == 32:
                    requiredSize = bitsize_signed_2(e.operands[1].value)
                    if requiredSize == 16:
                        requiredSize = 32
                    if obfu_debug: printi("0x%x: patch_32bit_add: acutalSize: %i, requiredSize: %i" % (ea, e.operands[1].size, requiredSize))
                    if requiredSize == 8:
                        addresses = addressList[0:e.size]
                        return (addresses,
                                (["add {}, {}".format(e.operands[0].name, e.operands[1].value)]))
    else:
        if obfu_debug: printi("patch_32bit_add: e was type %s" % type(e))
    return []

_push_imm = []
def patch_manual_store(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    global _push_imm
    imm = idc.get_wide_byte(addressList[1])
    _push_imm.append(imm)
    printi("storing push imm: 0x{:x}".format(imm))

def patch_manual(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    global _push_imm
    if not _push_imm:
        raise ObfuFailure("nothing to pop")
    imm = _push_imm.pop()
    printi("using push imm: 0x{:x}".format(imm))

    if not isInt(ea):
        raise ValueError("ea is {}".format(ea))

    # sig_maker_ex(obfu.combEx(ea, length=64), fullSig=1, noSig=1, show=1)
    return kassemble('add rsp, 0x{:x}'.format(imm))


def patch_double_stack_push_call_jump(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    #  48 ?? ?? ?? ?? ?? ??                 mov rax, qword [LoadLibraryA]
    #  48 ?? ?? ??                          lea rdx, qword [rbp+48h]
    #  48 ?? ??                             mov rcx, rdx ; mov library name into rcx
    #  55                                   push rbp
    #  48 ?? ?? ?? ?? ?? ??                 lea rbp, qword [sub_144A4AF5F]
    #  48 ?? ?? 24                          xchg rbp, [rsp]
    #  50                                   push rax
    #  c3                                   retn

    #  -- a different example
    #  48 8b 05 14 91 05 fd                 mov rax, qword [AddVectoredExceptionHandler]
    #  48 8d 15 a6 4f 0e 00                 lea rdx, qword [loc_14486BDC5]
    #  b9 01 00 00 00                       mov ecx, 1
    #  55                                   push rbp
    #  48 8d 2d ad b0 4b 00                 lea rbp, qword [sub_144ACFED4]
    #  48 87 2c 24                          xchg rbp, [rsp]
    #  50                                   push rax
    #  c3                                   retn

    #  -- a different example
    #  48 8b 05 f8 cc 04 fe                 mov rax, qword [SetUnhandledExceptionFilter]
    #  48 8d 15 54 6d 65 01                 lea rdx, qword [byte_144DE9A5F]
    #  52                                   push rdx
    #  59                                   pop rcx
    #  55                                   push rbp
    #  48 8d 2d 6d da 65 01                 lea rbp, qword [sub_144DF078B]
    #  48 87 2c 24                          xchg rbp, [rsp]
    #  50                                   push rax
    #  c3                                   retn

    #  mov rax, [0x1417f2798]
    #      lea rdx, [rbp+0x48]
    #      push rdx
    #      pop rcx
    #  lea rsp, [rsp-0x8]
    #  mov [rsp], rbp
    #  lea rbp, [0x144345cd3]
    #  xchg [rsp], rbp
    #  push rax
    #  retn


    #  -- a false positive
    #  mov     rax, cs:LoadLibraryA
    #  lea     rdx, [rbp+48h]
    #  push    rdx
    #  pop     rcx
    #  mov     [rbp+100h], rax
    #  mov     rax, [rbp+100h]
    #  mov     [rbp+150h], rax
    #  lea     rax, [rbp+48h]
    #  jmp     loc_14424AFE2   ; [obfu


    #  b1180 example
    #  48 8b 05 43 dd 00 fd          	mov rax, [off_140D0AB4C]    ; flags are 0x30509574
    #  8b 15 2d 6c d6 fc             	mov edx, [dword_140A63A3C]
    #  89 d1                         	mov ecx, edx
    #  55                            	push rbp
    #  48 8d 2d a2 bc db ff          	lea rbp, [label22]
    #  48 87 2c 24                   	xchg [rsp], rbp
    #  50                            	push rax
    #  c3                            	retn

    # all our arguments are basically useless, we're going to have to start from scratch.
    # first check if we're actually loading something that is actually code
    # idc.is_code(idc.get_full_flags(GetOperandValue(EA(), 1)))
    target = GetOperandValue(ea, 1)
    flags = idc.get_full_flags(target)
    # dprint("[debug] target, flags")
    if obfu_debug: printi("[patch_double_stack_push_call_jump] target:{:x}, flags:{:x}".format(target, flags))

    if idc.is_code(flags)                                                             \
        or flags == 0x305054a0                                                        \
        or flags & idc.FF_0OFF \
        or (type(idc.GetDisasm(target)) is str and idc.GetDisasm(target).startswith("extrn")) \
        or (type(GetType(target)) is str and GetType(target).endswith(")")):
            #  raise ObfuFailure("0x%x: serious business: %s {%s}" % (addressList[0], GetDisasm(target), GetDisasm(target)))

            state = 0
            solution = []
            callAddress = BADADDR
            jmpAddress = BADADDR
            addrLen = len(addressList)
            insAddresses = []
            i = 0
            while i < addrLen:
                addr = addressList[i]
                insAddresses.append(addr)
                skip = MyGetInstructionLength(addr)
                if obfu_debug: printi("skipped %i addressList" % skip)
                i += skip

            if obfu_debug: printi("insAddresses: %s" % insAddresses) # not used yet
            ourAddressList = []
            inslen = MyGetInstructionLength(ea)
            skip = 0
            end = 0
            for idx, a in enumerate(insAddresses):
                # d = re.sub(r'\s+', ' ', GetDisasm(a))
                d = dinjasm(a)
                if (1 + idx) < len(insAddresses):
                    dpeek = dinjasm(insAddresses[idx + 1])
                else:
                    dpeek = ""

                #  printi("0x%x: state: %i: %s" % (a, state, d))
                inslen = MyGetInstructionLength(a)

                # not used yet
                for i in range(inslen):
                    ourAddressList.append(a + i)

                #  0x144a91628: state: 0: mov rax, qword ptr cs:[LoadLibraryA]
                #  0x144a9162f: state: 1: lea rdx, qword ptr [rbp+48h]
                #  0x144a91633: state: 1: push rdx
                #  0x144a91634: state: 1: pop rcx
                #  0x144345cd3: state: 1: mov qword ptr [rbp+100h], rax
                #  0x144345cda: state: 1: mov rax, qword ptr [rbp+100h]
                #
                #  .text:0000000144A91628 1B8 48 8B 05 69 11 D6 FC                    mov     rax, cs:LoadLibraryA
                #  .text:0000000144A9162F 1B8 48 8D 55 48                             lea     rdx, [rbp+48h]
                #  .text:0000000144A91633 1B8 52                                      push    rdx
                #  .text:0000000144A91634 1C0 59                                      pop     rcx
                #  .text:0000000144345CD3 000 48 89 85 00 01 00 00                    mov     [rbp+100h], rax
                #  .text:0000000144345CDA 000 48 8B 85 00 01 00 00                    mov     rax, [rbp+100h]
                #  .text:0000000144345CE1 000 48 89 85 50 01 00 00                    mov     [rbp+150h], rax
                #  .text:0000000144345CE8 000 48 8D 45 48                             lea     rax, [rbp+48h]
                #  .text:0000000144345CEC 000 E9 F1 52 F0 FF                          jmp     loc_14424AFE2   ; [obfu::comb] unconditional jump
                #  .text:0000000144345CEC                             ; END OF FUNCTION CHUNK FOR sub_14548F1ED#

                if d.startswith("mov rax"):
                    t = GetOpType(a, 1)
                    #  if t in (idc.o_mem, idc.o_displ) and state == 0:
                    if state == 0:
                        callAddress = GetOperandValue(a, 1)
                        state = 1
                        # continue, else we'll add this line to our solution
                        continue
                    else:
                        if obfu_debug: printi("sequence: %i" % state)
                        return [] # raise ObfuFailure("serious business: out of sequence: %s" % d)

                elif d.startswith("mov [rsp-8], rbp") \
                and dpeek.startswith("lea rsp, [rsp-8]"):
                    if state == 1:
                        state = 2
                    else:
                        if obfu_debug: printi("serious business: out of sequence: %s" % (d + "; " + dpeek))
                        return []

                elif d.startswith("lea rsp, [rsp-8]") \
                and dpeek.startswith("mov [rsp], rbp"):
                    if state == 1:
                        state = 2
                    else:
                        if obfu_debug: printi("serious business: out of out of sequence: %s" % (d + "; " + dpeek))
                        return []


                elif d.startswith("push rbp"):
                    if state == 1:
                        state = 2
                    else:
                        if obfu_debug: printi("out of sequence: %i" % state)
                        return [] # raise ObfuFailure("serious business: out of out of sequence: %s" % d)
                # elif d.startswith("lea rbp") and GetOpType(a, 1) in (idc.o_mem, idc.o_displ):
                elif d.startswith("lea rbp"):
                    if state == 2:
                        jmpAddress = GetOperandValue(a, 1)
                        if obfu_debug: printi("jmpAddress: 0x%x" % jmpAddress)
                        state = 3
                    else:
                        if obfu_debug: printi("0x%x: serious business: out of out of sequence (%s): %s" % (ea, state, d))
                        return []
                elif d.startswith("xchg rbp, [rsp]") \
                or d.startswith("xchg [rsp], rbp"):
                    if state == 3:
                        state = 4
                    else:
                        if obfu_debug: printi("0x%x: serious business: out of out of sequence (%s): %s" % (ea, state, d))
                        return []
                elif d.startswith("push rax"):
                    if state == 4:
                        state = 5
                    else:
                        if obfu_debug: printi("0x%x: serious business: out of out of sequence (%s): %s" % (ea, state, d))
                        return []
                elif d.startswith("ret"):
                    if state == 5:
                        state = 6
                        end = insAddresses[idx] + GetInsnLen(insAddresses[idx])
                        break
                    else:
                        if obfu_debug: printi("out of sequence: %i" % state)
                        if state > 2:
                            if obfu_debug: printi("0x%x: serious business: out of out of sequence (%s): %s" % (ea, state, d))
                            return []
                        else:
                            return []
                if state == 1:
                    # solution.append(dii(a))
                    solution.append(d)



            if state == 6:
                #  solution.append("CALL 0x%x" % callAddress)
                #  solution.append("JMP 0x%x" % jmpAddress)

                # this way...
                usedAddresses = []
                for a in addressList:
                    if a == end:
                        break
                    usedAddresses.append(a)

                # --or--
                # https://stackoverflow.com/questions/5883265/python-add-item-to-list-until-a-condition-is-true
                usedAddresses2 = [x for x in it.takewhile(lambda x: x != end, addressList)]
                usedCount = len(usedAddresses)
                # compact, but readable? ... compact: yes, readable: hardly

                printi("usedAddresses1: %s" % usedAddresses)
                printi("usedAddresses2: %s" % usedAddresses)



                solution.append("call qword [rel 0x%x]" % callAddress)
                solution.append("jmp 0x%x" % jmpAddress)
                printi("Possible solution:\n%s" % "\n".join(solution))
                return (usedAddresses, solution)
                #  return (usedAddresses,
                #  return (search, replace, original, ea, addressList, patternComment, addressListWithNops)
            elif state > 4:
                raise ObfuFailure("{:x} serious business: only reached state {} of 6".format(addressList[0], state))
    return []

def patch_double_rsp_push_call_jump(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    """
    0:  55                      push   rbp
    1:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0xffffffff]
    8:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    c:  55                      push   rbp
    d:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0x1e650e]
    14: 48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    18: c3                      ret
    19:
    """
    jmpAddress = GetOperandValue(addressList[0x01], 1)
    callAddress  = GetOperandValue(addressList[0x0d], 1)
    # we can return the entire addressList, as this is a terminal pattern
    # (it ends it retn)
    return (addressList, [
        "call 0x{:x}".format(callAddress),
        "jmp 0x{:x}".format(jmpAddress),
        "int3"
        # "ret"
        ])

def patch_double_rsp_push_call_jump_b(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    """
    0:  55                      push   rbp
    (shoe-horn in 48 8d 64 24 f8 instead of 55)
    1:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0xffffffff]
    8:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    c:  55                      push   rbp
    d:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0x1e650e]
    14: 48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    18: c3                      ret
    19:
    """
    jmpAddress = GetOperandValue(addressList[0x01 + 4], 1)
    callAddress  = GetOperandValue(addressList[0x0d + 4], 1)
    # we can return the entire addressList, as this is a terminal pattern
    # (it ends it retn)
    return (addressList, [
        "call 0x{:x}".format(callAddress),
        "jmp 0x{:x}".format(jmpAddress),
        "int3"
        # "ret"
        ])

def patch_single_rsp_push_call_jump(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    """
    0:  55                      push   rbp
    1:  48 8D 2D[AB 37 35 00]   lea    rbp, sub_143C53296
    8:  48 87 2C 24             xchg   QWORD PTR [rsp],rbp
    c:  E9[03 DC DC FF]         jmp    _sub_1436CD6F7

    0: e8[0f dc dc ff]                             call    _sub_1436CD6F7
    5: e9[a9 37 35 00]                             jmp     sub_143C53296
    """

    """
    0:  48 8b 05[?? ?? ?? ??]   mov    rax,QWORD PTR [rip+0x366a13]        # 0x366a1a
    7:  8b 15 b8 3e 7f fc       mov    edx,DWORD PTR [rip+0xfffffffffc7f3eb8]        # 0xfffffffffc7f3ec5
    d:  89 d1                   mov    ecx,edx
    f:  55                      push   rbp
    10: 48 8d 2d[?? ?? ?? ??]   lea    rbp,[rip+0x56a224]        # 0x56a23b
    17: 48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    1b: ff e0                   jmp    rax
    """
    if (search[0] == 0x55 and isUnconditionalJmp(addressList[1+7]+4)):
        _asm = ["call {:#x}".format(GetTarget(addressList[1+7]+4)), "jmp {:#x}".format(addressList[1] + 7 + MakeSigned(idc.get_wide_dword(addressList[1]+3))), "int3"]
        try:
            nassemble(_asm)
            return _asm
        except RelocationAssemblerError:
            print('nope')
            pass
    if (search[0] == 0x48):
        jmpAddress = idc.get_operand_value(addressList[0x10], 1)
        callOffset = idc.get_operand_value(addressList[0], 1)
        callAddress = idc.get_qword(callOffset)
        addressJmp = 0
        printi("{:x} [patch_single_rsp_push_call_jump(push rax)] jmpAddress:{:x}, callOffset:{:x} callAddress:{:x}".format(ea, jmpAddress, callOffset, callAddress))

        if callAddress != idc.BADADDR:
            ForceFunction(callAddress)
            obfu._patch(callAddress)
            #  nassemble(addressJmp, "jmp 0x{:x}".format(jmpAddress), apply=1)
            return len(search), [
                "call 0x{:x}".format(callAddress),
                "jmp 0x{:x}".format(jmpAddress),
                "int3",
            ]
        return []

    jmpAddress = GetOperandValue(addressList[0x01], 1)
    # we can't see `jmp` instructions because they're purposefully hidden for chunk processing
    addressJmp = addressList[0x0b] + 1
    # dprint("[patch_single_rsp_push_call_jump] jmpAddress, addressJmp")

    if isUnconditionalJmp(addressJmp):
        printi("{:x} [patch_single_rsp_push_call_jump] jmpAddress:{:x}, addressJmp:{:x}".format(ea, jmpAddress, addressJmp))
        callAddress  = GetTarget(addressJmp)
        # Now we have to check what's next, to avoid clobbering other patterns
        addressNext = callAddress + GetInsnLen(callAddress)
        # dprint("[patch_single_rsp_push_call_jump] callAddress, addressNext")
        printi("{:x} [patch_single_rsp_push_call_jump] callAddress:{:x}, addressNext:{:x}".format(ea, callAddress, addressNext))

        if idc.print_insn_mnem(callAddress) in ('ret', 'retn', 'xchg') or \
           idc.print_insn_mnem(addressNext) in ('ret', 'retn', 'xchg'):
               printi("{:x} [patch_single_rsp_push_call_jump] fail: retn/xchg in callAddress:{:x}, addressNext:{:x}".format(ea, callAddress, addressNext))
               return []
        # XXX: removed this, not sure what it was meant for -- some kind of safety net i guess
        if 1:
            if not IsFuncHead(callAddress) and len(xrefs_to_ex(callAddress, flow=0)) < 1:
                printi("{:x} [patch_single_rsp_push_call_jump] fail: not enough xrefs ({}) to callAddress:{:x}".format(ea, len(xrefs_to_ex(callAddress, flow=0)), callAddress))
                return []


        """ some real subs
        .text:00000001441DC002 000                 push    rbp             ; [PatchBytes] lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
        .text:00000001441DC003 008                 nop     dword ptr [rax+rax+00000000h]
        .text:00000001441DC00B 008                 sub     rsp, 40h
        .text:00000001441DC00F 048                 lea     rbp, [rsp+20h]
        .text:00000001441DC014 048                 mov     [rbp+30h], rcx

        (same sub, before de-obfu)
        .text:00000001441DC002 000                 lea     rsp, [rsp-8]
        .text:00000001441DC007 008                 mov     [rsp+8+var_8], rbp
        .text:00000001441DC00B 008                 sub     rsp, 40h
        .text:00000001441DC00F 048                 lea     rbp, [rsp+48h+var_28]
        .text:00000001441DC014 048                 mov     [rbp+30h], rcx
        """

        if callAddress != idc.BADADDR:
            ForceFunction(callAddress)
            obfu._patch(callAddress)
            #  nassemble(addressJmp, "jmp 0x{:x}".format(jmpAddress), apply=1)
            return len(search), [
                "call 0x{:x}".format(callAddress),
                "jmp 0x{:x}".format(jmpAddress),
                "int3",
            ]
        else:
            printi("{:x} [patch_single_rsp_push_call_jump] fail: callAddress:{:x} BAD".format(ea, callAddress))
            pass
            # "ret"
    return []

def patch_checksummer(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
    # idc.patch_dword(addressList[4], idc.get_wide_dword(addressList[4]) - 0x20)
    # PatchNops(addressList[8], 5)
    value = idc.get_wide_dword(addressList[4]) - 0x20
    #  55 48 8D AC 24
    #  0-value
    #  60 FF FF FF
    #  idc.patch_byte(addressList[12], value)
    #  PatchNops(addressList[1], 7)
    return (addressList[0:13], [
        "push rbp",
        "sub rsp, 0{:x}h".format(value),
        "lea rbp, [rsp]"
        ])

def process_replace(replace, replace_asm):
    ra = kassemble(replace_asm)

    # printi("pr", replace, ra, replace_asm.split(';'))

    if ra == replace:
        return replace_asm.split(';')

    printi("[warn] incorrect hex for asm: {}\n[warn] ... should be {}".format(replace_asm, listAsHex(ra)))
    return replace_asm.split(';')

def process_replace_nocheck(replace, replace_asm):
    return replace_asm.split(';')

def process_hex_pattern(replace):
    hp = hex_pattern(replace)
    d = _.pluck(diInsns(hp), 3)

    def fn(value, index, container):
        return [int(x, 16) for x in re.split('(..)', value) if x]
    d = _.flatten(_.map(d, fn))

    #

    if d == hp:
        return _.pluck(diInsns(hp), 2)

    printi("process_hex_pattern", d, hp, _.pluck(diInsns(hp), 2))
    return hex_pattern(replace)




def obfu_append_patches():
    global obfu
    obfu.patterns = list()
    # obfu.append("", "push r11, pop rsp -> mov rsp, r11", hex_pattern(["41 53", "5c"]), hex_pattern(["4C 89 dc"]), safe=1)
    # obfu.append("", "push r11, pop rsp -> mov rsp, r11", hex_pattern(["41 53", "5c"]), ["mov rsp, r11"], safe=1)

    """
    028 -250   48 81 ec 50 02 00 00                 sub rsp, 0x250
    278        48 8d 6c 24 20                       lea rbp, [rsp+0x20]
    .....................................................
               48 8d a5 30 02 00 00                 lea rsp, [rbp+0x230]
    """
    obfu.append("", "mark lea rbp, [rsp+x]", hex_pattern("48 8d 6c 24 ??"),                                          [], mark_sp_factory('lea_rbp_rsp_x'))
    obfu.append("", "set  lea rsp, [rbp+x]", hex_pattern("48 8d a5 ?? ?? ?? ??"),                                    [], set_sp_factory('lea_rbp_rsp_x'))
    obfu.append("", "set  lea rsp, [rbp+x]", hex_pattern("48 8d 65 ??"),                                             [], set_sp_factory('lea_rbp_rsp_x'))
    obfu.append("", "set  mov rsp, rbp",     hex_pattern("48 8b e5"),                                                [], set_sp_factory('lea_rbp_rsp_x'))

    obfu.append("", "mov r11, rsp",          hex_pattern("4c 8b dc")       or nassemble("mov r11, rsp"),             [], mark_sp_factory('mov_r11_rsp'))
    obfu.append("", "lea r11, [rsp+??h]",    hex_pattern("4c 8d 5c 24 ??") or nassemble("lea r11, [rsp+60h]"),       [], mark_sp_factory('mov_r11_rsp'))
    obfu.append("", "lea r11, [rsp+????????h]",
                                             hex_pattern("4c 8d 9c 24 ?? ?? ?? ??") or nassemble("lea r11, [rsp+]"), [], mark_sp_factory('mov_r11_rsp'))
    obfu.append("", "mov rsp, r11",          hex_pattern("49 8b e3")       or nassemble("mov rsp, r11"),             [], set_sp_factory('mov_r11_rsp'))
    obfu.append("", "push r11; pop rsp",     hex_pattern("41 53 5c")       or nassemble("push r11; pop rsp"),        [], set_sp_factory('mov_r11_rsp', 8))

    obfu.append("""
            0:  48 8d 64 24 f8          lea    rsp, [rsp-0x8]
            5:  48 89 2c 24             mov    [rsp], rbp
            9:  48 8d 2d ?? ?? ?? ??    lea    rbp, [rip+0x0]        # 0x10
            10: 48 87 2c 24             xchg   [rsp], rbp
            14: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
            19: ff 64 24 f8             jmp    [rsp-0x8]
            """, "lea rbp<>rsp jmp variant1 (mit nop)",
            hex_pattern([
                "48 8d 64 24 f8",
                "48 89 2c 24",
                "90",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "48 8d 64 24 08",
                "ff 64 24 f8"
            ]), [],
            generate_patch1(0x09 + 3 + 1), # , 0x10 + 1, 0x05)
            reflow=1
            )


    obfu.append("""
            000 48 89 6C 24 F8                                mov     [rsp+var_8], rbp ; [PatchBytes] mov/lea->push order swap: rbp
                                                                                      ; [PatchBytes] lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
            000 48 8D 64 24 F8                                lea     rsp, [rsp-8]
            008 48 83 EC 40                                   sub     rsp, 40h
            048 48 8D 6C 24 20                                lea     rbp, [rsp+20h]

            to

            000 55                                            push    rbp             ; [PatchBytes] mov/lea->push order swap: rbp
                                                                                      ; [PatchBytes] lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
            008 48 83 EC 40                                   sub     rsp, 40h
            048 48 8D 6C 24 20                                lea     rbp, [rsp+20h]
            048 0F 1F 84 00 00 00 00 00                       nop     dword ptr [rax+rax+00000000h] ; [PatchBytes] PatchNops
            048 90                                            nop
            """, "ArxanHelper prologue",

            hex_pattern([
                "48 89 6C 24 F8",
                "48 8D 64 24 F8",
                "48 83 EC 40",
                "48 8D 6C 24 20",
            ]),
            hex_pattern([
                "55",
                "48 83 EC 40",
                "48 8D 6C 24 20",
            ]),
            safe=1,
            reflow=1
    )



    #  obfu.append("""
        #  0:  48 8d 64 24 f8          lea     rsp, [rsp-8]          ; === call LOCATION_2, insert LOCATION_1 into return stack
        #  5:  48 89 2c 24             mov     [rsp], rbp            ; push rbp
        #  9:  48 8d 2d ?? ?? ?? ??    lea     rbp, LOCATION_1       ; rbp = LOCATION_1
        #  10: 48 87 2c 24             xchg    rbp, [rsp]            ; pop rbp ; push LOCATION_1     ; push LOCATION_1
        #  14: 55                      push    rbp                   ; push rbp
        #  15: 48 8d 2d ?? ?? ?? ??    lea     rbp, LOCATION_2       ; rbp = LOCATION_2
        #  1c: 48 87 2c 24             xchg    rbp, [rsp]            ; pop rbp; push LOCATION_2      ; push LOCATION_2
        #  20: c3                      retn                          ; pop rax; jmp eax              ; pop rax; jmp rax
        #  """,
        #  "faked call to LOCATION_2    from LOCATION_1   ",
        #  hex_pattern([
            #  "48 8d 64 24 f8",
            #  "48 89 2c 24",
            #  "48 8d 2d ?? ?? ?? ??",
            #  "48 87 2c 24",
            #  "55",
            #  "48 8d 2d ?? ?? ?? ??",
            #  "48 87 2c 24",
            #  "c3"
        #  ]),
        #  [],
        #  generate_call_with_fake_return(0x18)
        #  )



    #  0:  58                      pop    rax               #  0:  50                      push   rax
    #  1:  59                      pop    rcx               #  1:  51                      push   rcx
    #  2:  5a                      pop    rdx               #  2:  52                      push   rdx
    #  3:  5b                      pop    rbx               #  3:  53                      push   rbx
    #  4:  5c                      pop    rsp               #  4:  54                      push   rsp
    #  5:  5d                      pop    rbp               #  5:  55                      push   rbp
    #  6:  5e                      pop    rsi               #  6:  56                      push   rsi
    #  7:  5f                      pop    rdi               #  7:  57                      push   rdi
    #  8:  41 58                   pop    r8                #  8:  41 50                   push   r8
    #  a:  41 59                   pop    r9                #  a:  41 51                   push   r9
    #  c:  41 5a                   pop    r10               #  c:  41 52                   push   r10
    #  e:  41 5b                   pop    r11               #  e:  41 53                   push   r11
    #  10: 41 5c                   pop    r12               #  10: 41 54                   push   r12
    #  12: 41 5d                   pop    r13               #  12: 41 55                   push   r13
    #  14: 41 5e                   pop    r14               #  14: 41 56                   push   r14
    #  16: 41 5f                   pop    r15               #  16: 41 57                   push   r15

    ####
    #
    # A series of patches to convert:
    # mov [rsp-8], REG
    # lea rsp, [rsp -8]
    #
    # with the slightly shorter
    # lea rsp, [rsp-8]
    # mov [rsp], REG
    #
    movlealistpush = [
            # MOV [RSP-0x8], RAX; LEA RSP, [RSP-0x8]
            [["48 89 44 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 04 24"], "rax"],
            [["48 89 4c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 0c 24"], "rcx"],
            [["48 89 54 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 14 24"], "rdx"],
            [["48 89 5c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 1c 24"], "rbx"],
            [["48 89 64 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 24 24"], "rsp"],
            [["48 89 6c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 2c 24"], "rbp"],
            [["48 89 74 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 34 24"], "rsi"],
            [["48 89 7c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "48 89 3c 24"], "rdi"],
            [["4c 89 44 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 04 24"], "r8"],
            [["4c 89 4c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 0c 24"], "r9"],
            [["4c 89 54 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 14 24"], "r10"],
            [["4c 89 5c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 1c 24"], "r11"],
            [["4c 89 64 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 24 24"], "r12"],
            [["4c 89 6c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 2c 24"], "r13"],
            [["4c 89 74 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 34 24"], "r14"],
            [["4c 89 7c 24 f8", "48 8d 64 24 f8"], ["48 8d 64 24 f8", "4c 89 3c 24"], "r15"]
    ]

    # A series of patches to convert:
    # mov [rdx+8], REG
    # lea rsp, [rsp+8]
    #
    # with the slightly shorter
    # lea rsp, [rsp-8]
    # mov [rsp], REG
    #
    #  movlealistpop = [# {{{
            #  # CANNOT FIND ANY OCCURANCES OF THIS OBFU IN 2189 -- WAS IT EVERY VALID?
            #  # 0:  48 8b 54 24 08          mov    rdx,QWORD PTR [rsp+0x8]
            #  # 5:  48 8d 64 24 08          lea    rsp,[rsp+0x8]
            #  #
            #  # 48 8b ?? 24 08 48 8d 64 24 08
            #  #
            #  #
            #  #  MOV RAX, [RSP+0x8]; LEA RSP, [RSP+0x8]
            #  [["48 8b 44 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 04 24"], "rax"],
            #  [["48 8b 4c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 0c 24"], "rcx"],
            #  [["48 8b 54 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 14 24"], "rdx"],
            #  [["48 8b 5c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 1c 24"], "rbx"],
            #  [["48 8b 64 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 24 24"], "rsp"],
            #  [["48 8b 6c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 2c 24"], "rbp"],
            #  [["48 8b 74 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 34 24"], "rsi"],
            #  [["48 8b 7c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "48 8b 3c 24"], "rdi"],
            #  [["4c 8b 44 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 04 24"], "r8"],
            #  [["4c 8b 4c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 0c 24"], "r9"],
            #  [["4c 8b 54 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 14 24"], "r10"],
            #  [["4c 8b 5c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 1c 24"], "r11"],
            #  [["4c 8b 64 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 24 24"], "r12"],
            #  [["4c 8b 6c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 2c 24"], "r13"],
            #  [["4c 8b 74 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 34 24"], "r14"],
            #  [["4c 8b 7c 24 08", "48 8d 64 24 08"], ["48 8d 64 24 08", "4c 8b 3c 24"], "r15"]
    #  ]# }}}
    """
    .text:0000000140CBD671 000 48 83 EC 28                                   sub     rsp, 28h
    .text:0000000140CBD675 028 48 8B 41 10                                   mov     rax, [rcx+10h]
    .text:0000000140CBD679 028 83 38 03                                      cmp     dword ptr [rax], 3
    .text:0000000140CBD67C 028 48 89 6C 24 F8                              / mov     [rsp-8], rbp
    .text:0000000140CBD681 028 48 8D 64 24 F8                              \ lea     rsp, [rsp-8]
    .text:0000000140CBD686 030 48 BD 2B 93 18 44 01 00 00 00                 mov     rbp, offset sub_14418932B
    .text:0000000140CBD690 030 48 87 2C 24                                   xchg    rbp, [rsp]
    .text:0000000140CBD694 030 48 8D 64 24 F8                                lea     rsp, [rsp-8]
    .text:0000000140CBD699 038 48 89 14 24                                   mov     [rsp], rdx
    .text:0000000140CBD69D 038 48 89 5C 24 F8                              / mov     [rsp-8], rbx
    .text:0000000140CBD6A2 038 48 8D 64 24 F8                              \ lea     rsp, [rsp-8]
    .text:0000000140CBD6A7 040 48 8B 54 24 10                                mov     rdx, [rsp+10h]
    .text:0000000140CBD6AC 040 48 BB 47 A5 D3 40 01 00 00 00                 mov     rbx, offset loc_140D3A547
    .text:0000000140CBD6B6 040 48 0F 47 D3                                   cmova   rdx, rbx
    .text:0000000140CBD6BA 040 48 89 54 24 10                                mov     [rsp+10h], rdx
    .text:0000000140CBD6BF 040 48 8D 64 24 08                                lea     rsp, [rsp+8]
    .text:0000000140CBD6C4 038 48 8B 5C 24 F8                                mov     rbx, [rsp-8]
    .text:0000000140CBD6C9 038 48 8D 64 24 08                                lea     rsp, [rsp+8]
    .text:0000000140CBD6CE 030 48 8B 54 24 F8                                mov     rdx, [rsp-8]
    .text:0000000140CBD6D3 030 48 8D 64 24 08                                lea     rsp, [rsp+8]
    .text:0000000140CBD6D8 028 FF 64 24 F8                                   jmp     qword ptr [rsp-8]
    .text:0000000140CBD6DC                                   ; ---------------------------------------------------------------------------
    .text:0000000140CBD6DC 000 E9 4A BC 4C 03                                jmp     near ptr sub_14418932B
    .text:0000000140CBD6E1
    """
    ####
    # POP1                        POP2
    #
    # mov [rsp+8], REG            lea     rsp, [rsp+8]
    # lea rsp, [rsp+8]            mov     REG, [rsp-8]
    #
    # with the slightly shorter
    # lea rsp, [rsp+8]            mov [rsp], REG
    # mov [rsp], REG              lea rsp, [rsp+8]

    # A series of patches to convert:
    # lea rsp, [rsp+8]
    # mov REG, [rbp-8],
    #
    # with the slightly shorter
    # mov [rsp], REG
    # lea rsp, [rsp+8]
    movlealistpop2 = [
            # lea [rsp],[rsp+8]; mov {r64},[rsp-8] => nop; mov [rsp],{r64}; lea rsp, [rsp+8]
            #
            # LEA RSP, [RSP+0x8]; MOV RAX, [RSP-0x8]
            [["48 8d 64 24 08", "48 8b 44 24 f8"], ["48 8b 04 24", "48 8d 64 24 08"], "rax"],
            [["48 8d 64 24 08", "48 8b 4c 24 f8"], ["48 8b 0c 24", "48 8d 64 24 08"], "rcx"],
            [["48 8d 64 24 08", "48 8b 54 24 f8"], ["48 8b 14 24", "48 8d 64 24 08"], "rdx"],
            [["48 8d 64 24 08", "48 8b 5c 24 f8"], ["48 8b 1c 24", "48 8d 64 24 08"], "rbx"],
            [["48 8d 64 24 08", "48 8b 64 24 f8"], ["48 8b 24 24", "48 8d 64 24 08"], "rsp"],
            [["48 8d 64 24 08", "48 8b 6c 24 f8"], ["48 8b 2c 24", "48 8d 64 24 08"], "rbp"],
            [["48 8d 64 24 08", "48 8b 74 24 f8"], ["48 8b 34 24", "48 8d 64 24 08"], "rsi"],
            [["48 8d 64 24 08", "48 8b 7c 24 f8"], ["48 8b 3c 24", "48 8d 64 24 08"], "rdi"],
            [["48 8d 64 24 08", "4c 8b 44 24 f8"], ["4c 8b 04 24", "48 8d 64 24 08"], "r8"],
            [["48 8d 64 24 08", "4c 8b 4c 24 f8"], ["4c 8b 0c 24", "48 8d 64 24 08"], "r9"],
            [["48 8d 64 24 08", "4c 8b 54 24 f8"], ["4c 8b 14 24", "48 8d 64 24 08"], "r10"],
            [["48 8d 64 24 08", "4c 8b 5c 24 f8"], ["4c 8b 1c 24", "48 8d 64 24 08"], "r11"],
            [["48 8d 64 24 08", "4c 8b 64 24 f8"], ["4c 8b 24 24", "48 8d 64 24 08"], "r12"],
            [["48 8d 64 24 08", "4c 8b 6c 24 f8"], ["4c 8b 2c 24", "48 8d 64 24 08"], "r13"],
            [["48 8d 64 24 08", "4c 8b 74 24 f8"], ["4c 8b 34 24", "48 8d 64 24 08"], "r14"],
            [["48 8d 64 24 08", "4c 8b 7c 24 f8"], ["4c 8b 3c 24", "48 8d 64 24 08"], "r15"]
            #pattern:  48 8d 64 24 08; (4[c8]) 8b ([4567][4c]) 24 f8
            #replace: 90; \1 8b \=printf('%02x' % submatch(2) - 0x40) 24; 48 8d 64 24 08
            # 'trinary' search:     '01001.00 10001011 01...100 00100100 f8',
            # 'trinary' replace: '90 01001.00 10001011 00...100 00100100',
    ]

    # messing about with alternate ways of expression
    # lhs = braceexpandlist("4{8,c} 8b {4..7}{4,c} 24 f8")
    # rhs = braceexpandlist("90 4{8,c} 8b {0..3}{4,c} 24")

    search_r = r"""(?x
        (\x48|\x4c) \x8b [\x44-\x7c] \x24 \xf8
    )"""

    replace_r = "\x90\1\x8b\$(\2 & ~0x40)\x24"

    # classic push - in reverse order (push1)
    search_asm = "mov [rsp-8], {r64}; lea rsp, [rsp-8]" # MOV [RSP-0x8], RAX; LEA RSP, [RSP-0x8]
    # becomes classic push
    # RSP <- RSP - 8; (* Push quadword *)
    # [RSP] <- SRC;
    replace_asm= "lea rsp, [rsp-8]; mov [rsp], {0}; nop"

    # THIS ONE SEEMS INVALID?!
    # pop-peek (double pop, first pop ignored) -- or perhaps this is two halves of different "atomic" instructions
    # DEST <- [RSP + 8]; (* Copy quadword *)
    # RSP <- RSP + 8;
    search_asm = "mov {r64}, [rsp+8]; lea rsp, [rsp+8]"  #  MOV RAX, [RSP+0x8]; LEA RSP, [RSP+0x8]
    # becomes tidier
    # RSP <- RSP + 8;
    # DEST <- [RSP]; (* Copy quadword *)
    replace_asm= "lea rsp, [rsp+8]; mov [rsp], {0}; nop"

    # classic pop - in reverse order (pop2)
    # RSP <- RSP + 8;
    # DEST <- [RSP - 8]; (* Copy quadword *)
    search_asm = "lea [rsp], [rsp+8]; mov {r64}, [rsp-8]" # LEA RSP, [RSP+0x8]; MOV RAX, [RSP-0x8]
    # becomes classic pop
    # DEST <- [RSP]; (* Copy quadword *)
    # RSP <- RSP + 8;
    replace_asm= "nop; mov {0}, [rsp]; lea rsp, [rsp+8]"


    # end messing about

    # intel pop
    # DEST <- [RSP]; (* Copy quadword *)
    # RSP <- RSP + 8;

    # intel push
    # RSP <- RSP - 8; (* Push quadword */
    # [RSP] <- SRC;


    # done it a bitwise obfu now
    if 0:
        for r in movlealistpush:
            obfu.append("", "mov/lea->push order swap: %s" % r[2], hex_pattern(r[0]), process_hex_pattern(r[1]), safe=1, resume=1)
    if 0: # can't find any instances of this in 2189
        for r in movlealistpop:
            obfu.append("", "mov/lea->pop order swap: %s" % r[2], hex_pattern(r[0]), process_hex_pattern(r[1]), safe=1)
    for r in movlealistpop2:
        obfu.append("", "mov/lea->pop#2 order swap: %s" % r[2], hex_pattern(r[0]), process_hex_pattern(r[1]), safe=1, resume=1, then='pop')



    #  48 05 FF FF FF 08                           add     rax, 8FFFFFFh  # standard short form
    #  48 81 C0 FF FF FF 08                        add     rax, 8FFFFFFh  # unused full form
    #  48 81 C1 FF FF FF 08                        add     rcx, 8FFFFFFh
    #  48 81 C2 FF FF FF 08                        add     rdx, 8FFFFFFh
    #  48 81 C3 FF FF FF 08                        add     rbx, 8FFFFFFh
    #  48 81 C4 FF FF FF 08                        add     rsp, 8FFFFFFh
    #  48 81 C5 FF FF FF 08                        add     rbp, 8FFFFFFh
    #  48 81 C6 FF FF FF 08                        add     rsi, 8FFFFFFh
    #  48 81 C7 FF FF FF 08                        add     rdi, 8FFFFFFh
    #
    #  49 81 C0 FF FF FF 08                        add     r8,  8FFFFFFh
    #  49 81 C1 FF FF FF 08                        add     r9,  8FFFFFFh
    #  49 81 C2 FF FF FF 08                        add     r10, 8FFFFFFh
    #  49 81 C3 FF FF FF 08                        add     r11, 8FFFFFFh
    #  49 81 C4 FF FF FF 08                        add     r12, 8FFFFFFh
    #  49 81 C5 FF FF FF 08                        add     r13, 8FFFFFFh
    #  49 81 C6 FF FF FF 08                        add     r14, 8FFFFFFh
    #  49 81 C7 FF FF FF 08                        add     r15, 8FFFFFFh
    #
    #  rax   01001000 00000101 11111111 11111111 11111111 00001000
    #
    #  rbx   01001000 10000001 11000011 11111111 11111111 11111111 00001000
    #  rcx   01001000 10000001 11000001 11111111 11111111 11111111 00001000
    #  rdx   01001000 10000001 11000010 11111111 11111111 11111111 00001000
    #  rbp   01001000 10000001 11000101 11111111 11111111 11111111 00001000
    #  rsp   01001000 10000001 11000100 11111111 11111111 11111111 00001000
    #  rdi   01001000 10000001 11000111 11111111 11111111 11111111 00001000
    #  rsi   01001000 10000001 11000110 11111111 11111111 11111111 00001000
    #
    #  r8    01001001 10000001 11000000 11111111 11111111 11111111 00001000
    #  r9    01001001 10000001 11000001 11111111 11111111 11111111 00001000
    #  r10   01001001 10000001 11000010 11111111 11111111 11111111 00001000
    #  r11   01001001 10000001 11000011 11111111 11111111 11111111 00001000
    #  r12   01001001 10000001 11000100 11111111 11111111 11111111 00001000
    #  r13   01001001 10000001 11000101 11111111 11111111 11111111 00001000
    #  r14   01001001 10000001 11000110 11111111 11111111 11111111 00001000
    #  r15   01001001 10000001 11000111 11111111 11111111 11111111 00001000
    #  hex

    # https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture
    br64 =  "r{{a,c,d,b}x,{s,b}p,{s,d}i,{8..15}}"
    br32 = "{e{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}d}"
    br16 =  "{{{a,c,d,b}x,{s,b}p,{s,d}i},r{8..15}w}"
    br8  =   "{{{a,c,d,b}{h,l},{s,b}pl,{s,d}il},r{8..15}b}"
    r64  = braceexpandlist(br64) # 16
    r32  = braceexpandlist(br32) # 16
    r16  = braceexpandlist(br16) # 16
    r8   = braceexpandlist(br8)  # 20

    flags = braceexpandlist("{{c,p,a,z,s,t,i,d,o,r,vi}f,ac,id,iopl,nt,vip,vm}")
    xmm  = braceexpandlist("xmm{0..15}")
    st87 = braceexpandlist("st{0..7}")
    valid = list()
    valid.append([r64[2], r32[2], r16[2], r8[2 * 2], r8[2 * 2 + 1], xmm[0]])
    valid.append([r64[3], r32[3], r16[3], r8[3 * 2], r8[3 * 2 + 1], xmm[1]])
    valid.append([r64[8], r32[8], r16[8], r8[8 * 2], r8[8 * 1 + 4], xmm[2]])
    valid.append([r64[9], r32[9], r16[9], r8[9 * 2], r8[9 * 1 + 4], xmm[3]])

    # 48 89 e1                              mov rcx, rsp
    # 48 81 c1 f8 ff ff ff                  add rcx, 0FFFFFFFFFFFFFFF8h
    # 51                                    push rcx
    # 5c                                    pop rsp
    with BitwiseMask() as bm:
        for r in r64:
            # convert 32-bit ADD to 8-bit ADD
            if r == 'rsp':
                continue

            # search      = hex_pattern([re.sub(r' de ad ff 08', ' f8 ff ff ff', listAsHex(kassemble(search_asm)))])
            search_asm  = "add {}, dword 0fffffff8h".format(r)
            search      = nassemble(search_asm)
            bm.add_list(search)

            search      = hex_pattern(listAsHex(search).replace('f8 ff ff ff', '08 00 00 00'))
            bm.add_list(search)


            #  printi("searchasm:  %s" % search_asm)
            #  printi("replaceasm: %s" % replace_asm)
            #  printi("search:     %s" % listAsHex(search))
            #  printi("replace:    %s" % listAsHex(replace))

        #  [values, mask] = gen_mask(None, previous)
        #  obfu.append_bitwise(values, mask, patch_32bit_add)
        obfu.append_bitwise(bm.value, bm.mask, patch_32bit_add, resume=1)
        if obfu_debug: pp([binlist(bm._set), binlist(bm._clear), bm._size, bm._reserved, binlist(bm.value), binlist(bm.mask)])


    """
    55                                  push rbp
    48 8d 2d ?? ?? ?? ??                lea rbp, [post_call_jmp]
    48 87 2c 24                         xchg rbp, [rsp]
    55                                  push rbp
    48 8d 2d ?? ?? ?? ??                lea rbp, [call_location]
    48 87 2c 24                         xchg rbp, [rsp]
    c3                                  retn
    """
    """
    0:  55                      push   rbp
    1:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0xfffffffff]
    8:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    c:  55                      push   rbp
    d:  48 8d 2d ?? ?? ?? ??    lea    rbp,[rip+0x1e650e]
    14: 48 87 2c 24             xchg   QWORD PTR [rsp],rbp
    18: c3                      ret
    19:
    """

    """
                                             checksummer2_29 prologue:                                this version can be properly decoded by ida
    000   -8 checksum  55                       push rbp               rsp = -8                         lea rbp, [rsp-0x580]
    008 -1e0 checksum  48 81 ec e0 01 00 00     sub rsp, 0x1e0         rsp = -1e8                       sub rsp, 0x680
    1e8      checksum  48 8d 6c 24 30           lea rbp, [rsp+0x30]    rbp = -1e8 + 30 = -1b8
                                                                                                        mov rbx, [rsp+0x6b0]
                                             checksummer2_29 epilogue:                                  add rsp, 0x680
    1e8 +1e0 checksum  48 8d a5 b0 01 00 00     lea rsp, [rbp+0x1b0]   rsp = -1b8 + 1b0 = 8
    008   +8 checksum  5d                       pop rbp                rsp = 0
    000      checksum  c3                       retn



























    """
    # obfu.append("", "checksummer stack-hide",
    #         hex_pattern([
    #             "55",
    #             "48 81 ec ?? ?? ?? ??",
    #             "48 8d 6c 24 20"
    #         ]),
    #         [],
    #         patch_checksummer
    # )


    """
    note: the function location checksum function can be written two/four/more ways.
    obviously also the REX.W versions

    f7 d8                               neg eax
    03 05 7f 64 66 00                   add eax, [dword_140000000]
    --
    33 05 6c d9 66 01                   xor eax, [dword_140000000]

    """
    #  with BitwiseMask() as bm:
    #  140dd659b Search|Replace (B): 48 f7 c4 0f 00 00 00 0f 85 -1 -1 -1 -1 6a 18 48 81 ec 08 00 00 00|[-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 72, 129, 196, 16, 0, 0, 0]
              #  checksummer-stack-align
    #  search = hex_pattern([
                #  #  "6a 10",                # push 0x10
                #  "48 f7 c4 0f 00 00 00", # test rsp, 0xf
                #  "0f 85 ?? ?? ?? ??",    # jnz label1
                #  "6a 18",                # push 0x18
                #  "48 81 ec 08 00 00 00", # sub rsp, 8
                #  #  "e8 ?? ?? ?? ??",       # call ArxanMutator_7
                #  #  "48 03 64 24 08",       # add rsp, [rsp+8]
    #  ])
    #  bm.add_list(search)
    obfu.append("", "checksummer-stack-align",
            # 48 f7 c4 0f 00 00 00 0f 85 7c 62 60 ff 6a 18 48 81 ec 08 00 00 00
            # 48 f7 c4 0f 00 00 00 0f 85 ?? ?? ?? ?? 6a 18 48 81 ec 08 00 00 00
            # 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21
            #
            # From:
            #  6a 10                         	push 0x10
            #  48 f7 c4 0f 00 00 00          	test rsp, 0xf
            #  0f 85 fd b7 3a ff             	jnz loc_143C0A8A6
            #  6a 18                         	push 0x18
            #  48 81 ec 08 00 00 00          	sub rsp, 8
            #  e8 3c 69 ef ff                	call ArxanCheckFunction2_531
            #  48 03 64 24 08                	add rsp, [rsp+8]
            #
            # To:
            #  6a 10                         	push 0x10
            #  0f 1f 84 00 00 00 00 00       	nop dword [rax+rax+0]
            #  0f 1f 44 00 00                	nop dword [rax+rax+0]
            #  66 90                         	nop
            #  0f 1f 80 00 00 00 00          	nop dword [rax+0]
            #  e8 3c 69 ef ff                	call ArxanCheckFunction2_531
            #  48 8d 64 24 08                	lea rsp, [rsp+8]
            #
            #
            hex_pattern([
                        "6a 10",                # 2  push 0x10
                        "48 f7 c4 0f 00 00 00", # 7  test rsp, 0xf
                        "0f 85 ?? ?? ?? ??",    # 6  jnz label1
                        "6a 18",                # 2  push 0x18
                        "48 81 ec 08 00 00 00", # 7  sub rsp, 8
                        "e8 ?? ?? ?? ??",       # 5  call ArxanMutator_7
                        "48 03 64 24 08",       # 5  add rsp, [rsp+8]
            ]),
            #  48 83 C4 10 0f 1f 00
            # hex_pattern(["??"] * 15 + ["48 81 C4 10 00 00 00"]),
            hex_pattern([
                "6a 10",                        # push 0x10
                "0f 1f 84 00 00 00 00 00",      # nop dword [rax+rax+0]
                "0f 1f 44 00 00",               # nop dword [rax+rax+0]
                "66 90",                        # nop
                "0f 1f 80 00 00 00 00",         # nop dword [rax+0]
                "e8 ?? ?? ?? ??",               # call ArxanCheckFunction2_531
                "48 8d 64 24 08",               # lea rsp, [rsp+8]
            ]),
            safe=1,
            resume=1,
            replFunc = lambda _search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs: \
                    ["push 0x10", diida(addressList[21+3]), "lea rsp, [rsp+8]"]
            # patch_stack_align

    )


    # :'<,'>s@"\(.*\)",\(.*\)@\=printf("\"%s\", %d %s", submatch(1), (strlen(submatch(1))+1)/3, submatch(2))
    # :'<,'>s@"\(.*\)",.*#\(.*\)@\=printf("\"%s\",\t# %d %s", submatch(1), (strlen(submatch(1))+1)/3, submatch(2))
    obfu.append("", "checksummer-stack-realign",
            hex_pattern([
                        "6a 10",                # 2  push 0x10
                        "48 f7 c4 0f 00 00 00", # 7  test rsp, 0xf
                        "0f 85 ?? ?? ?? ??",    # 6  jnz label1
                        "6a 18",                # 2  push 0x18
                        "48 83 C4 10",          # 4  add rsp, 0x10  :  expr 2 + 7 + 6 + 2 + 4 = 21
                        "e8 ?? ?? ?? ??",       # 5  call ArxanMutator_7
                        "48 03 64 24 08",       # 5  add rsp, [rsp+8]
            ]),
            safe=1,
            resume=1,
            replFunc = lambda _search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs: \
                    ["push 0x10", diida(addressList[21]), "lea rsp, [rsp+8]"]

            #  group=bm,
            #  reflow=1
    )
    #  6a 10                                push 0x10
    #  48 f7 c4 0f 00 00 00                 test rsp, 0xf
    #  0f 85 ?? ?? ?? ??                    jnz label1
    #  6a 18                                push 0x18
    #  48 81 ec 08 00 00 00                 sub rsp, 8
    #  e8 ?? ?? ?? ??                       call ArxanMutator_7



    if False:
        obfu.append("this is just to make the ArxanBalance functions easier to emu through",
                "add rsp, [rsp+0x8] => add rsp, 0x8",
                hex_pattern(["48 03 64 24 08"]), # add rsp, [rsp+0x8]
                ["add rsp, 0x8"],
                safe=1,
                resume = 1,
        )

    obfu.append("push qword [rdx+28h]; retn", "8bit push-retn tailcall",

            #  hex_pattern(["FF 62 28", "CC"]), # jmp  qword [rdx+0x28]

            # generally:
            # {70..77} or (n & ~0x77 == 0) or '0b1110...'
            bit_pattern(["FF 70&F8 ?? C2&FE"]),  # FF 72 28 C3   # push qword [rdx+0x28]; retn
            # bit_pattern(["FF 00~10 ?? CC"]),   # ff 62 28 cc   # jmp  qword [rdx+0x28]
            bit_pattern(["00~ff 00~ef 00~ff 0c~fc"]),

            # extra registers are 41 FF 70/77 ??
            safe=1, reflow=1
    )

    obfu.append("""
        refresh_bitwise()
        bm1 = BitwiseMask()
        for r in r64: bm1.add_list(nassemble('add {}, -8'.format(r)))
        printi(bm1.masked_pattern)     # '48&fe 83 c0&f8 f8'
        printi(bm1.pattern)            # '48~49 83 c0~c7 f8'
        printi(bm1.tri)

        bm2 = BitwiseMask()
        for r in r64: bm2.add_list(nassemble("sub {}, 8".format(r)))
        printi(bm2.masked_pattern)     # '48&fe 83 e8&f8 08'
        printi(bm2.pattern)            # '48~49 83 e8~ef 08'
        printi(bm2.tri)

        printi(bm1.diff(bm2))

        48&fe 83 c0&f8 f8     48~49 83 c0~c7 f8     0100100. 10000011 11000... 11111000
        48&fe 83 e8&f8 08     48~49 83 e8~ef 08     0100100. 10000011 11101... 00001000
                                                    ........ ........ ..1.1... 0000....
        """,
        "add r64, -8 => sub r64, 8",
        bit_pattern(['48&fe 83 c0&f8 f8']),
        # bit_pattern(['48~fe 83 e8~00 00~f0']),
        bit_pattern(['00~ff 00~ff 28~ff 00~0f']),
        safe=1, reflow=1
    )

    obfu.append("push qword [rdx]; retn", "0-offset push-retn tailcall",
            #  hex_pattern(["FF 32", "C3"]), # push qword [rdx]; retn
            #  hex_pattern(["FF 22", "CC"]), # jmp  qword [rdx]; int3

            # generally, for first 8 registers:
            bit_pattern(["FF 30&F8 C2&FE"]), # allow for `retn 0` [c2 00 00]
            bit_pattern(["FF 00~10 CC"]),    # jmp qword [rdx]; int3

            # extra registers are 41 FF 70/77 ??
            safe=1, reflow=1
    )

    obfu.append(
            brief    = "jmp locret",
            search   = PatternGroup(nassemble("retn"), nassemble("retn 0")),
            replFunc = lambda _search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs: \
                    [] if kwargs['addressListFull'][0] == ea else ["retn"]
    )



    #  obfu.append("", "checksummer self-position-check",
            #  hex_pattern([
                #  "48 8D 05 ?? ?? ?? ??",
                #  "48 89 45 ??",
                #  "48 8B 05 ?? ?? ?? ??",
                #  "48 F7 D8",
                #  "48 03 45 ??",
                #  #  "48 89 45 ??",
                #  #  "48 8B 45 ??",
            #  ]),
            #  hex_pattern(["48 31 c0"])
    #  )
#
    #  obfu.append("", "checksummer self-position-check #2",
            #  hex_pattern([
                #  "48 8B 05 ?? ?? ?? ??",  # mov     rax, cs:chucksummer2_abs_21
                #  "48 F7 D8",  # neg     rax
                #  "48 8D 15 ?? ?? ?? ??",  # lea     rdx, checksummer2_21
                #  "48 8D 04 02"  # lea     rax, [rdx+rax]
            #  ]),
            #  ['xor rax, rax']
    #  )

    obfu.append("", "call 2nd then return to 1st, via double push rsp and ret",
            hex_pattern([
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "c3",
            ]),
            [],
            patch_double_rsp_push_call_jump,
            reflow=1
            )

    obfu.append("", "call 2nd then return to 1st, mangled",
            # From:
            #  55                                            push    rbp             
            #  48 8D 2D 08 00 00 00                          lea     rbp, loc_140A2EBF0 
            #  48 87 2C 24                                   xchg    rbp, [rsp]
            #  E9 0B 00 00 00                                jmp     loc_140A2EC00
            #
            # To:
            #  E8 17 00 00 00                                call    loc_140A2EC00   ; lea rsp, qword ptr [rsp-8]; mov [rsp], rbp [140a2ebe4–140a2ebec]
            #  E9 06 00 00 00                                jmp     loc_140A2EBF0   ; call 2nd then return to 1st, via double push rsp and ret [140a2ebe4–140a2ec04]
            #
            #
            hex_pattern([
                        "55",                   # 1  push rbp
                        "48 8d 2d ?? ?? ?? ??", # 7  lea rbp, jmp_loc
                        "48 87 2c 24",          # 4  xchg rbp, [rsp]
                        "e9 ?? ?? ?? ??",       # 5  jmp call_loc
            ]),
            [],
            replFunc = lambda _search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs: \
                    ["call {:#x}".format(GetTarget(addressList[1+7+4])), "jmp {:#x}".format(GetTarget(addressList[1])), "int3"],
            safe=1,
            resume=1,
            priority=1

    )

    obfu.append("", "call 2nd then return to 1st, via lossy rbp manip and ret",
            hex_pattern([
                "48 8d 64 24 f8",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "c3"
            ]),
            [],
            patch_double_rsp_push_call_jump_b,
            reflow=1
            )

    """
    48 8b 05 ?? ?? ?? ??          	mov rax, [off_1444A47E3]
    8b 15 ?? ?? ?? ??             	mov edx, [dword_140CACA7A]
    89 d1                         	mov ecx, edx
    55                            	push rbp
    48 8d 2d ?? ?? ?? ??          	lea rbp, [loc_1453C4847]
    48 87 2c 24                   	xchg [rsp], rbp
    ff e0                         	jmp rax
    """
    obfu.append("", "call 2nd then return to 1st, via push rax, rsp and jmp",
            hex_pattern([
                "48 8b 05 ?? ?? ?? ??",
                "8b 15 ?? ?? ?? ??",
                "89 d1",
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "ff e0",
            ]),
            [],
            patch_single_rsp_push_call_jump,
            reflow=1
            )

    obfu.append("""
            .text:143787503   a8   -8 ChecksumOrHealer 55                            	push rbp
            .text:14378750c   b0      ChecksumOrHealer 48 8d 2d 52 41 5c 01          	lea rbp, [label22]
            .text:143787513   b0      ChecksumOrHealer 48 87 2c 24                   	xchg [rsp], rbp
            .text:143787517   b0      ChecksumOrHealer c3                            	retn

            .text:14181c629   d8   -8 ecksumOrHealer_2 55                            	push rbp
            .text:14181c633   e0      ecksumOrHealer_2 48 8d 2d ed ab 95 02          	lea rbp, [loc_144177227]
            .text:144a4db66   e0      ecksumOrHealer_2 48 87 2c 24                   	xchg [rsp], rbp
            .text:144a4db6a   e0      ecksumOrHealer_2 c3                            	retn

            """,
            "jmp via push rbp and xchg",
            hex_pattern([
                "55",                     # push rbp
                "48 8d 2d ?? ?? ?? ??",   # lea rbp, [whatever]
                "48 87 2c 24",            # xchg rbp, [rsp]
                "c3",                     # retn
            ]),
            [],
            # interpolation patch engine
            simple_patch_factory([
                "jmp {hex(idc.get_operand_value(addressList[1], 1))}",
                "int3"]),
            safe=1, reflow=1
    )

    obfu.append("""
            A catch-early version of the above, should save restarts due to `retn`

            """,
            "jmp via push rbp, xchg, lea rsp, jmp rsp-8",
            hex_pattern([
                "55",                     # push rbp
                "48 8d 2d ?? ?? ?? ??",   # lea rbp, [whatever]
                "48 87 2c 24",            # xchg rbp, [rsp]
                "48 8d 64 24 08",         # lea rsp, [rsp+8]
                "ff 64 24 f8"             # jmp qword [rsp-8]
            ]),
            [],
            # interpolation patch engine
            simple_patch_factory([
                "jmp {hex(idc.get_operand_value(addressList[1], 1))}",
                "int3"]),
            safe=1, reflow=1
    )

    if False: obfu.append("""
        (These disassembled sections aren't actually used, they're just there are comments really)
        XXX: We need to include the push in the search (and subsequent replace) else we will
             imbalance the stack.  Unfortunately this will mean far less matches... so... hmm....
             or is it actually correct to leave the push in?

        .text:00007FF746636E16 000 55                              push    rbp
        .text:00007FF746636E17 008 48 8D 2D AB DD FF FF            lea     rbp, sub_7FF746634BC9
        .text:00007FF746636E1E 008 48 87 2C 24                     xchg    rbp, [rsp]
        .text:00007FF746636E22 008 C3                              retn

        0:  55                      push   rbp
        1:  48 8d 2d 00 00 00 00    lea    rbp,[rip+0x0]        # 0x8
        8:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
        c:  c3                      ret

        .text:0000000143787503 000 55                                            push    rbp
        .text:0000000143787504 000 48 8D 2D 5A 41 5C 01                          lea     rbp, loc_144D4B665
        .text:000000014378750B 000 48 87 2C 24                                   xchg    rbp, [rsp]
        .text:000000014378750F 000 C3                                            retn
        """, "push rbp, xchg with rsp and return to effect jmp",
        hex_pattern([
            "90 90 90",
            "55",
            "48 8d 2d ?? ?? ?? ??",
            "48 87 2c 24",
            "c3"
        ]),
        [],
        # def generate_patch1(jmpTargetOffset, oldRip = 0, newRip = 0, jmpType = 0xE9):
        generate_patch1(1+3) # , 1+3+4, 1+4)
        , safe=1, reflow=1
        )
    if False: obfu.append("""
            .text:0000000143787503 000 55                                            push    rbp
            .text:0000000143787504 000 48 8d 2d 5a 41 5c 01                          lea     rbp, loc_144d4b665
            .text:000000014378750b 000 48 87 2c 24                                   xchg    rbp, [rsp]
            .text:000000014378750f 000 c3                                            retn
            """,
            "jmp via push rsp and retn",

            hex_pattern([
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
            ]),
            [],
            patch_single_rsp_push_call_jump, reflow=1
            )
    """
        ;========================================
        mov rdi, [rsp]
        lea rsp, qword ptr [rsp+8]
        ;========================================
        pop rdi
        ;========================================
    """
    ###
    # search for
    #     push    rdi
    #     mov     eax, [rsp]
    #     pop     rdi
    # replace with
    #     mov eax, edi
    ###

    with BitwiseMask() as bm:
        for r in r64:
            # convert 32-bit ADD to 8-bit ADD
            if r == 'rsp':
                continue

            # search      = hex_pattern([re.sub(r' de ad ff 08', ' f8 ff ff ff', listAsHex(kassemble(search_asm)))])
            search_asm  = "add {}, dword 0fffffff8h".format(r)
            search      = nassemble(search_asm)
            bm.add_list(search)

            search      = hex_pattern(listAsHex(search).replace('f8 ff ff ff', '08 00 00 00'))
            bm.add_list(search)


            #  printi("searchasm:  %s" % search_asm)
            #  printi("replaceasm: %s" % replace_asm)
            #  printi("search:     %s" % listAsHex(search))
            #  printi("replace:    %s" % listAsHex(replace))

        #  [values, mask] = gen_mask(None, previous)
        #  obfu.append_bitwise(values, mask, patch_32bit_add)
        obfu.append_bitwise(bm.value, bm.mask, patch_32bit_add, resume=1)
        if obfu_debug: pp([binlist(bm._set), binlist(bm._clear), bm._size, bm._reserved, binlist(bm.value), binlist(bm.mask)])

    if "bitwise_mov32,64":
        searches = [
            "50&f8 8b 04&c7 24 58&f8"
        ]
        replace_bits = "10001001 11......"
        replace_eval = \
            "x.bitset(10,y.bitget(5))r " + \
            "x.bitset(11,y.bitget(6))r " + \
            "x.bitset(12,y.bitget(7))r " + \
            "x.bitset(13,y.bitget(18))r " + \
            "x.bitset(14,y.bitget(19))r " + \
            "x.bitset(15,y.bitget(20))r"

        replace = BitwiseMask(replace_bits, replace_eval)
        #  replace.add(replace_eval)
        for i, search in enumerate(searches):
            obfu.append("", "",
                    BitwiseMask(search),
                    replace,
                    safe=1,
                    resume=1,
            )

        searches = [
            "41 50&f8 44 8b 04&c7 24 41 58&f8"
        ]
        replace_bits = "01000101 10001001 11......"
        replace_eval = \
            "x.bitset(18,y.bitget(13))r " + \
            "x.bitset(19,y.bitget(14))r " + \
            "x.bitset(20,y.bitget(15))r " + \
            "x.bitset(21,y.bitget(34))r " + \
            "x.bitset(22,y.bitget(35))r " + \
            "x.bitset(23,y.bitget(36))r"

        replace = BitwiseMask(replace_bits)
        replace.add(replace_eval)
        for i, search in enumerate(searches):
            obfu.append("", "",
                    BitwiseMask(search),
                    replace,
                    safe=1,
                    resume=1,
            )
    else:

        with BitwiseMask() as bm:
            # iterate through combinations of 64bit and 32bit registers
            for (src64, dst32) in (itertools.product(r64, r32)):
                # get register indexes (allows translation from rax to eax)
                src_index = r64.index(src64)
                dst_index = r32.index(dst32)

                # skip nonsensical 'mov rax, rax'
                if src_index == dst_index:
                    continue

                # determine 32bit register for destination
                src32 = r32[src_index]
                #
                # push rdx; mov ebx, [rsp]; pop rdx: repl: 89 d3
                #
                #  .text:140cd164e 028   -8 cover_set_impl_0              52                                       push RDX
                #  .text:143f3f5f4 030      cover_set_impl_0              8b 1c 24                                 mov EBX, [RSP]
                #  .text:143f3f5f7 030   +8 cover_set_impl_0              5a                                       pop RDX
                #
                # -> (wrong) mov     ecx, ebp
                search_asm  = "push {0}; mov {1}, [rsp]; pop {0}".format(src64, dst32)
                replace_asm = "mov {}, {}".format(dst32, src32)

                search      = kassemble(search_asm)
                replace     = kassemble(replace_asm)

                bm.add_list(search)

                obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, group=bm, resume=1)


    """
    ;========================================
    lea rsp, qword ptr [rsp-8]
    mov [rsp], r12
    ;========================================
    push r12
    ;========================================
    """

    for search_asm_fmt in braceexpandlist(braceform(
        """
            mov {0}, rsp      | push rsp; pop {0}
            sub {0}, 8        | lea rsp, [rsp-8]
            push {0}; pop rsp | mov rsp, {0}
        """
        )):

        replace_asm = "lea rsp, [rsp-8]"
        replace     = kassemble(replace_asm)

        for src in r64:
            if src == 'rsp': continue

            search_asm  = search_asm_fmt.format(src)
            search      = kassemble(search_asm)

            obfu.append('', 'generic rsp decrement', search, process_replace(replace, replace_asm), safe=1, resume=1, then='push')

    for search_asm_fmt in braceexpandlist(braceform(
        """
            mov {0}, rsp      | push rsp; pop {0}
            add {0}, 8        | lea rsp, [rsp+8]
            push {0}; pop rsp | mov rsp, {0}
        """)):

        replace_asm = "lea rsp, [rsp+8]"
        replace     = kassemble(replace_asm)

        for src in r64:
            # skip possibly dangerous rsp
            if src == 'rsp':
                continue

            search_asm  = search_asm_fmt.format(src)
            search      = kassemble(search_asm)

            obfu.append('', 'generic rsp increment', search, process_replace(replace, replace_asm), safe=1, resume=1, then='pop')


    if 0:
        with BitwiseMask() as bm:
            for src in r64:
                if src == 'rsp':
                    continue

                search_asm  = "mov {0}, rsp; sub {0}, 8; push {0}; pop rsp".format(src)
                replace_asm = "lea rsp, [rsp-8]"
                search      = kassemble(search_asm)
                replace     = kassemble(replace_asm)


                bm.add_list(search)
                obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, group=bm, resume=1)

        with BitwiseMask() as bm:
            for src in r64:
                if src == 'rsp':
                    continue

                search_asm  = "mov {0}, rsp; sub {0}, 8; mov rsp, {0}".format(src)
                replace_asm = "lea rsp, [rsp-8]"
                search      = kassemble(search_asm)
                replace     = kassemble(replace_asm)


                bm.add_list(search)
                obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, group=bm, resume=1)



        with BitwiseMask() as bm:
            for src in r64:
                if src == 'rsp':
                    continue

                search_asm  = "mov {0}, rsp; sub {0}, 8; push {0}; pop rsp".format(src)
                replace_asm = "lea rsp, [rsp-8]"
                search      = kassemble(search_asm)
                replace     = kassemble(replace_asm)


                bm.add_list(search)
                obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, group=bm, resume=1)


        with BitwiseMask() as bm:
            for src in r64:
                # skip possibly dangerous rsp
                if src == 'rsp':
                    continue

                search_asm  = "mov {0}, rsp; add {0}, 8; mov rsp, {0}".format(src)
                replace_asm = "lea rsp, [rsp+8]"
                search      = kassemble(search_asm)
                replace     = kassemble(replace_asm)

                #  printi("searchasm:  %s" % search_asm)
                #  printi("replaceasm: %s" % replace_asm)
                #  printi("search:     %s" % listAsHex(search))
                #  printi("replace:    %s" % listAsHex(replace))

                bm.add_list(search)
                obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, group=bm, resume=1)


    """
        ;========================================
        mov rdi, [rsp]
        lea rsp, qword ptr [rsp+8]
        ;========================================
        pop rdi
        ;========================================
    """

    if obfu_debug: printi("slow_load: 1")

    #  48 8B 04 24                                   mov     rax, [rsp]
    #   or
    #  4C 8B 04 24                                   mov     r8, [rsp]
    #   then
    #  48 8D 64 24 08                                lea     rsp, [rsp+8]
    obfu.append(""" """, "mov {}, [rsp]; lea rsp, [rsp+8] => pop {}",
            bit_pattern("48&fb 8b 04&c7 24 48 8d 64 24 08"),
            "",
            lambda a, b, c, *args, **kwargs: (len(a), [0x58 | ((c[2] & 0x38) >> 3)] if not c[0] & 4 else [0x41, 0x58 | ((c[2] & 0x38) >> 3)]),
            label='pop', resume=1,
    )


    # 41 52        push r10        ; \
    # 8b 04 24     mov eax, [rsp]  ;  > mov eax, r10d \
    # 41 5a        pop r10         ; /                 > mov [rbx], r10d
    # 87 03        xchg [rbx], eax ;                  /
    
    # "41 52 8b 04 24 41 5a 87 03" -> "44 89 13"

    obfu.append(""" """, "push r10, mov eax, [rsp], pop r10, xchg [rbx], eax => mov [rbx], r10d",
            bit_pattern("41 52 8b 04 24 41 5a 87 03"),
            "",
            lambda a, b, c, *args, **kwargs: (len(a), [0x44, 0x89, 0x13]),
            resume=1,
    )

    #  for src in r64:
        #  # skip possibly dangerous rsp
        #  if src == 'rsp':
            #  continue
#
        #  search_asm  = "mov {}, [rsp]; lea rsp, qword ptr [rsp+8]".format(src)
        #  replace_asm = "pop {}".format(src)
        #  search      = kassemble(search_asm)
        #  replace     = kassemble(replace_asm)
#
        #  obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), safe=1, resume=1, label='pop', priority=5)


    for pushed in r64:
        # skip possibly dangerous rsp
        if pushed == 'rsp':
            continue

        # related/dupe of bit_pattern("48 89 e0 48 05 f8 ff ff ff 48 89 c4 48 89 04~3c 24") ???
        # apparently not, need to document that ^^^ though
        # 54 58 48 83 c0 f8 90 90 90 50 5c 89 04 24


        # bitwise search: 48 8d 64 24 f8 48~4c 89 04~3c 24
        search_asm  = "lea rsp, qword ptr [rsp-8]; mov [rsp], {0}".format(pushed)
        search      = kassemble(search_asm)
        replace_asm = "push {}".format(pushed)
        replace     = kassemble(replace_asm)


        obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1, resume=1, priority=5)
        # obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1)

        #  search_asm  = "mov {0}, rsp; add {0}, -8; mov rsp, {0}; mov [rsp], {1}".format(tmp, pushed)
        #  search      = kassemble(search_asm)
        #
        #  obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1, resume=1)
        #  # obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1)
        #
        #  search_asm  = "push rsp; pop {0}; add {0}, -8; mov rsp, {0}; mov [rsp], {1}".format(tmp, pushed)
        #  search      = kassemble(search_asm)
        #
        #  obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1, resume=1)
        #  # obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1)
        #
        #  search_asm  = "mov {0}, rsp; add {0}, -8; push {0}; pop rsp; mov [rsp], {1}".format(tmp, pushed)
        #  search      = kassemble(search_asm)
        #
        #  obfu.append(search_asm, search_asm, search, process_replace(replace, replace_asm), label='push', safe=1, resume=1)
        #  # obfu.append(search_asm, search_asm, search, process_replace_nocheck(replace, replace_asm), label='push', safe=1)


    if obfu_debug: printi("slow_load: 3")
    if "bitwise version":
        searches = [
            "50&f8 48 8b 04&c7 24 54 58&f8 48 83 c0&f8 08 50&f8 5c",
            "50&f8 48 8b 04&c7 24 54 58&f8 48 83 c0&f8 08 48 89 c4&c7",
            "50&f8 48 8b 04&c7 24 48 89 e0&f8 48 83 c0&f8 08 50&f8 5c",
            "50&f8 48 8b 04&c7 24 48 89 e0&f8 48 83 c0&f8 08 48 89 c4&c7",
        ]
        replace_eval = \
            "x.bitset(18,y.bitget(5))r "  + \
            "x.bitset(19,y.bitget(6))r "  + \
            "x.bitset(20,y.bitget(7))r "  + \
            "x.bitset(21,y.bitget(26))r " + \
            "x.bitset(22,y.bitget(27))r " + \
            "x.bitset(23,y.bitget(28))r"

        replace = BitwiseMask(replace_bits)
        replace.add(replace_eval)
        for i, search in enumerate(searches):
            obfu.append("", "mov r1, r2 (#{})".format(i),
                    BitwiseMask(search),
                    replace,
                    safe=1,
                    resume=1,
            )
    else:
        for (dst, src, tmp) in (itertools.product(_.without(r64[0:8], 'rsp'), _.without(r64[0:8], 'rsp'), _.without(r64[0:8], 'rsp'))):

            # skip nonsensical 'mov rax, rax'
            if dst == src or dst == tmp: # this can happen: src == tmp:
                continue
            # skip possibly dangerous rsp
            if dst == 'rsp' or src == 'rsp' or tmp == 'rsp':
                continue

            """
            51                                   push src                         ; *(--rsp) = src
            4c 8b 0c 24                          mov dst, [rsp]                   ; dst = *rsp                     ; dst = src
            49 89 e0                             mov tmp, rsp                     ; tmp = rsp                      ; rsp += 8
            49 81 c0 08 00 00 00                 add tmp, 8                       ; tmp += 8                       ;
            4c 89 c4                             mov rsp, tmp                     ; rsp = tmp                      ;
            """

            """
            51           push src         *++rsp = src      rsp = 50    rsp[50] = src
            48 8b 1c 24  mov dst, [rsp]   dst  = *rsp       rsp = 50    dst = rsp[50] = src
            54           push rsp         *++rsp = rsp - 8  rsp = 58    rsp[58] = 50
            5a           pop tmp          tmp  = *--rsp     rsp = 50    tmp = rsp[58] = 50
            48 83 c2 08  add tmp, 8       tmp  -= 8         rsp = 50    tmp = tmp - 8 = 48
            52           push tmp         *++rsp = tmp      rsp = 58    rsp[58] = tmp = 48
            5c           pop rsp          rsp = *rsp--      rsp = rsp[58] = tmp  = 48
            """

            """
            51                                  push src                 *++rsp = src             0x30 = src
            48 8b 1c 24                         mov dst, [rsp]           dst    = *rsp            dst = src
            48 89 e1                            mov src, rsp             src    = rsp             /
            48 81 c1 08 00 00 00                add src, 8               src   += 8               | add rsp, 8
            48 89 cc                            mov rsp, src             rsp    = src             \
            """

            replace_asm = "mov {0}, {1}".format(dst, src)
            replace     = kassemble(replace_asm)


            # push {1} -- This seems very wrong
            #  search_asm  = "push {1}; mov {0}, [rsp]; mov {2}, rsp; add {2}, 8; push {1}; pop rsp".format(dst, src, tmp)
            #  search      = kassemble(search_asm)
            #  obfu.append_slow(search_asm, search_asm, search, replace)

            search_asm  = "push {1}; mov {0}, [rsp]; mov {2}, rsp; add {2}, 8; mov rsp, {2};".format(dst, src, tmp)
            search     = kassemble(search_asm)
            obfu.append(search_asm, search_asm, search, process_replace_nocheck(replace, replace_asm), safe=1, resume=1)

            search_asm  = "push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; push {2}; pop rsp".format(dst, src, tmp)
            search      = kassemble(search_asm)
            obfu.append(search_asm, search_asm, search, process_replace_nocheck(replace, replace_asm), safe=1, resume=1)

            search_asm  = "push {1}; mov {0}, [rsp]; mov {2}, rsp; add {2}, 8; push {2}; pop rsp".format(dst, src, tmp)
            search      = kassemble(search_asm)
            obfu.append(search_asm, search_asm, search, process_replace_nocheck(replace, replace_asm), safe=1, resume=1)

            search_asm  = "push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; mov rsp, {2}".format(dst, src.tmp)

            # braceexpandlist('push {1}; mov {0}, [rsp]; {push rsp; pop {2},mov {2}\, rsp};      add {2}, 8; {push {2}; pop rsp,mov rsp\, {2}}')


            #  push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; mov rsp, {2};
            #  push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; mov rsp, {2};
            #  push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; push {2}; pop rsp
            #  push {1}; mov {0}, [rsp]; mov {2}, rsp;      add {2}, 8; push {2}; pop rsp;
            #  push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; mov rsp, {2};
            #  push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; push {2}; pop rsp
            #  push {1}; mov {0}, [rsp]; push rsp; pop {2}; add {2}, 8; push {2}; pop rsp;

            #    for search_asm_fmt in braceexpandlist(braceform(
            #        """
            #            push {1}
            #            mov {0}, [rsp]
            #            push rsp; pop {2} | mov {2}, rsp
            #            add {2}, 8
            #            push {2}; pop rsp | mov rsp, {2}
            #        """))

    printi("slow_load: 4")
    #  disabled until we can prioritise this below the checksummer stack fix
    #  obfu.append("add rsp to previously pushed constant", 'add rsp, xmmword ptr [rsp+8]',
            #  hex_pattern(["48 03 64 24 ??"]),
            #  [],
            #  patch_manual, safe=1, resume=1)

    #  .text:0000000143C0686A 178 6A 10                                   push    10h
    #  .text:0000000143C0686C 180 48 F7 C4 0F 00 00 00                    test    rsp, 0Fh
    #  .text:0000000143C06873 180 0F 85 09 0D C7 FD                       jnz     loc_141877582
    #  .text:0000000143C06879 180 E9 FC E0 E6 FC                          jmp     loc_140A7497A

    #  disabled until we can prioritise this below the checksummer stack fix
    #  obfu.append("add rsp to previously pushed constant", 'add rsp, xmmword ptr [rsp+8]',
            #  hex_pattern(["6a ??"]),
            #  [],
            #  patch_manual_store, safe=1)

    # need to add in stupid int3 skipping via UnhandledExceptionHandler as they confuse this patch


    #  48 8b 05 43 dd 00 fd          	mov rax, [off_140D0AB4C]
    #  8b 15 2d 6c d6 fc             	mov edx, [dword_140A63A3C]
    #  89 d1                         	mov ecx, edx
    #  55                            	push rbp
    #  48 8d 2d a2 bc db ff          	lea rbp, [label22]
    #  48 87 2c 24                   	xchg [rsp], rbp
    #  50                            	push rax
    #  c3                            	retn
    obfu.append(None, "call-then-jump-via-push-push-ret",
            hex_pattern(["48 8b 05"]), # mov rax, []
            [],
            patch_double_stack_push_call_jump,
            safe=1, reflow=1
            )





    """
        ;========================================
        mov rdi, [rsp]
        lea rsp, qword ptr [rsp+8]
        ;========================================
        pop rdi
        ;========================================
    """

    """
            0:  48 ?? ?? ?? ?? ?? ?? ?? movabs rbp, location_1            48 bd b4 a7 c6 40 01      mov     rbp, offset location_1      mov     rbp, offset location_1
            a:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp        48 87 2c 24               xchg    rbp, [rsp]                  xchg    rbp, [rsp]
            e:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]              48 8d 64 24 f8            lea     rsp, [rsp-8]                lea     rsp, [rsp-8]
            13: 48 89 ?? 24             mov    QWORD PTR [rsp],ONE        48 89 14 24               mov     [rsp], rdx                  mov     [rsp], rdx
            17: 48 8d 64 24 f8          lea    rsp,[rsp-0x8]              48 8d 64 24 f8            lea     rsp, [rsp-8]                lea     rsp, [rsp-8]
            1c: 48 89 ?? 24             mov    QWORD PTR [rsp],TWO        48 89 1c 24               mov     [rsp], rbx                  mov     [rsp], rbx
            20: 48 8b ?? 24 10          mov    ONE,QWORD PTR [rsp+0x10]   48 8b 54 24 10            mov     rdx, [rsp+10h]              mov     rdx, [rsp+10h]
            25: 48 ?? ?? ?? ?? ?? ?? ?? movabs TWO, location_2            48 bb 99 a7 c6 40 01      mov     rbx, offset location_2      mov     rbx, offset location_2
            2f: 48 0f 45 ??             cmovne ONE,TWO                    48 0f 45 d3               cmovnz  rdx, rbx                    cmovnz  rdx, rbx
            33: 48 89 ?? 24 10          mov    QWORD PTR [rsp+0x10],ONE   48 89 54 24 10            mov     [rsp+10h], rdx              mov     [rsp+10h], rdx
            38: 48 8b ?? 24             mov    TWO,QWORD PTR [rsp]        48 8b 1c 24               mov     rbx, [rsp]                  mov     rbx, [rsp]
            3c: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8d 64 24 08            lea     rsp, [rsp+8]                lea     rsp, [rsp+8]
            41: 48 8b ?? 24             mov    ONE,QWORD PTR [rsp]        48 8d 64 24 08          > mov     rdx, [rsp]                  lea     rsp, [rsp+8]
            45: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8b 54 24 f8          > lea     rsp, [rsp+8]                mov     rdx, [rsp-8]
            4a: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8d 64 24 08            lea     rsp, [rsp+8]                lea     rsp, [rsp+8]
            4f: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]        ff 64 24 f8               jmp     qword ptr [rsp-8]           jmp     qword ptr [rsp-8]

            48 bd b4 a7 c6 40 01 00 00 00       mov     rbp, offset location_1
            48 87 2c 24                         xchg    rbp, [rsp]
            48 8d 64 24 f8                      lea     rsp, [rsp-8]
            48 89 14 24                         mov     [rsp], rdx
            48 8d 64 24 f8                      lea     rsp, [rsp-8]
            48 89 1c 24                         mov     [rsp], rbx
            48 8b 54 24 10                      mov     rdx, [rsp+10h]
            48 bb 99 a7 c6 40 01 00 00 00       mov     rbx, offset location_2
            48 0f 45 d3                         cmovnz  rdx, rbx
            48 89 54 24 10                      mov     [rsp+10h], rdx
            48 8b 1c 24                         mov     rbx, [rsp]
            48 8d 64 24 08                      lea     rsp, [rsp+8]
            48 8b 14 24                         mov     rdx, [rsp]
            48 8d 64 24 08                      lea     rsp, [rsp+8]
            48 8d 64 24 08                      lea     rsp, [rsp+8]
            ff 64 24 f8                         jmp     qword ptr [rsp-8]


            48 8d 64 24 08     48 8b 54 24 f8
"""


    if obfu_debug: printi("slow_load: 1")
    obfu.append("""
         000 #  1 54                                    push    rsp
         008 #  2 5a                                    pop     rdx
         000 #  3 48 81 c2 f8 ff ff ff                  add     rdx, 0FFFFFFFFFFFFFFF8h
         000 #  6 48 89 d4                              mov     rsp, rdx

        replace with:

        0:  48 8d 64 24 f8          lea    rsp, [rsp-0x8]

        """,
        "sub rsp via add rdx, 0xfffff8",
        hex_pattern([
            "54",
            "5a",
            "48 81 c2 f8 ff ff ff",
            "48 89 d4",
        ]),
        process_hex_pattern(["48 8d 64 24 f8"]), safe=1, resume=1)

    obfu.append("""
        53                        push    rbx
        48 83 EC 20               sub     rsp, 20h
        4C 8D 44 24 28            lea     r8, [rsp+28h]
        45 31 D2                  xor     r10d, r10d
        51                        push    rcx
        5B                        pop     rbx
        4D 8D 48 08               lea     r9, [r8+8]
        BA B7 1D C1 04            mov     edx, 4C11DB7h
        4D 85 C0                  test    r8, r8
        0F 84 E7 07 E4 FC         jz      loc_140D38464

        replace with:

        (the same thing, but nop the final jz)

        """,
        "AddToReportList retaddr confu-obfu",
        hex_pattern([
            "53",
            "48 83 EC 20",
            "4C 8D 44 24 28",
            "45 31 D2",
            "51",
            "5B",
            "4D 8D 48 08",
            "BA B7 1D C1 04",
            "4D 85 C0",
            "0F 84 E7 07 E4 FC"
        ]),
        hex_pattern([
            "53",
            "48 83 EC 20",
            "4C 8D 44 24 28",
            "45 31 D2",
            "51",
            "5B",
            "4D 8D 48 08",
            "BA B7 1D C1 04",
            "4D 85 C0",
            "66 0F 1F 44 00 00"
        ]), safe=1, resume=1)




    # this one might not be far enough reaching
    #  obfu.append("""
    #  b323
    #  .text:0001409e62cf  48 8d 64 24 f8                       lea     rsp, [rsp-8]
    #  .text:0001409e62d4  48 89 2c 24                          mov     [rsp], rbp
    #  .text:0001409e62d8  90                                   nop
    #  .text:0001409e62d9  48 8d 2d e3 3f 65 02                 lea     rbp, loc_14303A2C3
    #  .text:00014291a72b  48 87 2c 24                          xchg    rbp, [rsp]
    #  .text:000142a34e5a  48 89 e0                             mov     rax, rsp
    #  .text:000142a34e5d  48 05 f8 ff ff ff                    add     rax, 0FFFFFFFFFFFFFFF8h
    #  .text:000142a34e63  48 89 c4                             mov     rsp, rax
    #  .text:000142a34e66  48 89 2c 24                          mov     [rsp], rbp
    #  .text:000142a34e6a  48 81 ec 90 00 00 00                 sub     rsp, 90h
    #  .text:000142a34e71  48 8d 6c 24 20                       lea     rbp, [rsp+98h+var_80+8]
    #  .text:000142a34e76  48 89 5d 50                          mov     [rbp+50h], rbx
    #
        #  replace with:
        #  0:  48 8d 64 24 f8          lea    rsp, [rsp-0x8]
        #  and nops
        #
        #  """,
        #  "sub rsp via add rax, 0xfffff8",
        #  hex_pattern([
            #  "48 89 e0",
            #  "48 05 f8 ff ff ff",
            #  "48 89 c4",
        #  ]),
        #  hex_pattern(["48 8d 64 24 f8 0f 1f 80 00 00 00 00"])
        #  )

    obfu.append("""
            0:  48 8d 64 24 f8          lea    rsp, [rsp-0x8]
            5:  48 89 2c 24             mov    [rsp], rbp
            9:  48 8d 2d ?? ?? ?? ??    lea    rbp, [rip+0x0]        # 0x10
            10: 48 87 2c 24             xchg   [rsp], rbp
            14: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
            19: ff 64 24 f8             jmp    [rsp-0x8]
            """, "lea rbp<>rsp jmp variant1",
            hex_pattern([
                "48 8d 64 24 f8",
                "48 89 2c 24",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "48 8d 64 24 08",
                "ff 64 24 f8"
            ]), [],
            generate_patch1(0x09 + 3), # , 0x10, 0x05)
            reflow=1
            )

    obfu.append("""
            0:  48 89 6c 24 f8          mov    QWORD PTR [rsp-0x8],rbp
            5:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
            a:  48 8d 2d 00 00 00 00    lea    rbp,[rip+0x0]        # 0x11
            11: 48 87 2c 24             xchg   QWORD PTR [rsp],rbp
            15: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
            1a: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]
            1e:
            """, "lea rbp<>rsp jmp variant3",
            hex_pattern([
                "48 89 6c 24 f8",
                "48 8d 64 24 f8",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
                "48 8d 64 24 08",
                "ff 64 24 f8"
            ]), [],
            generate_patch1(0x0a + 3), # , 0x11, 0x05)
            reflow=1
            )

    if obfu_debug: printi("slow_load: 1")
    obfu.append("""
        Text description, and copy of output from dissasembly with offsets usually goes here.

                                                                         Undetected (leaves before stack is balanced)
        0:  48 ?? ?? ?? ?? ?? ?? ?? ?? ??    movabs rbp, location_1      48 bd 8b bd 72 44 01 00 00 00      mov     rbp, offset location_1
        a:  48 87 2c 24             xchg   [rsp],rbp                     48 87 2c 24                        xchg    rbp, [rsp]
        e:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]                 48 8d 64 24 f8                     lea     rsp, [rsp-8]
        13: 48 89 ?? 24             mov    [rsp],ONE                     48 89 14 24                        mov     [rsp], ONE
        17: 48 8d 64 24 f8          lea    rsp,[rsp-0x8]                 48 8d 64 24 f8                     lea     rsp, [rsp-8]
        1c: 48 89 ?? 24             mov    [rsp],TWO                     48 89 1c 24                        mov     [rsp], TWO
        20: 48 8b ?? 24 10          mov    ONE,[rsp+0x10]                48 8b 54 24 10                     mov     ONE, [rsp+10h]
        25: 48 ?? ?? ?? ?? ?? ?? ?? ?? ??    movabs TWO, location_2      48 bb ac 82 a1 40 01 00 00 00      mov     TWO, offset location_2
        2f: 48 0f 44 ??             cmovz  ONE,TWO                       48 0f 44 d3                        cmovz   ONE, TWO
        33: 48 89 ?? 24 10          mov    [rsp+0x10],ONE                48 89 54 24 10                     mov     [rsp+10h], ONE
        38: 48 8b ?? 24             mov    TWO,[rsp]                     48 8b 1c 24                        mov     TWO, [rsp]
        3c: 48 8d 64 24 08          lea    rsp,[rsp+0x8]                 48 8d 64 24 08                     lea     rsp, [rsp+8]
        41: 48 8b ?? 24             mov    ONE,[rsp]                     48 8b 14 24                        mov     ONE, [rsp]
        45: 48 8d 64 24 08          lea    rsp,[rsp+0x8]                 48 8d 64 24 08                     lea     rsp, [rsp+8]
        4a: 48 8d 64 24 08          lea    rsp,[rsp+0x8]                 48 8d 64 24 08                     lea     rsp, [rsp+8]
        4f: ff 64 24 f8             jmp    [rsp-0x8]                     ff 64 24 f8                        jmp     qword ptr [rsp-8]
        53:
        """,
        "cmovz abs jump",
        hex_pattern([
            "48 8d 64 24 f8",
            "48 89 2c 24",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 87 2c 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8b ?? 24 10",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 0f 44 ??",
            "48 89 ?? 24 10",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8d 64 24 08",
            #  "ff 64 24 f8",
            #  "e9 ?? ?? ?? ??"
        ]),
        [], # This can be a replacement hex pattern as above, of any length, if the replacement is simple, otherwise
        generate_cmov_abs_patch(0x02 + 9, 0x27 + 9, "jz"),
        reflow=1
        )
    """
    .text:0001446bbf9a     #  0                               PLAYER__GET_PLAYER_PED_START:
    .text:0001446bbf9a 000 #  1 49 89 e1                            mov     r9, rsp
    .text:0001446bbf9d 000 #  2 49 81 c1 f8 ff ff ff                add     r9, 0FFFFFFFFFFFFFFF8h
    .text:0001446bbfa4 000 #  3 4c 89 cc                            mov     rsp, r9
    .text:00014324090b 000 #  6 48 89 1c 24                         mov     [rsp], rbx
    .text:00014324090f 000 #  7 48 83 ec 20                         sub     rsp, 20h
    .text:000143f41ba7 000 # 10 4c 8d 44 24 28                      lea     r8, [rsp+28h]
    .text:000143f41bac 000 # 11 48 8d 64 24 f8                      lea     rsp, [rsp-8]
    .text:00014315250d 000 # 14 48 89 0c 24                         mov     [rsp], rcx
    .text:000143152512 000 # 16 48 8b 1c 24                         mov     rbx, [rsp]
    .text:000143152516 000 # 17 48 8d 64 24 08                      lea     rsp, [rsp+8]
    .text:000143b9eb46 000 # 20 ba b7 1d c1 04                      mov     edx, 4C11DB7h
    .text:000143b9eb4b 000 # 21 4d 8d 48 08                         lea     r9, [r8+8]
    .text:000143c32646 000 # 27 4d 3b c1                            cmp     r8, r9
    .text:000143c32649 000 # 28 48 8d 64 24 f8                      lea     rsp, [rsp-8]
    .text:000143c3264e 000 # 29 48 89 2c 24                         mov     [rsp], rbp

    .text:000143c32652 000 # 30 48 bd b4 a7 c6 40 01 00 00 00       mov     rbp, offset location_1
    .text:000144711a26 000 # 33 48 87 2c 24                         xchg    rbp, [rsp]
    .text:000144711a2a 000 # 34 48 8d 64 24 f8                      lea     rsp, [rsp-8]
    .text:000144711a2f 000 # 35 48 89 14 24                         mov     [rsp], rdx
    .text:000144711a34 000 # 37 48 8d 64 24 f8                      lea     rsp, [rsp-8]
    .text:0001430854bb 000 # 40 48 89 1c 24                         mov     [rsp], rbx
    .text:0001430854bf 000 # 41 48 8b 54 24 10                      mov     rdx, [rsp+10h]
    .text:00014309294d 000 # 44 48 bb 99 a7 c6 40 01 00 00 00       mov     rbx, offset location_2
    .text:0001430ea81b 000 # 47 48 0f 45 d3                         cmovnz  rdx, rbx
    .text:0001430ea81f 000 # 48 48 89 54 24 10                      mov     [rsp+10h], rdx
    .text:0001430ea824 000 # 49 48 8b 1c 24                         mov     rbx, [rsp]
    .text:0001430ea828 000 # 50 48 8d 64 24 08                      lea     rsp, [rsp+8]
    .text:000143f41001 000 # 53 48 8d 64 24 08                      lea     rsp, [rsp+8]
    .text:000143f41006 000 # 54 48 8b 54 24 f8                      mov     rdx, [rsp-8]
    .text:000143f4100b 000 # 55 48 8d 64 24 08                      lea     rsp, [rsp+8]
    .text:000143f41010 000 # 56 ff 64 24 f8                         jmp     qword ptr [rsp-8]

    """
    obfu.append("""
        Text description, and copy of output from dissasembly with offsets usually goes here.
             0   1  55                                  push    rbp                              55                                 push    rbp
             1  10  48 bd ?? ?? ?? ?? 01 00 00 00       mov     rbp, offset location_1           48 bd 60 7d 77 43 01 00 00 00      mov     rbp, offset location_1
             11  4  48 87 2c 24                         xchg    rbp, [rsp]                       48 87 2c 24                        xchg    rbp, [rsp+0]
             15  1  50                                  push    ONE                              51                                 push    TWO
             16  1  51                                  push    TWO                              52                                 push    ONE
             17  5  48 8b ?? 24 10                      mov     ONE, [rsp-8+arg_10]              48 8b 4c 24 10                     mov     TWO, [rsp+10h]
             22 10  48 ?? ?? ?? ?? ?? 01 00 00 00       mov     TWO, offset location_2           48 ba 9c 41 fe 40 01 00 00 00      mov     ONE, offset location_2
             32  4  48 0f ?? ??                         cmovnz  ONE, TWO                         48 0f 44 ca                        cmovz   TWO, ONE
             36  5  48 89 ?? 24 10                      mov     [rsp-8+arg_10], ONE              48 89 4c 24 10                     mov     [rsp+10h], TWO
             41  1  ??                                  pop     TWO                              5a                                 pop     ONE
             42  1  ??                                  pop     ONE                              59                                 pop     TWO
             43

        0:  55                              push   rbp
        1:  48 bd 60 7d 77 43 01 00 00 00   movabs rbp,0x143777d60
        b:  48 87 2c 24                     xchg   QWORD PTR [rsp],rbp
        f:  51                              push   rax
        10: 52                              push   rcx
        11: 48 8b 4c 24 10                  mov    rax,QWORD PTR [rsp+0x10]
        16: 48 ba 9c 41 fe 40 01 00 00 00   movabs rcx,0x140fe419c
        20: 48 0f 44 ca                     cmove  rax,rcx
        24: 48 89 4c 24 10                  mov    QWORD PTR [rsp+0x10],rax
        29: 5a                              pop    rcx
        2a: 59                              pop    rax
        2b: c3                              ret


        Why doesn't this work? -- becayse f7 7f (not rebased)
        55                                    push    rbp
        48 bd 53 24 fa 45 f7 7f 00 00         mov     rbp, offset sub_7FF745FA2453
        48 87 2c 24                           xchg    rbp, [rsp]
        51                                    push    rcx
        52                                    push    rdx
        48 8b 4c 24 10                        mov     rcx, [rsp+10h]
        48 ba 51 46 9f 45 f7 7f 00 00         mov     rdx, offset loc_7FF7459F4651
        48 0f 4d ca                           cmovge  rcx, rdx
        48 89 4c 24 10                        mov     [rsp+10h], rcx
        5a                                    pop     rdx
        59                                    pop     rcx
        c3                                    retn

        And why doesn't this work?

        55                            	push rbp                        "55",                            # 1
        48 bd 25 db ca 40 01 00 00 00 	mov rbp, label2                 "48 bd ?? ?? ?? ?? ?? ?? 00 00", # 10
        48 87 2c 24                   	xchg [rsp], rbp                 "48 87 2c 24",                   # 4
        51                            	push rcx                        "??",                            # 1
        52                            	push rdx                        "??",                            # 1
        48 8b 4c 24 10                	mov rcx, [rsp+0x10]             "48 8b ?? 24 10",                # 5
        48 ba a8 db ca 40 01 00 00 00 	mov rdx, label1                 "48 ?? ?? ?? ?? ?? ?? ?? 00 00", # 10
        48 0f 45 ca                   	cmovnz rcx, rdx                 "48 0f ?? ??",                   # 4
        48 89 4c 24 10                	mov [rsp+0x10], rcx             "48 89 ?? 24 10",                # 5
        5a                            	pop rdx                         "??",                            # 1
        59                            	pop rcx                         "??",                            # 1
        c3                            	retn                            "c3" # the ret is really a jump



















        """,
        "mini-cmov",
        hex_pattern([
            # "55 48 bd ?? ?? ?? ?? 01 00 00 00 48 87 2c 24 ?? ?? 48 8b ??  24 10 48 ?? ?? ?? ?? ?? 01 00 00 00 48 0f ?? ?? 48 89 ?? 24 10 ?? ??"
            "55",                            # 1
            "48 bd ?? ?? ?? ?? ?? ?? 00 00", # 10
            "48 87 2c 24",                   # 4
            "??",                            # 1
            "??",                            # 1
            "48 8b ?? 24 10",                # 5
            "48 ?? ?? ?? ?? ?? ?? ?? 00 00", # 10
            "48 0f ?? ??",                   # 4
            "48 89 ?? 24 10",                # 5
            "??",                            # 1
            "??",                            # 1
            "c3" # the ret is really a jump
        ]),
        [], # This can be a replacement hex pattern as above, of any length, if the replacement is simple, otherwise
        generate_compact_cmov_abs_patch(0x03, 0x18, 0x22),
        safe=1, resume=1
        )

    obfu.append("push qword rel; retn", "push qword rel tailcall",
            hex_pattern([
                "FF 35 ?? ?? ?? ??",
                "C3"
            ]),
            hex_pattern([
                "FF 25 ?? ?? ?? ??",
                "C3"
            ]),
            safe=1,
            resume=1,
            )

    obfu.append("push [rax]; retn", "jmp [rax]",
            hex_pattern([
                "50", "C3"
            ]),
            hex_pattern([
                "FF 20"
            ]),
            safe=1,
            resume=1,
            )

    if False:
        obfu.append("arxan_check misdirection", "arxan misdirection #1",
                hex_pattern([
                    "8b 85 ?? 00 00 00 85 c0 0f 85 ?? ?? ?? ??",
                    "48 8b 45 ?? 48 85 c0 0f ?? ?? ?? ?? 8b 85 ?? 00 00 00",
                    "85 c0 0f 85 ?? ?? ?? ??",
                ]),
                hex_pattern([
                    "8b 85 ?? 00 00 00 85 c0 90 e9 ?? ?? ?? ??",
                    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
                    "?? ?? ?? ?? ?? ?? ?? ??",
                ]),
                safe=1,
                resume=1,
                )
        obfu.append("arxan_check misdirection", "arxan misdirection #2",
                hex_pattern([
                    "8b 85 ?? 00 00 00 85 c0 0f 84 ?? ?? ?? ??",
                    "8b 85 ?? 00 00 00 8b 55 30 3b c2 0f 8d ?? ?? ?? ??"
                ]),
                hex_pattern([
                    "8b 85 ?? 00 00 00",
                    "85 c0",
                    "90 e9 ?? ?? ?? ??",
                    "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"
                ]),
                safe=1,
                resume=1,
                )

    obfu.append("""
        Text description, and copy of output from dissasembly with offsets usually goes here.

        Lets prefix these 9 bytes, then we can lose the `lea rsp, [rsp+8]` from the result
            48 8d 64 24 f8          lea     rsp, [rsp-8]
            48 89 2c 24             mov     [rsp], rbp

        0:  48 ?? ?? ?? ?? ?? ?? ?? movabs rbp, location_1            48 bd b4 a7 c6 40 01      mov     rbp, offset location_1
        a:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp        48 87 2c 24               xchg    rbp, [rsp]
        e:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]              48 8d 64 24 f8            lea     rsp, [rsp-8]
        13: 48 89 ?? 24             mov    QWORD PTR [rsp],ONE        48 89 14 24               mov     [rsp], rdx
        17: 48 8d 64 24 f8          lea    rsp,[rsp-0x8]              48 8d 64 24 f8            lea     rsp, [rsp-8]
        1c: 48 89 ?? 24             mov    QWORD PTR [rsp],TWO        48 89 1c 24               mov     [rsp], rbx
        20: 48 8b ?? 24 10          mov    ONE,QWORD PTR [rsp+0x10]   48 8b 54 24 10            mov     rdx, [rsp+10h]
        25: 48 ?? ?? ?? ?? ?? ?? ?? movabs TWO, location_2            48 bb 99 a7 c6 40 01      mov     rbx, offset location_2
        2f: 48 0f 45 ca             cmovne ONE,TWO                    48 0f 45 d3               cmovnz  rdx, rbx
        33: 48 89 ?? 24 10          mov    QWORD PTR [rsp+0x10],ONE   48 89 54 24 10            mov     [rsp+10h], rdx
        38: 48 8b ?? 24             mov    TWO,QWORD PTR [rsp]        48 8b 1c 24               mov     rbx, [rsp]
        3c: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8d 64 24 08            lea     rsp, [rsp+8]
        41: 48 8b ?? 24             mov    ONE,QWORD PTR [rsp]        48 8d 64 24 08            lea     rsp, [rsp+8]
        45: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8b 54 24 f8            mov     rdx, [rsp-8]
        4a: 48 8d 64 24 08          lea    rsp,[rsp+0x8]              48 8d 64 24 08            lea     rsp, [rsp+8]
        4f: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]        ff 64 24 f8               jmp     qword ptr [rsp-8]
        53: 90                      nop
        """,
        "cmovnz abs jump",
        hex_pattern([ # this one is playing up
            "48 8d 64 24 f8",
            "48 89 2c 24",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 87 2c 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8b ?? 24 10",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 0f 45 ??",
            "48 89 ?? 24 10",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8d 64 24 08",
            "ff 64 24 f8",
            #  "e9 ?? ?? ?? ??"
        ]),
        [], # This can be a replacement hex pattern as above, of any length, if the replacement is simple, otherwise
        generate_cmov_abs_patch(0x02 + 9, 0x27 + 9, "jnz"),
        reflow=1
        )

    obfu.append("""
        cmovb (same as cmovz but with a jb - [42] instead of [45])
        Lets prefix these 9 bytes, then we can lose the `lea rsp, [rsp+8]` from the result
            48 8d 64 24 f8          lea     rsp, [rsp-8]
            48 89 2c 24             mov     [rsp], rbp

        0:  48 bd 87 dd 43 43 01    movabs rbp, location_1
        a:  48 87 2c 24             xchg   QWORD PTR [rsp],rbp
        e:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        13: 48 89 1c 24             mov    QWORD PTR [rsp],rbx
        17: 48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        1c: 48 89 04 24             mov    QWORD PTR [rsp],rax
        20: 48 8b 5c 24 10          mov    rbx,QWORD PTR [rsp+0x10]
        25: 48 b8 46 f8 a2 40 01    movabs rax, location_2
        2f: 48 0f 42 d8             cmovb  rbx,rax
        33: 48 89 5c 24 10          mov    QWORD PTR [rsp+0x10],rbx
        38: 48 8b 04 24             mov    rax,QWORD PTR [rsp]
        3c: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
        41: 48 8b 1c 24             mov    rbx,QWORD PTR [rsp]
        45: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
        4a: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
        4f: ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]
        53: 90                      nop
        """,
        "cmovnz abs jump",
        hex_pattern([
            "48 8d 64 24 f8",
            "48 89 2c 24",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 87 2c 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8d 64 24 f8",
            "48 89 ?? 24",
            "48 8b ?? 24 10",
            "48 ?? ?? ?? ?? ?? ?? ?? ?? ??",
            "48 0f 42 ??", # 48 0f [42] [cmovb]
            "48 89 ?? 24 10",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8b ?? 24",
            "48 8d 64 24 08",
            "48 8d 64 24 08",
            "ff 64 24 f8",
        ]),
        [], # This can be a replacement hex pattern as above, of any length, if the replacement is simple, or leave as empty list and supply function below
        generate_cmov_abs_patch(0x02 + 9, 0x27 + 9, "jb"),
        reflow=1
    )


    """
    Matching new pattern against exsting cmovz

    .text:1439983d3   68       39 0d fb 70 38 fe             	cmp [g_pickup_related], ecx
    ---

    .text:143e84f4b   68   -8  55                            	push rbp
    .text:143e84f55   70       48 bd 6e 10 4d 43 01 00 00 00 	mov rbp, loc_1434D106E
    .text:140d25baa   70       48 87 2c 24                   	xchg [rsp], rbp
    .text:1440f2631   70   -8  52                            	push rdx
    .text:140a637bd   78   -8  53                            	push rbx
    .text:143515b59   80       48 8b 54 24 10                	mov rdx, [rsp+0x10]
    .text:143515b5e   80       48 bb 5d f6 ca 40 01 00 00 00 	mov rbx, loc_140CAF65D
    .text:143515b68   80       48 0f 44 d3                   	cmovz rdx, rbx
    .text:143515b6c   80       48 89 54 24 10                	mov [rsp+0x10], rdx
    .text:144009cc4   80    8  5b                            	pop rbx
    .text:144009ccd   78    8  48 8d 64 24 08                	lea rsp, [rsp+8]
    .text:143eac9cc   70    8  5a                            	pop rdx
    .text:143eac9d5   68       ff 64 24 f8                   	jmp qword [rsp-8]

    ---

        .text:00000001430E4114 018 48 B8 BB E8 F7 42 01 00 00 00                 mov     rax, 142F7E8BBh
        .text:00000001430E411E 018 48 0F 44 D8                                   cmovz   rbx, rax
                        48 BA 00 00 E0 04 14 00 00 00
                        48 ?? ?? ?? ?? ?? ?? 01 00 00 48 0f ?? ??
                        48 ?? ?? ?? ?? ?? 01 00 00 00 48 0f ?? ??

        0000:0000000143E352DA 48 8D 64 24 F8                                    lea     rsp, [rsp-8]
        0000:0000000143E352DF 48 89 2C 24                                       mov     [rsp], rbp
        0000:0000000143E352E3 48 BD 91 A2 AA 43 01 00 00 00                     mov     rbp, offset location_1
        0000:0000000143E352ED 48 87 2C 24                                       xchg    rbp, [rsp]
        0000:0000000143E352F1 48 8D 64 24 F8                                    lea     rsp, [rsp-8]
        0000:0000000143E352F6 48 89 1C 24                                       mov     [rsp], rbx
        0000:0000000143E352FA 48 89 44 24 F8                                    mov     [rsp-8], rax
        0000:0000000143E352FF 48 8D 64 24 F8                                    lea     rsp, [rsp-8]
        0000:0000000143E35304 48 8B 5C 24 10                                    mov     rbx, [rsp+10h]
        0000:0000000143E35309 48 B8 1A 8F 8E 40 01 00 00 00                     mov     rax, offset location_2
        0000:0000000143E35313 48 0F 44 D8                                       cmovz   rbx, rax
        0000:0000000143E35317 48 89 5C 24 10                                    mov     [rsp+10h], rbx
        0000:0000000143E3531C 48 8B 04 24                                       mov     rax, [rsp]
        0000:0000000143E35320 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E35325 48 8B 1C 24                                       mov     rbx, [rsp]
        0000:0000000143E35329 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E3532E 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E35333 FF 64 24 F8                                       jmp     qword ptr [rsp-8]
        0000:0000000143E35337                                   ; ---------------------------------------------------------------------------
        0000:0000000143E35337 E9 55 4F C7 FF                                    jmp     location_1
        0000:0000000143E3533C                                   ; ---------------------------------------------------------------------------


        becomes:

        0000:0000000143E352DA 48 8D 64 24 F8                                    lea     rsp, [rsp-8]
        0000:0000000143E352DF 48 89 2C 24                                       mov     [rsp], rbp
        0000:0000000143E352E3 48 BD 91 A2 AA 43 01 00 00 00                     mov     rbp, offset location_1
        0000:0000000143E352ED 48 87 2C 24                                       xchg    rbp, [rsp]
        0000:0000000143E352F1 48 8D 64 24 F8                                    lea     rsp, [rsp-8]
        0000:0000000143E352F6 48 89 1C 24                                       mov     [rsp], rbx
        0000:0000000143E352FA 48 8D 64 24 F8                                    lea     rsp, [rsp-8]    ; [PATCH] 10 bytes: mov/lea->push order swap: rax
        0000:0000000143E352FF 48 89 04 24                                       mov     [rsp], rax ; + NOP
        0000:0000000143E35304 48 8B 5C 24 10                                    mov     rbx, [rsp+10h]
        0000:0000000143E35309 48 B8 1A 8F 8E 40 01 00 00 00                     mov     rax, offset location_2
        0000:0000000143E35313 48 0F 44 D8                                       cmovz   rbx, rax
        0000:0000000143E35317 48 89 5C 24 10                                    mov     [rsp+10h], rbx
        0000:0000000143E3531C 48 8B 04 24                                       mov     rax, [rsp]
        0000:0000000143E35320 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E35325 48 8B 1C 24                                       mov     rbx, [rsp]
        0000:0000000143E35329 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E3532E 48 8D 64 24 08                                    lea     rsp, [rsp+8]
        0000:0000000143E35333 FF 64 24 F8                                       jmp     qword ptr [rsp-8]

    """






    if obfu_debug: printi("slow_load: 1")

    obfu.append("""
        54                      push    rsp                    -or-  48 89 E0                mov     rax, rsp
        58                      pop     rax                    -or/
        48 05 F8 FF FF FF       add     rax, 0FFFFFFFFFFFFFFF8h      48 05 F8 FF FF FF       add     rax, 0FFFFFFFFFFFFFFF8h
        50                      push    rax                    -or-  48 89 C4                mov     rsp, rax
        5C                      pop     rsp                    -or/
        48 89 1C 24             mov     [rsp], rbx                   48 89 1C 24             mov     [rsp], rbx

        replace with:

        53                      push   rbx
        """,
        "push rbx via add rax -8",
        hex_pattern([
            "54",
            "58",
            "48 05 F8 FF FF FF",
            "50",
            "5C",
            "48 89 1C 24",
            ]),
        process_hex_pattern(["53"]), safe=1, resume=1
        )

    obfu.append("See Above",
            "push rbx via add rax -8 #2",
            hex_pattern([
                "48 89 E0",           # mov rax, rsp
                "48 05 F8 FF FF FF",  # add rax, -8
                "48 89 C4",           # mov rsp, rax
                "48 89 1C 24",        # mov rsp, rbx   | 48 89 2C 24     mov rsp, rbp
                ]),
            process_hex_pattern(["53"])
            , safe=1, resume=1)

    obfu.append("""
            0:  48 89 e0                mov    rax,rsp
            3:  48 05 f8 ff ff ff       add    rax,0xfffffffffffffff8
            9:  48 89 c4                mov    rsp,rax
            c:  48 89 04 24             mov    QWORD PTR [rsp],rax
            """, "mov [rsp], r64 => push r64",
            bit_pattern("48 89 e0 48 05 f8 ff ff ff 48 89 c4 48 89 04~3c 24"),
            "", lambda a, b, c, *z, **kw: (len(a), [0x50 + (c[14] >> 3)]),
            resume=1
    )
    #  (two groups of 5, order swapped)
    #  00~ff 00~ff 00~bf 00~ff 00~97
    #  00~ff 00~ff 00~ff 00~ff 00~ff
    obfu.append("", "mov [rsp-0x8], rax; lea rsp, [rsp-0x8]",
            bit_pattern("48~4c 89 44~7c 24 f8 48 8d 64 24 f8"),
            "", lambda a, b, c, *z, **kw: \
                    hex_pattern('48 8d 64 24 f8') + bit_pattern('00~ff 00~ff 00~bf 00~ff 00~97').sub(c[0:5]),
                    #  (len(a), [c[5], c[6], c[7], c[8], c[9], c[0], c[1], c[2]&0xbf, c[3], c[4]&0x97]),
            resume=1, then='push', priority=2,
    )
    # bit_pattern('48 8d 64 24 f8')
    # bit_pattern('00~ff 00~ff 00~bf 00~ff 00~97').sub(c[5:10]) + hex_pattern('48 8d 64 24 f8')


    obfu.append("See Above",
            "push rbx via add rax -8 #3",
            hex_pattern([
                "54",
                "58",
                "48 05 F8 FF FF FF",
                "48 89 C4",
                "48 89 1C 24",
                ]),
            process_hex_pattern(["53"])
            , safe=1, resume=1)

    obfu.append("See Above",
            "push rbx via add rax -8 #4",
            hex_pattern([
                "48 89 e0",
                "48 05 f8 ff ff ff",
                "50",
                "5C",
                "48 89 1C 24",
                ]),
            process_hex_pattern(["53"])
            , safe=1, resume=1)

    if 0:
        # --- A little worried that will run when not actually a return, and fuck up a cmov-mini detection
        obfu.append("""
                000 48 8B 1C 24                                mov     rbx, [rsp+0]
                000 48 8D 64 24 08                             lea     rsp, [rsp+8]
                -08 48 8D 64 24 08                             lea     rsp, [rsp+8]
                -10 FF 64 24 F8                                jmp     qword ptr [rsp-8]

                replace with:

                0:  5b                      pop    rbx
                1:  c3                      ret
            """,
            "native return sig",
            hex_pattern([
                "48 8B 1C 24",
                "48 8D 64 24 08",
                "48 8D 64 24 08",
                "FF 64 24 F8",
                ]),
            process_hex_pattern(["5b", "c3"]),
            safe = 0
            )

    """
    ; Original
                             loc_14278FF6D:
        48 8D 64 24 F8                       lea     rsp, [rsp-8]        rsp = rsp - 8                            ;Load Effective Address
        48 89 2C 24                          mov     [rsp], rbp          *rsp = rbp
        48 8D 2D EE E1 33 00                 lea     rbp, LOCATION_1     rbp = LOCATION_1                         ;Load Effective Address
        48 87 2C 24                          xchg    rbp, [rsp]          swap rbp, rsp                            ;Exchange Register/Memory with Register

                                                             // meaning
                                                             rsp = rsp - 8
                                                             *rsp = LOCATION_1



        55                                   push    rbp                 rsp = rsp - 8;
        48 8D 2D 79 60 6C 00                 lea     rbp, LOCATION_2     *rsp = LOCATION_2                        ;Load Effective Address
        48 87 2C 24                          xchg    rbp, [rsp]          swap rbp, rsp                            ;Exchange Register/Memory with Register

                                                             // meaning
                                                             rsp = rsp - 8
                                                             *rsp = LOCATION_2

        C3                                   retn                        jmp *rsp                                 ;Return Near from Procedure
                                                             rsp = rsp + 8

        48 8D 64 24 F8                       lea     rsp, [rsp-8]    ; Load Effective Address
        48 89 2C 24                          mov     [rsp], rbp
        48 8D 2D 5F 12 2A 00                 lea     rbp, FAKE_LOCATION ; Load Effective Address
        48 87 2C 24                          xchg    rbp, [rsp+58h+var_58] ; Exchange Register/Memory with Register
        55                                   push    rbp
        48 8D 2D 85 C9 C3 01                 lea     rbp, REAL_LOCATION ; Load Effective Address
        48 87 2C 24                          xchg    rbp, [rsp+60h+var_60] ; Exchange Register/Memory with Register
        C3                                   retn                    ; Return Near from Procedure

    rsp  = rsp - 8      rsp = rsp - 8       call LOCATION_2; insert LOCATION_1 as retn address
    *rsp = LOCATION_1   *rsp = LOCATION_1
    rsp  = rsp - 8
    *rsp = LOCATION_2
    jmp *rsp            jmp LOCATION_2
    rsp  = rsp + 8


                              ; After de-obfu
    000                               loc_14278FF6D:
    000 55                                  push rbp                             ;[PATCH] 1 bytes: lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
    008 48 8d 2d ee e1 33 00                lea rbp, qword ptr [LOCATION_1]
    008 48 87 2c 24                         xchg rbp, [rsp]
    008 55                                  push rbp                             ;[PATCH] 1 bytes: lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
    010 48 8d 2d 5f 12 2a 00                lea rbp, qword ptr [FAKE_LOCATION]
    010 48 87 2c 24                         xchg rbp, [rsp]
    010 55                                  push rbp
    018 48 8d 2d 85 c9 c3 01                lea rbp, qword ptr [REAL_LOCATION]
    018 48 87 2c 24                         xchg rbp, [rsp]
    018 c3                                  retn                                 ;[obfu::comb] retn; call stack is empty; END OF BRANCH; BREAK

    """
    obfu.append("""
        0:  48 8d 64 24 f8          lea     rsp, [rsp-8]          ; === faked call to LOCATION_2    from LOCATION_1
        5:  48 89 2c 24             mov     [rsp], rbp            ; push rbp
        9:  48 8d 2d ?? ?? ?? ??    lea     rbp, LOCATION_1       ; rbp = LOCATION_1
        10: 48 87 2c 24             xchg    rbp, [rsp]            ; pop rbp ; push LOCATION_1     ; push LOCATION_1
        14: 55                      push    rbp                   ; push rbp
        15: 48 8d 2d ?? ?? ?? ??    lea     rbp, LOCATION_2       ; rbp = LOCATION_2
        1c: 48 87 2c 24             xchg    rbp, [rsp]            ; pop rbp; push LOCATION_2      ; push LOCATION_2
        20: c3                      retn                          ; pop rax; jmp eax              ; pop rax; jmp rax
        """,
        "faked call to LOCATION_2    from LOCATION_1   ",
        hex_pattern([
            "48 8d 64 24 f8",
            "48 89 2c 24",
            "48 8d 2d ?? ?? ?? ??",
            "48 87 2c 24",
            "55",
            "48 8d 2d ?? ?? ?? ??",
            "48 87 2c 24",
            "c3"
        ]),
        [],
        generate_log(),
        reflow=1
        )




    """ NOTE: XXX:
    XXX: legitimate tail call!
    028 48 83 C4 28                     add     rsp, 28h
    000 FF 72 20                        push    qword ptr [rdx+20h]
    008 48 8D 64 24 08                  lea     rsp, [rsp+8]
    000 FF 64 24 F8                     jmp     [rsp+var_8]
    """
    obfu.append("""
            000 48 8D 64 24 08                    lea     rsp, [rsp+8]
            -08 FF 64 24 F8                       jmp     qword ptr [rsp-8]
        """,
        "return disguised as lea + jmp",
        hex_pattern([
            "48 8d 64 24 08",
            "ff 64 24 f8"
            ]),
        [
            "retn",
            "int3"
        ],
        #  process_hex_pattern([
            #  "c3"
            #  ])
        safe=1, reflow=1
        )


    obfu.append("",
            "jmp: push abs64 via rax xchg",
            hex_pattern([
                "50", #                                                              push    rax
                "48 B8 ?? ?? ?? ?? ?? ?? ?? ??", #                                   mov     rax, 27E8CA2DB50h
                "48 87 04 24", #                                                     xchg    rax, [rsp]
                "C3", #                                                              retn
            ]),
            [],
            simple_patch_factory("jmp [rip+0]; dq {hex(idc.get_qword(addressList[3]))}; int 3"),
            safe=1, reflow=1
    )

    obfu.append("", "jmp via push rsp and retn",
            hex_pattern([
                "55",
                "48 8d 2d ?? ?? ?? ??",
                "48 87 2c 24",
            ]),
            [],
            patch_single_rsp_push_call_jump,
            )

#  .tramp1:000000013FFEF053 FF 25 00 00 00 00                             jmp     cs:qword_13FFEF059
#  .tramp1:000000013FFEF053                               ; ---------------------------------------------------------------------------
#  .tramp1:000000013FFEF059 90 82 B9 E1 E0 01 00 00       qword_13FFEF059 dq 1E0E1B98290h         ; DATA XREF: .tramp1:000000013FFEF053↑r


"""
 1  55                              55                                  push    rbp                          push    rbp                        push rbp
10  48 bd ?? ?? ?? ?? 01 00 00 00   48 bd 53 3e 15 44 01 00 00 00       mov     rbp, offset location_1       mov     rbp, offset location_1     mov rbp, location_1
 4  48 87 2c 24                     48 87 2c 24                         xchg    rbp, [rsp]                   xchg    rbp, [rsp+0]               xchg [rsp], rbp
 1  50                              53                                  push    ONE                          push    TWO                        push TWO
 1  51                              48 89 04 24                         push    TWO                          push    ONE                        push ONE | mov [rsp], ONE
 5  48 8b ?? 24 10                  48 8d 64 24 f8                      mov     ONE, [rsp-8+arg_10]          mov     TWO, [rsp+10h]                      |lea rsp, [rsp-8]
10  48 ?? ?? ?? ?? ?? 01 00 00 00   48 8b 5c 24 10                      mov     TWO, offset location_2       mov     ONE, offset location_2     mov TWO, [rsp+0x10]
 4  48 0f ?? ??                     48 b8 57 0d 7b 40 01 00 00 00       cmovnz  ONE, TWO                     cmovz   TWO, ONE                   mov ONE, location_2
 5  48 89 ?? 24 10                  48 0f 45 d8                         mov     [rsp-8+arg_10], ONE          mov     [rsp+10h], TWO             cmovnz TWO, ONE
 1  ??                              48 89 5c 24 10                      pop     TWO                          pop     ONE                        mov [rsp+0x10], TWO
 1  ??                              58                                  pop     ONE                          pop     TWO                        pop ONE
                                    5b                                                                                                          pop TWO
                                    c3                                                                                                          retn

 8  48 89 6C 24 F8                         PUSH / mov     [rsp-8], rbp                      0  48 8d 64 24 f8            PUSH / lea rsp, [rsp-8]     48 8d 64 24 f8                 lea rsp, [rsp-8]
 8  48 8D 64 24 F8                          RBP \ lea     rsp, [rsp-8]                      8  48 89 2c 24                RBP \ mov [rsp], rbp       48 89 2c 24                    mov [rsp], rbp
10  48 BD 2B 93 18 44 01 00 00 00                 mov     rbp, offset sub_14418932B         8  48 bd 53 3e 15 44 01 00          mov rbp:=location_1  48 bd 53 3e 15 44 01 00 00 00  mov rbp, location_1
10  48 87 2C 24                                   xchg    rbp, [rsp]                        8  48 87 2c 24       *sp[8]= loc_1  xchg [rsp], rbp      48 87 2c 24                    xchg [rsp], rbp
10  48 8D 64 24 F8                                lea     rsp, [rsp-8]                      8  48 89 5c 24 f8            PUSH / lea rsp, [rsp-8]     48 89 5c 24 f8                 mov [rsp-8], TWO
18  48 89 14 24                                   mov     [rsp], rdx                       10  48 8d 64 24 f8             RBX \ mov [rsp], rbx       48 8d 64 24 f8                 lea rsp, [rsp-8]
18  48 89 5C 24 F8                         PUSH / mov     [rsp-8], rbx                     10  48 89 44 24 f8            PUSH / lea rsp, [rsp-8]     48 89 44 24 f8                 mov [rsp-8], ONE
18  48 8D 64 24 F8                          RSP \ lea     rsp, [rsp-8]                     10  48 8d 64 24 f8             RAX \ mov [rsp], rax       48 8d 64 24 f8                 lea rsp, [rsp-8]
20  48 8B 54 24 10                                mov     rdx, [rsp+10h]                   18  48 8b 5c 24 10                   mov rbx, [rsp+0x10]  48 8b 5c 24 10                 mov TWO, [rsp+0x10]
20  48 BB 47 A5 D3 40 01 00 00 00                 mov     rbx, offset loc_140D3A547        18  48 b8 57 0d 7b 40 01 00 00 00    mov rax, location_2  48 b8 57 0d 7b 40 01 00 00 00  mov ONE, location_2
20  48 0F 47 D3                                   cmova   rdx, rbx                         18  48 0f 45 d8                      cmovnz rbx, rax      48 0f 45 d8                    cmovnz TWO, ONE
20  48 89 54 24 10                                mov     [rsp+10h], rdx                   18  48 89 5c 24 10                   mov [rsp+0x10], rbx  48 89 5c 24 10                 mov [rsp+0x10], TWO
20  48 8D 64 24 08                                lea     rsp, [rsp+8]                     18  48 8b 04 24                      mov rax, [rsp]       48 8b 04 24                    mov ONE, [rsp]
18  48 8B 5C 24 F8                                mov     rbx, [rsp-8]                     18  48 8d 64 24 08                   lea rsp, [rsp+8]     48 8d 64 24 08                 lea rsp, [rsp+8]
18  48 8D 64 24 08                                lea     rsp, [rsp+8]                     10  48 8d 64 24 08                   lea rsp, [rsp+8]     48 8d 64 24 08                 lea rsp, [rsp+8]
                                                                                            8  48 8b 5c 24 f8                   mov rbx, [rsp-8]     48 8b 5c 24 f8                 mov TWO, [rsp-8]
                                                                                            8  48 8d 64 24 f8                   lea rsp, [rsp-8]     48 8d 64 24 f8                 lea rsp, [rsp-8]
                                                                                           10  48 89 2c 24                      mov [rsp], rbp       48 89 2c 24                    mov [rsp], rbp
                                                                                           10 48 8d 2d 4c d2 66 00              lea rbp, [label1]    48 8d 2d 4c d2 66 00           lea rbp, [label1]
                                                                                           10 48 87 2c 24                       xchg [rsp], rbp      48 87 2c 24                    xchg [rsp], rbp
                                                                                           10 48 8d 64 24 08                    lea rsp, [rsp+8]     48 8d 64 24 08                 lea rsp, [rsp+8]
                                                                                            8 ff 64 24 f8                       jmp qword [rsp-8]    ff 64 24 f8                    jmp qword [rsp-8]


.text:143ab9a29    0   -8 _sub_143AB9A29   55                               push rbp
.text:143d6a1a1    8 (-8) _sub_143AB9A29   48 bd 53 3e 15 44 01 00 00 00    mov rbp, loc_144153E53
.text:143a88fb0    8      _sub_143AB9A29   48 87 2c 24                      xchg [rsp], rbp
.text:144249170    8   -8 _sub_143AB9A29   53                               push rbx
.text:14424917a   10      _sub_143AB9A29   48 89 04 24                      mov [rsp], rax
.text:143cc43cc   10   -8 _sub_143AB9A29   48 8d 64 24 f8                   lea rsp, [rsp-8]
.text:143cc43d1   18      _sub_143AB9A29   48 8b 5c 24 10                   mov rbx, [rsp+0x10]
.text:143cc43d6   18      _sub_143AB9A29   48 b8 57 0d 7b 40 01 00 00 00    mov rax, unk_1407B0D57
.text:143cc43e0   18      _sub_143AB9A29   48 0f 45 d8                      cmovnz rbx, rax
.text:143cece62   18      _sub_143AB9A29   48 89 5c 24 10                   mov [rsp+0x10], rbx
.text:143cece67   18    8 _sub_143AB9A29   58                               pop rax
.text:143cece71   10    8 _sub_143AB9A29   5b                               pop rbx
.text:143d0ee7b    8      _sub_143AB9A29   c3                               retn

.text:143ab9a29    0   -8 _sub_143AB9A29   55                               push rbp
.text:143d6a1a1    8 (-10) _sub_143AB9A29   48 bd 53 3e 15 44 01 00 00 00   mov rbp, sub_144153E53
.text:143a88fb0    8      _sub_143AB9A29   48 87 2c 24                      xchg [rsp], rbp
.text:144249170    8   -8(8) _sub_143AB9A29   53                            push rbx
.text:144249171   10   -8 _sub_143AB9A29   50                               push rax
.text:143cc43d1   18      _sub_143AB9A29   48 8b 5c 24 10                   mov rbx, [rsp+0x10]
.text:143cc43d6   18      _sub_143AB9A29   48 b8 57 0d 7b 40 01 00 00 00    mov rax, sub_1407B0D57
.text:143cc43e0   18      _sub_143AB9A29   48 0f 45 d8                      cmovnz rbx, rax
.text:143cece62   18      _sub_143AB9A29   48 89 5c 24 10                   mov [rsp+0x10], rbx
.text:143cece67   18    8 _sub_143AB9A29   58                               pop rax
.text:143cece71   10    8 _sub_143AB9A29   5b                               pop rbx
.text:143d0ee7b    8      _sub_143AB9A29   c3                               retn




            0:  48 8d 64 24 f8          lea    rsp, [rsp-0x8]
            5:  48 89 2c 24             mov    [rsp], rbp
            9:  48 8d 2d ?? ?? ?? ??    lea    rbp, [rip+0x0]        # 0x10
            10: 48 87 2c 24             xchg   [rsp], rbp
            14: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
            19: ff 64 24 f8             jmp    [rsp-0x8]

 0   55                             push rbp                     "55",                            # 1
 8   48 bd 53 3e 15 44 01 00 00 00  mov rbp, location_1          "48 bd ?? ?? ?? ?? 01 00 00 00", # 10
 8   48 87 2c 24                    xchg [rsp], rbp              "48 87 2c 24",                   # 4
 8   53                             push TWO                     "??",                            # 1
10   48 89 04 24                    mov [rsp], ONE               "??",                            # 1
10   48 8d 64 24 f8                 lea rsp, [rsp-8]             "48 8b ?? 24 10",                # 5
18   48 8b 5c 24 10                 mov TWO, [rsp+0x10]          "48 ?? ?? ?? ?? ?? 01 00 00 00", # 10
18   48 b8 57 0d 7b 40 01 00 00 00  mov ONE, location_2          "48 0f ?? ??",                   # 4
18   48 0f 45 d8                    cmovnz TWO, ONE              "48 89 ?? 24 10",                # 5
18   48 89 5c 24 10                 mov [rsp+0x10], TWO          "??",                            # 1
18   58                             pop ONE                      "??",                            # 1
10   5b                             pop TWO                      "c3" # the ret is really a jump
 8   c3                             retn

  0 _sub_14341658E   48 8d 64 24 f8                 lea rsp, [rsp-8]
  8 _sub_14341658E   48 89 2c 24                    mov [rsp], rbp
  8 _sub_14341658E   48 bd 53 3e 15 44 01 00 00 00  mov rbp, location_1
  8 _sub_14341658E   48 87 2c 24                    xchg [rsp], rbp
  8 _sub_14341658E   48 89 5c 24 f8                 mov [rsp-8], rbx
  8 _sub_14341658E   48 8d 64 24 f8                 lea rsp, [rsp-8]
 10 _sub_14341658E   48 89 44 24 f8                 mov [rsp-8], rax
 10 _sub_14341658E   48 8d 64 24 f8                 lea rsp, [rsp-8]
 18 _sub_14341658E   48 8b 5c 24 10                 mov rbx, [rsp+0x10]
 18 _sub_14341658E   48 b8 57 0d 7b 40 01 00 00 00  mov rax, location_2
 18 _sub_14341658E   48 0f 45 d8                    cmovnz rbx, rax
 18 _sub_14341658E   48 89 5c 24 10                 mov [rsp+0x10], rbx
 18 _sub_14341658E   48 8b 04 24                    mov rax, [rsp]
 18 _sub_14341658E   48 8d 64 24 08                 lea rsp, [rsp+8]
 10 _sub_14341658E   48 8d 64 24 08                 lea rsp, [rsp+8]
  8 _sub_14341658E   48 8b 5c 24 f8                 mov rbx, [rsp-8]
  8 _sub_14341658E   48 8d 64 24 f8                 lea rsp, [rsp-8]
 10 _sub_14341658E   48 89 2c 24                    mov [rsp], rbp
 10 _sub_14341658E   48 8d 2d 4c d2 66 00           lea rbp, [label1]
 10 _sub_14341658E   48 87 2c 24                    xchg [rsp], rbp
 10 _sub_14341658E   48 8d 64 24 08                 lea rsp, [rsp+8]
  8 _sub_14341658E   ff 64 24 f8                    jmp qword [rsp-8]
"""






# .text:143ab9a29    0   -8 _sub_14341658E   55                             push rbp                 "55",                            # 1
# .text:143d6a1a1    8      _sub_14341658E   48 bd 53 3e 15 44 01 00 00 00  mov rbp, location_1   "48 bd ?? ?? ?? ?? 01 00 00 00", # 10
# .text:143a88fb0    8      _sub_14341658E   48 87 2c 24                    xchg [rsp], rbp          "48 87 2c 24",                   # 4
# .text:144249170    8   -8 _sub_14341658E   53                             push rbx                 "??",                            # 1
# .text:14424917a   10      _sub_14341658E   48 89 04 24                    mov [rsp], rax           "??",                            # 1
# .text:143cc43cc   10   -8 _sub_14341658E   48 8d 64 24 f8                 lea rsp, [rsp-8]         "48 8b ?? 24 10",                # 5
# .text:143cc43d1   18      _sub_14341658E   48 8b 5c 24 10                 mov rbx, [rsp+0x10]      "48 ?? ?? ?? ?? ?? 01 00 00 00", # 10
# .text:143cc43d6   18      _sub_14341658E   48 b8 57 0d 7b 40 01 00 00 00  mov rax, location_2          "48 0f ?? ??",                   # 4
# .text:143cc43e0   18      _sub_14341658E   48 0f 45 d8                    cmovnz rbx, rax          "48 89 ?? 24 10",                # 5
# .text:143cece62   18      _sub_14341658E   48 89 5c 24 10                 mov [rsp+0x10], rbx      "??",                            # 1
# .text:143cece67   18    8 _sub_14341658E   58                             pop rax                  "??",                            # 1
# .text:143cece71   10    8 _sub_14341658E   5b                             pop rbx                  "c3" # the ret is really a jump
# .text:143d0ee7b    8      _sub_14341658E   c3                             retn

""" stack-maniuplation techniques i have known and loved ***
.text:143f1d066 000      checksummer                                                 checksummer:
.text:143f1d066 000   -8 checksummer                   55                                   push rbp
.text:143f1d067 008  -a0 checksummer                   48 81 ec a0 00 00 00                 sub rsp, 0A0h
.text:143f1d06e 0a8      checksummer                   48 8d 6c 24 20                       lea rbp, qword ptr [rsp+20h]
...
.text:140d040b3 0a8   -8 checksummer                   48 8d a5 80 00 00 00                 lea rsp, qword ptr [rbp+80h]
.text:140d040ba 0b0   +8 checksummer                   5d                                   pop rbp
.text:140d040bb 0a8      checksummer                   c3                                   retn                                             ; call stack is empty; END OF BRANCH   ; BREAK
###


.text:14105edf0 000      _sub_14105EDF0                                              _sub_14105EDF0:
.text:14105edf0 000      _sub_14105EDF0                48 89 5c 24 08                       mov [RSP+8], RBX
.text:14105edf5 000   -8 _sub_14105EDF0                55                                   push rbp
.text:14105edf6 008   -8 _sub_14105EDF0                56                                   push rsi
.text:14105edf7 010   -8 _sub_14105EDF0                57                                   push rdi
.text:14105edf8 018   -8 _sub_14105EDF0                41 54                                push r12
.text:14105edfa 020   -8 _sub_14105EDF0                41 57                                push r15
.text:14105edfc 028      _sub_14105EDF0                48 8d ac 24 80 fa ff ff              lea rbp, [rsp-0x580]
.text:14105ee04 028 -680 _sub_14105EDF0                48 81 ec 80 06 00 00                 sub rsp, 0x680

.text:14491b4fb 6a8      _sub_14105EDF0                48 8b 9c 24 b0 06 00 00              mov rbx, [rsp+0x6b0]
.text:14491b503 6a8 +680 _sub_14105EDF0                48 81 c4 80 06 00 00                 add rsp, 0x680
.text:14491b50a 028   +8 _sub_14105EDF0                41 5f                                pop r15
.text:14491b50c 020   +8 _sub_14105EDF0                41 5c                                pop r12
.text:14491b50e 018   +8 _sub_14105EDF0                5f                                   pop rdi
.text:14491b50f 010   +8 _sub_14105EDF0                5e                                   pop rsi
.text:14491b510 008   +8 _sub_14105EDF0                5d                                   pop rbp
.text:14491b511 000      _sub_14105EDF0                c3                                   retn

"""


"""
.text:143ffe08e 000      al_string_impl_0                                            misc__display_onscreen_keyboard_with_longer_initial_string_impl_0:
000        4c 89 4c 24 20                       mov [rsp+0x20], r9
000   -8   55                                   push rbp
008   -8   41 54                                push r12
010   -8   41 55                                push r13
018   -8   41 56                                push r14
020   -8   41 57                                push r15
028 -250   48 81 ec 50 02 00 00                 sub rsp, 0x250          rsp:1 = rsp:0 - 0x250
278        48 8d 6c 24 20                       lea rbp, [rsp+0x20]     rbp   = rsp:1 + 0x020
.....................................................
           48 8d a5 30 02 00 00                 lea rsp, [rbp+0x230]    rsp   =   rbp   + 0x230
                                                                        rsp   =  (rsp:1 + 0x020)  + 0x230
                                                                        rsp   = ((rsp:0 - 0x250)  + 0x020)  + 0x230
                                                                        rsp   =   rsp:0 - 0x250   + 0x020   + 0x230
                                                                        rsp   =   rsp:0 - 0x250   + 0x250
                                                                        rsp   =   rsp:0
                                                ; sp is returned to starting value
-228  +8   41 5f                                pop r15
-230  +8   41 5e                                pop r14
-238  +8   41 5d                                pop r13
-240  +8   41 5c                                pop r12
-248  +8   5d                                   pop rbp
-250       c3                                   retn
---------------------[or]----------------------------
000        4c 89 4c 24 20                       mov [rsp+0x20], r9
000   -8   55                                   push rbp
008   -8   41 54                                push r12
010   -8   41 55                                push r13
018   -8   41 56                                push r14
020   -8   41 57                                push r15                rsp   = -0x028
028 -250   48 81 ec 50 02 00 00                 sub rsp, 0x250          rsp   = -0x028 - 0x250 = -0x278
278        48 8d 6c 24 20                       lea rbp, [rsp+0x20]     rbp   = -0x278 + 0x020 = -0x258
.....................................................
           48 8d a5 30 02 00 00                 lea rsp, [rbp+0x230]    rsp   = rbp    + 0x230
                                                                        rsp   = -0x258 + 0x230 = -0x28
                                                                        rsp   = -0x28
                                                ; sp is returned to starting value



.text:0000000140A411D4 050 54                              push    rsp
.text:0000000140A411D5 058 41 5B                           pop     r11
.text:0000000140A411D7 050 49 83 C3 08                     add     r11, 8
.text:0000000140A411DE 050 4C 89 DC                        mov     rsp, r11



---------------------------[cmovz]-----
.text:1439983d3    0
.text:1439983d3    0          39 0d fb 70 38 fe             	cmp [g_pickup_related], ecx

.text:143e84f4b    0          48 89 6c 24 f8                	mov [rsp-8], rbp \ PUSH (will be swapped
.text:143e84f50    0   -8     48 8d 64 24 f8                	lea rsp, [rsp-8] /  RBP  for location_1)

.text:143e84f55    8          48 bd 6e 10 4d 43 01 00 00 00 	mov rbp, location_1
.text:140d25baa    8          48 87 2c 24                   	xchg [rsp], rbp  - PUSH location_1 to rsp[8]

.text:1440f2631    8   -8     48 8d 64 24 f8                	lea rsp, [rsp-8] \ PUSH to rsp[10h]
.text:1440f2636   10          48 89 14 24                   	mov [rsp], One   /  ONE --,
.text:140a637bd   10   -8     48 8d 64 24 f8                	lea rsp, [rsp-8] \ PUSH   | to rsp[18h]
.text:140a637c2   18          48 89 1c 24                   	mov [rsp], TWO   /  TWO   |
                                                                                ,-------'
                                                                               |
.text:143515b59   18          48 8b 54 24 10                	mov One, [rsp+0x10] MOV One, rsp[8]/location_1
.text:143515b5e   18          48 bb 5d f6 ca 40 01 00 00 00 	mov TWO, location_2
.text:143515b68   18          48 0f 44 d3                   	cmovz One, TWO
.text:143515b6c   18          48 89 54 24 10                	mov [rsp+0x10], One to rsp[8]

.text:144009cc4   18          48 8b 1c 24                   	mov TWO, [rsp]   \  POP
.text:144009cc8   18    8     48 8d 64 24 08                	lea rsp, [rsp+8] /  TWO
.text:144009ccd   10    8     48 8d 64 24 08                	lea rsp, [rsp+8] \  POP
.text:143eac9cb    8          48 8b 54 24 f8                	mov One, [rsp-8] /  ONE

.text:143eac9d0    8    8     48 8d 64 24 08                	lea rsp, [rsp+8]
.text:143eac9d5    0          ff 64 24 f8                   	jmp qword [rsp-8]-  JMP ONE

-----------------------
.text:00000001432B6F5E                                                                           ; VEHICLE__SET_PLAYBACK_TO_USE_AI_ACTUAL:loc_144B422E8j
.text:00000001432B6F5E 028 45 33 C9                        xor     r9d, r9d
.text:00000001432B6F61 028 48 89 5C 24 F8                  mov     [rsp-8], rbx
.text:00000001432B6F66 028 48 8D 64 24 F8                  lea     rsp, [rsp-8] ; push rbx to rsp[30h]
.text:00000001432B6F6B 030 44 8B 04 24                     mov     r8d, [rsp]   ; r8d = ebx
.text:00000001432B6F6F 030 48 8B 1C 24                     mov     rbx, [rsp]   ; rbx = rbx
.text:00000001432B6F73 030 48 89 E1                        mov     rcx, rsp     ; \
.text:00000001432B6F76 030 48 81 C1 08 00 00 00            add     rcx, 8       ; | lea rsp, [rsp+8]
.text:00000001432B6F7D 030 48 89 CC                        mov     rsp, rcx     ; /
.text:00000001432B6F80 030 33 D2                           xor     edx, edx     ; edx (rbx?) = 0
.text:00000001432B6F82 030 48 8D 64 24 F8                  lea     rsp, [rsp-8]
.text:00000001432B6F87 038 48 89 04 24                     mov     [rsp], rax   ; push rax
.text:00000001432B6F8B 038 48 8D 64 24 08                  lea     rsp, [rsp+8]
.text:00000001432B6F90 030 48 8B 4C 24 F8                  mov     rcx, [rsp-8] ; pop rcx

ultimately: xor r9d, r9d
	    mov r8d, ebx
	    xor edx, edx
	    push rax
	    pop rcx
	    jmp loc_140D394F4


------
.text:00000001438FFAE3 55                                          push    rbp
.text:00000001438FFAE4 48 8D 2D AB 37 35 00                        lea     rbp, sub_143C53296
.text:00000001438FFAEB 48 87 2C 24                                 xchg    rbp, [rsp]
.text:00000001438FFAEF E9 03 DC DC FF                              jmp     _sub_1436CD6F7

which is:

.text:00000001438FFAE3 E8 0F DC DC FF                              call    _sub_1436CD6F7
.text:00000001438FFAE8 E9 A9 37 35 00                              jmp     sub_143C53296

-----
switch the sausage
                    mov rax, rsp
                    sub rsp, 0xb8
                    lea r11, [rax]
                    mov rsp, r11
                    retn


----
consequitive calls:

    55                            	push rbp
    48 8d 2d 23 f2 0b fc          	lea rbp, [loc_140159EAD]
    48 87 2c 24                   	xchg [rsp], rbp
    e9 7a ae c6 fc                	jmp TheJudge
                                  TheJudge:
    55                            	push rbp
    48 8d 2d d3 59 53 00          	lea rbp, [loc_14123B4E8]
    48 87 2c 24                   	xchg [rsp], rbp
    e9 7c aa 37 02                	jmp TheWitch
                                  TheWitch:
    55                            	push rbp
    48 8d 2d 46 94 18 fd          	lea rbp, [loc_1402099E8]
    48 87 2c 24                   	xchg [rsp], rbp
    e9 09 e4 6e 01                	jmp ArxanBalance
                                  ArxanBalance:
    51                            	push rcx
    41 57                         	push r15

----
jmp within function via rsp + retn

.text:14362c247   28      sub_14485951D                                  label6:
.text:14362c247   28      sub_14485951D    48 85 d2                      	test rdx, rdx
.text:14362c24a   28      sub_14485951D    0f 85 06 3d ec fd             	jnz label2
.text:14362c250   28      sub_14485951D    e9 41 3d ec fd                	jmp label4
.text:1414effae   28      sub_14485951D                                  label12:
.text:1438ba73a   28      sub_14485951D    48 83 c2 08                   	add rdx, 8
.text:1439b53ea   28      sub_14485951D    48 8d 2d 56 6e c7 ff          	lea rbp, [rel label6]
.text:1439b53f1   28      sub_14485951D    48 87 2c 24                   	xchg [rsp], rbp
.text:1439b53f5   28      sub_14485951D    c3                            	retn


----


emulating a CALL using rbp + xchg

    push rbp
    lea rbp, [rel loc_143A7BD0F]  ; "return" address
    xchg [rsp], rbp
    jmp ArxanCheckFunction_269:
ArxanCheckFunction_269:
    push rbp
    sub rsp, 0xd0
    lea rbp, [rsp+0x20]
    ...
    retn

----
a [tail]call using push qword rel and retn

    call qword [rel GetCurrentProcess]
    mov edx, ebx
    mov rcx, rax
    add rsp, 0x20
    lea rsp, [rsp+8] ; --
    mov rbx, [rsp-8] ; pop rbx
    push qword [rel TerminateProcess]
    retn


---
jmp [rax]

    .text:0000000140055F1C 000 50                                            push    rax
    .text:0000000140055F1D 008 C3                                            retn

    .text:0000000140055F1C 000 FF 20                                         jmp     qword ptr [rax]

---
SP  SPD  OCTETS                          ASM
--  ---  ------------------------------  ------------------------------------------------
 0  -28  48 83 ec 28                     sub rsp, 0x28
28                                       ...
28   -8  55                              push rbp               ;\
30       48 bd 4d a7 09 44 01 00 00 00   mov rbp, bts_dword_ptr ; >-----------.
28    8  48 87 2c 24                     xchg [rsp], rbp        ;/            |
28   -8  50                              push rax               ; unused      |
30   -8  51                              push rcx               ; unused      v
38       48 8b 44 24 10                  mov rax, [rsp+0x10]    ; mov rax, bts_dword_ptr
38       48 b9 68 5e ca 40 01 00 00 00   mov rcx, add_rsp_0x28
38       48 0f 44 c1                     cmovz rax, rcx         ; jz  rcx [add_rsp_0x28]
38       48 89 44 24 10                  mov [rsp+0x10], rax    ;\
38    8  48 8d 64 24 08                  lea rsp, [rsp+8]       ; jnz rax [add_rsp_0x28]
30   -8  c3                              retn                   ;/
                                     ;------------------------
28                                   bts_dword_ptr:
28       0f ba a8 c0 00 00 00 1d         bts dword [rax+0xC0], 0x1D
28                                   add_rsp_0x28:
28       48 83 C4 28                     add rsp, 0x28
00  -28  C3                              retn


---
weird rdr psuedo-balance

TheJudge_0_0_0:                             
       .- push rax                          
       |  push 0x10                         
       |  test rsp, 0xf                     
       |  jnz label1                        
       |  push 0x18                         
label1:|                                    
       |  sub rsp, 8                        
       |  mov eax, [rel dword_14648A51F]    
       |  xor eax, [rel dword_1469BA3FE]    
       |  add rbp, rax                      
       |  add rsp, [rsp+8]                  
       `- pop rax                           
          mov [rsp+8], rcx                  
          sub rsp, 0x28                     
          mov rcx, [rsp+0x30]               
          call sub_140AF7DB0                
          imul eax, eax, 0x40d              
          mov ecx, [rel dword_144942340]    
          sub ecx, eax                      
          mov eax, ecx                      
          mov [rel dword_144942340], eax    
          mov al, 1                         
          add rsp, 0x28                     
          retn                              


TheJudge_0_0_0:                                                
.----< push rax                                                
|   .- push 0x10                                               
|   |  sub rsp, 8                                              
|   |  mov eax, [rel dword_14648A51F]                          
|   |  xor eax, [rel dword_1469BA3FE]                          
|   |  add rbp, rax      ; unset & unused register             
|   `- add rsp, [rsp+8]                                        
`----> pop rax           ; why restore unset & unused register?
-----------------[could.be.a.tail.call]------------------------
    .- mov [rsp+8], rcx  ; into homespace #1                   
    |  sub rsp, 0x28                                           
    `- mov rcx, [rsp+0x30] ; rcx = homespace #1                
       call sub_140AF7DB0; copy of which is below              
         l_.    mov eax, [rcx+0x10]                            
           '    shr eax, 0x1d                                  
       imul eax, eax, 0x40d                                    
       mov ecx, [rel dword_144942340]                          
       sub ecx, eax                                            
       mov eax, ecx                                            
       mov [rel dword_144942340], eax                          
       mov al, 1         ; will return true                    
       add rsp, 0x28     ; perfectly balanced                  
       retn                                                    
---
54                            	push rsp            
58                            	pop rax             
48 89 58 08                   	mov [rax+8], rbx    
48 89 70 10                   	mov [rax+0x10], rsi 
48 89 78 18                   	mov [rax+0x18], rdi # vim: set ts=4 sts=4 sw=4 et:
55                            	push rbp            
41 54                         	push r12            
41 55                         	push r13            
41 56                         	push r14            
41 57                         	push r15            
54                            	push rsp            
5d                            	pop rbp             
48 83 ec 70                   	sub rsp, 0x70       
4c 8d 5c 24 70                	lea r11, [rsp+0x70] 
49 8b 5b 30                   	mov rbx, [r11+0x30] 
49 8b 73 38                   	mov rsi, [r11+0x38] 
49 8b 7b 40                   	mov rdi, [r11+0x40] 
41 53                         	push r11            
5c                            	pop rsp             
41 5f                         	pop r15             
41 5e                         	pop r14             
41 5d                         	pop r13             
41 5c                         	pop r12             
5d                            	pop rbp             
c3                            	retn                

"""
