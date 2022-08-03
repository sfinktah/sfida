# Patch factory
def generate_patch1(jmpTargetOffset): # , oldRip = 0, newRip = 0, jmpType = 0xE9):
    """
    Typical Input:
        0:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        5:  48 89 2c 24             mov    [rsp], rbp
        9:  48 8d 2d 00 00 00 00    lea    rbp, [rip+0x0]        # 0x10
        10: 48 87 2c 24             xchg   [rsp], rbp
        14: 48 8d 64 24 08          lea    rsp,[rsp+0x8]
        19: ff 64 24 f8             jmp    [rsp-0x8]

    Typical Output:
        0:  e9 00 00 00 00          jmp    <target>
        5:

        offset of jmp target:  jmprip:  :newrip
        generate_patch1(0x09 + 3, 0x10, 0x05)
    """
    # replace=replaceFunction(search, replace, original, ea, addressList, patternComment)
    def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        addressList = addressList[:len(search)]
        # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
        # We will fill all these
        # result = [0xcc] * 5
        # result[0] = jmpType # this might be 0xe8 for CALL

        # We're going to cheat a lot, and convert this into a function that
        # will work with JMP blocks.
        #
        # This also means arguments oldRip and newRip will no longer be needed

        # if not MakeCodeAndWait(ea):
        # forceAsCode(ea, idc.next_head(ea+7)- ea)
        i = 0
        length = len(search)
        # ip += idaapi.as_signed(Dword(ip + 1), 32) + 5

        ip = addressList[jmpTargetOffset];
        if debug: print("patch: ip: 0x{:x}".format(ip))
        if debug: print("patch: ip signed dword: 0x{:x}".format(MakeSigned(idc.get_wide_dword(ip), 32)))
        ip += MakeSigned(Dword(ip), 32) + 4
        if debug: print("patch: ip + signed: 0x{:x}".format(ip))
        # fnName = GetOpnd(ItemHead(addressList[jmpTargetOffset]), 1)
        MakeCodeAndWait(ip, force = 1)
        fnName = idc.get_name(ip)
        if fnName:
            fnTarget = ip
        else:
            fnTarget = BADADDR

        if fnTarget == BADADDR:
            badIp = ItemHead(addressList[jmpTargetOffset])
            FixTargetLabels(badIp)
            #  MyMakeUnkn(ip, 0)
            #  MakeCodeAndWait(ip)
            fnName = idc.get_name(ip)
            if fnName:
                fnTarget = ip

        if fnTarget == BADADDR:
            MyMakeUnknown(idc.prev_head(ip), idc.next_head(ip) - idc.prev_head(ip), DOUNK_EXPAND | DOUNK_NOTRUNC)
            Wait()
            # MakeCodeAndWait(ip, force = 1)
            # We don't actually want a function, but we need a label fast.
            # (and turns out, that this won't actually give it to us)
            MakeCode(ip)
            Wait()
            if IsCode_(ip):
                fnName = ("loc_%X" % ip)
                #  MakeName(ip, fnName)
                MakeNameEx(ip, fnName, SN_NOWARN)
                Wait()
            if fnName:
                fnTarget = ip

        if fnTarget == BADADDR:
            print("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (
                ea,
                idc.generate_disasm_line(ItemHead(addressList[jmpTargetOffset]), GENDSM_FORCE_CODE),
                addressList[jmpTargetOffset],
                fnName,
                fnTarget,
                patternComment))
            print("search:   %s" % listAsHex(search))
            print("original: %s" % listAsHex(original))
            raise ObfuFailure("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (ea, idc.generate_disasm_line(ItemHead(addressList[jmpTargetOffset]), GENDSM_FORCE_CODE), addressList[jmpTargetOffset], fnName, fnTarget, patternComment))
            # Jump(ea) # A poor way to record the location, since it will cause
            # IDA to steal focus
            return []

        # idautils.Assemble only writes to buffer
        # toAssemble = "jmp " + fnName
        toAssemble = "jmp " + hex(ip)
        #  print("DEBUG: toAssemble: jmp " + fnName)

        result = []
        #  result += assemble_contig(0, 5, toAssemble, addressList)
        result.append(toAssemble)
        result.append("int3")
        return result

        #  print("assembled as " + listAsHex(result) + " for placement at %x" % addressList[0])
        #  srsly, why would it be a call - and result[0] is now not necessarily valid as we're searching for contig bytes
        #  result[0] = jmpType # this might be 0xe8 for CALL

        for i in range(len(search), len(search) - len(result) - 1):
            Commenter(addressList[i], 'line').add("[PATCH-INT] %i bytes: %s" % (contigCount, patternComment))
            idaapi.del_item_color(addressList[i])

        #  result.extend(MakeTerms(len(search) - len(result)))
        print("padded to " + listAsHex(result) + " for placement at %x" % addressList[0])
        # DEBUG: dont return the full patch yet, need to sort out proper placement for fragmented output
        #  return original

        #      a readDword too) for dealing with endian crap.
        #
        # jmpTarget = readDword(original, jmpTargetOffset)
        # adjustTarget = oldRip - newRip
        # jmpTarget = jmpTarget + adjustTarget
        # result[0] = jmpType # JMP rel32off
        # writeDword(result, 1, jmpTarget)

        # if len(result) != len(original):
            # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
        #  while len(result) < len(search):
            #  result.append(0xcc)
        return result
    return patch

# Patch Factory
#  PUSH does:
#
#  ESP := ESP-8  .
#  MEMORY[ESP]:=<operandvalue>
#  POP does:
#
#  <operandtarget>:=MEMORY[ESP];
#  ESP:=ESP+8
def generate_compact_cmov_abs_patch(fn1Offset = 3, fn2Offset = 0x11, conditionOffset = 0x22):
    """
RSP    OFF CODE                            ASSEMBLY                  TRANSLATION                     SIMPLIFICATION
000    0:  55    v-0x03                    push   rbp                rsp[08] = rbp                   x = fn1
008    1:  48 bd b0 70 d6 43 01 00 00 00   movabs rbp, fn1           rbp = fn1                       ? jmp fn2
008    b:  48 87 2c 24                     xchg   rbp, [rsp]         rsp[08] = fn1; rbp is restored  jmp fn1
008    f:  50                              push   rax                rsp[10] = rax
010    10: 51                              push   rcx                rsp[18] = rcx
018    11: 48 8b 44 24 10                  mov    rax, [rsp+10h]     rax = rsp[08] = fn1
              v-0x18
018    16: 48 b9 cc 1c 14 43 01 00 00 00   movabs rcx, fn2           rcx = fn2
              v-0x22
018    20: 48 0f 4d c1                     cmovge rax,rcx            x ? rax = rcx : noop ;
018    24: 48 89 44 24 10                  mov    [rsp+10h], rax     rsp[08] = rax = fn1/fn2
018    29: 59                              pop    rcx                rcx = rsp[18]; rcx is restored
010    2a: 58                              pop    rax                rax = rsp[10]; rax is restored
008    2b: c3                              ret                       jmp rsp[08] (fn1/fn2)

0000:0000000140CC5141 000 33 D2                                               xor     edx, edx
0000:0000000140CC5143 000 48 85 C0                                            test    rax, rax
0000:0000000140CC5146 000 55                                                  push    rbp
0000:0000000140CC5147 008 48 BD 47 A5 C6 40 01 00 00 00                       mov     rbp, offset loc_140C6A547
0000:0000000140CC5151 008 48 87 2C 24                                         xchg    rbp, [rsp]
0000:0000000140CC5155 008 50                                                  push    rax
0000:0000000140CC5156 010 51                                                  push    rcx
0000:0000000140CC5157 018 48 8B 44 24 10                                      mov     rax, [rsp+10h]
0000:0000000140CC515C 018 48 B9 4D A5 C6 40 01 00 00 00                       mov     rcx, offset loc_140C6A54D
0000:0000000140CC5166 018 48 0F 44 C1                                         cmovz   rax, rcx
0000:0000000140CC516A 018 48 89 44 24 10                                      mov     [rsp+10h], rax
0000:0000000140CC516F 018 59                                                  pop     rcx
0000:0000000140CC5170 010 58                                                  pop     rax
0000:0000000140CC5171 008 C3                                                  retn
    Conversion from cmov* to j*
    0:  48 0f 4d c1             cmovge rax,rcx              48 0f 4d ?? becomes 0f 8d
    4:  0f 8d 00 00 00 00       jge    a <_main+0xa>

    a:  48 0f 44 c1             cmove  rax,rcx              48 0f 44 ?? becomes 0f 84
    e:  0f 84 00 00 00 00       je     14 <_main+0x14>

    14: 48 0f 45 ca             cmovne rcx,rdx              48 0f 45 ?? becomes 0f 85
    18: 0f 85 00 00 00 00       jne    1e <_main+0x1e>
    """
    def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        addressList = addressList[:len(search)]
        i = 0
        length = len(search)
        if debug:
            print("ea", hex(ea))
            
            print("addressList[fn1Offset]", hex(addressList[fn1Offset]))
            print("addressList[fn2Offset]", hex(addressList[fn2Offset]))
            print("addressList[conditionOffset - 2]", hex(addressList[conditionOffset - 2]))
            print("addressList[conditionOffset]", hex(addressList[conditionOffset]))
            print("conditionalMnen: {}".format(idc.generate_disasm_line(addressList[conditionOffset - 2], GENDSM_FORCE_CODE)))
        conditionalMnem = idc.generate_disasm_line(addressList[conditionOffset - 2], GENDSM_FORCE_CODE).split(None, 1)[0].replace("cmov", "j")
        conditionalByte = Byte(addressList[conditionOffset]) + 0x40;
        addrs = []
        for i in range(length):
            _chunkstart = GetChunkStart(addressList[i])
            if _chunkstart == idc.BADADDR:
                pass
                #  raise ObfuFailure("0x%x: 0x%x: Couldn't get ChunkStart" % (ea, addressList[i]))
            else:
                EaseCode(_chunkstart)
            addrs.append(addressList[i])

        while addrs:
            assembled = forceCode(addrs[0])[0]
            if not IsCode(addrs[0]) and not EaseCode(addrs[0], forceStart=1, noExcept=1):
                raise ObfuFailure("0x%x: !IsCode(0x%x)" % (ea, addrs[0]))
                return []
            addrs = addrs[assembled:]
        # result = [0xcc]*len(search) # preallocate result with 0xcccccc...
        if not IsCode_(addressList[1]):
            forceCode(addressList[1])
        if GetMnem(addressList[1]) != 'mov' or MakeCodeAndWait(addressList[1]) != 10:
            raise ObfuFailure("0x{:x}: 0x{:x}: incorrectly detected compact movabs: expected 'mov' but got '{}' - {}".format \
                    (ea, addressList[1], idc.print_insn_mnem(addressList[1]), idc.generate_disasm_line(addressList[1], GENDSM_FORCE_CODE)))
            return None
        target = BADADDR

        #        for i in range(len(search) - 11):
        #            if (addressList[i + 11 - 1] - addressList[i] == 11 - 1):
        #                target = i
        #                break
        #        if target == BADADDR:
        #            print("0x%x: 11 contiguous bytes not found at target" % ea)
        #            raise ObfuFailure("0x%x: 11 contiguous bytes not found at target" % ea)
        #            return []
        #
        #        # If initial padding with nops is needed
        #        result = []
        #        if i:
        #            print("Making %i nops" % i)
        #            nopAddresses = [addressList[n] for n in range(i)]
        #            nopRanges = GenericRanger(nopAddresses)
        #            for r in nopRanges:
        #                print("%i nops" % r['length'])
        #                result += MakeNops(r['length'])
        #
        idc.op_plain_offset(addressList[fn1Offset - 2], 1, 0)
        idc.op_plain_offset(addressList[fn2Offset - 2], 1, 0)
        Wait()

        _addr1 = Qword(addressList[fn1Offset])
        _addr2 = Qword(addressList[fn2Offset])

        in1 = idc.get_item_head(addressList[fn1Offset])
        in2 = idc.get_item_head(addressList[fn2Offset])

        addr1 = MyGetOperandValue(addressList[fn1Offset - 2], 1)
        addr2 = MyGetOperandValue(addressList[fn2Offset - 2], 1)

        if addr1 != _addr1:
            err = "ObfuFailure: addr1 != _addr1  0x%x != 0x%x" % (addr1, _addr1)
            print("Error", err)
            raise ObfuFailure(err)

        if addr2 != _addr2:
            err = "ObfuFailure: addr2 != _addr2  0x%x != 0x%x" % (addr2, _addr2)
            print("Error", err)
            raise ObfuFailure(err)

        MakeCodeAndWait(addr1, 1)
        MakeCodeAndWait(addr2, 1)
        fn1 = Name(addr1)
        fn2 = Name(addr2)

        #  if len(fn1) == 0:
            #  err = "0x%x: Couldn't parse fn1 (0x%x) at 0x%x processing pattern '%s'" % (ea, addr1, addressList[fn1Offset], patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []

        #  if len(fn2) == 0:
            #  err = "0x%x: Couldn't parse fn2 (0x%x) 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, addr2, (addressList[fn2Offset] - 2), idc.generate_disasm_line((addressList[fn2Offset]) - 2), addressList[fn2Offset], fn1Offset, fn2Offset, conditionOffset, patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []

        #  toAssemble = "" + conditionalMnem + " " + ("0x%x" % addr2)
        #  print("0x%x: Assembling %s for 0x%x" % (ea, toAssemble, addressList[0]))
        #  result = assemble_contig(0, 8, toAssemble, addressList)
#  
        #  toAssemble = "jmp " + ("0x%x" % addr1)
        #  print("0x%x: Assembling %s for 0x%x (offset %i)" % (ea, toAssemble, addressList[len(result)], len(result)))
        #  asm = assemble_contig(len(result), 5, toAssemble, addressList)
        #  result += asm

        result = ["" + conditionalMnem + " " + ("0x%x" % addr2),
                  "jmp " + ("0x%x" % addr1),
                  "int3"
                 ]

        return result
        #  raise ObfuFailure("test here")

        #        asm = qassemble(addressList[len(result)], toAssemble)
        #        if not asm: #  or len(asm) != 6:
        #            print("0x%x: Expected 2-6 byte list from assembling '%s', got: '%s'. Was intending to change conditional to '0x%02x'" % (addressList[0], toAssemble, str(asm), conditionalByte))
        #            raise ObfuFailure("0x%x: Expected 6 byte list from assembling '%s', got: '%s'. Was intending to change conditional to '0x%02x'" % (addressList[0], toAssemble, str(asm), conditionalByte))
        #            return []
        #
        #        result += asm
        #
        #        toAssemble = "jmp %s" % fn1
        #        asm = qassemble(addressList[len(result)], toAssemble)
        #        if not asm:
        #            print("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
        #            raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
        #            return []
        #
        #        result += asm

        #  while len(result) < len(search):
            #  result.append(0xcc)
            #  idaapi.del_item_color(addressList[len(result)-1])
            #  Commenter(addressList[len(result) - 1], 'line').add("[PATCH-INT] mini-cmov")

        for i in range(len(search), len(search) - len(result) - 1):
            Commenter(addressList[i], 'line').add("[PATCH-INT] %i cmov: %s" % (contigCount, patternComment))
            idaapi.del_item_color(addressList[i])

        # result.extend(MakeTerms(len(search) - len(result)))

        if Byte(addressList[len(search) - 1] + 1) == 0xe9:
            if len(list(idautils.CodeRefsFrom(addressList[len(search) - 1] + 1, 1))) == 0:
                #  PatchBytes(addressList[len(search) - 1] + 1, [0xcc] * 5, patternComment)
                idaapi.del_item_color(addressList[len(search)-1] + 1)
                Wait();
                Commenter(addressList[len(search) - 1] + 1, 'line').add("[PATCH-INT] fake jump component of cmovz/nz")

        return result
    return patch
# Patch factory
def generate_cmov_abs_patch(fn1Offset, fn2Offset, condition = "jnz"):
    """
    BEFORE                                                               AFTER
    0: 028 48 bd 3c 9f c6 40 01+   movabs rbp,0x140c69f3c                fn1 = Qword(0x02)
    a: 028 48 87 2c 24             xchg   QWORD PTR [rsp],rbp            fn2 = Qword(0x27)
    e: 028 48 8d 64 24 f8          lea    rsp,[rsp-0x8]                  jne j_fn1
    13:030 48 89 0c 24             mov    QWORD PTR [rsp],rcx            jmp fn2
    17:030 48 8d 64 24 f8          lea    rsp,[rsp-0x8]            j_fn1:
    1c:038 48 89 14 24             mov    QWORD PTR [rsp],rdx            jmp fn1
    20:038 48 8b 4c 24 10          mov    rcx,QWORD PTR [rsp+0x10]
    25:038 48 ba 21 9f c6 40 01+   movabs rdx,0x140c69f21
    2f:038 48 0f 45 ca             cmovne rcx,rdx
    33:038 48 89 4c 24 10          mov    QWORD PTR [rsp+0x10],rcx
    38:038 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    3d:030 48 8b 54 24 f8          mov    rdx,QWORD PTR [rsp-0x8]
    42:030 48 8b 0c 24             mov    rcx,QWORD PTR [rsp]
    46:030 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    4b:028 48 8d 64 24 08          lea    rsp,[rsp+0x8]
    50:020 ff 64 24 f8             jmp    QWORD PTR [rsp-0x8]
    54:    90                      nop

    Conversion from cmov* to j*
    0:  48 0f 4d c1             cmovge rax,rcx              48 0f 4d ?? becomes 0f 8d
    4:  0f 8d 00 00 00 00       jge    a <_main+0xa>
    a:  48 0f 44 c1             cmove  rax,rcx              48 0f 44 ?? becomes 0f 84
    e:  0f 84 00 00 00 00       je     14 <_main+0x14>
    14: 48 0f 45 ca             cmovne rcx,rdx              48 0f 45 ?? becomes 0f 85
    18: 0f 85 00 00 00 00       jne    1e <_main+0x1e>

        48 0f 42 d8             cmovb   rbx, rax
        0F 82 00 00 00 00       jb      near ptr sub_140A2F5AC

    """
    def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        addressList = addressList[:len(search)]
        i = 0
        length = len(search)
        while i < length:
            assembled = MakeCodeAndWait(addressList[i])
            if not assembled:
                assembled = forceAsCode(addressList[i], 15)
            if not assembled:
                raise ObfuFailure("0x%x: could not assemble line 0x%x" % (ea, addressList[i]))
                return []
            i += assembled
        # result = [0xcc]*len(search) # preallocate result with 0xcccccc...
        if GetMnem(addressList[9]) != 'mov' or MakeCodeAndWait(addressList[9]) != 10:
            print("0x%x: incorrectly detected movabs: 0x%x: %s" % (ea, addressList[9], idc.generate_disasm_line(ea, GENDSM_FORCE_CODE)))
            return None

        # Step #1: Move the assembly code above the addressList checking
        #          code, as sometimes we don't even need 17 bytes (short jumps)
        #
        # Thought #1: Just calculate all the instructions as being at 0 to see
        # how big it's going to be using short jumps... no that won't work, as
        # the jumps will be to totally distance parts of the chunked code... if
        # it wasn't chunked, then we wouldn't have the issue with contiguous
        # bytes.
        #
        # Thought #2: We could use a translation of addressList to
        # addressListWithNops and keep the old logic.
        #
        # Thought #3: Just write the results in a list of instructions, leaving
        # them unresolved (not assembled) where appropriate, and figure it out
        # later.
        #
        # result = [0x48, 0x8d, 0x64, 0x24, 0x08, 0x75, 0x05] # lea rsp,[rsp+0x08]

        # If initial padding with nops is needed

        # Implementation of thought #3
        result = []
        #
        # Thought #4: Add the extra 9 bytes that alter lea to the pattern, and
        # save writing the adjustment out
        #
        #  result = result + [0x48, 0x8d, 0x64, 0x24, 0x08] # lea rsp,[rsp+8]
        #
        OpOff(addressList[fn1Offset - 2], 1, 0)
        OpOff(addressList[fn2Offset - 2], 1, 0)

        addr1 = Qword(addressList[fn1Offset])
        addr2 = Qword(addressList[fn2Offset])
        #  print("fn1Offset: 0x%x" % addr1)
        #  print("fn2Offset: 0x%x" % addr2)
        Wait()

        fn1 = Name(addr1)
        fn2 = Name(addr2)

        if len(fn1) == 0:
            MakeCodeAndWait(addr1, 1)
            fn1 = Name(addr1)
        if len(fn2) == 0:
            MakeCodeAndWait(addr2, 1)
            fn2 = Name(addr2)

        if len(fn1) == 0:
            err = "0x%x: Couldn't parse fn1 at 0x%x processing pattern '%s'" % (ea, addressList[fn1Offset], patternComment)
            MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            print("ObfuFailure: %s" % err)
            raise ObfuFailure(err)
            return []

        #  if len(fn2) == 0:
            #  err = "0x%x: Couldn't parse fn2 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, (addressList[fn2Offset] - 2), idc.generate_disasm_line((addressList[fn2Offset]) - 2), addressList[fn2Offset], fn1Offset, fn2Offset, condition, patternComment)
            #  MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            #  print("ObfuFailure: %s" % err)
            #  raise ObfuFailure(err)
            #  return []

        #  ptr = len(result)

        toAssemble = "%s %xh" % (condition, addr2)
        result.append(toAssemble)
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 (4-7) byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
        #  #  ptr = ptr + len(buffer[1])

        toAssemble = "jmp %s" % fn1
        result.append(toAssemble)

        return result

        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm

        # End of code from below

        requiredLen = len(result)

        useListEx = False
        target = BADADDR
        translatedAddressList = []
        for i in range(len(search)):
            translatedAddressList.append(addressList[i])

        #  for i in range(len(search) - requiredLen):
            #  if (addressList[i + requiredLen] - addressList[i] == requiredLen):
                #  target = i
                #  break

        r = len(search) - requiredLen + 1
        print("range: %i" % r)
        for i in range(r):
            if (addressList[i + requiredLen - 1] - addressList[i] == requiredLen - 1):
                target = i
                break

        print("target: %i" % target)

        if target == BADADDR:
            print("0x%x: %i contiguous bytes not found at target with addressList" % (ea, requiredLen))
            print("translatedAddressList", listAsHexWith0x(translatedAddressList))

            translatedAddressList = []
            for i in range(len(search)):
                translatedAddressList.append(addressListWithNops[i])
            for i in range(len(search) - 17):
                if (addressListWithNops[i + 17] - addressListWithNops[i] == 17):
                    target = i
                    break

            if target == BADADDR:
                raise ObfuFailure("0x%x: %i contiguous bytes not found at target with addressListWithNops" % (ea, requiredLen))
                return []

            raise ObfuFailure("0x%x: %i contiguous WERE found using addressListWithNops, but we haven't coded that yet" % (ea, requiredLen))
            useListEx = True
            # Now how the fuck are we going to cope with using a list that
            # includes nops, when the search patterns all rely on fixed
            # positions **without** nops.
            #
            # Step #1: Move the assembly code above the addressList checking
            #          code, as sometimes we don't even need 17 bytes (short jumps)

        # Step #1: Move the assembly code above the addressList checking
        #          code, as sometimes we don't even need 17 bytes (short jumps)
        #
        # result = [0x48, 0x8d, 0x64, 0x24, 0x08, 0x75, 0x05] # lea rsp,[rsp+0x08]

        # If initial padding with nops is needed

        result = []
        if i:
            if debug: print("Making %i nops" % i)
            nopAddresses = [addressList[n] for n in range(i)]
            nopRanges = GenericRanger(nopAddresses, sort=0, outsort=0)
            for r in nopRanges:
                if debug: print("%i nops" % r['length'])
                result += MakeNops(r['length'])

        # We don't need this anymore, as we're replacing the crap that caused loading up of RSP
        # result = result + [0x48, 0x8d, 0x64, 0x24, 0x08] # lea rsp,[rsp+8]
        addr1 = Qword(addressList[fn1Offset])
        addr2 = Qword(addressList[fn2Offset])
        #  print("fn1Offset: 0x%x" % addr1)
        #  print("fn2Offset: 0x%x" % addr2)

        fn1 = Name(addr1)
        fn2 = Name(addr2)

        if len(fn1) == 0:
            MakeCodeAndWait(addr1, 1)
            fn1 = Name(addr1)

        if len(fn2) == 0:
            MakeCodeAndWait(addr2, 1)
            fn2 = Name(addr2)

        if len(fn1) == 0:
            err = "0x%x: Couldn't parse fn1 at 0x%x processing pattern '%s'" % (ea, addressList[fn1Offset], patternComment)
            MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            print("ObfuFailure: %s" % err)
            raise ObfuFailure(err)
            return []

        if len(fn2) == 0:
            err = "0x%x: Couldn't parse fn2 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, (addressList[fn2Offset] - 2), 
                    idc.generate_disasm_line((addressList[fn2Offset]) - 2, GENDSM_FORCE_CODE), addressList[fn2Offset], fn1Offset, fn2Offset, condition, patternComment)
            MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            print("ObfuFailure: %s" % err)
            raise ObfuFailure(err)
            return []

        #  ptr = len(result)

        toAssemble = "%s %s" % (condition, fn2)
        asm = qassemble(addressList[len(result)], toAssemble)
        if not asm:
            raise ObfuFailure("0x%x: Expected 2-6 (4-8) byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            return []

        result += asm
        #  ptr = ptr + len(buffer[1])

        toAssemble = "jmp %s" % fn1
        asm = qassemble(addressList[len(result)], toAssemble)
        if not asm:
            raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            return []

        result += asm
        #  while len(result) < len(search):
            #  result.append(0xcc)
            #  idaapi.del_item_color(addressList[len(result)-1])
            #  Commenter(addressList[len(result) - 1], 'line').add("[PATCH-INT] cmovz/nz")

        for i in range(len(search), len(search) - len(result) - 1):
            Commenter(addressList[i], 'line').add("[PATCH-INT] %i cmov: %s" % (contigCount, patternComment))
            idaapi.del_item_color(addressList[i])

        #  result.extend(MakeTerms(len(search) - len(result)))

        if Byte(addressList[len(search) - 1] + 1) == 0xe9:
            if len(list(idautils.CodeRefsFrom(addressList[len(search) - 1] + 1, 1))) == 0:
                #  PatchBytes(addressList[len(search) - 1] + 1, MakeNops(5), patternComment)
                idaapi.del_item_color(addressList[len(search)-1] + 1)
                Wait();
                Commenter(addressList[len(search) - 1] + 1, 'line').add("[PATCH-INT] fake jump component of cmovz/nz")
        return result
    return patch

def generate_cmov_patch3(fn1Offset, fn2Offset, condition = "jnz"):
    """
    Conversion from cmov* to j*
    0:  48 0f 4d c1             cmovge rax,rcx              48 0f 4d ?? becomes 0f 8d
    4:  0f 8d 00 00 00 00       jge    a <_main+0xa>
    a:  48 0f 44 c1             cmove  rax,rcx              48 0f 44 ?? becomes 0f 84
    e:  0f 84 00 00 00 00       je     14 <_main+0x14>
    14: 48 0f 45 ca             cmovne rcx,rdx              48 0f 45 ?? becomes 0f 85
    18: 0f 85 00 00 00 00       jne    1e <_main+0x1e>

        48 0f 42 d8             cmovb   rbx, rax
        0F 82 00 00 00 00       jb      near ptr sub_140A2F5AC

    """
    def patch(search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        addressList = addressList[:len(search)]
        i = 0
        length = len(search)
        while i < length:
            assembled = MakeCodeAndWait(addressList[i])
            if not assembled:
                assembled = forceAsCode(addressList[i], 15)
            if not assembled:
                raise ObfuFailure("0x%x: could not assemble line 0x%x" % (ea, addressList[i]))
                return []
            i += assembled
        # result = [0xcc]*len(search) # preallocate result with 0xcccccc...
        if GetMnem(addressList[fn1Offset]) != 'mov' or MakeCodeAndWait(addressList[fn1Offset]) != 10:
            print("0x%x: incorrectly detected movabs: 0x%x: %s" % (ea, addressList[fn1Offset], idc.generate_disasm_line(ea, GENDSM_FORCE_CODE)))
            return None

        result = []

        addr1 = get_operand_value(addressList[fn1Offset], 1)
        insn2 = diida(addressList[fn2Offset])
        tgt2 = string_between(', ', '', insn2)
        Wait()

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


        toAssemble = "%s %xh" % (condition, addr1)
        result.append(toAssemble)
        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 (4-7) byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm
        #  #  ptr = ptr + len(buffer[1])

        toAssemble = "jmp %s" % tgt2
        result.append(toAssemble)

        return result

        #  asm = qassemble(addressList[len(result)], toAssemble)
        #  if not asm:
            #  raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            #  return []
#  
        #  result += asm

        # End of code from below

        requiredLen = len(result)

        useListEx = False
        target = BADADDR
        translatedAddressList = []
        for i in range(len(search)):
            translatedAddressList.append(addressList[i])

        #  for i in range(len(search) - requiredLen):
            #  if (addressList[i + requiredLen] - addressList[i] == requiredLen):
                #  target = i
                #  break

        r = len(search) - requiredLen + 1
        print("range: %i" % r)
        for i in range(r):
            if (addressList[i + requiredLen - 1] - addressList[i] == requiredLen - 1):
                target = i
                break

        print("target: %i" % target)

        if target == BADADDR:
            print("0x%x: %i contiguous bytes not found at target with addressList" % (ea, requiredLen))
            print("translatedAddressList", listAsHexWith0x(translatedAddressList))

            translatedAddressList = []
            for i in range(len(search)):
                translatedAddressList.append(addressListWithNops[i])
            for i in range(len(search) - 17):
                if (addressListWithNops[i + 17] - addressListWithNops[i] == 17):
                    target = i
                    break

            if target == BADADDR:
                raise ObfuFailure("0x%x: %i contiguous bytes not found at target with addressListWithNops" % (ea, requiredLen))
                return []

            raise ObfuFailure("0x%x: %i contiguous WERE found using addressListWithNops, but we haven't coded that yet" % (ea, requiredLen))
            useListEx = True
            # Now how the fuck are we going to cope with using a list that
            # includes nops, when the search patterns all rely on fixed
            # positions **without** nops.
            #
            # Step #1: Move the assembly code above the addressList checking
            #          code, as sometimes we don't even need 17 bytes (short jumps)

        # Step #1: Move the assembly code above the addressList checking
        #          code, as sometimes we don't even need 17 bytes (short jumps)
        #
        # result = [0x48, 0x8d, 0x64, 0x24, 0x08, 0x75, 0x05] # lea rsp,[rsp+0x08]

        # If initial padding with nops is needed

        result = []
        if i:
            if debug: print("Making %i nops" % i)
            nopAddresses = [addressList[n] for n in range(i)]
            nopRanges = GenericRanger(nopAddresses, sort=0, outsort=0)
            for r in nopRanges:
                if debug: print("%i nops" % r['length'])
                result += MakeNops(r['length'])

        # We don't need this anymore, as we're replacing the crap that caused loading up of RSP
        # result = result + [0x48, 0x8d, 0x64, 0x24, 0x08] # lea rsp,[rsp+8]
        addr1 = Qword(addressList[fn1Offset])
        addr2 = Qword(addressList[fn2Offset])
        #  print("fn1Offset: 0x%x" % addr1)
        #  print("fn2Offset: 0x%x" % addr2)

        fn1 = Name(addr1)
        fn2 = Name(addr2)

        if len(fn1) == 0:
            MakeCodeAndWait(addr1, 1)
            fn1 = Name(addr1)

        if len(fn2) == 0:
            MakeCodeAndWait(addr2, 1)
            fn2 = Name(addr2)

        if len(fn1) == 0:
            err = "0x%x: Couldn't parse fn1 at 0x%x processing pattern '%s'" % (ea, addressList[fn1Offset], patternComment)
            MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn1Offset])), 1)
            print("ObfuFailure: %s" % err)
            raise ObfuFailure(err)
            return []

        if len(fn2) == 0:
            err = "0x%x: Couldn't parse fn2 0x%x: %s at 0x%x (%i, %i, %s) processing pattern '%s'" % (ea, (addressList[fn2Offset] - 2), 
                    idc.generate_disasm_line((addressList[fn2Offset]) - 2, GENDSM_FORCE_CODE), addressList[fn2Offset], fn1Offset, fn2Offset, condition, patternComment)
            MyMakeUnkn(idc.prev_head(idc.next_head(addressList[fn2Offset])), 1)
            print("ObfuFailure: %s" % err)
            raise ObfuFailure(err)
            return []

        #  ptr = len(result)

        toAssemble = "%s %s" % (condition, fn2)
        asm = qassemble(addressList[len(result)], toAssemble)
        if not asm:
            raise ObfuFailure("0x%x: Expected 2-6 (4-8) byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(buffer)))
            return []

        result += asm
        #  ptr = ptr + len(buffer[1])

        toAssemble = "jmp %s" % fn1
        asm = qassemble(addressList[len(result)], toAssemble)
        if not asm:
            raise ObfuFailure("0x%x: Expected 2-5 byte list from assembling '%s', got: '%s'" % (addressList[len(result)], toAssemble, str(buffer)))
            return []

        result += asm
        #  while len(result) < len(search):
            #  result.append(0xcc)
            #  idaapi.del_item_color(addressList[len(result)-1])
            #  Commenter(addressList[len(result) - 1], 'line').add("[PATCH-INT] cmovz/nz")

        for i in range(len(search), len(search) - len(result) - 1):
            Commenter(addressList[i], 'line').add("[PATCH-INT] %i cmov: %s" % (contigCount, patternComment))
            idaapi.del_item_color(addressList[i])

        #  result.extend(MakeTerms(len(search) - len(result)))

        if Byte(addressList[len(search) - 1] + 1) == 0xe9:
            if len(list(idautils.CodeRefsFrom(addressList[len(search) - 1] + 1, 1))) == 0:
                #  PatchBytes(addressList[len(search) - 1] + 1, MakeNops(5), patternComment)
                idaapi.del_item_color(addressList[len(search)-1] + 1)
                Wait();
                Commenter(addressList[len(search) - 1] + 1, 'line').add("[PATCH-INT] fake jump component of cmovz/nz")
        return result
    return patch


def generate_mov_reg_reg_via_stack_patch():
    """
    Typical Input:
        0:  48 8d 64 24 f8          lea    rsp,[rsp-0x8]
        5:  48 89 0c 24             mov    QWORD PTR [rsp],rcx
        9:  4c 8b 0c 24             mov    r9,QWORD PTR [rsp]
        d:  48 8d 64 24 08          lea    rsp,[rsp+0x8]

    Typical Output:
        0:  48 89 D1                mov    rcx,rdx
        0:  49 89 C8                mov    r8,rcx
        0:  4C 89 C2                mov    rdx,r8

        offset of jmp target:  jmprip:  :newrip
        generate_patch1(0x09 + 3, 0x10, 0x05)
    """
    # replace=replaceFunction(search, replace, original, ea, addressList, patternComment, addressListWithNops)
    def patch(                search, replace, original, ea, addressList, patternComment, addressListWithNops, **kwargs):
        addressList = addressList[:len(search)]
        # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
        # We will fill all these
        # result = [0xcc] * 5
        # result[0] = jmpType # this might be 0xe8 for CALL

        # We're going to cheat a lot, and convert this into a function that
        # will work with JMP blocks.
        #
        # This also means arguments oldRip and newRip will no longer be needed

        # if not MakeCodeAndWait(ea):
        # forceAsCode(ea, idc.next_head(ea+7)- ea)
        i = 0
        length = len(search)
        # ip += idaapi.as_signed(Dword(ip + 1), 32) + 5

        ip = addressList[jmpTargetOffset];
        ip += idaapi.as_signed(Dword(ip), 32) + 4
        # fnName = GetOpnd(ItemHead(addressList[jmpTargetOffset]), 1)
        MakeCodeAndWait(ip, force = 1)
        fnName = GetTrueName(ip)
        if fnName:
            fnTarget = ip
        else:
            fnTarget = BADADDR

        if fnTarget == BADADDR:
            badIp = ItemHead(addressList[jmpTargetOffset])
            FixTargetLabels(badIp)
            #  MyMakeUnkn(ip, 0)
            #  MakeCodeAndWait(ip)
            fnName = GetTrueName(ip)
            if fnName:
                fnTarget = ip

        if fnTarget == BADADDR:
            print("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (
                ea,
                idc.generate_disasm_line(ItemHead(addressList[jmpTargetOffset]), GENDSM_FORCE_CODE),
                addressList[jmpTargetOffset],
                fnName,
                fnTarget,
                patternComment))
            print("search:   %s" % listAsHex(search))
            print("original: %s" % listAsHex(original))
            raise ObfuFailure("0x%x: %s: fnName 0x%x: (%s) resolved to (%x): %s" % (ea, idc.generate_disasm_line(ItemHead(addressList[jmpTargetOffset]), GENDSM_FORCE_CODE), addressList[jmpTargetOffset], fnName, fnTarget, patternComment))
            # Jump(ea) # A poor way to record the location, since it will cause
            # IDA to steal focus
            return []

        # In theory (haven't checked documents) idautils.Assemble only writes
        # to buffer
        toAssemble = "jmp " + fnName
        result = assemble_contig(0, toAssemble, 5, addressList)
        if not result or len(result) < 2:
            # raise Exception("Expected 5 byte list from assembling '%s', got: '%s'" % (toAssemble, str(result)))
            raise ObfuFailure("0x%x: Expected 5 byte list from assembling '%s', got: '%s'" % (addressList[0], toAssemble, str(result)))
            return []
        #  result[len(result) -  5] = jmpType # this might be 0xe8 for CALL

        #  for i in range(len(search), len(search) - len(result) - 1):
            #  Commenter(addressList[i], 'line').add("[PATCH-INT] %i bytes: %s" % (contigCount, patternComment))
            #  idaapi.del_item_color(addressList[i])

        #  result.extend([0xcc] * (len(search) - len(result)))

        #      a readDword too) for dealing with endian crap.
        #
        # jmpTarget = readDword(original, jmpTargetOffset)
        # adjustTarget = oldRip - newRip
        # jmpTarget = jmpTarget + adjustTarget
        # result[0] = jmpType # JMP rel32off
        # writeDword(result, 1, jmpTarget)

        # if len(result) != len(original):
            # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
        #  while len(result) < len(search):
            #  result.append(0xcc)
        return result
    return patch

#unused
def patch_brick_jmp_jz(search, replace, original, ea, addressList):
    addressList = addressList[:len(search)]
    # result = [0xcc]*len(original) # preallocate result with 0xcccccc...
    # result = [0xcc] * 5
    #
    #
    #
    # So we can read/write by offset using search and replace as char arrays
    # result[0] = jmpType # this might be 0xe8 for CALL
    #

    # so, um, 0x02 and 0x0e to 0x11 and 0x32 for 8 bytes each.
    # (excercise for reader a.k.a. brick) - un maffinnify this:

    # 0:  48 b8 11 11 11 11 11 11 01 00   movabs rax,0x1111111111111
    # a:  74 0a                           je     16 <skip>
    # c:  48 b8 22 22 22 22 22 22 02 00   movabs rax,0x2222222222222
    # <skip>:
    # 16: ff e0                   jmp    rax

    result[0] = 0x48
    result[1] = 0xb8
    #
    # so, um, 0x02 and 0x0e to 0x11 and 0x32 for 8 bytes each.
    result[2:8] = original[0x0e:8]

    result[0xa] = 0x74
    result[0xb] = 0x0a;
    # result[0xc] = original[0x32]
    # ...
    # result[0xc+8] = result[0x32+8]
    # this maybe will work
    result[0xc:8] = original[0x32:8]

    # fill remainder with 0xcc
    #  while len(result) < len(search):
        #  result.append(0xcc)

    # A nice solution would have readQWord or somesuch
    #  def readDword(array, offset):
        #  return struct.unpack_from("<I", bytearray(array), offset)[0]
    #
    #  def writeDword(array, offset, word):
        #  array[offset:offset+4] = bytearray(struct.pack("<I", word))

    # jmpTarget = readDword(original, jmpTargetOffset)
    # writeDword(result, 1, jmpTarget)

    # if len(result) != len(original):
        # raise Exception("result(%position) originalLength != original(%position)" % (len(result), len(original)))
    return result
