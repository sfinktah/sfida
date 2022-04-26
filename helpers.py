# &.update_file(__file__)

import idautils
import inspect
import collections
import json
import os
import idc
import circularlist
from attrdict1 import SimpleAttrDict
#  import pydot.src.pydot

from execfile import make_refresh
refresh_helpers = make_refresh(os.path.abspath(__file__))

"""
Some shortcut functions for CLI work in IDA via the Python REPL
See: help2()
"""
# import sfcommon

def helpers():
    print("""
    EA()      short for ScreenEA (return current address)
    pos()     return/show position in hex with label name
    down()    move down one line
    up()    move up one line
    next()    trace backwards one instruction
    prev() trace forwards one instruction
    """)
    

EA_circular = circularlist.CircularList(64)
def EA():
    ea = ScreenEA()
    EA_circular.append(ea)
    return ea

def EAhist():
    for ea in EA_circular:
        print("{:x} {}".format(ea, idc.get_name(ea)))

def F(ea = ScreenEA()):
    return idc.get_full_flags(ea)
    
def pos(ea = ScreenEA()):
    if type(ea) is tuple:
        ea = eval(ea[0])
    # print("type(ea): {0}, ea: {1}".format(type(ea), ea))
    name = NameEx(ea, ea) # Will return '' if none
    return ("0x%012x" % ea, name)
    
def traversalFactory(*args):
    def traversalFn(ea = None):
        if ea is None:
            ea = ScreenEA()
        targets = [x for x in [x(ea) for x in args] if x != idc.BADADDR]
        for target in targets:
            if not IsCode_(target):
                forceCode(target)
                idc.jumpto(target)

        target = ea
        nextAny = fn1(ea)
        nextHead = fn2(ea)
        if nextAny != nextHead:
            # The means that the next instruction is data
            print(("fn1: {0}    fn2: {1}".format(nextAny, nextHead)))
        else:
            target = nextHead
            Jump(target)

        return pos(target)
        return "%x" % target
    return traversalFn
        
    
up = traversalFactory(idc.prev_not_tail, idc.prev_head)
down = traversalFactory(lambda x: GetTarget(x, flow=1, calls=0, conditionals=0), lambda x: x + idc.get_item_size(x), idc.next_not_tail, idc.next_head)

# Normal

# FF_CODE      0x00000600  0x00000600  Code
# FF_FLOW      0x00010000  0x00010000  Exec flow from up instruction
# FF_IMMD      0x40000000  0x40000000  Has Immediate value
# MS_VAL       0x000000ff  0x00000000  Stack variable
# o_displ     phrase+addr  Op1        0x30 [[rbp+30h]]  Memory Reg [Base Reg + Index Reg + Displacement]
# o_reg               reg  Op2         0x1 [rcx]  General Register (al,ax,es,ds...)

# First Instruction

# FF_CODE      0x00000600  0x00000600  Code
# FF_REF       0x00001000  0x00001000  has references
# FF_LABL      0x00008000  0x00008000  Has dummy name
# FF_IMMD      0x40000000  0x40000000  Has Immediate value
# FF_1STK      0x0f000000  0x0b000000  Stack variable
# MS_VAL       0x000000ff  0x0b000000  Stack variable
# o_reg               reg  Op1         0x5 [rbp]  General Register (al,ax,es,ds...)
# o_displ     phrase+addr  Op2        0x20 [[rsp+20h]]  Memory Reg [Base Reg + Index Reg + Displacement]

def hasAnyName(F): # becuase idc.hasName() in idc.py 6.8 is broken
    return idc.hasName(F) or (F & idc.FF_LABL)

def makeFunctionFromInstruction(ea=None):
    """
    makeFunctionFromInstruction

    @param ea: linear address
    """
    ea = eax(ea)
    inslen = idaapi.decode_insn(ea)
    if not inslen:
        print("makeFunctionFromInstruction: couldn't decode instruction at {:x}".format(ea))
        return False
    return idc.add_func(ea, ea + inslen)

def myassert(condition, message):
    if not condition:
        print("%s" % (message))

def PrevGap(ea=None):
    ea = eax(ea)
    gap = ea - PrevHead(ea) + InsnLen(PrevHead(ea))
    return gap

def MakePrevHeadSuggestions(ea=None):
    ea = eax(ea)
    gap = PrevGap(ea)
    if gap > 0:
        for start in range(PrevHead(ea) + InsnLen(PrevHead(ea)), ea):
            yield start, diida(start, ea, returnLength=1)

def PrevMakeHead(ea=None):
    ea = eax(ea)
    unlikely = ['db'] + _unlikely_mnems()
    suggestions = [x for x in MakePrevHeadSuggestions(ea)]
    count = 0
    for start, _suggestion in suggestions:
        length, suggestion = _suggestion
        failed = False
        end = start + length
        if end != ea:
            print("bad end: {:x} {}".format(end, suggestion))
            continue
        for mnem in unlikely:
            if re.match(r'\b' + re.escape(mnem) + '\b', suggestion):
                print("rejected unlikely: {}".format(suggestion))
                failed = True
                break
        if failed:
            continue
        print("suggestion: {}".format(suggestion))
        if count == 0:
            print("Easing code {:x} - {:x}".format(start, ea))
            EaseCode(start, ea, forceStart=True)
        count += 1






def smartTraversalFactory(fn1, direction = -1):
    def next(ea = None, noJump = False):
        if ea is None:
            ea = ScreenEA()
        target = fn1(ea)
        idc.create_insn(ea)
        idc.create_insn(target)


        flags = F(ea)
        if direction < 0: # backwards
            if not idc.is_flow(flags) and not idc.isRef(flags) and PrevGap(ea) > 0:
                PrevMakeHead(ea)
                return ea
            if not idc.is_flow(flags) or idc.isRef(flags): # we must^H^H^H^Hmight have jumped here
                myassert(hasAnyName(flags), "No name flag")
                myassert(idc.isRef(flags), "No ref flag")

                #  refs = list(idautils.CodeRefsTo(ea, flow = 0))
                #  assert len(refs) == 1, "More than 1 CodeRefTo: how to follow?"
                #  target = refs[0]

                #  codeRefs = set(idautils.CodeRefsTo(ea, 1))
                #  jmpRefs = set(idautils.CodeRefsTo(ea, 0))
                #  dataRefs = set(idautils.DataRefsTo(ea))
                #  flowRefs = codeRefs - jmpRefs
                #  xrefRefs = jmpRefs | dataRefs

                refs = AllRefsTo(ea)
                callCount = len(refs['callRefs'])
                jumpCount = len(refs['jmpRefs'])
                codeCount = callCount + jumpCount
                dataCount = len(refs['dataRefs'])
                flowCount = len(refs['flowRefs'])
                xrefCount = len(refs['nonFlowRefs'])


                targetList = _.filter(list(refs['jmpRefs']) + list(refs['dataRefs']), lambda x, *a: idc.get_item_size(x) > 2)
                if not targetList:
                    targetList = _.filter(list(refs['jmpRefs']), lambda x, *a: idc.get_item_size(x) > 1)
                myassert(len(targetList) > 0, "Not enough refs")
                #  targetList = _.filter(targetList, lambda x, *a: not IsSameFunc(x, ea))
                targetList2 = []
                targetList2.extend(_.filter(targetList, lambda x, *a: isCall(x)))
                targetList2.extend(_.filter(targetList, lambda x, *a: isJmp(x)))
                targetList2.extend(_.filter(targetList, lambda x, *a: IsCode_(x)))
                targetList2.extend([x for x in targetList if x not in targetList2])
                targetList2 = _.flatten(targetList2)
                #  if not targetList2:
                targetList2.extend(refs['callRefs'])
                targetList2 = _.uniq(targetList2)
                while targetList2:
                    target = targetList2.pop(0)
                    if targetList2:
                        # we still have alternatives
                        if is_same_func(ea, target): continue
                        if max([0] + [is_same_func(ea, _ea) for _ea in xrefs_to(target)]): 
                            continue

                    # skip dead-end jumps
                    if IsFlow(target) or IsRef(target):
                        break


        elif direction > 0: # forwards
            loop = 0
            while loop < 10:
                loop += 1
                fnName = GetFunctionName(ea)
                fnStart = LocByName(fnName)
                fnEnd = FindFuncEnd(ea)
                instruction = GetMnem(ea)
                instructionStart = ItemHead(ea)
                instructionSize = idaapi.get_item_size(instructionStart)
                instructionEnd = instructionStart + instructionSize
                nextInsn = ea + instructionSize
                nextHead = next_head(ea)
                nextAny = NextNotTail(ea)
                hitFnEnd = nextAny == fnEnd
                allRefs = set(idautils.CodeRefsFrom(EA(), 1))
                jmpRefs = set(idautils.CodeRefsFrom(EA(), 0))
                flowRefs = allRefs - jmpRefs

                # Method 1
                if len(flowRefs) == 1 and hitFnEnd:
                    # Expand Function
                    idc.set_func_end(ea, idc.next_not_tail(fnEnd))
                    Wait()
                    continue

                # Method 2
                if fnName and instructionEnd == fnEnd and idc.is_flow(F(nextHead)):
                    # Extend the function end to match flow
                    SetFunctionEnd(fnStart, NextNotTail(nextHead))
                    Wait()
                    continue

                if len(jmpRefs) == 1 and len(flowRefs) == 0:
                    if instruction != 'jmp':
                        raise AdvanceFailure("flow inconsistency, instruction: '%s'" % instruction)

                if len(jmpRefs) == 2:
                    if not re.match(r"^(call|ja|jae|jb|jbe|jc|jcxz|je|jecxz|jg|jge|jl|jle|jna|jnae|jnb|jnbe|jnc|jne|jng|jnge|jnl|jnle|jno|jnp|jns|jnz|jo|jp|jpe|jpo|jrcxz|js)$", instruction):
                        raise AdvanceFailure("unknown condition jump or call: %s" % instruction)

                
                if len(allRefs) == 0 and nextHead != nextAny:
                    innerLoop = 0
                    while innerLoop < 10 and len(set(idautils.CodeRefsFrom(EA(), 1))) == 0 and nextHead != nextAny:
                        # The next bit of non-instruction surely must actually be 
                        # an instruction
                        innerLoop += 1
                        nextHead = next_head(ea)
                        nextAny = NextNotTail(ea)
                        if nextHead == nextAny:
                            break
                        MyMakeUnknown(nextAny, NextNotTail(nextAny) - nextAny, 0)
                        Wait()
                        MakeCodeAndWait(nextAny)
                        continue
                    continue


            ####
            mnem = GetMnem(ea)
            flow = 1
            numRefs = -1
            if mnem == 'call':
                flow = 0
            if mnem == 'jmp':
                loop = 0
                while loop < 10:
                    loop += 1
                    refs = list(idautils.CodeRefsFrom(ea, flow))
                    numRefs = len(refs)
                    if numRefs == 1:
                        break
                    inslen = idaapi.decode_insn(ea)
                    AnalyseArea(ea, ea + inslen)

            if numRefs == 1 and refs[0] != target:
                target = refs[0]
                # Check if there was more than one way here
                refs = list(idautils.CodeRefsTo(target, flow = 0)) # Or should we use flow=1 and include any name.group(0)
                numRefs = len(refs)
                line = ""
                if numRefs > 1:
                    line += ("There were %i xrefs to this location. " % numRefs)
                if idc.is_flow(F(target)):
                    line += "Instruction flow from previous instruction. "
                if line:
                    print(line)
            elif numRefs > 1:
                raise AdvanceFailure("Multiple ways to go from here")
        
        if not noJump:
            Jump(target)
            idc.set_color(target, CIC_ITEM, colorsys_rgb_to_dword(lighten(int_to_rgb(color_here(target)))))
            return pos(target)
        return target
    return next
    
prev = smartTraversalFactory(idc.prev_head, -1)
nextFn = smartTraversalFactory(idc.next_head, 1)

def _next():
    try:
        nextFn()
    except AdvanceFailure as e:
        print("AdvanceFailure: %s" % e)
    
def alpha(byte):
    if byte > 0x40 and byte < 0x5b:
        return True
    if byte > 0x60 and byte < 0x7b:
        return True
    return False


strings = set()
def autoStringBlocks(ea = ScreenEA()):
    skipped = 0
    counter = 0
    while alpha(Byte(ea)) or skipped < 1000:
        valid = alpha(Byte(ea)) and Byte(ea-1) == 0
        if not valid:
            skipped = skipped + 1
        else:
            skipped = 0
            MakeStr(ea, BADADDR)
            counter = counter + 1
            strings.add(GetString(ea))
        ea = ea + 0x10
    print("Count: %i" % counter)

def autoMakeQwords(ea = ScreenEA, count = -1):
    plausibleStart = idaapi.cvar.inf.minEA
    plausibleEnd = idaapi.cvar.inf.maxEA
    if count > 0:
        end = ea + 8 * count
    else:
        end = plausibleEnd

    while ea < end:
        if idc.is_unknown(F(ea)):
            # print("0x%0x: unknown" % ea)
            qword = Qword(ea)
            # print("0x%0x: qword: 0x%0x" % (ea, qword))
            if ea % 8 or ((qword < plausibleStart or qword > plausibleEnd) and qword != 0):
                MakeQword(ea)
                pass
            else:
                MakeQword(ea)
        else:
            print("0x%0x: not unknown, exiting" % ea)
            Jump(ea)
            return
        ea += 8

def makeQwords(ea = ScreenEA(), count = 1):
    end = ea + 8 * count
    while ea < end:
        if not idc.is_code(F(ea)):
            #  qword = Qword(ea)
            MakeQword(ea)
        ea += 8
    Jump(ea)

def colorPopularFunctions():
    k = Kolor()
    for ea in idautils.Functions():
        crefs = list(idautils.CodeRefsTo(ea, 0))
        drefs = list(idautils.DataRefsTo(ea))
        refCount = len(crefs) + len(drefs)
        if (refCount > 1):
            c = Commenter(ea, repeatable = 0)
            c.comments = filter(lambda x: "TEST" not in x, c.comments)
            c.commit()
            c = Commenter(ea, repeatable = 1)
            if len(crefs):
                c.add("[TEST] %i code refs" % len(crefs))
            if len(drefs):
                c.add("[TEST] %i data refs" % len(drefs))
            if (refCount > 10):
                # idaapi.set_item_color(ea, k.get(refCount))
                SetColor(ea, CIC_FUNC, k.get(refCount))
                SetColor(ea, CIC_ITEM, DEFCOLOR)
                for ref in (crefs + drefs):
                    SetColor(ref, CIC_ITEM, k.get(refCount))
            else:
                # idaapi.del_item_color(ea)
                SetColor(ea, CIC_FUNC, DEFCOLOR)
                SetColor(ea, CIC_ITEM, DEFCOLOR)
                for ref in (crefs + drefs):
                    SetColor(ref, CIC_ITEM, DEFCOLOR)

def trace_back_to_label(ea = None, fn1 = PrevNotTail):
    if ea is None:
        ea = idc.get_screen_ea()
    
    try:
        nextEA = ea
        ea = 0
        while nextEA != ea:
            ea = nextEA
            flags = F(ea)
            if not idc.is_flow(flags): break    # we must have jumped here
            elif hasAnyName(flags): break  # stop at label
            elif idc.isRef(flags): break       # stop at xref in

            nextEA = fn1(ea)
            print("nextEA", hex(nextEA))
    except:
        pass
    return ea

def trace_forward(ea = ScreenEA(), fn1 = NextNotTail):
    start = ea
    try:
        nextEA = ea
        ea = 0
        while nextEA != ea:
            ea = nextEA
            flags = F(ea)
            if start != ea and not idc.is_flow(flags): break    # we must have jumped here
            elif not idc.is_head(flags): break
            elif hasAnyName(flags): break  # stop at label
            elif idc.isRef(flags): break       # stop at xref in
            elif idc.is_unknown(flags): break
            else: nextEA = fn1(ea)
    except:
        pass
    return ea

def CheckCode(ea = ScreenEA()):
    mnem = GetMnem(ea)
    if mnem in ['in', 'out']:
        start = trace_back_to_label(ea)
        end = trace_forward(ea)
        print("0x%x: %012x - %012x: bad block" % (ea, start, end))
        MyMakeUnknown(start, end - start, 1)
        return end
    return 0
        

def MakeCodeRepeatedly(ea = ScreenEA()):
    start = ea
    result = MakeCodeAndWait(ea)
    while result:
        AnalyseArea(ea, ea + result)
        codeInvalid = CheckCode(ea)
        if codeInvalid:
            ea = codeInvalid
            while ea < BADADDR:
                f = F(ea)
                if hasAnyName(f): break
                if idc.is_code(f): break
                if idc.isRef(f): break
                ea = NextAddr(ea)
        else:
            ea += result
        f = F(ea)
        if idc.is_code(f): break
        result = MakeCodeAndWait(ea)
    return ea - start

def findbase():
    header = LocByName('__ImageBase')
    if (idaapi.cvar.inf.minEA & 0xffff == 0x1000):
        header = idaapi.cvar.inf.minEA &~ 0xffff
        print("Assuming that header == 0x1000 bytes before start of file, at: 0x%x" % header)
        return header
    if (idaapi.cvar.inf.minEA & 0xffff == 0x0000):
        header = idaapi.cvar.inf.minEA &~ 0xffff
        print("Assuming that header is at the start of file, at: 0x%x" % header)
        return header
    if header < BADADDR:
        print("Obtained header from __ImageBase")
        header = header &~ 0xffff
        return header
    for ref in idautils.Functions():
        gst = GetSegmentAttr(ref, SEGATTR_TYPE)
        # SegName(ea) == ".text"
        if gst == 2:
            gfn = GetFunctionName(ref)
            ss = idc.get_segm_attr(ref, SEGATTR_START)
            header = ss - 0x1000
            print("Found function %s, segment start: 0x%x, assuming exe starts at: 0x%x" % (gfn, ss, header))
            return header
            break
    print("unable to find header, defaulting to start of file")
    header = idaapi.cvar.inf.minEA
    print("Assuming that header is at the start of file, at: 0x%x" % header)
    return header

def autobase(ea, base = 0):
    """
    autobase(ea)
        Calculate specifed linear address, adjusting for rebased addresses
        in either direction.
            
        @param ea: linear address in rebased, offset, or original form.

        @eg: autobase(0x140000000), autobase(0x7FF69E6C9D70), autobase(0x20fed3)

        @notes:requires __ImageBase to be a defined label pointing to the header
               of the dump, eg: HEADER:0000000140000000 __ImageBase     dw 5A4Dh 
               (This should be automatically done by IDA, but sometimes isn't).

        @see-also: asoffset, normalise
    """
    imageBase = findbase()
    if imageBase == BADADDR:
        imageBase = findbase()
    originalImageBase = Qword(imageBase + 0x1a0) # sometimes 1a8?
    if originalImageBase == BADADDR:
        originalImageBase = imageBase
        # we have no originalImageBase, flip it around
        baseDifference = imageBase - 0x140000000
    else:
        baseDifference = imageBase - originalImageBase

    if base:
        return ea - base + imageBase
    
    # This probably won't work so well if you happen to have other segments loaded
    imageLen = idaapi.cvar.inf.maxEA - idaapi.cvar.inf.minEA

    # for GTA5.exe+0x12345 offsets
    if ea < imageLen:
        return ea + imageBase
    #  if ea >= idaapi.cvar.inf.minEA && ea < idaapi.cvar.inf.maxEA: 
        #  return ea + baseDifference

    # Address is inside our image, so translate it outside
    if ea >= imageBase and ea < imageBase + imageLen:
        return ea - baseDifference

    # Address is in the range of our original image, translate to our actual image
    if ea >= originalImageBase and ea < originalImageBase + imageLen:
        return ea + baseDifference

        

def is_sequence(arg):
    """ https://stackoverflow.com/questions/1835018/how-to-check-if-an-object-is-a-list-or-tuple-but-not-string/1835259#1835259
    """
    return (not hasattr(arg, "strip") and
            hasattr(arg, "__getitem__") or
            hasattr(arg, "__iter__"))

#  def overlap(r1, r2):
    #  start = 0
    #  end = 1
    #  """Does the range r1 overlap the range r2?"""
    #  return r1[end] > r2[start] and r2[end] > r1[start]
#  
#  def overlap2(ranges1, ranges2):
    #  len1 = len(A(ranges1))
    #  len2 = len(A(ranges2))
    #  i1 = 0
    #  i2 = 0
    #  loop = 0
    #  try:
        #  while i1 < len1 and i2 < len2:
            #  while loop or not overlap(ranges1[i1], ranges2[i2]):
                #  loop = 0
                #  if ranges1[i1+1][0] < ranges2[i2+1][0]:
                    #  i1 += 1
                #  else:
                    #  i2 += 1
            #  s1 = set(range(ranges1[i1][0], ranges1[i1][1]))
            #  s2 = set(range(ranges2[i2][0], ranges2[i2][1]))
            #  s = list(s1 & s2)
            #  yield (s[0], s[-1]+1, ranges1[i1], ranges2[i2])
#  
            #  loop = 1
    #  except IndexError:
        #  return
#  
#  def overlap3(ranges1, ranges2):
    #  return [x for x in overlap2(ranges1, ranges2)]

def __unpatch_worker(ea):
    ida_bytes.revert_byte(ea)
    return 0

def UnPatch(start, end = None):
    if end is None:
        if is_sequence(start):
            try:
                end = start[1]
                if end is not None:
                    return UnPatch(start[0], end)
            except TypeError:
                return 0
            except ValueError:
                return 0
        end = InsnLen(start) + start

    if end < start and end < 16364:
        end = start + end

    count = 0
    if isinstance(start, (int, long)) and isinstance(end, (int, long)):
        while start < end:
            if start in obfu.combed:
                obfu.combed.clear()
            if idc.get_cmt(start, 0):
                idc.set_cmt(start, '', 0)
            if ida_bytes.revert_byte(start):
                count += 1
            start += 1

        return count

    print("Unexpected type: %s" + type(start))
        #  ida_bytes.visit_patched_bytes(start, end, lambda ea, fpos, org_val, patch_val:
                #  #  print("ida_bytes.visit_patched_bytes: {}, {}, {}, {}".format(ea, fpos, org_val, patch_val))
                #  __unpatch_worker(ea))

def UnpatchFunc(funcea=None):
    """
    UnpatchFunc

    @param funcea: any address in the function
    """
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    def work(funcea):
        for ea1, ea2 in idautils.Chunks(funcea):
            n = UnpatchUntilChunk(ea1)
            if n: print("Unpatched {} bytes".format(n))
            idc.auto_wait()
            EaseCode(ea1, unpatch=1, noExcept=1)
            n = UnPatch(ea1, ea2)
            if n: print("Unpatched {} bytes".format(n))
            n = UnpatchUntilChunk(ea1)
            if n: print("Unpatched {} bytes".format(n))
            EaseCode(ea1, unpatch=1, noExcept=1)
            idc.auto_wait()
            EaseCode(ea1, unpatch=1, noExcept=1)
            idc.auto_wait()
            EaseCode(ea1, unpatch=1, noExcept=1)

    work(funcea)
    ZeroFunction(funcea)
    RemoveAllChunks(funcea)
    try:
        slowtrace2(funcea, modify=0)
    except AdvanceFailure:
        pass
    work(funcea)
    # slowtrace2(funcea, modify=0)
    ZeroFunction(funcea)
    RemoveAllChunks(funcea)
    try:
        slowtrace2(funcea, modify=0)
    except AdvanceFailure:
        pass
    for ea1, ea2 in idautils.Chunks(funcea):
        EaseCode(ea1, noExcept=1)
    work(funcea)
    # slowtrace2(funcea, modify=0)
    ZeroFunction(funcea)
    RemoveAllChunks(funcea)
    try:
        slowtrace2(funcea, modify=0)
    except AdvanceFailure:
        pass

    func = ida_funcs.func_t()
    func.start_ea = funcea
    r = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN)
    if r == ida_funcs.FIND_FUNC_OK:
        print("FIND_FUNC_OK")
    SetFuncStart(funcea, func.start_ea)
    SetFuncEnd(funcea, func.end_ea)
    EaseCode(funcea)

        
patchedBytes=[]

def get_patch_byte(ea, fpos, org_val, patch_val):
    # print("%x, %x, %x, %x" % (ea, fpos, org_val, patch_val))
    patchedBytes.append([ea, org_val])
    #  idaapi.patch_byte(ea, org_value)

def UnPatchAll1():
    patchedBytes=[]
    idaapi.visit_patched_bytes(0, idaapi.BADADDR, get_patch_byte)
    Wait()

def UnPatchAll2():
    for x, y in patchedBytes: 
        if x < 0x146000000:
            idaapi.patch_byte(x, y)

def UnPatchAll():
    UnPatchAll1()
    UnPatchAll2()

@static_vars(patched=[])
def UnpatchPredicate(predicate):
    def UnpatchPredicateCallback(_predicate, ea, fpos, org_val, patch_val):
        if _predicate(ea, fpos, org_val, patch_val):
            UnpatchPredicate.patched.append(ea)

    del UnpatchPredicate.patched[:]
    idaapi.visit_patched_bytes(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea, lambda *a: UnpatchPredicateCallback(predicate, *a))
    print("unpatching {} bytes...".format(len( UnpatchPredicate.patched )))
    for x in UnpatchPredicate.patched:
        ida_bytes.revert_byte(x)

def UnpatchUnused():
    UnpatchPredicate(lambda x, *a: not IsFunc_(x))

def UnpatchUnnamed():
    UnpatchPredicate(lambda x, *a: not HasUserName(GetFuncStart(x)))
    

def UnpatchUn():
    UnpatchPredicate(lambda x, *a: not IsFunc_(x) or not HasUserName(GetFuncStart(x)))


_unpatch_count = 0
def UnPatchAll3Worker(ea, fpos, org_val, patch_val):
    global _unpatch_count
    _unpatch_count += 1
    ida_bytes.revert_byte(ea)

def UnPatchAll3():
    global _unpatch_count
    idaapi.visit_patched_bytes(0, idaapi.BADADDR, UnPatchAll3Worker)
    print("{} bytes unpatched", _unpatch_count)

def ForceFunction2(start, noMakeFunction=False):
    fnName = idc.get_name(start)
    do_return = None
    ea = start
    func = SimpleAttrDict(clone_items(ida_funcs.get_fchunk(start)))
    if func:
        if func.flags & idc.FUNC_TAIL or func.start_ea != start:
            if func.start_ea < start:
                if not idc.set_func_end(func.start_ea, start):
                    print("[warn] idc.set_func_end({:x}, {:x}) failed".format(func.start_ea, start))
                    return False
                else:
                    if debug: print("[info] idc.set_func_end({:x}, {:x}) ok".format(func.start_ea, start))
            else:
                if not remove_func_or_chunk(func):
                    print("[warn] remove_func_or_chunk({:x}) failed".format(func.start_ea))
                    return False
                else:
                    if debug: print("[info] remove_func_or_chunk({:x}) ok".format(func.start_ea))

        else:
            do_return = func.end_ea - func.start_ea

    if get_byte(start) == 0xeb or get_byte(start) == 0xe9:
        insn_len = forceCode(start)[0]
        if insn_len:
            if not func:
                if not idc.add_func(start, start + insn_len):
                    if ida_funcs.get_func(start):
                        print("[info] delayed idc.add_func({:x}, {:x}) ok".format(start, insn_len))
                    else:
                        print("[warn] idc.add_func({:x}, {:x}) failed".format(start, insn_len))
                        raise Exception('Debug')
                else:
                    print("[info] idc.add_func({:x}, {:x}) ok".format(start, insn_len))
                    idc.auto_wait()
            if not IsThunk(start):
                #  print("[info] 1611: {}".format(start))
                # idc.add_func(start, insn_len)
                if not MakeThunk(start):
                    print("[warn] MakeThunk({:x}) failed".format(start))
                else:
                    if debug: print("[info] MakeThunk({:x}) ok".format(start))
        return insn_len

    if do_return is not None:
        return do_return

    insn_len = -1
    while not IsFuncHead(start) and not ida_funcs.add_func(start) and insn_len and ea - start < 1024:
        insn_len = forceCode(ea)[0]
        ea += insn_len

    if IsFuncHead(start):
        if fnName:
            LabelAddressPlus(start, fnName)
        return ea - start

    return False

def unpatch_func(ea):
    ea = GetFuncStart(ea)
    last_chunks = GetChunkAddresses(ea)
    _unpatch_count = 0
    for r in range(100):
        chunks = GetChunkAddresses(ea)
        RemoveAllChunks(ea)
        idc.del_func(ea)
        for x, y in chunks:
            ida_auto.revert_ida_decisions(x, y)
        for x, y in chunks:
            MyMakeUnknown(x, y - x, DOUNK_EXPAND | DOUNK_NOTRUNC)
        for x, y in chunks:
            z = x
            end = y
            while ida_bytes.get_original_qword(z) != Qword(z) or z < end:
                UnPatch(z, z + 4)
                _unpatch_count += 1
                z += 4
        cend = dict()
        if False:
            for x, y in chunks:
                z2 = EndOfContig(x)
                happy, start, end, trim = forceCode(x, z)
                print("unpatching chunk {:x} - {:x} z:{:x} z2:{:x} end:{:x} trim:{:x}".format(x, y, z, z2, end, trim))
                # r = obfu.combEx(x, 65535, oneChunk=True)
                cend[x] = z2

            for x, y in cend.items():
                if not IsFunc_(x):
                    EaseCode(x, forceStartIfHead=1, noExcept=1)
                    ida_auto.auto_apply_tail(x, ea)
                    idc.append_func_tail(ea, x, y)
                    idc.auto_wait()
            #  print("forcingCode {:x} - {:x}".format(x, y))
            #  forceCode(x, y, trim=True)
        idc.auto_wait()
        idc.add_func(ea)
        idc.auto_wait()

        # ida_funcs.reanalyze_function(ea)
        break
    #  for x, y in chunks: ida_auto.plan_and_wait(x, cend[x])
    #  ida_auto.auto_make_proc(ea)
    #  ida_auto.auto_wait()
    if debug: printi("unpatched {} bytes".format(_unpatch_count))

def unpatch_func2(funcea=None, unpatch=True):
    """
    unpatch_func2

    @param funcea: any address in the function
    """
    if isinstance(funcea, list):
        return [unpatch_funcs2(x, unpatch=unpatch) for x in funcea]
    funcea = eax(funcea)
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        funcea = func.start_ea

    ea = funcea
    last_chunks = [x[0] for x in split_chunks(idautils.Chunks(ea)) if len(GetChunkOwners(x[0], includeOwner=1)) == 1]
    func_name = idc.get_func_name(ea)
    chunks = genAsList(idautils.Chunks(ea))
    _unpatch_count = 0

    RemoveAllChunks(ea)
    idc.del_func(ea)
    for start, end in chunks:
        ida_auto.revert_ida_decisions(start, end)
        if unpatch:
            while start < end:
                if ida_bytes.get_original_qword(start) != idc.get_qword(start):
                    _unpatch_count += UnPatch(start, min(end, start + 4))
                start += 4

    #  EaseCode(ea)
    idc.add_func(ea)
    LabelAddressPlus(ea, func_name)
    for start in last_chunks:
        if start != ea:
            end = EaseCode(start, forceStart=1, noExcept=1)
            if isinstance(end, AdvanceFailure):
                msg = "EaseCode failed from {:x}".format(start)
                raise AdvanceFailure(msg)
            ida_auto.plan_and_wait(start, end)
            #  ida_auto.plan_range(start, end)  #
            # dprint("[debug] start, end")
            #  print("[debug] start:{:x}, end:{:x}".format(start, end))
            
            if isinstance(end, integer_types):
                #  ida_auto.auto_apply_tail(start, ea)
                if not IsChunk(start) and not IsFunc_(start):
                    idc.append_func_tail(ea, start, end)
                #  idc.auto_wait()
        #  print("forcingCode {:x} - {:x}".format(x, y))
        #  forceCode(x, y, trim=True)
    #  idc.auto_wait()

    # ida_funcs.reanalyze_function(ea)
    #  for x, y in chunks: ida_auto.plan_and_wait(x, cend[x])
    #  ida_auto.auto_make_proc(ea)
    #  ida_auto.auto_wait()
    idc.auto_wait()
    #  print("EaseCode(0x{:x})".format(ea))
    try:
        end = EaseCode(ea)
    except AdvanceFailure:
        GetDisasm(ea)
        end = EaseCode(ea)
    #  [GetDisasm(x) for x in idautils.Heads(ea, end)]
    ea1 = ea
    ea2 = end

    ida_auto.plan_and_wait(ea1, ea2),
    #  print("ida_auto results: {}".format([
        #  ida_auto.revert_ida_decisions(ea1, ea2), #
        #  [ida_auto.auto_recreate_insn(x) for x in Heads(ea1, ea2)],
        #  [ida_auto.plan_ea(x) for x in Heads(ea1, ea2)], #
        #  ida_auto.auto_wait_range(ea1, ea2),
        #  ida_auto.plan_and_wait(ea1, ea2, True),
        #  ida_auto.plan_range(ea1, ea2),  #
        #  ida_auto.auto_wait()
    #  ]))
    idc.auto_wait()
    #  end = EaseCode(ea)
    if _unpatch_count:
        print("[unpatch_funcs2] unpatched {} bytes".format(_unpatch_count))
    return _unpatch_count


patchedBytes = []
def RecordPatchedByte(ea, fpos, org_val, patch_val):
    # print("%x, %x, %x, %x" % (ea, fpos, org_val, patch_val))
    patchedBytes.append([ea - 0x140000000, patch_val])
    #  idaapi.patch_byte(ea, org_value)

def RecordPatches1(ranges):
    global patchedBytes
    del patchedBytes[:]
    #  patchedBytes=[]
    #  for i in ranges: idaapi.visit_patched_bytes(i[0] + 0x140000000, i[1] + i[0] + 0x140000000, RecordPatchedByte)
    if ranges:
        for start, end in ranges:
            idaapi.visit_patched_bytes(start, end, RecordPatchedByte)
    else:
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, RecordPatchedByte)

    n = 0
    c = dict()
    lastEa = 0
    startEa = 0
    for i in patchedBytes:
        a, b = i
        if a == lastEa + 1:
            c[startEa].append(b)
        else:
            startEa = a
            c[a] = [b]
        lastEa = a

    return c

def bestOf3(container, iteratee=None):
    if iteratee is None:
        iteratee = lambda x, *a: x
    counted = _.countBy(container, iteratee)
    #  print(counted)
    # {0x1: 0x1, 0x2: 0x2, 0x3: 0x1}
    q = _.reverse(_.sortBy(_.map(counted, lambda count, ea, *a: {'count': count, 'ea': ea}), 'count'))
    argc = len(q)
    if argc == 1:
        return q[0]['ea']
    if argc > 1:
        if q[0]['count'] > q[1]['count'] / 2:
            return q[0]['ea']
    print("bestOf3: undecided: {}".format(q))

def static_vars(**kwargs):
    def decorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate

@static_vars(loc=0)
def get_version_mb():
    if get_version_mb.loc:
        return mb(get_version_mb.loc)

    get_version_mb.loc = bestOf3([x.ea() for x in [
        ProtectScan("48 89 6c 24 10 48 89 7c 24 18 41 57 48 83 ec 60 48").add(-5),
        ProtectScan("75 0b 88 05 ?? ?? ?? ?? e9 ?? ?? ?? ?? b2").add(-58),
        ProtectScan("48 85 c0 0f 84 ?? ?? ?? ?? 4c 8d 3d").add(-88),
        ProtectScan("80 38 00 0f 84 ?? ?? ?? ?? 4c").add(-113),
        ProtectScan("48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 20 e8 ?? ?? ?? ?? 85 c0 75 47").add(-142),
        ProtectScan("e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 4c 8b c5 48").add(-168),
        ProtectScan("48 83 fb 1f").add(-193),
        ProtectScan("42 88 04 3b").add(-220),
        ProtectScan("48 89 6c 24 10 48 89 7c 24 18 41 57 48 83 ec 60 48").add(-5),
        ProtectScan("e8 ?? ?? ?? ?? 48 8b f8 48 85 c0 75 0b 88").add(-47),
        ProtectScan("48 85 c0 0f 84 ?? ?? ?? ?? 4c 8d 3d").add(-88),
        ProtectScan("48 8d 15 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 20 e8 ?? ?? ?? ?? 85 c0 75 47").add(-127),
        ProtectScan("48 8b cf e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 4c 8b c5").add(-165),
        ProtectScan("e8 ?? ?? ?? ?? 84 c0 75 06 80 3c").add(-202),
        ProtectScan("48 89 6c 24 10 48 89 7c 24 18 41 57 48 83 ec 60 48").add(-5),
        ProtectScan("48 85 c0 75 0b 88").add(-55),
        ProtectScan("80 38 23 0f 84 ?? ?? ?? ?? 80").add(-104),
        ProtectScan("e8 ?? ?? ?? ?? 85 c0 75 47 b2").add(-154),
        ProtectScan("84 c0 75 06 80 3c").add(-207)
    ] if not x.errored]) # , lambda x, *a: x.ea() if isinstance(x, memo) else int(str(x), 16))
    return mb(get_version_mb.loc)

def set_version_globals():
    mb(get_version_mb()).add(7).add(0x37).rip(4).name("g_version_number")
    mb(get_version_mb()).add(7).add(0x4d).rip(4).name("g_version_number")
    mb(get_version_mb()).add(7).add(0x5d).rip(4).name("g_short_version_number")
    mb(get_version_mb()).add(7).add(0x105).rip(4).name("g_online_version_number")
    #  mb(get_version_mb()).add(7).add(0x13a).rip(4).name("g_install_version_number")
    #  mb(get_version_mb()).add(7).add(0x16f).rip(4).name("g_savegame_version_number")
    #  mb(get_version_mb()).add(7).add(0x1a4).rip(4).name("g_replay_version_number")

def get_version_globals():
    def show_string(name, memptr):
        if memptr.valid():
            print("{:32} {}".format(name, memptr.str()))
        else:
            print("{:32} {} (invalid)".format(name, memptr.str()))
    show_string("g_version_number", mb(get_version_mb()).add(7).add(0x37).rip(4))
    show_string("g_version_number", mb(get_version_mb()).add(7).add(0x4d).rip(4))
    show_string("g_short_version_number", mb(get_version_mb()).add(7).add(0x5d).rip(4))
    show_string("g_online_version_number", mb(get_version_mb()).add(7).add(0x105).rip(4))
    #  show_string("g_install_version_number", mb(get_version_mb()).add(7).add(0x13a).rip(4))
    #  show_string("g_savegame_version_number", mb(get_version_mb()).add(7).add(0x16f).rip(4))
    #  show_string("g_replay_version_number", mb(get_version_mb()).add(7).add(0x1a4).rip(4))


def get_build_version():
    r = get_version_mb()
    if r and not r.errored:
        g_build_dev_ng_live = r.add(0x3e).rip(4)
        g_build = r.add(0x64).rip(4)
        g_gtav_x64_final_build_dev_ng_live = r.add(0x1d4).rip(4)
        return g_build.str() # , g_gtav_x64_final_build_dev_ng_live.str(), g_build_dev_ng_live.str()]
        #  return asString(idc.get_strlit_contents(g_build, 32, idc.STRTYPE_C))
    #  ea = ProtectScan("24 08 57 48 81 ec b0 00 00 00 83").add(0x104 - 0x4e).rip(4).str() \
      #  or mb(get_version_mb()).add(7).add(0x5d).rip(4).str()
    #  return asString(idc.get_strlit_contents(ea, 32, idc.STRTYPE_C))

def get_online_version():
    return ProtectScan("24 08 57 48 81 ec b0 00 00 00 83").add(0x104).rip(4).str() \
      or get_version_mb().add(7).add(0x105).rip(4).str()

def is_steam():
    execfile('winpe')
    pe = WinPE(64)
    pdb = os.path.basename(pe.dirs[5].data.entries[0].data.entries[0].data.PdbFileName)
    print("pdb: {}".format(pdb))
    return 'steam' in pdb

def constant_factory(value):
    return itertools.repeat(value).next

def get_stripped_lines(file_name):
    result = list()

    with open(file_name, 'r') as fr:
        for line in fr:
            s = line.strip()
            if len(s) == 0:
                continue
            result.append(s)
            if False: # this is fine for DeHashing, but it screws up other functionality
                result.append(s + "POOL")
                result.append(s + "LIST")
                if s[0] == 'C':
                    result.append(s[1:len(s)])

    #  return list(map(lambda x: x.strip(), open(file_name, 'r')))
    return result

def get_seperated_lines(file_name, sep):
    for line in get_stripped_lines(file_name):
        yield line.split(sep)

def xenprocess(s):
    s = s.replace('??','\n\n')
    return s
    


def infamous():
    keys = []
    result = []
    for i, v in enumerate(get_seperated_lines(process_cygwin_symlinks('/tmp/.sfinktah.posts.processed.txt'), '\t')):
        if i == 0:
            keys = v
        else:
            values = _.zipObject(keys, v)
            result.append(values)
            result['message'] = xenprocess(result['message'])
            
    return result


def asea(v):
    """
    As EA (as address)
    will run `v` through idc.get_name_simple if it is a string
    """
    if isinstance(v, str):
        ea = idc.get_name_ea_simple(v)
        if ea == BADADDR:
            raise Exception("%s was not a location" % ea)
        print(v, hex(ea))
        return ea
    return v

def xor_cipher(cipher, key, length):
    cipher = asea(cipher)
    key = asea(key)
    length = asea(length)
    result = ""
    for i in range(idc.get_wide_dword(length)):
        result += chr(idc.get_wide_byte(cipher + i) ^ idc.get_wide_byte(key + i))
    return result

class SavePatches(object):
    # Copyright 2017 Orwellophile LLC. MIT License.

    def __init__(self):
        #  self.e = collections.defaultdict(constant_factory(list))
        self.comments = dict()
        self.e = list() 
        self.d = collections.defaultdict(constant_factory(0))

    def add(self, ea, replaceList, patternComment):
        return
        self.e.append([ea, replaceList, patternComment])

    def patch_callback(self, ea, fpos, org_val, patch_val):
        c = Commenter(ea, "line")
        if c.comments:
            self.comments[ea] = c.comments[0]
        self.d[ea] = patch_val
        length = len(self.d)
        if not (length % 10000):
            print("%i patches..." % length)

    def refresh(self):
        self.d = collections.defaultdict(constant_factory(0))
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, self.patch_callback)
        Wait()

    def load(self, fn):
        try:
            with open(fn, 'r') as f:
                self.d = json.load(f)
        except IOError:
            print("file not found or some such")

    def savepython(self, fn):
        with open(fn, 'w') as f:
            f.write("""
def PatchBytes(ea, replaceList):
    for i in range(len(replaceList)):
        idaapi.patch_byte(ea+i, replaceList[i])

def hex_byte_as_pattern_int(string):
    return -1 if '?' in string else int(string, 16)

def hex_string_as_list(string):
    result = []
    result.extend([hex_byte_as_pattern_int(item) for item in string.split(" ")])
    return result

            """)
            for i in self.c.items():
                comment = ""
                if i[0] in self.comments:
                    comment = ", \"%s\"" % self.comments[i[0]]
                f.write("PatchBytes(0x%x, hex_string_as_list(\"%s\")%s)\n" % (i[0], listAsHex(i[1]), comment))

    def savee(self, fn):
        try:
            with open(fn, 'w') as f:
                json.dump(self.e, f)
        except IOError:
            print("file not writable or some such")
    def savejson(self, fn):
        try:
            with open(fn, 'w') as f:
                try:
                    json.dump(self.c, f)
                except:
                    json.dump(self.d, f)
        except IOError:
            print("file not writable or some such")

    def apply(self):
        for i in self.d.items():
            idaapi.patch_byte(long(i[0]), i[1])

    def sort(self):
        self.o = collections.OrderedDict(sorted(self.d.items(), key=lambda t: t[0]))

    def ranger(self):
        self.sort()
        self.r = self.GenericRanger(self.o.keys())

    def chunk(self):
        self.ranger()
        self.c = collections.defaultdict(list)
        for [ea, length] in self.r:
            bytes = []
            for i in range(length):
                bytes.append(self.d[ea + i])
            self.c[ea] = bytes
                
    
    ## The Generic Ranger

    def GenericRanger(self, genericRange):
        def lengthify(group):
            length = 1 if not 'last' in group else group['last'] - group['start'] + 1
            return [group['start'], length]

        last = 0
        start = 0
        result = []
        group = {}

        ## We cannot trust fool users to pre-sort the dates
        #  genericRange.sort()

        for n in genericRange:
            if n == last:
                continue

            if last and n == last + 1:
                start = start if start else last
                last = n
                continue

            if start:
                if last - start > 0:
                    group['last'] = last
                    start = 0
                else:
                    start = 0
                    raise "This point never reached"

            if len(group):
                result.append(group)

            group = { 'start': n }
            last = n

        ## If we were counting out a range, then it's over now.
        if start:
            group['last'] = last
        result.append(group)

        return [lengthify(g) for g in result]

# int file_put_contents ( string $filename , mixed $data [, int $flags = 0 [, resource $context ]] )
# flags: FILE_APPEND
def file_put_json(fn, data, flags = None):
    try:
        with open(fn, 'w') as f:
            json.dump(data, f)
    except IOError:
        print("file not writable or some such")

def mark_start():
    #  print("mark_start")
    idc.put_bookmark(idc.get_screen_ea(), 0, 0, 0, 18, 'mark_start')

def mark_end():
    #  print("mark_end")
    idc.put_bookmark(idc.get_screen_ea() + idc.get_item_size(idc.get_screen_ea()), 0, 0, 0, 19, 'mark_end')

def make_store_bookmark_fn(i):
    def func():
        #  print("stored 0x{:x} in bookmark {}".format(idc.here(), i))
        idc.put_bookmark(idc.here(), 0, 0, 0, i, 'mark_end')
    return func

def make_goto_bookmark_fn(i):
    def func():
        ea = idc.get_bookmark(i)
        if ea == idc.BADADDR:
            ask_yn(ASKBTN_BTN1, "bookmark {} is undefined".format(i))
            #  print("bookmark {} is undefined".format(i))
            return
        #  print("jumping to 0x{:x} (bookmark {})".format(ea, i))
        idc.jumpto(ea)
    return func

def ms():
    return idc.get_bookmark(18)

def me():
    return idc.get_bookmark(19)

def ml():
    return me() - ms()


def graph_results(results, links):
    import pydot.src.pydot as pydot
    def safe_name(name, second = None):
        if second is not None:
            return safe_name(name) + '-' + safe_name(second)
        return hex(eax(name))
        # return re.sub(r'[^a-zA-Z]', '_', get_name_by_any(name)).strip('_')

    def label(ea=None):
        """
        make vizgraph label for address

        @param ea: linear address
        """
        ea = eax(ea)

        fnLoc = hex(ea)
        fnHeadName = "<b>{}</b>".format(GetFuncName(ea)) if IsFuncHead(ea) else ''
        fnName = GetFuncName(ea) if not fnHeadName else ''
        fnLocName = idc.get_name(ea) if not fnHeadName else ''
        br = "<br />"
        heading = br.join([x for x in [fnHeadName, fnLoc, fnLocName, fnName] if x])
        #  br = "<br>" if fnName else ""
        response = "<{}{}{}>".format(heading, br, diida(ea))
        return response

    def fill(ea=None):
        """
        make vizgraph fillcolor for address

        @param ea: linear address
        """
        ea = eax(ea)

        fnLoc = hex(ea)
        fnHeadName = "<b>{}</b>".format(GetFuncName(ea)) if IsFuncHead(ea) else ''
        fnName = GetFuncName(ea) if not fnHeadName else ''
        fnLocName = idc.get_name(ea) if not fnHeadName else ''
        disasm = diida(ea)
        fnStart = '; '.join([str(x).lower() for x in der(ea)][0:6])

        isRealFunc = None
        canInclude = False

        c = Commenter(ea, "line")
        ct = Commenter(ea, "line")
        callRefs = list([x for x in list(CallRefsTo(ea)) if idc.get_segm_name(x) == '.text' and IsFunc_(x) and not idc.get_func_name(x).startswith("do_") and GetInsnLen(x) > 2])
        jmpRefs = list([x for x in list(JmpRefsTo(ea)) if idc.get_segm_name(x) == '.text'])

        if c.exists("[ALLOW JMP]") or ct.exists("[ALLOW JMP]"): 
            if debug: sprint("allow jmp")
            isRealFunc = False
        elif isSegmentInXrefsTo(ea, '.pdata') and get_pdata_fnStart(ea) == ea:
            #  if debug: 
            if debug: sprint("0x%x: legitimate function (in .pdata): 0x%x: %s" % (ea, ea, fnName))
            isRealFunc = True
            #  canInclude = True
        #  elif isSameFunc:
            #  isRealFunc = False
        #  elif GetChunkStart(fnLoc) != BADADDR and GetChunkStart(fnLoc) != GetFuncStart(fnLoc):
            #  # dprint("debug GetChunkStart(fnLoc) != BADADDR and GetChunkStart(fnLoc) != GetFuncStart(fnLoc)")
            #  if debug: sprint("GetChunkStart(fnLoc) != BADADDR and GetChunkStart(fnLoc) != GetFuncStart(fnLoc)")
            #  
            #  isRealFunc = True
        elif fnName.startswith("Arxan") and fnHeadName:
            # dprint("arxan ")
            if debug: sprint("arxan")
            isRealFunc = True
        elif c.exists("[DENY JMP]") or ct.exists("[DENY JMP]"):
            isRealFunc = True
            # dprint("deny jmp ")
            if debug: sprint("[DENY JMP]")
        elif isSegmentInXrefsTo(ea, '.rdata') and idc.get_segm_name(ea) != '.rdata':
            if debug: sprint("0x%x: legitimate function (in .rdata): 0x%x: %s" % (ea, ea, fnName))
            isRealFunc = True
        elif len(callRefs) > 0:
            if debug: sprint("0x%x: legitimate function (callRefs): 0x%x: %s" % (ea, ea, fnName))
            isRealFunc = True
        elif fnHeadName:
            isRealFunc = True
        elif isRealFunc is None:
            good_patterns = [r'sub rsp, ', r'push rbp', r'lea rbp, \[rsp']
            found = 0.0
            for pattern in good_patterns:
                if re.search(pattern, fnStart):
                    isRealFunc = True
                    found += 0.1

            return "{} {} {}".format(found * 0.5, found, 1.0)

        if isRealFunc:
            return "0.2 0.4 1"
        return "#eeeeee"


    dot_string = """digraph pprev {
        graph [
            bgcolor="#eeeeee",
            
            orientation=TD,
            newrank=true,
            compound=false,
            nodesep=0.1,
            overlap=true,
            // ranksep=0.1,
            splines=false,
            nodesep=0.1,
            ranksep=0.2
        ];
        node [fixedsize=false,
            fontname="Roboto"
            fontsize=12,
            height=1,
            shape=box,
            style="filled,setlinewidth(6)",
            width=2.2
        ];
        edge [arrowhead=none,
            arrowsize=0.5,
            style=invis,
            labelfontname="Roboto",
            weight=1
        ];
    }"""

    nodes = set()
    edges = set()
    graphs = pydot.graph_from_dot_data(dot_string)
    graph = graphs[0]
    #  graph = pydot.Dot('pprev',
            #  graph_type='digraph',
            #  bgcolor='#dddddd',
            #  fontname="Roboto",
            #  shape='box',
            #  compound=True,
            #  #  node = { 'shape':"box", 'fillcolor':"#eeeeee", 'fontname':"Roboto", 'fontsize':14 },
            #  orientation='TD',
            #  scale=1.3,
            #  sep=0.1,
            #  splines=True,
            #  overlap=False,
    #  )
    subgraph = pydot.Subgraph('cluster_0', label="ArxanCheck", color='lightgrey', bgcolor='#cccccc')
    subgraph2 = pydot.Subgraph('cluster_1', label="ArxanBalance", color='darkgrey', bgcolor='#bbbbbb')
    for result in results:
        #  for lhs, rhs in stutter_chunk(_.reverse(result), 2, 1):
            # dprint("[debug] lhs, rhs")
            #  print("[debug] lhs:{}, rhs:{}".format(lhs, rhs))
        pp(result)
        if result:
            lhs, rhs, insns = result
            if GetFuncName(lhs).startswith('ArxanCheck'):
                target = subgraph
            elif GetFuncName(lhs).startswith('ArxanBalance'):
                target = subgraph2
            else:
                target = graph
            for node in (rhs,):
                if node not in nodes:
                    nodes.add(node)
                    target.add_node(pydot.Node(safe_name(node), xlabel=safe_name(node), label="\n".join(insns) + " ", shape='box', fillcolor=fill(node), style='filled', fontname='Roboto'))
                else:
                    print("duplicate node: {}".format(node))
            if rhs is not None and lhs != rhs:
                #  safe_edge_name = safe_name(lhs, rhs)
                #  #  dprint("[debug] safe_edge_name")
                #  print("[debug] safe_edge_name:{}".format(safe_edge_name))
                
                if safe_name(lhs, rhs) not in edges:
                    target.add_edge(pydot.Edge(safe_name(lhs), safe_name(rhs), dir="back"))
                    edges.add(safe_name(lhs, rhs))

    for link in links:
        rhs, lhs = link
        if lhs != rhs and safe_name(lhs, rhs) not in edges:
            target.add_edge(pydot.Edge(safe_name(lhs), safe_name(rhs), dir="back", style="dashed"))
            edges.add(safe_name(lhs, rhs))

    graph.add_subgraph(subgraph)
    graph.add_subgraph(subgraph2)
    #  print(graph.to_string())
    #  try:
    print(graph.write_svg('pprev.svg'))
    #  except AssertionError as e:
        #  print(graph.to_string())
        #  print("Exception: {}".format(e))
    import subprocess
    subprocess.getstatusoutput('start pprev.svg')

class prevpath(object):
    """Pathing for `pprev`"""

    def __init__(self, addr, depth=0, paths=[], visited=set(), prev=None, links=[], data=False, extra=None):
        self.start_depth = depth
        self.start_ea = addr
        self.data = data
        self.depth = depth
        self.paths = paths
        self.visited = visited
        self.links = links
        self.prev = prev
        self.terminated = 0
        self.history = [addr]
        self.extra = extra
        self.addr = addr
        self.insn_history = []
        self.add_history()

    @property
    def viable(self):
        """ is this path still viable? """
        return not self.terminated

    @property
    def ea(self):
        """ returns current address """
        return self.addr

    @ea.setter
    def ea(self, value):
        """ set new addr and do housekeeping """
        
        self.addr = value
        self.visited.add(value)
        self.history.append(value)
        self.add_history()
        self.depth += 1
        return self.addr

    def add_history(self):
        ea = self.addr
        if idc.get_segm_name(ea) == '.pdata':
            value = '.pdata'
        elif idc.get_segm_name(ea) == '.rdata':
            if IsOff0(ea): value = idc.get_name(idc.get_qword(ea))
            else:
                value = '.rdata'
        else:
            value = diida(ea)
        self.insn_history.append(value)

    def advance(self):
        """ returns next address or None """
        try:
            self._next()
            return self.addr 
        except StopIteration:
            return None
    
    def __len__(self):
        return self.depth - self.start_depth 

    def __iter__(self):
        """Iterator interface. (Untested)."""
        return self

    def __next__(self):
        return self._next().ea

    def _next(self):
        """Returns the next xref

        If there's more than one, add the others to `paths`"""
        
        xrefs = [x for x in xrefs_to_ex(self.ea, flow=1) if x.frm not in self.visited]
        #  xrefs = [x for x in idautils.CodeRefsTo( self.addr , 1) if x not in self.visited]
        if not self.data:
            xrefs = [x for x in xrefs if not x.type.startswith('dr_')]
            #  xrefs.extend([x for x in idautils.DataRefsTo(self.addr) if x not in self.visited])
        #  print("xrefs: {}".format(hex(xrefs)))
        if not xrefs:
            #  print("terminated: {:x}".format(self.ea))
            self.terminated = 'deadend'
            #  self.links.append([self.start_ea, self.addr])
            raise StopIteration
        # this should be the flow ref (if such exists)
        if len(xrefs) == 1:
            n = xrefs.pop()
            self.ea = n.frm
            self.extra = n
            return self

            #  [debug] self.start_ea:143f8e2e2, self.addr:143b53c80, x.frm:143d29d6f, x.to:143b53c80
            #  [debug] self.start_ea:143f8e2e2, self.addr:143b53c80, x.frm:140cb2f00, x.to:143b53c80
            #  [debug] self.start_ea:140cb2f00, self.addr:140cb2f00, x.frm:143b0f718, x.to:140cb2f00
            #  [debug] self.start_ea:140cb2f00, self.addr:140cb2f00, x.frm:143bd5512, x.to:140cb2f00
            #  [debug] self.start_ea:140cb2f00, self.addr:140cb2f00, x.frm:143b0f718, x.to:140cb2f00
            #  [debug] self.start_ea:140cb2f00, self.addr:140cb2f00, x.frm:143bd5512, x.to:140cb2f00
            #  [debug] self.start_ea:143d29d6f, self.addr:143ccd547, x.frm:143dd9d0a, x.to:143ccd547
            #  [debug] self.start_ea:143d29d6f, self.addr:143ccd547, x.frm:143dd9cb5, x.to:143ccd547
            #  [debug] self.start_ea:143b0f718, self.addr:142ed9b1c, x.frm:14178b38f, x.to:142ed9b1c
            #  [debug] self.start_ea:143b0f718, self.addr:142ed9b1c, x.frm:142fd3803, x.to:142ed9b1c
            #  [debug] self.start_ea:14178b38f, self.addr:14178b388, x.frm:143d0f12c, x.to:14178b388
            #  [debug] self.start_ea:14178b38f, self.addr:14178b388, x.frm:143c42d3a, x.to:14178b388
            #  [debug] self.start_ea:143c42d3a, self.addr:143d93d46, x.frm:140a33807, x.to:143d93d46
            #  [debug] self.start_ea:143c42d3a, self.addr:143d93d46, x.frm:1417a5445, x.to:143d93d46

        #  self.links.append([self.start_ea, self.addr])
        self.terminated = 'branch'
        for x in xrefs:
            # dprint("[debug] self.addr, x.from, x.to")
            #  print("[debug] self.start_ea:{:x}, self.addr:{:x}, x.frm:{:x}, x.to:{:x}".format(self.start_ea, self.addr, x.frm, x.to))
            
            self.links.append([x.frm, x.to])
            self.paths.extend([self.__class__(x.frm, self.depth, self.paths, self.visited, self, self.links, self.data, x) for x in xrefs])
        raise StopIteration



def pprev(ea=None, data=0, stop=None, depth=0, show=0):
    results = []

    def history(path):
        return path.start_ea, path.ea, path.insn_history
        history = []
        _path = path
        while _path:
            _history = _path.history.copy()
            _history.reverse()
            history.append(_history)
            _path = _path.prev
        # history.reverse()
        # dprint("[history] history")
        #  print("[history] history:{}".format(history))
        
        return history
        # return _.flatten(history)
    
    start_ea = ea = eax(ea)
    visited = set([ea])
    links = []
    paths = []
    paths.append(prevpath(ea, depth, paths, visited, None, links, data=data))
    deadpaths = []

    while len(paths):
        #  print("viable {}/dead {}".format(len(paths), len(deadpaths)))
        # for path in paths:
        path = paths.pop(0)
        if path.viable:
            ea = path.advance()
            if ea is None:
                deadpaths.append(path)
                #  paths.remove(path)
            elif stop and callable(stop) and stop(ea):
                if show:
                    results.append(history(path))
                    graph_results(results)
                    #  print("path: {}".format(hex(history(path))))
                return ea
            if ea:
                if idc.print_insn_mnem(ea) == 'call' and GetTarget(ea) in visited:
                    print("call:  {:3} {:x} {:32} {}".format(path.depth, path.ea, GetFuncName(path.ea), diida(path.ea)))
                if isSegmentInXrefsTo(ea, '.pdata') and get_pdata_fnStart(ea) == ea:
                    print("pdata: {:3} {:x} {:32} {}".format(path.depth, path.ea, GetFuncName(path.ea), diida(path.ea)))
                paths.append(path)

    for path in deadpaths:
        # if not ida_funcs.is_same_func(path.ea, start_ea):
        if path.terminated == 'branch':
            print("depth: {:3} {:x} {:16} {:20} {}".format(path.depth, path.ea, GetFuncName(path.ea), diida(path.start_ea), get_name_or_hex(path.history[1]) if len(path.history) > 1 else ''))
            if show:
                results.append(history(path))
                #  for h in history(path):
                    #  results.append(h)
                #  print("path: {}".format(" -> ".join([hex(x) for x in history(path)])))
            
    if show:
        graph_results(results, links)
    else:
        return results

if 'HELPER_HOTKEYS' in globals():
    for hotkey in HELPER_HOTKEYS: HELPER_HOTKEYS._remove(hotkey)
    HELPER_HOTKEYS.clear()


    # or type('HELPER_HOTKEYS') != "<class 'MyHotkeys'>":
HELPER_HOTKEYS = MyHotkeys()
for i in range(10):
    HELPER_HOTKEYS.append(MyHotkey("Shift-{}".format(i), make_store_bookmark_fn(i)))
    HELPER_HOTKEYS.append(MyHotkey("{}".format(i), make_goto_bookmark_fn(i)))
HELPER_HOTKEYS.append(MyHotkey("Alt-R", fake_cli_factory("retrace(adjustStack=1)")))
HELPER_HOTKEYS.append(MyHotkey("Alt-Z", lambda: ZeroFunction(GetFuncStart(here()))))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-C", chunk_adder))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-D", sig_maker_data))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-N", make_nops))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-O", make_offset))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-S", sig_maker))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-Alt-U", hotkey_unpatch))
HELPER_HOTKEYS.append(MyHotkey("Alt-P", fake_cli_factory("hotkey_patch()")))
HELPER_HOTKEYS.append(MyHotkey("J", lambda: hotkey_switch_jumptype(shift=0)))
HELPER_HOTKEYS.append(MyHotkey("Ctrl-J", lambda: hotkey_skipjumps()))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-F", makeFunctionFromInstruction))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-J", down))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-K", up))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-N", nextFn))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-O", lambda *a: obfu._patch(here())))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-P", prev))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-U", hotkey_unchunk))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-[", mark_start))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-]", mark_end))
HELPER_HOTKEYS.append(MyHotkey("Shift-Ctrl-Alt-U", UnpatchUn))
HELPER_HOTKEYS.append(MyHotkey("Shift-Ctrl-J", hotkey_join_to_parent))
HELPER_HOTKEYS.append(MyHotkey("Shift-J", lambda: hotkey_switch_jumptype(shift=1)))
HELPER_HOTKEYS.append(MyHotkey("Shift-Alt-E", hotkey_edit_nasm))


#  
#  for ea in l:
    #  if retrace(ea, modify=0) != 0:
        #  ZeroFunction(ea)
        #  ZeroFunction(ea)
        #  ZeroFunction(ea)
        #  func_tails(ea)
        #  func_tails(ea)
        #  func_tails(ea)
        #  func_tails(ea)
        #  func_tails(ea)
        #  
        #

def sub_and(r, sub, mask, val):
    result = []
    for v in r:
        tmp = ((v - sub) & mask)
        if val is True:
            if tmp:
                result.append(v)
        elif tmp == val:
            result.append(v)
    return result

def sub_and_lt(r, sub, mask, val):
    result = []
    for v in r:
        if ((v - sub) & mask) < val:
            result.append(v)
    return result

def sub_and_lte(r, sub, mask, val):
    result = []
    for v in r:
        if ((v - sub) & mask) <= val:
            result.append(v)
    return result

def sub_lt(r, sub, val):
    result = []
    for v in r:
        if ((v - sub)) < val:
            result.append(v)
    return result

def sub_lte(r, sub, val):
    result = []
    for v in r:
        if ((v - sub)) <= val:
            result.append(v)
    return result

def and_eq(r, mask, val):
    result = []
    for v in r:
        tmp = (v & mask)
        if val is True:
            if tmp:
                result.append(v)
        elif tmp == val:
            result.append(v)
    return result

def usub_lte(r, sub, val):
    result = []
    for v in r:
        if ((v - sub) & 0xffffffff) <= val:
            result.append(v)
    return result

