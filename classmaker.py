from idc import *
import re
import os
import sys
from exectools import _import, _from
#  _import("from idarest.idarest_client import IdaRestClient")

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
#  from loader import import_from
#  import fuzzywuzzy
#  from fuzzywuzzy import fuzz
#  from fuzzywuzzy import process

#  BatchMode = _require('BatchMode').BatchMode

__class_maker_struct = []
__class_maker_member_names = []

from exectools import make_refresh
refresh_classmaker = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

import idaapi

classmaker_info = idaapi.get_inf_structure()

if classmaker_info.is_64bit():
    bits = 64
elif classmaker_info.is_32bit():
    bits = 32
else:
    bits = 16

try:
    is_be = classmaker_info.is_be()
except:
    is_be = classmaker_info.mf

endian = "big" if is_be else "little"

# print('Processor: {}, {}bit, {} endian'.format(classmaker_info.procName, bits, endian))
# Result: Processor: mipsr, 32bit, big endian

def ptrsize():
    return ptrsize.bits >> 3

ptrsize.bits = bits

def getptr(ea=None, bits=None, signed=False):
    if bits is None:
        bits = ptrsize.bits
    result = idc.get_qword(eax(ea)) & ((1 << bits) - 1)
    if signed:
        result = MakeSigned(result, bits)
    return result

def getptr(ea=None, bits=None, signed=False):
    if bits is None:
        bits = ptrsize.bits
    result = idc.get_qword(eax(ea)) & ((1 << bits) - 1)
    if signed:
        result = MakeSigned(result, bits)
    return result

def setptr(ea=None, value=0, bits=None, signed=False):
    ea = eax(ea)
    if bits is None:
        bits = ptrsize.bits
    result = (idc.get_qword(ea) & ~((1 << bits) - 1)) | (value & ((1 << bits) - 1))
    if signed:
        result = MakeSigned(result, bits)
    idc.patch_qword(ea, result)
    return result

getptr.bits = bits

def copy_vtable():
    l = [get_name_by_any(getptr(ea)) for ea in range(ms(), me(), ptrsize())]
    # for i, ea in enumerate(range(EA(), EA() + ptrsize() * len(l) + 1, ptrsize())): LabelAddressPlus(getptr(ea), l[i])
    print("""
l = [{}]
for i, ea in enumerate(range(EA(), EA() + ptrsize() * len(l) + 1, ptrsize())): LabelAddressPlus(getptr(ea), l[i])
        """.format(", ".join(['"{}"'.format(x) for x in l])))



for _annoying in ["PT_REPLACE", "PT_RAWARGS", "PT_NDC"]:
    if _annoying not in globals():
        globals()[_annoying] = idc.PT_SILENT;

#  if 'long' not in globals():
    #  globals()['long'] = int;

def _hasUserName(ea=None):
    """
    _hasUserName

    @param ea: linear address
    """
    ea = eax(ea)
    if not HasUserName(ea):
        return False
    name = idc.get_name(ea)
    if re.match('_sub_[0-9a-fA-F]+$', name):
        return False
    return True

def GetLocalTypeFixed(ordinal, flags):
    """
    Retrieve a local type declaration
    @param flags: any of PRTYPE_* constants
    @return: local type as a C declaration or ""
    """
    rv = get_local_tinfo(ordinal)
    if not rv:
        return ""
    (type, fields) = rv
    if type:
      name = get_numbered_type_name(ordinal)
      return ida_typeinf.idc_print_type(type, fields, name, flags)
    return ""

def struct_list_local():
    for i in range(1, idc.get_ordinal_qty()):
        print(i, GetLocalTypeFixed(i, PRTYPE_TYPE))

def local_struct_names():
    for i in range(1, idc.get_ordinal_qty()):
        yield idc.get_numbered_type_name(i)

def struct_names():
    i = get_first_struc_idx(); 
    while i != BADADDR:
        yield idc.get_struc_name(idc.get_struc_by_idx(i))
        i = get_next_struc_idx(i)

def get_struc_ordinal(name):
    for i in range(1, idc.get_ordinal_qty()+1):
        if idc.get_numbered_type_name(i) == name:
            return i
    return BADADDR

def get_ordinal_by_name(name):
    ti = ida_typeinf.get_idati()
    return ida_typeinf.get_type_ordinal(ti, name)

def get_struc_idx_re(pattern, flags = 0):
    i = get_first_struc_idx(); 
    while i != idc.BADADDR:
        name = idc.get_struc_name(idc.get_struc_by_idx(i))
        try:
            if re.match(pattern, name, flags):
                yield (i, name)
        except TypeError as e:
            print("**EXCEPTION** {}: {} ({}, {})".format(e.__class__.__name__, str(e), pattern, name))
        i = get_next_struc_idx(i)

def get_struc_ordinal_re(pattern, flags = 0):
    for i in range(1, idc.get_ordinal_qty()):
        name = idc.get_numbered_type_name(i)
        if name:
            try:
                if re.match(pattern, name, flags):
                    yield (i, name)
            except TypeError as e:
                print("**EXCEPTION** {}: {} ({}, {})".format(e.__class__.__name__, str(e), pattern, name))

def get_all_struc_ordinals_and_tinfo():
    idati = ida_typeinf.get_idati()

    for ordinal in range(1, ida_typeinf.get_ordinal_qty(idati)+1):
        ti = ida_typeinf.tinfo_t()
        if ti.get_numbered_type(idati, ordinal):
            yield ordinal, ti

def get_ordinal_tinfo_by_name(name):
    idati = ida_typeinf.get_idati()
    ti = ida_typeinf.tinfo_t()

    for ordinal in range(1, ida_typeinf.get_ordinal_qty(idati)+1):
        if ti.get_numbered_type(idati, ordinal) and ti.dstr() == name:
            return ti
    return BADADDR

def does_struc_exist(name):
    if idc.get_struc_id(name) == BADADDR and get_struc_ordinal(name) == BADADDR:
        return False
    return True

def does_struc_exist_re(pattern, flags):
    l = [x for x in get_struc_ordinal_re(pattern, flags)]
    l.extend([x for x in get_struc_idx_re(pattern, flags)])
    return len(l) > 0

#  def get_struc_name_fuzzy(name):
    #  choices = [x for x in struct_names()]
    #  choices.extend([x for x in local_struct_names()])
    #  print("choices", len(choices))
    #  return process.extract(name, choices, limit = 5)

BAD_FNNAME_PATTERN = re.compile(r'[^a-zA-Z0-9@$%&().?:_\[\]]')
def safe_func_name(name):
    if not BAD_FNNAME_PATTERN.findall(name):
        return name

    return re.sub(BAD_FNNAME_PATTERN, lambda x: "_x{:02x}_".format(ord(x.group(0))), name)

BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')
def demangled_name_to_c_str(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    -- from HexRaysPyTools
    """
    if not BAD_C_NAME_PATTERN.findall(name):
        return name
    idx = name.find("::operator")
    if idx >= 0:
        idx += len("::operator")
        if idx == len(name) and not BAD_C_NAME_PATTERN.findall(name[idx]):
            pass
        elif name[idx:idx + 2] == "==":
            name = name.replace("operator==", "operator_EQ_")
        elif name[idx:idx + 2] == "!=":
            name = name.replace("operator!=", "operator_NEQ_")
        elif name[idx] == "=":
            name = name.replace("operator=", "operator_ASSIGN_")
        elif name[idx:idx + 2] == "+=":
            name = name.replace("operator+=", "operator_PLUS_ASSIGN_")
        elif name[idx:idx + 2] == "-=":
            name = name.replace("operator-=", "operator_MINUS_ASSIGN_")
        elif name[idx:idx + 2] == "*=":
            name = name.replace("operator*=", "operator_MUL_ASSIGN_")
        elif name[idx:idx + 2] == "/=":
            name = name.replace("operator/=", "operator_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "%=":
            name = name.replace("operator%=", "operator_MODULO_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "|=":
            name = name.replace("operator|=", "operator_OR_ASSIGN_")
        elif name[idx:idx + 2] == "&=":
            name = name.replace("operator&=", "operator_AND_ASSIGN_")
        elif name[idx:idx + 2] == "^=":
            name = name.replace("operator^=", "operator_XOR_ASSIGN_")
        elif name[idx:idx + 3] == "<<=":
            name = name.replace("operator<<=", "operator_LEFT_SHIFT_ASSIGN_")
        elif name[idx:idx + 3] == ">>=":
            name = name.replace("operator>>=", "operator_RIGHT_SHIFT_ASSIGN_")
        elif name[idx:idx + 2] == "++":
            name = name.replace("operator++", "operator_INC_")
        elif name[idx:idx + 2] == "--":
            name = name.replace("operator--", "operator_PTR_")
        elif name[idx:idx + 2] == "->":
            name = name.replace("operator->", "operator_REF_")
        elif name[idx:idx + 2] == "[]":
            name = name.replace("operator[]", "operator_IDX_")
        elif name[idx] == "*":
            name = name.replace("operator*", "operator_STAR_")
        elif name[idx:idx + 2] == "&&":
            name = name.replace("operator&&", "operator_LAND_")
        elif name[idx:idx + 2] == "||":
            name = name.replace("operator||", "operator_LOR_")
        elif name[idx] == "!":
            name = name.replace("operator!", "operator_LNOT_")
        elif name[idx] == "&":
            name = name.replace("operator&", "operator_AND_")
        elif name[idx] == "|":
            name = name.replace("operator|", "operator_OR_")
        elif name[idx] == "^":
            name = name.replace("operator^", "operator_XOR_")
        elif name[idx:idx + 2] == "<<":
            name = name.replace("operator<<", "operator_LEFT_SHIFT_")
        elif name[idx:idx + 2] == ">>":
            name = name.replace("operator>", "operator_GREATER_")
        elif name[idx:idx + 2] == "<=":
            name = name.replace("operator<=", "operator_LESS_EQUAL_")
        elif name[idx:idx + 2] == ">=":
            name = name.replace("operator>>", "operator_RIGHT_SHIFT_")
        elif name[idx] == "<":
            name = name.replace("operator<", "operator_LESS_")
        elif name[idx] == ">":
            name = name.replace("operator>=", "operator_GREATER_EQUAL_")
        elif name[idx] == "+":
            name = name.replace("operator+", "operator_ADD_")
        elif name[idx] == "-":
            name = name.replace("operator-", "operator_SUB_")
        elif name[idx] == "/":
            name = name.replace("operator/", "operator_DIV_")
        elif name[idx] == "%":
            name = name.replace("operator%", "operator_MODULO_DIV_")
        elif name[idx:idx + 2] == "()":
            name = name.replace("operator()", "operator_CALL_")
        elif name[idx: idx + 6] == " new[]":
            name = name.replace("operator new[]", "operator_NEW_ARRAY_")
        elif name[idx: idx + 9] == " delete[]":
            name = name.replace("operator delete[]", "operator_DELETE_ARRAY_")
        elif name[idx: idx + 4] == " new":
            name = name.replace("operator new", "operator_NEW_")
        elif name[idx: idx + 7] == " delete":
            name = name.replace("operator delete", "operator_DELETE_")
        elif name[idx] == ' ':
            pass
        else:
            raise AssertionError("Replacement of demangled string by c-string for keyword `operatorXXX` is not yet"
                                 "implemented ({}). You can do it by yourself or create an issue".format(name))

    name = name.replace("public:", "")
    name = name.replace("protected:", "")
    name = name.replace("private:", "")
    name = name.replace("~", "DESTRUCTOR_")
    name = name.replace("*", "_PTR")
    name = name.replace("<", "_t_")
    name = name.replace(">", "_t_")
    name = "_".join(filter(len, BAD_C_NAME_PATTERN.split(name)))
    return name

def getString(ptr):
    s = ''
    null_term = False
    invalid_char = None
    for i in range(128):
        c = Byte(ptr + i)
        if c == 0:
            null_term = True
            break
        if c > 122 or c < 32:
            invalid_char = c
            break
        s += "%c" % c
    if null_term:
        return s
    if invalid_char:
        raise ValueError("Invalid char '%c'" % c)
    raise ValueError("String was not null terminated")

def rename_all_generic_methods():
    for fn in Functions():
        if not HasUserName(fn):
            for ea in seg_refs_to(fn, '.rdata'):
            #  if not _hasUserName(fn):
                print('rename_all_generic_methods: {}'.format(idc.get_name(ea.to)))
                rename_generic_methods(ea.frm)
                break

def bin_match(ea, pattern):
    start_ea = ida_search.find_binary(ea, ea + 32, pattern, 16, SEARCH_CASE | SEARCH_DOWN | SEARCH_NOSHOW)
    if start_ea == ea:
        print("bin_match: found: {}".format(pattern))
        return True
    if debug: print("bin_match: didn't find: {}".format(pattern))
    return False

def rename_generic_methods(ea=None):
    """
    rename_generic_methods

    @param ea: linear address
    """
    ea = eax(ea)
    _type = "__int64 __fastcall function();"
    isOff
    _is_offset = GetDisasm(ea).startswith('offset', 3)    
    if _is_offset:
        deref = getptr(ea) # idc.get_qword(ea)
        start_ea = deref # SkipJumps(deref)
        if debug: print("_is_offset: {:x} {}".format(start_ea, GetFuncName(start_ea)))
    else:
        start_ea = ea
    with BatchMode(0):
        found = True
        while isJmpOrObfuJmp(start_ea):
            if not isUnconditionalJmp(start_ea):
                retrace(start_ea)
            new_ea = SkipJumps(start_ea)
            if debug: print("{:x} skipjumps {:x}".format(start_ea, new_ea))
            if new_ea == start_ea:
                break
            start_ea = new_ea

        # this condition only reached is jumps skipped
        if _is_offset and start_ea != deref:
            fnName = ''
            if HasUserName(deref):
                fnName = idc.get_name(deref)
                print('HadUserName', fnName)
                MakeNameEx(deref, "", idc.SN_AUTO | idc.SN_NOWARN)
                #  fnNameTmp = idc.get_name(deref)
                #  print('ChangedUserName', fnNameTmp)
            else:
                print('!HasUserName', fnName)
            idaapi.del_fixup(ea)
            idc.patch_qword(ea, start_ea)
            if fnName:
                LabelAddressPlus(start_ea, fnName, force=1)
                #  not needed if del_fixup works
                #  PatchBytes(start_ea, " ".join(["{:02x}".format(x) for x in get_many_bytes(start_ea, 8)]))
            
            #  print("[GetJumpTarget]: {:x}".format(ea))
            #  ea = GetJumpTarget(ea)
        #  try:
            #  retrace(ea)
        #  except AdvanceFailure:
            #  ZeroFunction(ea)
            #  retrace(ea)
        if bin_match(start_ea, "48 8d 0d ?? ?? ?? ?? 33 d2 e9 ?? ?? ?? ??"):
            ptr = mem(start_ea).chain().add(3).rip(4).value()
            try:
                s = safe_func_name(getString(ptr))
                print("{:x} s: {}".format(start_ea, s))
                if s:
                    MyMakeFunction(start_ea)
                    LabelAddressPlus(start_ea, "joaat_" + s)
            except ValueError:
                print("ValueError: 0x{:x}".format(start_ea))
        
        # 48 8D 05 19 D2 01 00                    lea     rax, ??_R0?AV_lamb 
        # demangle_name(mem(EA()).add(3).rip(4).name(), DEMNAM_NAME)
        #   "class _lambda_75c0756d4e96e050ce430f299baa3f2b_ `RTTI Type Descriptor'"
        elif bin_match(start_ea, "48 8d 05 ?? ?? ?? ?? c3") or \
                bin_match(start_ea, "48 8d 05 ?? ?? ?? ?? 48 8d 64 24 08 ff 64 24 f8"):
            ptr = mem(start_ea).add(3).rip(4).value()
                
            try:
                print("getString(0x{:x})".format(ptr))
                s = safe_func_name(getString(ptr))
                s = "s_" + s
            except ValueError:
                if IsDword(ptr):
                    v = idc.get_wide_dword(ptr)
                    MyMakeFunction(start_ea)
                    j = mega.Lookup(v)
                    if j[1] != 'x':
                        s = "joaat_" + j
                    else:
                        s = "return_dword_" + j
                else:
                    s = safe_func_name(idc.get_name(ptr, GN_DEMANGLED))
                    if s:
                        s = "return_" + s

            print("{:x} s: {}".format(start_ea, s))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "s_" + s)

        elif bin_match(start_ea, "48 b8 ?? ?? ?? ?? ?? ?? ?? ?? c3"):
            s = hex(GetOperandValue(start_ea, 1))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_" + s)
        #
        #  .text:0000000141046364 000 48 8D 81 48 01 00 00                    lea     rax, [rcx+148h]
        #  .text:000000014104636B 000 C3                                      retn

        elif bin_match(start_ea, "48 8D 81 ?? ?? ?? ?? c3"):
            s = hex(GetOperandValue(start_ea, 1))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_offset_" + s)

        #  .text:00000001412C3DA0 000 48 8B 81 18 01 00 00      mov     rax, [rcx+118h]
        #  .text:00000001412C3DA7 000 C3                        retn

        elif bin_match(start_ea, "48 8B 81 ?? ?? ?? ?? c3"):
            s = hex(GetOperandValue(start_ea, 1))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_m_" + s)

        #  .text:00000001413B98EC 000 48 8B 41 08               mov     rax, [rcx+8]
        #  .text:00000001413B98F0 000 C3
        elif bin_match(start_ea, "48 8B 41 ??"):
            s = hex(GetOperandValue(start_ea, 1))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_m_" + s)

        elif bin_match(start_ea, "b8 ?? ?? 00 00 c3"):
            s = hex(MakeSigned(Dword(start_ea+1), 32 ))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_" + s)

        elif bin_match(start_ea, "b0 ?? c3"):
            s = GetOperandValue(start_ea, 1)
            if isinstance(s, int):
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_" + str(s))


        #  mov     eax, [rcx+8]
        #  retn
        elif bin_match(start_ea, "8b 41 ?? c3"):
            s = hex(MakeSigned(Byte(start_ea+2), 32 ))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_dw_field_" + s)

        #  8B 81 AC 00 00 00         mov     eax, [rcx+0ACh]
        #  C3                        retn
        elif bin_match(start_ea, "8b 81 ?? ?? ?? ?? c3"):
            s = hex(MakeSigned(Dword(start_ea+2), 32 ))
            if s:
                MyMakeFunction(start_ea)
                LabelAddressPlus(start_ea, "return_dw_field_" + s)

        elif bin_match(start_ea, "48 83 C8 FF c3"):
            MyMakeFunction(start_ea)
            LabelAddressPlus(start_ea, "return_minus_1")


        # C2 00 00                                retn    0
        elif bin_match(start_ea, "c2 00 00"):
            MyMakeFunction(start_ea)
            LabelAddressPlus(start_ea, "nullretn_{:X}".format(start_ea))

        elif GetNumChunks(start_ea) == 0:
            found = False
            dis1 = diida(GetFuncStart(start_ea), GetFuncEnd(start_ea))
            if debug: print("dis1: {}".format(dis1))
            """
            mov rax, [rcx]
            jmp qword [rax+0x10]
            """
            if not found:
                match = re.match(r'mov rax, \[rcx\]\njmp qword \[rax\+(?:0x)([0-9a-fA-F]+)\]', dis1)
                if match:
                    offset = parseHex(match.group(1)) // ptrsize()
                    found = True
                    MyMakeFunction(start_ea)
                    LabelAddressPlus(start_ea, "return_jump_m_{:x}".format(offset))
                    _type = "__int64 __fastcall function(void* a1);"

            if not found:

                match = re.match(r'mov eax, (?:0x)([0-9a-fA-F]+)\nret', dis1)
                if match:
                    offset = parseHex(match.group(1))
                    found = True
                    j = mega.Lookup(offset)
                    if j[1] != 'x':
                        LabelAddressPlus(start_ea, "joaat_" + j)
                    else:
                        LabelAddressPlus(start_ea, "return_dword_" + j)
                    MyMakeFunction(start_ea)
                    #  LabelAddressPlus(start_ea, "return_0x{:x}".format(offset))
                    _type = "int __fastcall function();"

            if not found:
                dis = dis1.split('\n')
                if len(dis) == 2 and (dis[1].startswith('retn') or dis[1].endswith('retn')):
                    if dis[0].startswith('xor'):
                        lhs = string_between(' ', ',', dis[0])
                        rhs = string_between(',', '', dis[0]).strip()
                        if lhs == rhs:
                            if lhs in ["rax", "eax", "ax", "ah", "al"]:
                                found = True
                                MyMakeFunction(start_ea)
                                if lhs == 'al':
                                    LabelAddressPlus(start_ea, "return_false".format(start_ea))
                                else:
                                    LabelAddressPlus(start_ea, "return_0".format(start_ea))


        else:
            found = False

        if found:
            SetType(start_ea, _type)

def get_class_informer(ea, silent=False):
    comment = idc.get_extra_cmt(ea, E_PREV+1)
    if comment is not None:
        regex = r"; class (.*?): (.*?);\s*?(\[[MI]+\])?\s*?\(#classinformer\)"
        for (className, classParents, classFlags) in re.findall(regex, comment):
            classHierarchy = classParents.split(", ")
            # print("class: {0} {2}  parents: {1}  ".format(className, classParents, classFlags))
            classList = [className]
            classList.extend(classHierarchy)
            return classList

        # fallback for classes with no inheritance
        regex = r"; (?:class|struct) (.*?):\s*?(\[[MI]+\])?\s*?\(#classinformer\)"
        for (className, classFlags) in re.findall(regex, comment):
            # print("class: {0} {2}  parents: {1}  ".format(className, "none", classFlags))
            classList = [className]
            return classList

        if not silent:
            print("0x%x Failed to scan with regex: %s" % (ea, comment))
    return None

def find_vtable_start(ref, fixVtables=0):
    if SegName(ref) == '.rdata':
        addr = ref
        while not Name(addr).startswith('??_7') and SegName(addr) == '.rdata' and GetDisasm(addr).startswith(
                'dq offset'):
            addr = idc.prev_head(addr)
        if Name(addr).startswith('??_7'):
            refName = Demangle(Name(addr), DEMNAM_FIRST)
            if not refName:
                refName = "unknown_vftable_0x%x" % addr
            functionRefs[target].add(addr)
            className = refName.replace("::`vftable'", "")
            offsetName = "m_{:x}".format(ref - addr)
            if fixVtables:
                ClassMakerFamily(ea=addr, redo=1)

def classmaker_get_vtable(ea):
    return idc.get_enum_member_name(ea)

def make_code_and_wait(ea, force = False, comment = ""):
    """
    make_code_and_wait(ea)
        Create an instruction at the specified address, and Wait() afterwards.
        
        @param ea: linear address
        
        @return: 0 - can not create an instruction (no such opcode, the instruction
        would overlap with existing items, etc) otherwise returns length of the
        instruction in bytes
    """

    if idc.get_wide_byte(ea) == 0xcc:
        # print("0x%x: %s can't make 0xCC into code" % (ea, comment))
        return 0


    while idc.is_data(idc.get_full_flags(idc.get_item_head(ea))):
        #  print("// 0x%012x: make_code_and_wait - FF_DATA - MakeUnknown" % ea)
        idc.MakeUnknown(idc.get_item_head(ea), idc.next_not_tail(ea) - idc.get_item_head(ea), 0)
        Wait()

    if idc.is_tail(idc.get_full_flags(ea)):
        idc.MakeUnknown(idc.get_item_head(ea), ea - idc.get_item_head(ea), 0)

    for i in range(32):
        if not idc.create_insn(ea):
            idc.MakeUnknown(ea, i, 0)
    insLen = idc.create_insn(ea)
    if insLen == 0:
        if force:
            #  print("// 0x%x: %s %s" % (ea, comment, idc.GetDisasm(ea)))
            count = 0
            # This should work, as long as we are not started mid-stream
            while not insLen and count < 16: #  and idc.next_head(ea) != idc.next_not_tail(ea):
                count += 1
                idc.MakeUnknown(idc.get_item_head(ea), count, 0)
                Wait()
                insLen = make_code_and_wait(ea)
                #  print("0x%x: make_code_and_wait: making %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, idc.GetDisasm(ea + count)))
            if count > 0:
                print("// 0x%x: make_code_and_wait: made %i unknown bytes (insLen now %i): %s" % (ea, count, insLen, idc.GetDisasm(ea + count)))
    #  print("0x%x: make_code_and_wait returning %i" % (ea, count))
    Wait()
    return insLen

def fix_offset(ea=None):
    """
    fix_offset

    @param ea: linear address
    """
    ea = eax(ea)
    if idc.get_full_flags(ea) & 0x30500500 == 0x30500500 and idc.GetDisasm(ea).startswith("dq offset"):
        target = idc.get_qword(ea)
        if SegName(target) != '.text':
            return False
        if target != idc.get_item_head(idc.get_qword(ea)) or not IsFuncHead(target):
            if not ForceFunction(target) and retrace(target) != 0:
                raise Exception("{:x} Couldn't make function from offset {:x}".format(ea, target))
            idc.add_func(target)
    return True

def fix_offset_test_loop(ea=None, end_ea=None):
    """
    fix_offset_test_loop

    @param ea: linear address
    """
    ea = eax(ea)
    end_ea = end_ea or ea + ptrsize()
    ea = ea - ptrsize()
    try:
        while ea <= end_ea and SegName(ea) == '.rdata':
            found = FindText(ea+ptrsize(), SEARCH_DOWN | SEARCH_CASE | SEARCH_REGEX, 0, 0, "dq offset (((unk|loc|qword|dword|word|byte|sub)\w+)|(\w+[+-]))")
            ea = ea + ptrsize()
            if found == ea:
                if not fix_offset(ea):
                    continue
                rename_generic_methods(ea)
                SetFuncFlags(Qword(EA()), lambda x: x & ~FUNC_LIB)
    except KeyboardInterrupt:
        return

def alternate_fn_offset_name(fnName):
    # dq offset ?narrow@?$ctype@D@std@@QEBADDD@Z_11; std::ctype<char>::narrow(char,char)
    if not re.match(r'(dq offset \w)', fnName):
        if re.match(r'(.*; \w)', fnName):
            fnName = re.sub(r'(dq offset [^\w][^;]+; (.+))', r'dq offset \2', fnName)
            fnName = re.sub(r'[^\w]', '_', fnName).replace('dq_offset_', '')

def class_get_member(ea):
    if idc.get_full_flags(ea) & 0x30500500 == 0x30500500 and (idc.GetDisasm(ea).startswith("dq offset") or idc.GetDisasm(ea).startswith("dd offset")  ):
        if not IsFuncHead(ea):
            print("fixing offset")
            fix_offset(ea)
        disasm = idc.GetDisasm(ea)
        if disasm is not None and disasm.startswith("dq offset"):
            regex = r"^d[dq] offset ([^; ]+)(.*)"
            for (fnName, offsetComment) in re.findall(regex, disasm):
                # dprint("[debug] fnName, offsetComment")
                print("[debug] fnName:{}, offsetComment:{}".format(fnName, offsetComment))
                
                if not re.match(r'(d[dq] offset \w)', fnName):
                    fnName = alternate_fn_offset_name(disasm)
                    if fnName:
                        fnName = fnName[10:]
                rawFnLoc = idc.get_qword(ea)
                # print("member_function: {0} / {2}  comments: {1}".format(fnName, offsetComment, rawFnName))
                print('rename_generic_methods {:x}'.format(rawFnLoc))
                rename_generic_methods(rawFnLoc)
                idc.auto_wait()
                if not fix_offset(rawFnLoc):
                    return False
                idc.auto_wait()
                rawFnName = idc.get_name(rawFnLoc) # can't be trusted for much
                return rawFnName
    return None

def process_usercall_args(test_str):
    abi = [['rcx',  'ecx', 'cx',  'ch',   'cl',  'xmm0'],
            ['rdx', 'edx', 'dx',  'dh',   'dl',  'xmm1'],
            ['r8',  'r8d', 'r8w', 'r12b', 'r8b', 'xmm2'],
            ['r9',  'r9d', 'r9w', 'r14b', 'r9b', 'xmm3']]
    regex = r"""
            (?:(?P<type>[a-zA-Z_][a-zA-Z0-9_ *]+?)  (?P<name>\w+) (?:@<(?P<register>[^>]+)>)?) (?# end) (?:, |[)])
            """
    args = list([None,None,None,None])
    matches = re.finditer(regex, test_str, re.VERBOSE)
    for matchNum, match in enumerate(matches, start=1):
        (_type, _name, _register) = match.groups()
        #  print("// {}, {}, {}, {}".format(matchNum, _type, _name, _register))
        for position, registers in enumerate(abi):
            if _register in registers:
                args[position] = _type
    while len(args) and args[len(args)-1] is None:
        args = args[0:len(args)-1]
    result = list()
    for count, _type in enumerate(args):
        if _type is None:
            _type = "void*"
        result.append("%s a%i" % (_type.strip(), count + 1))
    return result

def remove_usercall(ea, offset=0):
    try:
        cfunc = idaapi.decompile(ea)
        func_def = str(cfunc).split("\n")
        decl = [x for x in func_def if len(x) and not x[0] == '/'][0]
        if decl is not None:
            if ~decl.find("__usercall"):
                args = string_between("(", ")", decl, greedy = True, inclusive = True)
                fnNameType = decl.replace(args, '').replace('__usercall', '__fastcall')
                fnNameType = re.sub(r"@<[^>]+>", "", fnNameType)
                decl = "%s(%s)" % (fnNameType, ", ".join(process_usercall_args(args)))
                #  print("// Attempting to alter __usercall member to: %s" % decl)
                idc.SetType(ea, decl)
                Wait()

    except ida_hexrays.DecompilationFailure:
        print("// %s: DecompilationFailure: 0x0%0x" % (fnName, ea))
        return make_vfunc_struct_sig("void", "__fastcall", "error_%s_%02x" % (fnName, offset), "void*", offset=offset)


def sanitizedName(className, allowSpaces=True):
    # ('Not accepted: {}', 'void __fastcall CTrackedEventInfo__unsigned__int64__::m_8(CTrackedEventInfo<unsigned __int64>* self)')

    if isinstance(className, list):
        return [sanitizedName(x) for x in className]
    elif isinstance(className, str):
        # absolutely no spaces between < >
        if not allowSpaces:
            #  className = className.replace(' ', '')
            return demangled_name_to_c_str(className)

        className = string_between('<', '>', className, greedy=1, inclusive=1, repl=demangled_name_to_c_str) # lambda x: x.replace(' ', ''))
        #  className = className.replace('<', '__').replace('>','__').replace(',','_') # .replace(' ','')
        return className
    else:
        raise Exception("Unknown type: {}".format(type(className)))

def make_vfunc_struct_sig(returnType, callType, fnName, args, offset=0):
    if isinstance(args, str):
        joinedArgs = args
    else:
        joinedArgs = ", ".join(args)

    if callType == "__stdcall" or callType is None:
        callType = "__fastcall"

    if offset == 0 and fnName.endswith('::m_0'):
        returnType = 'void'

    return "    %s (%s *%s)(%s);" % (returnType, callType, fnName, joinedArgs)

def make_vfunc_function_sig(returnType, callType, fnName, args, offset=0):
    """
    Garbage In:  __int64 (__fastcall *__fastcall CRawClipFileView::m_8(__int64 a1, int a2, char a3))()
    Garbage Out: __int64  CRawClipFileView::m_8(CRawClipFileView*__hidden this, int a2, char a3))();
    """
    if isinstance(args, str):
        joinedArgs = args
    else:
        joinedArgs = ", ".join(args)

    if callType == "__stdcall":
        callType = "__fastcall"

    if offset == 0 and fnName.endswith('::m_0'):
        returnType = 'void'

    return "%s %s %s(%s);" % (returnType, callType, fnName, joinedArgs)


def fix_fnName(fnName, offset=0):
    # if re.match(r'.*_m_[0-9a-fA-F]+$', fnName)
    fnName = TagRemoveSubstring(fnName)
    if fnName.endswith('m_{:x}'.format(offset)):
        return fnName
    fnName += "_m_%x" % offset
    return fnName


def make_member_type(decl, memberType = None, fnNameAlt = None, offset=0):
    global __class_maker_member_names

    if decl:
        regex = r"(.*?) ?((?:(?:__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge) )*)([^* ]*?)\((.*)\)"
        for (returnType, callType, fnName, fnArgs) in re.findall(regex, decl):
            fnName = TagRemoveSubstring(fnName)
            #  print('//{:12}|{:10}|{}|{}|{}'.format(returnType, callType, fnName, fnArgs, decl))
            if fnNameAlt: 
                fnName = fnNameAlt
                fnName = TagRemoveSubstring(fnName)
            args = fnArgs.split(", ")
            if memberType and len(args): #  and not args[0].endswith("self"):
                #  print("memberType", memberType, args[0])
                args[0] = memberType

            fnName = fix_fnName(fnName, offset=offset)
            return make_vfunc_struct_sig(returnType, callType, fnName, sanitizedName(args), offset=offset)
    print("// Unrecognised function signature: {}".format(decl))
    return make_vfunc_struct_sig("void", "__fastcall", "error_%02x" % offset, "void*", offset=offset)


def decompile_member(ea, memberType, fnNameAlt = None, offset=0):
    global __class_maker_member_names
    try:
        cfunc = idaapi.decompile(ea)
        if not cfunc:
            ForceFunction(ea)
            cfunc = idaapi.decompile(ea)

        func_def = str(cfunc).split("\n")
        decl = [x for x in func_def if len(x) and not x[0] == '/'][0]
        if decl is not None:
            # print("decl: %s" % decl)
            decl = re.sub("__noreturn", "", decl)

            # fix up any __usercall methods
            if ~decl.find("__usercall"):
                print("// Attempting to alter __usercall member to: %s" % decl)
                remove_usercall(ea, offset=offset)
                idaapi.decompile(ea)
                remove_usercall(ea, offset=offset)
                cfunc = idaapi.decompile(ea)
                func_def = str(cfunc).split("\n")
                decl = [x for x in func_def if len(x) and not x[0] == '/'][0]

            regex = r"(.*?) ?(__array_ptr|__cdecl|__export|__far|__fastcall|__hidden|__huge|__import|__near|__noreturn|__pascal|__pure|__restrict|__return_ptr|__spoils|__stdcall|__struct_ptr|__thiscall|__thread|__unaligned|__usercall|__userpurge)? ?([^* ]*?)\((.*)\)"
            for (returnType, callType, fnName, fnArgs) in re.findall(regex, decl):
                if returnType == "_BOOL8": returnType = "bool"
                if fnNameAlt: 
                    fnName = fnNameAlt
                args = fnArgs.split(", ")
                if not args[0].startswith("void"):
                    args[0] = memberType
                fnName = fix_fnName(fnName, offset=offset)
                fnSig = make_vfunc_function_sig(returnType, callType, fnName, (args), offset=offset)
                strSig = make_vfunc_struct_sig(returnType, callType, fnName, (args), offset=offset)
                if not idc.SetType(ea, fnSig):
                    #  print("Initial type not accepted: {}".format(fnSig))
                    fnSig = make_vfunc_function_sig(returnType, callType, fnName, (sanitizedName(args)), offset=offset)
                    strSig = make_vfunc_struct_sig(returnType, callType, fnName, (sanitizedName(args)), offset=offset)
                    if not idc.SetType(ea, fnSig):
                        if not idc.SetType(ea, fnSig.replace('))();', ');')):
                        #  if not idc.SetType(ea, "__int64 fn({}* self);".format(memberType)):
                            
                            print("0x{:x} Final type Not accepted: {}".format(ea, fnSig))
                    #  else:
                        #  print("Final type accepted: {}".format(fnSig))

                # const char *(__fastcall *GetName)(CNetGamePlayer *);
                return strSig

    except KeyboardInterrupt as e:
        raise e
    except ida_hexrays.DecompilationFailure:
        print("// DecompilationFailure: 0x0%0x" % (ea))
        return make_vfunc_struct_sig("void", "__fastcall", "error_%0xd" % offset, "", offset=offset)

def ClassMaker(ea, memberType = None, className = None, famList = [], parentTypeName = None, redo = False, vtableOnly = False):
    """
    ea should be the location of the vtable line:
        ; const rage::CSyncDataReader::`vftable'

    ClassMaker(idc.get_screen_ea())
        or
    ClassMaker(idc.get_screen_ea(), "CPed *self")
    """

    global __class_maker_member_names
    global __class_maker_struct

    __class_maker_struct = []
    __class_maker_member_names = []


    if not className:
        #  classList = get_class_informer(ea - 8)
        if classList is None:
            raise Exception("'{:x}' is not a class".format(ea))
        #  classHierarchy = classList[1:]
        #  className = classList[0]

    try:
        ourFamPos = famList.index(className)
        print("className: {} famList: {} (ourFamPos: {})\n".format(sanitizedName(className), famList[ourFamPos+1:], ourFamPos))
    except ValueError:
        ourFamPos = -1
    vtable = classmaker_get_vtable(ea)
    if vtable is None:
        raise Exception("Not a vtable")
    #  print("// className (pre-processing):  %s" % className)
    # className = re.sub(r"^.*::", "", className)
    # Lets not remove rage::
    # className = re.sub(r'rage::', '', className).replace('<', '__').replace('>','__').replace(',','_').replace(' ','')
    className = sanitizedName(className)
    #  print("// className (post-processing):  %s" % className)
    #  return
    if not vtableOnly:
        defn = ''
        vtbl_name = "%s_vtbl" % className
        if not does_struc_exist(vtbl_name):
            defn += "struct /*VFT*/ %s_vtbl;\n" % className
            
        # if idc.get_struc_id(className) == BADADDR and get_struc_ordinal(className) == BADADDR:
        if not does_struc_exist(className):
            decls = {}
            if False and IdaRestClient.GetTypes(vtbl_name, decls):
                defn += decls[vtbl_name]
            else:
                if parentTypeName is not None:
                    defn += ("struct __cppobj %s : %s { %s_vtbl* __vftable; };\n" % (className, parentTypeName, className))
                else:
                    defn += ("struct %s { %s_vtbl* __vftable; };\n" % (className, className))

            rv = idc.parse_decls(defn, PT_SILENT | PT_REPLACE | PT_RAWARGS | PT_NDC)
            if rv:
                print("Couldn't parse defn (a):\n\n{}\n".format(defn))
                # raise Exception("Couldn't parse")

    defn = ''

    for offset in range(0, 1024 * ptrsize(), ptrsize()):
        offsetLoc = ea + offset
        if ptrsize() == 4:
            fnLoc = idc.get_qword(offsetLoc) & 0xffffffff
        else:
            fnLoc = idc.get_qword(offsetLoc)
        flags = idc.get_full_flags(fnLoc)
        # print("0x%x: offset 0x%x" % ( offsetLoc, offset))
        #  Why are we doing this at all?
        #  if offset > 0 and not Name.startswith('?'):
            #  idc.set_name(offsetLoc, "", SN_NOWARN)
        # if not (idc.get_full_flags(ea) & 0x30500500 == 0x30500500) or not re.match(r'(dq offset \w)', idc.GetDisasm(ea)) or not get_class_informer(offsetLoc, silent=0):
        print("idc.GetDisasm({:x}): {}".format(offsetLoc, idc.GetDisasm(offsetLoc)))
        if not re.match(r'(d[dq] offset \w)', idc.GetDisasm(offsetLoc)) or idc.is_strlit(flags): #  or not class_get_member(offsetLoc):
            print("not a good chance of still being a class")
            #  print("0x{:x} Finished at offset 0x{:x}; {}".format(offsetLoc, offset, idc.GetDisasm(offsetLoc)))
            #
            #  per https://www.hex-rays.com/products/ida/support/idadoc/1691.shtml
            #    - VFT pointer must have the "__vftable" name
            #    - VFT type must follow the "CLASSNAME_vtbl" pattern
            #  (rules which are already followed, the above is just a reminder)
            defn += "\n"

            decls = {}
            if False and IdaRestClient.GetTypes(vtbl_name, decls):
                defn += decls[vtbl_name]
            else:
                defn += "struct %s_vtbl {\n" % className
                #  defn += ("    void (__fastcall *__destruct)(%s *, bool b2);" % className)
                try:
                    defn += ("\n".join(__class_maker_struct))
                except TypeError as e:
                    print("TypeError: {}".format(e))
                    pp(__class_maker_struct);
                    raise e

                defn += ("\n};")
                defn = defn.replace('))();', ');')

            rv = idc.parse_decls(defn, PT_SILENT | PT_REPLACE | PT_RAWARGS | PT_NDC)
            if rv:
                print("Couldn't parse defn (a):\n\n{}\n".format(defn))
                # raise Exception("Couldn't parse")
            # idc.import_type(idx, type_name):
            defn = ''

            return
            break


        print("calling class_get_member")
        fnName = class_get_member(offsetLoc)
        print("fnName: {}".format(fnName))
        if not fnName:
            print("class_get_member(0x{:x}) failed".format(offsetLoc))
            #  break
        #  fnName = idc.get_name(fnLoc) # should use better call to get unfiltered name
        # print("Function location: 0x%x" % fnLoc)
        rename = False
        if _hasUserName(fnLoc):
            if ourFamPos > -1:
                for parent in famList[ourFamPos+1:]:
                    # dprint("[debug] fnName, parent")
                    
                    if fnName and fnName.startswith(parent):
                        print("[overwriting child class] {} with {}".format(fnName, parent))
                        rename = True
                        idc.SetType(fnLoc, idc.get_type(fnLoc).replace(parent, className))

        if memberType is not None:
            __class_maker_struct.append("dummy")
            __class_maker_struct[offset // ptrsize()] = "%s::dummy_%x" % (className, offset);
            __class_maker_member_names.append("dummy")
            __class_maker_member_names[offset // ptrsize()] = "%s::dummy_%x" % (className, offset);
        flags = idc.get_full_flags(fnLoc)
        if not idc.is_code(flags):
            print("// No code at {} offset {:x} loc: 0x{:x}".format(className, offset, fnLoc))
            # raise Exception("'{:x}' no code".format(ea))
            return
        if not hasAnyName(flags):
            print("// No function name at 0x%x" % fnLoc)
            return
        if rename or not _hasUserName(fnLoc) or fnName and ~fnName.find('?'): #  or fnName.startswith("CNetObjBike"): #  or fnName.startswith("CNetObjSubmarine"):
            print("renaming {:x} (rename:{}, _hasUserName:{})".format(fnLoc, rename, _hasUserName(fnLoc)))
            idc.add_func(fnLoc)
            Wait()
            idc.set_name(fnLoc, "%s::m_%x" % (className, offset), SN_NOWARN)
        else:
            # print("Already has function name: %s" % idc.Name(fnLoc))
            pass

        if memberType is not None:
            newName = idc.get_name(fnLoc)
            if newName:
                fnName = newName
                fnName = fix_fnName(fnName, offset=offset)
            else:
                print("no function name @ 0x{:x}".format(fnLoc))

            funcSig = 'woops! {} @{}'.format(fnName, hex(fnLoc))
            member_type = idc.get_type(fnLoc)
            must_decompile = member_type is None
            if not must_decompile:
                member_type = member_type.replace('(', ' %s(' % idc.get_func_name(fnLoc), 1)
            # print("member_type", member_type, must_decompile)

            #  print("must_decompile: {}".format(must_decompile))
            #  print("vtableOnly: {}".format(vtableOnly))
            if must_decompile:
                # print("// Couldn't get member type from {} at {}... decompiling".format(fnName, hex(fnLoc)))
                funcSig = decompile_member(fnLoc, memberType, fnName, offset=offset)
            elif vtableOnly:
                funcSig = make_member_type(member_type, memberType, fnName, offset=offset)
            else:
                print("checking commenter")
                if Commenter(fnLoc, 'func').matches(r'\[CLASS-MAKER-'):
                    print("was comment {:x}".format(fnLoc))
                    funcSig = make_member_type(member_type, memberType, fnName, offset=offset)
                    # dprint("[make_member_type] funcSig")
                    #  print("[make_member_type] funcSig:{}".format(funcSig))
                    
                else:
                    print("funcSig decompile_member")
                    funcSig = decompile_member(fnLoc, memberType, fnName, offset=offset)
                    # dprint("[decompile_member] funcSig")
                    print("[decompile_member] funcSig:{}".format(funcSig))
                    if funcSig:
                        print("commenting allrefsfrom")
                        refs = AllRefsFrom(fnLoc)
                        for ref in refs["fnRefs"]:
                            Commenter(LocByAnyName(ref), 'func').add("[CLASS-MAKER] called from {}".format(fnName))
                        print("finished commenting allrefsfrom")

            __class_maker_struct[offset // ptrsize()] = funcSig
            # print("funcSig", funcSig)

def mangle(name):
    # ??_7netArrayManager@rage@@6B@
    names = name.split('::')
    names.reverse()
    manglemore = '??_7' + '@'.join(names) + '@@6B@'
    return manglemore

redone = []
def ClassMakerFamily(family = None, ea = None, redo = False, redoParents = False, vtableOnly = False):
    ea = eax(ea)
    global redone
    if family is None:
        # ; class CAutomobileSyncTree: CAutomobileSyncTreeBase, CVehicleSyncTree, CPhysicalSyncTreeBase, CDynamicEntitySyncTreeBase, CEntitySyncTreeBase, CProximityMigrateableSyncTreeBase, CProjectSyncTree, rage::netSyncTree;   (#classinformer)
        #  try:
        family = LineA(ea - ptrsize(), 1) or idc.get_extra_cmt(ea, E_PREV + (0))
        if isinstance(family, str):
            family = family[2:]
            prev_vtbl = string_between(' ', ': ', family, rightmost=1)
            name = Name(ea)
            vtbl = string_between('', "::`vftable'", Demangle(name, DEMNAM_FIRST))
            print("family", family)
            print("prev_vtbl", prev_vtbl)
            print("vtbl", vtbl)
            if isinstance(vtbl, str) and prev_vtbl and vtbl:
                if vtbl != prev_vtbl and not '_i_' in vtbl and not name.endswith('@') and '<' not in vtbl and '<' not in prev_vtbl and ':' not in (vtbl + prev_vtbl):
                    LabelAddressPlus(ea, name.replace(vtbl, '{}_i_{}'.format(prev_vtbl, vtbl)))
                    return ClassMakerFamily(ea=ea, redo=redo, redoParents=redoParents, vtableOnly=vtableOnly)
            else:
                print("missing vtbl or prev_vtbl, aborting")
                print("family", family)
                print("prev_vtbl", prev_vtbl)
                print("vtbl", vtbl)
                return

            
            ClassMakerFamily(family=family, ea=ea, redo=redo, redoParents=redoParents, vtableOnly=vtableOnly)
            # else:

        family = Demangle(Name(ea), DEMNAM_FIRST).replace("::`vftable'", '')
        # CScriptEntityExtension::`vftable'{for `CGameScriptHandlerObject'}
        # CScriptEntityExtension{for `CGameScriptHandlerObject'}
        if '{for ' in family:
            first = string_between('', '{for `', family)
            second = string_between("{for `", "'}", family)
            family = "{}__for__{}".format(first, second)

        if family:
            return ClassMakerFamily(family = family, ea=ea, redo=redo, redoParents=redoParents, vtableOnly=vtableOnly)

        print("0x{:x}: no rtti comment at 0x{:x}".format(ea, ea - ptrsize()))
        return

        #  except Exception as e:
            #  print("0x{:x}: no rtti comment (Exception: {})".format(ea, str(e)))
            #  family = Demangle(Name(ea), DEMNAM_FIRST).split('::')[0]
            #  if not isinstance(family, str):
                #  raise e
    with JsonStoredSet('classmaker-complete.json') as __classes_completed:
        #  if "rage::netSyncDataNodeBase" in __classes_completed:
            #  __classes_completed.remove("rage::netSyncDataNodeBase")
        #  if "rage::netSyncDataNode" in __classes_completed:
            #  __classes_completed.remove("rage::netSyncDataNode")
        # family = "CAmphibiousAutomobile: CAutomobile, CVehicle, CPhysical, CDynamicEntity, CEntity"
        #  print("family: {}".format(family))
        family = re.sub(r'(^((const|struct|class|union) )+)', '', family)
        #  print("family: {}".format(family))
        family = re.sub(r'(\s+\(#classinformer\))', '', family)
        family = re.sub(r'(\[\w+\])', '', family)
        #  print("family: {}".format(family))
        if family[-1] == ':':
            family += " "
        #  print("family: {}".format(family))
        famList = re.split(r'; *|: |, ', family)
        famList = [re.sub(r'(^((const|struct|class|union) )+)', '', y) for y in famList]
        famList = [y.strip() for y in famList]
        family = family.strip()
        famList.reverse()
        famList = [y for y in famList if y]

        #  if isinstance(famList, list) and len(famList) > 2:
            #  print("ClassMakerFamily: ", famList, redo)
            #  famList = famList[-2:]
            #  print("ClassMakerFamily: ", famList, redo)

        if redoParents:
            for className in famList:
                print("Redoing {}".format(className))
                try:
                    redone.remove(className)
                except ValueError:
                    pass

                try:
                    __classes_completed.remove(className)
                except KeyError:
                    pass
                vtableLoc = LocByAnyName(className, vtable=1)
                if vtableLoc < BADADDR:
                    with Commenter(vtableLoc, "line") as c:
                        c.remove('[CLASS-MAKER]')

        if redo:
            className = famList[-1]
            if className in redone:
                redone.remove(className)
            if className in __classes_completed:
                __classes_completed.remove(className)
        for className in famList:
            print("\n\nclassName: {}".format(className))
            if className not in redone and className not in __classes_completed or vtableOnly:
                vtableLoc = LocByAnyName(className, vtable=1, ea=ea)
                #  print("0x{:x} doing {} ...".format(vtableLoc, className))
                if vtableLoc and vtableLoc < BADADDR:
                    try:
                        c = Commenter(vtableLoc, "line")
                        if True or vtableOnly or not c.contains("[CLASS-MAKER]"):
                            # className = re.sub(r"^.*::", "", className)
                            if vtableLoc != BADADDR:
                                print('calling classmaker')
                                ClassMaker(vtableLoc, "{}*__hidden this".format(className), className=className, famList=famList, redo=redo, vtableOnly=vtableOnly)
                                print('classmaker returned')
                                c.add("[CLASS-MAKER]")
                                __classes_completed.add(className)
                                print("0x{:x} {} done".format(vtableLoc, className))
                            else:
                                print("0x{:x} {} vtable loc bad".format(vtableLoc, className))
                        redone.append(className)
                    except KeyboardInterrupt:
                        raise Exception('KeyboardInterrupt')
                    #  except Exception as e:
                        #  print("0x{:x} {} failed (Exception: {})".format(vtableLoc, className, str(e)))
                        #  raise e
                        #  pass
                else:
                    __classes_completed.add(className)
                    # redone.append(className)
                    if isinstance(ea, str):
                        print("0x{} bad vtableLoc for {}".format(ea, className))
                    else:
                        print("0x{:x} bad vtableLoc for {}".format(ea, className))
            else:
                print("0x{:x} already done {}".format(ea, className))
                if className in redone:
                    print("redone")
                if className in __classes_completed:
                    print("__classes_completed")
                if vtableOnly:
                    print("vtableOnly")


def LocByUnmangledName(name, vtable=False, ea=None):
    if vtable:
        if '__for__' in name:
            # ??_7CScriptEntityExtension@@6BCGameScriptHandlerObject@@@
            # CScriptEntityExtension::`vftable'{for `CGameScriptHandlerObject'}
            # CScriptEntityExtension__for__CGameScriptHandlerObject
            name = name.replace('__for__', "::`vftable'{for `") + "'}"
        else:
            name += "::`vftable'"
    l = [y for y in idautils.Names() if Demangle(y[1], DEMNAM_FIRST) == name]
    if len(l):
        if ea and ea in l:
            return ea
        #  print("LocByUnmangledName found: {}".format(l))
        return l[0][0]
    print("LocByAnyName not found: {}".format(name))
    return BADADDR

def LocByAnyName(name, vtable=False, ea=None):
    if isinstance(name, (int, long)):
        return name
        
    if vtable:
        return LocByUnmangledName(name, vtable=vtable, ea=ea)
    ea = get_name_ea_simple(name)
    #  print("LocByAnyName found: {}".format(ea))
    if ea == BADADDR:
        return LocByUnmangledName(name, vtable=vtable)
    return ea



def VtableLocs():
    l = [y for y in idautils.Names() if y[1].startswith("??_7")]
    if (len(l)):
        return [x[0] for x in l]

def ClassMakerFullAuto(redo = False, vtableOnly=False):
    try:
        if redo:
            for fn in idautils.Names():
                Commenter(fn[0], 'line').remove('[CLASS-MAKER]')
        if redo or vtableOnly:
            with JsonStoredSet('classmaker-complete.json') as __classes_completed:
                while len(__classes_completed):
                    __classes_completed.pop()
            print("Wiped __class_maker_struct in classmaker-complete.json")
            with JsonStoredSet('classmaker-complete.json') as __classes_completed:
                print("It's length is now {}".format(len(__classes_completed)))

        for ea in VtableLocs():
            ClassMakerFamily(ea=ea, redo=redo, vtableOnly=vtableOnly)
    except KeyboardInterrupt:
        return

def ClassCopy(start=None, end=None):
    """
    ClassCopy

    @param ea: linear address
    """
    start = start or ms()
    end = end or me()
    ea = ms()
    result = []
    offset = start

    def append(_offset, _type, _value):
        result.append([_offset, _type, _value])

    # append(ea, "type", idc.get_type(ea))
    for ea in range(start, end, ptrsize()):
        ptrloc = getptr(ea)
        _name = idc.get_name(ea)
        _ptrname = idc.get_name(ptrloc)
        if _ptrname.startswith('??_R4'):
            if idc.get_extra_cmt(ea, E_PREV + (1)):
                append(ea - offset, "family", idc.get_extra_cmt(ea, E_PREV + (1)))
            offset += ptrsize()

        if re.match(r'(d[dq] offset \w)', idc.GetDisasm(ea)):
            if HasUserName(ea):
                append(ea - offset, "name", idc.get_name(ea))
            #  if _name.startswith('??_7'):
                #  append(ea - offset, "label", idc.get_name(ptrloc))
            _type = idc.get_type(ptrloc)
            if _type:
                append(ea - offset, "type", _type)
            if HasAnyName(ptrloc):
                if HasUserName(ptrloc):
                    append(ea - offset, "userlabel", idc.get_name(ptrloc))
                else:
                    append(ea - offset, "autolabel", idc.get_name(ptrloc))

    return result

def ClassPaste(j=None):
    if j is None:
        j = [   [0, 'name', '??_7rlRosHttpTask@rage@@6B@'],
        [0, 'type', 'void __fastcall(rage::rlRosHttpTask *__hidden this, char a2)'],
        [0, 'userlabel', 'rage::rlRosHttpTask::m_0'],
        [8, 'type', '__int64 __fastcall(CFileViewFilter *__hidden this)'],
        [8, 'userlabel', 'return_ptr_null_0'],
        [16, 'type', '__int64 __fastcall(rage::rlHttpTask *__hidden this)'],
        [16, 'userlabel', 'rage::rlHttpTask::Start'],
        [24, 'type', 'void __fastcall(rage::rlHttpTask *__hidden this, int a2)'],
        [24, 'userlabel', 'rage::rlHttpTask::Update'],
        [32, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [32, 'userlabel', 'return_true'],
        [40, 'type', '__int64 __fastcall(rage::sysMemAllocator *__hidden this)'],
        [40, 'userlabel', 'return_0'],
        [48, 'type', '__int64 __fastcall(rage::sysMemAllocator *__hidden this)'],
        [48, 'userlabel', 'return_0'],
        [   56,
            'type',
            'void __fastcall(rage::rlHttpTask *__hidden this, int a2, int a3)'],
        [56, 'userlabel', 'rage::rlHttpBase::GetShutdownBehaviour'],
        [   64,
            'type',
            '__int64 __fastcall(rage::rlTaskBase *__hidden this, __int64 a2)'],
        [64, 'userlabel', 'rage::rlTaskBase::Finish'],
        [72, 'type', '__int64 __fastcall(rage::rlHttpTask *__hidden this)'],
        [72, 'userlabel', 'rage::rlHttpTask::DoCancel'],
        [80, 'type', 'char __fastcall(rage::rlRosHttpTask *__hidden this)'],
        [80, 'userlabel', 'rage::rlRosHttpTask::UseHttps'],
        [   88,
            'type',
            '__int64 __fastcall(rage::rlRosHttpTask *__hidden this, __int64 a2, '
            'unsigned int a3)'],
        [88, 'userlabel', 'rage::rlRosHttpTask::GetUrlHostName'],
        [   96,
            'type',
            'char __fastcall(rage::rlRosHttpTask *this, char *a2, unsigned int '
            'a3)'],
        [96, 'userlabel', 'rage::rlRosHttpTask::GetServicePath'],
        [   104,
            'type',
            'char __fastcall(rage::rlRosHttpTask *this, char *a2, _DWORD *a3)'],
        [104, 'userlabel', 'rage::rlRosHttpTask::ProcessResponse'],
        [   112,
            'type',
            '_BYTE *__fastcall(rage::rlHttpTask *__hidden this, _BYTE *a2, '
            'unsigned int a3)'],
        [112, 'userlabel', 'rage::rlHttpTask::BuildUrl'],
        [120, 'type', '__int64 __fastcall()'],
        [120, 'userlabel', 'rage::rlRosHttpTask::GetSecurityFlags'],
        [128, 'type', 'void __fastcall(std::error_category *__hidden this)'],
        [128, 'userlabel', 'std::error_category::m_8'],
        [   136,
            'type',
            'char __fastcall(rage::rlRosHttpTask *__hidden this, __int64 a2, '
            '__int64 a3, _DWORD *a4)'],
        [136, 'userlabel', 'rage::rlRosHttpTask::m_88'],
        [   144,
            'type',
            'void __fastcall(rage::rlRosHttpTask *__hidden this, __int64 a2, '
            '__int64 a3, _DWORD *a4)'],
        [144, 'userlabel', 'rage::rlRosHttpTask::m_90'],
        [152, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [152, 'userlabel', 'return_true'],
        [160, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [160, 'userlabel', 'return_true'],
        [168, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [168, 'userlabel', 'return_true'],
        [176, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [176, 'userlabel', 'return_true'],
        [184, 'type', 'void __fastcall(rage::sysMemAllocator *__hidden this)'],
        [184, 'userlabel', 'return_true']]

    start = EA()
    # j = json.loads(data)
    for line in j:
        o, k, v = line
        ea = start + o * 2
        ptrloc = getptr(ea)
        if k == "family":
            idc.update_extra_cmt(ea, E_PREV + 0, v)
        elif k == "name":
            idc.set_name(ea, v, idc.SN_NOWARN)
        elif k == "type":
            SetType(ptrloc, v)
        elif k == "userlabel":
            idc.set_name(ptrloc, v, idc.SN_NOWARN)



