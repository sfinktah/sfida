__version_hash__ = "7c810857dd1c96633305b8d552a1b462"
__version_info__ = (0, 0, 19)
__version__ = ",".join(map(lambda x: str(x), __version_info__))

# &
# &.update_file(__file__, __version_hash__, __version_info__)
import re


# NativeRegistration** GetRegistrationTable()
# {
#   if (!dwRegistrationTablePtr) {
#       dwRegistrationTablePtr = Pattern::Scan(g_MainModuleInfo, "76 61 49 8B 7A 40 48 8D 0D");
# 
#       if (!dwRegistrationTablePtr) {
#           Log::Fatal("Unable to find Native Registration Table");
#       }
# 
#       dwRegistrationTablePtr += 6;
# 
#       DWORD64 dwAddressOfRegistrationTable = dwRegistrationTablePtr + *(DWORD*)(dwRegistrationTablePtr + 3) + 7;
# 
#       if (!dwAddressOfRegistrationTable ||
#           dwAddressOfRegistrationTable < (DWORD64)g_MainModuleInfo.lpBaseOfDll ||
#           dwAddressOfRegistrationTable >(DWORD64) g_MainModuleInfo.lpBaseOfDll + g_MainModuleInfo.SizeOfImage) {
#           Log::Fatal("Error reading Native Registration Table opcode (0x%I64X)", dwAddressOfRegistrationTable);
#       }
# 
#       dwRegistrationTablePtr = dwAddressOfRegistrationTable;
#       DEBUGOUT("dwRegistrationTablePtr = 0x%I64X", dwRegistrationTablePtr);
#   }
# 
#   return (NativeRegistration**)dwRegistrationTablePtr;
# }


# Not that I have tested this, but the location you need to label can be found in IDA via:
# idc.jumpto(FindBinary(0, SEARCH_DOWN | SEARCH_CASE, "76 61 49 8B 7A 40 48 8D 0D") + 6)
# Label it NativeRegistrationTable -- sfink


def MakeNativeHashBucketListInit():
    # Set up NativeRegistration struct if it doesn't exist
    id = idc.get_struc_id("NativeRegistration")
    if id == BADADDR:
        idc.begin_type_updating(UTP_STRUCT)

        id = idc.add_struc(-1,"NativeRegistration",0);

        id = idc.get_struc_id("NativeRegistration");
        mid = AddStrucMember(id,"nextRegistration",	0,	0x35500400,	0XFFFFFFFFFFFFFFFF,	8,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
        mid = AddStrucMember(id,"handler",	0X8,	0x35500400,	0XFFFFFFFFFFFFFFFF,	56,	0XFFFFFFFFFFFFFFFF,	0,	0x000009);
        mid = AddStrucMember(id,"numEntries",	0X40,	0x20000400,	-1,	4);
        mid = AddStrucMember(id,"__",	0X44,	0x20000400,	-1,	4);
        mid = AddStrucMember(id,"hash",	0X48,	0x30000400,	-1,	56);

        id = idc.get_struc_id("NativeRegistration");
        mid = AddStrucMember(id,"nextRegistration", 0,  0x35500400, 0XFFFFFFFFFFFFFFFF, 8,  0XFFFFFFFFFFFFFFFF, 0,  0x000009)
        # Hopefully this isn't something that needs to be run outside of this setup 
        #           to be able to reference NativeRegistration
        idc.SetType(idc.get_member_id(id, 0x0), "NativeRegistration *")
        # idc.SetType(idc.get_member_id(id, 0x0), "#355 *");
        idc.SetType(idc.get_member_id(id, 0x8), "void *[7]");
        idc.SetType(idc.get_member_id(id, 0x40), "int");
        idc.SetType(idc.get_member_id(id, 0x44), "int");

        
        idc.end_type_updating(UTP_STRUCT)


    #  if idc.get_name_ea_simple("NativeRegistrationTable") == BADADDR:
        #  dwRegistrationTablePtr = FindBinary(0, SEARCH_DOWN | SEARCH_CASE, "76 61 49 8B 7A 40 48 8D 0D") + 6
        #  dwAddressOfRegistrationTable = dwRegistrationTablePtr + idc.get_wide_dword(dwRegistrationTablePtr + 3) + 7
        #  idc.set_name(dwAddressOfRegistrationTable, "NativeRegistrationTable", 0)
        #  idc.jumpto(dwRegistrationTablePtr)
    #  else:
        #  idc.jumpto(idc.get_name_ea_simple("NativeRegistrationTable"))

    dwRegistrationTablePtr = FindBinary(0, SEARCH_DOWN | SEARCH_CASE, "76 61 49 8B 7A 40 48 8D 0D") + 6
    if dwRegistrationTablePtr == BADADDR:
        print("Failed to locate NativeRegistrationTable AOB")
    else:
        dwAddressOfRegistrationTable = dwRegistrationTablePtr + idc.get_wide_dword(dwRegistrationTablePtr + 3) + 7
        idc.set_name(dwAddressOfRegistrationTable, "NativeRegistrationTable", 0)
        idc.MakeQword(idc.get_name_ea_simple('NativeRegistrationTable'))
        # idc.jumpto(idc.get_name_ea_simple("NativeRegistrationTable"))

    hashes = processBucketLists(idc.get_name_ea_simple("NativeRegistrationTable"))
    print("hashes = processBucketLists(idc.get_name_ea_simple('NativeRegistrationTable')) - Done.")

    dic = {}
    for item in hashes:
        key = item[0]
        data = dict(zip(['name', 'address', 'hash'], item))
        dic[key] = data

    hashDict = dic
    print("dictionary is hashDict")


def makeBucketList(nextStruct):
    totalCount = 0
    nativeFunctions = []
    while nextStruct:
        if not idc.is_struct(idc.get_full_flags(nextStruct)):
            idc.MakeUnknown(nextStruct, 0x80, 1)
            if not idc.MakeStruct(nextStruct, "NativeRegistration"):
                print("Failed to convert location %012x into NativeRegistration" % nextStruct)
                break
        count = idc.get_wide_byte(nextStruct+8*8)
        for i in xrange(1, count + 1):
            ptr = nextStruct + 8 * i
            ea = autobase(idc.get_qword(ptr))
            # obfu.comb(ea, 1024)
            attempts = 10
            try:
                while attempts > 0 and slowtrace2(ea, "/dev/null", 0):
                    attempts -= 1
            except KeyboardInterrupt:
                print("\n*** Aborted by User ***")
                return
            except:
                pass
            name = idc.Name(ea)
            hash = "%016x" % (idc.get_qword(ptr + 64))
            if name == '' or idaapi.has_dummy_name(idc.get_full_flags(ea)):
                name = "____0x%s" % (hash)
                if not idc.set_name(ea, name, 0):
                    idc.MakeUnknown(ea, 5, DOUNK_DELNAMES)
                    forceAsCode(ea, 5)
                    idc.set_name(ea, name, 0)
            print("makeBucketList: 0x%0x '%s' (%s)" % (ea, name, hash))
            nativeFunctions.append([name, ea, hash])
        nextStruct = idc.get_qword(nextStruct)

    return nativeFunctions

def processBucketLists(ea, count = 256):
    totalCount = 0
    nativeFunctions = []
    for i in xrange(count):
        # idc.MakeQword(ea + i * 8)
        # Make a 256 array of the fuqers
        nextStruct = idc.get_qword(ea + i * 8)
        if not nextStruct:
            print("No more buckets to make at count %i" % count)
            break
        nativeFunctions.extend(makeBucketList(nextStruct))

    print("Found %i native functions" % nativeFunctions.__len__())
    return nativeFunctions

def fileSafeName(name):
    safe_string = str()
    for c in name:
        if c.isalnum() or c in ['_','-']:
            safe_string = safe_string + c
        else:
            safe_string = safe_string + "_"
    return safe_string

def _camelcase27(value):
    def camelcase(): 
        yield str.lower
        while True:
            yield str.capitalize

    c = camelcase()
    return "".join(c.next()(x) 
            if x else '_' 
            for x in value.split("_"))


def NativeFunctionHashBucketSlowtrace(d):
    # idc.get_name_ea_simple("__ImageBase")
    # r = processBucketLists(idc.get_name_ea_simple('NativeRegistrationTable'))
    # d = dir(r)
    for k in d.viewkeys():
        # if len(k) and k[0] == 's':
        if len(k):
            fnFull = k
            fnOnly = re.sub(r".*(__|::)", "", fnFull)
            if not fnOnly:
                print("couldn't get function name from %s" % fnFull)
            fnCamel = camelcase(fnOnly)

            fnLoc = idc.get_name_ea_simple(fnFull)
            if (fnLoc == BADADDR):
                fnLoc = idc.get_name_ea_simple(fnFull.replace("__", "::", 1))
            if (fnLoc < BADADDR):
                # print("Tracing NativeFunction at %s / 0x%x" % (k, fnLoc))
                if not forceAsCode(fnLoc, 5):
                    print("%012x: Error making code" % fnLoc)
                    continue
                if (idc.get_wide_byte(fnLoc) == 0xE9 or idc.get_wide_byte(fnLoc) == 0xE8):
                    # turn initial JMP into CALL
                    #  idc.patch_byte(fnLoc, 0xE8) 
                    # idc.patch_byte(fnLoc + 5, 0xc3) 
                    #  if not forceAsCode(fnLoc, 6):
                        #  print("%012x: Error making code (2)" % fnLoc)
                        #  continue
                    idc.add_func(fnLoc, fnLoc + 5)
                    target = idc.get_operand_value(fnLoc, 0)
                    idc.add_func(target)
                    fnFlags = idaapi.get_flags(fnLoc)
                    if idaapi.has_dummy_name(fnFlags):
                        # idc.jumpto(fnLoc)
                        newFunctionName = "j_%s" % fnCamel
                        if not idc.MakeName(target, newFunctionName):
                            print("%012x: Couldn't name as %s" % newFunctionName)
                            continue
                    targetType = idc.get_type(target)
                    if targetType is not None and "()" in targetType:
                        idc.SetType(target, targetType.replace("()", "(scrNativeCallContext *scrArgs)"))
                if fnFull[0] != 's':
                    comment = "[TEST] used by %s" % fnFull
                else:
                    comment = None
                # slowtrace2(fnLoc, fileSafeName(k + "-" + d[k]['hash']) + ".lst", 5, comment)
                print("Tracing %s" % fnFull)
                traceOptions = {
                        "comment": comment,
                        "stopAtCall": False,
                        "labelNextFunction": fnCamel,
                        }
                slowtrace2(fnLoc, "/dev/null", 0); # , traceOptions)
                #  slowtrace2(fnLoc, fileSafeName(fnFull + "-" + d[k]['hash']) + ".lst", 5, traceOptions)
            else:
                print("fn: %s loc: %s" % (fnNull, fnLoc))

def slowtrace_natives():
    NativeFunctionHashBucketSlowtrace(hashDict)

