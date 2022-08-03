import os, glob, re
import json, struct, array
from glob import glob
from braceexpand import braceexpand

def isflattenable(iterable):
    return hasattr(iterable,'__iter__') and not hasattr(iterable,'isalnum')

def flatten(t):
    l = []
    try:
        for item in t:
            if isflattenable(item):
                l.extend(flatten(item))
            else:
                l.append(item)
    except TypeError:
        l.append(t)
    return l

def braced_glob(path):
    return [glob(x) for x in braceexpand(path)]    
    l = []
    for x in braceexpand(path):
        if True:
            l.append(glob(x))
    
    l = []
    for x in braceexpand(path):
        l.extend(glob(x))
            
    return l

def path_glob(path):
    return [glob(x) for x in path.split(';')]    
    l = []
    for x in braceexpand(path):
        if True:
            l.append(glob(x))
    
    l = []
    for x in braceexpand(path):
        l.extend(glob(x))
            
    return l


def qwords_from_file_sparse_using_array(ea, filename, offset, filesize):
    print("offset: {}".format(offset))
    with open(filename, "rb") as f:
        f.seek(offset, os.SEEK_SET)
        arr = array.array('B')
        arr.fromfile(f, filesize)  # Reads entire file at once.
        print("arr.fromfile: {}".format(arr))

        remain = len(arr)
        index = 0

        while remain > 7:
            q = 0
            for i in range(8):
                q <<= 8
                q |= arr[index + 7 - i]
            if q:
                #  put_qword(ea + index, q)
                yield (ea + index, q)
            index += 8
            remain -= 8

def unpack_qwords(chunk):
    remain = len(chunk)
    offset = 0
    while remain > 7:
        q = 0
        for i in range(8):
            q <<= 1
            q |= chunk[offset + i] & 0xff

        yield struct.unpack_from('Q', chunk, offset)[0]
        offset += 8
        remain -= 8

def bytes_from_file(filename, chunksize=8192):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            for q in unpack_qwords(chunk):
                yield q
            if len(chunk) < chunksize:
                break

def unpack_qwords_sparse(chunk, ea):
    remain = len(chunk)
    offset = 0
    while remain > 7:
        # q = struct.unpack_from('Q', chunk, offset)[0]
        q = 0
        for i in range(8):
            q <<= 1
            q |= ord(chunk[offset + i]) & 0xff
        if q:
            yield (ea + offset, q)
        offset += 8
        remain -= 8

def bytes_from_file_sparse(filename, chunksize=8192, ea=0):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            for q in unpack_qwords_sparse(chunk, ea=ea):
                yield q
            if len(chunk) < chunksize:
                break

def unpack_into_data_offset(ea, filename, offset, filesize):
    print("Loading: " + filename)
    # LoadFile(filename, 0, addr, size)
    
    endea = ea + filesize
    last_pct = 0
    if filesize > 5000000:
        for f in qwords_from_file_sparse_using_array(ea, filename, offset, filesize):
           ida_bytes.put_qword(f[0], f[1])
           pct = 100 * (f[0] - ea) // filesize
           if pct > last_pct:
               last_pct = pct
               print("{}%".format(pct))
    else:
        for f in qwords_from_file_sparse_using_array(ea, filename, offset, filesize):
           ida_bytes.put_qword(f[0], f[1])

def unpack_into_data(ea, filename, filesize):
    print("Loading: " + filename)
    # LoadFile(filename, 0, addr, size)
    
    # for f in bytes_from_file_sparse(filename, ea=ea):
    #  qwords_from_file_sparse_using_array(ea, filename, filesize)
    endea = ea + filesize
    last_pct = 0
    if filesize > 5000000:
        for f in qwords_from_file_sparse_using_array(ea, filename, filesize):
           ida_bytes.put_qword(f[0], f[1])
           pct = 100 * (f[0] - ea) // filesize
           if pct > last_pct:
               last_pct = pct
               print("{}%".format(pct))
    else:
        for f in qwords_from_file_sparse_using_array(ea, filename, filesize):
           ida_bytes.put_qword(f[0], f[1])


def load_valloc_files():
    skip = 0
    print("home", home)
    for filename in glob.glob(path):
        if os.path.isfile(filename): 
            if 'xxxx_valloc_7ff7a5760000_1ad48150000-1ad65350000.dmp' in filename:
                skip = 0
            else:
                skip = 1
            if skip:
                continue
            s1 = string_between_repl('7ff7a5760000_', '.dmp', filename)
            if s1:
                s2 = s1.split('-')
                if len(s2) == 2:
                    addr = int(s2[0],16)
                    size = int(s2[1],16) - addr
                    unpack_into_data(addr, filename, size)
                        
                    #  with open(filename, "rb") as f:
                    #  byte = f.read(1)
                    #  while byte != "":
                        #  # Do stuff with byte.
                        #  byte = f.read(1)

def load_datasegment():
    unpack_into_data(0x141c68000, 'h:/logs/xxxx_datasegment_7ff7a73c8000_141c68000_121b000.dmp', 0x121b000)

def unload_valloc_range(ea, size):
    if size > ea:
        size = size - ea
    end = size + ea

    while ea < end:
        addr = ida_bytes.next_head(ea, ida_ida.cvar.inf.max_ea)
        ida_bytes.del_value(ea)
        if addr < (ea + 1) or addr == BADADDR:
            ea = addr
        else:
            ea += 1

def load_valloc_range(ea, size):
    if size > ea:
        size = size - ea
    path = 'h:/logs/xxxx_valloc_7ff657b50000_*.dmp'
    idb_path = idc.get_idb_path()
    idb_path = idb_path[:idb_path.rfind(os.sep)]
    path = path + ';{}/MEM*.mem'.format(idb_path)
    filecount = 0
    for filename in _.flatten(path_glob(path)):
        if os.path.isfile(filename): 
            filecount += 1
            # MEM_18B00000000_1D200000-7ff6e2ed0000.mem
            s1 = string_between('_', '-', filename)
            if s1:
                s2 = s1.split('_')
                if len(s2) == 2:
                    addr = int(s2[0],16)
                    end = addr + int(s2[1],16)
                    filelen = end - addr
                    if ea >= addr and ea < end:
                        print("found address 0x{:x} in file {}".format(ea, filename));
                        offset = ea - addr
                        # if filelen > filesize, we should reset ea/filelen for next loop
                        unpack_into_data_offset(ea, filename, offset, min(size, filelen - offset))
                        return True
            s1 = string_between_repl('7ff657b50000_', '.dmp', filename)
            if s1:
                s2 = s1.split('-')
                if len(s2) == 2:
                    addr = int(s2[0],16)
                    end = int(s2[1],16)
                    filelen = end - addr
                    if ea >= addr and ea < end:
                        print("found address 0x{:x} in file {}".format(ea, filename));
                        offset = ea - addr
                        # if filelen > filesize, we should reset ea/filelen for next loop
                        unpack_into_data_offset(ea, filename, offset, min(size, filelen - offset))
                        return True
    print("failed to find address in {} files".format(filecount))
    return False

def load_globals():
    indexes = [int(x) for x in get_stripped_lines('e:/scripts-2060/globalIndexes.txt')]
    sizes = get_name_ea_simple("g_globals_sectionSizes")
    addrs = get_name_ea_simple("g_globals_sections")
    for i in range(64):
        count = get_wide_dword(sizes + 4 * i)
        if count:
            start = get_qword(addrs + 8 * i)
            end = start + 8 * count
            is_func
            hasAnyName
            print("load_valloc_range({}, {})".format(hex(start), end - start))
            index_start = i << 18
            index_end = index_start + count
            LabelAddressPlus(start, "Globals_{}_{}".format(index_start, index_end - 1))
            for idx in [x for x in indexes if index_start <= x < index_end]:
                LabelAddressPlus(start + ((idx - index_start) * 8), "Global_{}".format(idx))

            #  while start < end:
                #  MakeQword(start)
                #  start += 8


def Global(index):
    sizes_addr = get_name_ea_simple("g_globals_sectionSizes")
    addrs_addr = get_name_ea_simple("g_globals_sections")
    sizes = struct.unpack_from('i' * 64, idc.GetManyBytes(sizes_addr, 64 * 4))
    addresses = struct.unpack_from('Q' * 64, idc.GetManyBytes(addrs_addr, 64 * 8))
    i = (index >> 18) & 0x3f
    j = index & 0x3ffff
    if j < sizes[i]:
        return addresses[i] + j * 8

"""

00000000: 0088 0000 55e1 b1bd e821 8d41 0100 0000  ....U....!.A....
00000010: 3822 8d41 0100 0000 9822 8d41 0100 0000  8".A.....".A....
00000020: a06b a941 0100 0000 0000 0000 0000 0000  .k.A............
00000030: 2e3f 4156 6572 726f 725f 6361 7465 676f  .?AVerror_catego
00000040: 7279 4073 7464 4040 0000 0000 0000 0000  ry@std@@........
00000050: a06b a941 0100 0000 0000 0000 0000 0000  .k.A............
00000060: 2e3f 4156 5f47 656e 6572 6963 5f65 7272  .?AV_Generic_err
00000070: 6f72 5f63 6174 6567 6f72 7940 7374 6440  or_category@std@
00000080: 4000 0000 0000 0000 a06b a941 0100 0000  @........k.A....
00000090: 0000 0000 0000 0000 2e3f 4156 5f49 6f73  .........?AV_Ios
000000a0: 7472 6561 6d5f 6572 726f 725f 6361 7465  tream_error_cate
000000b0: 676f 7279 4073 7464 4040 0000 0000 0000  gory@std@@......
000000c0: a06b a941 0100 0000 0000 0000 0000 0000  .k.A............
000000d0: 2e3f 4156 5f53 7973 7465 6d5f 6572 726f  .?AV_System_erro
000000e0: 725f 6361 7465 676f 7279 4073 7464 4040  r_category@std@@
000000f0: 0000 0000 0000 0000 a06b a941 0100 0000  .........k.A....
00000100: 0000 0000 0000 0000 2e3f 4156 6677 4673  .........?AVfwFs
00000110: 6d40 7261 6765 4040 0000 0000 0000 0000  m@rage@@........
00000120: a06b a941 0100 0000 0000 0000 0000 0000  .k.A............
00000130: 2e3f 4156 6677 4170 7040 7261 6765 4040  .?AVfwApp@rage@@
00000140: 0000 0000 0000 0000 a06b a941 0100 0000  .........k.A....
00000150: 0000 0000 0000 0000 2e3f 4156 4341 7070  .........?AVCApp
00000160: 4040 0000 0000 0000 0000 0000 0000 0000  @@..............
00000170: f2a3 3f06 0000 0000 0000 0000 0000 0000  ..?.............
xxxx_datasegment_7ff7a73c8000_141c68000_121b000.dmp
xxxx_valloc_7ff7a5760000_12892e00000-12892e03000.dmp
xxxx_valloc_7ff7a5760000_19052080000-19052100000.dmp

xxxx_valloc_7ff7a5760000_1ad00000000-1ad10000000.dmp
xxxx_valloc_7ff7a5760000_1ae01762000-1ae017ff000.dmp

xxxx_valloc_7ff7a5760000_221ccd80000-221cce00000.dmp
xxxx_valloc_7ff7a5760000_24ebd180000-24ebd28a000.dmp
xxxx_valloc_7ff7a5760000_28899900000-28899980000.dmp
xxxx_valloc_7ff7a5760000_296e5400000-296e5401000.dmp
xxxx_valloc_7ff7a5760000_296e5480000-296e5483000.dmp
xxxx_valloc_7ff7a5760000_296e5484000-296e54ff000.dmp
xxxx_valloc_7ff7a5760000_296e5500000-296e5503000.dmp
xxxx_valloc_7ff7a5760000_296e5504000-296e557f000.dmp
xxxx_valloc_7ff7a5760000_296e5580000-296e5583000.dmp
xxxx_valloc_7ff7a5760000_296e5584000-296e5599000.dmp
xxxx_valloc_7ff7a5760000_296e5600000-296e5603000.dmp
xxxx_valloc_7ff7a5760000_296e5604000-296e5619000.dmp
xxxx_valloc_7ff7a5760000_296e5680000-296e5683000.dmp
xxxx_valloc_7ff7a5760000_296e5684000-296e5699000.dmp
xxxx_valloc_7ff7a5760000_2ab17300000-2ab17308000.dmp
xxxx_valloc_7ff7a5760000_2b449300000-2b449303000.dmp
xxxx_valloc_7ff7a5760000_33ac4680000-33ac46bd000.dmp
xxxx_valloc_7ff7a5760000_34df0580000-34df06ad000.dmp
xxxx_valloc_7ff7a5760000_354f2500000-354f2580000.dmp
xxxx_valloc_7ff7a5760000_38d8c000000-38d8c080000.dmp
xxxx_valloc_7ff7a5760000_3b953500000-3b953580000.dmp
xxxx_valloc_7ff7a5760000_3c409b00000-3c409b80000.dmp
xxxx_valloc_7ff7a5760000_3c52fe00000-3c52fe80000.dmp
xxxx_valloc_7ff7a5760000_3e737700000-3e737780000.dmp
xxxx_valloc_7ff7a5760000_400000-401000.dmp
xxxx_valloc_7ff7a5760000_60e70000-60e71000.dmp
xxxx_valloc_7ff7a5760000_75a8ab1000-75a8b29000.dmp
xxxx_valloc_7ff7a5760000_75a8b2c000-75a8bb0000.dmp
xxxx_valloc_7ff7a5760000_75a8c0a000-75a8c1c000.dmp
xxxx_valloc_7ff7a5760000_75a8c1e000-75a8c20000.dmp
xxxx_valloc_7ff7a5760000_75a8c2c000-75a8c2e000.dmp
xxxx_valloc_7ff7a5760000_75a8c32000-75a8c38000.dmp
xxxx_valloc_7ff7a5760000_75a8c3c000-75a8c3e000.dmp
xxxx_valloc_7ff7a5760000_75a8c40000-75a8c42000.dmp
xxxx_valloc_7ff7a5760000_75a8d0d000-75a8d10000.dmp
xxxx_valloc_7ff7a5760000_75a8d16000-75a8d1c000.dmp
xxxx_valloc_7ff7a5760000_75a8d1e000-75a8d3a000.dmp
xxxx_valloc_7ff7a5760000_75a8d3c000-75a8d3e000.dmp
xxxx_valloc_7ff7a5760000_75a8d40000-75a8d5a000.dmp
xxxx_valloc_7ff7a5760000_75a8d5e000-75a8d60000.dmp
xxxx_valloc_7ff7a5760000_75a8d68000-75a8d72000.dmp
xxxx_valloc_7ff7a5760000_75a8d74000-75a8d8c000.dmp
xxxx_valloc_7ff7a5760000_75a8d8e000-75a8da0000.dmp
xxxx_valloc_7ff7a5760000_75a8da2000-75a8da4000.dmp
xxxx_valloc_7ff7a5760000_75a8da8000-75a8df0000.dmp
xxxx_valloc_7ff7a5760000_75a8dfa000-75a8dfc000.dmp
xxxx_valloc_7ff7a5760000_75a91e8000-75a9200000.dmp
xxxx_valloc_7ff7a5760000_75a92fb000-75a9300000.dmp
xxxx_valloc_7ff7a5760000_75a93fb000-75a9400000.dmp
xxxx_valloc_7ff7a5760000_75a95dc000-75a9600000.dmp
xxxx_valloc_7ff7a5760000_75a96dc000-75a9700000.dmp
xxxx_valloc_7ff7a5760000_75a97dc000-75a9800000.dmp
xxxx_valloc_7ff7a5760000_75a98dc000-75a9900000.dmp
xxxx_valloc_7ff7a5760000_75a99dc000-75a9a00000.dmp
xxxx_valloc_7ff7a5760000_75a9adc000-75a9b00000.dmp
xxxx_valloc_7ff7a5760000_75a9bfc000-75a9c00000.dmp
xxxx_valloc_7ff7a5760000_75a9cfc000-75a9d00000.dmp
xxxx_valloc_7ff7a5760000_75a9dfc000-75a9e00000.dmp
xxxx_valloc_7ff7a5760000_75a9efc000-75a9f00000.dmp
xxxx_valloc_7ff7a5760000_75a9f80000-75aa000000.dmp
xxxx_valloc_7ff7a5760000_75aa0f8000-75aa100000.dmp
xxxx_valloc_7ff7a5760000_75aa1fb000-75aa200000.dmp
xxxx_valloc_7ff7a5760000_75aa2fb000-75aa300000.dmp
xxxx_valloc_7ff7a5760000_75aa4f0000-75aa500000.dmp
xxxx_valloc_7ff7a5760000_75aa6fc000-75aa700000.dmp
xxxx_valloc_7ff7a5760000_75aa7fe000-75aa800000.dmp
xxxx_valloc_7ff7a5760000_75aa8f8000-75aa900000.dmp
xxxx_valloc_7ff7a5760000_75aa9e0000-75aaa00000.dmp
xxxx_valloc_7ff7a5760000_75aaae0000-75aab00000.dmp
xxxx_valloc_7ff7a5760000_75aabe0000-75aac00000.dmp
xxxx_valloc_7ff7a5760000_75aace0000-75aad00000.dmp
xxxx_valloc_7ff7a5760000_75aade0000-75aae00000.dmp
xxxx_valloc_7ff7a5760000_75aaee0000-75aaf00000.dmp
xxxx_valloc_7ff7a5760000_75aaffb000-75ab000000.dmp
xxxx_valloc_7ff7a5760000_75ab0fe000-75ab100000.dmp
xxxx_valloc_7ff7a5760000_75ab1fb000-75ab200000.dmp
xxxx_valloc_7ff7a5760000_75ab2fb000-75ab300000.dmp
xxxx_valloc_7ff7a5760000_75ab5f0000-75ab600000.dmp
xxxx_valloc_7ff7a5760000_75abafc000-75abb00000.dmp
xxxx_valloc_7ff7a5760000_75abb9f000-75abc00000.dmp
xxxx_valloc_7ff7a5760000_75abc9b000-75abd00000.dmp
xxxx_valloc_7ff7a5760000_75abdfb000-75abe00000.dmp
xxxx_valloc_7ff7a5760000_75abefe000-75abf00000.dmp
xxxx_valloc_7ff7a5760000_75ac0fe000-75ac100000.dmp
xxxx_valloc_7ff7a5760000_75ac1fd000-75ac200000.dmp
xxxx_valloc_7ff7a5760000_75ac2fb000-75ac300000.dmp
xxxx_valloc_7ff7a5760000_75ac3fc000-75ac400000.dmp
xxxx_valloc_7ff7a5760000_75ac4fb000-75ac500000.dmp
xxxx_valloc_7ff7a5760000_75ac5fb000-75ac600000.dmp
xxxx_valloc_7ff7a5760000_75ac6fb000-75ac700000.dmp
xxxx_valloc_7ff7a5760000_75ac7fb000-75ac800000.dmp
xxxx_valloc_7ff7a5760000_75ac8fe000-75ac900000.dmp
xxxx_valloc_7ff7a5760000_75ac9fc000-75aca00000.dmp
xxxx_valloc_7ff7a5760000_75acafc000-75acb00000.dmp
xxxx_valloc_7ff7a5760000_75acbf0000-75acc00000.dmp
xxxx_valloc_7ff7a5760000_75acdf9000-75ace00000.dmp
xxxx_valloc_7ff7a5760000_75acee0000-75acf00000.dmp
xxxx_valloc_7ff7a5760000_75acfe0000-75ad000000.dmp
xxxx_valloc_7ff7a5760000_75ad0e0000-75ad100000.dmp
xxxx_valloc_7ff7a5760000_75ad1e0000-75ad200000.dmp
xxxx_valloc_7ff7a5760000_75ad2fb000-75ad300000.dmp
xxxx_valloc_7ff7a5760000_75ad3c0000-75ad400000.dmp
xxxx_valloc_7ff7a5760000_75ad4f8000-75ad500000.dmp
xxxx_valloc_7ff7a5760000_75ad5f8000-75ad600000.dmp
xxxx_valloc_7ff7a5760000_75ad7ff000-75ad800000.dmp
xxxx_valloc_7ff7a5760000_75adaf0000-75adb00000.dmp
xxxx_valloc_7ff7a5760000_75adbfe000-75adc00000.dmp
xxxx_valloc_7ff7a5760000_75adcfc000-75add00000.dmp
xxxx_valloc_7ff7a5760000_75addfc000-75ade00000.dmp
xxxx_valloc_7ff7a5760000_75adefc000-75adf00000.dmp
xxxx_valloc_7ff7a5760000_75adffc000-75ae000000.dmp
xxxx_valloc_7ff7a5760000_75ae0fc000-75ae100000.dmp
xxxx_valloc_7ff7a5760000_75ae1fc000-75ae200000.dmp
xxxx_valloc_7ff7a5760000_75ae2fc000-75ae300000.dmp
xxxx_valloc_7ff7a5760000_75ae3fc000-75ae400000.dmp
xxxx_valloc_7ff7a5760000_75ae4fc000-75ae500000.dmp
xxxx_valloc_7ff7a5760000_75ae5fe000-75ae600000.dmp
xxxx_valloc_7ff7a5760000_75ae6f8000-75ae700000.dmp
xxxx_valloc_7ff7a5760000_75ae7e0000-75ae800000.dmp
xxxx_valloc_7ff7a5760000_75ae8e0000-75ae900000.dmp
xxxx_valloc_7ff7a5760000_75ae9e0000-75aea00000.dmp
xxxx_valloc_7ff7a5760000_75aeae0000-75aeb00000.dmp
xxxx_valloc_7ff7a5760000_75aebfc000-75aec00000.dmp
xxxx_valloc_7ff7a5760000_75aece0000-75aed00000.dmp
xxxx_valloc_7ff7a5760000_75aede0000-75aee00000.dmp
xxxx_valloc_7ff7a5760000_75aeee0000-75aef00000.dmp
xxxx_valloc_7ff7a5760000_75aefe0000-75af000000.dmp
xxxx_valloc_7ff7a5760000_75af0e0000-75af100000.dmp
xxxx_valloc_7ff7a5760000_75af1e0000-75af200000.dmp
xxxx_valloc_7ff7a5760000_75af2ee000-75af300000.dmp
xxxx_valloc_7ff7a5760000_75af3ee000-75af400000.dmp
xxxx_valloc_7ff7a5760000_75af4ee000-75af500000.dmp
xxxx_valloc_7ff7a5760000_75af5ee000-75af600000.dmp
xxxx_valloc_7ff7a5760000_75af6ee000-75af700000.dmp
xxxx_valloc_7ff7a5760000_75af7ee000-75af800000.dmp
xxxx_valloc_7ff7a5760000_75af8ee000-75af900000.dmp
xxxx_valloc_7ff7a5760000_75af9ee000-75afa00000.dmp
xxxx_valloc_7ff7a5760000_75afaf2000-75afb00000.dmp
xxxx_valloc_7ff7a5760000_75afbfc000-75afc00000.dmp
xxxx_valloc_7ff7a5760000_75afcfc000-75afd00000.dmp
xxxx_valloc_7ff7a5760000_75afdff000-75afe00000.dmp
xxxx_valloc_7ff7a5760000_75b03fc000-75b0400000.dmp
xxxx_valloc_7ff7a5760000_75b0bf0000-75b0c00000.dmp
xxxx_valloc_7ff7a5760000_75b0cf0000-75b0d00000.dmp
xxxx_valloc_7ff7a5760000_75b0dff000-75b0e00000.dmp
xxxx_valloc_7ff7a5760000_75b0eff000-75b0f00000.dmp
xxxx_valloc_7ff7a5760000_75b0ffd000-75b1000000.dmp
xxxx_valloc_7ff7a5760000_75b10fe000-75b1100000.dmp
xxxx_valloc_7ff7a5760000_75b11ff000-75b1200000.dmp
xxxx_valloc_7ff7a5760000_75b12fe000-75b1300000.dmp
xxxx_valloc_7ff7a5760000_75b13fe000-75b1400000.dmp
xxxx_valloc_7ff7a5760000_75b1401000-75b1479000.dmp
xxxx_valloc_7ff7a5760000_75b147c000-75b1500000.dmp
xxxx_valloc_7ff7a5760000_75b15fd000-75b1600000.dmp
xxxx_valloc_7ff7a5760000_75b18fc000-75b1900000.dmp
xxxx_valloc_7ff7a5760000_75b1ffd000-75b2000000.dmp
xxxx_valloc_7ff7a5760000_75b21f7000-75b2200000.dmp
xxxx_valloc_7ff7a5760000_75b23fe000-75b2400000.dmp
xxxx_valloc_7ff7a5760000_75b24fc000-75b2500000.dmp
xxxx_valloc_7ff7a5760000_75b25fc000-75b2600000.dmp
xxxx_valloc_7ff7a5760000_75b27ff000-75b2800000.dmp
xxxx_valloc_7ff7a5760000_75b29fd000-75b2a00000.dmp
xxxx_valloc_7ff7a5760000_75b2afb000-75b2b00000.dmp
xxxx_valloc_7ff7a5760000_75b2cfe000-75b2d00000.dmp
xxxx_valloc_7ff7a5760000_7ff7a48d0000-7ff7a48d5000.dmp
xxxx_valloc_7ff7a5760000_7ff7a49d0000-7ff7a49f3000.dmp
xxxx_valloc_7ff7a5760000_7ff7a5750000-7ff7a5751000.dmp
xxxx_valloc_7ff7a5760000_7ffe0000-7ffe1000.dmp
xxxx_valloc_7ff7a5760000_c1c7600000-c1c7680000.dmp
xxxx_valloc_7ff7a5760000_d5fa400000-d5fa480000.dmp
xxxx_valloc_7ff7a5760000_d66e580000-d66e600000.dmp
xxxx_valloc_7ff7a5760000_ff3f080000-ff3f100000.dmp
"""
