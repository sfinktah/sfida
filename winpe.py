import struct, os, re, idc, ida_bytes
#  import idc
#  import idaapi
from datetime import datetime

def render_timestamp(timestamp):
    dt_object = datetime.fromtimestamp(timestamp)
    return dt_object

def list_splice(target, start, delete_count=None, *items):
    """Remove existing elements and/or add new elements to a list.
    target        the target list (will be changed)
    start         index of starting position
    delete_count  number of items to remove (default: len(target) - start)
    *items        items to insert at start index
    Returns a new list of removed items (or an empty list)

    https://gist.github.com/jonbeebe/44a529fcf15d6bda118fe3cfa434edf3
    """
    if delete_count == None:
        delete_count = len(target) - start

    # store removed range in a separate list and replace with *items
    total = start + delete_count
    removed = target[start:total]
    target[start:total] = items

    return removed

class SimpleAttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(SimpleAttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

class helper_mixin(object):
    def get_rva(self, offset):
        return self.base + offset

    def zipObject(self, keys, values):
        result = {}
        for x in zip(keys, values):
            result[x[0]] = x[1]
        return result

    def unpack(self, ea, _names, fmt):
        d = struct.unpack(fmt, ida_bytes.get_bytes(ea, struct.calcsize(fmt)))
        o = self.zipObject(_names, d)
        self._overspill = list(d[len(_names):])
        return SimpleAttrDict(o)

    def struct_elemcount(self, fmt):
        elems = [x for x in re.split(r'(\d+)(\w)', fmt) if x]
        count = 0
        while elems:
            x = elems.pop(0)
            if x.isnumeric():
                count += int(x)
                elems.pop(0)
            else:
                count += len(x)
        return count



class section_header(object):
    _packstring = '8BIIIIIIHHI'
    _packcount = 16
    _packchunk = 17
    _packinfo = [
        [ 'B', 'Name', 8, 'string' ],
        [ 'I', 'VirtualSize' ],
        [ 'I', 'VirtualAddress' ],
        [ 'I', 'SizeOfRawData' ],
        [ 'I', 'PointerToRawData' ],
        [ 'I', 'PointerToRelocations' ],
        [ 'I', 'PointerToLinenumbers' ],
        [ 'H', 'NumberOfRelocations' ],
        [ 'H', 'NumberOfLinenumbers' ],
        [ 'I', 'Characteristics' ]
    ]

    def __str__(self):
        return "{:32} {} - {}".format(self.name(), 
                hex(self.base + self.data.VirtualAddress), 
                hex(self.base + self.data.VirtualAddress + self.data.VirtualSize)) 

    def __repr__(self):
        return "<{} '{}'>".format(str(__class__)[1:-2].split('.', 2)[1], self.name())

    def __init__(self, base, data):
        self.base = base
        self.data = SimpleAttrDict()
        for i in range(len(self._packinfo)):
            if len(self._packinfo[i]) > 2:
                count = self._packinfo[i][2]
                l = []
                for unused in range(count):
                    l.append(data.pop(0))
                if len(self._packinfo[i]) > 3:
                    iteratee_name = self._packinfo[i][3]
                    fn = getattr(self, iteratee_name)
                    result = fn(l)
                else:
                    result = l
            elif self._packinfo[i][1] == 'TimeDateStamp':
                result = render_timestamp(data.pop(0))
            else:
                result = data.pop(0)

            self.data[self._packinfo[i][1]] = result

    def name(self):
        return self.data.Name

    def empty(self):
        return self.data.VirtualSize == 0 and self.data.VirtualAddress == 0

    def string(self, data):
        return ''.join([chr(x) for x in data]).rstrip('\0')

class data_directory(helper_mixin, section_header):
    _names = [
        "Export Directory", "Import Directory", "Resource Directory",
        "Exception Directory", "Security Directory", "Base Relocation Table",
        "Debug Directory", "Architecture Specific Data", "RVA of GP", 
        "TLS Directory", "Load Configuration Directory", 
        "Bound Import Directory", "Import Address Table", 
        "Delay Load Import Descriptors", "COM Runtime descriptor"
    ]
    _packstring = 'II'
    _packcount = 16
    _packchunk = 2
    _packinfo = [
        [ 'I', 'VirtualAddress' ],
        [ 'I', 'Size' ],
    ]

    def __init__(self, base, data, number):
        # print("[data_directory] base:{:x}, data:{}, number:{}, name:{}".format(base, data, number, self._names[min(number, len(self._names) - 1)]))
        super(data_directory, self).__init__(base, data)
        if number < len(self._names):
            self.data.Name = self._names[number]
            if self.data.Name == "Debug Directory":
                fmt = debug_directory_entries._packstring
                fmtsize = struct.calcsize(fmt)
                count = self.data.Size // fmtsize
                self.data.entries = []
                for i in range(count):
                    d = list(struct.unpack(fmt, ida_bytes.get_bytes(self.get_rva(self.data.VirtualAddress) + i * fmtsize, fmtsize)))
                    self.data.entries.append(debug_directory_entries(self.base, d, 0))
        else:
            self.data.Name = 'Unknown'

    def __str__(self):
        return "{:32} {} - {}".format(self.name(), 
                hex(self.base + self.data.VirtualAddress), 
                hex(self.base + self.data.VirtualAddress + self.data.Size)) 

    def empty(self):
        return self.data.Size == 0 and self.data.VirtualAddress == 0

class debug_directory_entries(helper_mixin, section_header):
    """
    typedef struct _IMAGE_DEBUG_DIRECTORY {
            DWORD Characteristics;
            DWORD TimeDateStamp;
            WORD  MajorVersion;
            WORD  MinorVersion;
            DWORD Type;
            DWORD SizeOfData;
            DWORD AddressOfRawData;
            DWORD PointerToRawData;
    } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
    """

    _names = [ "IMAGE_DEBUG_TYPE_UNKNOWN",       "IMAGE_DEBUG_TYPE_COFF",
               "IMAGE_DEBUG_TYPE_CODEVIEW",      "IMAGE_DEBUG_TYPE_FPO",
               "IMAGE_DEBUG_TYPE_MISC",          "IMAGE_DEBUG_TYPE_EXCEPTION",
               "IMAGE_DEBUG_TYPE_FIXUP",         "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
               "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", "IMAGE_DEBUG_TYPE_BORLAND",
               "IMAGE_DEBUG_TYPE_RESERVED10",    "IMAGE_DEBUG_TYPE_CLSID",
               "IMAGE_DEBUG_TYPE_VC_FEATURE",    ]

    _packcount = 7 * 4
    _packchunk = 2
    _packinfo = [
        [ 'I', 'Characteristics' ],
        [ 'I', 'TimeDateStamp' ],
        [ 'H', 'MajorVersion' ],
        [ 'H', 'MinorVersion' ],
        [ 'I', 'Type' ],
        [ 'I', 'SizeOfData' ],
        [ 'I', 'AddressOfRawData' ],
        [ 'I', 'PointerToRawData' ],
    ]
    _pack_names = [x[1] for x in _packinfo]
    _packstring = ''.join([x[0] for x in _packinfo])

    def __init__(self, base, data, number):
        super(debug_directory_entries, self).__init__(base, data)
        number = self.data.Type
        if number < len(self._names):
            self.data.Name = self._names[number]
            if self.data.Name == 'IMAGE_DEBUG_TYPE_CODEVIEW':
                fmt = debug_information_codeview._packstring(self.data.SizeOfData)
                fmtsize = struct.calcsize(fmt)
                count = 1
                self.data.entries = []
                for i in range(count):
                    d = list(struct.unpack(fmt, ida_bytes.get_bytes(self.get_rva(self.data.AddressOfRawData) + i * fmtsize, fmtsize)))
                    self.data.entries.append(debug_information_codeview(self.base, d, self.data.SizeOfData))
        else:
            self.data.Name = 'Unknown'

    def __str__(self):
        return "{:32} {} - {}".format(self.name(), 
                hex(self.base + self.data.VirtualAddress), 
                hex(self.base + self.data.VirtualAddress + self.data.Size)) 

    def empty(self):
        return self.data.Size == 0 and self.data.VirtualAddress == 0

class debug_information_codeview(helper_mixin, section_header):
    """
    (['CVSig', 'GUID', 'PdbFileName'], '4s(IHH8B)256s')
    """
    _packcount = 7 * 4
    _packchunk = 2
    _packinfo = [
        [ 'B',     'CVSig',       4,    'string' ],
        [ 'IHH8B', 'GUID',        1,    'GUID'   ],
        [ 'I',     'Age'                         ],
        [ 'B',     'PdbFileName', -256, 'string' ],
    ]
    _pack_names = [x[1] for x in _packinfo]

    def _packstring(size):
        _packstring_fixed = '4BIHH8B'
        remain = size - struct.calcsize(_packstring_fixed)
        return '{}{}B'.format(_packstring_fixed, remain)

    def _pop(self, l):
        return l.pop(0)

    def _shift_factory(self, elemcount):
        def _pop(l):
            return list_splice(l, 0, elemcount)
        return _pop

    def GUID(self, data):
        result = SimpleAttrDict()
        result.Data1 = data[0]
        result.Data2 = data[1]
        result.Data3 = data[2]
        result.Data4 = data[3:]
        return result

    def __init__(self, base, data, size):
        #  super(debug_information_codeview, self).__init__(base, data)
        self.base = base
        self.data = SimpleAttrDict()
        self.data.Name = 'CodeView'
        for i in range(len(self._packinfo)):
            pop = self._pop
            elemcount = self.struct_elemcount(self._packinfo[i][0])
            
            if elemcount > 1:
                pop = self._shift_factory(elemcount)

            if len(self._packinfo[i]) > 2:
                count = self._packinfo[i][2]
                l = []
                if count > 0:
                    for unused in range(count):
                        l.append(pop(data))
                else:
                    l = data

                if count == 1:
                    l = l[0]

                if len(self._packinfo[i]) > 3:
                    iteratee_name = self._packinfo[i][3]
                    fn = getattr(self, iteratee_name)
                    result = fn(l)
                else:
                    result = l
            elif self._packinfo[i][1] == 'TimeDateStamp':
                result = render_timestamp(pop(data))
            else:
                result = pop(data)

            self.data[self._packinfo[i][1]] = result


    def __str__(self):
        return "yeah"
        #  return "{:32} {} - {}".format(self.name(), 
                #  hex(self.base + self.data.VirtualAddress), 
                #  hex(self.base + self.data.VirtualAddress + self.data.Size)) 

    def empty(self):
        return self.data.Size == 0 and self.data.VirtualAddress == 0


class WinPE(helper_mixin, object):
    """
    example usage:

        w = WinPE(64)
        print(w.nt.SizeOfCode)
        print(w.dos.e_lfanew)
        print(w.get_rva(w.nt.BaseOfCode))
    """

    _nt_nam_32 = [ "Signature", "Machine", "NumberOfSections",
        "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols",
        "SizeOfOptionalHeader", "Characteristics", "Magic", "MajorLinkerVersion",
        "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData",
        "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode",
        "BaseOfData", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
        "MinorSubsystemVersion", "Win32VersionValue", "SizeOfImage",
        "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve",
        "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes" ]
    _nt_nam_64 = _nt_nam_32[:]
    _nt_nam_64.remove('BaseOfData')
    _dos_nam = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr',
        'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs',
        'e_lfarlc', 'e_ovno', 'e_res_0', 'e_res_1', 'e_res_2', 'e_res_3',
        'e_oemid', 'e_oeminfo', 'e_res2_0', 'e_res2_1', 'e_res2_2', 'e_res2_3',
        'e_res2_4', 'e_res2_5', 'e_res2_6', 'e_res2_7', 'e_res2_8', 'e_res2_9',
        'e_lfanew' ]
    _dos_fmt = 'HHHHHHHHHHHHHH4HHH10Hi'
    _sig_fmt = 'I'
    _img_fmt = 'HHIIIHH'
    _dir_fmt = data_directory._packstring * data_directory._packcount
    _sec_fmt = section_header._packstring * section_header._packcount

    _nt_fmt_32 = _sig_fmt + _img_fmt + "HBBIIIIIIIIIHHHHHHIIIIHHIIIIII" \
            + _dir_fmt + _sec_fmt
    _nt_fmt_64 = _sig_fmt + _img_fmt + "HBBIIIIIQIIHHHHHHIIIIHHQQQQII"  \
            + _dir_fmt + _sec_fmt

    def __init__(self, bits=64, base=None):
        if bits not in (32, 64):
            raise RuntimeError("bits must be 32 or 64")
        if base is None:
            base = idc.MinEA() # idaapi.cvar.inf.min_ea

        self.bits = bits
        self.base = base
        self.dos = self.unpack(self.get_rva(0), self._dos_nam, self._dos_fmt)

        if self.dos.e_magic != 0x5A4D:
            raise ValueError("Invalid Magic: {:x}".format(self.dos.e_magic))


        self.nt  = self.unpack(
                self.get_rva(self.dos.e_lfanew),
                getattr(self, "_nt_nam_%i" % bits),
                getattr(self, "_nt_fmt_%i" % bits))

        t2s = data_directory._packcount * data_directory._packchunk
        t4s = section_header._packcount * section_header._packchunk

        self.dirs = [y for y in [data_directory(base, x[1], x[0])     \
                for x in enumerate(chunk_list(self._overspill[0:t2s], \
                data_directory._packchunk))]                          \
                if not y.empty()]

        self.sections = [y for y in [section_header(base, x)          \
                for x in chunk_list(self._overspill[t2s:t2s+t4s],     \
                section_header._packchunk)]                           \
                if not y.empty()]

        self.end  = self.base + self.nt.SizeOfCode;
        self.size = self.nt.SizeOfImage;

def winpe_test():
    pe = WinPE(32)
    print("-- DOS Header --")
    for k, s in pe.dos.items(): print("{:32} {}".format(k, hex(s)))
    print("-- NT Header --")
    for k, s in pe.nt.items(): print("{:32} {}".format(k, hex(s)))
    print("-- Directories --")
    for s in pe.dirs: print(s)
    print("-- Segments --")
    for s in pe.sections: print(s)

def chunk_list(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

#  pe = WinPE(64)
