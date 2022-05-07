import re, xmltodict

from exectools import make_refresh
refresh_structmaker = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
###
# HOW TO USE:
#   open function in decompiler, set type/name of variable representing struct
#   to `__int64 self`. remember to map `v1` or similar as required.
#
#   execute `StructMaker(idc.ScreenEA(), "CStruct")` (replacing CStruct with w/e)
#
#   change type/name of variable representing struct to `CStruct* self` and
#   repeat previous procedure.
#
#   repeat both procedures in other functions to refine the definition.
#
#   in case of issues, try decompiling again by pressing F5
###

###
# TODO:
#   ~find better way to set struct type, probably by removing following members
#   that prevent simply creating a QWORD (it won't let you, if there isn't
#   enough room in the struct)~ **done**
#
#   treat unaligned QWORD (e.g. at 0x04) as being 2 x DWORD being initialised
#   quickly?
#
#   ~do something with the undefined gaps that are created when a QWORD is
#   shrunk to a smaller type~ **done**
#
#   rename matched fields `SetMemberName` to dword_02c or somesuch **huh?**
#
#   ~read the decompiled function ourselves~ **done**
#
#   ~create the initial struct ourselves~ **done**
###

def line_split(foo): return iter(foo.splitlines())

if '__typedefs' not in globals():
    __typedefs = dict()
__typedefs = dict()

__typedefs_h = """
// wierd things seen in snowman
typedef bool int1_t

// stdpokey.h
#define CONST const
#define FAR far
#define NEAR near
#define VOID void
typedef char *PSZ;
typedef BOOL far *LPBOOL;
typedef BOOL near *PBOOL;
typedef BOOLEAN *PBOOLEAN;
typedef BYTE BOOLEAN;
typedef BYTE far *LPBYTE;
typedef BYTE near *PBYTE;
typedef CONST void far *LPCVOID;
typedef DWORD far *LPDWORD;
typedef DWORD near *PDWORD;
typedef FLOAT *PFLOAT;
typedef UCHAR *PUCHAR;
typedef ULONG *PULONG;
typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
typedef USHORT *PUSHORT;
typedef WORD far *LPWORD;
typedef WORD near *PWORD;
typedef __PTRDIFF_TYPE__ intptr_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __PTRDIFF_TYPE__ ssize_t;
typedef __SIZE_TYPE__ size_t;
typedef __SIZE_TYPE__ uintptr_t;
typedef __WCHAR_TYPE__ wchar_t;
typedef __int64 __time64_t;
typedef __int64 INT_PTR, *PINT_PTR;
typedef __int64 LONG64, *PLONG64;
typedef __int64 LONG_PTR, *PLONG_PTR;
typedef __int64_t int64_t;
typedef __uint64_t uint64_t;
typedef char CHAR;
typedef float FLOAT;
typedef int errno_t;
typedef int BOOL;
typedef int INT;
typedef int INT;
typedef int INT;
typedef int far *LPINT;
typedef int near *PINT;
typedef long __time32_t;
typedef long LONG;
typedef long far *LPLONG;
typedef short SHORT;
typedef signed __int64 INT64, *PINT64;
typedef signed char INT8, *PINT8;
typedef signed char int8_t;
typedef signed int INT32, *PINT32;
typedef signed int LONG32, *PLONG32;
typedef signed int int32_t;
typedef signed short INT16, *PINT16;
typedef signed short int int16_t;
typedef unsigned __int64 UINT64, *PUINT64;
typedef unsigned __int64 DWORD64, *PDWORD64;
typedef unsigned __int64 UINT_PTR, *PUINT_PTR;
typedef unsigned __int64 ULONG64, *PULONG64;
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
typedef unsigned char BYTE;
typedef unsigned char UINT8, *PUINT8;
typedef unsigned char UCHAR;
typedef unsigned char uint8_t;
typedef unsigned int *PUINT;
typedef unsigned int *PUINT;
typedef unsigned int UINT32, *PUINT32;
typedef unsigned int UINT;
typedef unsigned int UINT;
typedef unsigned int DWORD32, *PDWORD32;
typedef unsigned int ULONG32, *PULONG32;
typedef unsigned int uint32_t;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned short wctype_t;
typedef unsigned short wint_t;
typedef unsigned short UINT16, *PUINT16;
typedef unsigned short WORD;
typedef unsigned short USHORT;
typedef unsigned short int uint16_t;
typedef void far *LPVOID;


// stdint.h
typedef int int32_t;
typedef int int_fast16_t;
typedef int int_fast32_t;
typedef int int_least32_t;
typedef long long int64_t;
typedef long long int_fast64_t;
typedef long long int_least64_t;
typedef long long intmax_t;
typedef short int16_t;
typedef short int_least16_t;
typedef signed char int8_t;
typedef signed char int_fast8_t;
typedef signed char int_least8_t;
typedef unsigned char uint8_t;
typedef unsigned char uint_fast8_t;
typedef unsigned char uint_least8_t;
typedef unsigned int uint32_t;
typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;
typedef unsigned int uint_least32_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uint_fast64_t;
typedef unsigned long long uint_least64_t;
typedef unsigned long long uintmax_t;
typedef unsigned short uint16_t;
typedef unsigned short uint_least16_t;

// basestd.h
#define POINTER_64 __ptr64
#define POINTER_32 __ptr32
#define POINTER_32
#define POINTER_64 __ptr64
#define POINTER_64 __ptr64
#define POINTER_64
#define POINTER_32
#define FIRMWARE_PTR
#define POINTER_SIGNED __sptr
#define POINTER_UNSIGNED __uptr
#define POINTER_SIGNED
#define POINTER_UNSIGNED
#define SPOINTER_32 POINTER_SIGNED POINTER_32
#define UPOINTER_32 POINTER_UNSIGNED POINTER_32
#define _W64 __w64
#define _W64
#define __int3264   __int64
#define ADDRESS_TAG_BIT 0x40000000000UI64
typedef unsigned __int64 POINTER_64_INT;
typedef unsigned __int64 POINTER_64_INT;
typedef unsigned long POINTER_64_INT;
typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed __int64      INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned __int64    UINT64, *PUINT64;
typedef signed int LONG32, *PLONG32;
typedef unsigned int ULONG32, *PULONG32;
typedef unsigned int DWORD32, *PDWORD32;
typedef __int3264 INT_PTR, *PINT_PTR;
typedef unsigned __int3264 UINT_PTR, *PUINT_PTR;
typedef __int3264 LONG_PTR, *PLONG_PTR;
typedef unsigned __int3264 ULONG_PTR, *PULONG_PTR;
typedef __int64 INT_PTR, *PINT_PTR;
typedef unsigned __int64 UINT_PTR, *PUINT_PTR;
typedef __int64 LONG_PTR, *PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
typedef __int64 SHANDLE_PTR;
typedef unsigned __int64 HANDLE_PTR;
typedef unsigned int UHALF_PTR, *PUHALF_PTR;
typedef int HALF_PTR, *PHALF_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef LONG_PTR SSIZE_T, *PSSIZE_T;
typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
typedef __int64 LONG64, *PLONG64;
typedef unsigned __int64 ULONG64, *PULONG64;
typedef unsigned __int64 DWORD64, *PDWORD64;
typedef ULONG_PTR KAFFINITY;
typedef KAFFINITY *PKAFFINITY;

// minwindef.h
typedef unsigned long ULONG;
typedef ULONG* PULONG;
typedef unsigned short USHORT;
typedef USHORT* PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR* PUCHAR;
typedef _Null_terminated_ char* PSZ;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef float FLOAT;
typedef FLOAT* PFLOAT;
typedef BOOL near* PBOOL;
typedef BOOL far* LPBOOL;
typedef BYTE near* PBYTE;
typedef BYTE far* LPBYTE;
typedef int near* PINT;
typedef int far* LPINT;
typedef WORD near* PWORD;
typedef WORD far* LPWORD;
typedef long far* LPLONG;
typedef DWORD near* PDWORD;
typedef DWORD far* LPDWORD;
typedef void far* LPVOID;
typedef CONST void far* LPCVOID;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned int* PUINT;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef LONG_PTR LRESULT;
typedef HANDLE NEAR* SPHANDLE;
typedef HANDLE FAR* LPHANDLE;
typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;
typedef HANDLE GLOBALHANDLE;
typedef HANDLE LOCALHANDLE;
typedef INT_PTR(FAR WINAPI* FARPROC)();
typedef INT_PTR(NEAR WINAPI* NEARPROC)();
typedef INT_PTR(WINAPI* PROC)();
typedef int(FAR WINAPI* FARPROC)();
typedef int(NEAR WINAPI* NEARPROC)();
typedef int(WINAPI* PROC)();
typedef int(CALLBACK* FARPROC)();
typedef int(CALLBACK* NEARPROC)();
typedef int(CALLBACK* PROC)();
typedef INT_PTR(WINAPI* FARPROC)(void);
typedef INT_PTR(WINAPI* NEARPROC)(void);
typedef INT_PTR(WINAPI* PROC)(void);
typedef WORD ATOM;  // BUGBUG - might want to remove this from minwin
typedef HKEY* PHKEY;
typedef HINSTANCE HMODULE; /* HMODULEs can be used in place of HINSTANCEs */
typedef int HFILE;
typedef short HFILE;

// ida_defs.h
typedef __int64 ll;
typedef unsigned __int64 ull;
typedef long long ll;
typedef unsigned long long ull;
#define __int64 long long
#define __int32 int
#define __int16 short
#define __int8 char
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
#define _QWORD uint64
#define BYTE  uint8
#define WORD  uint16
#define DWORD uint32
#define QWORD uint64
#define _LONGLONG __int128

#define _OWORD __int128

typedef long long ll;
typedef unsigned long long ull;
typedef __int64 ll;
typedef unsigned __int64 ull;
typedef __int64 ll;
typedef unsigned __int64 ull;
typedef __int64 ll;
typedef unsigned __int64 ull;
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef char int8;
typedef signed char sint8;
typedef unsigned char uint8;
typedef short int16;
typedef signed short sint16;
typedef unsigned short uint16;
typedef int int32;
typedef signed int sint32;
typedef unsigned int uint32;
typedef ll int64;
typedef ll sint64;
typedef ull uint64;
typedef int8 _BOOL1;
typedef int16 _BOOL2;
typedef int32 _BOOL4;
typedef int32 LONG;
typedef int BOOL;  // uppercase BOOL is usually 4 bytes

// ida header export
#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long
typedef struct _GUID GUID;
typedef unsigned __int32 DWORD;
typedef unsigned __int64 ULONG_PTR;
typedef __int32 LONG;
typedef char CHAR;
typedef unsigned __int32 ULONG;
typedef HWND__ *HWND;
typedef const CHAR *LPCSTR;
typedef HINSTANCE__ *HINSTANCE;
typedef HKEY__ *HKEY;
typedef void *HANDLE;
typedef _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;
typedef unsigned __int16 WORD;
typedef _LIST_ENTRY LIST_ENTRY;
typedef unsigned __int16 wchar_t;
typedef wchar_t WCHAR;
typedef unsigned __int64 ULONGLONG;
typedef __int64 LONGLONG;
typedef unsigned __int64 DWORD64;
typedef unsigned __int8 BYTE;
typedef _XSAVE_FORMAT XSAVE_FORMAT;
typedef unsigned __int16 VARTYPE;
typedef WORD PROPVAR_PAD1;
typedef WORD PROPVAR_PAD2;
typedef WORD PROPVAR_PAD3;
typedef unsigned __int8 UCHAR;
typedef __int16 SHORT;
typedef unsigned __int16 USHORT;
typedef float FLOAT;
typedef double DOUBLE;
typedef __int16 VARIANT_BOOL;
typedef LONG SCODE;
typedef double DATE;
typedef GUID CLSID;
typedef tagCLIPDATA CLIPDATA;
typedef WCHAR OLECHAR;
typedef OLECHAR *BSTR;
typedef CHAR *LPSTR;
typedef WCHAR *LPWSTR;
typedef int INT;
typedef unsigned int UINT;
typedef tagVersionedStream *LPVERSIONEDSTREAM;
typedef tagSAFEARRAY SAFEARRAY;
typedef SAFEARRAY *LPSAFEARRAY;
typedef void *PVOID;
typedef tagSAFEARRAYBOUND SAFEARRAYBOUND;
typedef __int32 HRESULT;
typedef DWORD LCID;
typedef OLECHAR *LPOLESTR;
typedef LONG DISPID;
typedef tagDISPPARAMS DISPPARAMS;
typedef tagVARIANT VARIANT;
typedef tagEXCEPINFO EXCEPINFO;
typedef tagSTATSTG STATSTG;
typedef LPOLESTR *SNB;
typedef tagTYPEATTR TYPEATTR;
typedef tagFUNCDESC FUNCDESC;
typedef tagVARDESC VARDESC;
typedef DISPID MEMBERID;
typedef DWORD HREFTYPE;
typedef tagINVOKEKIND INVOKEKIND;
typedef tagTYPEKIND TYPEKIND;
typedef tagTYPEDESC TYPEDESC;
typedef tagIDLDESC IDLDESC;
typedef tagELEMDESC ELEMDESC;
typedef tagFUNCKIND FUNCKIND;
typedef tagCALLCONV CALLCONV;
typedef tagPARAMDESCEX *LPPARAMDESCEX;
typedef tagPARAMDESC PARAMDESC;
typedef tagVARKIND VARKIND;
typedef const OLECHAR *LPCOLESTR;
typedef int BOOL;
typedef tagDESCKIND DESCKIND;
typedef tagBINDPTR BINDPTR;
typedef tagTLIBATTR TLIBATTR;
typedef tagSYSKIND SYSKIND;
typedef USHORT ADDRESS_FAMILY;
typedef void *LPVOID;
typedef ULONG_PTR DWORD_PTR;
typedef ULONG_PTR SIZE_T;
typedef ULONGLONG DWORDLONG;
typedef tagWNDCLASSW WNDCLASSW;
typedef __int64 LONG_PTR;
typedef LONG_PTR LRESULT;
typedef unsigned __int64 UINT_PTR;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef LRESULT (__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef HICON__ *HICON;
typedef HICON HCURSOR;
typedef HBRUSH__ *HBRUSH;
typedef const WCHAR *LPCWSTR;
typedef #253 POINT;
typedef _XINPUT_STATE XINPUT_STATE;
typedef _XINPUT_GAMEPAD XINPUT_GAMEPAD;
typedef tagRECT RECT;
typedef tagRAWINPUTDEVICE RAWINPUTDEVICE;
typedef _XINPUT_VIBRATION XINPUT_VIBRATION;
typedef addrinfo ADDRINFOA;
typedef unsigned __int64 size_t;
typedef GUID UUID;
typedef unsigned int u_int;
typedef UINT_PTR SOCKET;
typedef _tagpropertykey PROPERTYKEY;
typedef _AMMediaType AM_MEDIA_TYPE;
typedef AM_MEDIA_TYPE DMO_MEDIA_TYPE;
typedef _EXCEPTION_RECORD EXCEPTION_RECORD;
typedef _SYSTEMTIME SYSTEMTIME;
typedef BYTE *LPBYTE;
typedef threadlocaleinfostruct *pthreadlocinfo;
typedef struct threadmbcinfostruct *pthreadmbcinfo;
typedef tagLC_ID LC_ID;
typedef unsigned int _dev_t;
typedef unsigned __int16 _ino_t;
typedef __int64 __time64_t;
typedef _iobuf FILE;
typedef _MEMORY_BASIC_INFORMATION MEMORY_BASIC_INFORMATION;
typedef uint16_t NetObjectId;
typedef in_addr IN_ADDR;
typedef size_t size_type;
typedef _RTL_CRITICAL_SECTION RTL_CRITICAL_SECTION;
typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;
typedef scrNativeCallContext *native;
typedef __MIDL___MIDL_itf_mfobjects_0000_0006_0003 MFT_REGISTER_TYPE_INFO;
enum tagINVOKEKIND
enum tagTYPEKIND
enum tagFUNCKIND
enum tagCALLCONV
enum tagVARKIND
enum tagDESCKIND
enum tagSYSKIND
enum eNetworkEvent
enum eReportType
enum eEntityType
enum MACRO_FALSE
enum eTlsOffset
enum btSeatbeltWindshieldBits
enum eThreadState
enum MACRO_NULL
enum MACRO_WM
enum bitwriter_flag_t
enum MACRO_SOCKET
enum MACRO_DNS_ERROR_INVALID_DATA
enum MACRO_AF
enum MACRO_SO_SNDBUF
enum MACRO_SOCK
enum MACRO_NULLPTR

// stdpkey.h


// types.h
typedef DWORD Any;
typedef DWORD Hash;
typedef DWORD Void;
typedef DWORD uint;
typedef int Blip;
typedef int Cam;
typedef int Camera;
typedef int CarGenerator;
typedef int ColourIndex;
typedef int CoverPoint;
typedef int Entity;
typedef int FireId;
typedef int Group;
typedef int Interior;
typedef int Object;
typedef int Ped;
typedef int Pickup;
typedef int Player;
typedef int ScrHandle;
typedef int Sphere;
typedef int TaskSequence;
typedef int Texture;
typedef int TextureDict;
typedef int Train;
typedef int Vehicle;
typedef int Weapon;
typedef uint Hash;


"""

"""
note: standard types for c++
    bool                        size: 1
    char                        size: 1
    char16_t                    size: 2
    char32_t                    size: 32
    char8_t                     size: 0
    double                      size: 8
    float                       size: 4
    int                         size: 4
    long double                 size: 8
    long int                    size: 4
    long long int               size: 8
    short int                   size: 2
    unsigned char               size: 1
    unsigned int                size: 4
    unsigned long int           size: 4
    unsigned long long int      size: 8
    unsigned short int          size: 2
    wchar_t => unsigned __int16 size: 2
"""

reclass_types = [
    "nt_base",   "nt_instance", "nt_struct",      "nt_hidden",   "nt_hex32",  "nt_hex64",
    "nt_hex16",  "nt_hex8",     "nt_pointer",     "nt_int64",    "nt_int32",  "nt_int16",
    "nt_int8",   "nt_float",    "nt_double",      "nt_uint32",   "nt_uint16", "nt_uint8",
    "nt_text",   "nt_unicode",  "nt_functionptr", "nt_custom",   "nt_vec2",   "nt_vec3",
    "nt_quat",   "nt_matrix",   "nt_vtable",      "nt_array",    "nt_class",  "nt_pchar",
    "nt_pwchar", "nt_bits",     "nt_uint64",      "nt_function",
    "nt_ptrarray" ]

def getStrucSize(name):
    return idc.get_struc_size(idc.get_struc_id(name))

def doesStrucExist(name):
    return idc.get_struc_id(name) != idc.BADADDR

def get_tinfo_by_parse(name):
    result = idc.parse_decl(name, idc.PT_SILENT)
    if result is None:
        return
    _, tp, fld = result
    tinfo = idaapi.tinfo_t()
    tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
    return tinfo

def get_tinfo_brute(name):
    idati = ida_typeinf.get_idati()
    ti = ida_typeinf.tinfo_t()

    for ordinal in range(1, ida_typeinf.get_ordinal_qty(idati)+1):
        if ti.get_numbered_type(idati, ordinal) and ti.dstr() == name:
            return ti
    return None

def get_tinfo_lame(name):
    ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, name)
    if ordinal:
        tinfo = idaapi.tinfo_t()
        if tinfo.get_numbered_type(idaapi.cvar.idati, ordinal):
            return tinfo

def get_field_at_offset(tinfo, offset):
    result = []
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    idx = tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
    if idx != -1:
        while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset == offset * 8:
            udt_member = udt_data[idx]
            if udt_member.offset == offset * 8:
                result.append(udt_member.type)
            idx += 1
    return result

def get_tinfo_mega(name):
    r = idc.parse_decl("""
        struct membrick_decl_test {{
            {0}  test_value;
            {0}* test_ptr;
            {0}  test_array[2];
        }};""".format(name),  idc.PT_SILENT |idc.PT_TYP | idc.PT_REPLACE | idc.PT_PAK1)
    if not r:
        return False
    
    tif = ida_typeinf.tinfo_t()
    tif.deserialize(None, r[1], r[2])
    tif = get_field_at_offset(tif, 0)
    if not tif:
        return False
    tif = tif[0]
    typename = tif.get_type_name()
    if not typename:
        print("[debug] not a 'real' type")
    typename = str(tif)
    if typename == name:
        return tif
    return False

def has_decl(name, size=None, raw=False):
    r = idc.parse_decl("""
        struct membrick_decl_test {{
            {0}  test_value;
            {0}* test_ptr;
            {0}  test_array[2];
        }};""".format(name),  idc.PT_SILENT) # |idc.PT_TYP | idc.PT_REPLACE | idc.PT_PAK1)
    if r:
        tif = ida_typeinf.tinfo_t()
        tif.deserialize(None, r[1], r[2])
        ti2 = get_field_at_offset(tif, 0)
        # return ti2
        if ti2 and len(ti2):
            ti3 = ti2[0]
            typename = ti3.get_type_name() or str(ti3)
            if typename == name:
                if size and size is not None:
                    if ti3.get_size() == size:
                        return ti3 if raw else (True, ti3)
                    return (False, "size", ti3.get_size())
                return ti3 if raw else (True, ti3)
            return (False, "get_type_name", [(t.get_type_name(), str(t)) for t in ti2])
        return (False, "get_field_at_offset")
    return (False, "parse_decl")

def get_fields_at_offset(tinfo, offset):
    """
    Given tinfo and offset of the structure or union, returns list of all tinfo at that offset.
    This function helps to find appropriate structures by type of the offset
    """
    EA64 = idaapi.get_inf_structure().is_64bit()
    EA_SIZE = 8 if EA64 else 4
    result = []
    if offset == 0:
        result.append(tinfo)
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    idx = tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
    if idx != -1:
        while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset <= offset * 8:
            udt_member = udt_data[idx]
            if udt_member.offset == offset * 8:
                if udt_member.type.is_ptr():
                    result.append(idaapi.get_unk_type(EA_SIZE))
                    result.append(udt_member.type)
                    result.append(idaapi.dummy_ptrtype(EA_SIZE, False))
                elif not udt_member.type.is_udt():
                    result.append(udt_member.type)
            if udt_member.type.is_array():
                if (offset - udt_member.offset // 8) % udt_member.type.get_array_element().get_size() == 0:
                    result.append(udt_member.type.get_array_element())
            elif udt_member.type.is_udt():
                result.extend(get_fields_at_offset(udt_member.type, offset - udt_member.offset // 8))
            idx += 1
    return result

def StructMatchOffset(_offset, _type, _limit = 32):
    min_size = _offset # + sizeof type
    _tinfo = get_tinfo(_type)
    result = []
    tinfo = idaapi.tinfo_t()
    for ordinal in range(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
        tinfo.get_numbered_type(idaapi.cvar.idati, ordinal)
        if tinfo.is_udt() and tinfo.get_size() >= min_size:
            is_found = False

            potential_members = get_fields_at_offset(tinfo, _offset)
            for potential_member in potential_members:
                if _tinfo.dstr() == potential_member.dstr():
                    # if tinfo.equals_to(_tinfo):
                    print(tinfo.dstr(), potential_member.dstr(), _tinfo.dstr())
                    is_found = True
                    break

            if is_found:
                result.append((ordinal, idaapi.tinfo_t(tinfo)))

    return result
#
#  def get_type_tinfo(t):
    #  type_tuple = idaapi.get_named_type(None, t, 1)
    #  tif = idaapi.tinfo_t()
    #  try:
        #  tif.deserialize(None, type_tuple[1], type_tuple[2])
        #  return tif
    #  except TypeError:
        #  return None
get_type_tinfo = get_tinfo

def parseTypeDefs(lines):
    global __typedefs
    re_typedef = re.compile(r'typedef\s+((?:(?:\w+)(?:\s+))+)((?:(?:\*?\w+)[,;]\s*)+)')
    re_define = re.compile(r'#define\s+(\w+)((?:(?:\s+)(?:\w+))+)')
    for l in lines:
        found = 0
        for (_type, _alias) in re.findall(re_typedef, l):
            found += 1
            _aliases = [x for x in [x.strip().rstrip(';') for x in _alias.split(",")] if len(x)]
            _type = " ".join([x for x in [x.strip() for x in _type.split(" ")] if len(x)])
            for _alias in _aliases:
                if "*" not in _alias:
                    #  _alias = resolveTypeDefModifiers(_alias)
                    _type = resolveTypeDefModifiers(_type)
                    if _alias is not None and _type is not None:
                        __typedefs[_alias] = _type
        for (_alias, _type) in re.findall(re_define, l):
            found += 1
            _type = " ".join([x for x in [x.strip() for x in _type.split(" ")] if len(x)])
            #  _alias = resolveTypeDefModifiers(_alias)
            _type = resolveTypeDefModifiers(_type)
            if _alias is not None and _type is not None:
                __typedefs[_alias] = _type
        if not found:
            pass
            #  print("No match found in line: %s" % l)
        #  else: print("Matched: %s" % l)

def parseHex(string, _default = None):
    if string.startswith('0x'):
        string = string[2:]
    #  string = string.lstrip('0x')
    if not string:
        print('empty string')
    return int(string, 16)

def parseHexDefault(string, _default = None):
    if not string:
        return _default
    try:
        string = string.lstrip('0x')
        return int(string, 16)
    except ValueError:
        print("Exception parseHex('{}'): Invalid".format(string))

def sizeTypeDef(type):
    sid = idc.get_struc_id(type)
    if sid != idc.BADADDR:
        return idc.get_struc_size(sid)

    try:
        name, tp, fld = idc.parse_decl(type, 1)
        if tp:
            return idc.SizeOf(tp)
    except:
        return 0

def resolveTypeDefModifiers(type):
    type = type.replace("std::", "")
    modifiers = ["signed", "unsigned", "short", "long"]
    modifiersFound = list()
    words = [x for x in [x.strip() for x in type.split(" ")] if len(x)]

    mods = list()
    non = list()
    for word in words:
        if word in modifiers:
            modifiersFound.append(modifiers.index(word))
            mods.append(word)
        else:
            non.append(word)

    if not len(non):
        non = ["int"]

    modBitmap = 0
    for mod in modifiersFound:
        modBitmap |= (1 << mod)


    if modBitmap & 0b0011 == 0b0011: # signed and unsigned
        print("invalid combination of signed and unsigned type modifiers")
        return None

    if modBitmap & 0b1100 == 0b1100: # long and short
        print("invalid combination of long and short type modifiers")
        return None

    modCount = dict()
    for mod in mods:
        if mod in modCount:
            if mod != "long" or mod == "long" and modCount["long"] == 2:
                print("too many %s's in type modifier" % mod)
                return None
            modCount[mod] += 1
        else:
            modCount[mod] = 1

    # todo: redo with bitmap
    if "signed" in modCount:
        del(mods[mods.index("signed")])
    if "long" in modCount and "double" in modCount:
        del(mods[mods.index("long")])
    if "long" in modCount and "float" in modCount:
        del(mods[mods.index("long")])
        del(mods[mods.index("float")])
        mods.append("double")

    mods.sort()
    # after sorting, alphabetical order is conviently:
    # long short signed unsigned
    mods.reverse()
    mods.extend(non)

    return " ".join(mods)

def resolveTypeDef(type):
    global __typedefs
    type = resolveTypeDefModifiers(type)
    while type in __typedefs:
        type = __typedefs[type]
    type = resolveTypeDefModifiers(type)
    return type

def resolveTypeDefs():
    global __typedefs
    types = list(__typedefs.keys())
    types = ["bool", "char", "char8_t", "char16_t", "char32_t", "double",
        "float", "int", "long", "long double", "long int", "long int unsigned long", "long long", "long long int", "short", "short int", "signed",
        "signed char", "signed int", "signed long", "signed long int", "signed long long", "signed long long int", "signed short", "signed short int",
        "unsigned", "unsigned char", "unsigned int", "unsigned long", "unsigned long int", "unsigned long long", "unsigned long long int", "unsigned short", 
        "unsigned short int", "std::wchar_t", "std::uint8_t",
        "std::uint16_t", "std::uint32_t", "std::uint64_t", "std::int8_t",
        "std::int16_t", "std::int32_t", "unsigned std::int64_t", "std::uintptr_t",
        "std::intptr_t", "const std::size_t", "DWORD", "_DWORD", "QWORD", "_QWORD",
        "_OWORD", "PSZ", "LPBOOL", "PBOOL", "PBOOLEAN", "BOOLEAN", "LPBYTE",
        "PBYTE", "LPCVOID", "LPDWORD", "PDWORD", "PFLOAT", "PUCHAR", "PULONG",
        "PDWORD_PTR", "PUSHORT", "LPWORD", "PWORD", "intptr_t", "ptrdiff_t",
        "ssize_t", "size_t", "uintptr_t", "wchar_t", "__time64_t", "PINT_PTR",
        "PLONG64", "PLONG_PTR", "CHAR", "FLOAT", "errno_t", "BOOL", "INT", "INT",
        "INT", "LPINT", "PINT", "__time32_t", "LONG", "LPLONG", "SHORT", "PINT64",
        "PINT8", "int8_t", "PINT32", "PLONG32", "int32_t", "PINT16", "int16_t",
        "PUINT64", "PDWORD64", "PUINT_PTR", "PULONG64", "PULONG_PTR", "BYTE",
        "PUINT8", "UCHAR", "uint8_t", "PUINT", "PUINT", "PUINT32", "UINT", "UINT",
        "PDWORD32", "PULONG32", "uint32_t", "DWORD", "ULONG", "wctype_t", "wint_t",
        "PUINT16", "WORD", "USHORT", "uint16_t", "LPVOID" ]
    #  types.extend(__typedefs.keys())
    for type in types:
        path = list()
        path.append(type)
        type = resolveTypeDefModifiers(type)
        path.append(type)
        while type in __typedefs:
            type = __typedefs[type]
            path.append(type)
        resolved = resolveTypeDefModifiers(type)
        if resolved != type:
            path.append(resolved)
        print(" => ".join(path) + " size: %s" % sizeTypeDef(type))




def parseStrucStringInternal(st):
    re_line = re.compile(r'^\s*((?:(?:\s+)(?:\w+))+)([ *]+)(\w+)((?:\[[0-9]+\])?);')
    line_iter = line_split(st)
    try:
        next(line_iter)
        next(line_iter)
    except StopIteration:
        print("StopIteration: Not enough lines: {}".format(st))
        raise StopIteration
    member_types = dict()
    alignments = dict()
    for l in line_iter:
        l = string_between('', ';', l, inclusive=1)
        if not l:
            continue
        #   __declspec(align(8)) float y;
        alignment, l = string_between_splice('__declspec(align(', ')) ', l, inclusive=1, repl='')
        for (_type, _stars, _name, _subscript) in re.findall(re_line, l):
            # dprint("[debug] _type, _stars, _name, _subscript")
            if debug:
                print("[debug] _type:{}, _stars:{}, _name:{}, _subscript:{}".format(_type, _stars, _name, _subscript))
            
            _type = " ".join([x for x in [x.strip() for x in _type.split(" ")] if len(x)]) + _stars.strip() + _subscript
            if debug:
                print("[debug] _type:{}".format(_type))
            member_types[_name] = _type
        if alignment and string_between('__declspec(align(', ')) ', alignment):
            alignment = int(string_between('__declspec(align(', ')) ', alignment))
            alignments[_name] = alignment
            if debug:
                print("[debug] _alignment:{}".format(alignment))

    return member_types, alignments

def my_print_decls(name, flags = PDF_INCL_DEPS | PDF_DEF_FWD):
    names = A(name)
    ordinals = []
    for name in names:
        ti = get_tinfo_by_parse(name)
        if ti:
            ordinal = ti.get_ordinal()
            if ordinal:
                ordinals.append(ordinal)
                continue
        print("[warn] couldn't get ordinal for type '{}'".format(name))
    if not ordinals:
        print("[warn] couldn't get ordinals for types '{}'".format(name))
        return ''
    #  else:
        #  print("[info] ordinals: {}".format(ordinals))


    # dprint("[debug] ordinals")
    # print("[debug] ordinals:{}".format(ordinals))
    # void __fastcall(__int64 a1, void (__fastcall ***a2)(_QWORD, __int64))
    result = ''
    if ordinals:
        result = idc.print_decls(','.join([str(x) for x in ordinals if x > -1]), flags)
    print(result)
    return result
    #  if ti.is_typeref():
        #  final_type = ti.get_final_type_name()
        #  if final_type and isString(final_type):
            #  return "typedef {} {};".format(final_type, name)

def GetStructRequirements(name):
    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        print("Invalid Struct Name: %s" % name)
        return []

    required = set()
    strucSize = idc.get_struc_size(sid)
    offset = 0
    lastMemberId = -1
    while offset < strucSize:
        mid = idc.get_member_id(sid, offset)
        name = idc.get_member_name(sid, offset)
        size = idc.get_member_size(sid, offset)
        flags = idc.get_member_flag(sid, offset)
        is_enum = is_member_enum(sid, offset)
        strid = idc.get_member_strid(sid, offset)
        tif    =_get_member_tinfo(sid,  offset)
        tiftype=get_member_typename(sid,  offset)

        if is_enum:
            enum_id = idc.get_enum(get_member_typename(sid, offset))
            enum_idx = idc.get_enum_idx(enum_id)
            enum_name = idc.get_enum_name(enum_id)
            required.add('enum {}'.format(enum_name))

        if idc.is_struct(flags):
            strid_name = idc.get_struc_name(strid)
            strid_type = tiftype
            print("struct {}: {} ({})".format(strid, strid_type, strid_name))
            required.add(strid_name) # strid
            for r in GetStructRequirements(strid_type):
                required.add(r)

        if tif:
            if tif.is_ptr_or_array():
                t2 = tif.get_ptrarr_object()
                required.add(str(t2))
            else:
                required.add(str(tif))

        if size:
            offset = offset + size
        else:
            offset += 1

    return required

def _get_member_tinfo(sid, offset):
    s = ida_struct.get_struc(sid)
    m = ida_struct.get_member(s, offset)
    tif = ida_typeinf.tinfo_t()
    try:
        if ida_struct.get_member_tinfo(tif, m):
            return tif
    except TypeError as e:
        print("s, m, tif", type(s), type(m), type(tif))
        print("Exception: {}".format(pprint.pformat(e)))
    return None

def get_member_typename(sid, offset):
    tif = _get_member_tinfo(sid, offset)
    if tif is None:
        return ""
    return tif.__str__()

def get_member_is_unsigned(sid, offset):
    tif = _get_member_tinfo(sid, offset)
    if tif is None:
        return None
    return tif.is_unsigned()

def get_member_is_array(sid, offset):
    tif = _get_member_tinfo(sid, offset)
    if tif is None:
        return None
    return tif.is_array()


def is_member_enum(sid, offset):
    tif = _get_member_tinfo(sid, offset)
    if tif is None:
        return False
    return tif.is_enum()

def log2(v):
    return v.bit_length() - 1

def struct_guess_elem_size(size, fudge=0):
    from functools import reduce
    def factors(n):    
        return _.sort(set(reduce(list.__add__, 
                    ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0))))

    results = []
    for r in range(0, fudge): 
        results.append([x//8 for x in _.sort(factors(size+r)) if not x % 8])
    return [(i,x[1:-1]) for i,x in enumerate(results) if len(x) > 2]

def getVarType(size, unsigned = None, count = 1, is_ptr = False, is_float = False):
    # @static: unsigned_types
    if 'unsigned_types' not in getVarType.__dict__:
        getVarType.unsigned_types = list(braceexpand("uint{8,16,32,64}_t"))
    # @static: signed_types
    if 'signed_types' not in getVarType.__dict__:
        getVarType.signed_types = list(braceexpand("int{8,16,32,64}_t"))
    # @static: maybe_signed_types
    if 'maybe_signed_types' not in getVarType.__dict__:
        getVarType.maybe_signed_types = ["_BYTE", "_WORD", "_DWORD", "_QWORD"]
    # @static: float_types
    if 'float_types' not in getVarType.__dict__:
        getVarType.float_types = ["float", "double", "Vector4"]

    if not size:            return ''
    if is_float:            packType = getVarType.float_types
    elif unsigned is None:  packType = getVarType.maybe_signed_types
    elif unsigned:          packType = getVarType.unsigned_types
    else:                   packType = getVarType.signed_types

    if size & (size - 1):
        raise ValueError("Size was not log2")

    idx = log2(size)
    if idx >= len(packType):
        raise IndexError("Size was too large")

    name = packType[idx]

    if is_ptr:
        if isinstance(is_ptr, int):
            name += "*" * is_ptr
        else:
            name += "*"

    if count > 1:
        name += "[{}]".format(count)

    return name

def getPackType(size, unsigned = True, count = 1, is_float = False):
    if size is None and unsigned is None:
        rv = '!'
    elif size is None:
        rv = '.'
    elif isinstance(size, int):
        if unsigned is None:
            #  rv = ':' * log2(size * 2)
            unsigned = True
        packType = 'bBhHiIqQ'
        packTypeFloat = '????ffdd'
        if is_float:
            packType = packTypeFloat
        extra = ''
        while size > 8:
            if not size % 8:
                extra += packType[7]
                size -= 8
            elif not size % 4:
                extra += packType[5]
                size -= 4
            elif not size % 2:
                extra += packType[3]
                size -= 2
            else:
                extra += packType[1]
                size -= 1

        name = 2 * log2(size) + int(unsigned)
        if name < len(packType):
            rv = extra + packType[name]
        else:
            raise Exception("Invalid padType: %s (%s)" % (name, size))
        if count > 1:
            if rv == 'b':
                return "%is" % count
            return "%i%s" % (count, rv)
    return rv

import re
import idc
import ida_struct
import ida_typeinf

def VirtualVtable(name):
    included = 0
    if isinstance(name, re.Match):
        name = name[1]
        included = 1

    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        return "// Invalid Struct Name: %s" % name
    ordinal = ida_struct.get_struc(sid).ordinal
    defn = idc.GetLocalType(ordinal, PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA | PRTYPE_NOARGS)
    # remove /* comments */
    defn = re.sub(r'/\*.*?\*/', '', defn)
    defn = re.sub(r'^  ([^(]+)\(__\w+ \*(\w+)\)\((\w+) \*__hidden[, ]*', r'  virtual \1 \2(', defn, 0, re.MULTILINE)
    # replace Destructor with ~
    defn = re.sub("virtual void  Destructor", "virtual ~{}".format(name.replace('_vtbl', '')), defn, 1)
    if included:
        defn = re.sub(r'^[^ ].*\n', '', defn, 0, re.MULTILINE)
    return defn

def VirtualClass(name):
    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        print("Invalid Struct Name: %s" % name)
        return
    ordinal = ida_struct.get_struc(sid).ordinal
    defn = idc.GetLocalType(ordinal, PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA | PRTYPE_SEMI)
    defn = re.sub(r'^  ([a-zA-Z0-9_:]+) \*[_VFTvftable]+ .*', VirtualVtable, defn, 0, re.MULTILINE)
    return defn

def StackInfo(ea, pack = False, parent_offset = 0, rename = False, renameRel = True, parent_tif = None, parents = [], verbose = False):

    def getOffset(offset, relative = True):
        if relative:
            return offset + parent_offset
        return offset
    def getName(name):
        return ".".join(parents + [name])

    ea = get_ea_by_any(ea)
    stkzero = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    sid = idc.get_frame_id(ea)
    if sid == idc.BADADDR:
        print("Invalid Struct Name: %s" % name)
        return

    this_name = name = 'stack'

    strucSize = idc.get_struc_size(sid)
    offset = 0
    lastMemberId = -1
    packString = ''
    names = []
    for member in idautils.StructMembers(sid):
        offset, name, size = member
        name    = name.strip()
        mid     = idc.get_member_id(sid,    offset)
        flags   = idc.get_member_flag(sid,  offset)
        strid   = idc.get_member_strid(sid, offset)
        tif     = _get_member_tinfo(sid,  offset)
        tiftype = get_member_typename(sid,  offset)
        unsign  = get_member_is_unsigned(sid, offset)
        array   = get_member_is_array(sid, offset)
        skip_this_name = 0

        if tif:
            ptr = tif.is_ptr()
            if ptr:
                globals()['tif'] = tif
                #  |  has_details(self, *args) -> 'bool'
                #  |      Does this type refer to a nontrivial type?
                if tif.has_details():
                    ptr_to = tif.copy()
                    ptr_to.remove_ptr_or_array()
                    if verbose:
                        strucText = idc.GetLocalType(ptr_to.get_final_ordinal(), PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA)
                        print(strucText + ";")
        else:
            ptr   = False

        if idc.is_struct(flags):
            strid_name = idc.get_struc_name(strid)
            strid_type = tiftype
        else:
            strid_name = ''
            strid_type = ''

        if name:
            new_name = name
            fix_name_size = False
            fix_name_offset = False
            if new_name != name:
                idc.set_member_name(sid, offset, new_name)
        if array:
            globals()['tif'] = tif
            elem_size = tif.get_array_element().get_size()
            elem_type = tif.get_array_element().__str__()
            elem_unsign = tif.get_array_element().is_unsigned()
            elem_count = tif.get_array_nelems()
            if strid_name:
                if debug:
                    print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
                if not header:
                    childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                    print(childPackString, childPackString)
                    thisPackString = "%i(%s)" % childPackString
            elif name is None and size is None:
                thisPackString = "."
            else:
                thisPackString = getPackType(elem_size, elem_unsign, elem_count, is_float = tif and tif.is_float())
        elif tif and tif.is_struct() and tif != parent_tif:
            if debug:
                print("// struct: {} (0x{:x})".format(strid_type, tif.get_size()))
            elem_size = tif.get_size()
            elem_type = tif.__str__()
            elem_unsign = tif.is_unsigned()
            elem_count = 1
            if debug:
                print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
            if not header:
                childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                print("childPackString", childPackString)
                for child_names in childPackString[1][0]:
                    names.append(name + "." + child_names)
                    skip_this_name = 1
                thisPackString = "(%s)" % childPackString[1][1]


            #  thisPackString = "(%s)" % StrucInfo(str(tif), parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif)
            if debug:
                print("// end-struct: {}".format(strid_type, tif.get_size()))
            offset = offset + size
            #  continue
        else:
            #  print("size: {}, unsign: {}, is_float: {}".format(size, unsign, tif and tif.is_float()))
            thisPackString = getPackType(size, unsign, is_float = tif and tif.is_float())

        #  enumid= idc.get_enum('ePHandleFlags'))debug

        cmts = []
        if idc.get_member_cmt(sid, offset, 0):
            cmts.append(idc.get_member_cmt(sid, offset, 0))
        if idc.get_member_cmt(sid, offset, 1):
            cmts.append(idc.get_member_cmt(sid, offset, 1))
        cmt = '\n'.join(cmts)

        alignment = 0
        type = ''
        if size is not None:
            if idc.is_struct(flags):
                print("type = name?", name)
                type = name
            else:
                #  print(("Unknown definition for type: {}".format(name)))
                if tif:
                    type = str(tif)
                else:
                    type = getVarType(size)
                    #  print(("Using type: {}".format(type)))

            ori_offset = offset
            #  if idc.is_struct(flags):
                #  strid_name = idc.get_struc_name(strid)
                #  print("// struct: {} (0x{:x})".format(type, idc.get_struc_size(strid)))
                #  # addRequiredStruct(strid, name)

            if not size:
                return
            if alignment:
                # alignment actually goes to the start of the struct, not the end (fixed)
                thisPackString = (max(alignment, size) - size) * 'x' + thisPackString
                # alignment needs to be calculated based on offset % alignment (TODO)
                # smth like: o = (o + (alignment - 1)) % alignment
                # or o += o % alignment
                # or a = o % alignment; if a: o += alignment - a  (best?)
                offset += max(alignment, size)
            else:
                offset = offset + size

            print(("0x{:04x} {} {:32} size:{:<4} flags:{:08x} type:{} strid:{:x} cmt:'{}'" \
                    .format(getOffset(ori_offset), thisPackString, getName(name), size, flags, type or tiftype or '', (strid ^ 0xff00000000000000) if strid != -1 else 0, cmt.strip())
                    .replace("strid:0 ", "")
                    .replace("cmt:''", "")
                    .replace("type: ", "")
                    ))
        else:
            size = 1
            if not name:
                name = 'padding'
            # padding
            print("0x{:04x} {} {:32} size:{:<4} flags:{:08x}".format(getOffset(offset), "x", getName(name), size, flags))
            offset = offset + 1

        
        if not skip_this_name:
            names.append(name)
        packString += thisPackString

    legalPackString = packString.replace('(', '').replace(')', '')
    r = "{} = struct.unpack('{}', b' ' * {})".format(", ".join(names), packString, struct.calcsize(legalPackString))
    print(r)
    return names, packString
# for debug purposes
def StrucInfo(name, pack = False, parent_offset = 0, rename = False, renameRel = True, parent_tif = None, parents = [], verbose = False, header=False, export=None):

    output = []
    def oprint(s):
        if export:
            output.append(s)
        else:
            print(s)

    ####
    #  |  get_numbered_type(self, *args) -> 'bool'
    ###|      Create a 'tinfo_t' object for an existing ordinal type.
    #get_named_type(self, *args) -> 'bool'
    def getOffset(offset, relative = True):
        if relative:
            return offset + parent_offset
        return offset
    def getName(name):
        return ".".join(parents + [name])

    thisPackString = ''
    names = []
    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        oprint(("Invalid Struct Name: %s" % name))
        return

    this_name = name

    #  if verbose:
        #  oprint(idc.print_decls(str(ida_struct.get_struc(sid).ordinal), PDF_INCL_DEPS | PDF_DEF_FWD | PDF_HEADER_CMT))
    strucText = idc.GetLocalType(ida_struct.get_struc(sid).ordinal, PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA)
    if verbose:
        oprint(strucText + ";")
    if header:
        oprint("struct {} {{".format(name))

    if idc.parse_decls(strucText + ";", 0) != 0:
        oprint("StrucInfo: Error re-parsing structure: {}\n{}".format(name, strucText))
    #  print("idc.GetLocalType: {}".format(strucText))
    #  if strucText.startswith('typedef'):
        #  oprint(strucText)
        #  return

    member_types, alignments = parseStrucStringInternal(strucText)

    if debug:
        oprint("member_types:")
        pp(member_types)
        oprint("alignments")
        pp(alignments)

    strucSize = idc.get_struc_size(sid)
    offset = 0
    lastMemberId = -1
    packString = ''
    while offset < strucSize:
        #  def GetMemberComment(id, member_offset, repeatable): return get_member_cmt(id, member_offset, repeatable)
        #  def GetMemberFlag(id, member_offset): return get_member_flag(id, member_offset)
        #  def GetMemberId(id, member_offset): return get_member_id(id, member_offset)
        #  def GetMemberName(id, member_offset): return get_member_name(id, member_offset)
        #  def GetMemberOffset(id, member_name): return get_member_offset(id, member_name)
        #  def GetMemberQty(id): return get_member_qty(id)
        #  def GetMemberSize(id, member_offset): return get_member_size(id, member_offset)
        #  def GetMemberStrId(id, member_offset): return get_member_strid(id, member_offset)

        mid   = idc.get_member_id(sid,    offset)
        name  = idc.get_member_name(sid,  offset)
        size  = idc.get_member_size(sid,  offset)
        flags = idc.get_member_flag(sid,  offset)
        strid = idc.get_member_strid(sid, offset)
        tif    =_get_member_tinfo(sid,  offset)
        tiftype=get_member_typename(sid,  offset)
        unsign= get_member_is_unsigned(sid, offset)
        array = get_member_is_array(sid, offset)
        if tif:
            ptr   = tif.is_ptr()
            if ptr:
                globals()['tif'] = tif
                #  |  has_details(self, *args) -> 'bool'
                #  |      Does this type refer to a nontrivial type?
                if tif.has_details():
                    ptr_to = tif.copy()
                    ptr_to.remove_ptr_or_array()
                    if verbose:
                        strucText = idc.GetLocalType(ptr_to.get_final_ordinal(), PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA)
                        oprint(strucText + ";")
        else:
            ptr   = False

        if idc.is_struct(flags):
            strid_name = idc.get_struc_name(strid)
            strid_type = tiftype
            if name in member_types:
                strid_type2 = member_types[name]
        else:
            strid_name = ''
            strid_type = ''

        if name and rename:
            new_name = name
            fix_name_size = False
            fix_name_offset = False
            m = re.fullmatch(r'(qw|dw|b|c|qword|dword|float|double|word|byte|field|pad|unpad|ptr)_(?:0x)?([0-9a-f]+)(_maybe)?$', name, re.IGNORECASE)
            
            if m or re.match(r'(N[0-9A-F]+|f[0-9])+$', name):
                if not m:
                    new_name = '%s_%03x' % (get_operand_size_type(size * 8), getOffset(offset, renameRel))
                    idc.set_member_name(sid, offset, new_name)
                else:
                    if m[1].lower() in ('qword', 'dword', 'word', 'byte'):
                        size_a = sizeTypeDef(m[1].upper())
                        size_b = size if not array else tif.get_array_element().get_size()
                        fix_name_size = True
                    else:
                        fix_name_size = True
                    offset_a = parseHex(m[2])
                    if offset_a != offset:
                        fix_name_offset = True

                    if fix_name_offset or fix_name_size:
                        if size <= 8:
                            new_name = '%s_%03x%s' % (get_operand_size_type(size * 8), getOffset(offset, renameRel), m[3] if m[3] else '')

            if new_name != name:
                print("renaming", name, new_name)
                idc.set_member_name(sid, offset, new_name)
        if array:
            globals()['tif'] = tif
            elem_size = tif.get_array_element().get_size()
            elem_type = tif.get_array_element().__str__()
            elem_unsign = tif.get_array_element().is_unsigned()
            elem_count = tif.get_array_nelems()
            if strid_name:
                if debug:
                    print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
                if not header:
                    childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                    oprint("cps, {}, {}".format(childPackString, childPackString))
                    thisPackString = "%i(%s)" % childPackString
            elif name is None and size is None:
                thisPackString = "."



            else:
                thisPackString = getPackType(elem_size, elem_unsign, elem_count, is_float = tif and tif.is_float())
                if re.match('(unpad|pad|gap)', name) and elem_size == 1:
                    o = offset
                    while elem_count > 0:
                        name="unpad_%03x" % getOffset(o, renameRel)
                        if elem_count > 7 and not o % 8:
                            count = elem_count // 8
                            structAdd(sid, o, "_QWORD", name, count = count)
                            elem_count -= 8 * count
                            o += 8 * count
                            continue
                        if elem_count > 3 and not o % 4:
                            count = 1
                            structAdd(sid, o, "_DWORD", name, count = count)
                            elem_count -= 4 * count
                            o += 4 * count
                            continue
                        if elem_count > 1 and not o % 2:
                            count = 1
                            structAdd(sid, o, "_WORD", name, count = count)
                            elem_count -= 2 * count
                            o += 2 * count
                            continue
                        if elem_count > 0:
                            count = 1
                            structAdd(sid, o, "_WORD", name, count = count)
                            elem_count -= 1 * count
                            o += 1 * count
                            continue
                        else:
                            raise Exception("elem_count is whacked %s" % elem_count)

                    #  if elem_size == 1 and not offset % 4:
                        #  for o in range(offset, offset + elem_count, 4):
                            #  structAdd(sid, o, "_DWORD", name)
        elif tif and tif.is_struct() and tif != parent_tif:
            # strid_name = idc.get_struc_name(strid)
            #  print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
            elem_size = tif.get_size()
            elem_type = tif.__str__()
            elem_unsign = tif.is_unsigned()
            elem_count = 1
            if debug:
                print("// struct: {} (0x{:x})".format(strid_type, elem_size))

            if not header:
                childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                if debug:
                    print('cps2', childPackString, childPackString)
                thisPackString = "(%s)" % childPackString[1][1]


            #  thisPackString = "(%s)" % StrucInfo(str(tif), parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif)
            if debug:
                print("// end-struct: {} ({})".format(strid_type, elem_size))
            #  offset = offset + elem_size
            size = elem_size
            #  continue
        else:
            #  print("size: {}, unsign: {}, is_float: {}".format(size, unsign, tif and tif.is_float()))
            thisPackString = getPackType(size, unsign, is_float = tif and tif.is_float())

        #  enumid= idc.get_enum('ePHandleFlags'))debug

        cmts = []
        if idc.get_member_cmt(sid, offset, 0):
            cmts.append(idc.get_member_cmt(sid, offset, 0))
        if idc.get_member_cmt(sid, offset, 1):
            cmts.append(idc.get_member_cmt(sid, offset, 1))
        cmt = '\n'.join(cmts)

        alignment = 0
        if size is not None:
            if name in alignments:
                alignment = alignments[name]
            if name in member_types:
                type = member_types[name]
            else:
                if idc.is_struct(flags):
                    print("type = name?", name)
                    type = name
                else:
                    # print(("Unknown definition for type: {}".format(name)))
                    if tif:
                        type = str(tif)
                        # print(("Using type: {}".format(type)))

            ori_offset = offset
            #  if idc.is_struct(flags):
                #  strid_name = idc.get_struc_name(strid)
                #  print("// struct: {} (0x{:x})".format(type, idc.get_struc_size(strid)))
                #  # addRequiredStruct(strid, name)

            if not size:
                oprint("size was 0")
                return
            if alignment:
                # alignment actually goes to the start of the struct, not the end (fixed)
                thisPackString = (max(alignment, size) - size) * 'x' + thisPackString
                # alignment needs to be calculated based on offset % alignment (TODO)
                # smth like: o = (o + (alignment - 1)) % alignment
                # or o += o % alignment
                # or a = o % alignment; if a: o += alignment - a  (best?)
                offset += max(alignment, size)
            else:
                offset = offset + size

            if header:
                _opt_array, _type = string_between_splice('[', ']', type, inclusive=1, greedy=1, repl='')
                oprint("/* 0x{:04x} */ {:<32} {}{};".format(getOffset(ori_offset), _type, getName(name), _opt_array))
            elif not header:
                oprint(("0x{:04x} {} {:32} size:{:<4} fflags:{:08x} type:{}/{} strid:{:x} cmt:{}" \
                        .format(getOffset(ori_offset), thisPackString, getName(name), size, flags, type, tiftype, (strid ^ 0xff00000000000000) if strid != -1 else 0, cmt.strip())))
        else:
            size = 1
            if not name:
                name = 'padding_{:03x}'.format(getOffset(offset))
            # padding
            if header:
                oprint("/* 0x{:04x} */ {:<32} {};".format(getOffset(offset), 'char', getName(name)))
            elif not header:
                oprint("0x{:04x} {} {:32} size:{:<4} fflags:{:08x};".format(getOffset(offset), "x", getName(name), size, flags))
            offset = offset + 1

        if 0:
            if offset and offset % 32 == 0:
                packString += "\n%4x " % getOffset(offset)
        packString += thisPackString

        names.append(name)

    if header:
        oprint("};")

    if export:
        export("\n".join(output))
    return names, packString
        #  [ "FF_BYTE",    @DT_TYPE,  0x00000000, "byte"                        ],
        #  [ "FF_WORD",    @DT_TYPE,  0x10000000, "word"                        ],
        #  [ "FF_DWRD",    @DT_TYPE,  0x20000000, "dword"                       ],
        #  [ "FF_QWRD",    @DT_TYPE,  0x30000000, "qword"                       ],
        #  [ "FF_TBYT",    @DT_TYPE,  0x40000000, "tbyte"                       ],
        #  [ "FF_ASCI",    @DT_TYPE,  0x50000000, "ASCII"                       ],
        #  [ "FF_STRU",    @DT_TYPE,  0x60000000, "Struct"                      ],
        #  [ "FF_OWRD",    @DT_TYPE,  0x70000000, "octaword (16 bytes)"         ],
        #  [ "FF_FLOAT",   @DT_TYPE,  0x80000000, "float"                       ],
        #  [ "FF_DOUBLE",  @DT_TYPE,  0x90000000, "double"                      ],
        #  [ "FF_PACKREAL",@DT_TYPE,  0xA0000000, "packed decimal real"         ],
        #  [ "FF_ALIGN",   @DT_TYPE,  0xB0000000, "alignment directive"         ],

    # ida_struct.get_struc(idc.get_struc_id("netSyncTree")).get_member(0x20)
    # ida_struct.get_struc(idc.get_struc_id("netSyncTree")).ordinal
    # idc.GetLocalType(ida_struct.get_struc(idc.get_struc_id("netSyncTree")).ordinal, PRTYPE_TYPE | PRTYPE_MULTI)


def StrucClassCommenter(name, pack = False, parent_offset = 0, rename = False, renameRel = True, parent_tif = None, parents = [], verbose = False, header=False):

    ####
    #  |  get_numbered_type(self, *args) -> 'bool'
    ###|      Create a 'tinfo_t' object for an existing ordinal type.
    #get_named_type(self, *args) -> 'bool'
    def getOffset(offset, relative = True):
        if relative:
            return offset + parent_offset
        return offset
    def getName(name):
        return ".".join(parents + [name])

    thisPackString = ''
    names = []
    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        print("Invalid Struct Name: %s" % name)
        return

    this_name = name

    if verbose:
        print(idc.print_decls(str(ida_struct.get_struc(sid).ordinal), PDF_INCL_DEPS | PDF_DEF_FWD | PDF_HEADER_CMT))
    strucText = idc.GetLocalType(ida_struct.get_struc(sid).ordinal, PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA)
    if verbose:
        print(strucText + ";")
    if header:
        print("struct {} {{".format(name))

    if idc.parse_decls(strucText + ";", 0) != 0:
        print("StrucInfo: Error re-parsing structure: {}\n{}".format(name, strucText))
    #  print("idc.GetLocalType: {}".format(strucText))
    member_types, alignments = parseStrucStringInternal(strucText)

    if debug:
        print("member_types:")
        pp(member_types)
        print("alignments")
        pp(alignments)

    strucSize = idc.get_struc_size(sid)
    offset = 0
    lastMemberId = -1
    packString = ''
    while offset < strucSize:
        #  def GetMemberComment(id, member_offset, repeatable): return get_member_cmt(id, member_offset, repeatable)
        #  def GetMemberFlag(id, member_offset): return get_member_flag(id, member_offset)
        #  def GetMemberId(id, member_offset): return get_member_id(id, member_offset)
        #  def GetMemberName(id, member_offset): return get_member_name(id, member_offset)
        #  def GetMemberOffset(id, member_name): return get_member_offset(id, member_name)
        #  def GetMemberQty(id): return get_member_qty(id)
        #  def GetMemberSize(id, member_offset): return get_member_size(id, member_offset)
        #  def GetMemberStrId(id, member_offset): return get_member_strid(id, member_offset)

        mid   = idc.get_member_id(sid,    offset)
        name  = idc.get_member_name(sid,  offset)
        size  = idc.get_member_size(sid,  offset)
        flags = idc.get_member_flag(sid,  offset)
        strid = idc.get_member_strid(sid, offset)
        tif    =_get_member_tinfo(sid,  offset)
        tiftype=get_member_typename(sid,  offset)
        unsign= get_member_is_unsigned(sid, offset)
        array = get_member_is_array(sid, offset)
        if tif:
            ptr   = tif.is_ptr()
            if ptr:
                globals()['tif'] = tif
                #  |  has_details(self, *args) -> 'bool'
                #  |      Does this type refer to a nontrivial type?
                if tif.has_details():
                    ptr_to = tif.copy()
                    ptr_to.remove_ptr_or_array()
                    if verbose:
                        strucText = idc.GetLocalType(ptr_to.get_final_ordinal(), PRTYPE_TYPE | PRTYPE_MULTI | PRTYPE_PRAGMA)
                        print(strucText + ";")
        else:
            ptr   = False

        if idc.is_struct(flags):
            strid_name = idc.get_struc_name(strid)
            strid_type = tiftype
            if name in member_types:
                strid_type2 = member_types[name]
        else:
            strid_name = ''
            strid_type = ''

        if name:
            new_name = name
            fix_name_size = False
            fix_name_offset = False
            m = re.fullmatch(r'(qw|dw|b|c|qword|dword|float|double|word|byte|field|pad|unpad|ptr)_([0-9a-f]+)', name, re.IGNORECASE)
            
            if m or re.match(r'(N[0-9A-F]+|f[0-9])+$', name):
                if not m:
                    new_name = '%s_%03x' % (get_operand_size_type(size * 8), getOffset(offset, renameRel))
                    idc.set_member_name(sid, offset, new_name)
                else:
                    if m[1].lower() in ('qword', 'dword', 'word', 'byte'):
                        size_a = sizeTypeDef(m[1].upper())
                        size_b = size if not array else tif.get_array_element().get_size()
                        fix_name_size = True
                    else:
                        fix_name_size = True
                    offset_a = parseHex(m[2])
                    if offset_a != offset:
                        fix_name_offset = True

                    if fix_name_offset or fix_name_size:
                        if size <= 8:
                            new_name = '%s_%03x' % (get_operand_size_type(size * 8), getOffset(offset, renameRel))

            if new_name != name:
                print("renaming", name, new_name)
                idc.set_member_name(sid, offset, new_name)
        if array:
            globals()['tif'] = tif
            elem_size = tif.get_array_element().get_size()
            elem_type = tif.get_array_element().__str__()
            elem_unsign = tif.get_array_element().is_unsigned()
            elem_count = tif.get_array_nelems()
            if strid_name:
                if debug:
                    print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
                if not header:
                    childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                    print("cps", childPackString, childPackString)
                    thisPackString = "%i(%s)" % childPackString
            elif name is None and size is None:
                thisPackString = "."



            else:
                thisPackString = getPackType(elem_size, elem_unsign, elem_count, is_float = tif and tif.is_float())
                if re.match('(unpad|pad|gap)', name) and elem_size == 1:
                    o = offset
                    while elem_count > 0:
                        name="unpad_%03x" % getOffset(o, renameRel)
                        if elem_count > 7 and not o % 8:
                            count = elem_count // 8
                            structAdd(sid, o, "_QWORD", name, count = count)
                            elem_count -= 8 * count
                            o += 8 * count
                            continue
                        if elem_count > 3 and not o % 4:
                            count = 1
                            structAdd(sid, o, "_DWORD", name, count = count)
                            elem_count -= 4 * count
                            o += 4 * count
                            continue
                        if elem_count > 1 and not o % 2:
                            count = 1
                            structAdd(sid, o, "_WORD", name, count = count)
                            elem_count -= 2 * count
                            o += 2 * count
                            continue
                        if elem_count > 0:
                            count = 1
                            structAdd(sid, o, "_WORD", name, count = count)
                            elem_count -= 1 * count
                            o += 1 * count
                            continue
                        else:
                            raise Exception("elem_count is whacked %s" % elem_count)

                    #  if elem_size == 1 and not offset % 4:
                        #  for o in range(offset, offset + elem_count, 4):
                            #  structAdd(sid, o, "_DWORD", name)
        elif tif and tif.is_struct() and tif != parent_tif:
            # strid_name = idc.get_struc_name(strid)
            #  print("// struct: {} (0x{:x})".format(strid_type, idc.get_struc_size(strid)))
            elem_size = tif.get_size()
            elem_type = tif.__str__()
            elem_unsign = tif.is_unsigned()
            elem_count = 1
            if debug:
                print("// struct: {} (0x{:x})".format(strid_type, elem_size))

            if not header:
                childPackString = (elem_count, StrucInfo(elem_type, parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif))
                if debug:
                    print('cps2', childPackString, childPackString)
                thisPackString = "(%s)" % childPackString[1][1]


            #  thisPackString = "(%s)" % StrucInfo(str(tif), parent_offset = getOffset(offset), parents = parents + [name], verbose = verbose, parent_tif = tif)
            if debug:
                print("// end-struct: {} ({})".format(strid_type, elem_size))
            #  offset = offset + elem_size
            size = elem_size
            #  continue
        else:
            #  print("size: {}, unsign: {}, is_float: {}".format(size, unsign, tif and tif.is_float()))
            thisPackString = getPackType(size, unsign, is_float = tif and tif.is_float())

        #  enumid= idc.get_enum('ePHandleFlags'))debug

        cmts = []
        if idc.get_member_cmt(sid, offset, 0):
            cmts.append(idc.get_member_cmt(sid, offset, 0))
        if idc.get_member_cmt(sid, offset, 1):
            cmts.append(idc.get_member_cmt(sid, offset, 1))
        cmt = '\n'.join(cmts)

        alignment = 0
        if size is not None:
            if name in alignments:
                alignment = alignments[name]
            if name in member_types:
                type = member_types[name]
            else:
                if idc.is_struct(flags):
                    print("type = name?", name)
                    type = name
                else:
                    # print(("Unknown definition for type: {}".format(name)))
                    if tif:
                        type = str(tif)
                        # print(("Using type: {}".format(type)))

            ori_offset = offset
            #  if idc.is_struct(flags):
                #  strid_name = idc.get_struc_name(strid)
                #  print("// struct: {} (0x{:x})".format(type, idc.get_struc_size(strid)))
                #  # addRequiredStruct(strid, name)

            if not size:
                print("size was 0")
                return
            if alignment:
                # alignment actually goes to the start of the struct, not the end (fixed)
                thisPackString = (max(alignment, size) - size) * 'x' + thisPackString
                # alignment needs to be calculated based on offset % alignment (TODO)
                # smth like: o = (o + (alignment - 1)) % alignment
                # or o += o % alignment
                # or a = o % alignment; if a: o += alignment - a  (best?)
                offset += max(alignment, size)
            else:
                offset = offset + size

            if header:
                _opt_array, _type = string_between_splice('[', ']', type, inclusive=1, greedy=1, repl='')
                print("/* 0x{:04x} */ {:<32} {}{};".format(getOffset(ori_offset), _type, getName(name), _opt_array))
            elif not header:
                print(("0x{:04x} {} {:32} size:{:<4} fflags:{:08x} type:{}/{} strid:{:x} cmt:{}" \
                        .format(getOffset(ori_offset), thisPackString, getName(name), size, flags, type, tiftype, (strid ^ 0xff00000000000000) if strid != -1 else 0, cmt.strip())))
        else:
            size = 1
            if not name:
                name = 'padding_{:03x}'.format(getOffset(offset))
            # padding
            if header:
                print("/* 0x{:04x} */ {:<32} {};".format(getOffset(offset), 'char', getName(name)))
            elif not header:
                print("0x{:04x} {} {:32} size:{:<4} fflags:{:08x};".format(getOffset(offset), "x", getName(name), size, flags))
            offset = offset + 1

        if 0:
            if offset and offset % 32 == 0:
                packString += "\n%4x " % getOffset(offset)
        packString += thisPackString

        names.append(name)

    if header:
        print("};")

    return names, packString
        #  [ "FF_BYTE",    @DT_TYPE,  0x00000000, "byte"                        ],
        #  [ "FF_WORD",    @DT_TYPE,  0x10000000, "word"                        ],
        #  [ "FF_DWRD",    @DT_TYPE,  0x20000000, "dword"                       ],
        #  [ "FF_QWRD",    @DT_TYPE,  0x30000000, "qword"                       ],
        #  [ "FF_TBYT",    @DT_TYPE,  0x40000000, "tbyte"                       ],
        #  [ "FF_ASCI",    @DT_TYPE,  0x50000000, "ASCII"                       ],
        #  [ "FF_STRU",    @DT_TYPE,  0x60000000, "Struct"                      ],
        #  [ "FF_OWRD",    @DT_TYPE,  0x70000000, "octaword (16 bytes)"         ],
        #  [ "FF_FLOAT",   @DT_TYPE,  0x80000000, "float"                       ],
        #  [ "FF_DOUBLE",  @DT_TYPE,  0x90000000, "double"                      ],
        #  [ "FF_PACKREAL",@DT_TYPE,  0xA0000000, "packed decimal real"         ],
        #  [ "FF_ALIGN",   @DT_TYPE,  0xB0000000, "alignment directive"         ],

    # ida_struct.get_struc(idc.get_struc_id("netSyncTree")).get_member(0x20)
    # ida_struct.get_struc(idc.get_struc_id("netSyncTree")).ordinal
    # idc.GetLocalType(ida_struct.get_struc(idc.get_struc_id("netSyncTree")).ordinal, PRTYPE_TYPE | PRTYPE_MULTI)






# *(_DWORD *)(self - 56)
#  pattern_4a = re.compile(r'*(_DWORD *)&v1->gap0[8] = 16358695;

# get_member_offset

def decompile_function_for_funcdefs(ea):
    try:
        cfunc = idaapi.decompile(ea)
        func_def = str(cfunc).split("\n")
        decl = [x for x in func_def if len(x) and not x[0] == '/'][0]
        if decl is not None:
            # print("decl: %s" % decl)
            decl = re.sub("__noreturn", "", decl)

            # fix up any __usercall methods
            if ~decl.find("__usercall"):
                decl = re.sub("__usercall", "__fastcall", decl)
                decl = re.sub(r"@<[^>]+>", "", decl)
                print("// Attempting to alter __usercall member to: %s" % decl)
                idc.SetType(ea, decl)
                Wait()

            #  regex = r"(.*?) ?(__(?:fastcall|stdcall|cdecl|usercall))? ?([^* ]*?)\((.*)\)"
            #  for (returnType, callType, fnName, fnArgs) in re.findall(regex, decl):

        return func_def

    except DecompilationFailure:
        print("%s: DecompilationFailure: 0x0%0x" % (fnName, ea))
        return "    %s (%s *%s)(%s);" % ("void", "__fastcall", "error_" + fnName, "")

def parseStrucString(st):
    re_header = re.compile(r'struct\s+([^ ]+)\s*{') # fuck y'all, put your braces on the same line as the struct heaer
    re_line = re.compile(r'^\s*((?:(?:\s+)(?:\w+))+)([ *]+)(\w+);')
    state = 0
    for l in line_split(st):
        if state == 0:
            m = re.match(re_header, l)
            if m is not None:
                structName = m.group(1)
                state = 1
                continue
        if state == 1:
            for (_type, _stars, _name) in re.findall(re_line, l):
                #  probably not needed, since we strip in the filter below
                #  _type = _type.strip()
                _stars = _stars.strip()
                _type = " ".join([x for x in [x.strip() for x in _type.split(" ")] if len(x)])
                if _type != "void" and not sizeTypeDef(_type) and not doesStrucExist(_type) and not sizeTypeDef(resolveTypeDef(_type)):
                    # we need to create a struct
                    print("Adding Empty Structure: %s" % _type)
                    idc.add_struc(-1, _type, 0)

    idc.parse_decls(st)

def structAddMember(sid, name, offset, flag, typeid, nbytes, count = 1, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Add structure member

    @param sid:    structure type ID
    @param name:   name of the new member
    @param offset: offset of the new member
                   -1 means to add at the end of the structure
    @param flag:   type of the new member. Should be one of
                   FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
                   if idc.is_off0(flag) then typeid specifies the offset base.
                   if idc.is_strlit(flag) then typeid specifies the string type (STRTYPE_...).
                   if ida_bytes.is_stroff(flag) then typeid specifies the structure id
                   if ida_bytes.is_enum(flag) then typeid specifies the enum id
                   if ida_bytes.is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                   Otherwise typeid should be -1.
    @param nbytes: number of bytes in the new member

    @param target: target address of the offset expr. You may specify it as
                   -1, ida will calculate it itself
    @param tdelta: offset target delta. usually 0
    @param reftype: see REF_... definitions

    @note: The remaining arguments are allowed only if idc.is_off0(flag) and you want
           to specify a complex offset expression

    @return: 0 - ok, otherwise error code (one of STRUC_ERROR_*)

    STRUC_ERROR_MEMBER_NAME    = -1 # already has member with this name (bad name)
    STRUC_ERROR_MEMBER_OFFSET  = -2 # already has member at this offset
    STRUC_ERROR_MEMBER_SIZE    = -3 # bad number of bytes or bad sizeof(type)
    STRUC_ERROR_MEMBER_TINFO   = -4 # bad typeid parameter
    STRUC_ERROR_MEMBER_STRUCT  = -5 # bad struct id (the 1st argument)
    STRUC_ERROR_MEMBER_UNIVAR  = -6 # unions can't have variable sized members
    STRUC_ERROR_MEMBER_VARLAST = -7 # variable sized member should be the last member in the structure

    """

    nbytes *= count
    result = idc.add_struc_member(sid, name,    offset, flag,     typeid, nbytes, target, tdelta, reftype)
    #  mid = add_struc_member(id,         "pad40", 0,      0x000400, -1,     40);
    if result < 0:
        error = "Unknown: {}".format(result)
        if result == ida_struct.STRUC_ERROR_MEMBER_NAME: error="already has member with this name (bad name)"
        if result == ida_struct.STRUC_ERROR_MEMBER_OFFSET: error="already has member at this offset"
        if result == ida_struct.STRUC_ERROR_MEMBER_SIZE: error="bad number of bytes or bad sizeof(type)"
        if result == ida_struct.STRUC_ERROR_MEMBER_TINFO: error="bad typeid parameter"
        if result == ida_struct.STRUC_ERROR_MEMBER_STRUCT: error="bad struct id (the 1st argument)"
        if result == ida_struct.STRUC_ERROR_MEMBER_UNIVAR: error="unions can't have variable sized members"
        if result == ida_struct.STRUC_ERROR_MEMBER_VARLAST: error="variable sized member should be the last member in the structure"
        if result == ida_struct.STRUC_ERROR_MEMBER_NESTED: error="STRUC_ERROR_MEMBER_NESTED"
        print("[structAddMember] add_struc_member: {}".format(error))
    elif result == 0:
        print("[structAddMember] add_struc_member: OK")
    else:
        print("[structAddMember] error unknown: {}", result)

    count = 0

    if result == STRUC_ERROR_MEMBER_OFFSET:
        prev_size = idc.get_member_size(sid, offset)
        if idc.get_member_name(sid, offset) is None \
                or name \
                or re.match('(.*maybe|_[A-Z]+|[a-z]+word|byte_|unknown|unused|unpad|pad|gap)', idc.get_member_name(sid, offset)) \
                or nbytes < prev_size:
            #  print("removing previous struc_member")
            for o in range(offset, offset + nbytes):
                #  print("removing previous struc_member at %s" % hex(o))
                idc.del_struc_member(sid, o)
            result = idc.add_struc_member(sid, name, offset, flag, typeid, nbytes, target, tdelta, reftype)
            if prev_size and prev_size > nbytes:
                count = 1
                remain = nbytes - prev_size
                print("remain", remain, type(remain))
                print("nbytes", nbytes, type(nbytes))
                offset += nbytes
                while remain >= 0:
                    idc.add_struc_member(sid, "{}_spare_{}".format(name, count), offset, flag, typeid, nbytes, target, tdelta, reftype)
                    print("remain", remain, type(remain))
                    print("nbytes", nbytes, type(nbytes))
                    remain -= nbytes
                    offset += nbytes
                    count += 1

#! @brief back to front parameters, but the 0 length left & right for detect from/to start/end work
def string_between_subject_first(subject, left, right, inclusive=False, greedy=False):
    null = -1
    start = 0
    end = 0

    leftlen = len(left)
    rightlen = len(right)

    if leftlen:
        start = subject.find(left, start)
        if start == null: return subject
        start += leftlen

    if rightlen:
        end = subject.rfind(right, start) if greedy \
                else subject.find(right, start)
        if end == null: return subject
        if inclusive: return subject[start - leftlen:end + rightlen]
        return subject[start:end]

    return subject[start:]


def structAdd(sid, offset, _type, name = None, count = 1, self_offset = 0):
    offset += self_offset
    if name is None or name == "maybe":
        tif = get_tinfo_by_parse(_type)
        if tif.is_ptr():
            name1 = "p%s_%03x" % (_type.lstrip('C').rstrip('*'), offset)
        else:
            name1 = "%s_%03x" % (re.sub(r'^_', '', _type).lower(), offset)
        if name == "maybe":
            name1 += "_maybe"
        name = name1
    elif '{}' in name:
        name = name.format("%03x" % offset)

    _typeid = -1
    if _type == "_BYTE":    structAddMember(sid, name, offset, FF_DATA | FF_BYTE, -1, 1, count = count)
    elif _type == "_WORD":  structAddMember(sid, name, offset, FF_DATA | FF_WORD, -1, 2, count = count)
    elif _type == "_DWORD": structAddMember(sid, name, offset, FF_DATA | FF_DWRD, -1, 4, count = count)
    elif _type == "_QWORD": structAddMember(sid, name, offset, FF_DATA | FF_QWRD, -1, 8, count = count)
    elif _type == "_OWORD": structAddMember(sid, name, offset, FF_DATA | FF_OWRD, -1, 16, count = count)
    elif _type == "float":  structAddMember(sid, name, offset, FF_DATA | FF_FLOAT, -1, 4, count = count)
    elif _type == "double": structAddMember(sid, name, offset, FF_DATA | FF_DOUBLE, -1, 8, count = count)
    else:
        flags = 0
        tif = get_tinfo_by_parse(_type)
        _is_struct = False
        _is_ptr = tif.is_ptr()
        if _is_ptr:
            if not tif.remove_ptr_or_array():
                raise RuntimeError("Couldn't remove ptr from type {}".format(_type))
        if tif.is_struct():
            _is_struct = True

        if _is_struct:
            if not _is_ptr:
                _typeid = idc.get_struc_id(tif.get_type_name())
                #  @param flag:   type of the new member. Should be one of
                               #  FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
                #  @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
                               #  if idc.is_off0(flag) then typeid specifies the offset base.
                               #  if idc.is_strlit(flag) then typeid specifies the string type (STRTYPE_...).
                               #  if ida_bytes.is_stroff(flag) then typeid specifies the structure id
                               #  if ida_bytes.is_enum(flag) then typeid specifies the enum id
                               #  if ida_bytes.is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                               #  Otherwise typeid should be -1.
                flags |= idc.FF_STRUCT
            else:
                flags |= FF_0OFF | FF_1OFF | FF_QWRD 
        size = sizeTypeDef(_type)
        if not flags:
            if size == 1:
                flags = FF_BYTE
            elif size == 2:
                flags = FF_WORD
            elif size == 4:
                flags = FF_DWORD
            elif size == 8:
                flags = FF_QWORD
            elif size == 10:
                flags = FF_OWORD
            else: 
                print(("Unknown type: %s" % _type))
                return
        structAddMember(sid, name, offset, FF_DATA | flags, _typeid, size, count=count)
        idc.SetType(get_member_id(sid, offset), _type)


def structReverse(filename, struct_name):
    """
    0    baseclass_0                      size:784 flags:60000400 type:CPhysical
    310  dword_310_maybe                  size:4 flags:20000400 type:DWORD
    314  float_314_maybe                  size:4 flags:80000400 type:float
    318  bRocketBoostEnabled              size:1 flags:00000400 type:unsigned __int8
    319  pad_0x0319                       size:7 flags:00000400 type:
    320  fRocketBoostCharge               size:4 flags:80000400 type:float
    324  fRocketBoostChargeRate           size:4 flags:80000400 type:float
    """
    sid = idc.get_struc_id(struct_name)
    if sid == idc.BADADDR:
        print("no existing structure")
        return

    def readlines(filename):
        for line in get_stripped_lines(filename):
            print(line)
            parts = re.split(' +|:', line)
            yield (int(parts[0], 16), parts[1], int(parts[3]), int(parts[5], 16), parts[7] if len(parts) > 7 else 'char[{}]'.format(int(parts[3])))

    # def structAddMember(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32):
    for f in readlines(filename):
        structAddMember(sid, f[1], f[0], f[3], -1, f[2])


def StructMaker(ea, struct_name, var=None, self_offset = 0, floor = 0):
    ea = eax(ea)
    sid = idc.get_struc_id(struct_name)
    if sid == idc.BADADDR:
        #  idc.add_struc(index, name, is_union)
        idc.add_struc(-1, struct_name, 0)

    sid = idc.get_struc_id(struct_name)
    #  size = idc.get_struc_size(sid)

    pattern_1   = re.compile(r'\*\(((?:_\w+|float)) \*\)&{}->field_([0-9a-fA-F]+)'.format(var))
    pattern_2   = re.compile(r'{}->field_([0-9a-fA-F]+)'.format(var))
    pattern_3   = re.compile(r'\*\(((?:_\w+|float)) \*\)\({} \+ (\d+)\)'.format(var))
    pattern_3aa = re.compile(r'\*\(((?:_\w+|float)) \*\)\({} - (\d+)\)'.format(var))
    pattern_3a  = re.compile(r'\({} \+ (\d+)\)'.format(var))
    pattern_3b  = re.compile(r'\*\(((?:_\w+|float)) \*\){}[; ]'.format(var))
    pattern_4   = re.compile(r'{}->gap([0-9a-fA-F]+)\[(\d+)]'.format(var))
    pattern_4a  = re.compile(r'(BYTE\d+|DWORD\d+|HIBYTE|HIDWORD|HIWORD|LOBYTE|LODWORD|LOWORD|SBYTE\d+|SHIBYTE|SHIDWORD|SHIWORD|SLOBYTE|SLODWORD|SLOWORD|SWORD\d+|WORD\d+)\({}->(\w+)\)'.format(var))
    # *(_QWORD *)&pVehicle->unpad_c00
    # nothing catches: LODWORD({}->pad_1348[0]) = 0;
    pattern_4b  = re.compile(r'\*\(((?:_\w+|float)) \*\)&{}->(\w+)'.format(var))
    pattern_4c  = re.compile(r'\*\(((?:_\w+|float)) \*\){}->gap(\w+)'.format(var))

    def readlines(filename):
        for line in get_stripped_lines(filename):
            yield line

    if isinstance(ea, str):
        decompiled = readlines(ea)
    else:
        decompiled = decompile_function_for_funcdefs(ea)

    for f in decompiled:
        f = f.replace('pVehicle_3', 'self')
        f = f.replace('pVehicle_4', 'self')
        f = f.replace('pVehicle', 'self')
        # print("line: %s" % f)
        for (_gap, _offset) in re.findall(pattern_4, f):
            offset = int(_gap, 16) + int(_offset, 10)
            if offset < floor: continue
            if offset % 8 == 0:
                _type = "_QWORD"
            elif offset % 4 == 0:
                _type = "_DWORD"
            elif offset % 2 == 0:
                _type = "_WORD"
            else:
                _type = "_BYTE"
            name="%s_%03x_maybe" % (_type.lstrip('_').lower(), offset)
            print("pattern 4: %s" % (name))
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', name='{}', self_offset=0x{:x})".format(sid, offset, _type, name, self_offset))
            structAdd(sid, offset, _type, "maybe", self_offset=self_offset)
        for (_offset) in re.findall(pattern_3a, f):
            offset = int(_offset, 10)
            if offset < floor: continue
            if offset % 8 == 0:
                _type = "_QWORD"
            elif offset % 4 == 0:
                _type = "_DWORD"
            elif offset % 2 == 0:
                _type = "_WORD"
            else:
                _type = "_BYTE"
            name="%s_%03x_maybe" % (_type.lstrip('_').lower(), offset)
            print("pattern 3a: %s" % (name))
            # idc.add_struc_member(sid, name, offset, flag, typeid, nbytes)
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', name='{}', self_offset=0x{:x})".format(sid, offset, _type, name, self_offset))
            structAdd(sid, offset, _type, "maybe", self_offset=self_offset)
        for (_type, _offset) in re.findall(pattern_1, f):
            # [('_DWORD', '1B8')]
            offset = int(_offset, 16)
            if offset < floor: continue
            name="%s_%03x" % (_type, offset)
            print("pattern 1: %s" % (name))
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', count=1, self_offset=0x{:x})".format(sid, offset, _type, self_offset))
            structAdd(sid, offset, _type, self_offset=self_offset)
        
        # line:         if ( LODWORD(pCamera->field_2A8)
        # pattern_2     re.compile(r'{}->field_([0-9a-fA-F]+)'.format(var))
        for (_offset) in re.findall(pattern_2, f):
            offset = int(_offset, 16)
            if offset < floor: continue
            _type = "_BYTE"
            name="%s_%03x" % (_type, offset)
            print("pattern 2: %s" % (name))
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', count=1, self_offset=0x{:x})".format(sid, offset, _type, self_offset))
            structAdd(sid, offset, _type, self_offset=self_offset)
        for (_type, _offset) in re.findall(pattern_3, f):
            offset = int(_offset, 10)
            if offset < floor: continue
            name="%s_%03x" % (_type.lstrip('_').lower(), offset)
            print("pattern 3: %s" % (name))
            structAdd(sid, offset, _type, self_offset=self_offset)
        for (_type, _offset) in re.findall(pattern_3aa, f):
            offset = 0 - int(_offset, 10)
            if offset < floor: continue
            name="%s_%03x" % (_type.lstrip('_').lower(), offset)
            print("pattern 3: %s" % (name))
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', count=1, self_offset=0x{:x})".format(sid, offset, _type, self_offset))
            structAdd(sid, offset, _type, self_offset=self_offset)

        for (_type) in re.findall(pattern_3b, f):
            offset = 0
            if offset < floor: continue
            name="%s_%03x" % (_type.lstrip('_').lower(), offset)
            print("pattern 3b: %s" % (name))
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', count=1, self_offset=0x{:x})".format(sid, offset, _type, self_offset))
            structAdd(sid, offset, _type, self_offset=self_offset)

        # line:         if ( *(_DWORD *)&pCamera->byte_2a8
        # pattern_4b    re.compile(r'\*\(((?:_\w+|float)) \*\)&{}->(\w+)'.format(var))
        # pattern 4b:   name: dword_2a8, offset: 0x2a8, _type: _DWORD
        for (_type, _field) in re.findall(pattern_4b, f):
            offset = idc.get_member_offset(sid, _field)
            if offset < floor: continue
            if offset != idc.BADADDR and offset > -1:
                name="%s_%03x" % (_type.lstrip('_').lower(), offset)
                print("pattern 4b: %s, %s, %s" % (name, hex(offset), _type))
                print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', name='{}', self_offset=0x{:x})".format(sid, offset, _type, name, self_offset))
                structAdd(sid, offset, _type, name, self_offset=self_offset)
        for (_type, offset) in re.findall(pattern_4c, f):
            offset = int(offset.strip('_'), 16)
            if offset < floor: continue
            if offset != idc.BADADDR and offset > 0:
                name="%s_%03x" % (_type.lstrip('_').lower(), offset)
                print("pattern 4c: %s, %s, %s" % (name, hex(offset), _type))
                print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', name='{}', self_offset=0x{:x})".format(sid, offset, _type, name, self_offset))
                structAdd(sid, offset, _type, name, self_offset=self_offset)
        for (_macro, _field) in re.findall(pattern_4a, f):
            # pattern_4a  = re.compile(r'(BYTE\d+|DWORD\d+|HIBYTE|HIDWORD|HIWOR..etc...|SWORD\d+|WORD\d+)\(self->(\w+)\)')
            # HIDWORD(self->qword_maybe_210) = LODWORD(defaultCoords.y);
            # LOBYTE(self->dword_1ff8_maybe) = 0;
            # BYTE2(self->dword_1ff8_maybe) = 0;
            # LODWORD(self->pad_1348[0]) = 0;
            offset = idc.get_member_offset(sid, _field)
            if offset < floor: continue
            if sid > -1:
                if "DWORD" in _macro:
                    _type = "_DWORD"
                elif "WORD" in _macro:
                    _type = "_WORD"
                elif "BYTE" in _macro:
                    _type = "_BYTE"
                else:
                    print("Unknown macro: %s" % _macro)
                    continue
            else:
                print("Couldn't find struct field: %s" % _field)
                continue

            postfix_number = string_between_subject_first(_macro, _type.lstrip('_'), '')
            if postfix_number:
                offset += int(postfix_number)
            name="%s_%03x" % (_type[1:].lower(), offset)
            print("pattern 4a: %s" % (name))
            # dprint("[readlines] structAdd(sid, offset, _type, self_offset")
            # def structAdd(sid, offset, _type, name = None, count = 1, self_offset = 0):
            print("[readlines] structAdd(sid=0x{:x}, offset=0x{:x}, _type='{}', count=1, self_offset=0x{:x})".format(sid, offset, _type, self_offset))
            
            structAdd(sid, offset, _type, self_offset=self_offset)

def callable_m(obj, name):
    """
    Return whether the named attribute of an object is callable

    Note that classes are callable, as are instances of classes with a
    __call__() method.
    """

    try:
        return callable(getattr(obj, name))
    except AttributeError:
        return False

def call(obj, name, *args):
    try:
        return getattr(obj, name)(*args)
    except TypeError as e:
        #  print("Exception: {}".format(repr(e)))
        return None


def call_every_tinfo_is(t):
    object_methods = [m for m in dir(t) if m.startswith('is_') and callable_m(t, m)]
    #  can_call = []
    #  for method_name in object_methods:
        #  try:
            #  if callable(getattr(t, method_name)):
                #  can_call.append(method_name)
        #  except AttributeError:
            #  pass
    results = [x for x in object_methods if call(t, x) is True]
    #  results = []
    #  for method_name in object_methods:
        #  try:
            #  result = getattr(t, method_name)()
            #  if result:
                #  results.append((method_name, result))
        #  except:
            #  pass
    return results

class my_tinfo_visitor_t(idaapi.tinfo_visitor_t):
    r"""
    Proxy of C++ tinfo_visitor_t class.
    """

    def __init__(self, *args):
        r"""


        __init__(self, s=0) -> tinfo_visitor_t
            s: int
        """
        super().__init__(*args)
        self._offset = 0
        self._visited_types = set()
        self._count = -1

    def visit_type(self, *args):
        r"""
        Visit a subtype? this function must be implemented in the derived
        class. it may optionally fill out with the new type info. this can be
        used to modify types (in this case the 'out' argument of 'apply_to()'
        may not be NULL) return 0 to continue the traversal. return !=0 to
        stop the traversal.

        visit_type(self, out, tif, name, cmt) -> int
            @param out (C++: type_mods_t  *)
            @param tif (C++: const  tinfo_t  &)
            @param name (C++: const char *)
            @param cmt (C++: const char *)
        """
        # print("visit_type", args) # out, tif, name, cmt)
        out, tif, name, cmt = args
        if isinstance(out, tuple):
            self._offset, align = out
        else:
            align = 0
            # as a visitor, we need to ignore the first call which will be
            # info about our entire structure
            self._count += 1
            if self._count == 0:
                print("visit_subtype {}".format(tif.dstr()))
                ida_typeinf.visit_subtypes(self, out, tif, name, cmt)
                print("returning 0")
                return 0

        size = tif.get_size() # align, idaapi.GTS_NESTED)
        padding = size - tif.get_unpadded_size()

        # Not really sure what to here
        if size == idc.BADADDR or name is None:
            size = 0
            padding = 0

        comment = ''
        if cmt:
            comment += " // {}".format(cmt)
        if padding:
            comment += " // padding: {}".format(padding)

        if tif.is_decl_complex():
            print("\n{}\n{:6} {:6} {:5} {} {} {}".format(
                " ".join(_.map(call_every_tinfo_is(tif), lambda x, *a: x[3:])),
                hex(self._offset),
                align, # self._offset,
                hex(size),
                tif.dstr(),
                name,
                comment))

        else:
            print("{:6} {:6} {:5} {} {} {}".format(
                hex(self._offset),
                align,
                hex(size),
                tif.dstr(),
                name,
                comment))


        # for correct operation as a visitor
        if not isinstance(out, tuple):
            self._offset += size
        return 0

    #  def prune_now(self, *args) -> "void":
        #  r"""
#
#
        #  To refuse to visit children of the current type, use this:
        #  """
        #  return _ida_typeinf.tinfo_visitor_t_prune_now(self, *args)
#
    #  def apply_to(self, *args) -> "int":
        #  r"""
#
#
        #  Call this function to initiate the traversal.
        #
        #  apply_to(self, tif, out=None, name=None, cmt=None) -> int
            #  @param tif (C++: const  tinfo_t  &)
            #  @param out (C++: type_mods_t  *)
            #  @param name (C++: const char *)
            #  @param cmt (C++: const char *)
        #  """
        #  return _ida_typeinf.tinfo_visitor_t_apply_to(self, *args)
        #
def my_add_enum(enum, value, name, toupper=False):
    if isinstance(value, str) and isinstance(name, int):
        name, value = value, name
    if toupper:
        name = name.upper()
    
    id = idc.get_enum(enum)
    print("get_enum({}): {:x}".format(enum, id))
    if id == BADADDR:
        for x, y in get_struc_ordinal_re(enum, re.I):
            name = y
            id = idc.get_enum(id)
            print("Found enum {} (#{})".format(name, id))
    if id == BADADDR:
        print("id: {}, Adding new enum: {}".format(id, enum))
        id = idc.add_enum(-1, enum, idaapi.hex_flag())

    r = idc.add_enum_member(id, name, value, -1)
    repeat = 1
    while repeat:
        repeat = 0
        if r:
            s = "unknown error adding enum"
            if r == ida_enum.ENUM_MEMBER_ERROR_NAME:
                s = """ already have member with this name (bad name) """
                """
                Python>f = get_first_enum_member(e, -1)
                Python>f
                0x269eb
                Python>f = get_next_enum_member(e, f, -1)
                Python>f
                0xe813dd
                Python>f = get_next_enum_member(e, f, -1)
                Python>f
                e = get_enum('megahash')
                del_enum_member(e, joaat('bonus_aukrgm'), 0, -1); brute_enum('report_hash2_', joaat('bonus_aukrgm'))

                """
            if r == ida_enum.ENUM_MEMBER_ERROR_VALUE:
                s = """ already have 256 members with this value """
            if r == ida_enum.ENUM_MEMBER_ERROR_ENUM:
                s = """ bad enum id """
            if r == ida_enum.ENUM_MEMBER_ERROR_MASK:
                s = """ bad bmask """
            if r == ida_enum.ENUM_MEMBER_ERROR_ILLV:
                s = """ bad bmask and value combination (~bmask & value != 0) """
            print("add_enum: error: {}".format(s))
    return r

def brute_enum(prefix, hash):
    if isinstance(hash, str):
        hash = joaat(hash)
    result = brute(prefix, hash)
    e = get_enum('megahash')
    del_enum_member(e, hash, 0, -1); 
    my_add_enum('megahash', hash, result)

def rage_map(name, T):
    s = """
        #define NAME {}
        #define BUCKET Bucket
        #define ENTRY Entry
        #define T {}

        #define KEY_TYPE uint32_t
        #define SIZE_TYPE uint16_t

        #define VALUE_TYPE T
        #define ENTRY_STRUCT NAME::ENTRY
        #define BUCKET_STRUCT NAME::BUCKET
        #define MAP_STRUCT NAME

        struct ENTRY_STRUCT {{
            KEY_TYPE key;
            VALUE_TYPE value;
            ENTRY_STRUCT* next;
        }};

        struct BUCKET_STRUCT {{
            ENTRY_STRUCT* first;
        }};

        struct MAP_STRUCT {{
            BUCKET_STRUCT* Buckets;
            SIZE_TYPE BucketCount;
            SIZE_TYPE Size;
            char gapC[3];
            bool DynamicSize;
        }};
    """.format(name, T)
    return idc.parse_decls(s)

def rage_vector(name, T):
    s = """
        struct {}
        {{
            {}* elements;
            uint16_t size;
            uint16_t reserved;
        }};
    """.format(name, T)
    return idc.parse_decls(s)


def add_enum_upper(enum, value, name):
    return my_add_enum(enum, value, name, toupper=True)


def struct_udt(name):
    visitor = my_tinfo_visitor_t()
    tif = get_tinfo(name)

    ordinal = tif.get_ordinal()
    print("ordinal", ordinal)

    _typename = tif.get_type_name()
    print("_typename", _typename)

    name_sid = idc.get_struc_id(_typename)
    print("name_sid", name_sid)


    nmembers = tif.get_udt_nmembers()
    for index in range(nmembers):
        u = idaapi.udt_member_t()
        u.offset = index
        if tif.find_udt_member(u, idaapi.STRMEM_INDEX) != -1:
            sys.modules["__main__"].udt = u
            out = None
            if u.cmt:
                print("omg, there was a udt comment!", u.cmt)
            else:
                offset = u.offset // 8
                comment = idc.get_member_cmt(name_sid, offset, 0)
                if comment:
                    u.cmt = comment
            visitor.visit_type((u.offset // 8, u.effalign), u.type, u.name, u.cmt)
            # member = Member(u.offset // 8, u.type, None)
            # member.name = u.name
            # self.add_row(member)
            #
#  old way
#  execfile('StructMaker.py')
#  t = get_tinfo('CPed')
#  v = my_tinfo_visitor_t()
#  m = idaapi.type_mods_t()
#  idaapi.visit_subtypes(v, m, t, "XXX", "cmt")
#
#  new way:
#  execfile('StructMaker.py')
#  t = get_tinfo('CPed')
#  v = my_tinfo_visitor_t()
#  # v.apply_to(t)
#  struct_udt('CPed')
# idc.parse_decl("", PT_PAK1 | PT_SILENT)
#
#
# Using get..
#  til = t.get_til()
#  r = idaapi.get_named_type(til, 'PlayerUID', idaapi.NTF_TYPE)
#  h = "code, type_str, fields_str, cmt, field_cmts, sclass, value".split(", ")
#  _.zipObject(h, r)
#  pp(_.zipObject(h, r))#

parseTypeDefs(__typedefs_h.splitlines())
