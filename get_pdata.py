import os, re, itertools
import idc
from glob import glob
from string_between import string_between
from exectools import execfile, make_refresh
refresh_pdata = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))
from JsonStoredList import JsonStoredDict, json_save_safe
from pprint import PrettyPrinter
from mypprint import MyPrettyPrinter
pp = MyPrettyPrinter(indent=4).pprint
pf = MyPrettyPrinter(indent=4).pformat


native_structs = """
    typedef int Hash;
    typedef int Entity;
    typedef int Player;
    typedef int FireId;
    typedef int Ped;
    typedef int Vehicle;
    typedef int Cam;
    typedef int CarGenerator;
    typedef int Group;
    typedef int Train;
    typedef int Pickup;
    typedef int Object;
    typedef int Weapon;
    typedef int Interior;
    typedef int Texture;
    typedef int TextureDict;
    typedef int CoverPoint;
    typedef int Camera;
    typedef int TaskSequence;
    typedef int ColourIndex;
    typedef int Sphere;
    typedef int Blip;

    struct NarrowVector3
    {
      float x;
      float y;
      float z;
    };

    struct WideVector3
    {
      __declspec(align(8)) float x;
      __declspec(align(8)) float y;
      __declspec(align(8)) float z;
    };


    union scrNativeCallContextArgList
    {
      bool Bool;
      float FLOAT;
      float *PFLOAT;
      signed __int8 INT8;
      signed __int8 *LPSTR;
      signed __int8 *PINT8;
      signed __int16 INT16;
      signed __int16 *PINT16;
      signed int INT32;
      signed int *PINT32;
      signed int BOOL;
      signed int Any;
      signed int Hash;
      signed int Entity;
      signed int Player;
      signed int FireId;
      signed int Ped;
      signed int Vehicle;
      signed int Cam;
      signed int CarGenerator;
      signed int Group;
      signed int Train;
      signed int Pickup;
      signed int Object;
      signed int Weapon;
      signed int Interior;
      signed int Texture;
      signed int TextureDict;
      signed int CoverPoint;
      signed int Camera;
      signed int TaskSequence;
      signed int ColourIndex;
      signed int Sphere;
      signed int Blip;
      signed __int64 INT64;
      signed __int64 *PINT64;
      unsigned __int8 BYTE;
      unsigned __int8 *PUINT8;
      unsigned __int16 UINT16;
      unsigned __int16 *PUINT16;
      unsigned int UINT32;
      unsigned int *PUINT32;
      unsigned __int64 UINT64;
      unsigned __int64 *PUINT64;
      void *LPVOID;
    };

    struct scrNativeCallContextArgStruct
    {
      scrNativeCallContextArgList a1;
      scrNativeCallContextArgList a2;
      scrNativeCallContextArgList a3;
      scrNativeCallContextArgList a4;
      scrNativeCallContextArgList a5;
      scrNativeCallContextArgList a6;
      scrNativeCallContextArgList a7;
      scrNativeCallContextArgList a8;
      scrNativeCallContextArgList a9;
      scrNativeCallContextArgList a10;
      scrNativeCallContextArgList a11;
      scrNativeCallContextArgList a12;
      scrNativeCallContextArgList a13;
      scrNativeCallContextArgList a14;
      scrNativeCallContextArgList a15;
      scrNativeCallContextArgList a16;
      scrNativeCallContextArgList a17;
      scrNativeCallContextArgList a18;
      scrNativeCallContextArgList a19;
      scrNativeCallContextArgList a20;
      scrNativeCallContextArgList a21;
      scrNativeCallContextArgList a22;
      scrNativeCallContextArgList a23;
      scrNativeCallContextArgList a24;
    };

    struct __declspec(align(16)) scrNativeCallContext
    {
      scrNativeCallContextArgStruct *pReturn;
      UINT32 m_nArgCount;
      scrNativeCallContextArgStruct *pArgs;
      UINT32 m_nReturnCount;
      WideVector3 *m_pOutVectors[4];
      NarrowVector3 m_VectorResults[4];
    };

    typedef scrNativeCallContext *native;

    """

sid = idc.get_struc_id('native')
if sid == idc.BADADDR:
    idc.parse_decls(native_structs, 0)


def file_size(fn):
    return os.path.getsize(fn)

def file_exists(fn):
    return os.path.exists(fn) and os.path.isfile(fn)

def hex_string(item):
    if isinstance(item, str):
        return ' '.join(["%02x" % ord(x) for x in item])

def native_handler_sig(ea):
    a = list()
    for x in obfu.combEx(ea, length=256)[1]:
        a.append(x[0:2])
    ra = list()
    skip1 = False
    replValues = []
    it = stutter_chunk(sig_maker_ex(addresses=a, fullSig=1, quick=1, show=0, ripRelAsQuad=1, replValues=replValues, noSig=0), 2, 1)
    for x, y in it:
        if not y or len(y) != 2 or len(x) != 2:
            ra.append(x)
        else:
            ra.append(x + " " + y)
            next(it)

    print(ra)
    if replValues:
        replValues = _.sort(_.uniq(replValues))
    result = ' '.join(["'{}'".format(x) for x in replValues])
    if result:
        result += ' '
    result += ' '.join([transmute_mov(x) for x in ra])
    print("sig: {}".format(result))
    return result

def get_unwind_info(offset):
    record = [0, 0, '']
    if not offset:
        return record
    if offset > ida_ida.cvar.inf.min_ea:
        offset -= ida_ida.cvar.inf.min_ea
    for ref in XrefsTo(ida_ida.cvar.inf.min_ea + offset):
        ea = ref.frm
        if idc.get_segm_name(ea) == '.pdata':
            unwind_info = ([x + ida_ida.cvar.inf.min_ea for x in struct.unpack('lll', get_bytes(ea, 12))])
            if offset + ida_ida.cvar.inf.min_ea == unwind_info[0]:
                unwind_info_addr = unwind_info[2]
                unwind_info_count = struct.unpack('BBBB', get_bytes(unwind_info_addr, 4))[2]
                unwind_bytes = get_bytes(unwind_info_addr, 4 + unwind_info_count * 2)
                unwind_hex = hex_string(unwind_bytes) or ''
                # record = [hex(ea - ida_ida.cvar.inf.min_ea)[2:], hex(unwind_info_addr - ida_ida.cvar.inf.min_ea)[2:], unwind_hex]
                record = [hex(ea - ida_ida.cvar.inf.min_ea)[2:], 0, unwind_hex]
                break

    return record

def skip_to_pdata(ea, limit=None):
    def is_pdata(ea):
        if ea is None:
            raise RuntimeError("ea was none")
        if ea == limit:
            return -1
        return len(seg_refs_to(ea, '.pdata')) > 0 and _.any(get_unwind_info(ea))
    r = SkipJumps(ea, until=is_pdata, untilInclusive=True)
    if r == limit:
        return 0
    if is_pdata(r):
        return r
    return 0

def file_split_path(fn):
    result = []
    root, fn = os.path.splitdrive(fn)
    while True:
        head, tail = os.path.split(fn)
        print(head, tail)
        if not head or not tail:
            break
        result.append(tail)
        fn = head

    result.append(root + os.path.sep)
    result.reverse()
    return result

def MakeFuncs(ea, until=None, unpatch=False):
    def helper(x, *a):
        if unpatch:
            if IsFunc_(x):
                if not IsFuncHead(x) or GetFuncSize(x) < 6 or not HasUserName(x):
                    unpatch_func2(x, unpatch=1)
                    idc.del_func(x)
                    idc.auto_wait()
                    UnpatchUntilChunk(x)
            else:
                UnpatchUntilChunk(x)
        if isObfuJmp(x):
            obfu._patch(x)
        if IsFuncHead(x) or (isNop(idc.prev_not_tail(x)) and IsFuncHead(idc.prev_not_tail(x))):
            pass
        else:
            if not ida_funcs.add_func(x):
                ForceFunction(x)

        end = EaseCode(x, forceStart=1)
        if IsFunc_(x) and not IsChunk(x):
            if GetFuncEnd(x) != end:
                SetFuncEnd(x, end)
        if not idc.SetType(GetFuncStart(x), "void native_handler(native args);"):
            print("couldn't set type at 0x{:x}".format(ea))

    return SkipJumps(ea, until=until, includeStart=True, includeEnd=True, iteratee=helper, skipObfu=1, skipNops=1)

def check_pdata(label=None, func=None, color=None, tails=None, tailsTerm=None, names=None, old_hash=None, spd=None, args=None, unpatch=False):
    global natives;
    _source = ''
    _build = ''
    _type = None
    old_hash = old_hash or 0
    impl_actual = 0
    impl_address = 0
    handler_actual = 0
    handler_address = 0
    count = 0
    re_version = re.compile(r'gta(s[ct]).*?[^0-9](\d{3,4})[^0-9]')
    for __source, __build in re.findall(re_version, get_idb_path()):
        _source = __source
        _build = __build
        break
    if _build:
        for _type in ("impl", "handler"):
            for _bucket in '0123456789abcdef':
                _tails_path = "e:\\git\\ida\\natives\\tails\\{}\\{}\\{}\\{:016x}.asm".format(_build, _type, _bucket, old_hash)
                split_path = file_split_path(_tails_path)
                # print("split_path: {}".format(split_path))
                for i, p in enumerate(split_path):
                    if i == 0: continue
                    if i == len(split_path) - 1: break
                    #  _path = os.path.join(*split_path[0:i+1])
                    _path = os.path.sep.join(split_path[0:i+1])
                    _exists = os.path.exists(_path)
                    # dprint("[debug] _path, _exists")
                    #  print("[debug] _path:{}, _exists:{}".format(_path, _exists))
                    if not _exists:
                        os.mkdir(_path)

                

    name_table = {}
    if names:
        if not file_exists(names):
            print("using default names file, since file provided in names argument cannot be found")
            names = 'e:/ida/gtasc-2699/native-names-2699.txt'
            # raise RuntimeError('!file_exists({})'.format(names))
        for line in get_stripped_lines(names):
            _hash, _func = line.split(' ', 1)
            #  0x3a8253262437ba02 AUDIO PROC PRELOAD_SCRIPT_CONVERSATION(BOOL DisplaySubtitles, BOOL addToBriefScreen = TRUE, BOOL cloneConversation = FALSE, BOOL Interruptible = TRUE)
            #  0xd973aa641a1cf78a AUDIO FUNC BOOL GET_IS_PRELOADED_CONVERSATION_READY()

            native_args = []
            _args = string_between('(', ')', _func)
            if _args:
                for _arg in _args.split(', '):
                    _default, _arg = string_between_splice(' = ', '', _arg, inclusive=1, repl='')
                    _vtype, _vname = _arg.split(' ', 1)
                    _array, _vname = string_between_splice('[', ']', _vname, inclusive=1, repl='')
                    _ref, _vtype = string_between_splice('&', '', _vtype, inclusive=1, repl='')
                    native_args.append(SimpleAttrDict({
                        'type': _vtype,
                        'ref': _ref,
                        'name': _vname,
                        'array': _array,
                        'default': _default
                    }))

            name_table[parseHex(_hash)] = SimpleAttrDict({ 
                    'name': "NATIVE::{}::{}".format(
                        string_between('', ' ', _func),
                        string_between(' ', '(', _func, rightmost=True)
                        ),
                    'rtype': string_between('FUNC ', ' ', _func),
                    'args': native_args,
                    'raw': _func,
                    'hash': _hash
            })

        setglobal('name_table', name_table)


    def check_tails(ea, r, output=None):
        output = A(output)
        bad = []
        if len(r):
            print("{:x} tail_errors: {}".format(ea, "; ".join(r)))
            if not retrace(ea) and not IsFuncHead(ea):
                retrace(ea)
            r = func_tails(ea, quiet=1, output=output, removeLabels=1)
            if len(r):
                ZeroFunction(ea)
                retrace(ea)
                r = func_tails(ea, output=output, removeLabels=1)
                if len(r):
                    print("\n".join(r))
                    bad.append(r)
                    if tailsTerm:
                        raise AdvanceFailure("func_tails {:x}".format(ea))

        _bucket = "{:016x}".format(old_hash)[0]
        _tails_path = "e:\\git\\ida\\natives\\tails\\{}\\{}\\{}\\{:016x}.asm".format(_build, _type, _bucket, old_hash)
        if _tails_path and output:
            file_put_contents(_tails_path, "\n".join(output))

        return bad

            #  file_put_contents("e:\\git\\ida\\natives\\build\\

    def lblfunc(impl_or_handler, oname, handler_address, x, until):
        # LabelAddressPlus(x, "native_{}_{}_{:x}".format(impl_or_handler, oname, parent), flags=SN_LOCAL)
        # SkipJumps(x, until=until, includeStart=1, includeEnd=0, skipObfu=1, skipNops=1, iteratee=lambda v, *a: LabelAddressPlus(GetFuncStart(x) if IsFunc_(x) else x, "", flags=SN_LOCAL))
        end = SkipJumps(x, until=until, includeStart=1, includeEnd=0, skipObfu=1, skipNops=1, iteratee=lambda v, *a: LabelAddressPlus(x, oname, force=x==handler_address))
        LabelAddressPlus(end, f"{oname}_ACTUAL", force=1)
        return end
        #  if not LabelAddressPlus(x, "{}_{}".format(oname, count), force=1):
            #  if impl_address:
                #  SkipJumps(impl_address, iteratee=lambda x, *a: ForceFunction(x) == 123)
            #  SkipJumps(handler_address, until=impl_address, iteratee=lambda x, *a: ForceFunction(x) == 123)
        #  count += 1

    filename = ''
    if color or label or tails or spd or func:
        filename = 'dummy.json'
    else:
        if _build and _source:
            filename = 'e:/git/ida/natives/pdata-{}-{}.json'.format(_build, _source)
        if not filename:
            filename = 'pdata-e-{}.json'.format(os.path.splitext(os.path.splitext(os.path.basename(get_idb_path()))[0])[0])

    with JsonStoredList(filename) as plist:
        while len(plist): plist.pop()
        count = 0
        dbg =0
        oname = ''
        new_hash=0
        x=0
        handler_offset=0
        impl_offset=0
        oname_impl = ''

        p = ProgressBar(len(natives))
        for i, row in enumerate(natives):
            p.update(i)
            if len(row) == 4:
                oname, new_hash, handler_offset, impl_offset = row
                old_hash = new_hash
            else:
                oname, x, new_hash, handler_offset, impl_offset = row[0:5]
                old_hash = new_hash

            oname_impl = oname.lower().replace('::', '__')

            impl_actual = 0
            impl_address = 0
            handler_actual = 0
            handler_address = 0
            if impl_offset and impl_offset != 0xffffffff and impl_offset != handler_offset:
                impl_address = impl_offset + ida_ida.cvar.inf.min_ea
                impl_actual = SkipJumps(impl_address, skipObfu=1, skipNops=1)
            else:
                impl_address = impl_actual = impl_offset = 0

            if handler_offset and handler_offset != 0xffffffff:
                handler_address = handler_offset + ida_ida.cvar.inf.min_ea
                handler_actual = SkipJumps(handler_address, skipObfu=1, skipNops=1)
            else:
                handler_address = handler_actual = handler_offset = 0

            start_addresses = [x for x in [impl_address, handler_address] if x]
            # dprint("[start_addresses] start_addresses")
            #  print("[start_addresses] start_addresses:{}".format(hex(start_addresses)))
            
            #  print("[debug] oname:{}, new_hash:{:x}, handler_offset:{:x}, impl_offset:{:x}".format(oname, new_hash, handler_offset, impl_offset))
            if func:
                if impl_address:
                    #  ForceFunction(impl_address)
                    MakeFuncs(impl_address, unpatch=unpatch)
                #  ForceFunction(handler_address)
                MakeFuncs(handler_address, until=impl_address, unpatch=unpatch)
            if color:
                retrace_list(start_addresses, recolor=1, func=func)

            ninfo = None
            if name_table:
                if new_hash in name_table:
                    ninfo = name_table[new_hash]
                    oname = ninfo.name
                else:
                    print("Missing name for hash: {:#x}".format(new_hash))


            if label:
                until = 0;
                if impl_actual and impl_offset and impl_offset != 0xffffffff and impl_offset != handler_offset:
                    until = impl_address
                    count = 0
                    lblfunc('impl', oname_impl, impl_address, impl_address, until)
                if handler_offset and handler_offset != 0xffffffff:
                    #  print("addr: {:x}".format(handler_address))
                    count = 0
                    lblfunc('handler', oname, handler_address, handler_address, until)
                #  print("Labelled {}".format(oname))
            if args:
                if ninfo and not ninfo.rtype and not ninfo.args:
                    _settype = "void __fastcall func()"
                else:
                    _settype = "void __fastcall func(native args)"
                until = impl_address
                end = SkipJumps(handler_address, until=until, includeStart=True, includeEnd=True, skipObfu=1, skipNops=1, iteratee=lambda x, *a: idc.SetType(GetFuncStart(x), _settype))
                if ninfo and IsValidEA(end):
                    # cmt = "[NATIVE-ARGS] {} {}({})".format(ninfo.rtype or 'void', string_between('::', '', oname, rightmost=1, retn_all_on_fail=1), ", ".join([' '.join(_.filter(x.values())) for x in t.args]))
                    cmt = "[NATIVE-ARGS] {} {}".format(ninfo.hash, ninfo.raw)
                    Commenter(end, "func").remove_matching(cmt.replace('[', '\\['))
                    Commenter(end, "func").add(cmt)
                    Commenter(handler_address, "func", True).remove_matching(r'^\[NATIVE-ARGS]')
                    # Commenter(handler_address, "func", True).add(cmt)
                    Commenter(handler_address, "func").remove_matching(cmt.replace('[', '\\['))
                    Commenter(handler_address, "func").add(cmt)


            if spd:
                if handler_actual:
                    _fix_spd_auto(handler_actual)
                if impl_actual:
                    _fix_spd_auto(impl_actual)
            if tails:
                tail_out = []
                bad = []
                globals()['bad_tails'] = bad
                if handler_actual:
                    _type = 'handler'
                    r = func_tails(handler_actual, quiet=1, output=tail_out)
                    bad.extend(check_tails(handler_actual, r, output=tail_out))
                if impl_actual:
                    _type = 'impl'
                    r = func_tails(impl_actual, quiet=1, output=tail_out)
                    bad.extend(check_tails(impl_actual, r, output=tail_out))

                globals()['bad_tails'] = bad

            if color or label or tails or spd or func or args:
                continue

            # dprint("[debug] oname, new_hash, handler_offset, impl_offset")
            

            count += 1
            old_hash = new_hash
            if not impl_offset or impl_offset == 0xffffffff:
                name = idc.get_func_name(handler_address)
                record_b = [-1, -1, '']
            else:
                name = idc.get_func_name(impl_address) or idc.get_func_name(handler_address)
                pdata_impl_address = skip_to_pdata(impl_address)
                record_b = get_unwind_info(pdata_impl_address)

            name = oname

            print('-----------------------------------{}------------------------------'.format(name))
            record_a = [name, "0x{:016X}".format(old_hash), "0x{:016X}".format(new_hash), hex(handler_offset), hex(impl_offset)]
            pdata_address = skip_to_pdata(handler_address, limit=impl_address)
            record_c = get_unwind_info(pdata_address)
            record_d = [native_handler_sig(SkipJumps(handler_address, until=impl_address))]
            if impl_address:
                record_d.append(native_handler_sig(SkipJumps(impl_address)))
            else:
                record_d.append("noimpl")

            record_a.append(':'.join([str(x) for x in record_b]))
            record_a.append(":".join([str(x) for x in record_c]))
            record_a.extend(record_d)
            plist.append(record_a)

def store_patches():
    print("processing patches")
    patchedbytes=[]
    #  pairs = []
    #  for k, v in ddd.items():
        #  pairs.extend([x for x in v])
    c = recordpatches1([(0, idaapi.badaddr)])
    json_save_safe('patches.json', c)


def glob_last(path):
    r = glob(path)
    if r:
        return r[-1]
    print("# Failed to locate any file matching '{}'".format(path))
    return ''

def get_stripped_lines(file_name):
    result = list()

    with open(file_name, 'r') as fr:
        for line in fr:
            yield line.strip()

def cut(filename, sep=' ', min=0):
    for line in get_stripped_lines(filename):
        splitted = re.split(sep, line)
        if splitted and len(splitted) >= min:
            yield re.split(sep, line)


def get_latest_native_names(cacheOnly=False):
    if cacheOnly and file_exists("natives-cache.json"):
        return json_load("natives-cache.json")

    nn = {}
    with JsonStoredDict('e:/git/give-two.github.io/storage/scripts/alloc8or.json') as natives:
        for namespace, d1 in natives.items():
            #  print("namespace: {}".format(namespace))
            for hash, d2 in d1.items():
                d2['namespace'] = namespace
                nn[int(hash, 16)] = d2

    with JsonStoredDict("https://raw.githubusercontent.com/alloc8or/gta5-nativedb-data/master/natives.json") as natives:
        # json_save_safe(f"/e/git/gta5-nativedb-data/natives.json", natives)
        for namespace, d1 in natives.items():
            #  print("namespace: {}".format(namespace))
            for hash, d2 in d1.items():
                d2['namespace'] = namespace
                nn[int(hash, 16)] = d2

    json_save_safe("natives-cache.json", nn)
    return nn
    

def make_latest_json():
    global natives;
    type_ranking = [None, "Any", "int"]
    #  limited_types = ['Vector3']
    limited_types = None

    def param_object(t):
        if t is None:
            return None
        _type, _name, _size = t
        o = {
            "type": _type,
            "name": _name, 
            "size": _size
        }
        return o

    def tuple_param(_param):
        _type = _param['type']
        _name = _param['name']
        _size = re.search(r'[0-9]+$', _type)
        if _size: _size = int(_size.group(0))
        else:     _size = 1
        return    _type, _name, _size

    def get_type_rank(s):
        s = s['type']
        s = s.strip('*')
        if s in type_ranking:
            return type_ranking.index(s)
        return len(type_ranking)

    def get_best_type(s1, s2):
        """get_best_type. 

        :param s1: (type, name, size)
        :param s2: (type, name, size)

        :return s1 or s2, if undecided then s1
        """
        if s1 is None and s2 is None:
            return None, None
        if s1 is None:
            return s2, s1
        if s2 is None:
            return s1, s2

        if limited_types:
            if s1['type'] not in limited_types:
                return s2
            
        if s1['size'] > s2['size']:
            return s1, s2
        if s2['size'] > s1['size']:
            return s2, s1

        r1 = get_type_rank(s1)
        r2 = get_type_rank(s2)

        if r1 > r2:
            return s1, s2
        if r2 > r1:
            return s2, s1

        #  print("equal: \n{}\n{}".format(s1, s2))
        return s1, s2



    def iterate_params(o):
        for _param in o['params']:
            y = param_object(tuple_param(_param))
            for _r in range(y['size']): 
                yield y

    _source = ''
    _build = ''
    re_version = re.compile(r'gta(s[ct]).*?[^0-9](\d{3,4})[^0-9]')
    if 'get_idb_path' not in globals():
        _source = 'sc'
        _build = '2612'
    else:
        for __source, __build in re.findall(re_version, get_idb_path()):
            _source = __source
            _build = __build

    if _build:
        
        ## set to None to force original hashes
        crossmap_file = glob_last("e:/git/GTA5Utilities/ScriptDiffer/Differ/Output/CrossMapping_323_" + str(_build) + ".txt")
        #  crossmap_file = None
        ## set to None if not using a crossmap
        natives_file = glob_last("e:/git/GTA5Utilities/ScriptDiffer/Differ/Tables/Addresses/NativeAddresses_" + str(_build) + "*.txt")
        #  natives_file = None
        ## path to formatted native argument types
        vtypes_file = glob_last("e:/git/ida/natives.*vtypes*")


        print("crossmap_file: {}".format(crossmap_file))
        print("natives_file: {}".format(natives_file))
        print("vtypes_file: {}".format(vtypes_file))

        vtypes = {}
        vtypes_cut = cut(vtypes_file, '; ', 3)
        for _vars, _vrtype, _vhash in vtypes_cut:
            _vhash = int(_vhash, 16)
            _vars = string_between('(', ')', _vars)
            _vparams = []
            if _vars:
                for _var in _vars.split(', '):
                    _varsplit = _var.split(' ')
                    if len(_varsplit) != 2:
                        print("[_var.split(' ')]: {}".format(_varsplit))

                    _type, _name = _varsplit
                    _vparams.append({
                        "type": _type,
                        "name": _name, 
                    })
            vtypes[_vhash] = {
                    "params": _vparams,
                    "return_type": _vrtype
            }

        native_hashes = []
        native_hash_to_offset = {}
        offset_to_native_hashes = defaultdict(list)

        json_result = {}
        crossmap = {}
        if crossmap_file:
            for old, new, ver in cut(crossmap_file):
                crossmap[int(new, 16)] = int(old, 16)

        alloc8 = get_latest_native_names()
        if natives_file:
            for _hash, _offset, *a in cut(natives_file, min=2):
                _hash = int(_hash, 16)
                _offset = int(_offset, 16)
                native_hashes.append(_hash)
                native_hash_to_offset[_hash] = _offset
                offset_to_native_hashes[_offset].append(_hash)
            native_hashes = [int(x[0], 16) for x in cut(natives_file, min= 2)]
        else:
            native_hashes = [x for x in alloc8.keys()]

        used = []
        for new_hash in native_hashes:
            n = {}
            if crossmap:
                old_hash = crossmap[int(new_hash)]
            else:
                print("nocrossmap")
                old_hash = new_hash
            if old_hash in vtypes:
                vtype = vtypes[old_hash]
            else:
                vtype = None
            if not old_hash in alloc8:
                for _hash in offset_to_native_hashes[native_hash_to_offset[new_hash]]:
                    if crossmap[_hash] in alloc8:
                        print("# Found alternate hash")
                        old_hash = crossmap[_hash]
            if old_hash in alloc8:
                if old_hash in used:
                    print("# HASH RE-USED: 0x{:016X}".format(old_hash))
                n = alloc8[old_hash]
                namespace = n['namespace']
                name = n['name']
                params = []
                

                if n['params'] and vtype:
                    if name == "NETWORK_GET_VC_BANK_BALANCE":
                        print("alloc: \n{}".format(pf(n)))
                        print("infms: \n{}".format(pf(vtype)))
                    alloc_iter = iterate_params(n)
                    infms_iter = iterate_params(vtype)
                    # dprint("[alloc8] [x for x in alloc_iter]")
                    #  print("[alloc8] [x for x in alloc_iter]:{}".format([x for x in alloc_iter]))
                    #  print("[infms_iter] [x for x in infms_iter]      :{}".format([x for x in infms_iter]))
                    
                    alloc = infms = False
                    while alloc is not None: # and infms is not None:
                        alloc = next(alloc_iter, None)
                        infms = next(infms_iter, None)
                        # dprint("[_loop] alloc, infms")
                        if name == "NETWORK_GET_VC_BANK_BALANCE":
                            print("[_loop] \nalloc:{}, \ninfms:{}, \nlen:  {}".format(alloc, infms, len(n['params'])))
                        
                        if alloc is None and infms is None:
                            break

                        if alloc is None:
                            params.append(infms)
                            continue
                        elif infms is None:
                            params.append(alloc)
                            continue

                        # default
                        # alloc8or params
                        # vtype params
                        best, second = get_best_type(infms, alloc)
                        #  print("best: \n{}\n{}".format(best, second))
                        params.append(best)
                        if True:
                            if best['size'] > 1:
                                # print("1kipping: {}".format(best, "None"))
                                for _r in range(best['size'] - 1):
                                    # print("skipping: {}".format(next(alloc_iter, "None")))
                                    next(alloc_iter, "None")
                                    next(infms_iter, "None")
                                    #  next(alloc_iter, None)
                                    #  print("skippin2: {}".format(next(infms_iter, "None")))
                            

                    _rtype1 = {
                        "type": n['return_type'],
                        "name": 'result' 
                    }
                    _rtype2 = {
                        "type": vtype['return_type'],
                        "name": 'result' 
                    }
                    _rtype, _second = get_best_type(param_object(tuple_param(_rtype2)), param_object(tuple_param(_rtype1)))
                    return_type = _rtype['type'].replace('BOOL', 'bool')

                    if name == "NETWORK_GET_VC_BANK_BALANCE":
                        print("final: \n{}".format(pf(params)))

                    n['return_type'] = return_type
                    n['params'] = params
                native_comment = n['comment']
                json_result["0x{:016X}".format(new_hash)] = n
                used.append(old_hash)
            else:
                print("# UNKNOWN HASH: ori: 0x{0:016X} new: 0x{0:016X}".format(old_hash, new_hash))

        json_save_safe("test_natives_" + str(_build) + ".json", json_result)
        json_save_safe("e:/git/GTA5Utilities/ScriptDiffer/YSCDisassembler/bin/Release/natives-{}.json".format(_build), json_result)
        # json_save_safe(f"/e/git/gta5-nativedb-data/nsalloc8or.json", json_result)
        return json_result

def make_native_labels(_build=''):
    global natives;
    _source = ''
    re_version = re.compile(r'gta(s[ct]).*?[^0-9](\d{3,4})[^0-9]')
    for __source, __build in re.findall(re_version, get_idb_path()):
        _source = __source
        _build = __build

    if _build:
        
        crossmap_file = glob_last("e:/git/GTA5Utilities/ScriptDiffer/Differ/Output/CrossMapping_323_" + str(_build) + ".txt")
        print("crossmap_file: {}".format(crossmap_file))
        if crossmap_file:
            crossmap = {}
            for old, new, ver in cut(crossmap_file):
                crossmap[int(new, 16)] = int(old, 16)


            alloc8 = get_latest_native_names()
            for row in natives:
                if len(row) == 4:
                    oname, new_hash, handler_offset, impl_offset = row
                else:
                    oname, old_hash, new_hash, handler_offset, impl_offset = row[0:5]

                old_hash = crossmap[int(new_hash)]
                if old_hash in alloc8:
                    #  print("nh", byteify(alloc8[old_hash_str]))
                    n = alloc8[old_hash]
                    #  pp(n)
                    namespace = n['namespace']
                    name = n['name']
                    params = n['params']
                    return_type = n['return_type']
                    native_comment = n['comment']
                    print("(0x{:08x}, '{}::{}'),".format(handler_offset, namespace, name))
                    if impl_offset and impl_offset != 0xffffffff and impl_offset != handler_offset:
                        print("(0x{:016x}, '{}__{}'),".format(handler_offset, namespace.lower(), name.lower()))
                    del alloc8[old_hash]
                else:
                    print("# (0x{:016x}, 'ERROR', '323', 0x{:016x}, '2372', 0x{:016x}),".format(handler_offset, old_hash, new_hash))


def make_decompiler_dat():
    global natives;
    _source = ''
    _build = ''
    results = {}
    re_version = re.compile(r'gta(s[ct]).*?[^0-9](\d{3,4})[^0-9]')
    for __source, __build in re.findall(re_version, get_idb_path()):
        _source = __source
        _build = __build

    if _build:
        
        crossmap_file = glob_last("e:/git/GTA5Utilities/ScriptDiffer/Differ/Output/CrossMapping_323_" + str(_build) + ".txt")
        print("crossmap_file: {}".format(crossmap_file))
        if crossmap_file:
            crossmap = {}
            for old, new, ver in cut(crossmap_file):
                crossmap[int(new, 16)] = int(old, 16)


            alloc8 = {}
            # /e/git/give-two.github.io/storage/scripts/natives.json
            alloc8 = get_latest_native_names()
            assert isinstance(_.keys(alloc8)[0], int), "alloc8 keys are not int"
            #  with JsonStoredDict('e:/git/give-two.github.io/storage/scripts/nsalloc8or.json') as tmp:
                #  alloc8 = tmp.copy()
            for row in natives:
                if len(row) == 4:
                    oname, new_hash, handler_offset, impl_offset = row
                else:
                    oname, x, new_hash, handler_offset, impl_offset = row[0:5]

                assert isinstance(new_hash, int), "hash not int"
                old_hash = crossmap[new_hash]
                old_hash_str = "0x%016X" % old_hash
                new_hash_str = "0x%016X" % new_hash
                if old_hash in alloc8:
                    #  print("nh", byteify(alloc8[old_hash_str]))
                    n = alloc8[old_hash]
                    results[old_hash] = n
                    results[new_hash] = n
                    #  pp(n)
                    namespace = n['namespace']
                    name = n['name']
                    params = n['params']
                    return_type = n['return_type']
                    native_comment = n['comment']
                    print("{}:{}:{}".format(new_hash_str, namespace, name))
                    del alloc8[old_hash]
                else:
                    print("old_hash_not_in_alloc8 {}:{}".format(new_hash_str, oname.replace('::', ':')))
    return results

def apply_native_renames():
    lookup = make_decompiler_dat()
    unfound = set()
    with JsonStoredDict("e:/git/GTA5Utilities/ScriptDiffer/YSCDisassembler/bin/Release/natives-{}.json".format(_build)) as natives:
        for fnLoc in FunctionsMatching('.*_0x.*'):
            fnName = GetFuncName(fnLoc)
            if 'common' in fnName:
                # common:common:NETWORK::_0x494B84826E4A775E:NETWORK::_0xEE3ACED204F48810:common:NETWORK::_0x7261FA840A6D9E98_helper_helper_0:NETWORK::_0xF7C55939E655699D_helper_helper:_1_others
                # common:common:system___0xe816e655de37fe20_helper
                common = True
                fnName = fnName.replace('::_', '!').replace('___', '!')
                newName = []
                for token in _.uniq(fnName.split(':')):
                    if '!' in token:
                        match = re.search(r'0x([0-9a-fA-F]{16})', token)
                        if match:
                            hashString = match.group(1)
                            try:
                                fnHashInt = parseHex(hashString)
                            except ValueError:
                                # dprint("[apply_native_renames] ValueError parsing {} from {}")
                                print("[apply_native_renames] ValueError parsing {} from {}".format(hashString, fnName))
                                continue
                        
                            fnHash = "0x%016X" % fnHashInt
                            if fnHashInt in lookup:
                                newName.append(camelCase(lookup[fnHashInt]['name']).replace('0X', '0x'))
                            else:
                                if not fnHashInt in unfound:
                                    unfound.add(fnHashInt)
                                    print("Couldn't find common fnHash {}".format(fnHash))
                                    newName.append(fnHash)
                    else:
                        newName.append(camelCase(token))
                LabelAddressPlus(fnLoc, ":".join(_.uniq(newName)))

            else:
                oldFnName = fnName
                for match in re.finditer(r'0x([0-9a-fA-F]{16})', fnName):
                    # hashString = string_between('0x', '', fnName, inclusive=1).split('_')[0]
                    hashString = match.group(1)
                    try:
                        fnHashInt = parseHex(hashString)
                    except ValueError:
                        # dprint("[apply_native_renames] ValueError parsing {} from {}")
                        print("[apply_native_renames] ValueError parsing {} from {}".format(hashString, fnName))
                        continue
                        
                    fnHash = "0x%016X" % fnHashInt
                    if fnHashInt and fnHashInt in lookup:
                        if fnName.find('::_0x' + hashString) > 0:
                            fnName = fnName.replace('::_0x' + hashString, '::' + lookup[fnHashInt]['name'])
                            if fnName.startswith('NATIVE'):
                                fnName = fnName.replace('NATIVE', lookup[fnHashInt]['namespace'])
                        elif fnName.find('___0x' + hashString) > 0:
                            fnName = fnName.replace('___0x' + hashString, '__' + lookup[fnHashInt]['name'].lower())
                        else:
                            print("!! {}: {}::{}".format( fnName, lookup[fnHashInt]['namespace'], lookup[fnHashInt]['name']))
                    else:
                        if not fnHashInt in unfound:
                            unfound.add(fnHashInt)
                            print("Couldn't find fnHash {}".format(fnHash))
                if fnName != oldFnName:
                    LabelAddressPlus(fnLoc, fnName)
                    #  except ValueError:
                        #  print("Couldn't parse hash {} from func {}".format(hashString, fnName))

import sys
if sys.stdin and sys.stdin.isatty():
    # running interactively
    print("running interactively")
    make_latest_json()
    # apply_native_renames()
else:
    print("running in the background")
