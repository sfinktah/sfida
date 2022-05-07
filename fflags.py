__version_hash__ = "300f87df28fcea09361fadbe018fd2be"
__version_info__ = (0, 0, 1)
__version__ = ",".join(map(lambda x: str(x), __version_info__))

# &
# &.update_file(__file__)

import os
from idc import *
from exectools import make_refresh
refresh_fflags = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

fflag_list = [
    # [ "MS_VAL",     MS_VAL,     None,       "Mask for byte value"             ],
    # [ "MS_CLS",     MS_CLS,     None,       "Mask for typing"                 ],
    # [ "MS_COMM",    MS_COMM,    None,       "Mask of common bits"             ],
    # [ "MS_0TYPE",   MS_0TYPE,   None,       "Mask for 1st arg typing"         ],
    # [ "MS_1TYPE",   MS_1TYPE,   None,       "Mask for 2nd arg typing"         ],
    # [ "MS_CODE",    MS_CODE,    None,       "Mask for code"                   ],


    # [ "FF_IVL",     FF_IVL,     FF_IVL,     "Byte has value"                  ],

    # macro,        mask,       match,      description ]
    [ "FF_CODE",    MS_CLS,     FF_CODE,    "Code"                            ],
    [ "FF_DATA",    MS_CLS,     FF_DATA,    "Data"                            ],
    [ "FF_TAIL",    MS_CLS,     FF_TAIL,    "Tail"                            ],
    [ "FF_UNK",     MS_CLS,     FF_UNK,     "Unknown"                         ],

    [ "FF_COMM",    FF_COMM,    FF_COMM,    "Has comment"                     ],
    [ "FF_REF",     FF_REF,     FF_REF,     "has references"                  ],
    [ "FF_LINE",    FF_LINE,    FF_LINE,    "Has next or prev cmt lines"      ],
    [ "FF_NAME",    FF_NAME,    FF_NAME,    "Has user-defined name"           ],
    [ "FF_LABL",    FF_LABL,    FF_LABL,    "Has dummy name"                  ],
    [ "FF_ANYNAME", FF_ANYNAME, FF_NAME,    "Has any name"                    ],
    [ "FF_ANYNAME", FF_ANYNAME, FF_LABL,    "Has any name"                    ],
    [ "FF_ANYNAME", FF_ANYNAME, FF_ANYNAME, "Has any name"                    ],
    [ "FF_FLOW",    FF_FLOW,    FF_FLOW,    "Exec flow from prev instruction" ],
    # "FF_SIGN",    FF_SIGN,    FF_SIGN,    "Inverted sign of operands"       ],
    # "FF_BNOT",    FF_BNOT,    FF_BNOT,    "Bitwise negation of operands"    ],
    [ "FF_VAR",     FF_VAR,     FF_VAR,     "Is byte variable"                ],

    [ "FF_FUNC",    FF_FUNC,    FF_FUNC,    "function start"                  ],
    [ "FF_IMMD",    FF_IMMD,    FF_IMMD,    "Has Immediate value"             ],
    [ "FF_JUMP",    FF_JUMP,    FF_JUMP,    "Has jump table"                  ],

    [ "FF_0VOID",   MS_0TYPE,   None,       "Void (unknown)"                  ],
    [ "FF_0NUMH",   MS_0TYPE,   FF_0NUMH,   "Hexadecimal number"              ],
    [ "FF_0NUMD",   MS_0TYPE,   FF_0NUMD,   "Decimal number"                  ],
    [ "FF_0CHAR",   MS_0TYPE,   FF_0CHAR,   "Char ('x')"                      ],
    [ "FF_0SEG",    MS_0TYPE,   FF_0SEG,    "Segment"                         ],
    [ "FF_0OFF",    MS_0TYPE,   FF_0OFF,    "Offset"                          ],
    [ "FF_0NUMB",   MS_0TYPE,   FF_0NUMB,   "Binary number"                   ],
    [ "FF_0NUMO",   MS_0TYPE,   FF_0NUMO,   "Octal number"                    ],
    [ "FF_0ENUM",   MS_0TYPE,   FF_0ENUM,   "Enumeration"                     ],
    [ "FF_0FOP",    MS_0TYPE,   FF_0FOP,    "Forced operand"                  ],
    [ "FF_0STRO",   MS_0TYPE,   FF_0STRO,   "Struct offset"                   ],
    [ "FF_0STK",    MS_0TYPE,   FF_0STK,    "Stack variable"                  ],
    # "FF_0FLT",    FF_0FLT,    FF_0FLT,    "Floating point number"           ],
    # "FF_0CUST",   FF_0CUST,   FF_0CUST,   "Custom format type"              ],

    [ "FF_1VOID",   MS_1TYPE,   None,       "Void (unknown)"                  ],
    [ "FF_1NUMH",   MS_1TYPE,   FF_1NUMH,   "Hexadecimal number"              ],
    [ "FF_1NUMD",   MS_1TYPE,   FF_1NUMD,   "Decimal number"                  ],
    [ "FF_1CHAR",   MS_1TYPE,   FF_1CHAR,   "Char ('x')"                      ],
    [ "FF_1SEG",    MS_1TYPE,   FF_1SEG,    "Segment"                         ],
    [ "FF_1OFF",    MS_1TYPE,   FF_1OFF,    "Offset"                          ],
    [ "FF_1NUMB",   MS_1TYPE,   FF_1NUMB,   "Binary number"                   ],
    [ "FF_1NUMO",   MS_1TYPE,   FF_1NUMO,   "Octal number"                    ],
    [ "FF_1ENUM",   MS_1TYPE,   FF_1ENUM,   "Enumeration"                     ],
    [ "FF_1FOP",    MS_1TYPE,   FF_1FOP,    "Forced operand"                  ],
    [ "FF_1STRO",   MS_1TYPE,   FF_1STRO,   "Struct offset"                   ],
    [ "FF_1STK",    MS_1TYPE,   FF_1STK,    "Stack variable"                  ],
    # "FF_1FLT",    FF_1FLT,    FF_1FLT,    "Floating point number"           ],
    # "FF_1CUST",   FF_1CUST,   FF_1CUST,   "Custom format type"              ],

	[ "FF_BYTE",	DT_TYPE,	FF_BYTE,	"Structure Type"	],
	[ "FF_WORD",	DT_TYPE,	FF_WORD,	"Structure Type"	],
	[ "FF_DWRD",	DT_TYPE,	FF_DWRD,	"Structure Type"	],
	[ "FF_QWRD",	DT_TYPE,	FF_QWRD,	"Structure Type"	],
	[ "FF_TBYT",	DT_TYPE,	FF_TBYT,	"Structure Type"	],
	[ "FF_ASCI",	DT_TYPE,	FF_ASCI,	"Structure Type"	],
	[ "FF_STRU",	DT_TYPE,	FF_STRU,	"Structure Type"	],
	[ "FF_OWRD",	DT_TYPE,	FF_OWRD,	"Structure Type"	],
	[ "FF_FLOAT",	DT_TYPE,	FF_FLOAT,	"Structure Type"	],
	[ "FF_DOUBLE",	DT_TYPE,	FF_DOUBLE,	"Structure Type"	],
	[ "FF_PACKREAL",	DT_TYPE,	FF_PACKREAL,	"Structure Type"	],
	[ "FF_ALIGN",	DT_TYPE,	FF_ALIGN,	"Structure Type"	],
	#  [ "FF_3BYTE",	DT_TYPE,	FF_3BYTE,	"Structure Type"	],
	[ "FF_CUSTOM",	DT_TYPE,	ida_bytes.FF_CUSTOM,	"Structure Type"	],
	#  [ "FF_YWRD",	DT_TYPE,	FF_YWRD,	"Structure Type"	],
]

operand_type_list = [
    ["o_void",   o_void,   "No Operand",                                       None          ],
    ["o_reg",    o_reg,    "General Register (al,ax,es,ds...)",                "reg"         ],
    ["o_mem",    o_mem,    "Direct Memory Reference  (DATA)",                  "addr"        ],
    ["o_phrase", o_phrase, "Memory Ref [Base Reg + Index Reg]",                "phrase"      ],
    ["o_displ",  o_displ,  "Memory Reg [Base Reg + Index Reg + Displacement]", "phrase+addr" ],
    ["o_imm",    o_imm,    "Immediate Value",                                  "value"       ],
    ["o_far",    o_far,    "Immediate Far Address  (CODE)",                    "addr"        ],
    ["o_near",   o_near,   "Immediate Near Address (CODE)",                    "addr"        ],
    ["o_trreg",  o_trreg,  "trace register",                                   None          ],
    ["o_dbreg",  o_dbreg,  "debug register",                                   None          ],
    ["o_crreg",  o_crreg,  "control register",                                 None          ],
    ["o_fpreg",  o_fpreg,  "floating point register",                          None          ],
    ["o_mmxreg", o_mmxreg, "mmx register",                                     None          ],
    ["o_xmmreg", o_xmmreg, "xmm register",                                     None          ],
]

func_flags_list = [

    ["FUNC_NORET",         ida_funcs.FUNC_NORET,     "function doesn't return"],
    ["FUNC_FAR",           ida_funcs.FUNC_FAR,       "far function"],
    ["FUNC_LIB",           ida_funcs.FUNC_LIB,       "library function"],
    ["FUNC_STATIC",        ida_funcs.FUNC_STATICDEF, "static function"],
    ["FUNC_FRAME",         ida_funcs.FUNC_FRAME,     "function uses frame pointer (BP)"],
    ["FUNC_USERFAR",       ida_funcs.FUNC_USERFAR,   "user has specified far-ness of the function"],
    ["FUNC_HIDDEN",        ida_funcs.FUNC_HIDDEN,    "a hidden function"],
    ["FUNC_THUNK",         ida_funcs.FUNC_THUNK,     "thunk (jump) function"],
    ["FUNC_BOTTOMBP",      ida_funcs.FUNC_BOTTOMBP,  "BP points to the bottom of the stack frame"],
    ["FUNC_NORET_PENDING", ida_funcs.FUNC_NORET_PENDING, "Function 'non-return' analysis must be performed. This flag is verified upon func_does_return()"],
    ["FUNC_SP_READY",      ida_funcs.FUNC_SP_READY,  "SP-analysis has been performed If this flag is on, the stack change points should not be not modified anymore. Currently this analysis is performed only for PC"],
    ["FUNC_PURGED_OK",     ida_funcs.FUNC_PURGED_OK, "'argsize' field has been validated.  If this bit is clear and 'argsize' is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module."],
    ["FUNC_TAIL",          ida_funcs.FUNC_TAIL,      "This is a function tail.  Other bits must be clear (except FUNC_HIDDEN)"],
]

def signed(n):
    return MakeSigned(n, 64)
    # return n if n <1<<63 else n - [i for i in (2**j if n//(2**(j-1)) else iter(()).next() for j in range(2**31-1))][-1]

def debug_fflags(ea = None, f = None, quiet = False):
    if ea is None:
        ea = ScreenEA()
    # for flag in fflag_list:
    #     [ macro, mask, description ] = flag

    result = []
    if isinstance(ea, idaapi.func_t):
        if f is None:
            f = ea.flags
        for k in dir(sys.modules['idc']):
            if k.startswith('FUNC_'):
                v = getattr(sys.modules['idc'], k)
                if f & v:
                    if not quiet: print("%s %s" % (k, v))
                    result.append(k)
        return result
        

    if f is None:
        f = idc.get_full_flags(ea);

    for [ macro, mask, match, description ] in fflag_list:
        if mask & f == match:
            if not quiet: print("%-12s 0x%08x  0x%08x  %s" % ( macro, mask, mask & f, description ))
    if f & FF_IVL:
        if not quiet: print("%-12s 0x%08x  0x%08x  %s" % ( "MS_VAL", 0xff, mask & f, description ))

    isList = list();
    if idc.is_code(f): isList.append("is_code")
    if idc.is_data(f): isList.append("is_data")
    if idc.is_tail(f): isList.append("is_tail")
    if idc.is_unknown(f): isList.append("is_unknown")
    if idc.is_head(f): isList.append("is_head")
    if idc.is_flow(f): isList.append("is_flow")
    if idc.isExtra(f): isList.append("isExtra")
    if idc.isRef(f): isList.append("isRef")
    if idc.hasName(f): isList.append("hasName")
    if idc.hasUserName(f): isList.append("hasUserName")
    if idc.is_defarg0(f): isList.append("is_defarg0")
    if idc.is_defarg1(f): isList.append("is_defarg1")
    if idc.isDec0(f): isList.append("isDec0")
    if idc.isDec1(f): isList.append("isDec1")
    if idc.isHex0(f): isList.append("isHex0")
    if idc.isHex1(f): isList.append("isHex1")
    if idc.isOct0(f): isList.append("isOct0")
    if idc.isOct1(f): isList.append("isOct1")
    if idc.isBin0(f): isList.append("isBin0")
    if idc.isBin1(f): isList.append("isBin1")
    if idc.is_off0(f): isList.append("is_off0")
    if idc.is_off1(f): isList.append("is_off1")
    if idc.is_char0(f): isList.append("is_char0")
    if idc.is_char1(f): isList.append("is_char1")
    if idc.is_seg0(f): isList.append("is_seg0")
    if idc.is_seg1(f): isList.append("is_seg1")
    if idc.is_enum0(f): isList.append("is_enum0")
    if idc.is_enum1(f): isList.append("is_enum1")
    if idc.is_manual0(f): isList.append("is_manual0")
    if idc.is_manual1(f): isList.append("is_manual1")
    if idc.is_stroff0(f): isList.append("is_stroff0")
    if idc.is_stroff1(f): isList.append("is_stroff1")
    if idc.is_stkvar0(f): isList.append("is_stkvar0")
    if idc.is_stkvar1(f): isList.append("is_stkvar1")
    if idc.is_byte(f): isList.append("is_byte")
    if idc.is_word(f): isList.append("is_word")
    if idc.is_dword(f): isList.append("is_dword")
    if idc.is_qword(f): isList.append("is_qword")
    if idc.is_oword(f): isList.append("is_oword")
    if idc.is_tbyte(f): isList.append("is_tbyte")
    if idc.is_float(f): isList.append("is_float")
    if idc.is_double(f): isList.append("is_double")
    if idc.is_pack_real(f): isList.append("is_pack_real")
    if idc.is_strlit(f): isList.append("is_strlit")
    if idc.is_struct(f): isList.append("is_struct")
    if idc.is_align(f): isList.append("is_align")

    if not quiet: print(" ".join(isList))
    result.extend(isList)

	# long    GetOpType       (long ea, long n);       // get operand type
	# 
	# 
	# Get number used in the operand
	# This function returns an immediate number used in the operand
	#      ea - linear address of instruction
	#      n  - the operand number
	# The return values are:
	#      operand is an immediate value  => immediate value
	#      operand has a displacement     => displacement
	#      operand is a direct memory ref => memory address
	#      operand is a register          => register number
	#      operand is a register phrase   => phrase number
	#      otherwise                      => -1
	
    if idc.is_code(f):
        opValue = [0, 0]
        opType = [ GetOpType(ea, 0), GetOpType(ea, 1) ]
        for opNumber in [0, 1]:
            n = opType[opNumber]
            if n == -1: 
                if not quiet: print("Op%i isn't" % ( opNumber + 1 ))
                break

            opValue[opNumber] = signed(GetOperandValue(ea, opNumber))
            for [ macro, match, description, short ] in operand_type_list:
                if match == n:
                    if not quiet: print("%-11s %11s  Op%i  %10s [%s]  %s" % ( macro, short, opNumber + 1, hex(opValue[opNumber]).replace('L', ''), GetOpnd(ea, opNumber), description ))

    flags = idc.get_func_flags(ea)
    if flags != -1:
        for (name, value, description) in func_flags_list:
            if flags & value:
                if not quiet: print("%-18s 0x%08x  %s" % ( name, value, description))
                result.append(name)

    return result


def list_fflags(f):
    result = list()

    for [ macro, mask, match, description ] in fflag_list:
        if mask & f == match:
            result.append(macro)

    return result
