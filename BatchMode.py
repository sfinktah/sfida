# This Python file uses the following encoding: utf-8
import idc

class BatchMode(object):
    old_batch_mode = None
    new_batch_mode = None
    def __init__(self, new_batch_mode):
        self.new_batch_mode = new_batch_mode
        self.old_batch_mode = idc.batch(self.new_batch_mode)

    def __enter__(self):
        # self.old_batch_mode = idc.batch(self.new_batch_mode)
        return self.old_batch_mode

    def __exit__(self, exc_type, exc_value, traceback):
        if self.old_batch_mode is not None:
            idc.batch(self.old_batch_mode)

class InfAttr(object):
    attr = None
    old_value = None
    new_value = None
    
    # get_value(idc.INF_AF)
    # set_value(idc.INF_AF, v & ~AF_CODE)

    #  INF_GENFLAGS   = 2            # ushort;  General flags:
    #  INFFL_AUTO     = 0x01         #              Autoanalysis is enabled?

    #  set_inf_attr(INF_GENFLAGS, get_inf_attr(INF_GENFLAGS) & ~INFFL_AUTO)
    #  You can programmatically disable that using using `set_inf_attr(INF_AT, get_inf_attr(INF_AT) & ~AF_CALL)`


    """
    @param attr int: INF_AF, etc
    @param value int|callable: temp replacement value or lambda old_value: new_value

    `attr` might be: INF_GENFLAGS, INF_LFLAGS, INF_DATABASE_CHANGE_COUNT,
    INF_CHANGE_COUNTER, INF_FILETYPE, INF_OSTYPE, INF_APPTYPE, INF_ASMTYPE,
    INF_SPECSEGS, INF_AF, INF_AF2
    
    @return 
    """
    def __init__(self, attr, value):
        self.attr = attr
        self.new_value = value

    def _get_new_value(self):
        return self.new_value(self.old_value) \
                if callable(self.new_value)   \
                else self.new_value

    def __enter__(self):
        self.old_value = idc.get_inf_attr(self.attr)
        idc.set_inf_attr(self.attr, self._get_new_value())
        return self.old_value

    def __exit__(self, exc_type, exc_value, traceback):
        if self.old_value is not None:
            idc.set_inf_attr(self.attr, self.old_value)



"""
idc.set_inf_attr(INF_AF, 0xdfe6300d)
PatchBytes
GetChunkNumber(0x14176d2d9)
old_value = idc.get_inf_attr(INF_GENFLAGS)
af = idc.get_inf_attr(INF_AF)

Python>af = idc.get_inf_attr(INF_AF)
Python>af
0xdfe6300d # without create func tails
Python>af = idc.get_inf_attr(INF_AF)
Python>af
0xdfe6310d # with create func tails

INFFL_AUTO
Wait()
ida_auto.auto_is_ok()
ida_auto.is_auto_enabled()
ida_auto.enable_auto(True)

ida_auto.plan_ea(0x143633604)
ida_auto.auto_apply_tail(tail_ea, parent_ea)
idc.plan_and_wait(0x14176d2d9, 0x14176d2e5)
idc.append_func_tail(0x143633604, 0x14176d2d9, 0x14176d2e5)
GetChunkNumber(0x14176d2d9)


140A8F37A: could not find tail range (corrupted database?)
UNDO: reached buffer size limit (134217728) and cleared some undo history
UNDO: if really desired, consider increasing UNDO_MAXSIZE in ida.cfg
UNDO: future messages about the buffer size will be suppressed
**DATABASE IS CORRUPTED: 141865D96: incorrect number of function referers
**DATABASE IS CORRUPTED: 1441A49C0: incorrect number of function referers
140D127F8: could not find tail range (corrupted database?)
1409F63F0: could not find tail range (corrupted database?)
140A5070F: could not find tail range (corrupted database?)
**DATABASE IS CORRUPTED: 143B48CBE: incorrect number of function referers
[autohidden] 143EE1616: can't get sp change points! -> OK
[autohidden] 1440A3823: can't get sp change points! -> OK
1440A192C: could not find tail range (corrupted database?)
1417B8A26: could not find tail range (corrupted database?)
[autohidden] 1447E1E43: can't get sp change points! -> OK
**DATABASE IS CORRUPTED: 14430A1FD: skipped bad chunk 14592B40F..14592B40F
**DATABASE IS CORRUPTED: 14430A1FD: skipped bad chunk 14592B40F..14592B40F
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 140A33EF4: skipped bad chunk 144EC2BE5..144EC2BE5
**DATABASE IS CORRUPTED: 14532437E: skipped bad chunk 145936CF2..145936CF2
**DATABASE IS CORRUPTED: 14532437E: skipped bad chunk 145936CF2..145936CF2
**DATABASE IS CORRUPTED: 140A39458: skipped bad chunk 140A39D93..140A39E08
**DATABASE IS CORRUPTED: 140A39458: cannot find function tails!
**DATABASE IS CORRUPTED: 1457B958A: skipped bad chunk 145936A18..145936A18
**DATABASE IS CORRUPTED: 1457B958A: skipped bad chunk 145936A18..145936A18
**DATABASE IS CORRUPTED: 145874747: skipped bad chunk 14593D71D..14593D71D
**DATABASE IS CORRUPTED: 145874747: skipped bad chunk 14593D71D..14593D71D
**DATABASE IS CORRUPTED: 145771D31: skipped bad chunk 1458DEC64..1458DEC64
**DATABASE IS CORRUPTED: 145771D31: skipped bad chunk 1458DEC64..1458DEC64
**DATABASE IS CORRUPTED: 140A82669: incorrect number of function referers
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A97AD4: skipped bad chunk 1458DB582..1458DB582
**DATABASE IS CORRUPTED: 140A9C324: cannot find function tails!
**DATABASE IS CORRUPTED: 1442C7C6D: skipped bad chunk 14593BA65..14593BA65
**DATABASE IS CORRUPTED: 140C3FDB8: cannot find function tails!
**DATABASE IS CORRUPTED: 145082EC3: skipped bad chunk 14566F27E..14566F27E
**DATABASE IS CORRUPTED: 140CF67BC: cannot find function tails!
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 140D6075C: skipped bad chunk 145785C4A..145785C4A
**DATABASE IS CORRUPTED: 143109E90: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E73: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E73: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109ECA: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109ECA: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EC2: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EC2: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EBA: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EBA: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EAD: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109EAD: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E6B: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E6B: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E63: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E63: function data are in conflicting state
**DATABASE IS CORRUPTED: 143109E5B: function data are in conflicting state
**DATABASE IS CORRUPTED: 144B1B1E8: cannot find function tails!
Python>FixAllChunks()
Stage #1
[FixChunk] We have a really messed up ghost chunk at 0x143fb4e86 belonging to 0x1401b069c with no ChunkOwners
[FixChunk] Attempting dangerous thing #1: ida_funcs.append_func_tail(1401b069c, 143fb4e86, 143fb4e9e
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "e:\git\ida\slowtrace_helpers.py", line 278, in FixAllChunks
    while FixChunks(funcea, leave=leave):
  File "e:\git\ida\slowtrace_helpers.py", line 323, in FixChunks
    r = ida_funcs.append_func_tail(func, _cc['start'], _cc['end'])
  File "C:\Program Files\IDA 7.5\python\3\ida_funcs.py", line 1245, in append_func_tail
    return _ida_funcs.append_func_tail(*args)
RuntimeError: Internal error 1543 occurred when running a script. Either
  - the script misused the IDA API, or
  - there is a logic error in IDA
Please check the script first.
If it appears correct, send a bug report to <support@hex-rays.com>.
In any case we strongly recommend you to restart IDA as soon as possible.


.text:00000001413A67F0                             ; =============== S U B R O U T I N E =======================================
.text:00000001413A67F0
.text:00000001413A67F0
.text:00000001413A67F0                             sub_1413A67F0   proc near               ; CODE XREF: .text:loc_1452FD026↓p
.text:00000001413A67F0                                                                     ; DATA XREF: sub_1413A67F0:loc_1451208DC↓o ...
.text:00000001413A67F0 000 55                                      push    rbp             ; [PatchBytes] mov rax, rsp; add rax, -8; mov rsp, rax; mov [rsp], rbp
.text:00000001413A67F1 008 0F 1F 84 00 00 00 00 00                 nop     dword ptr [rax+rax+00000000h]
.text:00000001413A67F9 008 0F 1F 80 00 00 00 00                    nop     dword ptr [rax+00000000h]
.text:00000001413A6800 008 E9 BE 0D 4A 04                          jmp     loc_1458475C3
.text:00000001413A6800                             sub_1413A67F0   endp
.text:00000001413A6800

.text:00000001458475C3                             ; ---------------------------------------------------------------------------
.text:00000001458475C3                             ; START OF FUNCTION CHUNK FOR sub_1413A67F0
.text:00000001458475C3
.text:00000001458475C3                             loc_1458475C3:                          ; CODE XREF: sub_1413A67F0+10↑j
.text:00000001458475C3 008 48 81 EC A0 00 00 00                    sub     rsp, 0A0h
.text:00000001458475CA 008 48 8D 6C 24 20                          lea     rbp, [rsp+20h]
.text:00000001458475CF 008 E9 C6 4B EF FF                          jmp     loc_14573C19A
.text:00000001458475CF                             ; END OF FUNCTION CHUNK FOR sub_1413A67F0
.text:00000001458475D4


[idapy] ida_funcs.get_fchunk(0x1458475ca):
{   'color': 0xffffffff,
    'endEA': 0x1458475d4,
    'end_ea': 0x1458475d4,
    'flags': 0x8000,
    'frame': 0x1413a67f0,
    'frregs': 0x5e40,
    'frsize': 1,
    'owner': 0x1413a67f0,
    'pntqty': 1,
    'points': {'count': 1, 'thisown': True},
    'referers': {   'count': 1,
                    'data': <Swig Object of type 'ea_t *' at 0x0000022F4BA7EF90>,
                    'thisown': True},
    'refqty': 1,
    'startEA': 0x1458475c3,
    'start_ea': 0x1458475c3}

[idapy] owner = ida_funcs.get_func(0x1458475ca):
{   'color': 0xffffffff,
    'endEA': 0x1413a6805,
    'end_ea': 0x1413a6805,
    'flags': 0x200,
    'frame': 0xffffffffffffffff,
    'owner': 0xffffffffffffffff,
    'pntqty': 1,
    'points': {   'count': 1,
                  'data': {'ea': 0x1413a67f1, 'spd': -8},
                  'thisown': True},
    'startEA': 0x1413a67f0,
    'start_ea': 0x1413a67f0}

[idapy] ida_funcs.get_func_chunknum(owner, 0x1458475ca): -1
[idapy] idc.get_func_name(0x1458475c3): sub_1413A67F0
[idapy] idc.get_func_name(0x1413a6800): sub_1413A67F0
[idapy] ida_funcs.is_same_func(0x1458475c3, 0x1413a6800): True
[idypy] idc.append_func_tail(0x1413a67f0, 0x1458475c3, 0x1458475d4): True
# Fixed


# IDA 7.0
.text:0000000143942F89
.text:0000000143942F89                          ; =============== S U B R O U T I N E =======================================
.text:0000000143942F89
.text:0000000143942F89
.text:0000000143942F89                          sub_143942F89   proc near               ; CODE XREF: .text:00000001444B2818↓j
.text:0000000143942F89                                                                  ; DATA XREF: .text:00000001433351EE↑o
.text:0000000143942F89
.text:0000000143942F89                          var_8           = qword ptr -8
.text:0000000143942F89                          var_s8          = qword ptr  8
.text:0000000143942F89                          arg_0           = qword ptr  10h
.text:0000000143942F89
.text:0000000143942F89                          ; FUNCTION CHUNK AT .text:0000000140CDD25A SIZE 00000009 BYTES
.text:0000000143942F89                          ; FUNCTION CHUNK AT .text:000000014304D2AA SIZE 00000018 BYTES
.text:0000000143942F89                          ; FUNCTION CHUNK AT .text:0000000143785156 SIZE 0000000F BYTES
.text:0000000143942F89                          ; FUNCTION CHUNK AT .text:00000001447101AF SIZE 00000018 BYTES
.text:0000000143942F89                          ; FUNCTION CHUNK AT .text:0000000144A4A0D1 SIZE 00000000 BYTES
.text:0000000143942F89
.text:0000000143942F89 000 40 38 73 0A                          cmp     [rbx+0Ah], sil
.text:0000000143942F8D 000 55                                   push    rbp             ; [PatchBytes] mov/lea->push order swap: rbp
.text:0000000143942F8D                                                                  ; [PatchBytes] lea rsp, qword ptr [rsp-8]; mov [rsp], rbp
.text:0000000143942F8E 000 0F 1F 84 00 00 00 00+                nop     dword ptr [rax+rax+00000000h]
.text:0000000143942F96 000 90                                   nop
.text:0000000143942F97 000 E9 BA 21 E4 FF                       jmp     loc_143785156
.text:0000000143942F97                          sub_143942F89   endp
.text:0000000143942F97

.text:0000000144A4A0D1                          ; ---------------------------------------------------------------------------
.text:0000000144A4A0D1                          ; START OF FUNCTION CHUNK FOR sub_143942F89
.text:0000000144A4A0D1 -08 E9 6D 08 65 FC                       jmp     loc_14109A943
.text:0000000144A4A0D1                          ; END OF FUNCTION CHUNK FOR sub_143942F89
.text:0000000144A4A0D1                          ; ---------------------------------------------------------------------------

Python>idc.append_func_tail(0x143942f89, 0x144a4a0d1, 0x144a4a0d6)
True
Python>idc.remove_fchunk(0x143942f89, 0x144a4a0d1)
False
Python>ida_funcs.is_same_func(0x143942f89, 0x144a4a0d1)
False
Python>idc.GetFunctionName(0x143942f89) == idc.GetFunctionName(0x144a4a0d1)
True

..

func = ida_funcs.get_func(0x143942f89)
fnLoc = func.start_ea
for start, end in idautils.Chunks(fnLoc):
    idc.remove_fchunk(start, end)
ida_funcs.del_func(func.start_ea)

Python>idc.append_func_tail(0x143942f89, 0x144a4a0d1, 0x144a4a0d6)
True
Python>ida_funcs.is_same_func(0x143942f89, 0x144a4a0d1)
True
Python>idc.remove_fchunk(0x143942f89, 0x144a4a0d1)
True


.text:0000000144AAF655                                   ; ---------------------------------------------------------------------------
.text:0000000144AAF655                                   ; START OF FUNCTION CHUNK FOR ArxanChecksumOrHealer
.text:0000000144AAF655
.text:0000000144AAF655                                   loc_144AAF655:                          ; CODE XREF: ArxanChecksumOrHealer-12CB56↑j
.text:0000000144AAF655 008 48 87 2C 24                                   xchg    rbp, [rsp]      ; [PatchBytes] mini-cmov
.text:0000000144AAF659 008 50                                            push    rax
.text:0000000144AAF65A 010 51                                            push    rcx
.text:0000000144AAF65A                                   ; END OF FUNCTION CHUNK FOR ArxanChecksumOrHealer
.text:0000000144AAF65B                                   ; START OF FUNCTION CHUNK FOR ArxanChecksumOrHealer
.text:0000000144AAF65B 010 E9 84 A1 A6 FF                                jmp     loc_1445197E4
.text:0000000144AAF65B                                   ; END OF FUNCTION CHUNK FOR ArxanChecksumOrHealer
.text:0000000144AAF65B                                   ; ---------------------------------------------------------------------------

Python>FixChunk()
[FixChunk] chunk at 144aaf65b is orphaned from ['0x1445a61db']
idc.append_func_tail(0x1445a61db, 0x144aaf65b, 0x144aaf660)

Python>idaapi.get_name_value(EA(), 'fred')
[autohidden] can't find struct name (id=0xFF000000000C0604) -> OK
[0x0, 0xffffffffffffffff]



Python>ida_auto.plan_range(0x1441a93c3, 0x1441a93ca)
Python>Wait()
True
Python>ida_auto.plan_range(0x1441a93c3, 0x1441a93ca)
Python>ida_auto.auto_apply_tail(0x1441a93c3, EA())
Python>Wait()
True
Python>[GetChunkNumber(x) for x in Heads(0x1441a93c3, 0x1441a93ca)]
[-0x1, -0x1, -0x1]
Python>[GetChunkOwner(x) for x in Heads(0x1441a93c3, 0x1441a93ca)]
[0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]
Python>[GetChunkOwners(x) for x in Heads(0x1441a93c3, 0x1441a93ca)]
[[], [], []]
Python>[ida_auto.plan_ea(x) for x in Heads(0x1441a93c3, 0x1441a93ca)]
[None, None, None]
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
False
Python>ida_auto.revert_ida_decisions(0x1441a93c3, 0x1441a93df)
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
False
Python>ida_auto.plan_and_wait(0x1441a93c3, 0x1441a93df)
0x1
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
False
Python>ida_auto.plan_and_wait(0x1441a93c3, 0x1441a93df, True)
0x1
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
False
Python>ida_auto.auto_wait_range(0x1441a93c3, 0x1441a93df)
0x0
Python>[ida_auto.auto_recreate_insn(x) for x in Heads(0x1441a93c3, 0x1441a93df)]
[0x3, 0x3, 0x1, 0x0, 0x0, 0x7, 0x4, 0x1]
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
False
Python>pp([GetDisasm(x) for x in Heads(0x1441a93c3, 0x1441a93df)])
[   'mov     eax, [rbp+0]',
    'mov     [rbp+30h], eax',
    'push    rbp; [PatchBytes] mov/lea->push order swap: rbp',
    'db 0Fh, 1Fh, 84h, 0',
    'lea     rbp, loc_1443B29D2',
    'xchg    rbp, [rsp]',
    'retn; [PatchBytes] return disguised as lea + jmp']
Python>EaseCode(0x1441a93c3)
Python>pp([GetDisasm(x) for x in Heads(0x1441a93c3, 0x1441a93df)])
[   'mov     eax, [rbp+0]',
    'mov     [rbp+30h], eax',
    'push    rbp; [PatchBytes] mov/lea->push order swap: rbp',
    'nop     dword ptr [rax+rax+00000000h]',
    'nop',
    'lea     rbp, loc_1443B29D2',
    'xchg    rbp, [rsp]',
    'retn; [PatchBytes] return disguised as lea + jmp']
Python>idc.append_func_tail(0x141794cbb, 0x1441a93c3, 0x1441a93df)
True

running idautils.Chunks(xxx):
Couldn't find insn at 1a89c1148
Couldn't find insn at 1583b2b23
Couldn't find insn at e7b34587

Python>for ea in FunctionsMatching('sub_'): idc.del_func(ea)
**DATABASE IS CORRUPTED: 1407DEA8A: skipped bad chunk 143D24FAC..143D24FAC
[autohidden] 140A598F8: can't get sp change points! -> OK
[autohidden] 140A5AB60: can't get sp change points! -> OK
[autohidden] 140A5AB78: can't get sp change points! -> OK
[autohidden] 140A6DCF7: can't get sp change points! -> OK
[autohidden] 140A77E9D: can't get sp change points! -> OK
[autohidden] 140A7A77D: can't get sp change points! -> OK
[autohidden] 140A7B0FB: can't get sp change points! -> OK
[autohidden] 140CBA810: can't get sp change points! -> OK
[autohidden] 140CBF4C1: can't get sp change points! -> OK
[autohidden] 140CBF574: can't get sp change points! -> OK
[autohidden] 140CBFE6C: can't get sp change points! -> OK
[autohidden] 140CCAC65: can't get sp change points! -> OK
[autohidden] 140CFF339: can't get sp change points! -> OK
[autohidden] 1414DD874: can't get sp change points! -> OK
[autohidden] 14184E510: can't get sp change points! -> OK
**DATABASE IS CORRUPTED: 14184E510: skipped bad chunk 14184E510..14184E510
**DATABASE IS CORRUPTED: 14184E510: skipped bad chunk 14184E510..14184E510
**DATABASE IS CORRUPTED: 14184E510: skipped bad chunk 14184E510..14184E510
**DATABASE IS CORRUPTED: 14184E510: skipped bad chunk 14184E510..14184E510
[autohidden] 1418C9A90: can't get sp change points! -> OK
**DATABASE IS CORRUPTED: 1418C9A90: cannot find function tails!
UNDO: reached buffer size limit (134217728) and cleared some undo history
UNDO: if really desired, consider increasing UNDO_MAXSIZE in ida.cfg
UNDO: future messages about the buffer size will be suppressed
140D405B6: could not find tail range (corrupted database?)
140D40572: could not find tail range (corrupted database?)
140D40476: could not find tail range (corrupted database?)
140D3FD77: could not find tail range (corrupted database?)
140D404CA: could not find tail range (corrupted database?)
140D36A73: could not find tail range (corrupted database?)
**DATABASE IS CORRUPTED: 143D8A5AE: cannot find function tails!
144307055: could not find tail range (corrupted database?)
**DATABASE IS CORRUPTED: 143DC84FA: skipped bad chunk 143D5B055..143D5B055
[autohidden] 143E1E64B: can't get sp change points! -> OK
"""
