def FindStackMutators(ea=None, skipRetrace=False, path=None, **kwargs):
    ea = eax(ea)
    b = asBytes(GetFuncCodeNoJunk(ea))
    i = GetFuncCodeIndexNoJunk(ea)

    #  b323
    #  .text:0000000143DCA64D 48 8B 45 18                          mov     rax, [rbp+18h]
    #  .text:0000000143DCA651 48 03 05 8F A5 83 FD                 add     rax, cs:_6
    #  .text:0000000143DCA658 48 8B 15 5D AA 8E FD                 mov     rdx, cs:o_loc_1416a602b
    #  .text:0000000143DCA65F 48 89 54 C5 70                       mov     [rbp+rax*8+70h], rdx

    #  .text:00000001440C5289 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C5290 48 03 05 AE 02 9A FC                 add     rax, cs:_32
    #  .text:00000001440C5297 48 8B 15 3A EF FF FF                 mov     rdx, cs:off_1440C41D8
    #  .text:00000001440C529E 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001440C52A6 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C52AD 48 03 05 09 D0 ED FF                 add     rax, cs:_31
    #  .text:00000001440C52B4 48 8B 15 0D 80 A9 00                 mov     rdx, cs:off_144B5D2C8
    #  .text:00000001440C52BB 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001440C52C3 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]
    #  .text:00000001440C52CA 48 03 05 B7 05 BE FC                 add     rax, cs:_30
    #  .text:00000001440C52D1 48 8B 15 BB 38 78 FD                 mov     rdx, qword ptr cs:loc_141848B93
    #  .text:00000001440C52D8 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+_arg_0], rdx

    #  .text:00000001434B8E2D 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62
    #  .text:00000001434B8E34 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]
    #  .text:00000001434B8E3B 48 03 15 53 20 7F FD                 add     rdx, qword ptr cs:loc_140CAAE95
    #  .text:00000001434B8E42 48 89 84 D5 90 01 00 00              mov     [rbp+rdx*8+180h+arg_0], rax

    #  .text:00000001434D1774 1B8 48 8B 05 BA EE 81 FD                 mov     rax, cs:off_140CF0635
    #  .text:00000001434D177B 1B8 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+var_28]
    #  .text:00000001434D1782 1B8 48 03 15 14 C1 15 FE                 add     rdx, cs:qword_14162D89D
    #  .text:00000001434D1789 1B8 48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax
    #  
    #  .text:00000001434B8E2D 1B8 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62
    #  .text:00000001434B8E34 1B8 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]
    #  .text:00000001434B8E3B 1B8 48 03 15 53 20 7F FD                 add     rdx, cs:_33
    #  .text:00000001434B8E42 1B8 48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax
    #  
    #  48 8B 05 B9 D4 24 FE             mov rax, cs:off_14186E902
    #  48 8B 95 58 01 00 00             mov rdx, [rbp+180h+_align]
    #  48 03 15 A6 24 44 FD             add rdx, cs:qword_140A638FD
    #  48 89 84 D5 90 01 00 00 00       mov [rbp+rdx*8+180h+arg_0], rax


    # regular
    # 48 8B 85 88 00 00 00              mov     rax, [rbp+0A0h+_align]           A     
    # 48 03 05 AE 02 9A FC              add     rax, cs:_32                      B 
    # 48 8B 15 3A EF FF FF              mov     rdx, cs:loc_resume_at            C   
    # 48 89 94 C5 B0 00 00 00 00        mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          

    #  1180
    #  48 8b 05 21 dd 48 00          	mov rax, [o_loc_1447c082b] 
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+0x170]       
    #  48 03 15 94 bd c3 fc          	add rdx, [qword_140CB8ABC] 
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+0x1a0], rax 

    # 1737
    # 48 8b 45 20                   	mov rax, [rbp+0x20]
    # 48 03 05 26 cf 48 fc          	add rax, [loc_140D0FA51]
    # 48 8b 15 e8 be be ff          	mov rdx, [o_sub_14436ccdf]
    # 48 89 94 c5 90 00 00 00       	mov [rbp+rax*8+0x90], rdx
    #
    #
    # 323
    # 48 8b 45 18                       mov rax, [rbp+18h]                       A
    # 48 03 05 8f a5 83 fd              add rax, cs:_6                           B
    # 48 8b 15 5d aa 8e fd              mov rdx, cs:o_loc_1416a602b              C
    # 48 89 54 c5 70                    mov [rbp+rax*8+70h], rdx                 D

    results = []
    c = MakeColumns()
    # 00 01 02 03|04 05 06 07 08 09 10|11 12 13 14 15 16 17|18 19 20 21 22 23 24 25
    # 48 8b 45 ??|48 03 05 ?? ?? ?? ??|48 8b 15 ?? ?? ?? ??|48 89 94 c5 ?? ?? 00 00
    #         ^^align     ^^ offset            ^^ location             ^^ arg0
    # 48 8b 45 20|48 03 05 26 cf 48 fc|48 8b 15 e8 be be ff|48 89 94 c5 90 00 00 00
    #
    # 48 8b 45 18|48 03 05 8f a5 83 fd|48 8b 15 5d aa 8e fd|48 89 54 c5 70         

    # r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89\x94\xc5..\x00\x00', b, re.DOTALL)
    r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89(\x94\xc5..\x00\x00|\x54\xc5.)', b, re.DOTALL)
    while r:
        s, e = r.span()
        _b = b[s:e]
        _i = i[s:e]
        try:
            align, offset, location, arg = struct.unpack('=xxxbxxxixxxixxxxi', _b)
        except:
            align, offset, location, arg = struct.unpack('=xxxbxxxixxxixxxxb', _b)
        #  printi("[raw] align:{:x}, offset:{:x}, location:{:x}, arg:{:x}".format(align, offset, location, arg))
        offset += _i[10] + 1
        location += _i[17] + 1
        # dprint("[debug] align, offset, location, arg")
        #  printi("[debug] align:{:x}, offset:{:x}, location:{:x}, arg:{:x}".format(align, offset, location, arg))
        
        _ori_location = idc.get_qword(location)
        if not _ori_location:
            raise Exception("Invalid location (0) at {:#x}".format(location))
        location = SkipJumps(_ori_location)
        if False and not skipRetrace:
            args = kwargs.copy()
            depth = args.get('depth', 0)
            args['depth'] = depth + 1
            printi("[fsm] calling retrace(0x{:x}, {})".format(location, ", ".join(args)))
            _r = retrace(location, **args)
            printi("[fsm] returned from retrace(0x{:x}, {}) with {}".format(location, ", ".join(args), _r), depth=depth)
            
        # dprint("[debug] location")
        #  printi("[debug] location:{:x}".format(location))
        
        if (Qword(location) << 8 | Byte(location + 8)) == 0x2464ff0824648d48f8:
            PatchBytes(location, [0xc3] + MakeNops(8))

        _insn = idc.generate_disasm_line(location, 1)[0:32]
        _insn = ' '.join(builtins.map(str.strip, _insn.split(' ', 1)))
        if _insn == 'lea rsp, [rsp+8]' and GetManyBytes(location, 9) == b'H\x8dd$\x08\xffd$\xf8':
            idc.patch_byte(location, 0xc3)
            ForceFunction(location)
            _insn = 'retn'
        _vals = [align, idc.get_qword(offset), location, arg, idc.print_insn_mnem(location), _insn, _ori_location]
        row = _.zipObject(['align', 'offset', 'location', 'arg', 'mnem', 'insn', 'ori_location'], _vals)
        results.append( row )
        #  c.addRow(row)
        b = b[e:]
        i = i[e:]
        # r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89\x94\xc5..\x00\x00', b, re.DOTALL)
        r = re.search(b'\x48\x8b\x45.\x48\x03\x05....\x48\x8b\x15....\x48\x89(\x94\xc5..\x00\x00|\x54\xc5.)', b, re.DOTALL)

    #  printi('c\n{}'.format('\n'.join(_.uniq(str(c).split('\n')))))

    #  .text:00000001440C5289                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]           A
    #  .text:00000001440C5290                 48 03 05 AE 02 9A FC                 add     rax, cs:qword_140A65545          B
    #  .text:00000001440C5297                 48 8B 15 3A EF FF FF                 mov     rdx, cs:off_1440C41D8            C
    #  .text:00000001440C529E                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx      D
    #
    #  .text:00000001440C52A6                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]
    #  .text:00000001440C52AD                 48 03 05 09 D0 ED FF                 add     rax, cs:qword_143FA22BD
    #  .text:00000001440C52B4                 48 8B 15 0D 80 A9 00                 mov     rdx, cs:off_144B5D2C8
    #  .text:00000001440C52BB                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx
    #
    #  .text:00000001440C52C3                 48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+var_18]
    #  .text:00000001440C52CA                 48 03 05 B7 05 BE FC                 add     rax, cs:qword_140CA5888
    #  .text:00000001440C52D1                 48 8B 15 BB 38 78 FD                 mov     rdx, cs:off_141848B93
    #  .text:00000001440C52D8                 48 89 94 C5 B0 00 00 00              mov     [rbp+rax*8+0A0h+arg_0], rdx
    #
    #  .text:00000001440C5289 0    TheArxan   48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]           A     
    #  .text:00000001440C5290 0    TheArxan   48 03 05 AE 02 9A FC                 add     rax, cs:_32                      B 
    #  .text:00000001440C5297 0    TheArxan   48 8B 15 3A EF FF FF                 mov     rdx, cs:loc_resume_at            C   
    #  .text:00000001440C529E 0    TheArxan   48 89 94 C5 B0 00 00 00 00           mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #  
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_33                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         
    #  
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_34                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         

    #  .text:00000001434B8E2D                 48 8B 05 2E FF 82 FD                 mov     rax, cs:off_140CE8D62            C
    #  .text:00000001434B8E34                 48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A
    #  .text:00000001434B8E3B                 48 03 15 53 20 7F FD                 add     rdx, cs:_num                     B
    #  .text:00000001434B8E42                 48 89 84 D5 90 01 00 00              mov     [rbp+rdx*8+180h+arg_0], rax      D

    #  .text:000000014403A903     48 8B 45 20                     mov     rax, [rbp+80h+_align]
    #  .text:000000014403A907     48 03 05 E2 C1 CD FC            add     rax, cs:_offset
    #  .text:000000014403A90E     48 8B 15 04 08 9D 00            mov     rdx, cs:off_144A0B119
    #  .text:000000014403A915     48 89 94 C5 90 00 00 00         mov     [rbp+rax*8+90h], rdx

    #---
    #  .text:00000001440CC80B 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:00000001440CC80F 0B8 48 03 05 20 54 99 FC            add     rax, qword ptr cs:loc_140A61C36
    #  .text:00000001440CC816 0B8 48 8B 15 0D CF 9C 00            mov     rdx, cs:off_144A9972A
    #  .text:00000001440CC81D 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx

    #  .text:00000001436120AD 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:00000001436120B1 0B8 48 03 05 AA E7 6C FD            add     rax, cs:qword_140CE0862
    #  .text:00000001436120B8 0B8 48 8B 15 0B 42 69 FD            mov     rdx, cs:off_140CA62CA
    #  .text:00000001436120BF 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx
    #
    #  .text:000000014404A11D 0B8 48 8B 45 28                     mov     rax, [rbp+90h+_align]
    #  .text:000000014404A121 0B8 48 03 05 07 29 0A 00            add     rax, cs:qword_1440ECA2F
    #  .text:000000014404A128 0B8 48 8B 15 9B B7 F5 FF            mov     rdx, cs:off_143FA58CA
    #  .text:000000014404A12F 0B8 48 89 94 C5 A0 00 00 00         mov     [rbp+rax*8+90h+_arg_0], rdx 
    #
    # 00 01 02 03|04 05 06 07 08 09 10|11 12 13 14 15 16 17|18 19 20 21 22 23 24 25
    # 48 8b 45 ??|48 03 05 ?? ?? ?? ??|48 8b 15 ?? ?? ?? ??|48 89 94 c5 ?? ?? 00 00
    #         ^^align     ^^ offset            ^^ location             ^^ arg0
    # 00 01 02 03 04 05 06|07 08 09 10 11 12 13|14 15 16 17 18 19 20|21 22 23 24 25 26 27 28
    # 48 8b 05 ?? ?? ?? ??|48 8b 95 ?? ?? 00 00|48 03 15 ?? ?? ?? ??|48 89 84 d5 ?? ?? 00 00
    # C        ^^ location|A        ^^ align   |B        ^^ offset  |D           ^^ arg0
    
    #  .text:00000001440C5289 0    TheArxan   48 8B 85 88 00 00 00                 mov     rax, [rbp+0A0h+_align]           A     
    #  .text:00000001440C5290 0    TheArxan   48 03 05 AE 02 9A FC                 add     rax, cs:_32                      B 
    #  .text:00000001440C5297 0    TheArxan   48 8B 15 3A EF FF FF                 mov     rdx, cs:loc_resume_at            C   
    #  .text:00000001440C529E 0    TheArxan   48 89 94 C5 B0 00 00 00 00           mov     [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #  
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_33                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         
    #  
    #  .text:00000001434B8E2D 0    TheArxan   48 8B 05 2E FF 82 FD                 mov     rax, cs:loc_resume_at            C   
    #  .text:00000001434B8E34 0    TheArxan   48 8B 95 58 01 00 00                 mov     rdx, [rbp+180h+_align]           A    
    #  .text:00000001434B8E3B 0    TheArxan   48 03 15 53 20 7F FD                 add     rdx, cs:_34                      B
    #  .text:00000001434B8E42 0    TheArxan   48 89 84 D5 90 01 00 00 00           mov     [rbp+rdx*8+180h+arg_0], rax      D         

    #  b1180
    #  48 8b 05 21 dd 48 00          	mov rax, [loc_resume_at]             C
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+_align]                A
    #  48 03 15 94 bd c3 fc          	add rdx, [_34]                       B
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+0x1a0], rax           D
    #
    #  b1180 (reordered)
    #  48 8b 95 70 01 00 00          	mov rdx, [rbp+_align]                A
    #  48 03 15 94 bd c3 fc          	add rdx, [_offset]                   B
    #  48 8b 05 21 dd 48 00          	mov rax, [location]                  C
    #  48 89 84 d5 a0 01 00 00       	mov [rbp+rdx*8+arg_0], rax           D
    #
    #  48 8b 95 70 01 00 00             mov rdx, [rbp+190h+_align]        143ad2622 A 0 offset   location align
    #  48 03 15 1a a4 c8 fd             add rdx, cs:offset                143ad2629 B 1 location align    ofset
    #  48 8b 05 9a fa 01 00             mov rax, cs:location              143f9ab4a C 2 align    offset   location
    #  48 89 84 d5 a0 01 00 00          mov [rbp+rdx*8+190h+_arg_0], rax  143ad2630 D 3 arg      arg      arg
    #
    #  b2245 
    #  48 8B 85 88 00 00 00             mov rax, [rbp+0A0h+_align]           A     
    #  48 03 05 AE 02 9A FC             add rax, cs:_32                      B 
    #  48 8B 15 3A EF FF FF             mov rdx, cs:loc_resume_at            C   
    #  48 89 94 C5 B0 00 00 00          mov [rbp+rax*8+0A0h+_arg_0], rdx     D          
    #
    #  .text:0000000143D123B4  48 8B 05 A5 DF 24 00               mov     rax, cs:o_loc_1447c082b
    #  .text:0000000143D123BB  48 8B 95 70 01 00 00               mov     rdx, [rbp+190h+_align]
    #  .text:0000000143D123C2  48 03 15 F3 66 FA FC               add     rdx, cs:qword_140CB8ABC
    #  .text:0000000143D123C9  48 89 84 D5 A0 01 00+              mov     [rbp+rdx*8+190h+_arg_0], rax
    #
    #  48 03 15 f3 66 fa fc
    #
    # valid permutations (A=0, B=1...)
    perms = [[0,1,2,3], [0,2,1,3], [2,0,1,3]]
    
    _results = []
    _header = ''
    field_names = \
        ['align',                'offset',         'location',       'arg'                   ]
    l = [7,                      7,                7,                8                       ] # instruction lengths
    r = [b'\x48\x8b...\x00\x00', b'\x48\x03.....', b'\x48\x8b.....', b'\x48\x89....\x00\x00' ] # regexes
    s = ['xxxi',                 'xxxi',           'xxxi',           'xxxxi'                 ] # struct.unpack parts
    four = list(range(4))

    for p in perms:
        b = asBytes(GetFuncCodeNoJunk(ea))
        i = GetFuncCodeIndexNoJunk(ea)

        regex = re.compile(r[p[0]] + r[p[1]] + r[p[2]] + r[p[3]], re.DOTALL)
        struc = '='      + s[p[0]] + s[p[1]] + s[p[2]] + s[p[3]]
        _tran = [p[x] for x in four]

        rev_index = [field_names[_tran[x]] for x in four]
        index = SimpleAttrDict(_.zipObject(rev_index, four))
        if not _header:
            _header = "                 {}".format(h16list([rev_index[x] for x in four]))

        match = re.search(regex, b)
        while match:
            mstart, mend = match.span()
            _b = b[mstart:mend]
            _i = i[mstart:mend]

            unpacked = struct.unpack(struc, _b)
            # cheating here, because the insn lens are always the same
            start_ea   = [_i[sum(l[0:x])] for x in four]
            end_ea     = [y + l[x] for x, y in  enumerate(start_ea)]
            #  start_ea   = [_i[0*7], _i[1*7], _i[2*7], _i[3*7]+1]
            #  end_ea     = [_i[0*6]+1, _i[1*6]+1, _i[2*6]+1, _i[3*7]+2]
            ptr        = [end_ea[j] + unpacked[j] for j in four]
            value      = [idc.get_qword(x) for x in ptr]

            #  idx = 0
            #  for start, end in zip(start_ea, end_ea):
                #  printi("{:32} {:24} {:x} {} {} {:8} {:8} {:8}".format(idii(start), bytes_as_hex(getCode(start, end - start)), start, idx, p[idx], field_names[_tran[idx]], rev_index[idx], index.get(rev_index[idx])))
                #  idx += 1

            #  printi(_header)
            #  printi("                 {}".format((h16list(['-' * 16] * 4))))
#  
            #  printi("unpacked:        {}".format((h16list(unpacked))))
            #  printi("ptr:             {}".format((h16list(ptr))))
            #  printi("value:           {}".format((h16list(value))))

            #                              align           offset         location              arg
            #  unpacked:                      88           ac3e30          167ee34               b0
            #  ptr:                    1434de50e        143fa22bd        144b5d2c8        1434de54c
            #  value:           c30000000000841f               31        143e73f80 89584503d8f75445


            # dprint("[indx] index, _tran")
            # printi("[indx] index:{}, _tran:{}".format(index, _tran))
            
            _vals = [
                unpacked[index.align],
                value[index.offset],
                value[index.location],
                unpacked[index.arg],
            ]

            vals = [0, 0, 0, 0]
            obj_vals = SimpleAttrDict()
            for x, _p in enumerate(p):
                vals[x] = _vals[_p]

            for x in four:
                obj_vals[rev_index[x]] = vals[x]

            #  printi("obj_vals: {}".format(obj_vals))
            _mnem     = idc.print_insn_mnem(obj_vals.location)
            _insn     = diida((obj_vals.location))
            if _insn == 'lea rsp, [rsp+8]' and GetManyBytes(obj_vals.location, 9) == b'H\x8dd$\x08\xffd$\xf8':
                ZeroFunction(obj_vals.location, 1)
                PatchBytes(obj_vals.location, [0xc3])
                #  ZeroFunction(obj_vals.location, 1)
                idc.auto_wait()
                idc.add_func(obj_vals.location, obj_vals.location+1)
                idc.auto_wait()
                remake_func(obj_vals.location)
                _insn = 'retn'
                _mnem = 'retn'
            obj_vals["ori_location"] = obj_vals["location"]
            obj_vals["location"] = SkipJumps(obj_vals["location"])

            _mnem     = GetMnemDi(obj_vals.location)
            _insn     = diida((obj_vals.location))
            obj_vals["mnem"] = _mnem 
            obj_vals["insn"] = _insn

            # from simple version:
            # row = _.zipObject(['align', 'offset', 'location', 'arg', 'mnem', 'insn', 'ori_location'], _vals)
            
            #  printi("                 {}".format((h16list(['-' * 16] * 4))))
            _results.append("                 {}".format((h16list(vals))))
            printi(_results[-1])
            #  printi("                 {}\n".format((h16list(['=' * 16] * 4))))

            
            results.append(obj_vals)
            b = b[mend:]
            i = i[mend:]
            match = re.search(regex, b)
            #  printi("next match: {}".format(match))

    #  _results = list(set(_results))
    #  _results.sort()
    #  printi(_header)
    #  printi("                 {}".format((h16list(['-' * 16] * 4))))
    #  printi("\n".join(_results))

    results = _(results).chain().uniq().sortBy('offset').map(lambda v, *a: SimpleAttrDict(v)).value()

    #  location    align offset arg   ori_location mnem insn                       
    #  ----------- ----- ------ ----- ------------ ---- -------------------------- 
    #  0x1446c0b01 0x168 0x30   0x1a0 0x1446c0b01  cmp  cmp [dword_14258A208], ebx 
    #  0x140a91e94 0x168 0x31   0x1a0 0x140a91e94  retn retn                       
    #  0x1435dcb35 0x168 0x32   0x1a0 0x1435dcb35  push push rbp  

    c.addRows(_.map(results, lambda x, *a: _.only(x, 'location', 'offset', 'insn')))
    with Commenter(ea, 'func') as cm:
        cm.clear(filter=lambda x: x.startswith('aa'))
        cm.add(indent(1, "Arxan Stack Return Manipulations:\n\n" + str(c), indentString='aa) '))

    if path:
        result = []
        for _ea in path:
            _name = idc.get_name(_ea)
            if _name:
                result.append("{:x} {}".format(_ea, _name))
            else:
                result.append("{:x}".format(_ea))

        cm.add("Call path: " + (" -> ".join(result)))
        
    #  printi(c)
    #  pp(hex(results))
    return results
