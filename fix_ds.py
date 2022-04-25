# KNOWN OFFSET FROM BASE:
# 0x0141a35a20   0x7ff7157c5a20
# 0x0140000000   0x7ff713d90000
# offset:        0x7ff5d3d90000
# 
# DUMP:          KNOWN:
# 0x7FF680DA5A20 0x7ff7157c5a20
# 
# Therefore, correct normalised base is obtained by:
# ea + 0x94a20000 - 0x7ff5d3d90000
# 
# Dump Extent: 0x0140000000 .. 0x014550fc00
# Dump Size:   0x550fc00
# 
# denormalised base is obtained by:
# 0x140000000 - 0x94a20000 + 0x7ff5d3d90000
# BASE: 0x7ff67f370000
# END:  0x7ff68487fc00
# 
# DS: 0x141c23000 to 0x142e1c000

#  un_start = 0x7ff67f370000
#  un_end =  0x7ff68487fc00
#  start = 0x141c23000 
#  end = 0x142e1c000
#  ea = start
#  while ea < end:
    #  qword = idc.get_qword(ea)
    #  if qword >= start and qword < end:
        #  idc.patch_qword(ea, qword + 0x94a20000 - 0x7ff5d3d90000)
    #  ea += 8
#  
import idautils

def fix_dataseg_offsets(base=None, ori_base=None, size=None, seg_name='.data', step=8):
    pe = idautils.peutils_t()
    base = base or pe.imagebase
    size = size or idc.get_wide_dword(base + 0x194)
    end = base + size

    if not ori_base:
        ori_base = idc.get_qword(base + 0x1a8)

    #  ori_base = ori_base or idc.get_qword(base + 0x150) # smth like 0x7ff657b50000
    ori_end = ori_base + size

    # dprint("[addresses] base, size, end, ori_base, size, ori_end")
    print("[addresses] base:{:x}, size:{:x}, end:{:x}, ori_base:{:x}, size:{:x}, ori_end:{:x}".format(base, size, end, ori_base, size, ori_end))
    

    count = 0
    results = []
    for segment in idautils.Segments():
        print("[segment] idc.get_segm_name(segment):{}, ".format(idc.get_segm_name(segment)))
        if idc.get_segm_name(segment) == seg_name:
            ea = SegStart(segment)
            ea_end = SegEnd(segment)
            # dprint("[segment] idc.get_segm_name(ea), ea, ea_end")
            print("[segment matches] {}, ea:{:x}, ea_end:{:x}".format(idc.get_segm_name(ea), ea, ea_end))
            
            while ea < ea_end:
                qword = idc.get_qword(ea)
                if qword >= ori_base and qword < ori_end:
                    new_offset = qword + base - ori_base
                    results.append(new_offset)
                    idc.patch_qword(ea, new_offset)
                    idc.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)
                    idc.op_plain_offset(ea, 0, 0)
                    count += 1
                elif qword >= base and qword < end:
                    print("making offset at {:x}".format(ea))
                    idc.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)
                    idc.op_plain_offset(ea, 0, 0)

                ea += step
    print("{} adjustments made".format(count))
    return results


#  Scylla Log:
# Imagebase: 00007FF760840000 Size: 04BF2000
# Memory dump saved N:\Games\GTA V\Grand Theft Auto V\MEM_00007FF760830000_00001000.mem

# print("offsets: {}".format(fix_dataseg_offsets(base=0x140000000, ori_base=0x7FF760840000 , size=0x04BF2000, seg_name='seg000', step=1)))

# hex([5386337203, 5382357257, 5375347798, 5375347338, 5392275149, 5387340589, 5387253557, 5392264341, 5392008049, 5369872401, 5375711599, 5384351238, 5389280991, 5370993570, 5388437913, 5392309929, 5387320469, 5389830667, 5386187055, 5370102881, 5389337983, 5389431269, 5379674749, 5370561959, 5370561181, 5382922461, 5386508585, 5386709636, 5389355797, 5386638746, 5386528183, 5392298521, 5392211397, 5386713635, 5386866189, 5388483273, 5392193055, 5392259673, 5392188203, 5387048605, 5386886799, 5376863291, 5386886663, 5386886527, 5386886255, 5386886119, 5386886935, 5386887071, 5386354151, 5386817801, 5392127251, 5391558155, 5382736087, 5389784969, 5382699413, 5382017329])
