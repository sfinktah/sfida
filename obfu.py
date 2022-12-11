import os, sys
from idc import *
import idaapi
import idautils
from exectools import _import, execfile
# _import("from exectools import execfile")

_cwd = os.path.dirname(os.path.realpath(os.curdir))
_ourname = sys.argv[0]
_basename = os.path.dirname(os.path.realpath(_ourname))

# scriptDir = "e:/git/ida"
scriptDir = os.path.dirname(__file__)
home = scriptDir

# debug = 0

from exectools import execfile, _import
refresh_obfu = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

__has_read_patches = 0

for fn in [ 
        "obfu_helpers.py",
        "obfu_class.py",
        "obfu_generators.py",
        "obfu_patches.py"
]:
    fnfull = os.path.join(home, fn)
    if os.path.isfile(fnfull):
        execfile(fnfull, globals())
    else:
        raise Exception("No such file: %s" % fnfull)
#  from obfu_helpers import *
#  from obfu_class import *
#  from obfu_patches import *
# import UltiSnips

obfu = Obfu()
obfu_append_patches()
obfu.prep_groups()
if hasglobal('PerfTimer'):
    PerfTimer.bindmethods(obfu)
    __obfu_generators__ = [generate_patch1, generate_compact_cmov_abs_patch, generate_cmov_abs_patch, generate_cmov_patch3, generate_mov_reg_reg_via_stack_patch, patch_brick_jmp_jz]
    __obfu_helpers__ = [GetSize, GenericRangerPretty, DeleteFunctionNames, DeleteCodeAndData, DeleteData, DeleteAllHiddenAreas, hideRepeatedBytes, listAsHex, listAsHexIfPossible, listAsHexWith0x, readDword, writeDword, IsCode, PatchBytes, MakeNop, MakeNops, MakeTerms, PatchNops, remove_null_sub_jmps, QueueClear, QueueClearAll, check_misaligned_code, patch_everything, MakeSigned, bitsize_unsigned, bitsize_signed, bitsize_signed_2, patch_manual_instruction_rsp, patch_force_as_code, colorise_xor, fix_loc_offset, FixTargetLabels, generate_log, find_contig, contig_ranges, kassemble, iassemble, ida_resolve, nassemble, qassemble, assemble_contig, bit_pattern, braceexpandlist, braceform, findAndPatch, QuickFixQueue, super_patch, patch_this_segment, slowtracepatch, fixThunks, SegmentRanges, truncateThunks, patch_register_native_namespace]
    __obfu_patches__ = [patch_stack_align, simple_patch_factory, mark_sp_factory, adjust_sp_factory, set_sp_factory, mark_sp_reg_factory, gen_mask, patch_32bit_add, patch_manual_store, patch_manual, patch_double_stack_push_call_jump, patch_double_rsp_push_call_jump, patch_double_rsp_push_call_jump_b, patch_single_rsp_push_call_jump, patch_checksummer, process_replace, process_replace_nocheck, process_hex_pattern, obfu_append_patches]
    PerfTimer.binditems(locals(), funcs=__obfu_generators__, name='obfu_generators')
    PerfTimer.binditems(locals(), funcs=__obfu_helpers__, name='obfu_helpers')
    PerfTimer.binditems(locals(), funcs=__obfu_patches__, name='obfu_patches')

# vim: set ts=4 sts=-1 sw=4 et:
