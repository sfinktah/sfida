import os, sys
from idc import *
import idaapi
import idautils
from execfile import _import
_import("from execfile import execfile")

_cwd = os.path.dirname(os.path.realpath(os.curdir))
_ourname = sys.argv[0]
_basename = os.path.dirname(os.path.realpath(_ourname))

print("obfu.py...")

# scriptDir = "e:/git/ida"
scriptDir = os.path.dirname(__file__)
home = scriptDir

# debug = 0

from execfile import execfile, _import, _require
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
        print("obfu-load: {}...".format(fnfull))
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

# vim: set ts=4 sts=-1 sw=4 et:
