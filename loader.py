import sys
import os
from exectools import execfile


def pwd():
    _ourname = 'None'
    _scriptDir = 'None'
    _basename = 'None'
    _cwd = os.path.dirname(os.path.realpath(os.curdir))

    _ourname = sys.argv[0]
    if _ourname:
        _basename = os.path.dirname(os.path.realpath(_ourname))
    if '__file__' in globals() and __file__:
        _scriptDir = os.path.dirname(os.path.realpath((__file__)))

    print("loader...")
    print("cwd:        %s" % _cwd)
    print("sys.argv[0]:%s" % _ourname)
    print("_basename:  %s" % _basename)
    if '__file__' in globals() and __file__:
        print("__file__:   %s" % __file__)
    print("_scriptDir: %s" % _scriptDir)

pwd()
# scriptDir = "e:\git\ida"
scriptDir = os.path.dirname(__file__)
home = scriptDir

# from loader import import_from

#  def execfile(filepath, _globals=None, locals=None):
    #  print("loader-execfile: {}...".format(filepath))
    #  if _globals is None:
        #  _globals = globals()
    #  _globals.update({
        #  "__file__": filepath,
        #  "__name__": "__main__",
    #  })
    #  with open(filepath, 'rb') as file:
        #  exec(compile(file.read(), filepath, 'exec'), _globals, locals)

def import_from(files):
    if not isinstance(files, list):
        files = [files]

    for fn in files:
        fnfull = os.path.join(home, fn + ".py")
        if os.path.isfile(fnfull):
            execfile(fnfull)
        else:
            raise Exception("No such file: %s" % fnfull)
