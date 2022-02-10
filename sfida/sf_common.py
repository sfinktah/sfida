import idaapi
import idc
from idc import BADADDR, SN_NOWARN, SN_AUTO

try:
    import __builtin__ as builtins
    integer_types = (int, long)
    string_types = (str, unicode)
    string_type = unicode
    byte_type = str
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str, bytes)
    byte_type = bytes
    string_type = str
    long_type = int
    long = int

