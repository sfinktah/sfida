# retrace 280c01  #010c28 
# checked 010128  #280101 
# checked 140128  #280114 
# checked 410128  #280141 
# healed  280128  #280128 
# chk+hld 3c0128  #28013c 
# chk+hld 7c0128  #28017c 
_col_checked = 0x140128
_col_healed  = 0x280128
_cols_checked = [0x010128, 0x140128, 0x410128]
_cols_healed  = [0x280128]

def eac(ea, what=idc.CIC_ITEM):
    if isinstance(ea, int) and not ea & ~0xffffff:
        return ea
    ea = eax(ea)
    if ea & ~0xffffff:
        return idc.get_color(ea, what)
    return ea

def is_healed_col(ea, what=idc.CIC_ITEM): 
    color = hldchk_msk(eac(ea, what))
    if not color: return False
    return _.any(_cols_healed, lambda x, *a: color & x == x)

def is_checked_col(ea, what=idc.CIC_ITEM): 
    color = hldchk_msk(eac(ea, what))
    if not color: return False
    return _.any(_cols_checked, lambda x, *a: color & x == x)

def is_hldchk_col(ea, what=idc.CIC_ITEM):
    return is_checked_col(ea) and is_healed_col(ea)

#  def is_healed_col(ea): return is_hldchk_col(eac(ea, what)) & eac(ea, what) >> 16 in (1, 0x14)
#  def is_checked_col(ea): return is_hldchk_col(eac(ea, what)) & eac(ea, what) >> 16 in (1, 0x28)
#  def is_hldchk_col(ea): return is_hldchk_msk(eac(ea, what)) & eac(ea, what) >> 16 == 1
def hldchk_msk(ea, what=idc.CIC_ITEM): return (eac(ea, what)) & (0x280128 | 0x140128 | 0x010128 | 0x410128)
def hldchk_invmsk(ea, what=idc.CIC_ITEM): return (eac(ea, what)) & ~(0x280128 | 0x140128 | 0x010128 | 0x410128)
def is_hldchk_msk(ea, what=idc.CIC_ITEM): return hldchk_msk(ea) & 0xffff == 0x128

def set_healed_col(ea=None, what=None, end=None):
    """
    Set item color to 'healed'

    @param ea: address of the item
    @param what: type of the item (one of CIC_* constants)
    @param end: (for CIC_ITEM, apply to range ea..end)

    @return: success (True or False)
    """
    # `ea` is added in-case we want to re-use this code with def func(*args) later...
    args = [ea, what, end]
    ea = args.pop(0)
    what = end = None
    for a in args:
        if a is not None:
            if a in (idc.CIC_ITEM, idc.CIC_SEGM, idc.CIC_FUNC):
                what = a
            elif IsValidEA(eax(a)):
                end = eax(a)
            else:
                raise TypeError("Not sure what to do with argument '{}' (type {})".format(a, type(a).__name__))

    if isinstance(ea, list):
        return [set_healed_col(ea=x, what=what, end=end) for x in ea]

    ea = eax(ea)
    
    if end is not None:
        # [idc.set_color(x, what, 0x280128) for x in range(ea, end)]
        return _.all([set_healed_col(x, what=what) for x in range(ea, end)])

    current_color = eac(ea, what)
    if not is_hldchk_msk(current_color):
        return idc.set_color(ea, what, _col_healed)
    new_color = _col_healed
    if is_checked_col(ea):
        new_color |= _col_checked
    if new_color != current_color:
        return idc.set_color(ea, what, new_color)

def set_checked_col(ea=None, what=None, end=None):
    """
    Set item color to 'checked'

    @param ea: address of the item
    @param what: type of the item (one of CIC_* constants)
    @param end: (for CIC_ITEM, apply to range ea..end)

    @return: success (True or False)
    """
    args = [ea, what, end]
    ea = args.pop(0)
    what = end = None
    for a in args:
        if a is not None:
            if a in (idc.CIC_ITEM, idc.CIC_SEGM, idc.CIC_FUNC):
                what = a
            elif IsValidEA(eax(a)):
                end = eax(a)
            else:
                raise TypeError("Not sure what to do with argument '{}' (type {})".format(a, type(a).__name__))

    if isinstance(ea, list):
        return [set_checked_col(ea=x, what=what, end=end) for x in ea]

    ea = eax(ea)
    
    if end is not None:
        return _.all([set_checked_col(x, what=what) for x in range(ea, end)])

    current_color = eac(ea, what)
    if not is_hldchk_msk(current_color):
        return idc.set_color(ea, what, _col_checked)
    new_color = _col_checked
    if is_healed_col(ea):
        new_color |= _col_healed
    if new_color != current_color:
        return idc.set_color(ea, what, new_color)
