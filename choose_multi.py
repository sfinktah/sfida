"""
summary: A widget showing data in a tabular fashion, providing multiple selection
description:
  Similar to @{choose}, but with multiple selection
keywords: chooser, actions
see_also: choose, chooser_with_folders
"""

from __future__ import print_function
from ida_kernwin import Choose


class MyChoose(Choose):

    def __init__(self, items, title, cols, icon=-1):
        #  idaapi.Choose.__init__(self, title, cols, flags=idaapi.Choose.CH_MODAL | idaapi.Choose.CH_MULTI, icon=icon)
        Choose.__init__(
            self,
            #  title,
            #  [ ["Bit", Choose.CHCOL_HEX | 10] ],
            title, # "Select Patch",
            cols, # [["Type", 8], ["Function", 25], ["Start", 16], ["End", 16], ["Disassembly", 128]],
            flags = Choose.CH_MULTI
        )
        # self.items = items
        #  self.items = [ "1,2,3,4," for x in range(len(items)) ] 
        self.n = 0
        self.items = [ self.make_item(item) for item in items ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        self.deflt = n  # save current selection
        return (Choose.NOTHING_CHANGED, )

    def OnDeleteLine(self, indices):
        new_items = []
        for idx, item in enumerate(self.items):
            if idx not in indices:
                new_items.append(item)
        self.items = new_items
        return [Choose.ALL_CHANGED] + indices

    def make_item(self, item):
        r = [str(x) for x in item]
        self.n += 1
        return r

    def show(self, num):
        #  self.deflt = [x
                      #  for x in range(len(self.items))
                      #  if (num & (1 << x)) != 0]
        if self.Show(True) < 0:
            return 0
        return self.deflt
        #  return sum([(1 << x) for x in self.deflt])


# -----------------------------------------------------------------------
#  def test_choose(num):
    #  c = MyChoose("Choose - sample 2", nb = 5)
    #  return c.show(num)

# -----------------------------------------------------------------------
if __name__ == '__main__':
    print(test_choose(11))
