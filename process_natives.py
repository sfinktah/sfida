from exectools import execfile, make_refresh
refresh_natives = make_refresh(os.path.abspath(__file__))

l = [x[2] + 0x140000000 for x in natives if x[2] and x[2] != 0xffffffff]
m = [x[3] + 0x140000000 for x in natives if x[3] and x[3] != 0xffffffff and x[3] + 0x140000000 not in l]

