def initFishyElements():
    ea = eax('initFishyElements')
    if ea:
        jump(ea)
        comment_version()
        file_put_contents(GetIdbDir() + "initFishyElements.c", "\n".join(decompile_function(ea)))
    else:
        print("initFishyElements not found")

    idc.qexit(0)

# initFishyElements()
