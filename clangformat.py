def clangformat(source_code):
    #  idc.batch(0)
    import glob
    clang_paths = glob.glob(r"C:\Program Files (x86)\Microsoft Visual Studio\20*\*\Common7\IDE\VC\vcpackages\clang-format.exe") + \
            glob.glob(r"C:\Program Files\Microsoft Visual Studio\*\Community\VC\Tools\Llvm\x64\bin\clang-format.exe")
    if clang_paths:
        if len(clang_paths) > 1:
            print("{} possible locations for clang-format found:".format(len(clang_paths)))
            for i, clang_path in enumerate(clang_paths):
                print("\t[{}] {}".format(i, clang_path))
            print("picking one at random:")
            clang_paths.shuffle()
            print("selecting:  {}".format(clang_path))
        clang_path = clang_paths[0]
    else:
        # No clang, just return input
        return source_code

    # change directory to project dir, to pick up any
    # .clang-format files (maybe should specify as arg)
    cwd_path = os.getcwd()
    idb_path = idc.get_idb_path()
    idb_path = idb_path[:idb_path.rfind(os.sep)]
    os.chdir(idb_path)

    clang_args = [clang_path];
    #  clang_args.append("--argname=option")
    #  and so forth, and so on... if necessary

    try:
        phandle = subprocess.Popen(clang_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
        out, err = phandle.communicate(source_code.encode("utf-8"))

        if err:
            print("clang-format error: {}".format(err))

    except Exception as err:
        print("Exception executing clang-format: {}".format(str(err)))
        return None

    finally:
        os.chdir(cwd_path)

    return out.decode("utf-8")

