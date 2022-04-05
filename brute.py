import os, subprocess

brute_dir = os.path.dirname(os.path.abspath(__file__))

brute_filename = 'joaat-brute-1-simple.exe'
brute_executable_filepath = os.path.sep.join([brute_dir, brute_filename])

def brute(*args):
    args = [brute_executable_filepath] + list([str(x) for x in args])
    

    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        ret = subprocess.check_output(args, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=startupinfo)
        args.pop(0)
        if len(args) > 2:
            result = {}
            for i, reversed in enumerate(ret.split("\n")):
                if reversed.strip():
                    result[args[i*2+1]] = reversed;
            return result
        else:
            return ret.strip()



    except subprocess.CalledProcessError as e:
        print("CalledProcessError: %s" % e.__dict__)

# print(brute('', '0x12345', 'bonus_', 0x12345))
