import os
import re
import subprocess
import idc
from execfile import _find as find
# from hotkey_utils import bytes_as_hex
# from idc_bc695 import GetIdbPath, GetInputFile
# from obfu_helpers import PatchBytes
# from sfcommon import forceAllAsCode
# from slowtrace2 import RelocationAssemblerError
# from sftools import MyMakeFunction
# from start import debug, home


from execfile import make_refresh
refresh_nasm = make_refresh(os.path.abspath(__file__))
refresh = make_refresh(os.path.abspath(__file__))

def extend(obj, *args):
    """
    adapted from underscore-py
    Extend a given object with all the properties in
    passed-in object(s).
    """
    args = list(args)
    for src in args:
        obj.update(src)
        for k, v in src.items():
            if v is None:
                del obj[k]
    return obj

nasm_cache = dict()
def nasm64(ea, string):
    global nasm_cache
    input = list()
    if debug:
        print("debug: {}".format(type(debug)))

    # have to align nasm on on a 4byte paragraph or it does alignment thing
    if ea is None:
        adjusted_ea = None
        shift = None
    else:
        adjusted_ea = ea & ~0x3
        shift = ea - adjusted_ea

    if isinstance(string, list):
        string = '\n'.join(string)

    string = string.replace('\r', '')
    string = re.sub(r'\n0x([0-9a-fA-F]+)(?=:)', r'\nloc_\1', "\n" + string)

    ori_string = string[:]

    options = dict()
    for line in string.split('\n'):
        if line.startswith('['):
            meat = string_between('[', ']', line)
            k, x, v = meat.partition(' ')
            if x:
                options[k] = v
                continue
        if line.endswith(':'):
            input.append(re.sub(r'[^\w]', '_', line)[0:-1] + ':')
        else:
            input.append(line)

    if 'org' in options:
        ea = int(options['org'], 16)
        ValidateEA(ea)
        adjusted_ea = ea & ~0x3
        shift = ea - adjusted_ea

    for i in range(shift):
        input.insert(0, "nop")

    input.insert(0, "[org 0x{:x}]".format(adjusted_ea))
    input.insert(0, "[bits {}]".format(options.get('bits', '64')))
    input.insert(0, "")

    #  if isinstance(string, list):
        #  input.extend(string)
        #  string = '\n'.join(input)
    #  else:
        #  input.extend(string.split('\n'))
    string = '\n'.join(input)

    string = string.replace('\r', '')


    if string in nasm_cache:
        return nasm_cache[string]

    retry = 2
    while retry:
        retry -= 1

        if debug: print("NasmAssemble:\n{}".format(indent(4, string)))
        # r = NasmAssemble(adjusted_ea, string)

        fw = tempfile.NamedTemporaryFile(mode='w', suffix='.asm', delete=False)

        string = string.replace(' xmmword ', ' oword ')

        #  asm_path = idb_subdir + os.sep + '%s.asm' % out_path
        asm_path = fw.name
        out_path = asm_path + ".o"
        #  print("asm_path", asm_path)
        #  print("out_path", out_path)
        
        fw.write(string)
        fw.close()

        #  dir = idb_subdir
    #  
        #  orig_dir = os.getcwd()
        #  os.chdir(dir)
    #  
        #  path = home
        yasm_filename = 'yasm.exe'
        yasm_executable_filepath = find(yasm_filename)

        args = list()
        args.append("--machine=amd64")
        args.append("--objfile=%s" % out_path)
        #  args.append("--list=%s.lst" % out_path)
        args.append("--force-strict")
        args.append(asm_path)

        args = [yasm_executable_filepath] + list(args)
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            with PerfTimer('nasm'):
                ret = subprocess.check_output(args, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=startupinfo)
            # ret = ret.decode('ascii')
            # dprint("[nasm len(ret)] ret")
            if debug: print("[nasm len(ret)] ret:{} type(ret):{}".format(ret, type(ret)))
            if len(ret):
                # we have output? we have error? actually I think this is never called
                # Unexpect ret: E:\APPDAT~1\tmpp6mlb3dh.asm:11: warning: value does not fit in signed 32 bit field

                #  print("Unexpect ret: {}".format(ret))
                #  raise RuntimeError("I don't think this is ever called")
                r = False, {'output': ret}
                #  r = (   False,
                        #  {   'cmd': [   'e:/git/ida\\yasm.exe',
                                       #  '--machine=amd64',
                                       #  '--objfile=C:\\Users\\sfink\\AppData\\Local\\Temp\\tmpa2p9mxtt.asm.o',
                                       #  '--force-strict',
                                       #  'C:\\Users\\sfink\\AppData\\Local\\Temp\\tmpa2p9mxtt.asm'],
                            #  'output': 'C:\\Users\\sfink\\AppData\\Local\\Temp\\tmpa2p9mxtt.asm:8: '
                                      #  "error: undefined symbol `dword_14268428C' (first use)\n"
                                      #  'C:\\Users\\sfink\\AppData\\Local\\Temp\\tmpa2p9mxtt.asm:8: '
                                      #  'error:  (Each undefined symbol is reported only once.)\n',
                            #  'returncode': 1,
                            #  'stderr': None}) 
            else:
                with open(out_path, "rb") as fr:
                    o = fr.read()

                length = len(o)
                if length:
                    #  shift = 0
                    #  if ea % 4:
                        #  shift = 4 - (ea % 4)
                    # assembled = length - shift, bytearray(o)[shift:]
                    assembled = bytearray(o)[shift:]
                    # dprint("[nasm64 single r] assembled, ret")
                    if debug: print("[nasm64 single r] assembled:{}, ret:{}".format(assembled, ret))

                    # dprint("[debug] retry")
                    
                    if ori_string not in nasm_cache:
                        if retry > 0 and ("0x" not in ori_string or "+0x" in ori_string or "-0x" in ori_string):
                            if debug: print("[caching]\n{}".format(indent(8, ori_string)))
                            nasm_cache[ori_string] = assembled
                        else:
                            if debug: print("[not caching]\n{}".format(indent(8, ori_string)))

                    
                    if debug: print("assembled at 0x{:x}:\n{}".format(ea, indent(8, ori_string)))
                    return True, {'output': assembled, 'input': input}
                    #  r = True, assembled
                else:
                    return False, {'output': '', 'input': ''}

        except subprocess.CalledProcessError as e:
            if debug:
                print("CalledProcessError: %s" % e.__dict__)
            r = False, e.__dict__
            # return False, e.__dict__
        finally:
            os.unlink(asm_path)
            try:
                os.unlink(out_path)
            except FileNotFoundError:
                pass

        if debug:
            print('r: {}'.format(pfh(r)))

        if r[0]:
            r = r[0] - shift, {'output': r[1][shift:], 'input': input}
        else:
            r = r[0], {'output': r[1], 'input': input}

        happy, r2 = r

        if not happy:
            #  print("Error compiling: %s" % r2['output'])
            #  {
            #      "returncode": 1,
            #      "cmd": ["e:/git/ida/yasm.exe", "--machine=amd64", "--objfile=E:/APPDAT~1/tmpoox7oos4.asm.o", "--force-strict", "E:/APPDAT~1/tmpoox7oos4.asm"],
            #      "output": "E:/APPDAT~1/tmpoox7oos4.asm:6: error: invalid combination of opcode and operands\\n",
            #      "stderr": null
            #  }
            #  C:\Users\sfink\AppData\Local\Temp\tmpnwmgeik0.asm:8: warning: value does not fit in 32 bit field
            try:
                output = r2['output']['output']
                #  if isinstance(output, dict):
                    #  print("***required!")
                    #  output = output['output'].replace('\\', '/').strip()
            except AttributeError:
                print("[error] r2: {}".format(pf(r2)))
            #  pp(r2)
            errors = []
            error = re.finditer(r'^(?:.*):(?P<line>\d+): (?P<level>\w+): (?P<message>.*)', output, re.M)
            for m in error:
                # pp(m)
                #  ('E:/APPDAT~1/tmpoox7oos4.asm',
                #   '6',
                #   'error',
                #   'invalid combination of opcode and operands')
                #
                #   ('8', 'warning', 'value does not fit in 32 bit field')
                line, level, message = m.groups()
                message = message.strip()
                if message in ("(Each undefined symbol is reported only once.)"):
                    continue
                if retry == 5:
                    continue
                error_display_str = "{:8} {:3} {} {:18} {}".format(level, line, message, '', r2['input'][int(line)-1].strip())
                error_store_str = "{}: {} ({})".format(level, message, r2['input'][int(line)-1].strip())
                errors.append(error_store_str)
                if debug: print("[nasm error] " + error_display_str)
                #  print("fn, line, level, message", fn, line, level, message)
                    
            for sym in re.findall(r"undefined symbol `([^']+)", output):
                repl = idc.get_name_ea_simple(sym)
                if repl == idc.BADADDR:
                    repl = idc.get_name_ea_simple(sym.replace('__', '::', 1))
                    if repl == idc.BADADDR:
                        raise Exception("Couldn't find address of %s" % sym)
                repl = hex(repl).rstrip('L')

                if debug: print("{:13}replacing {} with {}".format('', re.escape(sym), repl))
                #  print("types", type(sym), type(repl), type(string))
                # string = re.sub(r"(?<=[^\w]){}(?=[^\w])".format(re.escape(sym)), repl, string)
                string = re.sub(r"\b{}\b".format(re.escape(sym)), repl, string)
                #  print(string)
                #  string = re.sub("(?<=[^\w]){}(?=[^\w])".format(re.escape(sym)), repl, string)
                # print("retrying with:\n{}".format(indent(8, string)))

            if not retry:
                print("Failed to assemble at {:x}:\n{}".format(ea, indent(4, string)))
                raise RelocationAssemblerError("\n".join(errors))

    return r

def nasm(ea, string):
    r = nasm64(ea, string)
    if r[0]:
        return bytes_as_hex(r[1]['output'])
    else:
        raise Exception("nasm: " + r[1])

def NasmAssembleAddresses(ea, s, apply = 0):
    happy, o = nasm64(ea, s)

    if happy and apply:
        length = happy
        PatchBytes(ea, o)
        forceAllAsCode(ea, length)
    return (happy, o)



def NasmFromFile(ea, filename):
    s = file_get_contents(filename)
    happy, o = NasmAssembleAddresses(ea, s)

    if happy and type(o) is bytearray and len(o):
        length = len(o)
        PatchBytes(ea, o)
        forceCode(ea, length)
        #  analyze(ea, ea + length)
        if not MyMakeFunction(ea, ea + length):
            print("couldn't make function at 0x%x" % ea)
            raise RelocationAssemblerError("couldn't make function at 0x%x" % ea)
    else:
        print("Error assembling: %s" % o)
        raise RelocationAssemblerError()
