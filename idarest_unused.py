def is_plugin():
    stk = []                                         
    raw = []
    for i in range(len(inspect.stack()) - 1, 0, -1): 
        s = inspect.stack()[i]
        s2 = s[0]
        raw.append((
            s2.f_code.co_filename,
            s2.f_lineno,
            s2.f_code.co_name,
        ))
        stk.append('  File "{}", line {}, in {}'.format(
            s2.f_code.co_filename,
            s2.f_lineno,
            s2.f_code.co_name,
        ))

        if s2.f_code.co_name == "load_plugin":
            print("\n".join(stk))
            return True

        #  stk.append(s2.f_code.co_firstlineno)
        #  pp(inspect.stack()[i])
        #  stk.append(inspect.stack()[i])            
    print("\n".join(stk))
    return False

def reload_idarest():
    l = ida_loader.load_plugin(get_ir_plugin().__file__)
    ida_loader.run_plugin(l, 0)
    unload_module('idarest')
    l = ida_loader.load_plugin(get_ir_plugin().__file__)

    #    import gc
    #    ir = getglobal('sys.modules.__plugins__idarest_plugin.instance') or getglobal('sys.modules.idarest.instance') or getglobal('idarest_main.instance')
    #    if ir:
    #        for o in gc.get_referrers(ir):
    #            if isinstance(o, dict):
    #                for k in o.keys():
    #                    if o[k] == ir:
    #                        print("deleting key {}".format(k))
    #                        o.pop(k)
    #            else:
    #                for k in dir(o):
    #                    if getattr(o, k, None) == ir:
    #                        print("deleting attribute {}".format(k))
    #                        delattr(o, k)
    #
    #    removeglobal('sys.modules.__plugins__idarest_plugin.instance')
    #    removeglobal('sys.modules.idarest.instance')
    #    removeglobal('idarest_main.instance')
    #    unload_module('idarest')
    #    unload_module('__plugins__idarest')
    #    removeglobal('ir')

#  def cleanup():
    #  print("**atexit** cleanup2")
    #  ir.term()
#  print('registered atexit cleanup2')
#  atexit.register(cleanup)
