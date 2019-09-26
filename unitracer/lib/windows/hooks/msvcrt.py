from unicorn.x86_const import *

hooks = None
hooks = set(vars().keys())


def _controlfp(ut):

    retaddr = ut.popstack()

    print('_controlfp(,)')
    ut.pushstack(retaddr)

def __p__commode(ut):

    retaddr = ut.popstack()
    res = 0

    module_name ='msvcrt.dll'.upper()  
    if module_name in map(lambda x:x[0].upper(), ut.dlls):
        if '_commode' in ut.dll_funcs:
            global_var_addr = ut.dll_funcs['_commode']
            res = global_var_addr

    print('__p__commode()')
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def __getmainargs(ut):
    retaddr = ut.popstack()
    _Argc = ut.popstack()
    _Argv = ut.popstack()
    _Env = ut.popstack()
    _DoWildCard = ut.popstack()
    _StartInfo = ut.popstack()

    module_name ='msvcrt.dll'.upper()  
    if module_name in map(lambda x:x[0].upper(), ut.dlls):
        if '_acmdln' in ut.dll_funcs:
            exp_var_addr = ut.dll_funcs['_acmdln']
            # lp_pe_path = ut.heap_alloc(len(pe_path))
            ut.emu.mem_write(ut.SHARED_MEM, ut.command_line)
            _t = ut.pack(ut.SHARED_MEM)
            ut.emu.mem_write(exp_var_addr, _t)
            print('# Patch glboal var _acmdln')

    print('__getmainargs(0x{0:x},  0x{1:x}, 0x{2:x}, 0x{3:x}, 0x{4:x}) = 0x{5:x} => 0x{6:x}'.format(
        _Argc, _Argv, _Env, _DoWildCard, _StartInfo, 0, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def __p__fmode(ut):
    module_name ='msvcrt.dll'.upper()  
    _fmode = 0
    retaddr = ut.popstack()

    if module_name in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper() == module_name, ut.dlls)[0][1]
        _fmode = res + 0x31F4

    print('__p__fmode() = 0x{0:x} => 0x{1:x}'.format(_fmode, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, _fmode)
    ut.pushstack(retaddr)


def memset(ut):
    retaddr = ut.popstack()
    ptr = ut.popstack()
    value = ut.popstack()
    num = ut.popstack()
    ut.emu.mem_write(ptr, '\x00'*num)

    print('memset(0x{0:08x}, 0x{1:08x}, 0x{2:08x}) => 0x{3:08x}'.format(ptr, value, num, retaddr))
 
    ut.pushstack(retaddr)


def malloc(ut):
    retaddr = ut.popstack()
    size = ut.popstack()
    lpMem = ut.heap_alloc(size)

    print('malloc(0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(size, lpMem, retaddr))
 
    ut.emu.reg_write(UC_X86_REG_EAX, lpMem)
    ut.pushstack(retaddr)


def strlen(ut):
    retaddr = ut.popstack()
    lpStr = ut.popstack()
    _str = ut.getstr(lpStr)
    _len = len(_str)

    print('strlen(0x{:08x} -> "{}") = 0x{:08x} => 0x{:08x}'.format(lpStr, _str, _len, retaddr))
 
    ut.emu.reg_write(UC_X86_REG_EAX, _len)


hooks = set(vars().keys()).difference(hooks)