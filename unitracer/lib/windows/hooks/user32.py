from unicorn.x86_const import *
import struct 


hooks = None
hooks = set(vars().keys())


def wsprintfA(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    arg1 = ut.popstack()
    arg2 = ut.popstack()
 
    str_fmt = ut.getstr(arg2)
    print('wsprintfA (arg1=, arg2={0:08x} -> "{1}") = {2}'.format(arg2, str_fmt, len(str_fmt)))

    ut.emu.reg_write(UC_X86_REG_EAX, len(str_fmt))
    ut.pushstack(arg2)
    ut.pushstack(arg1)
    ut.pushstack(retaddr)

hooks = set(vars().keys()).difference(hooks)

