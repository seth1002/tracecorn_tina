from unicorn.x86_const import *

class Hook(object):
    def __init__(self, name, restype, argtypes):
        self.name = name
        self.restype = restype
        self.argtypes = argtypes

    def hook(self, ut):
        args = []
        # retaddr = ut.getstack(0)
        retaddr = ut.popstack()
        idx = 1
        res = 0x00
        for t, n in self.argtypes:
            # val = ut.getstack(idx)
            val = ut.popstack()
            if t in []:
                if val == 0:
                    args.append("0x{0:08x}".format(val))
                else:
                    args.append('"{}"'.format(ut.getstr(val)))
            else:
                args.append("0x{0:08x}".format(val))
            idx += 1
        print("Unhooked function: {} ({}) = 0x{:08x} => 0x{:08x}".format(self.name, ', '.join(args), res, retaddr))
        ut.emu.reg_write(UC_X86_REG_EAX, res)
        ut.pushstack(retaddr)
