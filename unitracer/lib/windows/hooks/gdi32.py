from unicorn.x86_const import *

hooks = None
hooks = set(vars().keys())

def GetColorAdjustment(ut):

    # GetColorAdjustment = Hook('GetColorAdjustment', 'WINBOOL', [['HDC', 'hdc'], ['LPCOLORADJUSTMENT', 'lpca']])
    retaddr = ut.popstack()
    hdc = ut.popstack() 
    lpca = ut.popstack()
    res = 0

    print('GetColorAdjustment({0:x}, {1:x}) = {2:x}'.format(hdc, lpca, res))

    ut.emu.reg_write(UC_X86_REG_EAX,0)
    ut.pushstack(retaddr)



hooks = set(vars().keys()).difference(hooks)