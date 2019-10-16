from unicorn.x86_const import *

hooks = None
hooks = set(vars().keys())


def init_dll(ut):

    if '_acmdln' in ut.dll_funcs:
        exp_var_addr = ut.dll_funcs['_acmdln']
        # lp_pe_path = ut.heap_alloc(len(pe_path))
        ut.emu.mem_write(ut.SHARED_MEM, ut.command_line)
        _t = ut.pack(ut.SHARED_MEM)
        ut.emu.mem_write(exp_var_addr, _t)
        print('# Patch glboal var _acmdln')


hooks = set(vars().keys()).difference(hooks)