from unicorn.x86_const import *

hooks = None
hooks = set(vars().keys())


def PathFindExtensionW(ut):

    retaddr = ut.popstack()
    pszPath = ut.popstack() 
    res = 0

    path = ut.getstrw(pszPath)
    file_name_pos = path.rfind('\\')+1
    ext_pos = 0
    ext = ""
    if file_name_pos == -1:
        file_name = path
        ext_pos = 0
    else:
        file_name = path[file_name_pos:]

        ext_pos = file_name.rfind('.')
        if ext_pos != -1:
            ext = file_name[ext_pos:]
            ext_pos += file_name_pos
        else:
            ext_pos = 0

    print('PathFindExtensionW(0x{:08x}:"{}") = 0x{:08x}:"{}" => 0x{:08x}'.format(pszPath, path, res, ext, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX,pszPath+ext_pos)
    ut.pushstack(retaddr)


def PathFindFileNameW(ut):

    retaddr = ut.popstack()
    pszPath = ut.popstack() 
    res = 0

    file_name = ''
    path = ut.getstrw(pszPath)
    file_name_pos = path.rfind('\\')+1
    if file_name_pos == -1:
        file_name_pos = 0
    else:
        file_name = path[file_name_pos:]

    print('PathFindFileNameW(0x{:08x}:"{}") = 0x{:08x}:"{}" => 0x{:08x}'.format(pszPath, path, res, file_name, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX,pszPath+file_name_pos)
    ut.pushstack(retaddr)


hooks = set(vars().keys()).difference(hooks)