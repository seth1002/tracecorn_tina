from unicorn.x86_const import *
import importlib


hooks = None
hooks = set(vars().keys())

def RegCreateKeyA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpSubKey = ut.popstack()
    phkResult = ut.popstack()

    print 'RegCreateKeyA (hKey=0x{0:x}, lpSubkey="{1}", phkResult=0x{2:x})'.format(hKey, ut.getstr(lpSubKey), phkResult)
    ut.emu.mem_write(phkResult, ut.pack(0x12341234))
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegSetValueExA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpValueName = ut.popstack()
    _ = ut.popstack()
    dwType = ut.popstack()
    lpData = ut.popstack()
    cbData = ut.popstack()

    dwType_s = None
    m = importlib.import_module('advapi32', package="..i386")
    for n in dir(m):
        if n.startswith('REG_'):
            if getattr(m, n) == dwType:
                dwType_s = n

    print 'RegSetValueExA (hKey=0x{0:x}, lpValueName="{1}", dwType={2}, lpData="{3}", cbData={4})'.format(hKey, ut.getstr(lpValueName), dwType_s, ut.getstr(lpData), cbData)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegCloseKey(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()

    print 'RegCloseKey (hKey=0x{0:x})'.format(hKey)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)


def RegOpenKeyA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpSubKey = ut.popstack()
    pHandle = ut.popstack()

    res = 0
    SubKey = bytes(ut.getstr(lpSubKey))
    print('RegOpenKeyA (hKey=0x{0:08x}, lpSubkey={1:08x}:"{2}", pHandle=0x{3:08x}) = {4} => {5:08x}'.format(
        hKey, lpSubKey, SubKey, pHandle, res, retaddr))

    SubKey = SubKey.lower()
    if SubKey in ut.reg_value_map:
        value = ut.reg_value_map[SubKey]
        handle = len(ut.reg_path_handle_map)
        ut.reg_path_handle_map[handle] = value

    ut.emu.mem_write(pHandle, ut.pack(handle))
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def RegQueryValueExW(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpValueName = ut.popstack()
    lpReserved = ut.popstack()
    lpValueType = ut.popstack()
    lpBuffer = ut.popstack()
    lpBufSize = ut.popstack()

    res = 0
    value = ''
    size = 0

    if hKey in ut.reg_path_handle_map:
        value = ut.reg_path_handle_map[hKey]
        data = value.encode('utf-16LE') 
        size = len(data)+2
        ut.emu.mem_write(lpBuffer, data+'\x00\x00')
        ut.emu.mem_write(lpBufSize, ut.pack(size))

    print('RegQueryValueExW (hKey=0x{:08x}, lpValueName=0x{:08x}:"{}", lpReserved=0x{:08x}, lpValueType=0x{:08x}, lpBuffer={:08x}:"{}", lpBufSize={:08x}:{}) = {} => {:08x}'.format(
       hKey, lpValueName, ut.getstrw(lpValueName), lpReserved, lpValueType, lpBuffer, value, lpBufSize, size, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)



def RegQueryValueExA(ut):
    retaddr = ut.popstack()
    hKey = ut.popstack()
    lpValueName = ut.popstack()
    lpReserved = ut.popstack()
    lpValueType = ut.popstack()
    lpBuffer = ut.popstack()
    lpBufSize = ut.popstack()

    res = 0
    value = ''
    size = 0

    if hKey in ut.reg_path_handle_map:
        value = ut.reg_path_handle_map[hKey]
        data = value.encode() 
        size = len(data)
        ut.emu.mem_write(lpBuffer, data)
        ut.emu.mem_write(lpBufSize, ut.pack(size))

    print('RegQueryValueExA (hKey=0x{:08x}, lpValueName=0x{:08x}:"{}", lpReserved=0x{:08x}, lpValueType=0x{:08x}, lpBuffer={:08x}:"{}", lpBufSize={:08x}:{}) = {} => {:08x}'.format(
       hKey, lpValueName, ut.getstr(lpValueName), lpReserved, lpValueType, lpBuffer, value, lpBufSize, size, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


hooks = set(vars().keys()).difference(hooks)
hooks = [_x for _x in hooks if not _x.startswith('_')]
