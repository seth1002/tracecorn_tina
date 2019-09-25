from unicorn.x86_const import *
# from win32api import GetTickCount
import unitracer.lib.windows.config.os as win_os_cfg
import base64

hooks = None
hooks = set(vars().keys())


def PathFindFileNameA(ut):
    retaddr = ut.popstack()
    pszPath = ut.popstack()

    path = ut.getstr(pszPath)
    offset = path.rfind('\\')+1 
    if offset == -1:
        offset = 0
    res = pszPath+offset

    print('PathFindFileNameA(0x{:08x} -> "{}") = 0x{:08x} => 0x{:08x}'.format(
        pszPath, path, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def PathFindExtensionA(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack()

    path = ut.getstr(p1)
    offset = path.rfind('.') 
    if offset == -1:
        offset = len(path)
    res = p1+offset

    print('PathFindExtensionA(0x{:08x} -> "{}") = 0x{:08x} => 0x{:08x}'.format(p1, path, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetStringTypeW(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack()
    p2 = ut.popstack()
    p3 = ut.popstack()
    p4 = ut.popstack()
    res = 0x00000001
    print('GetStringTypeW(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(p1, p2, p3, p4, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LCMapStringW(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack()
    p2 = ut.popstack()
    p3 = ut.popstack()
    p4 = ut.popstack()
    res = 0x00000001
    print('LCMapStringW(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(p1, p2, p3, p4, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetCPInfo(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack()
    p2 = ut.popstack()
    res = 0x00000001
    print('GetCPInfo(0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(p1, p2, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetACP(ut):
    retaddr = ut.popstack()
    res = 0x000003A8
    print('GetACP() = 0x{:08x} => 0x{:08x}'.format(res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def FreeEnvironmentStringsW(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack()
    res = 0x00000001
    print('FreeEnvironmentStringsW(0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(p1, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetEnvironmentStringsW(ut):
    retaddr = ut.popstack()
    os_env_strw_addr = ut.OS_ENVIRONMENT_STR_ADDR
    os_env_strw = ut.getstrw(os_env_strw_addr)
    print('GetEnvironmentStringsW() = 0x{0:08x}:{1} => 0x{2:08x}'.format(
        os_env_strw_addr, os_env_strw, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, os_env_strw_addr)
    ut.pushstack(retaddr)

def GetCommandLineA(ut):
    retaddr = ut.popstack()

    cmd_line_addr = ut.CMD_LINE_ADDR
    cmd_line = ut.getstr(cmd_line_addr)
    print('GetCommandLineA() = 0x{0:08x}:{1} => 0x{2:08x}'.format(cmd_line_addr, cmd_line, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, cmd_line_addr)
    ut.pushstack(retaddr)


def GetCurrentThreadId(ut):
    retaddr = ut.popstack()
    
    print('GetCurrentThreadId() = {0}'.format(ut.current_thread_id))
    # print(hex(retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, ut.current_thread_id)
    ut.pushstack(retaddr)


def GetTickCount(ut):
    retaddr = ut.popstack()
    
    tick_count = 0x5F8B7E
    print('GetTickCount() = {0} => 0x{1:08x}'.format(tick_count, retaddr))
    # print(hex(retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, tick_count)
    ut.pushstack(retaddr)


def FlsAlloc(ut):
    retaddr = ut.popstack()
    lpCallback = ut.popstack()

    idx = len(ut.fls_stors)
    ut.fls_stors[idx] = lpCallback

    print('FlsAlloc(lpCallback = 0x{0:08x}) = {1} => 0x{2:08x}'.format(lpCallback, idx, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, idx)
    ut.pushstack(retaddr)


def FlsGetValue(ut):
    retaddr = ut.popstack()
    dwFlsIndex = ut.popstack()

    lpCallback = ut.fls_stors[dwFlsIndex]
    res = 0
    print('FlsGetValue(dwFlsIndex = {0}) = {1} => 0x{1:08x}'.format(dwFlsIndex, res, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def TlsAlloc(ut):
    retaddr = ut.popstack()
    idx = len(ut.tls_stors)
    ut.tls_stors[idx] = 0
    print('TlsAlloc() = {0} => 0x{1:08x}'.format(idx, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, idx)
    ut.pushstack(retaddr)


def TlsSetValue(ut):
    retaddr = ut.popstack()
    idx = ut.popstack()
    value = ut.popstack()

    ut.tls_stors[idx] = value
    print('TlsSetValue(dwTlsIndex = {0}, lpTlsValue = {1:08x}) => 0x{2:08x}'.format(idx, value, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, 1)
    ut.pushstack(retaddr)


def TlsGetValue(ut):
    retaddr = ut.popstack()
    idx = ut.popstack()

    value = 0
    if idx in ut.tls_stors:
        value = ut.tls_stors[idx]

    print('TlsGetValue(dwTlsIndex = {0}) = {1:08x}) => 0x{2:08x}'.format(idx, value, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, value)
    ut.pushstack(retaddr)


def EncodePointer(ut):
    retaddr = ut.popstack()
    Ptr = ut.popstack()
    ut.emu.reg_write(UC_X86_REG_EAX, Ptr)
    print('EncodePointer(0x{0:08x}) = 0x{1:08x} => 0x{2:08x}'.format(Ptr, Ptr, retaddr))
    ut.pushstack(retaddr)


def DecodePointer(ut):
    retaddr = ut.popstack()
    Ptr = ut.popstack()
    ut.emu.reg_write(UC_X86_REG_EAX, Ptr)
    print('DecodePointer(0x{0:08x}) = 0x{1:08x} => 0x{2:08x}'.format(Ptr, Ptr, retaddr))
    ut.pushstack(retaddr)


def GetCurrentProcessId(ut):
    retaddr = ut.popstack()
    
    print('GetCurrentProcessId() = {0}'.format(ut.process_id))
    # print(hex(retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, ut.process_id)
    ut.pushstack(retaddr)


def InitializeCriticalSectionAndSpinCount(ut):
    retaddr = ut.popstack()
    p1 = ut.popstack() 
    p2 = ut.popstack()

    res = 1
    print('InitializeCriticalSectionAndSpinCount({:08x}, {:08x}) = {:08x} => {:08x}'.format(p1, p2, res, retaddr))

    ut.pushstack(retaddr)
    ut.emu.reg_write(UC_X86_REG_EAX, res)



def InitializeCriticalSectionEx(ut): 
    retaddr = ut.popstack()
    lpCriticalSection = ut.popstack() 
    dwSpinCount = ut.popstack()
    Flags = ut.popstack()
    res = 1
    print('InitializeCriticalSectionEx({0:x}, {1:x}, {2:x}) = {3:x}'.format(
        lpCriticalSection, dwSpinCount, Flags, res))
    ut.pushstack(retaddr)


def GetVersion(ut):
    retaddr = ut.popstack()
    print('GetVersion()')
    ut.pushstack(retaddr)
    ut.emu.reg_write(UC_X86_REG_EAX, 0x1DB10106)


def GetVersionExA(ut):
    retaddr = ut.popstack()
    lpVersionInformation = ut.popstack()

    res = 0x1DB10106

    os_version = win_os_cfg.gen_os_version()
    ut.emu.mem_write(lpVersionInformation, os_version)

    print('GetVersionExA({:08x}) = {:08x} => {:08x}'.format(lpVersionInformation, res, retaddr))

    ut.pushstack(retaddr)
    ut.emu.reg_write(UC_X86_REG_EAX, res)


def LocalReAlloc(ut):
    retaddr = ut.popstack()
    hMem = ut.popstack()
    uBytes = ut.popstack()
    uFlags = ut.popstack()

    old_size = ut.alloc_mem_list[hMem]
    old_data = ut.emu.mem_read(hMem, old_size)
    res = ut.heap_alloc(uBytes+old_size)
    ut.emu.mem_write(res, bytes(old_data))
    print('LocalReAlloc(0x{:08x}, 0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(
        hMem, uBytes, uFlags, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LocalAlloc(ut):
    retaddr = ut.popstack()
    uFlags = ut.popstack()
    dwBytes = ut.popstack()

    res = ut.heap_alloc(dwBytes)
    print('LocalAlloc({0:08x}, {1:08x}) = 0x{2:08x} => 0x{3:08x}'.format(
        uFlags, dwBytes, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GlobalLock(ut):
    retaddr = ut.popstack()
    hMem = ut.popstack()
    res = hMem

    print('GlobalLock({:08x}) = 0x{:08x} => 0x{:08x}'.format(
        hMem, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GlobalAlloc(ut): 
    retaddr = ut.popstack()
    uFlags = ut.popstack()
    dwBytes = ut.popstack()

    res = ut.heap_alloc(dwBytes)
    print('GlobalAlloc({0:08x}, {1:08x}) = 0x{2:08x} => 0x{3:08x}'.format(
        uFlags, dwBytes, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def HeapSize(ut):
    retaddr = ut.popstack()
    hHeap = ut.popstack()
    dwFlags = ut.popstack()
    lpMem = ut.popstack()

    heap_size = 1

    for base, size in ut.alloc_mem_list.items():
        if lpMem >=base and lpMem < base+size:
            heap_size = size
            break

    print('HeapSize({0:08x}, {1:08x}, {2:08x}) = 0x{3:08x} => 0x{4:08x}'.format(
        hHeap, dwFlags, lpMem, heap_size, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, heap_size)
    ut.pushstack(retaddr)


def HeapAlloc(ut):
    retaddr = ut.popstack()
    hHeap = ut.popstack()
    dwFlags = ut.popstack()
    dwSize = ut.popstack()

    res = ut.heap_alloc(dwSize)
    print('HeapAlloc({0:08x}, {1:08x}, {2:08x}) = 0x{3:08x} => 0x{4:08x}'.format(
        hHeap, dwFlags, dwSize, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def HeapCreate(ut):
    retaddr = ut.popstack()
    flOptions = ut.popstack() 
    dwInitialSize = ut.popstack()
    dwMaximumSize = ut.popstack()
    res = ut.heap_alloc(dwInitialSize)

    print('HeapCreate({0:x}, {1:x}, {2:x}) = {3:x}'.format(
        flOptions, dwInitialSize, dwMaximumSize, res))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetProcessHeap(ut):
    retaddr = ut.popstack()
    res = ut.HEAP_CUR

    print('GetProcessHeap() = {:08x} => {:08x}'.format(res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)



def GetWindowsDirectoryA(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpBuffer = ut.popstack()
    uSize = ut.popstack()
    windir = "C:\\Windows"
    print 'GetWindowsDirectoryA = "{0}"'.format(windir)
    emu.mem_write(lpBuffer, windir)
    emu.reg_write(UC_X86_REG_EAX, len(windir))
    ut.pushstack(retaddr)


def lstrcat(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpString1 = ut.popstack()
    lpString2 = ut.popstack()
    lpString1_s = ut.getstr(lpString1)
    lpString2_s = ut.getstr(lpString2)

    emu.mem_write(lpString1+len(lpString1_s), bytes(lpString2_s+b'\x00'))
    ret_str = str(ut.getstr(lpString1))
    print 'lstrcat (0x{:08x} -> "{}", 0x{:08x} -> "{}") = 0x{:08x} -> "{}" => 0x{:08x}'.format(
        lpString1, lpString1_s, lpString2, lpString2_s, lpString1, ret_str, retaddr)

    emu.reg_write(UC_X86_REG_EAX, lpString1)
    ut.pushstack(retaddr)

def lstrcpyn(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpString1 = ut.popstack()
    lpString2 = ut.popstack()
    iMaxLength = ut.popstack() 

    res = lpString1
    lpString2_s = ''

    if lpString2:
        lpString2_s = ut.getstr(lpString2)
        emu.mem_write(lpString1, bytes(lpString2_s+b'\x00'))

    ret_str = str(ut.getstr(lpString1))
    print 'lstrcpyn (0x{:08x}, 0x{:08x} -> "{}", 0x{:08x}) = 0x{:08x} -> "{}" => 0x{:08x}'.format(
        lpString1, lpString2, lpString2_s, iMaxLength, res, ret_str, retaddr)

    emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def lstrcpy(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    lpString1 = ut.popstack()
    lpString2 = ut.popstack()

    res = lpString1
    lpString2_s = ''

    if lpString2:
        lpString2_s = ut.getstr(lpString2)
        emu.mem_write(lpString1, bytes(lpString2_s+b'\x00'))

    ret_str = str(ut.getstr(lpString1))
    print 'lstrcpy (0x{:08x}, 0x{:08x} -> "{}") = 0x{:08x} -> "{}" => 0x{:08x}'.format(
        lpString1, lpString2, lpString2_s, res, ret_str, retaddr)

    emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def ExitProcess(ut):
    retaddr = ut.popstack()
    uExitCode = ut.popstack()

    print 'ExitProcess ({0})'.format(uExitCode)
    ut.pushstack(retaddr)


def IsDebuggerPresent(ut):
    retaddr = ut.popstack()
    res = 0

    print 'IsDebuggerPresent = {0}'.format(res)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetModuleHandleW(ut):
    retaddr = ut.popstack()
    lpModuleName = ut.popstack()

    hModule = 0x0
    ModuleName = ''

    # get main module
    if lpModuleName == 0:
        hModule = ut.ADDRESS
    else:
        ModuleName = ut.getstrw(lpModuleName).encode('ascii')

        for (name, handle) in ut.dlls:
            if ModuleName.upper() == name.upper():
                hModule = handle
                break

    print('GetModuleHandleW(lpModuleName=0x{0:08x}) = 0x{1:08x}'.format(lpModuleName, hModule))
    ut.emu.reg_write(UC_X86_REG_EAX, hModule)
    ut.pushstack(retaddr)


def GetModuleHandleA(ut):
    retaddr = ut.popstack()
    lpModuleName = ut.popstack()

    hModule = 0x0
    ModuleName = ''

    # get main module
    if lpModuleName == 0:
        hModule = ut.ADDRESS
    else:
        ModuleName = ut.getstr(lpModuleName)

        for (name, handle) in ut.dlls:
            if '.DLL' not in ModuleName.upper():
                ModuleName += '.DLL'

            if ModuleName.upper() == name.upper():
                hModule = handle
                break

    print('GetModuleHandleA(lpModuleName=0x{:08x}:"{}") = 0x{:08x}'.format(lpModuleName, ModuleName, hModule))
    ut.emu.reg_write(UC_X86_REG_EAX, hModule)
    ut.pushstack(retaddr)


def GetProcAddress(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    lpProcName = ut.popstack()

    lpProcName_s = None

    try:
        # ordinal
        if lpProcName <0xFFFF:
            lpProcName_s = ut.dll_ord_fun_name_mp[hModule][lpProcName]
        else: # fun name
            lpProcName_s = str(ut.getstr(lpProcName))
    except Exception as e:
        print('failed to call GetProcAddress:hModule=0x{0:08x}, lpProcName={1:x}\n+++\n{2}\n'.format(
            hModule, lpProcName, str(e)))

    res = None
    if lpProcName_s in ut.dll_funcs:
        res = ut.dll_funcs[lpProcName_s]
    else:
        res = 0x0

    print 'GetProcAddress (hModule=0x{0:08x}, lpProcName=0x{1:08x}:"{2}") = 0x{3:08x} => 0x{4:08x}'.format(
        hModule, lpProcName, lpProcName_s, res, retaddr)
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LoadLibraryExW(ut):
    retaddr = ut.popstack()
    lpFileName = ut.popstack()
    hfile = ut.popstack()
    dwFlags = ut.popstack()

    lpFileName_s = str(ut.getstrw(lpFileName)).upper()
    print('# Load Library:"{0}")'.format(lpFileName_s))

    res = None

    if lpFileName_s in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s, ut.dlls)[0][1]
    elif lpFileName_s+'.DLL' in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s+'.DLL', ut.dlls)[0][1]
    else:
        res = ut.load_dll(lpFileName_s)

    print('LoadLibraryExW (lpLibFileName={:08x} -> "{}") = {:08x} => 0x{:08x}'.format(lpFileName, lpFileName_s, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LoadLibraryExA(ut):
    retaddr = ut.popstack()
    lpFileName = ut.popstack()
    hfile = ut.popstack()
    dwFlags = ut.popstack()

    lpFileName_s = str(ut.getstr(lpFileName)).upper()
    print('# Load Library:"{0}")'.format(lpFileName_s))

    res = None

    if lpFileName_s in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s, ut.dlls)[0][1]
    elif lpFileName_s+'.DLL' in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s+'.DLL', ut.dlls)[0][1]
    else:
        res = ut.load_dll(lpFileName_s)

    print('LoadLibraryExA (lpLibFileName={:08x} -> "{}") = {:08x} => 0x{:08x}'.format(lpFileName, lpFileName_s, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LoadLibraryA(ut):
    retaddr = ut.popstack()
    lpFileName = ut.popstack()

    lpFileName_s = str(ut.getstr(lpFileName)).upper()
    print('# Load Library:"{0}")'.format(lpFileName_s))

    res = None

    if lpFileName_s in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s, ut.dlls)[0][1]
    elif lpFileName_s+'.DLL' in map(lambda x:x[0].upper(), ut.dlls):
        res = filter(lambda x:x[0].upper()==lpFileName_s+'.DLL', ut.dlls)[0][1]
    else:
        res = ut.load_dll(lpFileName_s)

    print('LoadLibraryA (lpFileName="{0}") = {1:08x} => 0x{2:08x}'.format(lpFileName_s, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def WinExec(ut):
    retaddr = ut.popstack()
    lpCmdLine = ut.popstack()
    lpCmdLine_s = ut.getstr(lpCmdLine)
    uCmdShow = ut.popstack()

    print 'WinExec (lpCmdLine="{0}", uCmdShow=0x{1:x})'.format(lpCmdLine_s, uCmdShow)
    ut.emu.reg_write(UC_X86_REG_EAX, 0x20)
    ut.pushstack(retaddr)


def VirtualProtect(ut):
    retaddr = ut.popstack()
    lpAddress = ut.popstack()
    dwSize = ut.popstack()
    flNewProtect = ut.popstack()
    lpflOldProtect = ut.popstack()

    print('VirtualProtect (lpAddress={0:08x}, dwSize={1:08x}, flNewProtect={2:08x}, lpflOldProtect={3:08x})'.format(
        lpAddress, dwSize, flNewProtect, lpflOldProtect
    ))

    ut.emu.reg_write(UC_X86_REG_EAX, 0x1)
    ut.pushstack(retaddr)


def VirtualAlloc(ut):
    retaddr = ut.popstack()
    lpAddress = ut.popstack()
    dwSize = ut.popstack()
    flAllocationType = ut.popstack()
    flProtect = ut.popstack()

    if lpAddress != 0x00000000:
        res = lpAddress
        try:
            ut.emu.mem_map(lpAddress, dwSize)
        except Exception as e:
            print('#'+str(e)) 
    else:
        res = ut.heap_alloc(dwSize)

    print('VirtualAlloc (lpAddress=0x{:08x}, dwSize=0x{:08x}, flAllocationType=0x{:08x}, flProtect=0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(
        lpAddress, dwSize, flAllocationType, flProtect, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def VirtualAllocEx(ut):
    retaddr = ut.popstack()
    hProcess = ut.popstack()
    lpAddress = ut.popstack()
    dwSize = ut.popstack()
    flAllocationType = ut.popstack()
    flProtect = ut.popstack()

    res = ut.heap_alloc(dwSize)

    print('VirtualAllocEx (hProcess=0x{:08x}, lpAddress=0x{:08x}, dwSize=0x{:08x}, flAllocationType=0x{:08x}, flProtect=0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(
        hProcess, lpAddress, dwSize, flAllocationType, flProtect, res, retaddr
    ))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetNLSVersionEx(ut):
    retaddr = ut.popstack()
    function = ut.popstack()
    lpLocaleName = ut.popstack()
    lpVersionInformation = ut.popstack()
    print('GetNLSVersionEx (function={0:08x}, lpLocaleName={1:08x}, lpVersionInformation={2:08x})'.format(
               function, lpLocaleName, lpVersionInformation
            ))

    ut.emu.reg_write(UC_X86_REG_EAX, 0x0)
    ut.pushstack(retaddr)


def lstrlen(ut):
    retaddr = ut.popstack()
    lpString = ut.popstack()
    _str = ut.getstr(lpString)
    strlen = len(_str)
    print('lstrlen (lpString={0:08x} -> "{1}") = {2}'.format(lpString, _str, strlen))
    ut.emu.reg_write(UC_X86_REG_EAX, strlen)
    ut.pushstack(retaddr)


def ShellExecuteA(ut):
    retaddr = ut.popstack()
    hWnd = ut.popstack()
    Operation = ut.popstack()
    FileName = ut.popstack()
    Parameters = ut.popstack()
    DefDir = ut.popstack()
    IsShow = ut.popstack()

    res = 2

    strOperation = ut.getstr(Operation)
    strFileName = ut.getstr(FileName)

    print('ShellExecuteA(hWnd=0x{}, Operation=0x{}, FileName=0x{}, Parameters=0x{}, DefDir=0x{}, IsShow=0x{}) = {} => {}'.format(
        hWnd, Operation, FileName, Parameters, DefDir, IsShow, res, retaddr
    ))

    print('->[0x{}] = "{}"\n->[0x{}] = "{}"'.format(Operation, strOperation, FileName, strFileName))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def GetModuleFileNameA(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    lpFilename = ut.popstack()
    nSize = ut.popstack()
    res = 0

    ut.emu.mem_write(lpFilename, ut.command_line)

    _str = ut.getstr(lpFilename)
    strlen = len(_str)
 
    print('GetModuleFileNameA(0x{:08x}, lpString=0x{:08x} -> "{}", 0x{:08x}) = {:08x} => 0x{:08x}'.format(hModule, lpFilename, _str, nSize, strlen, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def FindResourceA(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    lpName = ut.popstack()
    lpType = ut.popstack()
    res = 0

    import pefile
    pe = pefile.PE(ut.pe.fname)
    # pe = pefile.PE('./samples/emotet/2019_0919/ac2162d2ae066bf9067ad7f8bf3697a78154ea68')

    rt_rcdata_idx = [
    entry.id for entry in 
    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(lpType)
    # pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

    rt_rcdata_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_rcdata_idx]
    for entry in rt_rcdata_directory.directory.entries:

        if lpName == entry.struct.Name:
            handle = len(ut.other_handle_map)+1
            res = handle
            ut.other_handle_map[handle] = entry
            ut.pefile_ = pe
            break
        
    print('FindResourceA(0x{:08x}, 0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(hModule, lpName, lpType, res, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, handle)
    ut.pushstack(retaddr)


def LoadResource(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    handle = ut.popstack()
    res = 0

    entry = ut.other_handle_map[handle]

    data_rva = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size

    # Retrieve the actual data and start processing the strings
    data = ut.pefile_.get_memory_mapped_image()[data_rva:data_rva+size]
    res = ut.heap_alloc(size)
    ut.emu.mem_write(res, bytes(data))

    print('LoadResourceA(0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(hModule, handle, res, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LockResource(ut):
    retaddr = ut.popstack()
    hMem = ut.popstack()

    print('LockResourceA(0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(hMem, hMem, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, hMem)
    ut.pushstack(retaddr)


def SizeofResource(ut):
    retaddr = ut.popstack()
    hModule = ut.popstack()
    handle = ut.popstack()
    res = 0

    entry = ut.other_handle_map[handle]
    res = entry.directory.entries[0].data.struct.Size

    print('SizeofResourceA(0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(hModule, handle, res, retaddr))
    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def CryptStringToBinaryA(ut):
    retaddr = ut.popstack()
    pszString = ut.popstack()
    cchString = ut.popstack()
    dwFlags = ut.popstack()
    pbBinary = ut.popstack()
    pcbBinary = ut.popstack()
    pdwSkip = ut.popstack()
    pdwFlags = ut.popstack()

    pszString_s = ut.emu.mem_read(pszString, cchString)
    res = 0
    if pbBinary == 0x00:
        size = len(base64.b64decode(pszString_s))
        ut.emu.mem_write(pcbBinary, ut.pack(size))
        res = 1
    elif pbBinary != 0x00:
        data = base64.b64decode(pszString_s)
        ut.emu.mem_write(pbBinary, bytes(data))
        res = 1

    print('CryptStringToBinaryA(0x{:08x} -> "{}", 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}) = 0x{:08x} => 0x{:08x}'.format(
        pszString, pszString_s, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)



def WideCharToMultiByte(ut):
    retaddr = ut.popstack()
    CodePage = ut.popstack()
    dwFlags = ut.popstack()
    lpWideCharStr = ut.popstack()
    cchWideChar = ut.popstack()
    lpMultiByteStr = ut.popstack()
    cbMultiByte = ut.popstack()
    lpDefaultChar = ut.popstack()
    lpUsedDefaultChar = ut.popstack()

    lpWideCharStr_s = ut.emu.mem_read(lpWideCharStr, cchWideChar*2)
    res = 0

    if lpMultiByteStr == 0x00:
        res = cchWideChar
    elif lpMultiByteStr != 0x00:
        lpWideCharStr_s = bytes(lpWideCharStr_s)
        data = lpWideCharStr_s.decode('UTF-16LE').encode("ascii","ignore")
        ut.emu.mem_write(lpMultiByteStr, bytes(data))
        res = cchWideChar

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)



hooks = set(vars().keys()).difference(hooks)

