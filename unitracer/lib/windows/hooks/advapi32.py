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


def CryptAcquireContextA(ut):
    res = 0
    defalut_prov_name = 'default_prov_handle'
    prov_name = ''
    handle = 0

    retaddr = ut.popstack()
    phProv = ut.popstack()

    if phProv != 0:
        handle = ut.unpack(ut.emu.mem_read(phProv, 4))
        if handle in ut.other_handle_map:
            res = 0

    szContainer = ut.popstack()
    str1 = ''
    if szContainer != 0:
        str1 = ut.getstr(szContainer)

    szProvider = ut.popstack()
    str2 = ''
    if szProvider != 0:
        str2 = ut.getstr(szProvider)

    dwProvType = ut.popstack()
    if dwProvType != 0:
        res = 1

    dwFlags = ut.popstack()

    if szContainer == 0:
        prov_name = defalut_prov_name
    else:
        prov_name = str1

    if handle == 0: # and prov_name not in ut.other_handle_map.values():
        # create default
        handle = len(ut.other_handle_map)+1 
        ut.other_handle_map[handle] = prov_name 
        ut.emu.mem_write(phProv, ut.pack(handle))
    else:
        res = 0

    print('CryptAcquireContextA(0x{:08x}, 0x{:08x}="{}", 0x{:08x}="{}", 0x{:08x}, 0x{:08x}) = {} =>0x{:08x}'.format(
        phProv, szContainer, str1, szProvider, str2, dwProvType, dwFlags, res, retaddr
    ))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut. pushstack(retaddr)


def CryptEncrypt(ut):

    retaddr = ut.popstack()
    hKey = ut.popstack()
    hHash = ut.popstack()
    Final = ut.popstack()
    dwFlags = ut.popstack()
    pbData = ut.popstack()
    pdwDataLen = ut.popstack()
    dwBufLen = ut.popstack()

    res = 0
    dwDataLen = ut.unpack(ut.emu.mem_read(pdwDataLen, 4))
    bData = ut.emu.mem_read(pbData, dwDataLen)
    val_hKey = ut.other_handle_map[hKey]
    if 'rc4_key' in val_hKey:

        # do rc4 decrypt
        def KSA(key):
            keylength = len(key)

            S = range(256)

            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % keylength]) % 256
                S[i], S[j] = S[j], S[i]  # swap

            return S

        def PRGA(S):
            i = 0
            j = 0
            while True:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]  # swap

                K = S[(S[i] + S[j]) % 256]
                yield K

        def RC4(key):
            S = KSA(key)
            return PRGA(S)
            res = 1

        def convert_key(s):
            # return [ord(c) for c in s]
            return [c for c in s]

        rc4_key = val_hKey['rc4_key']
        key = convert_key(rc4_key)

        keystream = RC4(key)
        plaintxt = ''.join([chr(c ^ keystream.next()) for c in bData])
        if len(plaintxt) > 0:
            ut.emu.mem_write(pbData, bytes(plaintxt))
            res = 1

    print('CryptEncrypt(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}) = {} => 0x{:08x}'.format(
        hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)
 

def CryptImportKey(ut):

    retaddr = ut.popstack()
    hProv = ut.popstack()
    pbData = ut.popstack()
    dwDataLen = ut.popstack()
    hPubKey = ut.popstack()
    dwFlags = ut.popstack()
    phKey = ut.popstack()
    res = 0

    bData = ut.emu.mem_read(pbData, dwDataLen)
    # ut.dump_mem(pbData)

    # init phKey
    val_phKey = {}

    if bData[0] == 0x07:
        val_phKey['bType'] = 'PRIVATEKEYBLOB'
    elif bData[0] == 0x01:
        val_phKey['bType'] = 'SIMPLEBLOB'

    if bData[4] == 0x00 and bData[5] == 0xA4:
        val_phKey['aiKeyAlg'] = 'CALG_RSA_KEYX'
    elif bData[4] == 0x01 and bData[5] == 0x68:
        # alg is rc4 
        val_phKey['aiKeyAlg'] = 'CALG_RC4'
        if bData[0x0C] == 0x00:
            val_phKey['rc4_key'] = reversed(bData[0x0C:0x0C+0x10])
            # print('# import RC4 key:', [x for x in val_phKey['rc4_key']])
        else:
            # import will fail
            val_phKey = {}

    if len(val_phKey) >0:
        handle = len(ut.other_handle_map)+1
        ut.other_handle_map[handle] = val_phKey
        ut.emu.mem_write(phKey, ut.pack(handle))
        res = 1
    else:
        res = 0

    print('CryptImportKey(0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}, 0x{:08x}) = {} => 0x{:08x}'.format(
        hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey, res, retaddr
    ))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)
 

hooks = set(vars().keys()).difference(hooks)
hooks = [_x for _x in hooks if not _x.startswith('_')]
