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


def LoadStringW(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    hInstance = ut.popstack()
    uID = ut.popstack()
    lpBuffer = ut.popstack()
    cchBufferMax = ut.popstack()

    res = 0
    string = ""

    import pefile

    pe = pefile.PE(ut.pe.fname)

    # Fetch the index of the resource directory entry containing the strings
    #
    rt_string_idx = [
    entry.id for entry in 
    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])

    # Get the directory entry
    #
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

    # For each of the entries (which will each contain a block of 16 strings)
    #
    for entry in rt_string_directory.directory.entries:

        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        if uID in entry.directory.strings:
            string = entry.directory.strings[uID]
            bytes_data =bytes(string.encode('utf-16le'))
            size = len(bytes_data)
            res = size
            buff = ut.heap_alloc(size)
            ut.emu.mem_write(buff, bytes_data)
            ut.emu.mem_write(lpBuffer, ut.pack(buff))

    print('LoadStringW(0x{:08x}, 0x{:08x}, 0x{:08x} -> "" , 0x{:08x},) = {} => 0x{:08x}'.format(
        hInstance, uID, lpBuffer, cchBufferMax, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


hooks = set(vars().keys()).difference(hooks)

