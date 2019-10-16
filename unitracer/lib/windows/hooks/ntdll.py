from unicorn.x86_const import *
import struct 


hooks = None
hooks = set(vars().keys())


def RtlAllocateHeap(ut):
    retaddr = ut.popstack()
    HeapHandle = ut.popstack()
    Flags = ut.popstack()
    Size = ut.popstack()

    res = ut.heap_alloc(Size)
    print('RtlAllocateHeap({0:08x}, {1:08x}, {2:08x}) = 0x{3:08x} => 0x{4:08x}'.format(
        HeapHandle, Flags, Size, res, retaddr))

    ut.emu.reg_write(UC_X86_REG_EAX, res)
    ut.pushstack(retaddr)


def LdrGetProcedureAddress(ut):
    emu = ut.emu
    retaddr = ut.popstack()
    ModuleHandle = ut.popstack()
    FunctionName = ut.popstack()
    Oridinal = ut.popstack()
    FunctionAddress = ut.popstack()

    lpProcName_s = None

    try:
        # ordinal
        if Oridinal != 0:
            lpProcName_s = ut.dll_ord_fun_name_mp[ModuleHandle][Oridinal]
        else: 
        # fun name
            # typedef struct _ANSI_STRING {
            #     USHORT  Length;
            #     USHORT  MaximumLength;
            #     PSTR    Buffer;
            # } ANSI_STRING, *PANSI_STRING;

            lpProcName_len = struct.unpack('<H', emu.mem_read(FunctionName, 2))[0]
            lpProcName = struct.unpack('<I', emu.mem_read(FunctionName+4, 4))[0]
            lpProcName_s = str(emu.mem_read(lpProcName, lpProcName_len))
    except Exception as e:
        print('failed to call :LdrGetProcedureAddress=0x{0:08x}, FunctionName={1:x}\n+++\n{2}\n'.format(
            ModuleHandle, FunctionName, str(e)))

    res = None
    if lpProcName_s in ut.dll_funcs:
        res = ut.dll_funcs[lpProcName_s]
        _t = struct.pack('I', res)
        emu.mem_write(FunctionAddress, struct.pack('I', res))
    else:
        res = 0x0

    print 'LdrGetProcedureAddress (ModuleHandle=0x{0:08x}, FunctionsName=0x{1:08x}:"{2}", ...) = 0x{3:08x}'.format(
        ModuleHandle, FunctionName, lpProcName_s, res)
    ut.emu.reg_write(UC_X86_REG_EAX, 0)
    ut.pushstack(retaddr)

hooks = set(vars().keys()).difference(hooks)

