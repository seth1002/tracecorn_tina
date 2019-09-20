from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86_const import *

from .unitracer import Unitracer
from .lib.util import *
from .lib.segment import GDT_32
from .lib.windows.pe import PE
from .lib.windows.i386 import *
from .lib.windows import hooks as m_hooks
from .lib.windows.hooks.tool.hook import Hook

from ctypes import sizeof

import sys
import struct
import os
import types


class Windows(Unitracer):

    CMD_LINE_ADDR = 0x1B000
    OS_ENVIRONMENT_STR_ADDR = 0x1C000

    SHARED_MEM = 0x260000
    SHARED_SIZE = 0x10000

    ADDRESS = 0x400000

    STACK_BASE = 0x00d00000
    STACK_SIZE = 0x10000

    GDT_BASE = 0x80000000
    GDT_SIZE = 0x1000

    TIB_ADDR = 0x00b7d000
    TEB_ADDR = TIB_ADDR
    PEB_ADDR = 0x00b2f000
    PEB_LDR_ADDR = 0x77dff000

    HEAP_BASE = 0x00d50000
    HEAP_CUR = HEAP_BASE
    HEAP_DEFAULT_SIZE = 0x2A0000

    DLL_BASE = 0x70000000
    DLL_CUR = DLL_BASE

    STACK_FIRST_SYS_CALL_ADDR = 0x7FFD4000


    alloc_mem_range_list = {}
    alloc_mem_list = {}

    dlls = []
    dll_funcs = {}
    dll_funcs_addrs_fast_tb = {}

    user_ins_callback = None
    user_hooks_addr_tb = {}
    api_hooks = {}

    hooks = []
    # dll_path = [os.path.join('unitracer', 'lib', 'windows', 'dll')]
    dll_path = [os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib', 'windows', 'dll')]
    print(dll_path)

    verbose = True
    pe = None
    start_trace = False


    def __init__(self, os="Windows 7", bits=32, mem_size = 15*1024*1024, emu_time = 60):
        self.process_id = 758
        self.first_thread_id = 6674
        self.current_thread_id = self.first_thread_id
        self.bits = bits
        self.bytes = bits/8
        self.is64 = True if bits == 64 else False
        self.os = os
        self.emu_time = emu_time

        self.dll_ord_fun_name_mp = {}
        self.tls_stors = {}
        self.fls_stors = {}

        ############################
        #  OS config
        ############################

        self.reg_value_map = {'interface\{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}':'IActiveScriptParseProcedure32'}
        self.reg_path_handle_map = {}
        self.other_handle_map = {}

        self.command_line = b'C:\\Users\\admin\\AppData\\Local\\easywindow\\easywindow.exe\x00'
        # self.command_line = b'C:\\Users\\tina\\Desktop\\wawa.exe\x00'
        self.os_environment_wstr = 'ALLUSERSPROFILE=C:\Documents and Settings\All Users'.encode('UTF-16LE')

        self.LPOSVERSIONINFOA = ''


        # emu default init
        assert bits == 32, "currently only 32 bit is supported"

        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs = cs

        self.emu.mem_map(self.SHARED_MEM, self.SHARED_SIZE)
        self.emu.mem_write(self.SHARED_MEM, '\x00'*self.SHARED_SIZE)

        self._load_hooks()


    def _init_process(self):
        emu = self.emu
        bits = self.bits
        os = self.os

        self.PEB = {
            "Windows NT"        : [PEB_NT,      None],
            "Windows 2000"      : [PEB_2000,    None],
            "Windows XP"        : [PEB_XP,      PEB_XP_64],
            "Windows 2003"      : [PEB_2003,    PEB_2003_64],
            "Windows 2003 R2"   : [PEB_2003_R2, PEB_2003_R2_64],
            "Windows 2008"      : [PEB_2008,    PEB_2008_64],
            "Windows 2008 R2"   : [PEB_2008_R2, PEB_2008_R2_64],
            "Windows 7"         : [PEB_W7,      PEB_W7_64],
        }[os][self.is64]

        self.TEB = {
            "Windows NT"        : [TEB_NT,      None],
            "Windows 2000"      : [TEB_2000,    None],
            "Windows XP"        : [TEB_XP,      TEB_XP_64],
            "Windows 2003"      : [TEB_2003,    TEB_2003_64],
            "Windows 2003 R2"   : [TEB_2003_R2, TEB_2003_R2_64],
            "Windows 2008"      : [TEB_2008,    TEB_2008_64],
            "Windows 2008 R2"   : [TEB_2008_R2, TEB_2008_R2_64],
            "Windows 7"         : [TEB_W7,      TEB_W7_64],
        }[os][self.is64]

        if bits == 32:
            # init Thread Information Block
            teb = self.TEB()
            peb = self.PEB()

            # setup peb, teb
            peb.ImageBaseAddress = self.ADDRESS
            peb.Ldr = self.PEB_LDR_ADDR
            peb.ProcessHeap = self.HEAP_BASE
            peb.OSMajorVersion = 6

            teb.NtTib.StackBase = self.STACK_BASE
            teb.NtTib.StackLimit = self.STACK_BASE - self.STACK_SIZE
            teb.NtTib.Self = self.TEB_ADDR
            teb.ThreadLocalStoragePointer = self.TEB_ADDR
            teb.ProcessEnvironmentBlock = self.PEB_ADDR

            emu.mem_map(self.PEB_ADDR, align(sizeof(peb)))
            emu.mem_write(self.PEB_ADDR, struct2str(peb))

            emu.mem_map(self.TEB_ADDR, align(sizeof(teb)))
            emu.mem_write(self.TEB_ADDR, struct2str(teb))

            # init Global Descriptor Table
            gdt = GDT_32(emu, self.GDT_BASE, self.GDT_SIZE)

            # cs : 0x0023 (index:4)
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=3, ex=1, dc=0, rw=1, ac=1)
            selector = gdt.set_entry(4, 0x0, 0xffffffff, flags)
            emu.reg_write(UC_X86_REG_CS, selector)

            # ds, es, gs : 0x002b (index:5)
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1)
            selector = gdt.set_entry(5, 0x0, 0xffffffff, flags)
            emu.reg_write(UC_X86_REG_DS, selector)
            emu.reg_write(UC_X86_REG_ES, selector)
            emu.reg_write(UC_X86_REG_GS, selector)

            # ss
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=0, ex=0, dc=1, rw=1, ac=1)
            selector = gdt.set_entry(6, 0x0, 0xffffffff, flags, rpl=0)
            emu.reg_write(UC_X86_REG_SS, selector)

            # fs : 0x0053 (index:10)
            flags = GDT_32.gdt_entry_flags(gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1) # 0x4f3
            selector = gdt.set_entry(10, self.TIB_ADDR, 0xfff, flags)
            emu.reg_write(UC_X86_REG_FS, selector)

            self.gdt = gdt


    def _init_ldr(self, dlls=None, exe_ldr=None):
        emu = self.emu
        containsPE = False

        if dlls == None or len(dlls)==0:
            dlls = ["ntdll.dll", "kernel32.dll"]

        dlls_name_lower = [x.lower() for x in dlls]
        if 'ntdll.dll' not in dlls_name_lower:
            dlls.append('ntdll.dll')
        if 'kernel32.dll' not in dlls_name_lower:
            dlls.append('kernel32.dll')

        # allocate processheap
        emu.mem_map(self.HEAP_BASE, self.HEAP_DEFAULT_SIZE)

        # create LDR_DATA_TABLE_ENTRY
        ldrs = []
        for dll in dlls:
            dllpath = self._find_dll(dll)
            if not dllpath:
                # raise IOError, "{} does not exist".format(dll)
                print("* {} does not exist".format(dll))
                continue

            pe = PE(dllpath)

            dllbase = self.load_dll(dll)
            dll_name = os.path.basename(dll)
            fulldllname = "C:\\Windows\\System32\\{}".format(dll_name).encode("UTF-16LE")
            basedllname = dll_name.encode("UTF-16LE")

            ldr_module = LDR_MODULE()

            ldr_module.addr = self._alloc(sizeof(ldr_module))
            ldr_module.fulldllname = fulldllname
            ldr_module.basedllname = basedllname

            ldr_module.BaseAddress = dllbase
            ldr_module.EntryPoint = pe.entrypoint
            ldr_module.SizeOfImage = pe.imagesize

            ldr_module.FullDllName.Length = len(fulldllname)
            ldr_module.FullDllName.MaximumLength = len(fulldllname)+2
            ldr_module.FullDllName.Buffer = self._alloc(len(fulldllname)+2)
            ldr_module.BaseDllName.Length = len(basedllname)
            ldr_module.BaseDllName.MaximumLength = len(basedllname)+2
            ldr_module.BaseDllName.Buffer = self._alloc(len(basedllname)+2)

            ldrs.append(ldr_module)

        if exe_ldr:
            ldrs.insert(0, exe_ldr)

        # setup PEB_LDR_DATA
        ldr_data = PEB_LDR_DATA()
        ldr_data.addr = self.PEB_LDR_ADDR
        ldr_data.InLoadOrderModuleList.Flink = ldrs[0].addr
        ldr_data.InLoadOrderModuleList.Blink = ldrs[-1].addr
        ldr_data.InMemoryOrderModuleList.Flink = ldrs[0].addr+0x8
        ldr_data.InMemoryOrderModuleList.Blink = ldrs[-1].addr+0x8
        ldr_data.InInitializationOrderModuleList.Flink = ldrs[0].addr+0x10
        ldr_data.InInitializationOrderModuleList.Blink = ldrs[-1].addr+0x10

        # link table entries
        for i in range(len(ldrs)):
            n = (i+1)%len(ldrs)
            p = (i-1+len(ldrs))%len(ldrs)

            ldrs[i].InLoadOrderModuleList.Flink = ldrs[n].addr
            ldrs[i].InLoadOrderModuleList.Blink = ldrs[p].addr
            ldrs[i].InMemoryOrderModuleList.Flink = ldrs[n].addr+0x8
            ldrs[i].InMemoryOrderModuleList.Blink = ldrs[p].addr+0x8
            ldrs[i].InInitializationOrderModuleList.Flink = ldrs[n].addr+0x10
            ldrs[i].InInitializationOrderModuleList.Blink = ldrs[p].addr+0x10

        ldrs[0].InLoadOrderModuleList.Blink = ldr_data.addr+0xc
        ldrs[-1].InLoadOrderModuleList.Flink = ldr_data.addr+0xc
        ldrs[0].InMemoryOrderModuleList.Blink = ldr_data.addr+0x14
        ldrs[-1].InMemoryOrderModuleList.Flink = ldr_data.addr+0x14
        ldrs[0].InInitializationOrderModuleList.Blink = ldr_data.addr+0x1c
        ldrs[-1].InInitializationOrderModuleList.Flink = ldr_data.addr+0x1c

        # write data
        emu.mem_map(self.PEB_LDR_ADDR, align(sizeof(ldr_data)))
        emu.mem_write(self.PEB_LDR_ADDR, struct2str(ldr_data))

        for ldr_module in ldrs:
            emu.mem_write(ldr_module.FullDllName.Buffer, ldr_module.fulldllname)
            emu.mem_write(ldr_module.BaseDllName.Buffer, ldr_module.basedllname)
            emu.mem_write(ldr_module.addr, struct2str(ldr_module))

        self.ldr_data = ldr_data
        self.ldrs = ldrs


    def heap_alloc(self, size):
        return self._alloc(size)


    def _alloc(self, size):

        # size = align(size, 0x100)
        # log all alloc mem info
        addr_range = '{0:08x}_{1:08x}'.format(self.HEAP_CUR, self.HEAP_CUR+size-1)
        self.alloc_mem_range_list[addr_range] = [self.HEAP_CUR, size]
        self.alloc_mem_list[self.HEAP_CUR] = size

        ret = self.HEAP_CUR
        self.HEAP_CUR += size
        if self.HEAP_CUR > self.HEAP_BASE+self.HEAP_DEFAULT_SIZE:
            more_size = (((size%0x1000)+1)*0x1000)
            self.emu.mem_map(self.HEAP_CUR, more_size)
        return ret


    def _find_dll(self, dllname):
        dll_path = self.dll_path
        path = None
        for d in dll_path:
            p = os.path.join(d, dllname.lower())
            if os.path.exists(p):
                path = p
                break
        return path


    def load_dll(self, dllname):
        dlls = self.dlls
        emu = self.emu
        base = self.DLL_CUR

        path = self._find_dll(dllname)
        if path is None:
            print('Cannot locate dll file:{}'.format(dllname))
            return 0

        dlldata = self._load_dll(path, base, dllname)
        size = align(len(dlldata))
        emu.mem_map(base, size)
        emu.mem_write(base, dlldata)
        dlls.append([dllname, base])
        self.DLL_CUR += size

        print("{0} is loaded @ 0x{1:08x}".format(dllname, base))

        return base


    def _load_dll(self, path, base, analysis=True):
        dll_funcs = self.dll_funcs
        dll_funcs_addrs_fast_tb = self.dll_funcs_addrs_fast_tb

        dll = PE(path)
        data = bytearray(dll.mapped_data)

        self.dll_ord_fun_name_mp[self.DLL_CUR] = dll.dll_ord_exp_name

        # patch all exported fun with 0xc3, just return
        for name, addr in dll.exports.items():
            # print(name)
            vaddr = dll.nt_header.OptionalHeader.DataDirectory[0].VirtualAddress
            size = dll.nt_header.OptionalHeader.DataDirectory[0].Size
            if addr > vaddr and addr < vaddr+size:
                # Bug
                # TO DO: get reall fun addr, hook the real functions address
                # fwd import funcitons
                data[addr] = '\xc3'
                dll_funcs[name] = base + addr
                dll_funcs_addrs_fast_tb[base+addr] = name
            else:
                data[addr] = '\xc3'
                dll_funcs[name] = base + addr
                dll_funcs_addrs_fast_tb[base+addr] = name

        # offset = str(data).find('InitializeProcThreadAttributeList')
        return bytes(data)


    def _hook_code(self, uc, address, size, userdata):

        api_hooks = self.api_hooks
        dll_funcs = self.dll_funcs

        # user ins code hook 
        if self.user_ins_callback:
            self.user_ins_callback(self, address, size, userdata)

        # user defined code hook
        if address in self.user_hooks_addr_tb:
            self.user_hooks_addr_tb[address](self, address, size, userdata)

        if self.verbose:
            code = uc.mem_read(address, size)
            self.dumpregs(['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'])
            for insn in self.cs.disasm(str(code), address):
                ins = '0x{0:08x}: \t{1}\t{2}\n'.format(insn.address, insn.mnemonic, insn.op_str)
                print(ins)

        # if address in dll_funcs.values():
        if address in self.dll_funcs_addrs_fast_tb:
            func = {v:k for k, v in dll_funcs.items()}[address]
            if func in api_hooks.keys():
                hook = api_hooks[func]
                if isinstance(hook, Hook):
                   # predefined API hook
                   hook.hook(self)
                elif isinstance(hook, types.FunctionType):
                    # user defined API hook
                    hook(self)
                else:
                    print("unknown hook type: {}".format(type(hook)))
            else:
                print("unregistered function: {}".format(func))


    def _load_hooks(self):
        api_hooks = self.api_hooks
        for n in m_hooks.hooks:
            api_hooks[n] = getattr(m_hooks, n)
        self.api_hooks = api_hooks


    def load_code(self, data):
        emu = self.emu
        ADDRESS = self.ADDRESS

        self.size = len(data)
        self.entry = self.ADDRESS + 0
        self._init_ldr(["ntdll.dll", "ntdll.dll", "kernel32.dll"])
        self._init_process()

        # map shellcode
        emu.mem_map(ADDRESS, align(len(data)))
        emu.mem_write(ADDRESS, data)
        emu.reg_write(UC_X86_REG_EIP, ADDRESS)

        # init stack
        STACK_BASE = self.STACK_BASE
        STACK_SIZE = self.STACK_SIZE
        emu.mem_map(STACK_BASE - STACK_SIZE, align(STACK_SIZE))
        print("stack: 0x{0:08x}-0x{1:08x}".format(STACK_BASE - STACK_SIZE, STACK_BASE))
        emu.reg_write(self.ucreg('sp'), STACK_BASE)
        emu.reg_write(self.ucreg('bp'), STACK_BASE)

        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)


    def load_pe(self, fname):
        emu = self.emu
        # ADDRESS = self.ADDRESS
        dll_funcs = self.dll_funcs

        pe = PE(fname)
        self.pe = pe

        self.ADDRESS = pe.imagebase
        ADDRESS = self.ADDRESS
        dlls = pe.imports.keys()

        self.STACK_SIZE = pe.stacksize
        
        exe_ldr = LDR_MODULE()
        pe_name = os.path.basename(fname)
        fulldllname = "C:\\Users\\victim\\{}".format(pe_name).encode("UTF-16LE")
        basedllname = pe_name.encode("UTF-16LE")

        exe_ldr.addr = self._alloc(sizeof(exe_ldr))
        exe_ldr.fulldllname = fulldllname
        exe_ldr.basedllname = basedllname

        exe_ldr.BaseAddress = ADDRESS
        exe_ldr.EntryPoint = pe.entrypoint
        exe_ldr.SizeOfImage = pe.imagesize

        exe_ldr.FullDllName.Length = len(fulldllname)
        exe_ldr.FullDllName.MaximumLength = len(fulldllname)+2
        exe_ldr.FullDllName.Buffer = self._alloc(len(fulldllname)+2)
        exe_ldr.BaseDllName.Length = len(basedllname)
        exe_ldr.BaseDllName.MaximumLength = len(basedllname)+2
        exe_ldr.BaseDllName.Buffer = self._alloc(len(basedllname)+2)

        self._init_ldr(dlls, exe_ldr)
        self._init_process()

        # rewrite IAT
        data = bytearray(pe.mapped_data)
        for dllname in pe.imports:
            for api, addr in pe.imports[dllname].items():
                overwritten = False
                if api in dll_funcs:
                    offset = addr - pe.imagebase
                    data[offset:offset+4] = p32(dll_funcs[api])
        data = str(data)

        # map PE
        pe_mem_size = align(len(data))
        emu.mem_map(ADDRESS, pe_mem_size)
        emu.mem_write(ADDRESS, data)
        self.size = len(data)
        self.entry = ADDRESS + pe.entrypoint

        # init stack
        STACK_BASE = self.STACK_BASE
        STACK_SIZE = self.STACK_SIZE
        emu.mem_map(STACK_BASE - STACK_SIZE, align(STACK_SIZE))
        print("stack: 0x{0:08x}-0x{1:08x}".format(STACK_BASE - STACK_SIZE, STACK_BASE))
        emu.reg_write(self.ucreg('sp'), STACK_BASE)
        emu.reg_write(self.ucreg('bp'), STACK_BASE)

        # init OS env
        emu.mem_map(self.CMD_LINE_ADDR, align(len(self.command_line)))
        emu.mem_write(self.CMD_LINE_ADDR, self.command_line)

        emu.mem_map(self.OS_ENVIRONMENT_STR_ADDR, align(len(self.os_environment_wstr)))
        emu.mem_write(self.OS_ENVIRONMENT_STR_ADDR, self.os_environment_wstr)


        # emu control flow from kernel32 
        self.pushstack(self.HEAP_CUR)
        self.pushstack(self.STACK_FIRST_SYS_CALL_ADDR)

        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)
        # emu.hook_add(UC_HOOK_BLOCK, self._hook_code)


    def search_process(self, sig):
        emu = self.emu
        pe_data = emu.mem_read(self.ADDRESS, self.size)
        pe_data = str(pe_data)
        _offset = pe_data.find(sig)
        return self.ADDRESS+_offset # +self.pe.nt_header.OptionalHeader.BaseOfCode-0x1000
        

    def dump_pe_mem(self, dump_path):
        emu = self.emu
        pe_data = emu.mem_read(self.ADDRESS, self.size)
        with open(dump_path, 'wb') as fh:
            fh.write(pe_data)


    def dump_heap(self, dump_path):
        emu = self.emu
        for addr_range, mem_info  in self.alloc_mem_range_list.items():
            pe_data = emu.mem_read(mem_info[0], mem_info[1])
            with open(dump_path+'/'+addr_range, 'wb') as fh:
                fh.write(pe_data)


    def set_emu_time(self, emu_time=60):
        self.emu_time = emu_time


    def start_from(self, address, size):
        emu = self.emu
        self.entry = address
        self.size = size
        entry = self.entry

        try:
            # start emu timmer

            emu.emu_start(entry, entry + self.size)
        except UcError as e:
            print("ERROR: %s" % e)
            self.dumpregs(["eax", "ebx", "ecx", "edx", "edi", "esi", "esp", "ebp", "eip"])


    def start(self, offset):
        emu = self.emu
        entry = self.entry

        try:
            # start emu timmer

            emu.emu_start(entry, entry + self.size)
        except UcError as e:
            print("ERROR: %s" % e)
            self.dumpregs(["eax", "ebx", "ecx", "edx", "edi", "esi", "esp", "ebp", "eip"])


    def dump_ins(self, code, address):
        for insn in self.cs.disasm(str(code), address):
            ins = '0x{0:08x}: \t{1}\t{2}'.format(insn.address, insn.mnemonic, insn.op_str)
            print(ins)