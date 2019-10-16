import unitracer
from unicorn import *
from unicorn.x86_const import *
import os, sys, re, struct, shutil
import pefile

# A copy of WinAppdbg
def pattern(token):
    """
    Convert an hexadecimal search pattern into a POSIX regular expression.
    For example, the following pattern::
        "B8 0? ?0 ?? ??"
    Would match the following data::
        "B8 0D F0 AD BA"    # mov eax, 0xBAADF00D
    @type  token: str
    @param token: String to parse.
    @rtype:  str
    @return: Parsed string value.
    """
    token = ''.join([ c for c in token if c == '?' or c.isalnum() ])
    if len(token) % 2 != 0:
        raise ValueError("Missing characters in hex data")
    regexp = ''
    for i in range(0, len(token), 2):
        x = token[i:i+2]
        if x == '??':
            regexp += '.'
        elif x[0] == '?':
            f = '\\x%%.1x%s' % x[1]
            x = ''.join([ f % c for c in range(0, 0x10) ])
            regexp = '%s[%s]' % (regexp, x)
        elif x[1] == '?':
            f = '\\x%s%%.1x' % x[0]
            x = ''.join([ f % c for c in range(0, 0x10) ])
            regexp = '%s[%s]' % (regexp, x)
        else:
            regexp = '%s\\x%s' % (regexp, x)
    return regexp


def search(data, sig):

    addr = -1
    pt = pattern(sig)
    ret = re.search(pt.encode(), data)
    if ret:
        offset = ret.end()
        addr = offset
    
    return addr


def myins_callback(ut, address, size, userdata):

    code = ut.emu.mem_read(address, size)

    # bypass layer trash code
    if code and code[0] == 0x81:
        for insn in ut.cs.disasm(str(code), address):
            ins = '0x{0:08x}: \t{1}\t{2}'.format(insn.address, insn.mnemonic, insn.op_str)

            if ', 0x' in ins and 'cmp' in ins:
                counter = int(ins.split(', 0x')[1], 16)
                if counter > ut.ADDRESS and counter < ut.ADDRESS+ut.size: return
                if counter > 100000 and counter < 400000000:
                    print('# patch to bypass trash code -> {}'.format(ins))
                    inss = '\x83\xfc\00'+'\x90'*(insn.size-3)
                    ut.emu.mem_write(address, inss)
    
    # if address == 0x0040B97A:
    #     ut.emu.reg_write(UC_X86_REG_EAX, 1)


def extract_ioc(dump_path, base, is_mem_dump=True):

    print('extract ioc from:{}'.format(dump_path))

    data = None
    if is_mem_dump:
         with open(dump_path, 'rb') as fh:
            data = fh.read()
    else:
        pe = pefile.PE(dump_path)
        data = pe.get_memory_mapped_image()

    rsa_pub_key = ''
    c2_list = []

    # .text:00401FA1 68 00 80 00 00                          push    8000h
    # .text:00401FA6 6A 6A                                   push    6Ah
    # .text:00401FA8 68 D0 F8 40 00                          push    offset unk_40F8D0
    # .text:00401FAD 6A 13                                   push    13h
    # .text:00401FAF 68 01 00 01 00                          push    10001h
    # .text:00401FB4 FF 15 F4 05 41 00                       call    CryptDecodeObjectEx
    sig_rsa_pub_key = '68 00 80 00 00 6a 6a 68'
    offset = search(data, sig_rsa_pub_key)
    rsa_pub_key_offset = struct.unpack('<I', data[offset:offset+4])[0]-base
    rsa_pub_key = data[rsa_pub_key_offset:rsa_pub_key_offset+0x6a]
    rsa_pub_key = ''.join(['{:02x} '.format(ord(x)) for x in rsa_pub_key])

    # .text:004060C5 B8 C0 F3 40 00                          mov     eax, offset stru_40F3C0
    # .text:004060CA A3 E0 26 41 00                          mov     off_4126E0, eax
    # .text:004060CF A3 E4 26 41 00                          mov     off_4126E4, eax
    # .text:004060D4 33 C0                                   xor     eax, eax
    sig_c2_list = 'B8 ?? ?? ?? 00 A3 ?? ?? ?? 00 A3 ?? ?? ?? 00 33 C0'
    offset = search(data, sig_c2_list)
    c2_list_offset = struct.unpack('<I', data[offset-16:offset-16+4])[0]-base
    for idx in range(0, 200):
        item = data[c2_list_offset+idx*8:c2_list_offset+idx*8+8]
        ip = '{}.{}.{}.{}'.format(*reversed(struct.unpack('<BBBB', item[0:4])))
        port = struct.unpack('<H', item[4:6])[0]
        if item[0] == '\x00': break
        c2_list.append('{}:{}'.format(ip, port))

    return c2_list, rsa_pub_key


def get_final_payload(file_path, sig):

    print('processing mem dump:{}'.format(file_path))
    final_paylaod_path = None
    data = None
    # scan file 
    with open(file_path, 'rb') as fh:
        data = fh.read()
        offset = search(data, sig)
        if -1 == offset:
            return None
            
    print('hit sig')
    if data:
        # extract final payload
        final_payload_offset = data.rfind('\x4D\x5A\x90')
        if final_payload_offset == -1: return 
        print('hit final payload')
        final_payload = data[final_payload_offset:]
        final_paylaod_path = './dump/final_payload.dump'
        with open(final_paylaod_path, 'wb') as fh:
            fh.write(final_payload)

    # return final payload file path
    return final_paylaod_path

 
if __name__ == '__main__':


    file_path = sys.argv[1]
    # file_path = './samples/emotet/2019_0919/ac2162d2ae066bf9067ad7f8bf3697a78154ea68'
    # file_path = './samples/emotet/2019_0920/sha1_4d95854d87ab6397b48de09558255e257d4f644d'
    # file_path = './samples/emotet/2019_1016/88dd0ac77bdb9185d3b776b56417ad7c88bd00c9'

    uni = unitracer.Windows()
    uni.verbose = False

    # if sys.argv[2] == 1:
    #     verbos = True

    # add search path for dll
    uni.dll_path.insert(0, "dlls")

    # change stack
    uni.STACK_BASE = 0x60000000
    uni.STACK_SIZE = 0x80000

    uni.load_pe(file_path)

    # set my ins hook
    uni.user_ins_callback = myins_callback

    import datetime
    start = datetime.datetime.now() 
    uni.start(0)

    print(start)
    end = datetime.datetime.now()
    print(end)

    dump_pe_path = './dump/pe.dump'
    dump_heap_path = './dump/heap'

    # clear dump
    if os.path.exists(dump_pe_path):
        os.remove(dump_pe_path)

    if os.path.exists(dump_heap_path):
        shutil.rmtree(dump_heap_path, ignore_errors=True)

    os.mkdir(dump_heap_path)

    print('emulation time: ({}) sec'.format((end-start).seconds))
    print('dump main process at: {}'.format(dump_pe_path))
    print('dump all heaps at: {}'.format(dump_heap_path))
    uni.dump_pe_mem(dump_pe_path)
    uni.dump_heap(dump_heap_path)

    print('\n-----------------------------')
    final_paylaod_path = None

    # searching final payload
    # scan pe.dump
    sig_rsa_pub_key = '68 00 80 00 00 6a 6a 68'
    final_paylaod_path = get_final_payload(dump_pe_path, sig_rsa_pub_key)
    if final_paylaod_path is None:
        # scan each heap dump 
        for s in os.listdir(dump_heap_path):
            _p =os.path.join(dump_heap_path,s)
            if os.path.isfile(_p):
                final_paylaod_path = get_final_payload(_p, sig_rsa_pub_key)
                if final_paylaod_path:
                    break

    if final_paylaod_path:
        c2_list , rsa_pub_key = extract_ioc(final_paylaod_path, 0x400000, False)

        print('\nc2 list:')
        for c2 in c2_list:
            print('{}'.format(c2))

        print('\nrsa key:\n{}'.format(rsa_pub_key))
    
