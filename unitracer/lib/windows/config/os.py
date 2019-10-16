from __future__ import absolute_import

from ctypes import *
from io import BytesIO

# standard types
CHAR        = c_char
BYTE        = c_ubyte
WORD        = c_uint16
DWORD       = c_uint32
LONG        = c_int32
ULONGLONG   = c_uint64


class OSVERSIONINFOA (Structure):
    _fields_ = [
        ("dwOSVersionInfoSize",             DWORD),     # 0xFEEF04BD
        ("dwMajorVersion",                  DWORD),
        ("dwMinorVersion",                  DWORD),
        ("dwBuildNumber",                   DWORD),
        ("dwPlatformId",                    DWORD),
        ("szCSDVersion",                    CHAR*128),
    ]


def gen_os_version():
    os_ver = OSVERSIONINFOA()
    os_ver.dwOSVersionInfoSize = 0x94
    os_ver.dwMajorVersion = 0x06
    os_ver.dwMinorVersion = 01
    os_ver.dwBuildNumber = 0x1DB1
    os_ver.dwPlatformId = 0x02
    os_ver.szCSDVersion = 'Service Pack 1'
    return BytesIO(os_ver).read()


'''
typedef struct _SYSTEM_INFO {
  union {
    DWORD dwOemId;
    struct {
      WORD wProcessorArchitecture;
      WORD wReserved;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  DWORD     dwPageSize;
  LPVOID    lpMinimumApplicationAddress;
  LPVOID    lpMaximumApplicationAddress;
  DWORD_PTR dwActiveProcessorMask;
  DWORD     dwNumberOfProcessors;
  DWORD     dwProcessorType;
  DWORD     dwAllocationGranularity;
  WORD      wProcessorLevel;
  WORD      wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;
'''

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("dwOemId",                           DWORD),
        ("dwPageSize",                        DWORD),
        ("lpMinimumApplicationAddress",       DWORD),
        ("lpMaximumApplicationAddress",       DWORD),
        ("dwActiveProcessorMask",             DWORD),
        ("dwNumberOfProcessors",              DWORD),
        ("dwProcessorType",                   DWORD),
        ("dwAllocationGranularity",           DWORD),
        ("wProcessorLevel",                   WORD),
        ("wProcessorRevision",                WORD),
    ]


def gen_system_ifno():
    sys_info = SYSTEM_INFO()
    sys_info.dwOemId = 0x00000000 
    sys_info.dwPageSize = 0x00001000 
    sys_info.lpMinimumApplicationAddress = 0x00010000
    sys_info.lpMaximumApplicationAddress = 0x7FFEFFFF
    sys_info.dwActiveProcessorMask = 0x0000000F
    sys_info.dwNumberOfProcessors = 0x00000004
    sys_info.dwProcessorType = 0x0000024A
    sys_info.dwAllocationGranularity = 0x00010000
    sys_info.wProcessorLevel = 0x0006
    sys_info.wProcessorRevision = 0x3C03
    return BytesIO(sys_info).read()
