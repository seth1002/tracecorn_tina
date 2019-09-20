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

