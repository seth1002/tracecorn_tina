# Tracecorn_tina
This is a modified version of Tracecorn - https://github.com/icchy/tracecorn
I just made a few patches and added more API hooks. My goal is to unpack emotet layer1 and layer2 packers then extract c2 and rsa key from dump files.

Thank you Icchy! Your tracecorn is great!

# Requirements
Unicorn - https://github.com/unicorn-engine/unicorn

# Tricks
Emotet will start very large loop which cause high CPU usage. I Patched such trash code.
e.g 
```
# patch to bypass trash code -> 0x00401779: 	cmp	dword ptr [ebp - 4], 0x1b2e5
# patch to bypass trash code -> 0x00d604a6: 	cmp	dword ptr [ebp - 0xc], 0x32dcd5
```

# Sample

download test file from
```
https://app.any.run/tasks/c15700a4-6078-46a5-8d1c-d6c65090fbb9/
```

here is the dump file from tracecorn_tina
```
https://www.virustotal.com/gui/file/65e544a280c25733781704dee70ea82cb22a3dcb9a9db224a3dadc1aad8f988a/detection
```

here is ioc info
```
c2 list:
190.92.103.7:80
190.55.39.215:80
190.55.86.138:8443
179.24.118.93:990
181.230.126.152:8090
93.78.205.196:443
176.58.93.123:8080
69.164.216.124:8080
190.13.146.47:443
139.59.242.76:8080
149.202.153.251:8080
159.69.211.211:7080
203.150.19.63:443
5.9.128.163:8080
216.154.222.52:7080
192.241.175.184:8080

rsa key:
30 68 02 61 00 ce 36 ea e3 75 d6 7d 8b 64 39 3f 26 24 bd dd 62 16 1b b7 c6 09 09 8f e2 1e 72 20 95 31 27 0a e3 c2 d1 95 7b 10 9e 94 3d 96 2a b0 f0 f6 c6 bf c4 ac 26 40 a9 37 6f 67 d4 87 09 c7 5e 3a 12 a5 1e e9 2d a0 e8 ee 91 1c 88 90 79 cb a8 63 6c fc ab 49 f2 f7 17 1b bb e0 cd 92 01 2d 00 ae 3d ee 01 02 03 01 00 01 
```

running
```
python emotet_ioc_extractor.py {sample file path}
['/home/seth1002/project/PeEmu/unitracer/lib/windows/dll']
GDI32.dll is loaded @ 0x70000000
SHELL32.dll is loaded @ 0x70047000
KERNEL32.dll is loaded @ 0x7085c000
ADVAPI32.dll is loaded @ 0x70930000
SHLWAPI.dll is loaded @ 0x709cb000
USER32.dll is loaded @ 0x70a41000
IMM32.dll is loaded @ 0x70ad1000
ntdll.dll is loaded @ 0x70aee000
stack: 0x5ff00000-0x60000000
GetModuleHandleA(lpModuleName=0x00000000:"") = 0x00400000
Unhooked function: DeleteMetaFile (0x00000001)
Unhooked function: GetTopWindow (0x00000001)
Unhooked function: GetDC (0x00000001)
Unhooked function: GetMessageTime ()
Unhooked function: DestroyWindow (0x00000001)
Unhooked function: IsWindowEnabled (0x00000001)
Unhooked function: VkKeyScanW (0x00000001)
Unhooked function: IsClipboardFormatAvailable (0x00000001)
Unhooked function: GetKeyboardType (0x00000001)
Unhooked function: GetWindowContextHelpId (0x00000001)
Unhooked function: DestroyCursor (0x00000001)
Unhooked function: GetSystemPaletteUse (0x00000001)
Unhooked function: IsIconic (0x00000001)
Unhooked function: VkKeyScanA (0x00000001)
Unhooked function: CreateSolidBrush (0x00000001)
Unhooked function: IsWindowEnabled (0x00000001)
Unhooked function: CharUpperW (0x00432348)
Unhooked function: GetOpenClipboardWindow ()
Unhooked function: IsCharLowerA (0x00000001)
Unhooked function: ShowCaret (0x00000001)
Unhooked function: GetMenu (0x00000001)
Unhooked function: CreateSolidBrush (0x00000001)
Unhooked function: GetEnhMetaFileW (0x00432360)
Unhooked function: GdiFlush ()
Unhooked function: GetKeyState (0x00000001)
Unhooked function: CharUpperA (0x00432378)
Unhooked function: CharUpperA (0x00432384)
Unhooked function: CharUpperA (0x00432390)
Unhooked function: CharUpperA (0x0043239c)
Unhooked function: GetUserNameA (0x5fffff28, 0x5fffff94)
Unhooked function: GetStockObject (0x000011ab)
# patch to bypass trash code -> 0x00401779: 	cmp	dword ptr [ebp - 4], 0x1b2e5
Unhooked function: GetTextAlign (0x00000000)
#Load Library:"ADVAPI32")
LoadLibraryA (lpFileName="ADVAPI32") = 70930000 => 0x00401476
GetProcAddress (hModule=0x70930000, lpProcName=0x00432330:"RegOpenKeyA") = 0x7095c41b => 0x0040147d
Unhooked function: LoadCursorW (0x00000000, 0x00000d05)
RegOpenKeyA (hKey=0x80000000, lpSubkey=004322c0:"Interface\{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}", pHandle=0x00434580) = 0 => 004014b3
#Load Library:"ADVAPI32")
LoadLibraryA (lpFileName="ADVAPI32") = 70930000 => 0x004017a1
GetProcAddress (hModule=0x70930000, lpProcName=0x004323a8:"RegQueryValueExA") = 0x70937883 => 0x004017a8
Unhooked function: SetErrorMode (0x00000002)
GetModuleHandleW(lpModuleName=0x00000000) = 0x00400000
RegQueryValueExA (hKey=0x00000000, lpValueName=0x00434578:"", lpReserved=0x00000000, lpValueType=0x5ffffefc, lpBuffer=5ffffe2c:"IActiveScriptParseProcedure32", lpBufSize=5ffffef8:29) = 0 => 0040139b
VirtualAlloc (lpAddress=0x00000000, dwSize=0x00010200, flAllocationType=0x00003000, flProtect=0x00000040) = 0x00d50574 => 0x004019b7
# patch to bypass trash code -> 0x00d604a6: 	cmp	dword ptr [ebp - 0xc], 0x32dcd5
GetProcAddress (hModule=0x7085c000, lpProcName=0x5ffffe64:"LoadLibraryExA") = 0x708a07fa => 0x00d5fb6d
Unhooked function: LoadLibraryExA (0x5ffffe74, 0x00000000, 0x00000000)
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50574:"99999934tfserdgfwGetProcAddress") = 0x00000000 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50585:"GetProcAddress") = 0x708af3d3 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50596:"VirtualAlloc") = 0x708aefb6 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505a7:"LoadLibraryExA") = 0x708a07fa => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505b8:"SetFilePointer") = 0x708a9b36 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505c9:"lstrlenA") = 0x708a6611 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505da:"lstrcatA") = 0x708a619f => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505eb:"VirtualProtect") = 0x7089e341 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d505fc:"UnmapViewOfFile") = 0x708a9b13 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d5060d:"GetModuleHandleA") = 0x708a8f41 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d5061e:"WriteFile") = 0x708ad400 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d5062f:"CloseHandle") = 0x708a8a7c => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50640:"VirtualFree") = 0x708adda4 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50651:"GetTempPathA") = 0x708c2a65 => 0x00d5fbb4
GetProcAddress (hModule=0x00000000, lpProcName=0x00d50662:"CreateFileA") = 0x708a8ee8 => 0x00d5fbb4
GetProcAddress (hModule=0x7085c000, lpProcName=0x5ffffe74:"VirtualAlloc") = 0x708aefb6 => 0x00d5fc20
VirtualAlloc (lpAddress=0x00000000, dwSize=0x0000f200, flAllocationType=0x00003000, flProtect=0x00000040) = 0x00d60774 => 0x00d5fc33
VirtualAlloc (lpAddress=0x00000000, dwSize=0x00016000, flAllocationType=0x00003000, flProtect=0x00000040) = 0x00d6f974 => 0x00d6015b
VirtualProtect (lpAddress=00001000, dwSize=0000cba8, flNewProtect=00d506a4, lpflOldProtect=5ffffe60)
VirtualProtect (lpAddress=0000e000, dwSize=00000b2e, flNewProtect=00d50684, lpflOldProtect=5ffffe60)
VirtualProtect (lpAddress=0000f000, dwSize=00004034, flNewProtect=00d5068c, lpflOldProtect=5ffffe60)
VirtualProtect (lpAddress=00014000, dwSize=00000004, flNewProtect=00d50684, lpflOldProtect=5ffffe60)
VirtualProtect (lpAddress=00015000, dwSize=000003fc, flNewProtect=00d50684, lpflOldProtect=5ffffe60)
Unhooked function: LoadLibraryExA (0x00d7e494, 0x00000000, 0x00000000)
GetProcAddress (hModule=0x00000000, lpProcName=0x00d7e47a:"IsProcessorFeaturePresent") = 0x708b36b5 => 0x00d5ff47
Unhooked function: UnmapViewOfFile (0x00400000)
#Invalid memory mapping (UC_ERR_MAP)
VirtualAlloc (lpAddress=0x00400000, dwSize=0x00016000, flAllocationType=0x00003000, flProtect=0x00000040) = 0x00400000 => 0x00d60268
Unhooked function: GetModuleFileNameW (0x00000000, 0x5ffffb00, 0x00000104)
Unhooked function: GetProcessHeap ()
RtlAllocateHeap(00000000, 00000008, 00000010) = 0x00d85974 => 0x00401502
unregistered function: _snwprintf
Unhooked function: GetProcessHeap ()
Unhooked function: HeapFree (0x00000000, 0x00000000, 0x00d85974)
Unhooked function: GetCommandLineW ()
Unhooked function: lstrlenW (0x00000000)
Unhooked function: lstrlenW (0x5ffffd08)
Unhooked function: lstrcmpiW (0x00000000, 0x5ffffd08)
GetTickCount() = 6261630 => 0x0040a7be
Unhooked function: GetWindowsDirectoryW (0x5ffff8d0, 0x00000104)
Unhooked function: GetProcessHeap ()
RtlAllocateHeap(00000000, 00000008, 00000018) = 0x00d85984 => 0x00401502
unregistered function: _snwprintf
Unhooked function: GetProcessHeap ()
Unhooked function: HeapFree (0x00000000, 0x00000000, 0x00d85984)
Unhooked function: CreateMutexW (0x00000000, 0x00000000, 0x5ffffa50)
ExitProcess (0)
memset(0x5ffffa90, 0x00000000, 0x00000044) => 0x0040151a
ERROR: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
-----------------------------------------------------
 eax: 0x5fffff10  ebx: 0x00000104  ecx: 0x5ffffa90  edx: 0x00000044 
 edi: 0x5ffffb00  esi: 0x5ffffd08  esp: 0x5ffffa8c  ebp: 0x00401cd9 
 eip: 0x00000002 
-----------------------------------------------------
2019-09-17 04:41:34.008364
2019-09-17 04:42:27.290584
emulation time: (53) sec
dump main process at: ./dump/pe.dump
dump all heaps at: ./dump/heap
extract ioc from:./dump/pe.dump
c2 list:
190.92.103.7:80
190.55.39.215:80
190.55.86.138:8443
179.24.118.93:990
181.230.126.152:8090
93.78.205.196:443
176.58.93.123:8080
69.164.216.124:8080
190.13.146.47:443
139.59.242.76:8080
149.202.153.251:8080
159.69.211.211:7080
203.150.19.63:443
5.9.128.163:8080
216.154.222.52:7080
192.241.175.184:8080

rsa key:
30 68 02 61 00 ce 36 ea e3 75 d6 7d 8b 64 39 3f 26 24 bd dd 62 16 1b b7 c6 09 09 8f e2 1e 72 20 95 31 27 0a e3 c2 d1 95 7b 10 9e 94 3d 96 2a b0 f0 f6 c6 bf c4 ac 26 40 a9 37 6f 67 d4 87 09 c7 5e 3a 12 a5 1e e9 2d a0 e8 ee 91 1c 88 90 79 cb a8 63 6c fc ab 49 f2 f7 17 1b bb e0 cd 92 01 2d 00 ae 3d ee 01 02 03 01 00 01 
```
