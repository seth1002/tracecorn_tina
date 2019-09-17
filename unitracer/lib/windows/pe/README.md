# pe
simple PE parser

## Features
 * `IMAGE_DIRECTORY_ENTRY_IMPORT`
 * `IMAGE_DIRECTORY_ENTRY_EXPORT`
 * mapped data extracted to memory
 * support both 32bit and 64bit binary

## sample code
```python
from pe import PE

# list export functions
pe = PE('kernel32.dll')
print "ImageBaseAddr: 0x{0:08x}".format(pe.imagebase)
for api, addr in pe.exports.items():
    print "{0} @ 0x{1:08x}".format(api, addr)

# list import functions
pe = PE('test.exe')
print "ImageBaseAddr: 0x{0:08x}".format(pe.imagebase)
for dllname in pe.imports:
    for api, addr in pe.imports[dllname].items():
        print "{0} ({1}) @ 0x{2:08x} (IAT)".format(api, dllname, addr)
```
