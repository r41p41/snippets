/*
clc hashes for api name for x86apiheet
names must be case sensitive
usage of compiler flags -s -nostdlib -lmsvcrt
compiled with mingw gcc
for 64bit code change r32 to r64.
*/


#include<windows.h>
#include<stdio.h>
DWORD hash=0;
char arr[1024];
unsigned char arr2[2048];
WinMainCRTStartup()
{
	gets(arr);
	
	__asm(".intel_syntax noprefix");
	__asm("lea esi,_arr");
	__asm("mov ecx,_hash");
	__asm("prev:");
	__asm("xor eax,eax");
	__asm("lodsb");
	__asm("test al,al");
	__asm("jz next");
	__asm("ror ecx,0xd");
	__asm("add ecx,eax");
	__asm("jmp prev");
	__asm("next:");
	__asm("mov _hash,ecx");
	__asm(".att_syntax");
	
	
	printf("0x%0.2x = hash value",hash);
}
/* 64bit
#include<windows.h>
#include<stdio.h>

DWORD64 genhash_64(BYTE *arr);
int WinMainCRTStartup()
{
	BYTE arr[1024];
	gets(arr);
	printf("0x%x%x = hash value",genhash_64(arr)>>0x20,genhash_64(arr));
	return 0;
}

DWORD64 genhash_64(BYTE *arr)
{
	__asm(".intel_syntax noprefix");
	__asm("mov rsi,rcx");
	__asm("xor rcx,rcx");
	__asm("prev:");
	__asm("xor rax,rax");
	__asm("lodsb");
	__asm("test al,al");
	__asm("jz next");
	__asm("ror rcx,0xd");
	__asm("add rcx,rax");
	__asm("jmp prev");
	__asm("next:");
	__asm("mov rax,rcx");
	__asm(".att_syntax");
}
*/