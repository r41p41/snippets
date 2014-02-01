/*
using MS Sapi via classes and objects just for speech output bumps file to 200kb+
reverse engineering internal offsets and using them without hassle of compiling com
objects can be easy.
Following snippet can give voice output in a hacky way and bump executable size to 
2.5kb with correct params in gcc

******* 1kb with no imports if used gpr function from x86apiSheet.asm to get address of cocreateinstance && coinitialize********

compiler flags
gcc -o output.exe speakapi.c -nostdlib -s -mwindows -lole32
used mingw gcc from Dev-C++ for compiling this.
*/


#include<windows.h>
void * pVoice = NULL;
DWORD speak,setrate;
voidinit();
speakapi(LPWSTR,int);
WinMainCRTStartup()
{
    init();
	
	//speak api first param is unicode text to be spoken
	//speak api second param is rate of output tested only from -10 to 10.
	//can be embedded into any C program
    speakapi(L"Hello World",-2);
	
}
void init()
{
    DWORD iid_ispvoice[] = {0x6c44df74, 0x499272b9, 0x99efeca1, 0xd422046e};
    DWORD clsid_spvoice[] = {0x96749377, 0x11d23391, 0xc000e39e, 0x9673794f};
    DWORD clsctx_all = 0x17;
    CoInitialize(NULL);
    CoCreateInstance((REFCLSID)clsid_spvoice, NULL, clsctx_all, (REFIID)iid_ispvoice, (void **)&pVoice);
}
speakapi(LPWSTR text,int rate)
{
    FARPROC addr;
    __asm(".intel_syntax noprefix");
    __asm("mov eax,_pVoice");
    __asm("mov eax,[eax]");
    __asm("mov ebx,[eax+0x70]");
    __asm("mov _setrate,ebx");
    __asm("mov eax,[eax+0x50]");
    __asm("mov _speak,eax");
    __asm(".att_syntax");
    addr=(FARPROC)setrate;
    addr(pVoice,rate);
    addr=(FARPROC)speak;
    addr(pVoice,text,0,NULL);
}
