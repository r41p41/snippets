/*
	to grab syscall no from ntdll, from its string
	example:
	GetSysCallNo("ZwTerminateProcess");
	returns SysCallNo as per ntdll
	
	Since visual studio is a bitch to work with, when coding 64bit asm mixed with C.
	Its compiled with x86_64-w64-mingw32 without optimizations
	switches for smaller binary and easy to read in debugger
	-nostdlib -s
	
	working:
	list all exports of ntdll.dll
	if first two characters of api offset are Zw,	//fix from Nt to Zw Switch because of NtdllDefWin... apis
	then calculate address by walking EAT
	and place that address in a list.
	After list is populated, sort them in ascending order of their addresses.
	starting address is syscall 0 and so on we can calculate any syscall NO
	from just its address.
	
	This is to ensure that even if SysCall is tampered with or hooked or detoured
	we will get a proper Syscall No, without reading ntdll from disk.
	
	Logic can be used in x86 as well as x64 environments,
	however current code only gets x64 syscall nos
	
	Note: if you will get extra junk Api's which get considered as syscall because
	of this trashy method, kindly report so i can change the algorithm.
	Dirty hack, thus very little error checking
	
*/
#define a_start __asm(".intel_syntax noprefix");__asm(
#define a_end );__asm(".att_syntax");
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
DWORD64 gpr(DWORD64 hash,DWORD64 dllbase)
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
DWORD64 GetSysCallNo(char *SysCallName)
{
	DWORD64 ntdll=getntdll();
	DWORD64 SysCallAddress = gpr(gethash(SysCallName),ntdll);
	if(SysCallAddress == 0)
		return SysCallAddress;
	
	a_start
	"push rax\n"
	a_end
	
	getntdll();
	//rax contains ntdll base
	a_start
	"mov rdx,rax\n"
	"xor rax,rax\n"
	"mov eax,[rdx+0x3c]\n"
	"mov rbx,rdx\n"
	"add rdx,rax\n"
	"add rdx,0x88\n"
	"mov eax,[rdx]\n"
	"add rax,rbx\n"
	
	"xor rcx,rcx\n"
	"xor r14,r14\n"
	"mov r10,rsp\n"
	"sub r10,0x8\n"
	"earlier_1:\n"
	"cmp r14d,[rax+0x18]\n"
	"jg sort\n"
	
	
	"xor r9,r9\n"
	"xor rdx,rdx\n"
	"mov edx,[rax+0x20]\n"
	"mov r9d,[rax+0x24]\n"
	"add rdx,rbx\n"
	"add r9,rbx\n"
	
	
	"xor rsi,rsi\n"
	"mov esi,[rdx+r14*4]\n"
	"add rsi,rbx\n"
	"cmp word ptr ds:[rsi],0x775A\n"
	"jne mid\n"
	"mov cx,[r9+r14*2]\n"
	"xor rdx,rdx\n"
	"mov edx,[rax+0x1c]\n"
	"add rdx,rbx\n"
	"mov r11d,[rdx+rcx*4]\n"
	"add r11,rbx\n"
	"push r11\n"
	"mid:\n"
	"inc r14\n"
	"jmp earlier_1\n"
	
	"sort:\n"
	"mov r8,rsp\n"
	"mov r13,r10\n"
	
	"sort_start:\n"
	"mov rsp,r8\n"	
	"mov rdx,rsp\n"
	"pop rax\n"
	"loop:\n"
	"pop rcx\n"
	"cmp rax,rcx\n"
	"ja end_loop\n"
	"mov rax,rcx\n"
	"mov rdx,rsp\n"
	"sub rdx,0x8\n"
	"end_loop:\n"
	"cmp rsp,r10\n"
	"jbe loop\n"
	"mov rsi,[r10]\n"
	"mov [rdx],rsi\n"
	"mov [r10],rax\n"
	"sub r10,0x8\n"
	"cmp r10,r8\n"
	"jne sort_start\n"
	"mov rsp,r13\n"
	"add rsp,0x8\n"
	// sort done, r10 points to first syscall no. 0
	//r13 points to last syscall no. X
	//rsp contains old pushed syscall address
	
	"pop rax\n"
	"loop2:\n"
	"cmp rax,[r13]\n"
	"je gotit\n"
	"sub r13,0x8\n"
	"cmp r13,r10\n"
	"jge loop2\n"
	"jmp end_func\n"
	"gotit:\n"
	"mov rax,r13\n"
	"sub rax,r10\n"
	"shr rax,0x3\n"
	"end_func:\n"
	a_end
}
