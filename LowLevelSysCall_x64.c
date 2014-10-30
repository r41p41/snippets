/*
compiled with x86_64-w64-mingw32 without optimizations
switches for smaller binary
-nostdlib -s
from a 64bit program
	->Call SystemCalls in 64Bit OS
	
	-Do not use Optimization
	-Do not use Optimization of any sort
	-Again do not use any sort of Optimization

	This type of SystemCall calling bypasses
	all forms of usermode sandbox which utilize
	inline,EAT,IAT and other forms of hooking
	including cuckoo, sandboxie, anubis etc.
	except ring0 hooks
	->SSDT
	->kernel hooks
	->Driver Inline Hooks
	->and more
	
	
uses:
break ring3 rootkits
break ring3 sandboxes
bypasses all usermode detection tools which rely on ring3 hooks
To dynamically Find SysCall NO from Name, use GetSysCallNo_FromName.c in this same repo.


fallback:
Ugly Code
*/
#define a_start __asm(".intel_syntax noprefix");__asm(
#define a_end );__asm(".att_syntax");
DWORD64 x64ApiCallBySysNo(DWORD syscallNo,...)
{
// Prologue code will put top 4 stack entries with rcx,rdx,r8,r9 respectively putting our syscallNo at rsp+0x10
	a_start                               //prologue
	"mov rax,[rsp]\n"                     //return address into rax
	"add rsp,8\n"                         //rsp points rbp which was put to rsp+8 during prologue
	"xchg [rsp],rax\n"                    //exchange return address with rbp
	"xchg [rsp+8],rax\n"                  //exchange rbp with first param i.e. syscall No
	"mov rbp,rsp\n"                       //rsp contains return address, rsp+8 contains rbp, rax contains syscall No
	"mov rcx,[rsp+0x10]\n"                //rcx gets Second param, but due to stack realignment now First param.
	"mov rdx,[rsp+0x18]\n"                //rcx gets Third param, but due to stack realignment now Second param.
	"mov r8,[rsp+0x20]\n"                 //rcx gets Fourth param, but due to stack realignment now Third param.
	"mov r9,[rsp+0x28]\n"                 //rcx gets Fifth param, but due to stack realignment now Fourth param.
	"mov r10,rcx\n"                       //requirement for syscall instruction
	"syscall\n"
	"mov rcx,[rsp+8]\n"                   //after syscall completes we need to realign stack by 8 bytes
	"mov [rsp],rcx\n"
	"sub rsp,8\n"                         //all set, stack realigned to default
	a_end                                 //epilogue
}



//  example usage

int main()
{
  return x64ApiCallBySysNo(0x29,0xFFFFFFFFFFFFFFFF,0);    //0x29 is syscall no for ZwTerminateProcess
}
