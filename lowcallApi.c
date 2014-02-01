/*
compiled with visual studio 2012
from a 32bit program
	->call api's in 32bit OS
	->call api's in 64bit OS

	Since this is a low level procedure no error checking is done for maximum speed
	error checking should be implemented before calling this Api set

	This type of api calling bypasses
	all forms of usermode sandbox which utilize
	inline,EAT,IAT and other forms of hooking
	including cuckoo, sandboxie, anubis etc.
	except ring0 hooks
	->SSDT
	->kernel hooks
	->Driver Inline Hooks
	->and more
	
	
uses:
detect ring3 rootkits
detect ring3 sandboxes
no need for usermode unhooking
*/

__declspec (naked) DWORD x86ApiCallBySysNo( DWORD no, DWORD no_of_params , ...)
{
//first parameter is SysCall no
//second param is no of parameters required for this api
//third param onwards are normal api arguments
	__asm
	{
		pop ecx						;pop return address in ecx
		pop eax						;pop syscall no in eax
		pop ebx						;pop no of params into ebx which is unchanged after sysenter
		shl ebx,2					;multiply no of params with 4 for stack boundary
		push ecx					;push return address back
		jmp last					;jmp forward
		back:						;now stack top is return back after sysenter and esp+4 is return address of function
		mov edx,esp					;put data ptr in esp and sysclal in eax
		sysenter					;stub for api call returning to [esp]
		last:						
		call back					;jmp to back: only to push next eip
		nop							;jump here after sysenter with unset stack
		pop ecx						;ebx holds return address
		add esp,ebx					;align stack before this function call wa even setup
		jmp ecx						jmp to return address preserving stack as if api never got called
	}
}

__declspec (naked) DWORD x64ApiCallBySysNo( DWORD no , DWORD no_of_params , ...)
{
//first parameter is SysCall no
//second param is no of parameters required for this api
//third param onwards are normal api arguments
	__asm
	{
		pop ecx						;pop return address in ecx
		pop eax						;pop syscall no in eax
		pop ebx						;pop no of params into ebx which is unchanged after x64_sysenter
		shl ebx,2					;multiply no of params with 4 for stack boundary
		push ecx					;push return address back
		jmp last					;jmp forward
		back:						;now stack top is return back after sysenter and esp+4 is return address of function
		lea edx,dword [esp+4]
		xor ecx,ecx
		jmp fs:[0xc0]
		last:						
		call back					;jmp to back: only to push next eip
		add esp,4							;jump here after sysenter with unset stack
		pop ecx						;ebx holds return address
		add esp,ebx					;align stack before this function call wa even setup
		jmp ecx						jmp to return address preserving stack as if api never got called
	}
}