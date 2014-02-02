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

__declspec (naked) DWORD x86ApiCallBySysNo( DWORD no,  ...)
{
//first parameter is SysCall no
//second param onwards are normal api arguments
//no need for epilogue cleanup or prologue setup
//leave stack as it was so VS can handle stack alignment on its own

	__asm
	{
		pop ecx						;pop return address in ecx
		pop eax						;pop syscall no in eax
		push ecx					;push return address back
		jmp last					;jmp forward
back:								;now stack top is return back after sysenter and esp+4 is return address of function

		mov edx,esp					;put data ptr in esp and syscall in eax
		sysenter					;perform sysenter and goto end
		
last:						
		call back					;jmp to back: only to push next eip
		jmp dword ptr ss:[esp]		;visual studio will add epilogue to clean up stack after subroutine returns back with stack pointer being intact
	}
}

__declspec (naked) DWORD x64ApiCallBySysNo( DWORD no , DWORD no_of_params , ...)
{
//first parameter is SysCall no
//second param is no of parameters required for this api
//third param onwards are normal api arguments
//no need for epilogue cleanup or prologue setup
//leave stack as it was so VS can handle stack alignment on its own

	__asm
	{
		pop ecx						;pop return address in ecx
		pop eax						;pop syscall no in eax
		push ecx					;push return address back
		xor ecx,ecx
		lea edx,dword ptr ss:[esp+4]
		jmp next
back:


		jmp dword ptr fs:[0xc0]		;can replace this with far jump to X86SwitchTo64BitMode
									;far jmp will always be in this byte sequence -> EA 1E 27 XX 7X 33 00 
									;with XX 7X being ASLR random, rest constant.
next:
		call back

		add esp,4					;jump here after api call with unset stack, add esp,4 puts stack in original position as it entered this function
		jmp dword ptr ss:[esp]		;since stack is in original position and esp points to return address jmp [esp] will serve as perfect trampoline
	}
}