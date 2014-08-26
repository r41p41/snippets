/*
compiled with visual studio 2012 with universal __stdcall Declaration
from a 32bit program
	->Call SystemCalls in 32Bit OS
	
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
	
	Note: Further if KiFastSystemCallRet is NOP'd and KiIntSystemCall's First bytes are hooked.
	directly after our inline sysenter stub is executed, after kernelmode transition is done
	it will return EIP to usermode KiFastSystemCallRet which will return directly to our jmp [esp]
	if however KiFastSystemCallRet is NOP'd and KiIntSystemCall is hooked, sandbox hooks can still
	be executed, But 
		-They won't have Syscall no. since Eax is Volatile.
		-damage might have already been done.
	
uses:
break ring3 rootkits
break ring3 sandboxes
bypasses all usermode detection tools which rely on ring3 hooks

fallback:
race condition when KiFastSystemCallRet is hooked (in user mode) however it is unlikely.
*/


__declspec (naked) DWORD x86ApiCallBySysNo( DWORD no,  ...)
{
	__asm
	{
		pop ecx						;return address in ecx
		pop eax						;syscall no in eax
		push ecx					;return address pushed back
		jmp later					;add another return address on top of stack pointing to last instruction
back:
		mov edx,esp					;edx contains data of syscall, eax contains syscall no
		mov edi,0x7ffe0300			;copy shareduserdata in edi
		mov edi,[edi]				;get KiFastSystemCall in edi
		add edi,4					;Calculate KiFastSystemCallRet
		cmp byte ptr [edi],0xc3		;compare if hooked
		je final_call				;if not hooked execute sysenter
		mov byte ptr [edi],0xc3		;if hooked place 0xc3 and patch
final_call:
		_emit 0x0f					;visual studio 2012 won't recognize sysenter as a inline asm instruction so emit is used
		_emit 0x34
later:
		call back


		jmp DWORD ptr ds:[esp]		;first return address is ret from KiFastSystemCallRet ,
									;returns to here (in case our race condition patch doesn't work)
									;now stack has 3 params first containing return address from x86ApiCallbySysNo
									;when universal stdcall is in place, total params pushed were params+1 (syscall no)
									;when function is returning stack has 2 params+1 return address hence jmp [esp] and not ret.
									;it will be patched after stdcall clears up stack.
	}
}
