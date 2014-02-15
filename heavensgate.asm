;Program for executing 64bit code in a 32bit WOW64 Process
;uses Far jump at selector 33h segment for transition
;x86tox64 subroutine: migrate from 32bit code to 64bit code
;[esp] takes address of code to be executed as 64bit instructions
;points to note
; [*]	only ntdll x64 will be available to 64bit code.
; [*]	kernel32 cannot be loaded due to base address relocation issues.
; [*]	best way to do stuff is to migrate 64bit code to another process.
; [*]	for migration we require ntdll Api for Allocation, Writing
;			i.e.
;			ZwAllocateVirtualMemory
;			ZwWriteVirtualMemory
; [*]	after migration either shellcode will be executed or PE image, in latter case loadling and linking has to be done manually
;original research done by vxers thus vxers called it heavens gate
;in reference to the call gate found at fs:0xc0 which can lead to a different world of 64bit opcodes
;for testing purposes windbgx64 can be used.
;RIP vxHeavens

[BITS 32]
x86tox64:
mov esi,fs:[0xc0]
cmp esi,0									;fs:[0xc0] contains pointer to x86switchto64 if its NULL we are in 32bit OS
jnz later
xor eax,eax
ret											;return 0 if we are in 32bit OS

later:
pop ecx										;ecx contains code to be executed as 64bit instructions
jmp trampoline
back:
pop ebx										;ebx contains offset to far jump
inc ebx										;now ebx contains pointer to 0x90909090
mov [ebx],ecx								;0x90909090 replaced with address to be executed
jmp trampoline+2							;jump to far jump

trampoline:
call back
db 0xEA,0x90,0x90,0x90,0x90,0x33,0x00		; far jump to 0x90909090 at segment 0x0033