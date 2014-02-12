;gpr is a low level procedure to find direct address of any API
;using its name and the name of dll in whih its present
;this technique can be used for import masking and created from scratch
;can be used to find API address and then call it directly without putting
;any api in import section of PE

;to be used in shellcode development for dynamically locating
;address of api's
;for better security it handles named hash of api
;and dll baseaddress

;usage in x64 shellcodes



[BITS 64]


gpr:
;returns address of function in eax
;rdx should be base of dll
;rcx should be 64bit funchash
;rcx and rdx are supported as per __fastcall
;so this procedure can be embedded in C program
;
;funchash generation
;byte arr[]="apiname";
;hash=0
;hash = hash + (ror 0xd, byte[arr[i]])

xor rax,rax
mov eax,[rdx+0x3c]	;dword pointer to nt header
mov rbx,rdx			;save baseaddress in rbx
add rdx,rax			;add rva of nt header to base address
add rdx,0x88			;offset to export dir rva
mov eax,[rdx]		;place rva in dword eax
add rax,rbx			;place sum of rva EAT and image base in eax
					;by now rax holds EAT VA
					;and rbx holds base address
mov r8,rcx			;save function hash in r8

xor rcx,rcx
xor rdx,rdx
xor r9,r9
					;[rax+18] is no of function names
					;[rax+1c] is RVA of AOF
mov edx,[rax+0x20]	;rdx contains RVA of AON (address of names)
mov r9d,[rax+0x24]	;r9 contains RVA of name ordinal array (mapping)

add rdx,rbx			;rdx points to AON
add r9,rbx			;r9 points to ordinal array (word array not dword)

loop_through_AON:
xor rsi,rsi
xor r10,r10			;xor for hash storage
xor r11,r11			;xor for string byte storage
mov esi,[rdx+rcx*4]	;pointer to indexed strings into rsi
add rsi,rbx

earlier:
mov r11b,[rsi]
test r11b,r11b
jz later
inc rsi
ror r10,0xd
add r10,r11
jmp earlier
later:
cmp r10,r8
jne again			;no hit
mov cx,[r9+rcx*2]	;hash hit and cx contains no of ordinal distance
xor rdx,rdx
mov edx,[rax+0x1c]
add rdx,rbx
mov r11d,[rdx+rcx*4]
mov rax,r11
add rax,rbx
jmp end

again:
inc rcx
cmp rcx,[rax+0x18]
jne loop_through_AON
xor rax,rax
end:
ret					;remove this ret if compiling on gcc (it will be appended by pop rbp\nret
					;which will fuck up the stack alignment, only use it when compiling shellcode

getimagebase:		;returns image base of main Process
xor rax,rax
mov al,0x60
mov rax,[gs: rax]
mov rax,[rax+0x18]
mov rax,[rax+0x10]
mov rax,[rax+0x30]
ret

getntdll: 			;returns ntdll base in rax
xor rax,rax
mov al,0x60
mov rax,[gs: rax]
mov rax,[rax+0x18]
mov rax,[rax+0x10]
mov rax,[rax]
mov rax,[rax+0x30]
ret

getkernel32: 		;returns kernel32 base in rax
xor rax,rax
mov al,0x60
mov rax,[gs: rax]
mov rax,[rax+0x18]
mov rax,[rax+0x10]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax+0x30]
ret