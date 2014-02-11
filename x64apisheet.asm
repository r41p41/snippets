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
;rcx should be 32bit funchash
;rcx and rdx are supported as per __fastcall
;so this procedure can be embedded in C program
;
;funchash generation
;byte arr[]="apiname";
;hash=0
;hash = hash + (ror 0xd, byte[arr[i]])







getimagebase:		;returns image base of main Process
xor rax,rax
mov al,60h
mov rax,[gs: rax]
mov rax,[rax+18h]
mov rax,[rax+10h]
mov rax,[rax]
mov rax,[rax+30h]
ret

getntdll: 			;returns ntdll base in rax
xor rax,rax
mov al,60h
mov rax,[gs: rax]
mov rax,[rax+18h]
mov rax,[rax+10h]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax+30h]
ret

getkernel32: 		;returns kernel32 base in rax
xor rax,rax
mov al,60h
mov rax,[gs: rax]
mov rax,[rax+18h]
mov rax,[rax+10h]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax]
mov rax,[rax+30h]
ret