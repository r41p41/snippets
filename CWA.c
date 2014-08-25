/*
CWA in short for call windows APi
takes n + 2 parameters
where n is the number of param required for api to be called.
CWA can be used to call any API and is written from scratch to ensure maximum compatibility
optimized for visual studio 2012
first two parameters provide 
hash of apiname
hash of dllname
next n parameters are in same sequence as youwould call them
This offers a clean cut api call rather than calling tacky and time consuming import table



example usage

#define kernel32 0xcd3308cb
#define _VirtualAlloc 0x91afca54

CWA(kernel32,_VirtualAlloc,0,0x1000,0x3000,0x40);


the above line calls virtual alloc from kernel32.dll for address 0, size 0x10000, allocation type 0x3000 and protection type 0x40 (RWE)
only drawback is above usage wont provide auto complete for new people
note:hashes are generated  via rot 0xd call specified in hashcalc.c in same reository
*/

__declspec (naked) DWORD gpr(...)
{
	__asm
	{	
								;returns address of function in eax
								;[esp+4] should be base of dll
								;[esp+8] should be funchash

		xor edi,edi
rerun:
		mov eax,[esp+0x4]
		xor ebx,ebx
		add bx,[eax+0x3c]
		add eax,ebx ;eax= address of "PE"
		xor bx,bx
		add eax,0x78
		mov eax,[eax]     ;eax= EAT RVA
		add eax,[esp+0x4] ;eax= EAT VA
		cmp edi,[esp+8]
		je backagain
		mov ebx,[eax+0x20] 		;ebx= aon RVA
		add ebx,[esp+0x4]  		;ebx=aon VA
		mov ecx,[eax+0x18] 		;ecx=number of func
		xor edx,edx
		xor eax,eax

		sub ebx,4

back:
		test ecx,ecx
		jz last

		add ebx,4
		add edx,2

		mov esi,[ebx] 			;hash computing begins esi=string pointer till 0x00
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
later: 							;edi holds hash now
		cmp edi,[esp+8]
		jne neee
		jmp rerun
backagain: 						;eax=EAT VA again
		mov ebx,[eax+0x24]
		add ebx,[esp+4]
		add ebx,edx
		xor ecx,ecx
		mov cx,[ebx]
		mov ebx,[eax+0x1c] 		;ebx=aof rva
		add ebx,[esp+4] 		;ebx=aof rva
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
	}
}
__declspec (naked) DWORD getdll(...)
{
	__asm
	{
	 							;returns dll base in eax until hash [esp+4] is found
		xor ecx,ecx
		mov cl,30h
		mov ecx,fs:[ecx]
		mov ecx,[ecx+0ch]
		mov ecx,[ecx+14h]
l1:
		mov esi,ecx
		mov esi,[esi+28h]		;esi contains unicode string
		cmp esi,0
		jz last1
		xor ebx,ebx
		xor eax,eax
genhash1:
		lodsb
		cmp al,0x60
		jg lm1
		cmp al,0x40
		jl lm1
		add al,0x20
lm1:
		test al,al
		jz late
		ror ebx,0xd
		add ebx,eax
		inc esi
		jmp genhash1
late:
		cmp ebx,[esp+4]
		je l3
		mov ecx,[ecx]
		jmp l1
l3:
		mov eax,ecx
		mov eax,[eax+10h]
		retn  4
last1:
		mov eax,0
		retn 4
	}
}
__declspec (naked) DWORD CWA(...)
{
	__asm
	{

		push [esp+8]
		call getdll
		push [esp+4]
		push eax
		call gpr
		add esp,8
		mov ebx,[esp-8]
		add ebx,3
		mov [esp],ebx
		jmp eax

	}	
}
