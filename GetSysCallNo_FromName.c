DWORD GetSysCallNo(char *SysCallName)
{
	
	/*
	to grab syscall no from ntdll, from its string
	example:
	GetSysCallNo("ZwTerminateProcess");
	returns SysCallNo as per ntdll
	
	
	working:
	list all exports of ntdll.dll
	if first two characters of api offset are Nt,
	then calculate address by walking EAT
	and place that address in a list.
	After list is populated, sort them in ascending order of their addresses.
	starting address is syscall 1 and so on we can calculate any syscall NO
	from just its address.
	
	This is to ensure that even if SysCall is tampered with or hooked or detoured
	we will get a proper Syscall No
	
	Logic can be used in x86 as well as x64 environments,
	however current code only gets x86 and WOW64 syscall nos
	
	Note: you will get extra junk Api's which get considered as syscall because
	of this trashy method.
	No Error checking, do it yourself
	*/
	
	DWORD ntdll = (DWORD)GetModuleHandle(L"ntdll");
	DWORD SysCallAddress = (DWORD)GetProcAddress((HMODULE)ntdll,SysCallName);
	DWORD *Arr,TotalNames;
	DWORD temp,i=-1,j,k;
	__asm
	{
		mov eax,ntdll
		mov ebx,eax
		mov eax,[eax+0x3c]
		add eax,ebx
		add eax,0x78
		mov eax,[eax]
		add eax,ebx
		xor ecx,ecx
		add ecx,eax
		mov esi,[ecx+0x18]
		mov TotalNames,esi
	}
	Arr = (DWORD*)VirtualAlloc(0,TotalNames*4,0x3000,0x40);
	__asm
	{
		mov eax,ntdll
		mov ebx,eax
		mov eax,[eax+0x3c]
		add eax,ebx
		add eax,0x78
		mov eax,[eax]
		add eax,ebx
		xor ecx,ecx
		add ecx,eax
		mov eax,[ecx+0x24]
		mov esi,[ecx+0x18]
		mov ecx,[ecx+0x20]
		add eax,ebx
		add ecx,ebx
back:
		mov edi,[ecx]
		xor edx,edx
		mov dx,word ptr [eax]
		add edi,ebx
		add ecx,4
		add eax,2
		cmp word ptr ds:[edi],0x775A
		jne continue_last
		push ebx
		mov ebx,[ebx+0x3c]
		add ebx,[esp]
		add ebx,0x78
		mov ebx,[ebx]
		add ebx,[esp]
		mov ebx,[ebx+0x1c]
		add ebx,[esp]
		mov ebx,[ebx+edx*4]
		add ebx,[esp]
		mov edx,ebx
		pop ebx
		mov temp,edx
		inc i
		pushad
	}
	Arr[i] = temp;
	__asm
	{
		popad
continue_last:
		dec esi
		test esi,esi
		jnz back
	}
	
	k=i;
	for(i=0;i<=k;i++)
		for(j=i+1;j<=k;j++)
			if(Arr[i]>Arr[j])
			{
				temp = Arr[i];
				Arr[i] = Arr[j];
				Arr[j] = temp;
			}
			
	
	for (i=0;i<=k;i++)
		if(Arr[i]==SysCallAddress)
			return i;
	return 0;
}
