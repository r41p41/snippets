/*
generic way to detect Actual Thread OEP iterate all seh handlers till we reach 0xffffffff
note the address at which -1 or last handler's address is located and label this temp.
add 0x30 to  temp, and simultaneously add 0x18 to temp.
they both will be equal to each other and point to start address in normal circumstances under windows xp and +.
in some flavours of windows xp 0x18 will point to OEP of thread but 0x30 will be out of bounds.
*/
#include<windows.h>
DWORD GetThreadStartAddress(HANDLE hThread,HANDLE hProcess)
{
	typedef struct _THREAD_BASIC_INFORMATION
	{
		int ExitStatus;
		PVOID TebBaseAddress;
		DWORD a,b,c,d,e;
	}THREAD_BASIC_INFORMATION;

	THREAD_BASIC_INFORMATION tbi;
	FARPROC qti;
	DWORD ntdll,temp=0,temp2=0,temp3=0,pd=0;
	ntdll = (DWORD) GetModuleHandle("ntdll");
	if(ntdll)
	{
		qti=GetProcAddress(ntdll,"ZwQueryInformationThread");
		if(qti)
		{
			qti(hThread,0,&tbi,sizeof(THREAD_BASIC_INFORMATION),NULL);
			if(tbi.TebBaseAddress)
			{
				SuspendThread(hThread);
				
				if(ReadProcessMemory(hProcess,tbi.TebBaseAddress,&temp2,4,&pd)) 	//temp2 gets fs:[0x00] or current seh handler)
				{
					while(temp!=0xffffffff)             							//iterate all seh handlers till we reach last
					{
						if(ReadProcessMemory(hProcess,temp2,&temp,4,&pd)==0)
						break;
                    	if(temp!=0xffffffff)temp2=temp;
                    }
				}
				ResumeThread(hThread);
			}
		}
	}
	temp=0;
	temp3=0;
	ReadProcessMemory(hProcess,temp2+0x18,&temp,4,&pd);
	ReadProcessMemory(hProcess,temp2+0x30,&temp3,4,&pd);
	/*  experimental
	if(temp == temp3) 	
	return temp;		
	else
	return temp;
	*/
	return temp;
}
