/*
generic way to detect Actual Thread OEP iterate all seh handlers till we reach 0xffffffff
note the address at which -1 or last handler's address is located and label this temp.
add 0x30 to  temp, and simultaneously add 0x18 to temp.
they both will be equal to each other and point to start address in normal circumstances.
*/
#include<windows.h>
DWORD GetThreadStartAddress(HANDLE hThread)
{
	typedef struct _THREAD_BASIC_INFORMATION
	{
		int ExitStatus;
		PVOID TebBaseAddress;
		DWORD a,b,c,d,e;
	}THREAD_BASIC_INFORMATION;

	THREAD_BASIC_IFNORMATION tbi;
	FARPROC qti;
	DWORD ntdll,temp=0,temp2=0,temp3=0,pd=0;
	ntdll = (DWORD) GetModuleHandle("ntdll");
	SuspendThread(hThread);
	if(ntdll)
	{
		qti=GetProcAddress(ntdll,"ZwQueryInformationThread");
		if(qti)
		{
			qti(hThread,0,&tbi,sizeof(THREAD_BASIC_INFORMATION),NULL);
			if(tbi)
			{
				ReadProcessMemory(hThread,tbi.TebBaseAddress,&temp2,4,&pd); //temp2 gets fs:[0x00] or current seh handler
				if(pd==4)
				{
					while(temp!=0xffffffff)             					//iterate all seh handlers till we reach last
					{
                    	ReadProcessMemory(open,temp2,&temp,4,&pd);			
						if(pd!=4)
						break;
                    	if(temp!=0xffffffff)temp2=temp;
                    }
				}
			}
		}
	}
	if(pd!=4) //didn't work out
	temp2=0;
	else
	{
		ReadProcessMemory(open,temp2+0x30,&temp,4,&pd);
		ReadProcessMemory(open,temp2+0x18,&temp3,4,&pd);
	}
	ResumeThread(hThread);
	if(temp == temp3)
	return temp;
	else
	return 0;
}