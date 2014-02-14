//dump a 32bit process's memory
//by providing size and address
#include<windows.h>
#include<stdio.h>
int main()
{
	int pid;
	DWORD size;
	DWORD addr;
	LPBYTE arr;
	printf("process pid:");
	scanf("%d",&pid);
	printf("size:");
	scanf("%x",&size);
	printf("addr:");
	scanf("%x",&addr);
	printf("%0.8x\n",addr);
    arr=VirtualAlloc(0,size,0x3000,0x40);	
    DWORD pd;
    HANDLE open=(HANDLE)OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	if(open)
	{
		if(ReadProcessMemory(open,(LPVOID)addr,arr,size,&pd))
		{
			printf("%d  bytes read",pd);
			HANDLE hFile=CreateFile("dump.bin",                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL); 
            if(hFile)
			{
				WriteFile(hFile,arr,size,&pd,0);
				CloseHandle(hFile);
			}
		}
		CloseHandle(open);
	}
}