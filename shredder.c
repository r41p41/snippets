/*
Routine for carefully shredding a file
drill:
[*] open a file
[*] overwrite with NULL bytes
[*] repeat above process 7 times (more for your paranoia)
[*] NULLify it
[*] remove it if you want, its useless at this point
*/
BOOL Shredder(LPWSTR path)
{
	DWORD count=0,temp=0,attrib,dwBuf;
	HANDLE hFile;
	DWORD hOrder,lOrder;
	unsigned char buffer[]= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	while(count<=7)
	{
		attrib = GetFileAttributesW(path);
		SetFileAttributesW(path,FILE_ATTRIBUTE_NORMAL);
		hFile = CreateFileW(path,GENERIC_ALL,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,NULL);
		if(GetLastError() == 0xc0000005)	//error access denied
		{
			//dbg_print("file cannot be opened\neither its read only \nor protected by security permissions \nor a rootkit");
			//dbg_print("\nor its opened in some process \nor simply does not exist");
			return 0;
		}
		lOrder=GetFileSize(hFile,&hOrder);
		printf("lOrder = %x\nhOrder = %x",lOrder,hOrder);
		if(hOrder==0)			//if file size < 4Gb
		{
			while(temp<lOrder)
			{
				WriteFile(hFile,buffer,32,&dwBuf,0);
				temp=temp+32;
				if(temp%0x20000==0)	//after every 100mb sleep for 100ms
				Sleep(100);
			}
		}
		else
		{
			DWORD newf=0;
			while(newf<hOrder)
			{
				while(temp<lOrder)
				{
					WriteFile(hFile,buffer,32,&dwBuf,0);
					temp=temp+32;
					if(temp%0x20000==0)	//after every 100mb sleep for 100ms
					Sleep(100);
				}
				temp=0;
				newf++;
			}
		}	
		CloseHandle(hFile);
		SetFileAttributesW(path,attrib);
		count++;
	}
	CloseHandle(CreateFileW(path,GENERIC_ALL,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL));
}
