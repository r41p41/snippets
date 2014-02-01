/*
find and remove non existential reg entries from startup
along with malwares which are readonly & hidden
entries of file rootkits will be removed, so before hand 
killing the persistance is recommended
*/

void remove_reg() //incomplete
{
	int i=0;
	ptr=(char *)malloc(1024);
	HKEY key1,key2,key3;
	char blank[1024];
	char name1[100],name2[100],name3[100];
	char val1[100],val2[100],val3[100];
	DWORD size1=100,size2=100,size3=100;
	DWORD size11=100,size12=100,size13=100;
	long ret1=0,ret2=0,ret3=0;
	WIN32_FIND_DATA win;
	FARPROC _RegDeleteKeyValueA=(FARPROC)GetProcAddress(GetModuleHandle("advapi32.dll"),"RegDeleteKeyValueA");
	while(ret1==0 || ret2==0 || ret3==0)
	{
		size1=size2=size3=size11=size12=size13=100;
		if(flag == 0xea)
		{
			ret1 = RegOpenKeyExA(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &key1);
			ret2 = RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &key2);
			ret3 = RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_ALL_ACCESS, &key3);
		}
		else
		{
			ret1 = RegOpenKeyExA(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &key1);
			ret2 = RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &key2);
			ret3 = RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_ALL_ACCESS, &key3);
		}
			if(ret1==ERROR_SUCCESS)
			{
				ret1 = RegEnumValue(key1,i,&name1,&size1,NULL,NULL,&val1,&size11);
				size1=1024;
				ret1 = RegEnumValue(key1,i,&name1,&size1,NULL,NULL,NULL,NULL);
			}
			if(ret2==ERROR_SUCCESS)
			{
				ret2 = RegEnumValue(key2,i,&name2,&size2,NULL,NULL,&val2,&size12);	
				size2=1024;
				ret2 = RegEnumValue(key2,i,name2,&size2,NULL,NULL,NULL,NULL);	
			}
			if(ret3==ERROR_SUCCESS)
			{
				ret3 = RegEnumValue(key3,i,&name3,&size3,NULL,NULL,&val3,&size13);
				size3=1024;
				ret3 = RegEnumValue(key3,i,&name3,&size3,NULL,NULL,NULL,NULL);
			}
			if(ret1!=ERROR_NO_MORE_ITEMS&&size1<100&&size11<100)
			{
				strcpy(ptr,name1);
				ExpandEnvironmentStrings(val1,name1,100);
				if(GetFileAttributes(name1)==INVALID_FILE_ATTRIBUTES||GetFileAttributes(name1)==FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY)
				{
					puts(ptr);
					if(_RegDeleteKeyValueA)
					_RegDeleteKeyValueA(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",ptr);
					else
					RegDeleteValueA(key1,ptr);
				}
			}
			if(ret2!=ERROR_NO_MORE_ITEMS&&size2<100&&size12<100)
			{
				strcpy(ptr,name2);
				ExpandEnvironmentStrings(val2,name2,100);
				if(GetFileAttributes(name2)==INVALID_FILE_ATTRIBUTES||GetFileAttributes(name2)==FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY)
				{
					puts(ptr);
					if(_RegDeleteKeyValueA)
					_RegDeleteKeyValueA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",ptr);
					else
					RegDeleteValueA(key2,ptr);
				}
			}
			if(ret3!=ERROR_NO_MORE_ITEMS&&size3<100&&size13<100)
		 	{
		 		strcpy(ptr,name3);
		 		ExpandEnvironmentStrings(val3,name3,100);
		 		if(GetFileAttributes(name3)==INVALID_FILE_ATTRIBUTES||GetFileAttributes(name3)==FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY)
		 		{	
					puts(ptr);
					if(_RegDeleteKeyValueA)
		 			_RegDeleteKeyValueA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",ptr);
		 			else
		 			RegDeleteValueA(key3,ptr);
		 		}
		 	}
		i++;
	}
	printf("returned");
}