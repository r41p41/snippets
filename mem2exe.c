#include<windows.h>
#include<Stdio.h>
int winmaincrtstartup()
{
	DWORD i =0;
	
	FILE *fp = fopen("dump.bin","rb");
	fseek(fp,0,SEEK_END);
	DWORD len = ftell(fp);
	LPVOID arr = VirtualAlloc(0,len,0x3000,0x4);
	fseek(fp,0,SEEK_SET);
	fread(arr,len,1,fp);
	fclose(fp);
	
	fp = fopen("dumped.exe","wb+");
	
	PIMAGE_DOS_HEADER dos = arr;

	printf("PE Header offset = %x\n",dos->e_lfanew);
	
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPVOID)arr + dos->e_lfanew);
	
	//Not necessary
	nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	
	fwrite(arr,nt->OptionalHeader.SizeOfHeaders,1,fp);
	
	printf("no of sections : %d",nt->FileHeader.NumberOfSections);

	PIMAGE_SECTION_HEADER sec;
	sec = ((LPVOID)nt + sizeof(IMAGE_NT_HEADERS));

	for(i=0;i<nt->FileHeader.NumberOfSections;i++)
	{
		printf("\nSection : %d\n",i+1);
		printf("Name : %s\n",sec->Name);
		printf("RVA : %x\n",sec->VirtualAddress);
		printf("RVASize : %x\n",sec->Misc.VirtualSize);
		printf("Raw : %x\n",sec->PointerToRawData);
		printf("RawSize : %x\n",sec->SizeOfRawData);
		
		fwrite(((LPVOID)arr+sec->VirtualAddress),sec->SizeOfRawData,1,fp);
		
		printf("Section %d written",i+1);
		sec = ((LPVOID)sec + sizeof(IMAGE_SECTION_HEADER));	
	}
	
	fclose(fp);
}
