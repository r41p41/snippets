/*
used for printing out an executable file
in form of hex C style representation
*/

#include<stdio.h>
#include<windows.h>
#include<conio.h>
LPBYTE RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)
{
	int a, b = 0, s[256];
	BYTE swap;
	DWORD dwCount;
	for(a = 0; a < 256; a++)
	{
		s[a] = a;
	}
	for(a = 0; a < 256; a++)
	{
		b = (b + s[a] + lpKey[a % dwKeyLen]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
	}
	for(dwCount = 0; dwCount < dwBufLen; dwCount++)
	{
		a = (a + 1) % 256;
		b = (b + s[a]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
		lpBuf[dwCount] ^= s[(s[a] + s[b]) % 256];
	}
	return lpBuf;
}
int main(void)
{
 	LPBYTE data;
 	DWORD len;
	char name[1024];
	gets(name);
	
 	FILE *fptr;
 	fptr=fopen(name,"rb");
 	fseek(fptr,0,SEEK_END);
 	len=ftell(fptr);
 	
 	data=(BYTE*)malloc(len);
 	
 	fseek(fptr,0,SEEK_SET);
 	fread(data,len,1,fptr);
 	fclose(fptr);
 	
 	
 	//if encoded via RC4
 	//RC4(data,(BYTE*)"key",len,sizeof("key"));
 	
 	
 	
 	long int i=0;
	int counter=0;
 	FILE *newfp;
	newfp=fopen("array.cpp","w+");
 	fprintf(newfp,"BYTE arr[]=\"");
 	for(i=0;i<=len;i++)
	 {
	 fprintf(newfp,"\\x%02x",data[i]);
	 }
	 fprintf(newfp,"\";");
 	fclose(newfp);
 	
 	free(data);
} 
