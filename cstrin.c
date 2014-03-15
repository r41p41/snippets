/*
background:
most of the strings statically allocated are kept in different section in PE file
a simple compiler hack

char str[]="hello world";
above will put string in a raw data section and load it with static address (which need to be relocated later if image base is adjusted)

to remove this hassle
char str[]= {'h','e','l','l','o',' ','w','o','r','l','d',0x00}; (in ansi)
char str[]= {'h',0x00,'e',0x00,'l',0x00,'l',0x00,'o',0x00,' ',0x00,'w',0x00,'o',0x00,'r',0x00,'l',0x00,'d',0x00,0x00}; (in utf)
above will put string on stack and put it there byte by byte (to put it there in dword format something else is required but more on that later.

below given program asks a user for normal string and spits out stack implementation.
this way no extra section is required and the string iwll be on stack, so no relocation will be required to address it.
though it consumes time, it can be used to get meaningful shellcodes.
*/
#include<stdio.h>
int main()
{
	char arr[1024];
	gets(arr);
	int i=0;
	printf("{");
	for(i=0;arr[i]!=0;i++)
	{
		printf("'%c',",arr[i]);
	}
	printf("0x00}");
	printf("\n\n\n\n");
	
	printf("{");
	for(i=0;arr[i]!=0;i++)
	{
		printf("'%c',0x00,",arr[i]);
	}
	printf("0x00,0x00}");
}
