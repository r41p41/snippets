#include<stdio.h>
#include<stdint.h>
#include "disasm.h"
#include "/usr/local/opt/capstone/include/capstone/capstone.h"
int main()
{
	char *ptr;
	uint8_t buff[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\xeb\xfe\xeb\x70\xeb\xf0\xff\xff";
	uint8_t buff64[] = "\x48\x31\xc9\x48\xf7\xe1\x04\x3b\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05\xeb\xfe\xeb\x70\xeb\xf0\xff\xff";

	int i=0;
	uint64_t addr = 0x401000;
	while( (ptr=disassemble(&buff[i],CS_ARCH_X86,CS_MODE_64,1,addr))!=0 )
	{
		printf("0x%llx : %s\n",addr+i,ptr);
		free(ptr);
		i = i+GetInstLength(&buff[i],CS_ARCH_X86,CS_MODE_64);
	}
}
