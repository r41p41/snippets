
#include <fstream>
#include "pin.H"

#include <stdlib.h>

ADDRINT maxima,minima;
FILE *fptr;
static UINT64 icount = 0;
VOID Instruction(INS ins, VOID *v)
{
	IMG img = IMG_FindByAddress(INS_Address(ins));
	if((IMG_Id(img) == 1) || !IMG_Valid(img))
	{
		fprintf(fptr,"0x%x : %s",INS_Address(ins),INS_Disassemble(ins).c_str());
		fputc('\n',fptr);
	}
}
BOOL ChildProcess(CHILD_PROCESS chpd,void *v)
{
	fprintf(fptr,"new process created -> %d\n",chpd->GetId());
	return 1;
}
VOID ImageLoad(IMG img, VOID *v)
{
	if(IMG_Id(img) == 1)
	{
		maxima = IMG_HighAddress(img);
		minima = IMG_LowAddress(img);
		fprintf(fptr,"maxima = 0x%x\nminima = 0x%x\n",maxima,minima);
	}
}
VOID Fini(INT32 code, VOID *v)
{
  fclose(fptr);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    return -1;
}
int main(int argc, char * argv[])
{
	if (PIN_Init(argc, argv)) 
		return Usage();
	
	fptr = fopen("trace.log","wb+");
	INS_AddInstrumentFunction(Instruction, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
	PIN_AddFollowChildProcessFunction(ChildProcess,0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
