
#include <fstream>
#include "pin.H"

#include <stdlib.h>

ADDRINT maxima,minima;
FILE *fptr;
// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;
// This function is called before every instruction is executed
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // Insert a call to docount before every instruction, no arguments are passed
	if(INS_Address(ins) >= minima && INS_Address(ins) <= maxima)
	{
		fprintf(fptr,"0x%x : %s",INS_Address(ins),INS_Disassemble(ins).c_str());
		fputc('\n',fptr);
	}
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
//KNOB KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
  //  "o", "inscount.out", "specify output file name");
// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
  fclose(fptr);
}
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
 //   cerr << "This tool counts the number of dynamic instructions executed" << endl;
  //  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t  -- ...    */
/* ===================================================================== */
int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    
	fptr = fopen("trace.log","wb+");
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    // Start the program, never returns

    PIN_StartProgram();
    return 0;

}