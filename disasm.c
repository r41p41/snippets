#include<stdint.h>
#include "/usr/local/opt/capstone/include/capstone/capstone.h"

typedef uint32_t Address;

// return ptr from disassemble function is supposed to be free'd at caller's end
char *disassemble(uint8_t *mem, int arch, int mode, int opcode_str, uint64_t addr)
{
	csh handle;
	cs_insn *ins;
	size_t count=0;
	uint32_t i=0;
	char *buff = malloc(0x200);
	char *opcode = malloc(0x100);
	if(buff != 0)
	{
		if(opcode != 0)
		{
			if (cs_open(arch, mode, &handle) == CS_ERR_OK)
			{
				count = cs_disasm(handle, mem, 0x200, addr, 0, &ins);
				if(count > 0)
				{
					if(opcode_str == 0)
					{
						sprintf(buff,"%s %s",ins->mnemonic,ins->op_str);
					}
					else
					{
						for(i=0; i<ins->size; i++)
						{
							sprintf(opcode,"%s %0.2x",opcode,ins->bytes[i]);
						}
						sprintf(buff,"%s -> %s %s",opcode,ins->mnemonic,ins->op_str);
					}
					cs_free(ins, count);
				}
				cs_close(&handle);
			}
			free(opcode);
		}
		if(count == 0)
		{
			free(buff);
			buff = 0;
		}
	}
	return buff;
}

signed int GetInstLength(uint8_t *mem, uint32_t arch, uint32_t mode)
{
	csh handle;
	cs_insn *ins;
	size_t count;
	uint32_t report=0;
	if (cs_open(arch, mode, &handle) != CS_ERR_OK)
		return 0;
	count = cs_disasm(handle, mem, 100, 0, 1, &ins);
	if(count > 0)
	{
		report = ins->size;
		cs_free(ins, count);
	}
	cs_close(&handle);
	return report;
}

uint32_t StackOperation(unsigned char *mem)
{
	csh handle;
	cs_insn *ins;
	cs_x86 *x86;
	size_t count;
	uint32_t i;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 0;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, mem, 100, 0, 1, &ins);
	if(count > 0)
	{
		x86 = &(ins->detail->x86);
		for(i = 0; i < x86->op_count; i++)
		{
			cs_x86_op *op = &(x86->operands[i]);
			switch((int)op->type)
			{
				case X86_OP_IMM:
					i = op->imm;
					cs_free(ins,count);
					cs_close(&handle);
					return i;
			}
		}
		cs_free(ins, count);
	}
	cs_close(&handle);
	return 0;
}

uint32_t ContainsOffset(unsigned char *mem)
{
	csh handle;
	cs_insn *ins;
	cs_x86 *x86;
	size_t count;
	uint32_t i;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 0;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, mem, 100, 0, 1, &ins);
	if(count > 0)
	{
		x86 = &(ins->detail->x86);
		for(i = 0; i < x86->op_count; i++)
		{
			cs_x86_op *op = &(x86->operands[i]);
			switch((int)op->type)
			{
				case X86_OP_IMM:
					i = op->imm;
					cs_free(ins,count);
					cs_close(&handle);
					return i;
			}
		}
		cs_free(ins, count);
	}
	cs_close(&handle);
	return 0;
}
