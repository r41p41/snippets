#include<windows.h>
#include<stdio.h>
#include<commctrl.h>
DWORD x,y;
DWORD len,wid;
void RandomMouseMove();
void FindParent();
BOOL CALLBACK Parent_Callback(HWND window , LPARAM param);
BOOL CALLBACK Child_Callback(HWND childWindow , LPARAM param);
int winmaincrtstartup()
{
    HWND hwDesktop = GetDesktopWindow();
    RECT check;
    GetWindowRect(hwDesktop,&check);
    wid = check.bottom;
    len = check.right;
    CloseHandle(hwDesktop);
    while(1)
    {
        //RandomMouseMove();
        FindParent();
        Sleep(100);
    }
}
 
char keywords[][100]={
        "yes",
        "next",
        "ok",
        "install",
        "run",
        "enable",
        "don't send",
        "continue",
        "finish",
        "i accept",
        "later",
        "i &accept",
        "i &agree",
        "i agree",
        "activex",
        "allow",
        "close"
};
 
char blacklist[][100] = {
 
"o not accept",
"o not agree",
"ot accept",
"ot agree",
"on't accept",
"on't agree"
};
void ClickMouse(x,y)
{
	  INPUT buffer;
    buffer.type = INPUT_MOUSE;
    buffer.mi.dx = (x)* (0xFFFF / len);
	  buffer.mi.dy = (y)* (0xFFFF / wid);
    buffer.mi.mouseData = 0;
    buffer.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
    buffer.mi.time = 0;
    buffer.mi.dwExtraInfo = 0;
    SendInput(1, &buffer, sizeof(INPUT));
    buffer.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN;
    SendInput(1, &buffer, sizeof(INPUT));
    Sleep(10);
    buffer.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTUP;
    SendInput(1, &buffer, sizeof(INPUT));
}
void ConvertToLowerCase(LPSTR data)
{
    DWORD i = 0xFFFFFFFF;
    while(data[++i] != 0)
    {
        if(data[i] >= 0x41 && data[i] <= 0x5A)
            data[i] = data[i] + 0x20;
    }
}
typedef int (__stdcall *__strstr)(LPSTR addr,LPSTR str);
HWND save=0;
BOOL CALLBACK Child_Callback(HWND ChildWindow , LPARAM param)
{
    char data[1024];
    char lpButton[]="button";
    char lpWindowsForms[]="forms";
    char lpDropdown[]="";
    
    ConvertToLowerCase(lpButton);
    GetClassNameA(ChildWindow,data,1024);
    
    ConvertToLowerCase(data);
    __strstr strstr = (__strstr)GetProcAddress(GetModuleHandleA("ntdll.dll"),"strstr");
    
    if((strstr(data,lpButton) || strstr(data,lpWindowsForms) ) && IsWindowVisible(ChildWindow) && IsWindowEnabled(ChildWindow))
    {      
        GetWindowText(ChildWindow,data,1024);
        ConvertToLowerCase(data);
        
        int i=-1;
        while(keywords[++i][0]!= '\0')
        if(strstr(data,keywords[i]))
        {
            printf("Found %s\n",keywords[i]);
            SetActiveWindow(ChildWindow);
            SetForegroundWindow(ChildWindow);
            SendMessage(ChildWindow, BM_CLICK , 0 , 0);
						
						//RECT rect;
            //GetWindowRect(ChildWindow,&rect);
            //ClickMouse(rect.left+15,rect.top+15);
            break;
        }
    }
    return 1;
}
BOOL CALLBACK Parent_Callback(HWND Parent_Window , LPARAM param)
{
		EnumChildWindows(Parent_Window,(WNDENUMPROC)Child_Callback,param);
    return 1;
}
 
void FindParent()
{
    EnumWindows((WNDENUMPROC)Parent_Callback,0);
}
 
void RandomMouseMove()
{
    x = rand()%GetSystemMetrics(0);
    y = rand()%GetSystemMetrics(1);
    SetCursorPos(x,y);
}
