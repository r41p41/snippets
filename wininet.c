/*
Example for using wininet api
*/


#include<windows.h>
#include<wininet.h>
int main()
{
	HINTERNET session=InternetOpen("uniquesession",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
	HINTERNET http=InternetConnect(session,"localhost",80,0,0,INTERNET_SERVICE_HTTP,0,0);
	HINTERNET hHttpRequest = HttpOpenRequest(http,"POST","p.php",0,0,0,INTERNET_FLAG_RELOAD,0);
    char szHeaders[] = "Content-Type: application/x-www-form-urlencoded; charset=UTF-8";
    char szReq[1024]="cmd=winfuckinginet";
    HttpSendRequest(hHttpRequest, szHeaders, strlen(szHeaders), szReq, strlen(szReq));
    char szBuffer[1025];
    DWORD dwRead=0;
    while(InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer)-1, &dwRead) && dwRead) {
      szBuffer[dwRead] = '\0';
      MessageBox(0,szBuffer,0,0);
}
    InternetCloseHandle(hHttpRequest);
    InternetCloseHandle(session);
    InternetCloseHandle(http);
}
