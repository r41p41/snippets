BOOL SetDebugPriv(BOOL bEnablePriv, LPCSTR Priv)
{
    HANDLE hToken;
    LUID PrivLUID;
    TOKEN_PRIVILEGES tkprivs;
    ZeroMemory(&tkprivs, sizeof(tkprivs));

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if(LookupPrivilegeValue(NULL, Priv, &PrivLUID))
        {
            tkprivs.PrivilegeCount = 1;
            tkprivs.Privileges[0].Luid = PrivLUID;
            if(bEnablePriv)
            tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
            tkprivs.Privileges[0].Attributes = 0;
            if(AdjustTokenPrivileges(hToken, false, &tkprivs, sizeof(tkprivs), NULL, NULL))
            {
                CloseHandle(hToken);
                return true;
            }
        }
    }
    CloseHandle(hToken);
    return false;
}

//priv == SE_PRIVILEGE_ENABLED for debug enabled
//priv == 0 for debug disabled

BOOL EnableDebugPrivileges(DWORD priv) 
{
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = priv;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
            AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) {
                ret = TRUE;
        }

        CloseHandle(token);
    }

    return ret;
}
