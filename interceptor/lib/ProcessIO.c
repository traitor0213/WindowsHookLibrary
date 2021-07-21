HANDLE OpenProcess(DWORD ProcessId)
{
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
}

BOOL WriteProcessMemory(HANDLE ProcessHandle, LPVOID WriteAddress, LPVOID WriteBuffer, DWORD WriteSize)
{
    DWORD OldProtection = 0;
    DWORD NewProtection = 0;
    
    if(VirtualProtectEx(ProcessHandle, WriteAddress, WriteSize, PAGE_EXECUTE_READWRITE, &OldProtection) != FALSE)
    {
        if(WriteProcessMemory(ProcessHandle, WriteAddress, WriteBuffer, WriteSize, NULL) == FALSE)
        {
            return FALSE;
        }

        if(VirtualProtectEx(ProcessHandle, WriteAddress, WriteSize, OldProtection, &NewProtection) == FALSE)
        {
            return FALSE;
        }
        else 
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL ReadProcessMemory(HANDLE ProcessHandle, LPVOID ReadAddress, LPVOID ReadBuffer, DWORD ReadSize)
{
    return ReadProcessMemory(ProcessHandle, ReadAddress, ReadBuffer, ReadSize, NULL);
}