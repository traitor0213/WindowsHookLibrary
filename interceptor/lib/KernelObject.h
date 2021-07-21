#include "address.h"
#include "DLLProc.c"
#include <windows.h>

typedef long NTSTATUS;

NTSTATUS CreateSystemProcessList()
{
    typedef NTSTATUS (WINAPI *tpNtQuerySystemInformation)(
        int       SystemInformationClass,
        PVOID     SystemInformation,
        ULONG     SystemInformationLength,
        PULONG    ReturnLength);

    tpNtQuerySystemInformation lpNtQuerySystemInformation = NULL;
    lpNtQuerySystemInformation = GetDllProc(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");

    ULONG SystemInfoLength = 0;
    ULONG ReturnLength = 0; 

    lpNtQuerySystemInformation(5, NULL, 0, &SystemInfoLength);
    
    LPBYTE SystemInformation = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, SystemInfoLength);
    
    return lpNtQuerySystemInformation(5, SystemInformation, SystemInfoLength, &ReturnLength);
}

void FreeSystemProcessInformation(PVOID SystemInformation)
{
    HeapFree(GetProcessHeap(), 0, SystemInformation);
}