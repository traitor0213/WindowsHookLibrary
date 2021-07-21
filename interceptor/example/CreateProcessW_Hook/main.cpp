#include <stdio.h>
#include "../lib/Interceptor.hpp"

#define SUSPEND_CONDITION1 1
#define SUSPEND_CONDITION2 2

#define RUNNING_CONDINTION1 0

int SuspendFlag = 0;

PROCESS_INFORMATION CreateProcessInfo;

typedef BOOL (WINAPI *tpCreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

ADDRESS lpCreateProcessW = 0;

BOOL WINAPI _INT_CreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    for(SuspendFlag = SUSPEND_CONDITION1;; Sleep(1))
    {
        if(SuspendFlag == RUNNING_CONDINTION1) break;
    }    

    BOOL Return = ((tpCreateProcessW)lpCreateProcessW)(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        CREATE_SUSPENDED,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
    
    CreateProcessInfo = *lpProcessInformation;

    for(SuspendFlag = SUSPEND_CONDITION2;; Sleep(1))
    {
        if(SuspendFlag == RUNNING_CONDINTION1) break;
    }

    if(dwCreationFlags != CREATE_SUSPENDED)
    {
        ResumeThread(lpProcessInformation->hThread);
    }

    return Return;
}

DWORD WINAPI GlobalHooker(DWORD Param)
{
    DWORD ProcessId = Param;

    printf("intercept to: %d\n", ProcessId);

    lpCreateProcessW = (ADDRESS)GetProcAddress(GetModuleHandleA("kernel32"), "CreateProcessW"); 

    Interceptor hooker = Interceptor(
        ProcessId, 
        (LPVOID)lpCreateProcessW);

    hooker.HookInit(_INT_CreateProcessW);
    BOOL ret = hooker.DoHook();

    hooker.WriteRemoteVariable(&lpCreateProcessW, &lpCreateProcessW, sizeof(lpCreateProcessW));

    for(;;)
    {
        int f = 0;
        if(hooker.ReadRemoteVariable(&SuspendFlag, &f, sizeof(f)) == FALSE)
        {
            printf("error from get remote variable..\n");
            break;
        }

        if(f == SUSPEND_CONDITION1)
        {
            f = RUNNING_CONDINTION1;
            hooker.WriteRemoteVariable(&SuspendFlag, &f, sizeof(f));
            hooker.UndoHook();

            Sleep(1);
        }

        if(f == SUSPEND_CONDITION2)
        {
            hooker.ReadRemoteVariable(&CreateProcessInfo, &CreateProcessInfo, sizeof(CreateProcessInfo));

            printf("CreateProcessW API is intercepted!\n");
            printf("Process ID: %d\n", CreateProcessInfo.dwProcessId);

            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GlobalHooker, (LPVOID)CreateProcessInfo.dwProcessId, 0, NULL);

            f = RUNNING_CONDINTION1;
            hooker.WriteRemoteVariable(&SuspendFlag, &f, sizeof(f));
            hooker.DoHook();

            Sleep(1);
        }

        Sleep(1);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if(argc == 1) return 0;

    GlobalHooker(atoi(argv[1]));

    return 0;
}