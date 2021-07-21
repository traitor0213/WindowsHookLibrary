#include <stdio.h>
#include "../../lib/Interceptor.hpp"

#define SUSPEND_CONDITION1 1
#define SUSPEND_CONDITION2 2

#define RUNNING_CONDINTION1 0

typedef struct _FILE_READ_INFO {
    PVOID Buffer;
    ULONG Length;
}FILE_READ_INFO;

FILE_READ_INFO FileReadInfo;

int SuspendFlag = 0;
ADDRESS lpNtReadFile = 0;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (WINAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

typedef BOOL (WINAPI *tpNtReadFileW) (
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);

BOOL WINAPI _INT_NtReadFileW(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key)
{
    FileReadInfo.Buffer = Buffer;
    FileReadInfo.Length = Length;

    for (SuspendFlag = SUSPEND_CONDITION1;; Sleep(1))
    {
        if (SuspendFlag == RUNNING_CONDINTION1)
            break;
    }

    BOOL Return = ((tpNtReadFileW)lpNtReadFile)(FileHandle,
        Event,
        ApcRoutine,
        ApcContext, 
        IoStatusBlock,
        Buffer, 
        Length, 
        ByteOffset,
        Key);

    for (SuspendFlag = SUSPEND_CONDITION2;; Sleep(1))
    {
        if (SuspendFlag == RUNNING_CONDINTION1)
        {
            break;
        }    
    }

    return Return;
}

DWORD WINAPI GlobalHooker(DWORD Param)
{
    DWORD ProcessId = Param;

    printf("intercept to: %d\n", ProcessId);

    lpNtReadFile = (ADDRESS)GetProcAddress(GetModuleHandleA("ntdll"), "NtReadFile");

    Interceptor hooker = Interceptor(
        ProcessId,
        (LPVOID)lpNtReadFile);

    hooker.HookInit(_INT_NtReadFileW);
    BOOL ret = hooker.DoHook();

    hooker.WriteRemoteVariable(&lpNtReadFile, &lpNtReadFile, sizeof(lpNtReadFile));

    for (;;)
    {
        int f = 0;
        if (hooker.ReadRemoteVariable(&SuspendFlag, &f, sizeof(f)) == FALSE)
        {
            printf("error from get remote variable..\n");
            break;
        }

        if (f == SUSPEND_CONDITION1)
        {
            f = RUNNING_CONDINTION1;
            hooker.WriteRemoteVariable(&SuspendFlag, &f, sizeof(f));
            hooker.UndoHook();

            Sleep(1);
        }

        if (f == SUSPEND_CONDITION2)
        {
            FILE_READ_INFO LocalFileReadInfo;
            hooker.ReadRemoteVariable(&FileReadInfo, &LocalFileReadInfo, sizeof(LocalFileReadInfo));

            printf("NtReadFileW API is intercepted!\n");
            
            if(LocalFileReadInfo.Length != 0) {
                LPBYTE Buffer = (LPBYTE)malloc(LocalFileReadInfo.Length);
                
                BOOL f = ReadProcessMemory(hooker.ProcessHandle, LocalFileReadInfo.Buffer, Buffer, LocalFileReadInfo.Length);

                printf("%p\n", LocalFileReadInfo.Buffer);
                printf("%s\n", Buffer);
                
                free(Buffer);
            }

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
    if (argc == 1)
        return 0;

    GlobalHooker(atoi(argv[1]));

    return 0;
}