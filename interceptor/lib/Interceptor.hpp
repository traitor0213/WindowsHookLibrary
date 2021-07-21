#include "address.h"

#include <Windows.h>

#include "./DLLProc.c"
#include "./ProcessIO.c"

typedef struct _Interceptor_INFO
{
    HANDLE InterceptorFileHandle;
    ADDRESS InterceptorFileEntry;
    char FileName[32];

    LPVOID lpOpenFileMappingA;
    LPVOID lpMapViewOfFile;

}Interceptor_INFO;

DWORD WINAPI OpenInterceptor(LPVOID Param)
{
    Interceptor_INFO *InterceptorInfo = (Interceptor_INFO *)Param;

    InterceptorInfo->InterceptorFileHandle = ((HANDLE (WINAPI*)(DWORD, BOOL, LPCSTR))InterceptorInfo->lpOpenFileMappingA)(
        FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE, 
        FALSE, 
        InterceptorInfo->FileName);

    InterceptorInfo->InterceptorFileEntry = (ADDRESS)((LPVOID (WINAPI *)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))
        InterceptorInfo->lpMapViewOfFile)(
            InterceptorInfo->InterceptorFileHandle, 
            FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE, 
            0,
            0, 
            0);

    return 0;
}

volatile void __end__OpenInterceptor()
{
    int dummy = 0xCC;

    return;
}

typedef class _Interceptor
{
private:
    BYTE OriginalCode[32];
    
#ifdef _WIN64
    
BYTE JmpCode[12] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0
};
#else
BYTE JmpCode[7] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0
};
#endif

    // PID to String
    void HexToAscii(char *Buffer, int Int)
    {
        int j = 0;

        BYTE byte = 0;
        for(int i = sizeof(int) - 1; i >= 0; i -= 1)
        {
            byte = ((BYTE*)&Int)[i];

            BYTE HighBit = byte >> 4;
            BYTE LowBit = byte << 4;
            LowBit /= 0x10;

            if(HighBit >= 0 && HighBit <= 9)
                HighBit += '0';
            else 
                HighBit += '7';
            
            if(LowBit >= 0 && LowBit <= 9)
                LowBit += '0';
            else 
                LowBit += '7';

            Buffer[j++] = HighBit;
            Buffer[j++] = LowBit;
            Buffer[j] = 0;
        }
    }

    HANDLE hFile = NULL;
    LPVOID MappedAddress = NULL;
    char FileName[32];
    
    HANDLE InterceptorFileHandle;
    Interceptor_INFO *InterceptorInfo;
    
    void CloseInterceptor()
    {
        UnmapViewOfFile((LPVOID)InterceptorFileEntry);
        CloseHandle(InterceptorFileHandle);
    }

    ADDRESS lpOpenInterceptor = 0;
    ADDRESS HookProc = 0;
    
public:

    HANDLE ProcessHandle;
    ADDRESS CallBackProc = 0;
    ADDRESS InterceptorFileEntry = 0;

    _Interceptor(DWORD ProcessId, LPVOID HookAddress)
    {
        HookProc = (ADDRESS)HookAddress;
        ProcessHandle = OpenProcess(ProcessId);

        // write API prologue to buffer 
        memcpy(OriginalCode, HookAddress, sizeof(OriginalCode));

        IMAGE_DOS_HEADER *SelfDos = (IMAGE_DOS_HEADER *)GetModuleHandleA(NULL);
        IMAGE_NT_HEADERS *SelfNt = (IMAGE_NT_HEADERS *)((ADDRESS)SelfDos + SelfDos->e_lfanew); 
        DWORD SizeOfImage = SelfNt->OptionalHeader.SizeOfImage;

        for(;;)
        {
            memset(FileName, 0, sizeof(FileName));
            HexToAscii(FileName, ProcessId);

            hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, SizeOfImage, FileName);
            if(hFile != NULL)
            {
                break;
            }

            ProcessId -= 1;
        }

        MappedAddress = MapViewOfFile(hFile, FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if(MappedAddress != NULL)
        {
            memcpy(MappedAddress, SelfDos, SizeOfImage);
        }
    }

    LPVOID GetRemoteAddress(LPVOID LocalAddress)
    {
        ADDRESS RVA = (ADDRESS)LocalAddress - (ADDRESS)GetModuleHandleA(NULL);
        return (LPVOID)(RVA + InterceptorFileEntry);
    }

    BOOL ReadRemoteVariable(LPVOID LocalAddress, LPVOID Buffer, DWORD BufferSize)
    {
        return ReadProcessMemory(ProcessHandle, GetRemoteAddress(LocalAddress), Buffer, BufferSize);
    }

    BOOL WriteRemoteVariable(LPVOID LocalAddress, LPVOID Buffer, DWORD BufferSize)
    {
        return WriteProcessMemory(ProcessHandle, GetRemoteAddress(LocalAddress), Buffer, BufferSize);
    }

    void CallRemoteProc(LPVOID LocalProc, LPVOID Param)
    {
        WaitForSingleObject(
            CreateRemoteThread(
                ProcessHandle, 
                NULL, 
                0, 
                (LPTHREAD_START_ROUTINE)GetRemoteAddress(LocalProc), 
                Param, 
                0, 
                NULL), 
            INFINITE);
    }

    void HookInit(LPVOID ProcAddress)
    {   
        InterceptorInfo = (Interceptor_INFO *)VirtualAllocEx(
            ProcessHandle, 
            NULL, 
            sizeof(Interceptor_INFO), 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE);

        Interceptor_INFO InterceptorInfo2;
        InterceptorInfo2.lpMapViewOfFile = (LPVOID)GetDllProc((ADDRESS)GetModuleHandleA("kernel32"), "MapViewOfFile");
        InterceptorInfo2.lpOpenFileMappingA = (LPVOID)GetDllProc((ADDRESS)GetModuleHandleA("kernel32"), "OpenFileMappingA");

        WriteProcessMemory(ProcessHandle, InterceptorInfo, &InterceptorInfo2, sizeof(InterceptorInfo2));
        WriteProcessMemory(ProcessHandle, InterceptorInfo->FileName, FileName, sizeof(FileName)); 

        lpOpenInterceptor = (ADDRESS)VirtualAllocEx(
            ProcessHandle, 
            NULL, 
            (ADDRESS)__end__OpenInterceptor - (ADDRESS)OpenInterceptor, 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(
            ProcessHandle, 
            (LPVOID)lpOpenInterceptor, 
            OpenInterceptor, 
            (DWORD)((ADDRESS)__end__OpenInterceptor - (ADDRESS)OpenInterceptor));

        //printf("remote Interceptor entry: 0x%p\n", lpOpenInterceptor);
        //printf("intercept info entry: 0x%p\n", InterceptorInfo);

        HANDLE RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lpOpenInterceptor, InterceptorInfo, 0, NULL);
        //printf("remote thread handle: 0x%x\n", RemoteThreadHandle);

        WaitForSingleObject(RemoteThreadHandle, INFINITE);

        ReadProcessMemory(ProcessHandle, (LPVOID)InterceptorInfo, &InterceptorInfo2, sizeof(InterceptorInfo2));    

        //printf("virtual file entry: %p\n", InterceptorInfo2.InterceptorFileEntry);

        InterceptorFileEntry = InterceptorInfo2.InterceptorFileEntry;
        InterceptorFileHandle = InterceptorInfo2.InterceptorFileHandle;
    
        ADDRESS ProcRVA = (ADDRESS)ProcAddress - (ADDRESS)GetModuleHandleA(NULL);
        CallBackProc = InterceptorInfo2.InterceptorFileEntry + (ADDRESS)ProcRVA;
    }

    BOOL DoHook()
    {
        //jmp CallBackProc

        if(CallBackProc == 0) return FALSE;
        
        if(JmpCode[0] == 0x48)
        {
            // x8664

            memcpy(JmpCode + 2, &CallBackProc, sizeof(CallBackProc));
        }
        else 
        {
            // x86
            memcpy(JmpCode + 1, &CallBackProc, sizeof(CallBackProc));
        }
        
        return WriteProcessMemory(ProcessHandle, (LPVOID)HookProc, JmpCode, sizeof(JmpCode));
    }

    BOOL UndoHook()
    {
        return WriteProcessMemory(ProcessHandle, (LPVOID)HookProc, OriginalCode, sizeof(OriginalCode));
    }

    ~_Interceptor()
    {
        VirtualFreeEx(ProcessHandle, InterceptorInfo, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, (LPVOID)lpOpenInterceptor, 0, MEM_RELEASE);

        CloseInterceptor();
        UnmapViewOfFile(MappedAddress);
        CloseHandle(hFile);
        CloseHandle(ProcessHandle);
    }

}Interceptor;
