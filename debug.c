#include <stdio.h>
#include <windows.h>

void hooker()
{
    printf("This is payload!\n");
}

int main()
{
    const char *ModuleName = "kernel32.dll";
    const char *FunctionName = "SetCurrentDirectoryA";

    printf("[+] target=%s\n", FunctionName);

    HANDLE ModuleAddress = (HANDLE)GetModuleHandleA(ModuleName);
    if(ModuleAddress == NULL) 
    {
        printf("[!] %s faild; error=%d\n", "GetModuleHandleA", GetLastError());
    }
    LPVOID FunctionAddress = (LPVOID)GetProcAddress(ModuleAddress, FunctionName);

    BYTE JMP[5] = {0xE9, 0x00, };
    BYTE ApiEpilog[sizeof(JMP)] = { 0x00, };

    BYTE RET[5] = {0xE9, 0x00, };

    /*
    printf("hooker=%p\n", &hooker);
    printf("return=%p\n", &FunctionAddress);
    */
    
    //함수주소 - 현재명령주소 - 5(jmp instruction size)
    
    //create hook instruction
    DWORD* p = 0;
    DWORD r = 0;

    printf("instruction view!\n");
    printf("%x - %x - 5\n", (DWORD)hooker, (DWORD)FunctionAddress);

    r = (DWORD)hooker - (DWORD)FunctionAddress - (DWORD)5;
    memcpy(JMP + 1, &r, sizeof(LPVOID));

    //create return instruction
    r += (DWORD)5;
    memcpy(RET + 1, &r, sizeof(LPVOID));

    printf("====================\n");
    //=========================
    //debug
    for(int i = 0; i <= sizeof(LPVOID); ++i) printf("%02X ", JMP[i]);
    printf("\n");
    for(int i = 0; i <= sizeof(LPVOID); ++i) printf("%02X ", RET[i]);
    printf("\n");
    //=========================
    printf("====================\n");


    //create hook
    DWORD Protected = 0;
    if(VirtualProtect((LPVOID)FunctionAddress, 5, PAGE_EXECUTE_READWRITE, &Protected) == FALSE) 
    {
        printf("[!] %s faild, error=%d\n", "VirtualProtect", GetLastError());
    }

    memcpy(ApiEpilog, FunctionAddress, sizeof(FunctionAddress));
    printf("[+] create hook..\n");
    memcpy(FunctionAddress, JMP, sizeof(JMP));
    printf("[+] done!\n");
    
    if(VirtualProtect((LPVOID)FunctionAddress, 5, Protected, &Protected) == FALSE)
    {
        printf("[!] %s faild; error=%d\n", "VirtualProtect", GetLastError());
    }

    printf("API epilogue..\n");
    for(int i = 0; i != sizeof(JMP); i += 1) printf("%02X ", ApiEpilog[i]);
    printf("\n");

    SetCurrentDirectoryA("/");

    getchar();

    return 0;
}