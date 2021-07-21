ADDRESS GetDllProc(ADDRESS Module, const char *ProcName)
{
    int ProcNameLength = 0;
    for(;ProcName[ProcNameLength] != 0; ProcNameLength += 1);

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)Module;
    IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(Module + DosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY *ExportDir = (IMAGE_EXPORT_DIRECTORY *)
        (Module + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    const int *ProcNameList = (const int *)(Module + ExportDir->AddressOfNames);

    for(DWORD NameIndex = 0;; NameIndex += 1)
    {
        if(NameIndex >= ExportDir->NumberOfNames) 
            break;

        int SearchedProcNameLength = 0;
        for(;((const char *)(Module + ProcNameList[NameIndex]))[SearchedProcNameLength] != 0; 
            SearchedProcNameLength += 1);

        if(ProcNameLength == SearchedProcNameLength)
        {
            int StringCompareIndex = 0;
            for(; StringCompareIndex != SearchedProcNameLength; StringCompareIndex += 1)
                if(((const char *)(Module + ProcNameList[NameIndex]))[StringCompareIndex] != ProcName[StringCompareIndex])
                    break;
            
            if(StringCompareIndex == SearchedProcNameLength)
            {
                WORD *OrdinalList = (WORD*)(Module + ExportDir->AddressOfNameOrdinals);
                int *ProcList = (int*)(Module + ExportDir->AddressOfFunctions);

                return (ADDRESS)(Module + ProcList[OrdinalList[NameIndex]]);
            }
        }
    }

    return 0;
}
