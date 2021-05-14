#include "pch.h"


bool Hook(void * dst, void * func, int len)
{
    if (len < 5) // jmp instruction requires 5 bytes
    {
        return false;
    }

    DWORD currProtect; // Store current protection level for memory region
    VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &currProtect); // Change permisson to read/write

    memset(dst, 0x90, len); // Nop instructions where our jmp is

    DWORD relativeaddr = ((DWORD)func - (DWORD)dst) - 5; // Offset from our jmp to our function.

    *(BYTE*)dst = 0xE9; // Set first byte to jmp opcode
    *(DWORD*)((DWORD)dst + 1) = relativeaddr; // Set the 4 remaining bytes to jmp location

    DWORD tempProtect;
    VirtualProtect(dst, len, currProtect, &tempProtect); // Revert permission to old (currProtect).

    return true;
}

DWORD jmpBackAddr;
void __declspec(naked) func()
{
    __asm 
    {
        add [ebx+04], edi
        mov eax, edi
        jmp [jmpBackAddr]
    }
}

DWORD WINAPI MainThread(HMODULE hModule)
{
    int hookLength = 5;
    DWORD hookAddr = 0x429D1F;
    jmpBackAddr = hookAddr + hookLength;

    Hook((void*)hookAddr, func, hookLength);

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            break;
        }
        Sleep(50);
    }
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH: 
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

