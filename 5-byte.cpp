#include <windows.h>
#include <iostream>

class MessageBoxHook {
private:
    HMODULE hModule = nullptr;
    FARPROC targetAddress = nullptr;
    BYTE* originalBytes = nullptr;
    BYTE* trampoline = nullptr;
    CRITICAL_SECTION cs;
    static const size_t patchSize = 16; // Larger patch size to avoid splitting instructions
    static constexpr BYTE jmpPatchTemplate[16] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}; // JMP + NOPs

    using MessageBoxA_t = int (WINAPI *)(HWND, LPCSTR, LPCSTR, UINT);
    static MessageBoxA_t OriginalMessageBoxA;

public:
    MessageBoxHook() {
        InitializeCriticalSection(&cs);
        originalBytes = new BYTE[patchSize];
        ZeroMemory(originalBytes, patchSize);
    }

    ~MessageBoxHook() {
        RemoveHook();
        if (hModule) FreeLibrary(hModule);
        if (originalBytes) delete[] originalBytes;
        if (trampoline) VirtualFree(trampoline, 0, MEM_RELEASE);
        DeleteCriticalSection(&cs);
    }

    bool SetHook() {
        EnterCriticalSection(&cs);

        // Load user32.dll
        hModule = GetModuleHandleA("user32.dll");
        if (!hModule) hModule = LoadLibraryA("user32.dll");
        if (!hModule) {
            std::cerr << "Failed to load user32.dll: " << GetLastError() << std::endl;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Get MessageBoxA address
        targetAddress = GetProcAddress(hModule, "MessageBoxA");
        if (!targetAddress) {
            std::cerr << "Failed to find MessageBoxA: " << GetLastError() << std::endl;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Save original bytes
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)targetAddress, originalBytes, patchSize, nullptr)) {
            std::cerr << "Failed to read original bytes: " << GetLastError() << std::endl;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Allocate executable trampoline
        trampoline = (BYTE*)VirtualAlloc(nullptr, patchSize + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline) {
            std::cerr << "Failed to allocate trampoline: " << GetLastError() << std::endl;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Build trampoline: original bytes + JMP back
        memcpy(trampoline, originalBytes, patchSize);
        trampoline[patchSize] = 0xE9; // JMP
        ptrdiff_t offset = (BYTE*)targetAddress + patchSize - (trampoline + patchSize + 5);
        memcpy(trampoline + patchSize + 1, &offset, 4);
        OriginalMessageBoxA = (MessageBoxA_t)trampoline;

        // Create JMP patch
        BYTE* jmpPatch = new BYTE[patchSize];
        memcpy(jmpPatch, jmpPatchTemplate, patchSize);
        offset = (BYTE*)HookedMessageBoxA - (BYTE*)targetAddress - 5;
        memcpy(jmpPatch + 1, &offset, 4);

        // Change memory protection
        DWORD oldProtect;
        if (!VirtualProtect((LPVOID)targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
            delete[] jmpPatch;
            VirtualFree(trampoline, 0, MEM_RELEASE);
            trampoline = nullptr;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Write JMP patch
        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)targetAddress, jmpPatch, patchSize, nullptr)) {
            std::cerr << "Failed to write JMP patch: " << GetLastError() << std::endl;
            VirtualProtect((LPVOID)targetAddress, patchSize, oldProtect, &oldProtect);
            delete[] jmpPatch;
            VirtualFree(trampoline, 0, MEM_RELEASE);
            trampoline = nullptr;
            LeaveCriticalSection(&cs);
            return false;
        }

        // Restore memory protection and flush instruction cache
        VirtualProtect((LPVOID)targetAddress, patchSize, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)targetAddress, patchSize);
        delete[] jmpPatch;
        LeaveCriticalSection(&cs);
        return true;
    }

    static int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
        char* newText = _strdup("Hooked! This is a custom message.");
        int result = OriginalMessageBoxA(hWnd, newText, lpCaption, uType);
        free(newText);
        return result;
    }

    bool RemoveHook() {
        EnterCriticalSection(&cs);
        if (!targetAddress || !originalBytes) {
            LeaveCriticalSection(&cs);
            return false;
        }

        DWORD oldProtect;
        if (!VirtualProtect((LPVOID)targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
            LeaveCriticalSection(&cs);
            return false;
        }

        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)targetAddress, originalBytes, patchSize, nullptr)) {
            std::cerr << "Failed to restore original bytes: " << GetLastError() << std::endl;
            VirtualProtect((LPVOID)targetAddress, patchSize, oldProtect, &oldProtect);
            LeaveCriticalSection(&cs);
            return false;
        }

        // Restore memory protection and flush instruction cache
        VirtualProtect((LPVOID)targetAddress, patchSize, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)targetAddress, patchSize);
        LeaveCriticalSection(&cs);
        return true;
    }
};

MessageBoxHook::MessageBoxA_t MessageBoxHook::OriginalMessageBoxA = nullptr;

int main() {
    MessageBoxHook hook;
    MessageBoxA(nullptr, "Original message", "Test", MB_OK);
    std::cout << "Original MessageBoxA called.\n";

    if (hook.SetHook()) {
        std::cout << "Hook installed successfully.\n";
    } else {
        std::cerr << "Failed to install hook.\n";
        return 1;
    }

    MessageBoxA(nullptr, "This should be hooked", "Test", MB_OK);
    std::cout << "Hooked MessageBoxA called.\n";

    if (hook.RemoveHook()) {
        std::cout << "Hook removed successfully.\n";
    } else {
        std::cerr << "Failed to remove hook.\n";
        return 1;
    }

    MessageBoxA(nullptr, "Original message again", "Test", MB_OK);
    std::cout << "Original MessageBoxA called after unhooking.\n";

    return 0;
}
