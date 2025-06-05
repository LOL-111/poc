#include <windows.h>
#include <iostream>
#include <psapi.h> // For GetModuleInformation

// Define the original MessageBoxA function signature
typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = nullptr;

// Hook function to intercept MessageBoxA calls
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Create a copy of the custom message
    char* newText = _strdup("Hooked! This is a custom message.");
    // Call the original MessageBoxA with the modified text
    int result = OriginalMessageBoxA(hWnd, newText, lpCaption, uType);
    free(newText);
    return result;
}

class IATHook {
private:
    HMODULE hModule = nullptr; // Handle to the module (our process's executable)
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr; // Import descriptor table
    LPCSTR targetDllName = nullptr; // Name of the DLL to hook (e.g., "user32.dll")
    LPCSTR targetFunctionName = nullptr; // Name of the function to hook (e.g., "MessageBoxA")
    FARPROC newFunction = nullptr; // Address of the hook function
    FARPROC* originalFunctionPtr = nullptr; // Pointer to the original function address in the IAT

public:
    IATHook(LPCSTR dllName, LPCSTR functionName, FARPROC hookFunction) 
        : targetDllName(dllName), targetFunctionName(functionName), newFunction(hookFunction) {}

    ~IATHook() {
        Unhook();
    }

    bool Hook() {
        // Step 1: Get the base address of the current module (our executable)
        hModule = GetModuleHandle(nullptr);
        if (!hModule) {
            std::cerr << "Failed to get module handle: " << GetLastError() << std::endl;
            return false;
        }

        // Step 2: Get the DOS header of the module
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS header signature" << std::endl;
            return false;
        }

        // Step 3: Get the NT header
        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid NT header signature" << std::endl;
            return false;
        }

        // Step 4: Get the import directory from the data directory
        PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImportDir->VirtualAddress == 0) {
            std::cerr << "No import table found" << std::endl;
            return false;
        }

        // Step 5: Get the import descriptor table
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pImportDir->VirtualAddress);

        // Step 6: Iterate through the import descriptors to find the target DLL
        for (; pImportDesc->Name; pImportDesc++) {
            LPCSTR dllName = (LPCSTR)((BYTE*)hModule + pImportDesc->Name);
            if (_stricmp(dllName, targetDllName) == 0) {
                break; // Found the target DLL
            }
        }

        if (!pImportDesc->Name) {
            std::cerr << "Target DLL (" << targetDllName << ") not found in import table" << std::endl;
            return false;
        }

        // Step 7: Get the Import Name Table (INT) and Import Address Table (IAT)
        PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);

        if (!pINT || !pIAT) {
            std::cerr << "Invalid INT or IAT" << std::endl;
            return false;
        }

        // Step 8: Iterate through the IAT to find the target function
        while (pINT->u1.AddressOfData) {
            if (!(pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) { // Not imported by ordinal
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pINT->u1.AddressOfData);
                if (strcmp(pImport->Name, targetFunctionName) == 0) {
                    // Found the target function
                    originalFunctionPtr = (FARPROC*)&pIAT->u1.Function;
                    OriginalMessageBoxA = (MessageBoxA_t)*originalFunctionPtr; // Save the original function address
                    break;
                }
            }
            pINT++;
            pIAT++;
        }

        if (!originalFunctionPtr) {
            std::cerr << "Target function (" << targetFunctionName << ") not found in IAT" << std::endl;
            return false;
        }

        // Step 9: Modify the IAT entry to point to our hook function
        DWORD oldProtect;
        if (!VirtualProtect(originalFunctionPtr, sizeof(FARPROC), PAGE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
            return false;
        }

        *originalFunctionPtr = newFunction;

        if (!VirtualProtect(originalFunctionPtr, sizeof(FARPROC), oldProtect, &oldProtect)) {
            std::cerr << "Failed to restore memory protection: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }

    bool Unhook() {
        if (!originalFunctionPtr || !OriginalMessageBoxA) {
            return false;
        }

        // Restore the original IAT entry
        DWORD oldProtect;
        if (!VirtualProtect(originalFunctionPtr, sizeof(FARPROC), PAGE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection: " << GetLastError() << std::endl;
            return false;
        }

        *originalFunctionPtr = (FARPROC)OriginalMessageBoxA;

        if (!VirtualProtect(originalFunctionPtr, sizeof(FARPROC), oldProtect, &oldProtect)) {
            std::cerr << "Failed to restore memory protection: " << GetLastError() << std::endl;
            return false;
        }

        originalFunctionPtr = nullptr;
        OriginalMessageBoxA = nullptr;
        return true;
    }
};

int main() {
    // Test MessageBoxA before hooking
    MessageBoxA(nullptr, "Original message", "Test", MB_OK);
    std::cout << "Original MessageBoxA called.\n";

    // Create IAT hook for MessageBoxA
    IATHook hook("user32.dll", "MessageBoxA", (FARPROC)HookedMessageBoxA);
    if (hook.Hook()) {
        std::cout << "Hook installed successfully.\n";
    } else {
        std::cerr << "Failed to install hook.\n";
        return 1;
    }

    // Test MessageBoxA after hooking
    MessageBoxA(nullptr, "This should be hooked", "Test", MB_OK);
    std::cout << "Hooked MessageBoxA called.\n";

    // Remove the hook
    if (hook.Unhook()) {
        std::cout << "Hook removed successfully.\n";
    } else {
        std::cerr << "Failed to remove hook.\n";
        return 1;
    }

    // Test MessageBoxA after unhooking
    MessageBoxA(nullptr, "Original message again", "Test", MB_OK);
    std::cout << "Original MessageBoxA called after unhooking.\n";

    return 0;
}
