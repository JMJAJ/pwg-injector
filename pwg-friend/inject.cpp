#include "inject.hpp"
// Add any necessary includes here

void* InjectDll(void* process, std::wstring dllPath) {
    const auto dllAddr = VirtualAllocEx(process, nullptr, dllPath.size() * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);

    if (!dllAddr) {
        std::cout << "Failed to allocate memory for DLL path" << std::endl;
        return 0;
    }

    if (!WriteProcessMemory(process, dllAddr, dllPath.c_str(), dllPath.size() * sizeof(wchar_t), nullptr)) {
        std::cout << "Failed to write DLL path into memory" << std::endl;
        return 0;
    }

    const auto loadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");

    const auto thread =
        CreateRemoteThreadEx(process, nullptr, 0, (PTHREAD_START_ROUTINE)loadLib, dllAddr, 0, nullptr, nullptr);

    if (!thread) {
        std::cout << "Failed to create remote thread" << std::endl;
        return thread;
    }

    std::cout << "Created remote thread for loading DLL" << std::endl;

    return thread;
}