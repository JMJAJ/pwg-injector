#include "config.hpp"
#include "inject.hpp"
#include "manual.hpp"

#include "pch.hpp"

typedef void (*setDirectory)(std::wstring directory);
typedef int (*init)(HINSTANCE hInstDLL);

bool IsProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        
        CloseHandle(hToken);
    }
    
    return isElevated != FALSE;
}

PWSTR askForLauncherPath() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    PWSTR pszFilePath = NULL;

    if (SUCCEEDED(hr)) {
        IFileOpenDialog* pFileOpen;

        // Create the FileOpenDialog object.
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog,
            reinterpret_cast<void**>(&pFileOpen));

        if (SUCCEEDED(hr)) {
            const COMDLG_FILTERSPEC filter[] = {
                {L"TOF Launcher", L"HottaGame.exe"},
            };
            pFileOpen->SetFileTypes(ARRAYSIZE(filter), filter);
            // Show the Open dialog box.
            hr = pFileOpen->Show(NULL);

            // Get the file name from the dialog box.
            if (SUCCEEDED(hr)) {
                IShellItem* pItem;
                hr = pFileOpen->GetResult(&pItem);
                if (SUCCEEDED(hr)) {

                    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                    if (SUCCEEDED(hr)) {
                        return pszFilePath;
                    }

                    pItem->Release();
                }
            }
            pFileOpen->Release();
        }
        CoUninitialize();
    }

    return pszFilePath;
}

bool startLauncher(wchar_t* launcherPath) {
    if (!IsProcessElevated()) {
        std::cout << "This program requires administrative privileges. Please run as administrator." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return false;
    }

    STARTUPINFO si;
    si.cb = sizeof(si);
    ZeroMemory(&si, sizeof(si));
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Create the process with explicit admin privileges
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    SetEnvironmentVariable(L"__COMPAT_LAYER", L"RUNASINVOKER");

    const auto launcherProcessResult =
        CreateProcess(nullptr, launcherPath, nullptr, nullptr, false, 
                     CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
                     nullptr, nullptr, &si, &pi);

    if (!launcherProcessResult) {
        std::cout << "Failed to start the launcher. Exiting..." << std::endl;
        std::cout << "Error: " << GetLastError() << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return false;
    }

    // Resume the process
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        while (Process32Next(handleSnapshot, &procEntry)) {
            if (_wcsicmp(procEntry.szExeFile, procName) == 0) {
                procId = procEntry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(handleSnapshot);

    return procId;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL) 
                  && GetLastError() == ERROR_SUCCESS;

    CloseHandle(hToken);
    return result;
}

HANDLE OpenProcessWithFullAccess(DWORD processId) {
    // Try different combinations of access rights
    const DWORD accessFlags[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
    };

    HANDLE hProcess = NULL;
    
    // Enable debug privilege first
    EnableDebugPrivilege();

    // Try each access flag combination
    for (const DWORD flags : accessFlags) {
        hProcess = OpenProcess(flags, FALSE, processId);
        if (hProcess) {
            return hProcess;
        }
    }

    return NULL;
}

bool InjectWithElevatedPrivileges(HANDLE hProcess, const wchar_t* dllPath) {
    // Ensure we have debug privileges
    if (!EnableDebugPrivilege()) {
        std::cout << "Warning: Failed to enable debug privileges. Error: " << GetLastError() << std::endl;
    }

    // Try manual mapping first as it's more reliable for elevated processes
    std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
    if (!dllFile.is_open()) {
        std::wcout << L"Failed to open DLL file: " << dllPath << std::endl;
        return false;
    }

    auto dllSize = dllFile.tellg();
    BYTE* pSrcData = new BYTE[(UINT_PTR)dllSize];
    dllFile.seekg(0, std::ios::beg);
    dllFile.read((char*)(pSrcData), dllSize);
    dllFile.close();

    bool result = ManualMapDll<const wchar_t*>(
        hProcess, 
        pSrcData, 
        dllSize, 
        "preMain",
        std::filesystem::path(dllPath).parent_path().c_str(),
        (std::filesystem::path(dllPath).parent_path().wstring().size() + 1) * 2,
        true,  // ClearHeader
        true,  // ClearNonNeededSections
        true,  // AdjustProtections
        true,  // SEHExceptionSupport
        DLL_PROCESS_ATTACH,  // fdwReason
        nullptr,  // lpReserved
        PAGE_EXECUTE_READWRITE  // protection
    );

    delete[] pSrcData;

    if (!result) {
        // If manual mapping fails, try LoadLibrary as fallback
        result = InjectDll(hProcess, dllPath);
    }

    return result;
}

int main() {
    if (!IsProcessElevated()) {
        std::cout << "This program requires administrative privileges. Please run as administrator." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    const auto launcherPid = GetProcId(L"HottaGame.exe");

    if (launcherPid != 0) {
        std::cout << "Launcher is already running." << std::endl;
        std::cout << "If it wasn't started by this injector. Please close it and launch the injector again."
            << std::endl;
    }

    const uint16_t pathSize = 2048;
    wchar_t path[pathSize];
    GetModuleFileName(nullptr, (LPWSTR)path, sizeof(path));
    std::wstring directory = std::wstring(path);
    directory = directory.substr(0, directory.find_last_of(L"\\") + 1);

    Config::setDirectory(directory);
    Config::init();

    auto launcherPath = Config::get<std::string>("/launcherPath", "");

    if (launcherPath->empty()) {
        std::wcout << L"Launcher path not found. Please select the launcher path." << std::endl;

        const auto path = std::wstring(askForLauncherPath());

        if (!path.empty()) {
            char multiBytePath[2048];
            const auto convertRes =
                WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, multiBytePath, 2048, nullptr, nullptr);
            launcherPath = std::string(multiBytePath);
        }
        else {
            std::wcout << L"Launcher path not given. Exiting..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            return 1;
        }
    }

    auto wideLauncherPath = std::wstring(launcherPath->begin(), launcherPath->end());

    if (!startLauncher(wideLauncherPath.data())) {
        return 1;
    }

    auto configuredInjectionMethod = Config::get<std::string>("/injectionMethod", "");
    std::string injectionMethod = "loadLibrary";

    if (!configuredInjectionMethod->empty()) {
        injectionMethod = std::string(configuredInjectionMethod->begin(), configuredInjectionMethod->end());
    }
    else {
        configuredInjectionMethod = injectionMethod;
    }

    std::cout << "Injection method: " << injectionMethod << std::endl;

    std::cout << "Launcher has been started. Please start the game from the launcher." << std::endl;

    DWORD qrslPid = 0;

    while (true) {
        qrslPid = GetProcId(L"QRSL.exe");

        if (qrslPid != 0) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const auto dllPath = directory + L"ue_sdk.dll";

    std::wcout << L"Injecting " + dllPath << std::endl;

    // Use the new process opening function
    HANDLE proc = OpenProcessWithFullAccess(qrslPid);
    if (!proc) {
        std::cout << "Failed to open process. Error: " << GetLastError() << std::endl;
        std::cout << "Make sure you have administrator privileges and try again." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    bool result = false;

    if (injectionMethod == "manual") {
        std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
        if (!dllFile.is_open()) {
            std::wcout << L"Failed to open DLL file: " << dllPath << std::endl;
            CloseHandle(proc);
            return 1;
        }

        auto dllSize = dllFile.tellg();
        BYTE* pSrcData = new BYTE[(UINT_PTR)dllSize];
        dllFile.seekg(0, std::ios::beg);
        dllFile.read((char*)(pSrcData), dllSize);
        dllFile.close();

        result = ManualMapDll<const wchar_t*>(
            proc, 
            pSrcData, 
            dllSize, 
            "preMain", 
            directory.c_str(),
            directory.size() * 2,
            true,  // ClearHeader
            true,  // ClearNonNeededSections
            true,  // AdjustProtections
            true,  // SEHExceptionSupport
            DLL_PROCESS_ATTACH,  // fdwReason
            nullptr,  // lpReserved
            PAGE_EXECUTE_READWRITE  // protection
        );

        delete[] pSrcData;
    }
    else if (injectionMethod == "loadLibrary") {
        std::cout << "Press F1 to start injection. This is preferably done at the login screen and not when the game "
            "is loading."
            << std::endl;
        
        // Wait for F1 and retry logic
        int retryCount = 0;
        const int maxRetries = 3;
        
        while (retryCount < maxRetries) {
            if (GetAsyncKeyState(VK_F1) & 1) {
                result = InjectWithElevatedPrivileges(proc, dllPath.c_str());
                if (result) break;
                
                std::cout << "Injection attempt " << (retryCount + 1) << " failed. Error: " << GetLastError() << std::endl;
                if (retryCount < maxRetries - 1) {
                    std::cout << "Retrying in 2 seconds..." << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
                retryCount++;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    else {
        std::cout << "Invalid injection method." << std::endl;
        CloseHandle(proc);
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    if (result) {
        std::cout << "Injected successfully." << std::endl;
    }
    else {
        std::cout << "Failed to inject. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(proc);
    Config::shutdown();
    std::this_thread::sleep_for(std::chrono::seconds(4));
    return 0;
}