#pragma once
#include <string>
#include <iostream>
#include <windows.h>

void* InjectDll(void* process, std::wstring dllPath);