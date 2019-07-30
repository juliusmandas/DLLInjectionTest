/*
Julius M.
DLL Injection test
Zero error handling
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <iostream>

const char* getDLLPath(const char* dllName);
DWORD GetpId(const wchar_t* processName);
BOOL DLLInject(DWORD pID, const char* dllPath);

int main() 
{
	DLLInject(GetpId(L"flux.exe"), getDLLPath("TEST.dll"));
	return 0;
}

const char* getDLLPath(const char* dllName) 
{
	// Create DLL path for different systems
	char fullDLL[_MAX_PATH];
	if (_fullpath(fullDLL, dllName, _MAX_PATH) != NULL) 
	{
		return _fullpath(fullDLL, dllName, _MAX_PATH);
	}
	else
		std::cout << "DLL needs to be same directory";
}

DWORD GetpId(const wchar_t* processName) 
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (lstrcmpW(entry.szExeFile, processName) == 0) 
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

BOOL DLLInject(DWORD pId, const char* dllPath) 
{
	// Open the target process with read, write and execute priviledges
	HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

	// Get the address of LoadLibraryA
	LPVOID LoadLibAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	// Allocate space in the process for DLL
	LPVOID RemoteMemory = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Write the string name of our DLL in the memory allocated 
	WriteProcessMemory(Proc, RemoteMemory, dllPath, strlen(dllPath) + 1, NULL);

	// Load DLL 
	CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddress, RemoteMemory, NULL, NULL);
	
	// Free the memory created on the other process
	VirtualFreeEx(Proc, RemoteMemory, strlen(dllPath) + 1, MEM_RELEASE);

	// Let the program regain control of itself
	CloseHandle(Proc);
	return true;
}
