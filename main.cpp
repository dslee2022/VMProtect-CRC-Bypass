#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
using namespace std;
DWORD TargetBase = 0;
DWORD HookBase = 0xCBE3;
DWORD DumpBase = 0x0;
//https://forum.tuts4you.com/topic/36991-inlineme-vmprotect-isvalidimagecrc/

DWORD GetMainThreadId() { 
    const std::tr1::shared_ptr<void> hThreadSnapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), CloseHandle);
    if (hThreadSnapshot.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("GetMainThreadId failed");
    }
    THREADENTRY32 tEntry;
    tEntry.dwSize = sizeof(THREADENTRY32);
    DWORD result = 0;
    DWORD currentPID = GetCurrentProcessId();
    for (BOOL success = Thread32First(hThreadSnapshot.get(), &tEntry);
        !result && success && GetLastError() != ERROR_NO_MORE_FILES;
        success = Thread32Next(hThreadSnapshot.get(), &tEntry))
    {
        if (tEntry.th32OwnerProcessID == currentPID) {
            result = tEntry.th32ThreadID;
        }
    }
    return result;
}

void SetHardwareBreakpoint()
{
	int TID = GetMainThreadId();
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, TID);
	if (hThread)
	{
		CONTEXT context;
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		SuspendThread(hThread);

		if (GetThreadContext(hThread, &context))
		{
			context.Dr0 = HookBase + TargetBase;
			context.Dr1 = 0;
			context.Dr2 = 0;
			context.Dr3 = 0;

			context.Dr7 = (1 << 0) | (1 << 2) | (1 << 4);

			SetThreadContext(hThread, &context);
		}

		ResumeThread(hThread);
		CloseHandle(hThread);
	}
}

LONG WINAPI VectoredExceptionHandler1(EXCEPTION_POINTERS * ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionAddress == (void*)(TargetBase + HookBase))
	{
		cout << "Accessed: " << hex << ExceptionInfo->ContextRecord->Edx << " Modified to: " << (ExceptionInfo->ContextRecord->Edx - TargetBase) + DumpBase << endl;
		ExceptionInfo->ContextRecord->Edx = (ExceptionInfo->ContextRecord->Edx - TargetBase) + DumpBase;
		ExceptionInfo->ContextRecord->Eip += 0x2;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void DumpTarget()
{
	MODULEINFO Info{};
	GetModuleInformation(GetCurrentProcess(), (HMODULE)TargetBase, &Info, sizeof(Info));
	DumpBase = (DWORD)VirtualAlloc(0, Info.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	int* tmp = new int[Info.SizeOfImage];
	ReadProcessMemory(GetCurrentProcess(), (void*)TargetBase, tmp, Info.SizeOfImage, 0);
	WriteProcessMemory(GetCurrentProcess(), (void*)DumpBase, tmp, Info.SizeOfImage, 0);
	cout << hex << "DumpBase: " << DumpBase << endl;
	delete[] tmp;
	return;
}

int main()
{

	AllocConsole();
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);

	TargetBase = (DWORD)GetModuleHandle(0);
	DumpTarget();
	AddVectoredExceptionHandler(0, VectoredExceptionHandler1);
	SetHardwareBreakpoint();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, NULL, NULL, NULL);
		break;
	}
	return TRUE;
}