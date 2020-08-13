#pragma once

#include <Windows.h>
//#include <winternl.h>
#include <winternl.h>
#include <TlHelp32.h>
#pragma warning(disable:4700)
#define SYSSING "\\\\.\\GIO"

typedef VOID (NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef SHORT(WINAPI* pGetAsyncKeyState)(int vKey);
typedef HWND(WINAPI* pFindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName);
typedef DWORD(WINAPI* pGetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
typedef NTSTATUS(WINAPI* pNtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(WINAPI* pNtDeviceIoControlFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef HHOOK(WINAPI* pSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
typedef VOID(WINAPI* pSleep)(DWORD dwMilliseconds);
typedef BOOL(WINAPI* pUnhookWindowsHookEx)(HHOOK hhk);
typedef BOOL(WINAPI* pPostThreadMessageW)(DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);

/*要写入的数据结构*/
typedef struct _THREAD_PARAM {
	pGetAsyncKeyState dwGetAsyncKeyState;
	pSleep dwSleep;
	pNtOpenFile dwNtOpenFile;
	pFindWindowW dwFindWindowW;
	pGetWindowThreadProcessId dwGetWindowThreadProcessId;
	pNtDeviceIoControlFile dwNtDeviceIoControlFile;
	pSetWindowsHookExW dwSetWindowsHookExW;
	pUnhookWindowsHookEx dwUnhookWindowsHookEx;
	pPostThreadMessageW dwPostThreadMessageW;
	HMODULE NTDLL;
	int processID = 0;
	int x = 0x5F3A83BA;
	int dllsize = 0;
	wchar_t deviceksdd[32] = { 0 };
	wchar_t UnrealWindow[30] = { 0 };
}THREAD_PARAM;

BOOL AdjustProcessTokenPrivilege() {//提升进程权限

	LUID luidTmp;
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		OutputDebugString("AdjustProcessTokenPrivilege OpenProcessToken Failed ! \n");

		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp)) {
		OutputDebugString("AdjustProcessTokenPrivilege LookupPrivilegeValue Failed ! \n");

		CloseHandle(hToken);

		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luidTmp;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		OutputDebugString("AdjustProcessTokenPrivilege AdjustTokenPrivileges Failed ! \n");
		CloseHandle(hToken);
		return FALSE;
	}
	return true;
}

DWORD GetProcessIDByName(const char* pName)
{

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (strcmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

VOID LOADSYS() {
	HANDLE filehandle;
	char BufferData = NULL;
	DWORD ReturnLength = 0;
	DWORD ReturnLength2 = 0;
	int64_t str= 0x6000;
	int64_t str2 = 0xFFFFBA8182506000;
	//SECURITY_ATTRIBUTES sa;
	filehandle = CreateFileA(SYSSING, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DeviceIoControl(filehandle, 0xC3502800, &str, 4, (LPVOID)BufferData, 8, &ReturnLength, 0);
	DeviceIoControl(filehandle, 0xC3502808, &str2, 0x18, (LPVOID)BufferData, 0x600000000, &ReturnLength2, 0);
	CloseHandle(filehandle);
}