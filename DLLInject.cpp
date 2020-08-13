// DLLInject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "data.h"





UNICODE_STRING stringdevice;


int ss() {
	return 0;
}

VOID WINAPI threadProc(THREAD_PARAM* param) {
	/********************初始化调用函数*************************/
	DWORD processid;
	int threadid;
	HANDLE pfile;
	OBJECT_ATTRIBUTES  os;
	//UNICODE_STRING string;
	IO_STATUS_BLOCK IoStatusBlock;
	//RtlInitUnicodeString(&string, param->deviceksdd);
	InitializeObjectAttributes(&os, &stringdevice, OBJ_EXCLUSIVE, NULL, NULL);
	while (true)
	{
		if ((param->dwGetAsyncKeyState(VK_HOME) && 0x8000) == 1) {
			HWND gamehwnd = param->dwFindWindowW(param->UnrealWindow, NULL);
			threadid = param->dwGetWindowThreadProcessId(gamehwnd, &processid);
			if (threadid != param->processID) {
				param->processID = processid;
				param->dwNtOpenFile(&pfile, FILE_EXECUTE | FILE_TRAVERSE, &os, &IoStatusBlock, 
									FILE_SHARE_DELETE| FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
				param->dwNtDeviceIoControlFile(pfile, NULL, NULL, NULL, &IoStatusBlock, 0xB6DC56, (PVOID)0x6B0, 0x10,0, 0x8);
				*(int*)(param + 0x8DC) = param->x;
				param->dwNtDeviceIoControlFile(pfile, NULL, NULL, NULL, &IoStatusBlock, 0xB6DC5A, 0, 0x10,param + 0xDC, param->dllsize);
				HHOOK hkeyboard = param->dwSetWindowsHookExW(3, (HOOKPROC)ss, param->NTDLL, threadid);
				*(int*)(param + 0x8DC) = 0;
				param->dwPostThreadMessageW(threadid, 0, 0, 0);
				param->dwNtDeviceIoControlFile(pfile, NULL, NULL, NULL, &IoStatusBlock, 0xB6DC5A, 0, 0x10,param + 0xDC, 1);
				param->dwUnhookWindowsHookEx(hkeyboard);
				param->dwSleep(0x32);
			}
		}
	}
}

int main()
{
	IO_STATUS_BLOCK IoStatusBlock;

	if (AdjustProcessTokenPrivilege() == FALSE) {
		MessageBoxA(NULL, "请以管理员身份运行", NULL, NULL);
		exit(1);
	}

    HANDLE open_dllsize = OpenFileMappingA(FILE_MAP_ALL_ACCESS, NULL, "Prodlsabnkxgckgaw");
	if (open_dllsize == 0) {
		MessageBoxA(NULL, "取数据失败", NULL, NULL);
		CloseHandle(open_dllsize);
		exit(1);
	}
    char* DLLsize_char = (char*)MapViewOfFile(open_dllsize, FILE_MAP_ALL_ACCESS, NULL, NULL, 7);
	int DLLsize_int = atoi(DLLsize_char);
	
	HANDLE hand2 = OpenFileMappingA(FILE_MAP_ALL_ACCESS, NULL, "Drohftfgakknczlfd");
	if (hand2 == 0) {
		MessageBoxA(NULL, "取数据失败", NULL, NULL);
		CloseHandle(hand2);
		exit(1);
	}
	CHAR* DLLmemory = (char*)MapViewOfFile(hand2, FILE_MAP_ALL_ACCESS, NULL, NULL, DLLsize_int);

	/*打开进程*/
	DWORD processid = GetProcessIDByName("explorer.exe");
	HANDLE hOpenProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processid);

	/*获取系统模块句柄*/
	HMODULE user32 = LoadLibrary("user32.dll");
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (user32 != 0 && kernel32 != 0 && ntdll != 0) {
		pRtlInitUnicodeString dwpRtlInitUnicodeString;

		THREAD_PARAM param = { 0 };
		dwpRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

		param.dwGetAsyncKeyState = (pGetAsyncKeyState)GetProcAddress(user32, "GetAsyncKeyState");
		param.dwSleep = (pSleep)GetProcAddress(kernel32, "Sleep");
		param.dwNtOpenFile = (pNtOpenFile)GetProcAddress(ntdll, "NtOpenFile");
		param.dwFindWindowW = (pFindWindowW)GetProcAddress(user32, "FindWindowW");
		param.dwGetWindowThreadProcessId = (pGetWindowThreadProcessId)GetProcAddress(user32, "GetWindowThreadProcessId");
		param.dwNtDeviceIoControlFile = (pNtDeviceIoControlFile)GetProcAddress(ntdll, "NtDeviceIoControlFile");
		param.dwSetWindowsHookExW = (pSetWindowsHookExW)GetProcAddress(user32, "SetWindowsHookExW");
		param.dwUnhookWindowsHookEx = (pUnhookWindowsHookEx)GetProcAddress(user32, "UnhookWindowsHookEx");
		param.dwPostThreadMessageW = (pPostThreadMessageW)GetProcAddress(user32, "PostThreadMessageW");
		param.NTDLL = ntdll;
		param.dllsize = DLLsize_int;
		param.processID = 0;
		param.x = 0x5F3A83BA;
		wcscpy_s(param.deviceksdd, L"\\Device\\KsecDD");
		wcscpy_s(param.UnrealWindow, L"UnrealWindow");
		char* pBuffer = (char*)malloc(0x100000);
		if (pBuffer != NULL) {
			memset(pBuffer, 0, 0x100000);
		}
		RtlMoveMemory(pBuffer + sizeof(THREAD_PARAM) + 4, DLLmemory, DLLsize_int);
		RtlMoveMemory(pBuffer, &param, sizeof(THREAD_PARAM));

		dwpRtlInitUnicodeString(&stringdevice, param.deviceksdd);

		LPVOID AllocAddres = VirtualAllocEx(hOpenProcess, NULL, 0x1000E0, MEM_COMMIT, PAGE_READWRITE);
		if (AllocAddres != NULL && pBuffer != NULL) {
			std::cout << "AllocAddres=" << AllocAddres << std::endl;
			WriteProcessMemory(hOpenProcess, AllocAddres, pBuffer, 0x1000E0, 0);//参数写入目标
		}
		LPVOID AllocAddres1 = VirtualAllocEx(hOpenProcess, NULL, 0xA000, MEM_TOP_DOWN | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (AllocAddres1 != NULL) {
			std::cout << "AllocAddres1=" << (DWORD*)AllocAddres1 + 0x1000 << std::endl;
			WriteProcessMemory(hOpenProcess, (DWORD*)AllocAddres1 + 0x1000 , &threadProc, 0x225, 0);
		}
		Sleep(0x1F4);
		HANDLE threadhandle =  CreateRemoteThread(hOpenProcess, 0, 0, (LPTHREAD_START_ROUTINE)((DWORD*)AllocAddres1 + 0x1000), AllocAddres, NULL, NULL);
		if (threadhandle != 0) {
			MessageBoxA(NULL, "Please enter the game hall and press the HOME button to activate", "Tip", NULL);
			Sleep(0x7D0);
			PVOID outbuffer;
			param.dwNtDeviceIoControlFile(filehandle, 0, 0, 0, &IoStatusBlock, 0xB6DC62, (LPVOID)processid, 0x10, outbuffer, 0x8);
			CloseHandle(hOpenProcess);
			CloseHandle(??);

		}
	}
	
	return 0;
}
