#pragma once

typedef NTSTATUS(NTAPI* RtlSetLastWin32ErrorAndNtStatusFromNtStatus_t)(NTSTATUS status);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
	);

// THE VALUES FOR NAMES ARE GUESSED, BUT NAMES ARE CORRECT (THAT HOW ENUM SHOULD LOOK LIKE)
enum CONSOLE_TYPE {
	CONSOLE_TYPE_XBOX_ONE = 1,
	CONSOLE_TYPE_XBOX_ONE_S = 2,
	CONSOLE_TYPE_XBOX_ONE_X = 3,
	CONSOLE_TYPE_XBOX_ONE_X_DEVKIT = 4
};

typedef struct _SYSTEMOSVERSIONINFO {
	UINT8 MajorVersion;
	UINT8 MinorVersion;
	UINT16 BuildNumber;
	UINT16 Revision;
} SYSTEMOSVERSIONINFO, * LPSYSTEMOSVERSIONINFO;

typedef struct _PROCESSOR_SCHEDULING_STATISTICS {
	UINT64 RunningTime;
	UINT64 IdleTime;
	UINT64 GlobalTime;
} PROCESSOR_SCHEDULING_STATISTICS, * PPROCESSOR_SCHEDULING_STATISTICS;

typedef struct _TOOLINGMEMORYSTATUS {
	DWORD     dwLength;
	DWORD     dwReserved;
	DWORDLONG ullTotalMem;
	DWORDLONG ullAvailMem;
	DWORDLONG ulPeakUsage;
	DWORDLONG ullPageTableUsage;
} TOOLINGMEMORYSTATUS, * PTOOLINGMEMORYSTATUS, * LPTOOLINGMEMORYSTATUS;

typedef struct _TITLEMEMORYSTATUS {
	DWORD dwLength;
	DWORD dwReserved;
	DWORDLONG ullTotalMem;
	DWORDLONG ullAvailMem;
	DWORDLONG ullLegacyUsed;
	DWORDLONG ullLegacyPeak;
	DWORDLONG ullLegacyAvail;
	DWORDLONG ullTitleUsed;
	DWORDLONG ullTitleAvail;
} TITLEMEMORYSTATUS, * PTITLEMEMORYSTATUS, * LPTITLEMEMORYSTATUS;

__int64 sub_18001BB8C();

NTSTATUS sub_18001BCA0(HINSTANCE hInstance, DWORD forwardReason, LPVOID lpvReserved);

static CRITICAL_SECTION XMemSetAllocationHooksLock_X;