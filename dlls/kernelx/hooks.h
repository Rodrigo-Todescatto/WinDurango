#pragma once
#include <winrt/Windows.ApplicationModel.h>

#include "utils.h"
#include "CoreApplicationWrapperX.h"
#include <windows.applicationmodel.core.h>

#include "CurrentAppWrapper.hpp"

/* This function is used to compare the class name of the classId with the classIdName. */
inline bool IsClassName(HSTRING classId, const char* classIdName)
{
	const wchar_t* classIdString = WindowsGetStringRawBuffer(classId, nullptr);
	std::wstring classIdWString(classIdString);
	const std::string classIdStringUTF8(classIdWString.begin(), classIdWString.end());

	return (classIdStringUTF8 == classIdName);
}

/* Function pointers for the DllGetForCurrentThread */
typedef HRESULT(*DllGetForCurrentThreadFunc) (ICoreWindowStatic*, CoreWindow**);
/* Function pointers for the DllGetForCurrentThread */
DllGetForCurrentThreadFunc pDllGetForCurrentThread = nullptr;
/* Function pointers for the DllGetForCurrentThread */
HRESULT(STDMETHODCALLTYPE* TrueGetForCurrentThread)(ICoreWindowStatic* staticWindow, CoreWindow** window);
/* Function pointers for the DllGetActivationFactory */
typedef HRESULT(*DllGetActivationFactoryFunc) (HSTRING, IActivationFactory**);
/* Function pointers for the DllGetActivationFactory */
DllGetActivationFactoryFunc pDllGetActivationFactory = nullptr;
/* Function pointers for the WinRT RoGetActivationFactory function. */
HRESULT(WINAPI* TrueRoGetActivationFactory)(HSTRING classId, REFIID iid, void** factory) = RoGetActivationFactory;

HRESULT(WINAPI* TrueActivateInstance)(IActivationFactory* thisptr, IInspectable** instance) = nullptr;


/* Function pointers for filesystem APIs */
HFILE(WINAPI* TrueOpenFile)(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) = OpenFile;
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;

DWORD(WINAPI* TrueGetFileAttributesW)(LPCWSTR lpFileName) = GetFileAttributesW;
BOOL(WINAPI* TrueGetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) = GetFileAttributesExW;

HANDLE(WINAPI* TrueFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;

BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR lpFileName) = DeleteFileW;

HMODULE(WINAPI* TrueLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD dwFlags) = LoadLibraryExW;
HMODULE(WINAPI* TrueLoadLibraryExA)(LPCSTR lpLibFileName, HANDLE  hFile, DWORD dwFlags) = LoadLibraryExA;
HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR lpLibFileName) = LoadLibraryW;

HRESULT(STDMETHODCALLTYPE* TrueGetLicenseInformation)(
	ABI::Windows::ApplicationModel::Store::ILicenseInformation** value
) = nullptr;

std::unordered_map<void*, void*> FakePhysicalPages; // Maps fake physical pages

BOOL WINAPI AllocateTitlePhysicalPages_X(HANDLE hProcess, ULONG flAllocationType, PULONG_PTR NumberOfPages, PULONG_PTR PageArray) 
{
	SIZE_T pageSize = 65536; // 64KB pages
	SIZE_T numPages = *NumberOfPages;
	if (flAllocationType & MEM_4MB_PAGES && numPages % 64 != 0) {
		printf("Error: NumberOfPages must be a multiple of 64 when using MEM_4MB_PAGES.\n");
		return FALSE;
	}

	if (flAllocationType & MEM_4MB_PAGES) {
		// When MEM_4MB_PAGES is specified, convert the number of 4MB pages to 64KB pages
		numPages = numPages * 64 *2;  // 1 4MB page = 64 pages of 64KB
	}

	for (SIZE_T i = 0; i < numPages; i++) {
		void* allocatedPage = VirtualAlloc(NULL, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!allocatedPage) {
			printf("FakeAllocateTitlePhysicalPages: VirtualAlloc failed!\n");
			return FALSE;
		}
		printf("%d\n", allocatedPage);
		if(i == 0xfc0)
		{
			printf("%d\n", allocatedPage);
		}
		// Store each allocated 64 KB page in the output array (PageArray)
		PageArray[i] = reinterpret_cast<ULONG_PTR>(allocatedPage);
		FakePhysicalPages[(void*)PageArray[i]] = allocatedPage;  // Mapping fake physical pages to allocated memory
	}

	*NumberOfPages = numPages;
	return TRUE;
}

PVOID WINAPI MapTitlePhysicalPages_X(PVOID VirtualAddress, ULONG_PTR NumberOfPages, ULONG flAllocationType, ULONG flProtect, PULONG_PTR PageArray) 
{
	SIZE_T dwSize = NumberOfPages * 64 * 1024; // 64 KB per page

	// Step 2: If VirtualAddress is NULL, allocate a region of memory
	if (VirtualAddress == NULL)
	{
		VirtualAddress = VirtualAlloc(NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // TODO HANDLE GRAPHIC THING
		if (VirtualAddress == NULL)
		{
			return NULL; // Allocation failed
		}
	}

	// Step 3: Iterate over the virtual pages in PageArray and map each to the new virtual address
	for (ULONG_PTR i = 0; i < NumberOfPages; ++i)
	{
		printf("%d\n", PageArray[i]);
	}

	// Step 3: Iterate over the virtual pages in PageArray and map each to the new virtual address
	for (ULONG_PTR i = 0; i < NumberOfPages; ++i)
	{
		// Step 3.1: Calculate the new virtual address for each page
		PVOID pageBase = (PVOID)((ULONG_PTR)VirtualAddress + (i * 64 * 1024)); // 64 KB per page

		// Step 3.2: Copy the data from the "fake" physical address in PageArray[i] to the new virtual address (pageBase)
		memcpy(pageBase, (PVOID)PageArray[i], 64 * 1024); // Copy 64 KB from the fake "physical" address to the new virtual address
	}

	// Return the mapped virtual address
	return VirtualAddress;
}

BOOL WINAPI FreeTitlePhysicalPages_X(HANDLE hProcess, PULONG_PTR NumberOfPages, PULONG_PTR PageArray) 
{
	for (SIZE_T i = 0; i < *NumberOfPages; i++) {
		if (FakePhysicalPages.find((void*)PageArray[i]) != FakePhysicalPages.end()) {
			VirtualFree((void*)PageArray[i], 0, MEM_RELEASE);
			FakePhysicalPages.erase((void*)PageArray[i]);
		}
	}


	return TRUE;
}

BOOL
WINAPI
VirtualProtect_X(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
)
{
	BOOL res = VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
	if (!res)
		printf("ERRORO %i\n", GetLastError());
	return res;
}


NTSTATUS NtEnable32BitProcess_X(HANDLE processHandle, int unk_flag, __int64* bufAddress)
{
	// (1) Validate parameters.
	if ((unk_flag & ~1) != 0) {
		return STATUS_INVALID_PARAMETER;
	}
	if (bufAddress == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	// (2) Determine target process.
	// In the kernel this might attach to another process.
	// Here, if processHandle == (HANDLE)-1, we use GetCurrentProcess().
	HANDLE hProcess = NULL;
	if (processHandle == (HANDLE)-1) {
		hProcess = GetCurrentProcess();
	}
	else {
		// In a full implementation you might duplicate or validate the handle.
		hProcess = processHandle;
	}
	// (No further use of hProcess in our simulation.)

	// (3) Allocate a temporary buffer P of 0x200 bytes.
	// In the kernel this is allocated from the paged pool.
	uint8_t* P = (uint8_t*)malloc(0x200);
	if (P == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(P, 0, 0x200);

	// In the kernel, P is later used as an array of 128 32–bit integers.
	// We simulate this by filling the buffer with a simple pattern.
	uint32_t* pInts = (uint32_t*)P;
	for (int i = 0; i < 128; i++) {
		// For example, base value 0x100000 plus the index.
		pInts[i] = 0x100000 + i;
	}

	// (4) Simulate “critical region”, locks, and descriptor updates.
	// For user mode, we skip actual locking and assume all helper functions succeed.
	/*/ (We call one stub that “programs” the mapping, and we assume it succeeds.)
	NTSTATUS status = FUN_fffff80040023364(0, 0, 0, 0, 0);
	if (!NT_SUCCESS(status)) {
		free(P);
		return status;
	}*/

	// (5) Generate the mapping table.
	// The kernel code loops 128 times (0x80) and, for each entry in P (an unsigned int),
	// left–shifts it by 6 bits to get a base value, then writes 64 consecutive 64–bit entries.
	// (128 * 64 * 8 bytes = 64 KB)
	uint64_t* outMappingTable = (uint64_t*)bufAddress;
	for (int i = 0; i < 128; i++) {
		uint64_t base = ((uint64_t)pInts[i]) << 6;  // left–shift by 6 bits
		for (int j = 0; j < 64; j++) {
			outMappingTable[i * 64 + j] = base + j;
		}
	}

	// (6) Clean up and return.
	free(P);
	// In the kernel, additional unlocking and detachment would occur here.
	return STATUS_SUCCESS;
}


FARPROC WINAPI GetProcAddress_X(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
)
{
	if (strcmp(lpProcName, "NtEnable32BitProcess") == 0)
	{
		return (FARPROC)NtEnable32BitProcess_X;
	}
	/*if (strcmp(lpProcName, "NtUpdateVirtualPageTables") == 0)
	{
		return (FARPROC)NtUpdateVirtualPageTables_X;
	}*/
	return GetProcAddress(hModule, lpProcName);
}




HMODULE WINAPI LoadLibraryExW_X(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD   dwFlags)
{
	printf("LoadLibraryExW_X: %S\n", lpLibFileName);
	if (wcscmp(lpLibFileName, L"xaudio2_9.dll") == 0 ||
		wcscmp(lpLibFileName, L"xaudio2_9d.dll") == 0)
	{
		void* returnAddress = _ReturnAddress();

		HMODULE hModule = NULL;
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, static_cast<LPCWSTR>(returnAddress), &hModule);

		// get caller path without file name and extension
		wchar_t callerPath[MAX_PATH];
		GetModuleFileNameW(hModule, callerPath, MAX_PATH);
		wchar_t* callerfileName = PathFindFileNameW(callerPath);
		PathRemoveFileSpecW(callerPath);

		// get the current module path without file name and extension
		wchar_t currentPath[MAX_PATH];
		GetModuleFileNameW(NULL, currentPath, MAX_PATH);
		PathRemoveFileSpecW(currentPath);



		if (wcscmp(currentPath, callerPath) == 0 &&
			!(wcscmp(callerfileName, L"xaudio2_9_x.dll") == 0))
		{
			LPCWSTR proxyXAudioModule = L"xaudio2_9_x.dll";
			return LoadLibraryExW(proxyXAudioModule, hFile, dwFlags);
		}
	}


	return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}


// Hooks for filesystem APIs
void FixRelativePath(LPCWSTR& lpFileName)
{
	static std::wstring convert{};
	std::wstring_view fileName(lpFileName);

	if (fileName.size() == 0)
		return;

	if (fileName[1] != ':')
	{
		convert = std::filesystem::current_path().c_str();
		convert.append(L"\\");
		convert.append(fileName);

		lpFileName = convert.data();
	}
	else if (fileName[0] == 'G' && fileName[1] == ':')
	{

		static std::wstring trimPath{};
		trimPath = fileName.substr(2);
		fileName = trimPath.data();
		convert = std::filesystem::current_path().c_str();
		convert.append(fileName);

		lpFileName = convert.data();
	}
}


HMODULE WINAPI LoadLibraryExA_Hook(LPCSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags)
{

	static std::string convert{};
	std::string_view fileName(lpLibFileName);

	if (fileName.size() != 0 && fileName[0] == 'G' && fileName[1] == ':')
	{
		std::string trimPath = std::string(fileName.substr(2));
		convert = std::filesystem::current_path().string();
		convert.append(trimPath);
		lpLibFileName = convert.c_str();
	}

	//printf("LoadLibraryExA_Hook-: %s\n", lpLibFileName);




	HMODULE result = TrueLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	// Print last error if failed
	if (result == NULL)
	{
		printf("LoadLibraryExA_Hook failed: %d\n", GetLastError());
	}
	return result;
}

HMODULE WINAPI LoadLibraryW_Hook(LPCWSTR lpLibFileName)
{

	static std::wstring convert{};
	std::wstring_view fileName(lpLibFileName);


	if (fileName[0] == 'G' && fileName[1] == ':' && fileName.size() != 0)
	{

		static std::wstring trimPath{};
		trimPath = fileName.substr(2);
		fileName = trimPath.data();
		convert = std::filesystem::current_path().c_str();
		convert.append(fileName);

		lpLibFileName = convert.data();
	}
	//printf("LoadLibraryW_Hook: %ls\n", lpLibFileName);

	return TrueLoadLibraryW(lpLibFileName);
}
HFILE WINAPI OpenFile_Hook(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle)
{
	//FixRelativePath(lpFileName);

	return TrueOpenFile(lpFileName, lpReOpenBuff, uStyle);
}

HANDLE WINAPI CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	FixRelativePath(lpFileName);

	return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DWORD WINAPI GetFileAttributesW_Hook(LPCWSTR lpFileName)
{
	FixRelativePath(lpFileName);

	return TrueGetFileAttributesW(lpFileName);
}

BOOL WINAPI GetFileAttributesExW_Hook(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
{
	FixRelativePath(lpFileName);

	return TrueGetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
}


HANDLE WINAPI FindFirstFileW_Hook(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	FixRelativePath(lpFileName);

	return TrueFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI DeleteFileW_Hook(LPCWSTR lpFileName)
{
	FixRelativePath(lpFileName);

	return TrueDeleteFileW(lpFileName);
}

// The hook function for GetForCurrentThread
HRESULT STDMETHODCALLTYPE GetForCurrentThread_Hook(ICoreWindowStatic* pThis, CoreWindow** ppWindow)
{
	HRESULT hr = TrueGetForCurrentThread(pThis, ppWindow);
	if (FAILED(hr))
	{
		return hr;
	}

	if (*ppWindow == NULL)
		return hr;

	if (IsXboxCallee())
		*reinterpret_cast<ICoreWindowX**>(ppWindow) = new CoreWindowWrapperX(*ppWindow);

	return hr;
}

template <typename T>
inline T GetVTableMethod(void* table_base, std::uintptr_t index) {
	return (T)((*reinterpret_cast<std::uintptr_t**>(table_base))[index]);
}

HRESULT STDMETHODCALLTYPE CurrentAppActivateInstance_Hook(IActivationFactory* thisptr, IInspectable** instance)
{
	HRESULT hr = TrueActivateInstance(thisptr, instance);
	if (FAILED(hr))
		return hr;

	*instance = reinterpret_cast<Store::ILicenseInformation*>(new LicenseInformationWrapperX(reinterpret_cast<Store::ILicenseInformation*>(*instance)));
	return hr;
}

/* Hook for the WinRT RoGetActivationFactory function. */
inline HRESULT WINAPI RoGetActivationFactory_Hook(HSTRING classId, REFIID iid, void** factory)
{
	// Get the raw buffer from the HSTRING
	const wchar_t* rawString = WindowsGetStringRawBuffer(classId, nullptr);

	// this might be a lil expensive? evaluate later
	if (wcscmp(rawString, L"Windows.UI.Core.CoreWindow") != 0)
		wprintf(L"%ls\n", rawString);

	auto hr = 0;

	if (IsClassName(classId, "Windows.ApplicationModel.Store.CurrentApp"))
	{
		hr = TrueRoGetActivationFactory(classId, iid, factory);

		if (FAILED(hr))
			return hr;

		// @unixian: is there a better way to do this? it works, but we never know if the vtable will change (microsoft please don't make breaking ABI changes)
		TrueActivateInstance = GetVTableMethod<decltype(TrueActivateInstance)>(*factory, 6);

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&TrueActivateInstance, CurrentAppActivateInstance_Hook);
		DetourTransactionCommit();
	}

		if (IsClassName(classId, "Windows.ApplicationModel.Core.CoreApplication"))
		{
			ComPtr<IActivationFactory> realFactory;

			hr = TrueRoGetActivationFactory(HStringReference(RuntimeClass_Windows_ApplicationModel_Core_CoreApplication).Get(), IID_PPV_ARGS(&realFactory));

			if (FAILED(hr))
				return hr;

			ComPtr<CoreApplicationWrapperX> wrappedFactory = Make<CoreApplicationWrapperX>(realFactory);

			return wrappedFactory.CopyTo(iid, factory);
		}

		if (IsClassName(classId, "Windows.UI.Core.CoreWindow"))
		{
			//
			// for now we just hook GetForCurrentThread to get the CoreWindow but i'll change it later to
			// wrap ICoreWindowStatic or as zombie said another thing that works is by hooking IFrameworkView::SetWindow
			// but for now this *should* work just fine -AleBlbl
			//
			ComPtr<ICoreWindowStatic> coreWindowStatic;
			hr = TrueRoGetActivationFactory(HStringReference(RuntimeClass_Windows_UI_Core_CoreWindow).Get(), IID_PPV_ARGS(&coreWindowStatic));
			if (FAILED(hr)) {
				return hr;
			}

			if (!TrueGetForCurrentThread)
			{
				*reinterpret_cast<void**>(&TrueGetForCurrentThread) = (*reinterpret_cast<void***>(coreWindowStatic.Get()))[6];

				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(&TrueGetForCurrentThread, GetForCurrentThread_Hook);
				DetourTransactionCommit();
			}

			return coreWindowStatic.CopyTo(iid, factory);
		}

		// After WinDurango overrides try to load the rest

		if (!pDllGetActivationFactory)
		{
			auto library = LoadPackagedLibrary(L"winrt_x.dll", 0);

			if (!library) library = LoadLibraryW(L"winrt_x.dll");

			if (!library) return hr;

			pDllGetActivationFactory = reinterpret_cast<DllGetActivationFactoryFunc>
				(GetProcAddress(library, "DllGetActivationFactory"));

			if (!pDllGetActivationFactory)
				return hr;
		}

		// fallback
		ComPtr<IActivationFactory> fallbackFactory;
		hr = pDllGetActivationFactory(classId, fallbackFactory.GetAddressOf());

		if (SUCCEEDED(hr))
			return fallbackFactory.CopyTo(iid, factory);

	return TrueRoGetActivationFactory(classId, iid, factory);
}
