#include "Pch.h"

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

/// <summary>
/// Allocate new Unicode string from Paged pool
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="size">Buffer size in bytes to alloacate</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiSafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size)
{
    ASSERT(result != NULL);
    if (result == NULL || size == 0)
        return STATUS_INVALID_PARAMETER;

    result->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, size, 'xxxx');
    result->Length = 0;
    result->MaximumLength = size;

    if (result->Buffer)
        RtlZeroMemory(result->Buffer, size);
    else
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}

/// <summary>
/// Allocate and copy string
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="source">Source string</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source)
{
    ASSERT(result != NULL && source != NULL);
    if (result == NULL || source == NULL || source->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    // No data to copy
    if (source->Length == 0)
    {
        result->Length = result->MaximumLength = 0;
        result->Buffer = NULL;
        return STATUS_SUCCESS;
    }

    result->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, source->MaximumLength, 'xxxx');
    result->Length = source->Length;
    result->MaximumLength = source->MaximumLength;

    RtlZeroMemory(result->Buffer, result->MaximumLength);

    memcpy(result->Buffer, source->Buffer, source->Length);

    return STATUS_SUCCESS;
}

NTSTATUS LeiLeiSafeInitStringEx(OUT PUNICODE_STRING result, IN PUNICODE_STRING source, USHORT addSize)
{
    ASSERT(result != NULL && source != NULL);
    if (result == NULL || source == NULL || source->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    // No data to copy
    if (source->Length == 0)
    {
        result->Length = result->MaximumLength = 0;
        result->Buffer = NULL;
        return STATUS_SUCCESS;
    }

    result->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, source->MaximumLength + addSize, 'xxxx');
    result->Length = source->Length + addSize;
    result->MaximumLength = source->MaximumLength + addSize;

    RtlZeroMemory(result->Buffer, result->MaximumLength);

    memcpy(result->Buffer, source->Buffer, source->Length);

    return STATUS_SUCCESS;
}

/// <summary>
/// Search for substring
/// </summary>
/// <param name="source">Source string</param>
/// <param name="target">Target string</param>
/// <param name="CaseInSensitive">Case insensitive search</param>
/// <returns>Found position or -1 if not found</returns>
LONG LeiLeiSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
    ASSERT(source != NULL && target != NULL);
    if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    // Size mismatch
    if (source->Length < target->Length)
        return -1;

    USHORT diff = source->Length - target->Length;
    for (USHORT i = 0; i < diff; i++)
    {
        if (RtlCompareUnicodeStrings(
            source->Buffer + i / sizeof(WCHAR),
            target->Length / sizeof(WCHAR),
            target->Buffer,
            target->Length / sizeof(WCHAR),
            CaseInSensitive
        ) == 0)
        {
            return i;
        }
    }

    return -1;
}

/// <summary>
/// Get file name from full path
/// </summary>
/// <param name="path">Path.</param>
/// <param name="name">Resulting name</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name)
{
    ASSERT(path != NULL && name);
    if (path == NULL || name == NULL)
        return STATUS_INVALID_PARAMETER;

    // Empty string
    if (path->Length < 2)
    {
        *name = *path;
        return STATUS_NOT_FOUND;
    }

    for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
    {
        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
        {
            name->Buffer = &path->Buffer[i + 1];
            name->Length = name->MaximumLength = path->Length - (i + 1) * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }
    }

    *name = *path;
    return STATUS_NOT_FOUND;
}

/// <summary>
/// Get directory path name from full path
/// </summary>
/// <param name="path">Path</param>
/// <param name="name">Resulting directory path</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir)
{
    ASSERT(path != NULL && dir);
    if (path == NULL || dir == NULL)
        return STATUS_INVALID_PARAMETER;

    // Empty string
    if (path->Length < 2)
    {
        *dir = *path;
        return STATUS_NOT_FOUND;
    }

    for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
    {
        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
        {
            dir->Buffer = path->Buffer;
            dir->Length = dir->MaximumLength = i * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }
    }

    *dir = *path;
    return STATUS_NOT_FOUND;
}

/// <summary>
/// Check if file exists
/// </summary>
/// <param name="path">Fully qualifid path to a file</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiFileExists(IN PUNICODE_STRING path)
{
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK statusBlock = { 0 };
    OBJECT_ATTRIBUTES obAttr = { 0 };
    InitializeObjectAttributes(&obAttr, path, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwCreateFile(
        &hFile, FILE_READ_DATA | SYNCHRONIZE, &obAttr,
        &statusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
    );

    if (NT_SUCCESS(status))
        ZwClose(hFile);

    return status;
}

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS LeiLeiSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/// <summary>
/// Check if process is terminating
/// </summary>
/// <param name="imageBase">Process</param>
/// <returns>If TRUE - terminating</returns>
BOOLEAN LeiLeiCheckProcessTermination(PEPROCESS pProcess)
{
    LARGE_INTEGER zeroTime = { 0 };
    return KeWaitForSingleObject(pProcess, Executive, KernelMode, FALSE, &zeroTime) == STATUS_WAIT_0;
}

PVOID LeiLeiGetKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    // Already found
    if (g_KernelBase != NULL)
    {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
        return NULL;

    // Protect from UserMode AV
    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        DPRINT("LoadDriver: %s: Invalid SystemModuleInformation size\n", __FUNCTION__);
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'xxxx');
    RtlZeroMemory(pMods, bytes);

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status))
    {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            // System routine is inside module
            if (checkPtr >= pMod[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
            {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                if (pSize)
                    *pSize = g_KernelSize;
                break;
            }
        }
    }

    if (pMods)
        ExFreePoolWithTag(pMods, 'xxxx');

    return g_KernelBase;
}

/// <summary>
/// Gets SSDT base - KiServiceTable
/// </summary>
/// <returns>SSDT base, NULL if not found</returns>
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase()
{
    PUCHAR ntosBase = (PUCHAR)LeiLeiGetKernelBase(NULL);

    // Already found
    if (g_SSDT != NULL)
        return g_SSDT;

    if (!ntosBase)
        return NULL;

    PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader(ntosBase);
    PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
    {
        // Non-paged, non-discardable, readable sections
        // Probably still not fool-proof enough...
        if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
            pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
            (*(PULONG)pSec->Name != 'TINI') &&
            (*(PULONG)pSec->Name != 'EGAP'))
        {
            PVOID pFound = NULL;

            // KiSystemServiceRepeat pattern
            UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
            NTSTATUS status = LeiLeiSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
            if (NT_SUCCESS(status))
            {
                g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
                //DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT );
                return g_SSDT;
            }
        }
    }

    return NULL;
}

/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID GetSSDTEntry(IN ULONG index)
{
    ULONG size = 0;
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
    PVOID pBase = LeiLeiGetKernelBase(&size);

    if (pSSDT && pBase)
    {
        // Index range check
        if (index > pSSDT->NumberOfServices)
            return NULL;

        return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
    }

    return NULL;
}

/*
LeiLeiScanSection( "PAGE", (PCUCHAR)"\x48\x8D\x7D\x18\x48\x8B", 0xCC, 6, (PVOID)&pData->ExRemoveTable )
*/
NTSTATUS LeiLeiScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL);
    if (ppFound == NULL)
        return STATUS_INVALID_PARAMETER;

    PVOID base = LeiLeiGetKernelBase(NULL);
    if (!base)
        return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
    if (!pHdr)
        return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0)
        {
            PVOID ptr = NULL;
            NTSTATUS status = LeiLeiSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(status))
                *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

            return status;
        }
    }

    return STATUS_NOT_FOUND;
}

PEPROCESS BBGetProcessByName(char* szProcessName)
{
    size_t i = 0;
    PEPROCESS Process = NULL;
    if (szProcessName == NULL || szProcessName[0] == '\0')
        return NULL;

    for (i = 8; i < 65000; i = i + 4)
    {
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &Process)))
        {
            if (!_strnicmp(szProcessName, (char*)PsGetProcessImageFileName(Process), strlen(szProcessName)))
            {
                ObDereferenceObject(Process);
                return Process;
            }
            ObDereferenceObject(Process);
        }
    }

    return NULL;
}

//PGLOBAL_INFO g_Context = NULL;
NTSTATUS RegQueryValueKey(LPWSTR KeyName, LPWSTR ValueName, PKEY_VALUE_PARTIAL_INFORMATION *pkvpi)
{
    ULONG ulSize;
    NTSTATUS ntStatus;
    PKEY_VALUE_PARTIAL_INFORMATION pvpi;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE hRegister;
    UNICODE_STRING usKeyName;
    UNICODE_STRING usValueName;
    RtlInitUnicodeString(&usKeyName, KeyName);
    RtlInitUnicodeString(&usValueName, ValueName);
    InitializeObjectAttributes(&objectAttributes,
        &usKeyName,
        OBJ_CASE_INSENSITIVE,//对大小写敏感
        NULL,
        NULL);
    ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
    if (!NT_SUCCESS(ntStatus))
    {
        //DbgPrint("[RegQueryValueKey]ZwOpenKey failed!\n");
        return ntStatus;
    }
    ntStatus = ZwQueryValueKey(hRegister,
        &usValueName,
        KeyValuePartialInformation,
        NULL,
        0,
        &ulSize);
    if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
    {
        ZwClose(hRegister);
        //DbgPrint("ZwQueryValueKey 1 failed!\n");
        return STATUS_UNSUCCESSFUL;
    }
    pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
    ntStatus = ZwQueryValueKey(hRegister,
        &usValueName,
        KeyValuePartialInformation,
        pvpi,
        ulSize,
        &ulSize);
    if (!NT_SUCCESS(ntStatus))
    {
        ZwClose(hRegister);
        //DbgPrint("ZwQueryValueKey 2 failed!\n");
        return STATUS_UNSUCCESSFUL;
    }
    //这里的pvpi是没有释放的用完要释放。ExFreePool(pvpi);
    *pkvpi = pvpi;
    ZwClose(hRegister);
    //DbgPrint("ZwQueryValueKey success!\n");
    return STATUS_SUCCESS;
}

ULONG GetProcesidByName(CHAR* szProcessName)
{
    size_t i = 0;
    PEPROCESS Process = NULL;

    for (i = 8; i < 0x20000; i += 4)
    {
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &Process)))
        {
            __try {
                if (!_strnicmp(szProcessName, PsGetProcessImageFileName(Process), strlen(szProcessName)))
                {
                    ObDereferenceObject(Process);
                    return i;
                }
            }
            __except (1)
            {
                i += 4;
            }

            ObDereferenceObject(Process);
        }
    }

    return 0;
}

BOOLEAN CheckSig(PUNICODE_STRING pRegPath)
{
    ULONG sig = 0;
    ULONG tempSig = 0;
    //ULONG exPid = 0;
    ULONG LsPid = 0;
    ULONG smssPid = 0;
    ULONG wy = 0;
    BOOLEAN bRet = FALSE;
    CHAR lsName[10] = { 0 };
    CHAR smssName[9] = { 0 };
    PKEY_VALUE_PARTIAL_INFORMATION pKeyInfo = NULL;
    lsName[0] = 'l';
    lsName[1] = 's';
    lsName[2] = 'a';
    lsName[3] = 's';
    lsName[4] = 's';
    lsName[5] = '.';
    lsName[6] = 'e';
    lsName[7] = 'x';
    lsName[8] = 'e';
    lsName[9] = '\0';
    smssName[0] = 's';
    smssName[1] = 'm';
    smssName[2] = 's';
    smssName[3] = 's';
    smssName[4] = '.';
    smssName[5] = 'e';
    smssName[6] = 'x';
    smssName[7] = 'e';
    smssName[8] = '\0';

    //KdBreakPoint();
    if (NT_SUCCESS(RegQueryValueKey(pRegPath->Buffer, L"Debug", &pKeyInfo)))
    {
        if (pKeyInfo->Type == REG_DWORD)
        {
            RtlCopyMemory(&sig, pKeyInfo->Data, pKeyInfo->DataLength);
            LsPid = GetProcesidByName(lsName);
            smssPid = GetProcesidByName(smssName);
            if (LsPid == 0 || smssPid == 0)
            {
                ExFreePool(pKeyInfo);
                return FALSE;
            }
            wy = LsPid + smssPid - 456;
            tempSig = smssPid * wy + smssPid * LsPid + LsPid * wy + LsPid;
            //lsass.exe pid + smss.exe pid - 456 = wy
            // Sig = smssPid * wy  + smssPid * LsPid + LsPid * wy + LsPid
            //DPRINT("%d\n", tempSig);
            if (tempSig == sig)
                bRet = TRUE;
        }

        ExFreePool(pKeyInfo);
    }

    return bRet;
}