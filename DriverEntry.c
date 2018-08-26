#include "Pch.h"

#pragma warning(disable: 4100)

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pReg)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING us = { 0 };
    PUNICODE_STRING pUsHideDriverPath = NULL;
    PUNICODE_STRING pUsLoaderDriverPath = NULL;
    PGLOBAL_INFO pInfo = NULL;

    pDriverObject->DriverUnload = DriverUnload;

    pInfo = ExAllocatePool(NonPagedPool, sizeof(GLOBAL_INFO));

    if (pInfo == NULL)
        return STATUS_SUCCESS;

    RtlZeroMemory(pInfo, sizeof(GLOBAL_INFO));

    status = LeiLeiInitLdrData((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection);

    if (!NT_SUCCESS(status))
        return STATUS_SUCCESS;

    status = LeiLeiStripFilename(&((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName, &us);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("SreipFileName faild...\n");
        return STATUS_SUCCESS;
    }

    pUsLoaderDriverPath = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
    RtlZeroMemory(pUsLoaderDriverPath, sizeof(UNICODE_STRING));

    LeiLeiSafeInitString(pUsLoaderDriverPath, &((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName);

    if (pUsLoaderDriverPath->Buffer == NULL)
        return STATUS_SUCCESS;

    pUsHideDriverPath = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
    RtlZeroMemory(pUsHideDriverPath, sizeof(UNICODE_STRING));

    LeiLeiSafeInitStringEx(pUsHideDriverPath, &us, 260 * 2);

    if (pUsHideDriverPath->Buffer == 0)
        return STATUS_SUCCESS;

    wcscat(pUsHideDriverPath->Buffer, L"\\ThaSafe.dll");

    RtlInitUnicodeString(pUsHideDriverPath, pUsHideDriverPath->Buffer);

    pInfo->pUsLoaderDriverPath = pUsLoaderDriverPath;
    pInfo->pUsMappDriverPath = pUsHideDriverPath;

    status = LeiLeiMMapDriver(pInfo);

    // 如果load成功 此驱动直接卸载 load失败 此驱动长留
    if (NT_SUCCESS(status))
        status = STATUS_UNSUCCESSFUL;
    else
        status = STATUS_SUCCESS;

    return status;
}