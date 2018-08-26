#ifndef _PCH_
#define _PCH_ 1

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>

typedef struct _GLOBAL_INFO
{
    //ULONG BuildNumber; // *NtBuildNumber
    //ULONG OffsetProtect; // EPROCESS:PROTECT
    //ULONG OffsetFlags2; // EPROCESS:Flags2 on win7
    //ULONG unknow;
    ULONG dwVaild;
    PDRIVER_OBJECT pDriverObject;
    size_t ImageSize;
    PVOID ImageBase;
    WCHAR* szSymbloName;
    PUNICODE_STRING pUsMappDriverPath; // 用于删除
    PUNICODE_STRING pUsLoaderDriverPath; // 用户删除
}GLOBAL_INFO, *PGLOBAL_INFO;

NTKERNELAPI
NTSTATUS
ObCreateObject(
    IN KPROCESSOR_MODE ProbeMode,
    IN POBJECT_TYPE ObjectType,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN KPROCESSOR_MODE OwnershipMode,
    IN OUT PVOID ParseContext OPTIONAL,
    IN ULONG ObjectBodySize,
    IN ULONG PagedPoolCharge,
    IN ULONG NonPagedPoolCharge,
    OUT PVOID *Object
);

NTKERNELAPI	UCHAR *	PsGetProcessImageFileName(__in PEPROCESS Process);

extern POBJECT_TYPE *IoDriverObjectType;

#include "NativeStructs.h"
#include "Utils.h"
#include "Imports.h"
#include "LeiLeiLoad.h"
#include "HideDriver.h"
#include "GetDrvObject.h"
#include "khttp.h"

#endif // !_PCH_
