#include "Pch.h"

NTSTATUS
IopInvalidDeviceRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS MakeFakeDriverObject(IN PUNICODE_STRING driverName, OUT PDRIVER_OBJECT* ppdriverObject)
{
    NTSTATUS status;
    ULONG i;
    OBJECT_ATTRIBUTES objectAttributes;
    PDRIVER_OBJECT driverObject;
    InitializeObjectAttributes(&objectAttributes,
        driverName,
        OBJ_PERMANENT,
        (HANDLE)NULL,
        (PSECURITY_DESCRIPTOR)NULL);
    status = ObCreateObject(ExGetPreviousMode(),
        *IoDriverObjectType,
        &objectAttributes,
        KernelMode,
        (PVOID)NULL,
        (ULONG)(sizeof(DRIVER_OBJECT) + sizeof(DRIVER_EXTENSION) + 256),
        0,
        0,
        (PVOID *)ppdriverObject);

    if (!NT_SUCCESS(status))
    {
        *ppdriverObject = NULL;
        return status;
    }

    driverObject = *ppdriverObject;

    RtlZeroMemory(driverObject, sizeof(DRIVER_OBJECT) + sizeof(DRIVER_EXTENSION) + 256);

    driverObject->DriverExtension = (PDRIVER_EXTENSION)(driverObject + 1);
    driverObject->DriverExtension->DriverObject = driverObject;//这个DriverExtension常用，如果没有直接惨死
    driverObject->Type = IO_TYPE_DRIVER;
    driverObject->Size = sizeof(DRIVER_OBJECT);
    driverObject->Flags = DRVO_BUILTIN_DRIVER;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        driverObject->MajorFunction[i] = IopInvalidDeviceRequest;

    /*driverObject->DriverName.Buffer = ExAllocatePool(PagedPool, driverName->MaximumLength);
    if (driverObject->DriverName.Buffer)
    {
    driverObject->DriverName.MaximumLength = driverName->MaximumLength;
    driverObject->DriverName.Length = driverName->Length;
    RtlCopyMemory(driverObject->DriverName.Buffer, driverName->Buffer, driverName->MaximumLength);
    }*/
    return status;
}

BOOLEAN GetDrvObject(PDRIVER_OBJECT *lpDriverObject)
{
    UNICODE_STRING usDriverName = { 0 };
    WCHAR buffer[60] = { 0 };
    usDriverName.Buffer = buffer;
    usDriverName.Length = 60 * 2;
    usDriverName.MaximumLength = 60 * 2;

    if (NT_SUCCESS(RtlUnicodeStringPrintf(&usDriverName, L"\\Driver\\Rtl%08u", PsGetCurrentThreadId())))
    {
        if (NT_SUCCESS(MakeFakeDriverObject(&usDriverName, lpDriverObject)))
        {
            //DPRINT("Get Success...\n");
            return TRUE;
        }
        else
        {
            DPRINT("Get Faild...");
            return FALSE;
        }
    }

    return FALSE;
}