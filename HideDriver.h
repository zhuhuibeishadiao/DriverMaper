#pragma once
//#include <ntifs.h>
#include <ntddk.h>

typedef struct _DRIVER_CONTEXT_INFO {
	PVOID ImageBase;
	PVOID SectionPoint;
	PUNICODE_STRING pRegPath;
	ULONG ImageSize;
}DRIVER_CONTEXT_INFO, *PDRIVER_CONTEXT_INFO;


VOID HideDriver(PVOID pDriverSection);

KIRQL WPOFF();

void WPON(KIRQL irql);

NTSTATUS EnableSEH(PVOID pDriverInfo);
