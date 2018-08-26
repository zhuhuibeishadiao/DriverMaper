#pragma once
#include "Pch.h"

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTSYSAPI
NTSTATUS 
NTAPI
ZwQueryInformationProcess(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    IN  PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


NTKERNELAPI
PPEB 
NTAPI
PsGetProcessPeb( IN PEPROCESS Process );

NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb( IN PETHREAD Thread );

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process( IN PEPROCESS Process );

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process( );

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess( IN PEPROCESS Process );


NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader( PVOID Base );

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    PVOID ImageBase,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
    );
