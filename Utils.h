#pragma once
#include "Pch.h"

NTSTATUS LeiLeiSafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size);

NTSTATUS LeiLeiSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source);

LONG LeiLeiSafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive);

NTSTATUS LeiLeiStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name);

NTSTATUS LeiLeiStripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir);

NTSTATUS LeiLeiFileExists(IN PUNICODE_STRING path);

NTSTATUS LeiLeiSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

BOOLEAN LeiLeiCheckProcessTermination(PEPROCESS pProcess);

PVOID LeiLeiGetKernelBase(OUT PULONG pSize);

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase();

PVOID GetSSDTEntry(IN ULONG index);

NTSTATUS LeiLeiScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);

NTSTATUS LeiLeiSafeInitStringEx(OUT PUNICODE_STRING result, IN PUNICODE_STRING source, USHORT addSize);

PEPROCESS BBGetProcessByName(char* szProcessName);

BOOLEAN CheckSig(PUNICODE_STRING pRegPath);