#include "Pch.h"

#pragma warning(disable: 4100)

extern PSHORT NtBuildNumber;
//
// Mark a HIGHADJ entry as needing an increment if reprocessing.
//
#define LDRP_RELOCATION_INCREMENT   0x1

//
// Mark a HIGHADJ entry as not suitable for reprocessing.
//
#define LDRP_RELOCATION_FINAL       0x2

#define IMAGE_REL_BASED_ABSOLUTE                0
#define IMAGE_REL_BASED_HIGH                    1
#define IMAGE_REL_BASED_LOW                     2
#define IMAGE_REL_BASED_HIGHLOW                 3
#define IMAGE_REL_BASED_HIGHADJ                 4
#define IMAGE_REL_BASED_MIPS_JMPADDR            5
#define IMAGE_REL_BASED_SECTION                 6
#define IMAGE_REL_BASED_REL32                   7
#define IMAGE_REL_BASED_MIPS_JMPADDR16          9
#define IMAGE_REL_BASED_IA64_IMM64              9
#define IMAGE_REL_BASED_DIR64                   10

#define IMAGE32(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_VAL_T(hdr, val) (IMAGE64(hdr) ? ((PIMAGE_NT_HEADERS64)hdr)->OptionalHeader.val : ((PIMAGE_NT_HEADERS32)hdr)->OptionalHeader.val)
#define THUNK_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_THUNK_DATA64)ptr)->val : ((PIMAGE_THUNK_DATA32)ptr)->val)
#define TLS_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_TLS_DIRECTORY64)ptr)->val : ((PIMAGE_TLS_DIRECTORY32)ptr)->val)
#define CFG_DIR_VAL_T(hdr, dir, val) (IMAGE64(hdr) ? ((PIMAGE_LOAD_CONFIG_DIRECTORY64)dir)->val : ((PIMAGE_LOAD_CONFIG_DIRECTORY32)dir)->val)

typedef NTSTATUS LDR_RELOCATE_IMAGE_RETURN_TYPE;

PLIST_ENTRY PsLoadedModuleList;

//NTKERNELAPI
//UCHAR * PsGetProcessImageFileName(IN PEPROCESS Process);
//
//PEPROCESS BBGetProcessByName(char* szProcessName)
//{
//    size_t i = 0;
//    PEPROCESS Process = NULL;
//    if (szProcessName == NULL || szProcessName[0] == '\0')
//        return NULL;
//
//    for (i = 8; i < 65000; i = i + 4)
//    {
//        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &Process)))
//        {
//            if (!_strnicmp(szProcessName, (char*)PsGetProcessImageFileName(Process), strlen(szProcessName)))
//            {
//                ObDereferenceObject(Process);
//                return Process;
//            }
//            ObDereferenceObject(Process);
//        }
//    }
//
//    return NULL;
//}
//extern PSHORT NtBuildNumber;

PIMAGE_BASE_RELOCATION
LdrProcessRelocationBlockLongLong(
    IN ULONG_PTR VA,
    IN ULONG SizeOfBlock,
    IN PUSHORT NextOffset,
    IN LONGLONG Diff
)
{
    PUCHAR FixupVA;
    USHORT Offset;
    LONG Temp;
    //ULONG Temp32;
    ULONGLONG Value64;
    //LONGLONG Temp64;

    while (SizeOfBlock--) {

        Offset = *NextOffset & (USHORT)0xfff;
        FixupVA = (PUCHAR)(VA + Offset);

        //
        // Apply the fixups.
        //

        switch ((*NextOffset) >> 12) {

        case IMAGE_REL_BASED_HIGHLOW:
            //
            // HighLow - (32-bits) relocate the high and low half
            //      of an address.
            //
            *(LONG UNALIGNED *)FixupVA += (ULONG)Diff;
            break;

        case IMAGE_REL_BASED_HIGH:
            //
            // High - (16-bits) relocate the high half of an address.
            //
            Temp = *(PUSHORT)FixupVA << 16;
            Temp += (ULONG)Diff;
            *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
            break;

        case IMAGE_REL_BASED_HIGHADJ:
            //
            // Adjust high - (16-bits) relocate the high half of an
            //      address and adjust for sign extension of low half.
            //

            //
            // If the address has already been relocated then don't
            // process it again now or information will be lost.
            //
            if (Offset & LDRP_RELOCATION_FINAL) {
                ++NextOffset;
                --SizeOfBlock;
                break;
            }

            Temp = *(PUSHORT)FixupVA << 16;
            ++NextOffset;
            --SizeOfBlock;
            Temp += (LONG)(*(PSHORT)NextOffset);
            Temp += (ULONG)Diff;
            Temp += 0x8000;
            *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);

            break;

        case IMAGE_REL_BASED_LOW:
            //
            // Low - (16-bit) relocate the low half of an address.
            //
            Temp = *(PSHORT)FixupVA;
            Temp += (ULONG)Diff;
            *(PUSHORT)FixupVA = (USHORT)Temp;
            break;

        case IMAGE_REL_BASED_IA64_IMM64:

            //
            // Align it to bundle address before fixing up the
            // 64-bit immediate value of the movl instruction.
            //

            FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
            Value64 = (ULONGLONG)0;

            //
            // Extract the lower 32 bits of IMM64 from bundle
            //

            /*
            EXT_IMM64(Value64,
            (PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
            EMARCH_ENC_I17_IMM7B_SIZE_X,
            EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM7B_VAL_POS_X);
            EXT_IMM64(Value64,
            (PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
            EMARCH_ENC_I17_IMM9D_SIZE_X,
            EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM9D_VAL_POS_X);
            EXT_IMM64(Value64,
            (PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
            EMARCH_ENC_I17_IMM5C_SIZE_X,
            EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM5C_VAL_POS_X);
            EXT_IMM64(Value64,
            (PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
            EMARCH_ENC_I17_IC_SIZE_X,
            EMARCH_ENC_I17_IC_INST_WORD_POS_X,
            EMARCH_ENC_I17_IC_VAL_POS_X);
            EXT_IMM64(Value64,
            (PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
            EMARCH_ENC_I17_IMM41a_SIZE_X,
            EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41a_VAL_POS_X);

            EXT_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
            EMARCH_ENC_I17_IMM41b_SIZE_X,
            EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41b_VAL_POS_X);
            EXT_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
            EMARCH_ENC_I17_IMM41c_SIZE_X,
            EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41c_VAL_POS_X);
            EXT_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
            EMARCH_ENC_I17_SIGN_SIZE_X,
            EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
            EMARCH_ENC_I17_SIGN_VAL_POS_X);
            //
            // Update 64-bit address
            //

            Value64+=Diff;

            //
            // Insert IMM64 into bundle
            //

            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
            EMARCH_ENC_I17_IMM7B_SIZE_X,
            EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM7B_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
            EMARCH_ENC_I17_IMM9D_SIZE_X,
            EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM9D_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
            EMARCH_ENC_I17_IMM5C_SIZE_X,
            EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM5C_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
            EMARCH_ENC_I17_IC_SIZE_X,
            EMARCH_ENC_I17_IC_INST_WORD_POS_X,
            EMARCH_ENC_I17_IC_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
            EMARCH_ENC_I17_IMM41a_SIZE_X,
            EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41a_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
            EMARCH_ENC_I17_IMM41b_SIZE_X,
            EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41b_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
            EMARCH_ENC_I17_IMM41c_SIZE_X,
            EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
            EMARCH_ENC_I17_IMM41c_VAL_POS_X);
            INS_IMM64(Value64,
            ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
            EMARCH_ENC_I17_SIGN_SIZE_X,
            EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
            EMARCH_ENC_I17_SIGN_VAL_POS_X);
            */
            break;

        case IMAGE_REL_BASED_DIR64:

            *(ULONGLONG UNALIGNED *)FixupVA += Diff;

            break;

        case IMAGE_REL_BASED_MIPS_JMPADDR:
            //
            // JumpAddress - (32-bits) relocate a MIPS jump address.
            //
            Temp = (*(PULONG)FixupVA & 0x3ffffff) << 2;
            Temp += (ULONG)Diff;
            *(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
                ((Temp >> 2) & 0x3ffffff);

            break;

        case IMAGE_REL_BASED_ABSOLUTE:
            //
            // Absolute - no fixup required.
            //
            break;

        case IMAGE_REL_BASED_SECTION:
            //
            // Section Relative reloc.  Ignore for now.
            //
            break;

        case IMAGE_REL_BASED_REL32:
            //
            // Relative intrasection. Ignore for now.
            //
            break;

        default:
            //
            // Illegal - illegal relocation type.
            //

            return (PIMAGE_BASE_RELOCATION)NULL;
        }
        ++NextOffset;
    }
    return (PIMAGE_BASE_RELOCATION)NextOffset;
}

LDR_RELOCATE_IMAGE_RETURN_TYPE
LdrRelocateImageWithBias(
    __in PVOID NewBase,
    __in LONGLONG AdditionalBias,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Success,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Conflict,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Invalid
)
/*++

Routine Description:

This routine relocates an image file that was not loaded into memory
at the preferred address.

Arguments:

NewBase - Supplies a pointer to the image base.

AdditionalBias - An additional quantity to add to all fixups.  The
32-bit X86 loader uses this when loading 64-bit images
to specify a NewBase that is actually a 64-bit value.

Success - Value to return if relocation successful.

Conflict - Value to return if can't relocate.

Invalid - Value to return if relocations are invalid.

Return Value:

Success if image is relocated.
Conflict if image can't be relocated.
Invalid if image contains invalid fixups.

--*/

{
    LONGLONG Diff;
    ULONG TotalCountBytes = 0;
    ULONG_PTR VA;
    ULONGLONG OldBase;
    ULONG SizeOfBlock;
    PUSHORT NextOffset = NULL;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION NextBlock;
    LDR_RELOCATE_IMAGE_RETURN_TYPE Status;

    NtHeaders = RtlImageNtHeader(NewBase);
    if (NtHeaders == NULL) {
        Status = Invalid;
        goto Exit;
    }

    switch (NtHeaders->OptionalHeader.Magic) {

    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        OldBase =
            ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.ImageBase;
        break;

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        OldBase =
            ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.ImageBase;
        break;

    default:

        Status = Invalid;
        goto Exit;
    }

    //
    // Locate the relocation section.
    //

    NextBlock = (PIMAGE_BASE_RELOCATION)RtlImageDirectoryEntryToData(
        NewBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &TotalCountBytes);

    //
    // It is possible for a file to have no relocations, but the relocations
    // must not have been stripped.
    //

    if (!NextBlock || !TotalCountBytes)
    {
        Status = (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ? Conflict : Success;
        goto Exit;
    }

    //
    // If the image has a relocation table, then apply the specified fixup
    // information to the image.
    //
    Diff = (ULONG_PTR)NewBase - OldBase + AdditionalBias;
    while (TotalCountBytes)
    {
        SizeOfBlock = NextBlock->SizeOfBlock;

        // Prevent crash
        if (SizeOfBlock == 0)
        {
            Status = Invalid;
            goto Exit;
        }

        TotalCountBytes -= SizeOfBlock;
        SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
        SizeOfBlock /= sizeof(USHORT);
        NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));

        VA = (ULONG_PTR)NewBase + NextBlock->VirtualAddress;
        NextBlock = LdrProcessRelocationBlockLongLong(VA, SizeOfBlock, NextOffset, Diff);

        if (!NextBlock)
        {
            Status = Invalid;
            goto Exit;
        }
    }

    Status = Success;
Exit:
    return Status;
}

LDR_RELOCATE_IMAGE_RETURN_TYPE
LdrRelocateImage(
    __in PVOID NewBase,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Success,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Conflict,
    __in LDR_RELOCATE_IMAGE_RETURN_TYPE Invalid
)
/*++

Routine Description:

This routine relocates an image file that was not loaded into memory
at the preferred address.

Arguments:

NewBase - Supplies a pointer to the image base.

Success - Value to return if relocation successful.

Conflict - Value to return if can't relocate.

Invalid - Value to return if relocations are invalid.

Return Value:

Success if image is relocated.
Conflict if image can't be relocated.
Invalid if image contains invalid fixups.

--*/

{
    //
    // Just call LdrRelocateImageWithBias() with a zero bias.
    //
    return LdrRelocateImageWithBias(NewBase, 0, Success, Conflict, Invalid);
}

NTSTATUS LeiLeiCreateCookie(IN PVOID imageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIMAGE_NT_HEADERS pHeader = RtlImageNtHeader(imageBase);
	//DbgBreakPoint();
    if (pHeader)
    {
        ULONG cfgSize = 0;
        PVOID pCfgDir = RtlImageDirectoryEntryToData(imageBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &cfgSize);

        // TODO: implement proper cookie algorithm
        if (pCfgDir && CFG_DIR_VAL_T(pHeader, pCfgDir, SecurityCookie))
        {
            ULONG seed = (ULONG)(ULONG_PTR)imageBase ^ (ULONG)((ULONG_PTR)imageBase >> 32);
            ULONG_PTR cookie = (ULONG_PTR)imageBase ^  RtlRandomEx(&seed);

            // SecurityCookie value must be rebased by this moment
            if (IMAGE64(pHeader))
                *(PULONG_PTR)CFG_DIR_VAL_T(pHeader, pCfgDir, SecurityCookie) = cookie;
            else
                *(PULONG)CFG_DIR_VAL_T(pHeader, pCfgDir, SecurityCookie) = (ULONG)cookie;
        }
    }
    else
        status = STATUS_INVALID_IMAGE_FORMAT;

    return status;
}

NTSTATUS BBSafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source)
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

    result->Buffer = ExAllocatePoolWithTag(PagedPool, source->MaximumLength, 'xxxx');
    result->Length = source->Length;
    result->MaximumLength = source->MaximumLength;

    memcpy(result->Buffer, source->Buffer, source->Length);

    return STATUS_SUCCESS;
}

NTSTATUS LeiLeiInitLdrData(IN PVOID pLdr)
{
    PKLDR_DATA_TABLE_ENTRY pThisModule = (PKLDR_DATA_TABLE_ENTRY)pLdr;
    PVOID kernelBase = LeiLeiGetKernelBase(NULL);
    if (kernelBase == NULL)
    {
        DPRINT("LoadDriver: %s: Failed to retrieve Kernel base address. Aborting\n", __FUNCTION__);
        return STATUS_NOT_FOUND;
    }

    // Get PsLoadedModuleList address
    for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink; pListEntry != &pThisModule->InLoadOrderLinks; pListEntry = pListEntry->Flink)
    {
        // Search for Ntoskrnl entry
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (kernelBase == pEntry->DllBase)
        {
            // Ntoskrnl is always first entry in the list
            // Check if found pointer belongs to Ntoskrnl module
            if ((PVOID)pListEntry->Blink >= pEntry->DllBase && (PUCHAR)pListEntry->Blink < (PUCHAR)pEntry->DllBase + pEntry->SizeOfImage)
            {
                PsLoadedModuleList = pListEntry->Blink;
                break;
            }
        }
    }

    if (!PsLoadedModuleList)
    {
        DPRINT("LoadDriver: %s: Failed to retrieve PsLoadedModuleList address. Aborting\n", __FUNCTION__);
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

PKLDR_DATA_TABLE_ENTRY LeiLeiGetSystemModule(IN PUNICODE_STRING pName, IN PVOID pAddress)
{
    ASSERT((pName != NULL || pAddress != NULL) && PsLoadedModuleList != NULL);
    if ((pName == NULL && pAddress == NULL) || PsLoadedModuleList == NULL)
        return NULL;

    // No images
    if (IsListEmpty(PsLoadedModuleList))
        return NULL;

    // Search in PsLoadedModuleList
    for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        // Check by name or by address
        if ((pName && RtlCompareUnicodeString(&pEntry->BaseDllName, pName, TRUE) == 0) ||
            (pAddress && pAddress >= pEntry->DllBase && (PUCHAR)pAddress < (PUCHAR)pEntry->DllBase + pEntry->SizeOfImage))
        {
            return pEntry;
        }
    }

    return NULL;
}

PVOID LeiLeiGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName)
{
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
    PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
    ULONG expSize = 0;
    ULONG_PTR pAddress = 0;

    ASSERT(pBase != NULL);
    if (pBase == NULL)
        return NULL;

    /// Not a PE file
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

    // Not a PE file
    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // 64 bit image
    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else
    {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
    PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
    PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

    for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
    {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName = NULL;

        // Find by index
        if ((ULONG_PTR)name_ord <= 0xFFFF)
        {
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
        {
            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return NULL;

        if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
            ((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
        {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

            // Check forwarded export
            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
            {
                /*WCHAR strbuf[256] = { 0 };
                ANSI_STRING forwarder = { 0 };
                ANSI_STRING import = { 0 };

                UNICODE_STRING uForwarder = { 0 };
                ULONG delimIdx = 0;
                PVOID forwardBase = NULL;
                PVOID result = NULL;*/

                // System image, not supported
                if (pProcess == NULL)
                    return NULL;

                //RtlInitAnsiString(&forwarder, (PCSZ)pAddress);
                //RtlInitEmptyUnicodeString(&uForwarder, strbuf, sizeof(strbuf));

                //RtlAnsiStringToUnicodeString(&uForwarder, &forwarder, FALSE);
                //for (ULONG j = 0; j < uForwarder.Length / sizeof(WCHAR); j++)
                //{
                //  if (uForwarder.Buffer[j] == L'.')
                //  {
                //      uForwarder.Length = (USHORT)(j * sizeof(WCHAR));
                //      uForwarder.Buffer[j] = L'\0';
                //      delimIdx = j;
                //      break;
                //  }
                //}

                //// Get forward function name/ordinal
                //RtlInitAnsiString(&import, forwarder.Buffer + delimIdx + 1);
                //RtlAppendUnicodeToString(&uForwarder, L".dll");

                ////
                //// Check forwarded module
                ////
                //UNICODE_STRING resolved = { 0 };
                //UNICODE_STRING resolvedName = { 0 };
                //BBResolveImagePath(NULL, pProcess, KApiShemaOnly, &uForwarder, baseName, &resolved);
                //BBStripPath(&resolved, &resolvedName);

                //forwardBase = BBGetUserModule(pProcess, &resolvedName, PsGetProcessWow64Process(pProcess) != NULL);
                //result = BBGetModuleExport(forwardBase, import.Buffer, pProcess, &resolvedName);
                //RtlFreeUnicodeString(&resolved);

                //return result;
            }

            break;
        }
    }

    return (PVOID)pAddress;
}

NTSTATUS LeiLeiResolveImageRefs(
    IN PVOID pImageBase,
    IN BOOLEAN systemImage,
    IN PEPROCESS pProcess,
    IN BOOLEAN wow64Image,
    IN PVOID pContext,
    IN ULONG flags
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG impSize = 0;
    PIMAGE_NT_HEADERS pHeader = RtlImageNtHeader(pImageBase);
    PIMAGE_IMPORT_DESCRIPTOR pImportTbl = RtlImageDirectoryEntryToData(pImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &impSize);

    // No import libs
    if (pImportTbl == NULL)
        return STATUS_SUCCESS;

    for (; pImportTbl->Name && NT_SUCCESS(status); ++pImportTbl)
    {
        PVOID pThunk = ((PUCHAR)pImageBase + (pImportTbl->OriginalFirstThunk ? pImportTbl->OriginalFirstThunk : pImportTbl->FirstThunk));
        UNICODE_STRING ustrImpDll = { 0 };
        UNICODE_STRING resolved = { 0 };
        ANSI_STRING strImpDll = { 0 };
        ULONG IAT_Index = 0;
        PCCHAR impFunc = NULL;
        union
        {
            PVOID address;
            PKLDR_DATA_TABLE_ENTRY ldrEntry;
        } pModule = { 0 };

        RtlInitAnsiString(&strImpDll, (PCHAR)pImageBase + pImportTbl->Name);
        RtlAnsiStringToUnicodeString(&ustrImpDll, &strImpDll, TRUE);

        // Resolve image name
        BBSafeInitString(&resolved, &ustrImpDll);

        // Get import module
        pModule.address = LeiLeiGetSystemModule(&ustrImpDll, NULL);

        
        // Failed to load
        if (!pModule.address)
        {
            DPRINT("LoadDriver: %s: Failed to load import '%wZ'. Status code: 0x%X\n", __FUNCTION__, ustrImpDll, status);
            RtlFreeUnicodeString(&ustrImpDll);
            RtlFreeUnicodeString(&resolved);

            return STATUS_NOT_FOUND;
        }

        while (THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData))
        {
            PIMAGE_IMPORT_BY_NAME pAddressTable = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)pImageBase + THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData));
            PVOID pFunc = NULL;

            // import by name
            if (THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) < (IMAGE64(pHeader) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) &&
                pAddressTable->Name[0])
            {
                impFunc = pAddressTable->Name;
            }
            // import by ordinal
            else
            {
                impFunc = (PCCHAR)(THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) & 0xFFFF);
            }

            pFunc = LeiLeiGetModuleExport(
                systemImage ? pModule.ldrEntry->DllBase : pModule.address,
                impFunc,
                NULL,
                &resolved
            );

            // No export found
            if (!pFunc)
            {
                if (THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) <  (IMAGE64(pHeader) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) && pAddressTable->Name[0])
                    DPRINT("LoadDriver: %s: Failed to resolve import '%wZ' : '%s'\n", __FUNCTION__, ustrImpDll, pAddressTable->Name);
                else
                    DPRINT("LoadDriver: %s: Failed to resolve import '%wZ' : '%d'\n", __FUNCTION__, ustrImpDll, THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) & 0xFFFF);

                status = STATUS_NOT_FOUND;
                break;
            }

            if (IMAGE64(pHeader))
            {
                // Save address to IAT
                if (pImportTbl->FirstThunk)
                    *(PULONG_PTR)((PUCHAR)pImageBase + pImportTbl->FirstThunk + IAT_Index) = (ULONG_PTR)pFunc;
                // Save address to OrigianlFirstThunk
                else
                    *(PULONG_PTR)((PUCHAR)pImageBase + THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData)) = (ULONG_PTR)pFunc;
            }
            else
            {
                // Save address to IAT
                if (pImportTbl->FirstThunk)
                    *(PULONG)((PUCHAR)pImageBase + pImportTbl->FirstThunk + IAT_Index) = (ULONG)(ULONG_PTR)pFunc;
                // Save address to OrigianlFirstThunk
                else
                    *(PULONG)((PUCHAR)pImageBase + THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData)) = (ULONG)(ULONG_PTR)pFunc;
            }

            // Go to next entry
            pThunk = (PUCHAR)pThunk + (IMAGE64(pHeader) ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
            IAT_Index += (IMAGE64(pHeader) ? sizeof(ULONGLONG) : sizeof(ULONG));
        }

        RtlFreeUnicodeString(&ustrImpDll);
        RtlFreeUnicodeString(&resolved);
    }

    return status;
}

NTSTATUS LeiLeiMapWorker(IN PVOID pArg)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hFile = NULL;
    PUNICODE_STRING pPath = ((PGLOBAL_INFO)pArg)->pUsMappDriverPath;
    OBJECT_ATTRIBUTES obAttr = { 0 };
    IO_STATUS_BLOCK statusBlock = { 0 };
    PVOID fileData = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PVOID imageSection = NULL;
    PMDL pMDL = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    DRIVER_CONTEXT_INFO DriverInfo = { 0 };
 
    //WCHAR* szSymName = NULL;
    //szSymName = ExAllocatePool(NonPagedPool, 260 * 2);
    // 这点内存都没有 玩你麻痹
    //RtlZeroMemory(szSymName, 260 * 2);
    //DbgBreakPoint();
    InitializeObjectAttributes(&obAttr, pPath, OBJ_KERNEL_HANDLE, NULL, NULL);

    // Open driver file
    status = ZwCreateFile(
        &hFile, FILE_READ_DATA | SYNCHRONIZE, &obAttr,
        &statusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
    );

    if (!NT_SUCCESS(status))
    {
        DPRINT("LoadDriver: %s: Failed to open %wZ. Status: 0x%X\n", __FUNCTION__, pPath, status);
        PsTerminateSystemThread(status);
        return status;
    }

    // Allocate memory for file contents
    status = ZwQueryInformationFile(hFile, &statusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (NT_SUCCESS(status))
        fileData = ExAllocatePoolWithTag(PagedPool, fileInfo.EndOfFile.QuadPart, 'xxxx');
    else
        DPRINT("LoadDriver: %s: Failed to get '%wZ' size. Status: 0x%X\n", __FUNCTION__, pPath, status);

    // Get file contents
    status = ZwReadFile(hFile, NULL, NULL, NULL, &statusBlock, fileData, fileInfo.EndOfFile.LowPart, NULL, NULL);
    if (NT_SUCCESS(status))
    {
        pNTHeader = RtlImageNtHeader(fileData);
        if (!pNTHeader)
        {
            DPRINT("LoadDriver: %s: Failed to obtaint NT Header for '%wZ'\n", __FUNCTION__, pPath);
            status = STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    else
        DPRINT("LoadDriver: %s: Failed to read '%wZ'. Status: 0x%X\n", __FUNCTION__, pPath, status);

    ZwClose(hFile);

    if (NT_SUCCESS(status))
    {
        //
        // Allocate memory from System PTEs
        //
        PHYSICAL_ADDRESS start = { 0 }, end = { 0 };
        end.QuadPart = MAXULONG64;

        pMDL = MmAllocatePagesForMdl(start, end, start, pNTHeader->OptionalHeader.SizeOfImage);
        imageSection = MmGetSystemAddressForMdlSafe(pMDL, NormalPagePriority);

        if (NT_SUCCESS(status) && imageSection)
        {
            // Copy header
            RtlCopyMemory(imageSection, fileData, pNTHeader->OptionalHeader.SizeOfHeaders);

            // Copy sections
            for (PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNTHeader + 1);
                pSection < (PIMAGE_SECTION_HEADER)(pNTHeader + 1) + pNTHeader->FileHeader.NumberOfSections;
                pSection++)
            {
                RtlCopyMemory(
                    (PUCHAR)imageSection + pSection->VirtualAddress,
                    (PUCHAR)fileData + pSection->PointerToRawData,
                    pSection->SizeOfRawData
                );
            }

            // Relocate image
            status = LdrRelocateImage(imageSection, STATUS_SUCCESS, STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_IMAGE_FORMAT);
            if (!NT_SUCCESS(status))
                DPRINT("LoadDriver: %s: Failed to relocate image '%wZ'. Status: 0x%X\n", __FUNCTION__, pPath, status);

            // Fill IAT
            if (NT_SUCCESS(status))
                status = LeiLeiResolveImageRefs(imageSection, TRUE, NULL, FALSE, NULL, 0);
        }
        else
        {
            DPRINT("LoadDriver: %s: Failed to allocate memory for image '%wZ'\n", __FUNCTION__, pPath);
            status = STATUS_MEMORY_NOT_ALLOCATED;
        }
    }

    // PatchGuard
    // SEH support
    /*if (NT_SUCCESS( status ))
    {
    //NTSTATUS( NTAPI* RtlInsertInvertedFunctionTable )(PVOID, SIZE_T) = (NTSTATUS( *)(PVOID, SIZE_T))((ULONG_PTR)GetKernelBase( NULL ) + 0x9B0A8);
    NTSTATUS( NTAPI* RtlInsertInvertedFunctionTable )(PVOID, PVOID, SIZE_T) = (NTSTATUS( *)(PVOID, PVOID, SIZE_T))((ULONG_PTR)GetKernelBase( NULL ) + 0x11E4C0);
    RtlInsertInvertedFunctionTable((PUCHAR)GetKernelBase( NULL ) + 0x1ED450, imageSection, pNTHeader->OptionalHeader.SizeOfImage );
    }*/
    if (*NtBuildNumber < 9600)
    {
        DriverInfo.ImageBase = imageSection;
        DriverInfo.ImageSize = pNTHeader->OptionalHeader.SizeOfImage;
        HideDriver(&DriverInfo);
    }

    // Initialize kernel security cookie
    if (NT_SUCCESS(status))
        LeiLeiCreateCookie(imageSection);

    // Call entry point
    if (NT_SUCCESS(status) && pNTHeader->OptionalHeader.AddressOfEntryPoint)
    {
        PDRIVER_INITIALIZE pEntryPoint = (PDRIVER_INITIALIZE)((ULONG_PTR)imageSection + pNTHeader->OptionalHeader.AddressOfEntryPoint);
        PGLOBAL_INFO pInfo = pArg;
        pInfo->ImageBase = imageSection;
        pInfo->ImageSize = pNTHeader->OptionalHeader.SizeOfImage;
        pInfo->dwVaild = 0x999;
        pInfo->szSymbloName = NULL;
        if(GetDrvObject(&pInfo->pDriverObject))
            pEntryPoint(pArg, NULL);
    }

    // Wipe header
    if (NT_SUCCESS(status) && imageSection)
        RtlZeroMemory(imageSection, pNTHeader->OptionalHeader.SizeOfHeaders);

    // Erase info about allocated region
    if (pMDL)
    {
        // Free image memory in case of failure
        if (!NT_SUCCESS(status))
            MmFreePagesFromMdl(pMDL);

        ExFreePool(pMDL);
    }

    if (fileData)
        ExFreePoolWithTag(fileData, 'xxxx');

    if (NT_SUCCESS(status))
        DPRINT("LoadDriver: %s: Successfully mapped '%wZ' at 0x%p\n", __FUNCTION__, pPath, imageSection);

    PsTerminateSystemThread(status);
    return status;
}

/*\\??\\c:test.sys*/
NTSTATUS LeiLeiMMapDriver(IN PGLOBAL_INFO pInfo)
{
    HANDLE hThread = NULL;
    CLIENT_ID clientID = { 0 };
    OBJECT_ATTRIBUTES obAttr = { 0 };
    PETHREAD pThread = NULL;
    OBJECT_HANDLE_INFORMATION handleInfo = { 0 };

    InitializeObjectAttributes(&obAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    ASSERT(pInfo != NULL);
    if (pInfo == NULL)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &obAttr, NULL, &clientID, &LeiLeiMapWorker, pInfo);
    if (!NT_SUCCESS(status))
    {
        DPRINT("LoadDriver: %s: Failed to create worker thread. Status: 0x%X\n", __FUNCTION__, status);
        return status;
    }

    // Wait on worker thread
    status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pThread, &handleInfo);
    if (NT_SUCCESS(status))
    {
        THREAD_BASIC_INFORMATION info = { 0 };
        ULONG bytes = 0;

        status = KeWaitForSingleObject(pThread, Executive, KernelMode, TRUE, NULL);
        status = ZwQueryInformationThread(hThread, ThreadBasicInformation, &info, sizeof(info), &bytes);
        if (NT_SUCCESS(status));
        status = info.ExitStatus;
    }

    if (pThread)
        ObDereferenceObject(pThread);

    return status;
}