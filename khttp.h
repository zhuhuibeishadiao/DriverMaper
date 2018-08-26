#ifndef __KHTTP__
#define __KHTTP__ 


#if defined(__cplusplus)
extern "C" {
#endif

NTSTATUS
HttpGetFile(
   __in char *HostAddress,                  // http server ip
   __in char *FileName,                     // remote file name
   __in char *HostName,                     // http server name 
   __in_opt char *LocalFile                 // [optinal] local file full path
   );

BOOLEAN
HttpIsResponseOk(__in PCHAR Buffer, __in ULONG BufferLen);

BOOLEAN
HttpCheck(
    __in char *HostAddress,                  // http server ip
    __in char *FileName,                     // remote file name
    __in char *HostName,                     // http server name 
    __in_opt char *LocalFile,                 // [optinal] local file full path
    __in USHORT Port,
    __in PEPROCESS PopWindowProcess,
    __in_opt WCHAR* szSymName
);

#if defined(__cplusplus)
}
#endif

//VOID
//DeinitSock();

#endif // __KSOCKET__
