#pragma once

#define SECURITY_WIN32

#include<Windows.h>
#include<rpc.h>
#include<rpcndr.h>
#include<stdio.h>
#include<NTSecAPI.h>
#include<DsGetDC.h>
#include<sspi.h>
#include<Midles.h>
#include<sddl.h>
#include<msasn1.h>
#include<string.h>

#include "helper.h"
#include "crypto.h"

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef CONST UNICODE_STRING* PCUNICODE_STRING;

extern NTSTATUS WINAPI RtlGUIDFromString(IN PCUNICODE_STRING GuidString, OUT GUID* Guid);
extern DWORD WINAPI NetApiBufferFree(IN LPVOID Buffer);
extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);


#define	PRINT_INFO(...)			(print_msg(L"[i] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_ERROR(...)		(print_msg(L"[x] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_SUCCESS(...)		(print_msg(L"[+] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_NORMAL(...)		(print_msg(__VA_ARGS__))

