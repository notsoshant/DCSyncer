#pragma once

#include "globals.h"

#define CALG_CRC32	(ALG_CLASS_HASH | ALG_TYPE_ANY | 0)

#define	MD5_DIGEST_LENGTH	16
#define LM_NTLM_HASH_LENGTH	16

#define RtlDecryptDES2blocks1DWORD	SystemFunction025
#define RtlEncryptDecryptRC4		SystemFunction032

typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_INITIALIZE) (DWORD unk0, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_SUM) (PVOID pContext, DWORD Size, LPCVOID Buffer);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_FINALIZE) (PVOID pContext, PVOID Buffer);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_CHECKSUM_INITIALIZEEX) (LPCVOID Key, DWORD KeySize, DWORD KeyUsage, PVOID* pContext);

typedef struct _MD5_CTX {
	DWORD count[2];
	DWORD state[4];
	BYTE buffer[64];
	BYTE digest[MD5_DIGEST_LENGTH];
} MD5_CTX, * PMD5_CTX;

typedef struct _CRYPTO_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PBYTE Buffer;
} CRYPTO_BUFFER, * PCRYPTO_BUFFER;

typedef struct _KERB_CHECKSUM {
	LONG Type;
	DWORD Size;
	DWORD Flag;
	PKERB_CHECKSUM_INITIALIZE Initialize;
	PKERB_CHECKSUM_SUM Sum;
	PKERB_CHECKSUM_FINALIZE Finalize;
	PKERB_CHECKSUM_FINISH Finish;
	PKERB_CHECKSUM_INITIALIZEEX InitializeEx;
	PVOID unk0_null;
} KERB_CHECKSUM, * PKERB_CHECKSUM;

extern VOID WINAPI MD5Init(PMD5_CTX pCtx);
extern VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
extern VOID WINAPI MD5Final(PMD5_CTX pCtx);

BOOL crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
