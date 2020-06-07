#pragma once

#include "globals.h"

typedef char ASN1char_t;
typedef struct ASN1encoding_s* ASN1encoding_t;

typedef struct {
	unsigned short length;
	unsigned char* value;
} OssEncodedOID;

extern ASN1_PUBLIC BOOL ASN1API ASN1BERDotVal2Eoid(__in ASN1encoding_t pEncoderInfo, __in const ASN1char_t* dotOID, __out OssEncodedOID* encodedOID);

BOOL DotVal2Eoid(__in const ASN1char_t* dotOID, __out OssEncodedOID* encodedOID);
void freeEnc(void* pBuf);

void print_msg(PCWCHAR format, ...);
BOOL string_copy(LPWSTR* dst, LPCWSTR src);
BOOL getSidDomainFromName(PCWSTR pName, PSID* pSid, PWSTR* pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);
