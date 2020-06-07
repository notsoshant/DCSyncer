#pragma once

#include "helper.h"

ASN1module_t hASN1Module = NULL;
ASN1encoding_t ASN1enc = NULL;
ASN1decoding_t ASN1dec = NULL;

static const ASN1GenericFun_t encdecfreefntab[] = { NULL };
static const ASN1uint32_t sizetab[] = { 0 };
BOOL asn1_init()
{
	BOOL status = FALSE;
	int ret;
	if (hASN1Module = ASN1_CreateModule(ASN1_THIS_VERSION, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 1, encdecfreefntab, encdecfreefntab, (const ASN1FreeFun_t*)encdecfreefntab, sizetab, 'iwik'))
	{
		ret = ASN1_CreateEncoder(hASN1Module, &ASN1enc, NULL, 0, NULL);
		if (ASN1_FAILED(ret))
		{
			PRINT_ERROR(L"ASN1_CreateEncoder: %i\n", ret);
			ASN1enc = NULL;
		}
		else
		{
			ret = ASN1_CreateDecoder(hASN1Module, &ASN1dec, NULL, 0, NULL);
			if (ASN1_FAILED(ret))
			{
				PRINT_ERROR(L"ASN1_CreateDecoder: %i\n", ret);
				ASN1dec = NULL;
			}
		}
	}
	else PRINT_ERROR(L"ASN1_CreateModule\n");

	status = hASN1Module && ASN1enc && ASN1dec;
	if (!status)
		asn1_term();
	return status;
}

void asn1_term()
{
	if (ASN1dec)
	{
		ASN1_CloseDecoder(ASN1dec);
		ASN1dec = NULL;
	}
	if (ASN1enc)
	{
		ASN1_CloseEncoder(ASN1enc);
		ASN1enc = NULL;
	}
	if (hASN1Module)
	{
		ASN1_CloseModule(hASN1Module);
		hASN1Module = NULL;
	}
}

BOOL DotVal2Eoid(__in const ASN1char_t* dotOID, __out OssEncodedOID* encodedOID)
{
	BOOL status = FALSE;
	if (ASN1enc && dotOID && encodedOID)
	{
		encodedOID->length = 0;
		encodedOID->value = NULL;
		status = ASN1BERDotVal2Eoid(ASN1enc, dotOID, encodedOID);
	}
	return status;
}

void freeEnc(void* pBuf)
{
	if (ASN1enc && pBuf)
		ASN1_FreeEncoded(ASN1enc, pBuf);
}

void print_msg(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	vwprintf(format, args);
	fflush(stdout);
	va_end(args);
}

BOOL string_copy(LPWSTR* dst, LPCWSTR src)
{
	BOOL status = FALSE;
	size_t size;
	if (src && dst && (size = wcslen(src)))
	{
		size = (size + 1) * sizeof(wchar_t);
		if (*dst = (LPWSTR)LocalAlloc(LPTR, size))
		{
			RtlCopyMemory(*dst, src, size);
			status = TRUE;
		}
	}
	return status;
}

BOOL getSidDomainFromName(PCWSTR pName, PSID* pSid, PWSTR* pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system)
{
	BOOL result = FALSE;
	SID_NAME_USE sidNameUse;
	PSID_NAME_USE peUse = pSidNameUse ? pSidNameUse : &sidNameUse;
	DWORD cbSid = 0, cchReferencedDomainName = 0;

	if (!LookupAccountName(system, pName, NULL, &cbSid, NULL, &cchReferencedDomainName, peUse) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if (*pSid = (PSID)LocalAlloc(LPTR, cbSid * sizeof(wchar_t)))
		{
			if (*pDomain = (PWSTR)LocalAlloc(LPTR, cchReferencedDomainName * sizeof(wchar_t)))
			{
				result = LookupAccountName(system, pName, *pSid, &cbSid, *pDomain, &cchReferencedDomainName, peUse);
				if (!result)
					*pDomain = (PWSTR)LocalFree(*pDomain);
			}
			if (!result)
				*pSid = (PSID)LocalFree(*pSid);
		}
	}
	return result;
}

void displaySID(IN PSID pSid)
{
	LPSTR stringSid;
	if (ConvertSidToStringSidA(pSid, &stringSid))
	{
		printf("%s", stringSid);
		LocalFree(stringSid);
	}
}

PCWCHAR WPRINTF_TYPES[] =
{
	L"%02x",		// WPRINTF_HEX_SHORT
	L"%02x ",		// WPRINTF_HEX_SPACE
	L"0x%02x, ",	// WPRINTF_HEX_C
	L"\\x%02x",		// WPRINTF_HEX_PYTHON
};

void wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
	DWORD i, sep = flags >> 16;
	PCWCHAR pType = WPRINTF_TYPES[flags & 0x0000000f];

	if ((flags & 0x0000000f) == 2)
		PRINT_NORMAL(L"\nBYTE data[] = {\n\t");

	for (i = 0; i < cbData; i++)
	{
		PRINT_NORMAL(pType, ((LPCBYTE)lpData)[i]);
		if (sep && !((i + 1) % sep))
		{
			PRINT_NORMAL(L"\n");
			if ((flags & 0x0000000f) == 2)
				PRINT_NORMAL(L"\t");
		}
	}
	if ((flags & 0x0000000f) == 2)
		PRINT_NORMAL(L"\n};\n");
}