#pragma once

#include "helper.h"

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