#pragma once

#include "crypto.h"

BOOL crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hashLen;
	PBYTE buffer;
	PKERB_CHECKSUM pCheckSum;
	PVOID Context;

	if (algid == CALG_CRC32)
	{
		if ((hashWanted == sizeof(DWORD)) && NT_SUCCESS(CDLocateCheckSum(KERB_CHECKSUM_REAL_CRC32, &pCheckSum)))
		{
			if (NT_SUCCESS(pCheckSum->Initialize(0, &Context)))
			{
				pCheckSum->Sum(Context, dataLen, data);
				status = NT_SUCCESS(pCheckSum->Finalize(Context, hash));
				pCheckSum->Finish(&Context);
			}
		}
	}
	else if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hProv, algid, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, (LPCBYTE)data, dataLen, 0))
			{
				if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &hashLen, 0))
				{
					if (buffer = (PBYTE)LocalAlloc(LPTR, hashLen))
					{
						status = CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0);
						RtlCopyMemory(hash, buffer, min(hashLen, hashWanted));
						LocalFree(buffer);
					}
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}
