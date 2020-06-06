#pragma once

#include "rpc.h"

void __RPC_USER ReadFcn(void* State, char** pBuffer, unsigned int* pSize)
{
	*pBuffer = (char*)((PRPC_FCNSTRUCT)State)->addr;
	((PRPC_FCNSTRUCT)State)->addr = *pBuffer + *pSize;
	((PRPC_FCNSTRUCT)State)->size -= *pSize;
}

void Generic_Free(PVOID pObject, PGENERIC_RPC_FREE fFree)
{
	RPC_STATUS rpcStatus;
	RPC_FCNSTRUCT UserState = { NULL, 0 };
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle); // for legacy
	if (NT_SUCCESS(rpcStatus))
	{
		RpcTryExcept
			fFree(pHandle, pObject);
		RpcExcept(EXCEPTION_EXECUTE_HANDLER)
			PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
			MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}

BOOL createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE* hBinding, void (RPC_ENTRY* RpcSecurityCallback)(void*))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = { RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH, RPC_C_QOS_IDENTITY_STATIC, ImpersonationType };
	DWORD szServer, szPrefix;
	LPWSTR fullServer = NULL;

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose((RPC_WSTR)uuid, (RPC_WSTR)ProtSeq, (RPC_WSTR)NetworkAddr, (RPC_WSTR)Endpoint, NULL, &StringBinding);
	if (rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if (rpcStatus == RPC_S_OK)
		{
			if (*hBinding)
			{
				if (AuthnSvc != RPC_C_AUTHN_NONE)
				{
					if (addServiceToNetworkAddr)
					{
						if (NetworkAddr && Service)
						{
							szServer = lstrlen(NetworkAddr) * sizeof(wchar_t);
							szPrefix = lstrlen(Service) * sizeof(wchar_t);
							if (fullServer = (LPWSTR)LocalAlloc(LPTR, szPrefix + sizeof(wchar_t) + szServer + sizeof(wchar_t)))
							{
								RtlCopyMemory(fullServer, Service, szPrefix);
								RtlCopyMemory((PBYTE)fullServer + szPrefix + sizeof(wchar_t), NetworkAddr, szServer);
								((PBYTE)fullServer)[szPrefix] = L'/';
							}
						}
						else PRINT_ERROR(L"Cannot add NetworkAddr & Service if NULL\n");
					}

					if (!addServiceToNetworkAddr || fullServer)
					{
						rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR)(fullServer ? fullServer : Service), RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth, RPC_C_AUTHZ_NONE, &SecurityQOS);
						if (rpcStatus == RPC_S_OK)
						{
							if (RpcSecurityCallback)
							{
								rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR)RpcSecurityCallback);
								status = (rpcStatus == RPC_S_OK);
								if (!status)
									PRINT_ERROR(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
							}
							else status = TRUE;
						}
						else PRINT_ERROR(L"RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					}
				}
				else status = TRUE;

				if (!status)
				{
					rpcStatus = RpcBindingFree(hBinding);
					if (rpcStatus == RPC_S_OK)
						*hBinding = NULL;
					else PRINT_ERROR(L"RpcBindingFree: 0x%08x (%u)\n", rpcStatus, rpcStatus);
				}
			}
			else PRINT_ERROR(L"No Binding!\n");
		}
		else PRINT_ERROR(L"RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus, rpcStatus);
		RpcStringFree(&StringBinding);
	}
	else PRINT_ERROR(L"RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);
	return status;
}
