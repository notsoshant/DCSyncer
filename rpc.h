#pragma once

#include "globals.h"

#define RPC_EXCEPTION (RpcExceptionCode() != STATUS_ACCESS_VIOLATION) && \
	(RpcExceptionCode() != STATUS_DATATYPE_MISALIGNMENT) && \
	(RpcExceptionCode() != STATUS_PRIVILEGED_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_ILLEGAL_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_BREAKPOINT) && \
	(RpcExceptionCode() != STATUS_STACK_OVERFLOW) && \
	(RpcExceptionCode() != STATUS_IN_PAGE_ERROR) && \
	(RpcExceptionCode() != STATUS_ASSERTION_FAILURE) && \
	(RpcExceptionCode() != STATUS_STACK_BUFFER_OVERRUN) && \
	(RpcExceptionCode() != STATUS_GUARD_PAGE_VIOLATION)

typedef void (*PGENERIC_RPC_FREE) (IN handle_t pHandle, IN PVOID pObject);

typedef struct RPC_FCNSTRUCT {
	PVOID addr;
	size_t size;
} RPC_FCNSTRUCT, * PRPC_FCNSTRUCT;

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR* p);

void Generic_Free(PVOID data, PGENERIC_RPC_FREE fFree);

BOOL createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE* hBinding, void (RPC_ENTRY* RpcSecurityCallback)(void*));
BOOL deleteBinding(RPC_BINDING_HANDLE* hBinding);
