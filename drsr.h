#pragma once

#include "globals.h"
#include "rpc.h"

#define DRS_WRIT_REP								0x00000010
#define DRS_INIT_SYNC								0x00000020
#define DRS_FULL_SYNC_NOW							0x00008000
#define DRS_SYNC_URGENT								0x00080000
#define DRS_NEVER_SYNCED							0x00200000

#define DRS_EXT_GETCHGREPLY_V6						0x04000000
#define DRS_EXT_STRONG_ENCRYPTION					0x00008000
#define DRS_EXT_GETCHGREQ_V8						0x01000000

#define szOID_objectclass					"2.5.4.0"
#define szOID_hasMasterNCs					"1.2.840.113556.1.2.14"
#define szOID_dMDLocation					"1.2.840.113556.1.2.36"
#define szOID_isDeleted						"1.2.840.113556.1.2.48"
#define szOID_invocationId					"1.2.840.113556.1.2.115"

#define szOID_ANSI_name						"1.2.840.113556.1.4.1"
#define szOID_objectGUID					"1.2.840.113556.1.4.2"

#define szOID_ANSI_sAMAccountName			"1.2.840.113556.1.4.221"
#define szOID_ANSI_userPrincipalName		"1.2.840.113556.1.4.656"
#define szOID_ANSI_servicePrincipalName		"1.2.840.113556.1.4.771"
#define szOID_ANSI_sAMAccountType			"1.2.840.113556.1.4.302"
#define szOID_ANSI_userAccountControl		"1.2.840.113556.1.4.8"
#define szOID_ANSI_accountExpires			"1.2.840.113556.1.4.159"
#define szOID_ANSI_pwdLastSet				"1.2.840.113556.1.4.96"
#define szOID_ANSI_objectSid				"1.2.840.113556.1.4.146"
#define szOID_ANSI_sIDHistory				"1.2.840.113556.1.4.609"
#define szOID_ANSI_unicodePwd				"1.2.840.113556.1.4.90"
#define szOID_ANSI_ntPwdHistory				"1.2.840.113556.1.4.94"
#define szOID_ANSI_dBCSPwd					"1.2.840.113556.1.4.55"
#define szOID_ANSI_lmPwdHistory				"1.2.840.113556.1.4.160"
#define szOID_ANSI_supplementalCredentials	"1.2.840.113556.1.4.125"

#define szOID_ANSI_trustPartner				"1.2.840.113556.1.4.133"
#define szOID_ANSI_trustAuthIncoming		"1.2.840.113556.1.4.129"
#define szOID_ANSI_trustAuthOutgoing		"1.2.840.113556.1.4.135"

#define szOID_ANSI_currentValue				"1.2.840.113556.1.4.27"

#define szOID_options						"1.2.840.113556.1.4.307"
#define szOID_systemFlags					"1.2.840.113556.1.4.375"
#define szOID_ldapServer_show_deleted		"1.2.840.113556.1.4.417"
#define szOID_serverReference				"1.2.840.113556.1.4.515"
#define szOID_msDS_Behavior_Version			"1.2.840.113556.1.4.1459"
#define szOID_msDS_ReplicationEpoch			"1.2.840.113556.1.4.1720"
#define szOID_msDS_HasDomainNCs				"1.2.840.113556.1.4.1820"
#define szOID_msDS_hasMasterNCs				"1.2.840.113556.1.4.1836"
#define szOID_isRecycled					"1.2.840.113556.1.4.2058"

#define szOID_ANSI_nTDSDSA					"1.2.840.113556.1.5.7000.47"

#define FreeDRS_MSG_GETCHGREPLY_V6(pObject) Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_GETCHGREPLY_V6_Free)
#define FreeDRS_MSG_CRACKREPLY_V1(pObject) Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_CRACKREPLY_V1_Free)
#define FreeDRS_MSG_DCINFOREPLY_V2(pObject) Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_DCINFOREPLY_V2_Free)

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void* DRS_HANDLE;

typedef struct _ms2Ddrsr_MIDL_TYPE_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[1757];
} ms2Ddrsr_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Ddrsr_MIDL_PROC_FORMAT_STRING {
	SHORT Pad;
	UCHAR Format[853];
} ms2Ddrsr_MIDL_PROC_FORMAT_STRING;

typedef enum {
	DS_UNKNOWN_NAME = 0,
	DS_FQDN_1779_NAME = 1,
	DS_NT4_ACCOUNT_NAME = 2,
	DS_DISPLAY_NAME = 3,
	DS_UNIQUE_ID_NAME = 6,
	DS_CANONICAL_NAME = 7,
	DS_USER_PRINCIPAL_NAME = 8,
	DS_CANONICAL_NAME_EX = 9,
	DS_SERVICE_PRINCIPAL_NAME = 10,
	DS_SID_OR_SID_HISTORY_NAME = 11,
	DS_DNS_DOMAIN_NAME = 12,

	DS_LIST_SITES = -1,
	DS_LIST_SERVERS_IN_SITE = -2,
	DS_LIST_DOMAINS_IN_SITE = -3,
	DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE = -4,
	DS_LIST_INFO_FOR_SERVER = -5,
	DS_LIST_ROLES = -6,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = -7,
	DS_MAP_SCHEMA_GUID = -8,
	DS_LIST_DOMAINS = -9,
	DS_LIST_NCS = -10,
	DS_ALT_SECURITY_IDENTITIES_NAME = -11,
	DS_STRING_SID_NAME = -12,
	DS_LIST_SERVERS_WITH_DCS_IN_SITE = -13,
	DS_USER_PRINCIPAL_NAME_FOR_LOGON = -14,
	DS_LIST_GLOBAL_CATALOG_SERVERS = -15,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX = -16,
	DS_USER_PRINCIPAL_NAME_AND_ALTSECID = -17,
} DS_NAME_FORMAT;

typedef enum {
	DS_NAME_NO_ERROR = 0,
	DS_NAME_ERROR_RESOLVING = 1,
	DS_NAME_ERROR_NOT_FOUND = 2,
	DS_NAME_ERROR_NOT_UNIQUE = 3,
	DS_NAME_ERROR_NO_MAPPING = 4,
	DS_NAME_ERROR_DOMAIN_ONLY = 5,
	DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6,
	DS_NAME_ERROR_TRUST_REFERRAL = 7
} DS_NAME_ERROR;

typedef enum {
	EXOP_FSMO_REQ_ROLE = 1,
	EXOP_FSMO_REQ_RID_ALLOC = 2,
	EXOP_FSMO_RID_REQ_ROLE = 3,
	EXOP_FSMO_REQ_PDC = 4,
	EXOP_FSMO_ABANDON_ROLE = 5,
	EXOP_REPL_OBJ = 6,
	EXOP_REPL_SECRETS = 7
} EXOP_REQ;

typedef struct _NT4SID {
	UCHAR Data[28];
} NT4SID;

typedef struct _DSNAME {
	ULONG structLen;
	ULONG SidLen;
	GUID Guid;
	NT4SID Sid;
	ULONG NameLen;
	WCHAR StringName[ANYSIZE_ARRAY];
} DSNAME;

typedef struct _USN_VECTOR {
	USN usnHighObjUpdate;
	USN usnReserved;
	USN usnHighPropUpdate;
} USN_VECTOR;

typedef struct _UPTODATE_CURSOR_V1 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
} UPTODATE_CURSOR_V1;

typedef struct _UPTODATE_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V1 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V1_EXT;

typedef struct _OID_t {
	unsigned int length;
	BYTE* elements;
} OID_t;

typedef struct _PrefixTableEntry {
	ULONG ndx;
	OID_t prefix;
} PrefixTableEntry;

typedef struct _SCHEMA_PREFIX_TABLE {
	DWORD PrefixCount;
	PrefixTableEntry* pPrefixEntry;
} SCHEMA_PREFIX_TABLE;

typedef struct _PARTIAL_ATTR_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cAttrs;
	ATTRTYP rgPartialAttr[ANYSIZE_ARRAY];
} PARTIAL_ATTR_VECTOR_V1_EXT;

typedef struct _PROPERTY_META_DATA_EXT {
	DWORD dwVersion;
	DSTIME timeChanged;
	UUID uuidDsaOriginating;
	USN usnOriginating;
} PROPERTY_META_DATA_EXT;

typedef struct _PROPERTY_META_DATA_EXT_VECTOR {
	DWORD cNumProps;
	PROPERTY_META_DATA_EXT rgMetaData[ANYSIZE_ARRAY];
} PROPERTY_META_DATA_EXT_VECTOR;

typedef struct _ATTRVAL {
	ULONG valLen;
	UCHAR* pVal;
} ATTRVAL;

typedef struct _ATTRVALBLOCK {
	ULONG valCount;
	ATTRVAL* pAVal;
} ATTRVALBLOCK;

typedef struct _ATTR {
	ATTRTYP attrTyp;
	ATTRVALBLOCK AttrVal;
} ATTR;

typedef struct _ATTRBLOCK {
	ULONG attrCount;
	ATTR* pAttr;
} ATTRBLOCK;

typedef struct _ENTINF {
	DSNAME* pName;
	ULONG ulFlags;
	ATTRBLOCK AttrBlock;
} ENTINF;

typedef struct _REPLENTINFLIST {
	struct _REPLENTINFLIST* pNextEntInf;
	ENTINF Entinf;
	BOOL fIsNCPrefix;
	UUID* pParentGuid;
	PROPERTY_META_DATA_EXT_VECTOR* pMetaDataExt;
} REPLENTINFLIST;

typedef struct _UPTODATE_CURSOR_V2 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
	DSTIME timeLastSyncSuccess;
} UPTODATE_CURSOR_V2;

typedef struct _UPTODATE_VECTOR_V2_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V2 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V2_EXT;

typedef struct _VALUE_META_DATA_EXT_V1 {
	DSTIME timeCreated;
	PROPERTY_META_DATA_EXT MetaData;
} VALUE_META_DATA_EXT_V1;

typedef struct _REPLVALINF_V1 {
	DSNAME* pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V1 MetaData;
} REPLVALINF_V1;

typedef struct _DRS_MSG_GETCHGREPLY_V6 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME* pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V2_EXT* pUpToDateVecSrc;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST* pObjects;
	BOOL fMoreData;
	ULONG cNumNcSizeObjects;
	ULONG cNumNcSizeValues;
	DWORD cNumValues;
	REPLVALINF_V1* rgValues;
	DWORD dwDRSError;
} DRS_MSG_GETCHGREPLY_V6;

typedef union _DRS_MSG_GETCHGREPLY {
	DRS_MSG_GETCHGREPLY_V6 V6;
} DRS_MSG_GETCHGREPLY;

typedef struct _DRS_MSG_GETCHGREQ_V8 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME* pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT* pUpToDateVecDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
	PARTIAL_ATTR_VECTOR_V1_EXT* pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT* pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V8;

typedef union _DRS_MSG_GETCHGREQ {
	DRS_MSG_GETCHGREQ_V8 V8;
} DRS_MSG_GETCHGREQ;

typedef struct _DRS_MSG_DCINFOREQ_V1 {
	WCHAR* Domain;
	DWORD InfoLevel;
} DRS_MSG_DCINFOREQ_V1;

typedef union _DRS_MSG_DCINFOREQ {
	DRS_MSG_DCINFOREQ_V1 V1;
} DRS_MSG_DCINFOREQ, * PDRS_MSG_DCINFOREQ;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_2W {
	WCHAR* NetbiosName;
	WCHAR* DnsHostName;
	WCHAR* SiteName;
	WCHAR* SiteObjectName;
	WCHAR* ComputerObjectName;
	WCHAR* ServerObjectName;
	WCHAR* NtdsDsaObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
	BOOL fIsGc;
	GUID SiteObjectGuid;
	GUID ComputerObjectGuid;
	GUID ServerObjectGuid;
	GUID NtdsDsaObjectGuid;
} DS_DOMAIN_CONTROLLER_INFO_2W;

typedef struct _DRS_MSG_DCINFOREPLY_V2 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_2W* rItems;
} DRS_MSG_DCINFOREPLY_V2;

typedef union _DRS_MSG_DCINFOREPLY {
	DRS_MSG_DCINFOREPLY_V2 V2;
} DRS_MSG_DCINFOREPLY;

typedef struct _DRS_EXTENSIONS {
	DWORD cb;
	BYTE rgb[ANYSIZE_ARRAY];
} DRS_EXTENSIONS;

typedef struct _DRS_EXTENSIONS_INT {
	DWORD cb;
	DWORD dwFlags;
	GUID SiteObjGuid;
	DWORD Pid;
	DWORD dwReplEpoch;
	DWORD dwFlagsExt;
	GUID ConfigObjGUID;
	DWORD dwExtCaps;
} DRS_EXTENSIONS_INT, * PDRS_EXTENSIONS_INT;

typedef struct _DRS_MSG_CRACKREQ_V1 {
	ULONG CodePage;
	ULONG LocaleId;
	DWORD dwFlags;
	DWORD formatOffered;
	DWORD formatDesired;
	DWORD cNames;
	WCHAR** rpNames;
} DRS_MSG_CRACKREQ_V1;

typedef struct _DS_NAME_RESULT_ITEMW {
	DWORD status;
	WCHAR* pDomain;
	WCHAR* pName;
} DS_NAME_RESULT_ITEMW, * PDS_NAME_RESULT_ITEMW;

typedef struct _DS_NAME_RESULTW {
	DWORD cItems;
	PDS_NAME_RESULT_ITEMW rItems;
} DS_NAME_RESULTW, * PDS_NAME_RESULTW;

typedef union _DRS_MSG_CRACKREQ {
	DRS_MSG_CRACKREQ_V1 V1;
} DRS_MSG_CRACKREQ;

typedef struct _DRS_MSG_CRACKREPLY_V1 {
	DS_NAME_RESULTW* pResult;
} DRS_MSG_CRACKREPLY_V1;

typedef union _DRS_MSG_CRACKREPLY {
	DRS_MSG_CRACKREPLY_V1 V1;
} DRS_MSG_CRACKREPLY;

void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1* _pType);
void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2* _pType);

void free_DRS_MSG_DCINFOREPLY_data(DWORD dcOutVersion, DRS_MSG_DCINFOREPLY* reply);
void free_DRS_MSG_CRACKREPLY_data(DWORD nameCrackOutVersion, DRS_MSG_CRACKREPLY* reply);
void free_DRS_MSG_GETCHGREPLY_data(DWORD dwOutVersion, DRS_MSG_GETCHGREPLY* reply);
void free_SCHEMA_PREFIX_TABLE_data(SCHEMA_PREFIX_TABLE* prefixTable);

void RPC_ENTRY RpcSecurityCallback(void* Context);

BOOL getDomainAndUserInfos(RPC_BINDING_HANDLE* hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID* DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID* UserGuid, DRS_EXTENSIONS_INT* pDrsExtensionsInt);
BOOL getDCBind(RPC_BINDING_HANDLE* hBinding, GUID* NtdsDsaObjectGuid, DRS_HANDLE* hDrs, DRS_EXTENSIONS_INT* pDrsExtensionsInt);
BOOL CrackName(DRS_HANDLE hDrs, DS_NAME_FORMAT NameFormat, LPCWSTR Name, DS_NAME_FORMAT FormatWanted, LPWSTR* CrackedName, LPWSTR* CrackedDomain);

BOOL MakeAttid(SCHEMA_PREFIX_TABLE* prefixTable, LPCSTR szOid, ATTRTYP* att, BOOL toAdd);

ULONG IDL_DRSBind(handle_t rpc_handle, UUID* puuidClientDsa, DRS_EXTENSIONS* pextClient, DRS_EXTENSIONS** ppextServer, DRS_HANDLE* phDrs);
ULONG IDL_DRSUnbind(DRS_HANDLE* phDrs);
ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ* pmsgIn, DWORD* pdwOutVersion, DRS_MSG_GETCHGREPLY* pmsgOut);
ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ* pmsgIn, DWORD* pdwOutVersion, DRS_MSG_CRACKREPLY* pmsgOut);
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ* pmsgIn, DWORD* pdwOutVersion, DRS_MSG_DCINFOREPLY* pmsgOut);
