#pragma once

#include "globals.h"

void print_msg(PCWCHAR format, ...);
BOOL string_copy(LPWSTR* dst, LPCWSTR src);
BOOL getSidDomainFromName(PCWSTR pName, PSID* pSid, PWSTR* pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system);
