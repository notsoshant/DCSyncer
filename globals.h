#pragma once

#include<Windows.h>
#include<rpc.h>
#include<rpcndr.h>
#include<stdio.h>

#include "output.h"

#define	PRINT_INFO(...)			(print_msg(L"[i] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_ERROR(...)		(print_msg(L"[-] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_SUCCESS(...)		(print_msg(L"[+] " TEXT(__FUNCTION__) L": " __VA_ARGS__))
#define	PRINT_NORMAL(...)		(print_msg(__VA_ARGS__))

