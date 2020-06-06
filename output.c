#pragma once

#include "output.h"

void print_msg(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	vwprintf(format, args);
	fflush(stdout);
	va_end(args);
}