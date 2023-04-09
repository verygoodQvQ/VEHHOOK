#pragma once
#include <Windows.h>

typedef struct _CONTEXT_INFO
{

	ULONG_PTR efl;
	ULONG_PTR _edi;
	ULONG_PTR _esi;
	ULONG_PTR _ebp;
	ULONG_PTR _esp;
	ULONG_PTR _ebx;
	ULONG_PTR _edx;
	ULONG_PTR _ecx;
	ULONG_PTR _eax;

}CONTEXT_INFO, *PCONTEXT_INFO;

bool InitVHook();

typedef void (WINAPI * HookCallback)(PCONTEXT_INFO contextInfo);

bool AddHook(ULONG_PTR HookAddr, HookCallback newAddr);