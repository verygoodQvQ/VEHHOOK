// VEHHook.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include "VHook.h"

void WINAPI  OpenProcessHook(PCONTEXT_INFO contextInfo)
{
	printf("xxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n");
	return;
}
 
int main()
{
	HMODULE hModule = GetModuleHandleA("kernel32.dll");

	ULONG OpenProcessp = (ULONG)GetProcAddress(hModule, "OpenProcess");
 	if (InitVHook())
	{
		AddHook((ULONG)OpenProcessp, OpenProcessHook);
	}
	OpenProcess(NULL, NULL, NULL);
	system("pause");
    return 0;
}

