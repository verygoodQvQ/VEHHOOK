#include "VHook.h"
#include <map>
#include <vector>
#include <ImageHlp.h>
#include "AsmCode.h"
//std::map<
typedef struct _vehNode
{
	LIST_ENTRY entry;
	ULONG isEncode;
	ULONG encodeFunction;

}vehNode;

typedef PVOID(WINAPI *RtlPcToFileHeaderProc)(PVOID PcValue, PVOID *BaseOfImage);

RtlPcToFileHeaderProc RtlPcToFileHeaderX = NULL;

typedef struct _HookInfo
{
	ULONG_PTR HookAddr;
	ULONG_PTR newAddr;
	ULONG_PTR OrgMouduleBase;
	ULONG_PTR OrgMouduleSize;
	ULONG_PTR NewMouduleBase;
	char OrgiCode[20];
	ULONG OrgiLen;
	ULONG_PTR DispatchFuncCall;
	bool isHook;

}HookInfo,*PHookInfo;



std::map<ULONG_PTR, std::vector<HookInfo>> gHookinfoMaps;

int GetInsLen(ULONG_PTR hookAddr, int minLen)
{
	int len = 0;
	do 
	{
		int temp =insn_len_x86_32((PVOID)hookAddr);
		hookAddr = temp + hookAddr;
		len += temp;
	} while (len < minLen);

	return len;
}

LONG NTAPI VHookException(PEXCEPTION_POINTERS ExceptionInfo)
{
	if(ExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000005)
	{
		PVOID imageBase = NULL;
		RtlPcToFileHeaderX(ExceptionInfo->ExceptionRecord->ExceptionAddress,&imageBase);
		if (imageBase)
		{
			std::vector<HookInfo> & infos = gHookinfoMaps[(ULONG)imageBase];
			HookInfo findInfo = {0};
			if (!infos.empty())
			{
				for (int i = 0; i < infos.size(); i++)
				{
					HookInfo& info =infos[i];
					ULONG startAddr = ((ULONG)ExceptionInfo->ExceptionRecord->ExceptionAddress & (~0xFFF));
					ULONG startAddr2  = ((ULONG)info.HookAddr & (~0xFFF));
					if (startAddr == startAddr2)
					{
						findInfo = info;
						break;
					}
				}
	
				//找到了
				if (findInfo.HookAddr)
				{
					ExceptionInfo->ContextRecord->Eip =  (ULONG)ExceptionInfo->ExceptionRecord->ExceptionAddress - findInfo.OrgMouduleBase + findInfo.NewMouduleBase;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool InitVHook()
{

	vehNode * node = (vehNode *)AddVectoredExceptionHandler(TRUE, VHookException);
	
	gHookinfoMaps.clear();

	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	
	RtlPcToFileHeaderX = (RtlPcToFileHeaderProc)GetProcAddress(hModule, "RtlPcToFileHeader");
	//if (node)
	//{
	//	node->isEncode = 100;
	//	return true;
	//}
	
	return true;
}


bool AddHook(ULONG_PTR HookAddr, HookCallback newAddr)
{
	

	
	
	bool isRet = false;

	HookInfo info;
	info.HookAddr = HookAddr;
	info.newAddr = (ULONG_PTR)newAddr;
	ULONG_PTR imageBase = NULL;
	
	if (RtlPcToFileHeaderX((PVOID)HookAddr, (PVOID *)&imageBase))
	{
		std::vector<HookInfo> infos = gHookinfoMaps[imageBase];

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imageBase + pDos->e_lfanew);

		info.OrgMouduleBase = imageBase;
		info.OrgMouduleSize = pNts->OptionalHeader.SizeOfImage;


  		if (infos.empty())
		{
         	info.NewMouduleBase = (ULONG_PTR)malloc(info.OrgMouduleSize);

			int count = info.OrgMouduleSize >> 12;
			int i = 0;
			do 
			{
				ULONG size = 0;
				ReadProcessMemory(GetCurrentProcess(),
					(PVOID)(info.OrgMouduleBase + i * USN_PAGE_SIZE), (PVOID)(info.NewMouduleBase + i * USN_PAGE_SIZE), USN_PAGE_SIZE,&size);
				i++;
				count--;
			} while (count != 0);
			

			ULONG pro = 0;
			VirtualProtect((PVOID)info.NewMouduleBase, info.OrgMouduleSize, PAGE_EXECUTE_READWRITE, &pro);

		}
		else 
		{
			info.NewMouduleBase = infos[0].NewMouduleBase;
		}

	

		//修改页属性
		ULONG pageOffset = HookAddr & 0xFFF;
		ULONG page = HookAddr & (~0xFFF);
		ULONG moduleOffset = HookAddr - imageBase;

		//求得模块HOOK地址
		ULONG targetHookAddr = info.NewMouduleBase + moduleOffset;

		//获取长度 保存原字节
		int insLen = GetInsLen(targetHookAddr, 5);

		memcpy(info.OrgiCode, (PUCHAR)targetHookAddr, insLen);
		info.OrgiLen = insLen;

		/*
			0175E6AF  <模块入口点>                60                                          pushad                                                                     
			0175E6B0                              9C                                          pushfd                                                                     
			0175E6B1                              8D 04 24                                    lea  eax,dword ptr ss:[esp]                                                
			0175E6B4                              B9 78 56 34 12                              mov  ecx,0x12345678                                                        
			0175E6B9                              50                                          push  eax                                                                  
			0175E6BA                              FF D1                                       call  ecx                                                                  
			0175E6BC                              9D                                          popfd                                                                      
			0175E6BD                              61                                          popad                                                                      
			0175E6BE                              90                                          nop                                                                        
			0175E6BF                              90                                          nop                                                                        
			0175E6C0                              90                                          nop                                                                        
			0175E6C1                              90                                          nop                                                                        
			0175E6C2                              90                                          nop                                                                        
			0175E6C3                              90                                          nop                                                                        
			0175E6C4                              90                                          nop                                                                        
			0175E6C5                              90                                          nop                                                                        
			0175E6C6                              90                                          nop                                                                        
			0175E6C7                              90                                          nop                                                                        
			0175E6C8                              90                                          nop                                                                        
			0175E6C9                              90                                          nop                                                                        
			0175E6CA                              68 78 45 23 01                              push  0x01234578                                                           
			0175E6CF                              C3                                          retn                                                                       

		*/

		char bufcode[] = 
		{
			0x60,
			0x9C,
			0x8D,0x04,0x24,
			0xB9,0x78,0x56,0x34,0x12,
			0x50,
			0xFF,0xD1,
			0x9D,
			0x61,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x68,0x78,0x45,0x23,0x01,
			0xC3
		};

		//制作派发流程
		ULONG pro = 0;

		info.DispatchFuncCall = (ULONG_PTR)malloc(sizeof(bufcode));
		VirtualProtect((PVOID)info.DispatchFuncCall, sizeof(bufcode), PAGE_EXECUTE_READWRITE, &pro);

		*(PULONG_PTR)&bufcode[6] = (ULONG_PTR)newAddr;
		*(PULONG_PTR)&bufcode[28] = targetHookAddr + insLen;
		memcpy(&bufcode[15], info.OrgiCode, insLen);
		
		memcpy((PVOID)info.DispatchFuncCall, bufcode, sizeof(bufcode));


		char jmpCode[5] = {0xe9,0};
		*(PULONG_PTR)&jmpCode[1] = info.DispatchFuncCall - targetHookAddr - 5;

		//开始挂页
		memcpy((PVOID)targetHookAddr, jmpCode, 5);

		infos.push_back(info); 

		isRet = true;

		info.isHook = isRet;

		gHookinfoMaps[imageBase] = infos;
		
		//int y = 0;
		//int x1 = y / 0;
		//MessageBoxA(NULL, NULL, NULL, NULL);
		bool x = VirtualProtect((PVOID)page, USN_PAGE_SIZE, PAGE_READONLY, &pro);
		
		
		//memset((PVOID)info.NewMouduleBase, 0, info.OrgMouduleSize);
		
		
	}


	return isRet;
	
}