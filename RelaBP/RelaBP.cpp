#include <Windows.h>
#include "pluginsdk/_plugin_types.h"
#include "pluginsdk/_plugins.h"
#include "pluginsdk/jansson/jansson.h"
#include <cstring>
#include <vector>

#pragma comment(lib, "pluginsdk/x64dbg.lib")
#pragma comment(lib, "pluginsdk/x64bridge.lib")
#pragma comment(lib, "pluginsdk/jansson/jansson_x64.lib")


#define PLUGIN_NAME "RelaBP"
#define PLUGIN_VERSION 1
#define CONFIG_NAME "relabp.json"
#define PLUGIN_DIR "plugins\\"


#define dprintf(x, ...) _plugin_logprintf("[" PLUGIN_NAME "] " x, __VA_ARGS__)
#define PLUG_EXPORT extern "C" __declspec(dllexport)


int g_pluginHandle;
int g_hMenuDisasm;

void* g_shellCodeBase = NULL;
ULONG g_shellCodeSize = 0;
HANDLE g_hDbgProcess = NULL;
//////////////////////////////////////////////////////////////////////////

enum
{
	MENU_DISASM_SETINFO,
	MENU_DISASM_RESTOREBP,
	MENU_DISASM_SET_AND_RESTORE,
};



bool GetConfigFilePath(char* szPath, int nLen)
{
	bool bRet = false;
	do 
	{
		if (!szPath || !nLen)
		{
			break;
		}

		HMODULE hModule = GetModuleHandleW(NULL);
		if (!hModule)
		{
			break;
		}

		if (!GetModuleFileNameA(hModule, szPath, nLen))
		{
			break;
		}

		char* pPos = strrchr(szPath, '\\');
		*(pPos + 1) = '\0';
		strcat(szPath, PLUGIN_DIR);
		strcat(szPath, CONFIG_NAME);

		bRet = true;
	} while (false);
	return bRet;
}


bool SaveToJson(const std::vector<ULONG_PTR>& vtBpList)
{
	bool bRet = false;
	do 
	{
		if (vtBpList.empty())
		{
			break;
		}

		json_t* root = json_array();
		if (!root)
		{
			break;
		}

		for (auto addr : vtBpList)
		{
			json_t* val = json_integer((unsigned long long)addr);
			json_array_append_new(root, val);
		}
		
		char szPath[MAX_PATH] = { 0 };
		if (!GetConfigFilePath(szPath, MAX_PATH))
		{
			break;
		}

		dprintf("save relative breakpoints to %s", szPath);
		if (json_dump_file(root, szPath, 0) != 0)
		{
			break;
		}

		json_decref(root);
		bRet = true;
	} while (false);
	return bRet;
}

bool ReadFromJson(std::vector<ULONG_PTR>& vtBpList)
{
	bool bRet = false;
	do 
	{
		vtBpList.clear();

		char szPath[MAX_PATH] = { 0 };
		if (!GetConfigFilePath(szPath, MAX_PATH))
		{
			break;
		}

		dprintf("load relative breakpoints from %s", szPath);
		json_error_t error;
		json_t* root = json_load_file(szPath, 0, &error);
		if (!root)
		{
			dprintf("failed to load config %s", szPath);
			break;
		}

		if (!json_is_array(root))
		{
			break;
		}

		for (int i = 0; i != json_array_size(root); ++i)
		{
			json_t* val = json_array_get(root, i);
			if (!json_is_integer(val))
			{
				break;
			}

			ULONG_PTR addr = json_integer_value(val);
			vtBpList.push_back(addr);
		}

		json_decref(root);
		bRet = true;
	} while (false);
	return bRet;
}

bool SaveBpList()
{
	bool bRet = false;
	do 
	{
		if (!g_shellCodeBase || !g_shellCodeSize)
		{
			dprintf("set shellcode info first!");
			break;
		}

		BPMAP bpMap;
		if (!DbgGetBpList(bp_normal, &bpMap))
		{
			dprintf("%s", "DbgGetBpList failed.");
			break;
		}

		ULONG_PTR nShellcodeBegin = (ULONG_PTR)g_shellCodeBase;
		ULONG_PTR nShellcodeEnd = (ULONG_PTR)g_shellCodeBase + g_shellCodeSize;

		int bpCount = bpMap.count;
		std::vector<ULONG_PTR> vtBpList;

		for (int i = 0; i != bpCount; ++i)
		{
			ULONG_PTR nBpAddr = bpMap.bp[i].addr;
			if (nBpAddr < nShellcodeBegin || nBpAddr > nShellcodeEnd)
			{
				continue;
			}

			ULONG_PTR nRelaAddr = (nBpAddr - (duint)g_shellCodeBase);
			vtBpList.push_back(nRelaAddr);
		}

		if (!SaveToJson(vtBpList))
		{
			break;
		}

		bRet = true;
	} while (false);
	return bRet;
}


bool RestoreBpList()
{
	bool bRet = false;
	do 
	{
		if (!g_shellCodeBase)
		{
			dprintf("set shellcode info first!");
			break;
		}

		std::vector<ULONG_PTR> vtBpList;
		if (!ReadFromJson(vtBpList))
		{
			dprintf("load bp list from json failed.");
			break;
		}

		ULONG_PTR nShellcodeBegin = (ULONG_PTR)g_shellCodeBase;
		ULONG_PTR nShellcodeEnd = (ULONG_PTR)g_shellCodeBase + g_shellCodeSize;

		char szCmd[256] = { 0 };
		for (auto addr : vtBpList)
		{
			ULONG_PTR bpAddr = addr + (ULONG_PTR)nShellcodeBegin;
			sprintf(szCmd, "bp 0x%llx", bpAddr);
			DbgCmdExecDirect(szCmd);
		}

		bRet = true;
	} while (false);
	return bRet;
}


void SetShellcodeInfo()
{
	do 
	{
		REGDUMP regDump;
		size_t nLen = sizeof(REGDUMP);
		if (!DbgGetRegDumpEx(&regDump, nLen))
		{
			dprintf("Get reg dump failed.");
			break;
		}

		if (!g_hDbgProcess)
		{
			break;
		}

		// yeah, this should be in config or menu though..
		void* pEntryPoint = (void*)regDump.regcontext.cax;

		MEMORY_BASIC_INFORMATION memInfo;
		if (!VirtualQueryEx(g_hDbgProcess, pEntryPoint, &memInfo, sizeof(memInfo)))
		{
			break;
		}

		g_shellCodeBase = memInfo.AllocationBase;
		g_shellCodeSize = memInfo.RegionSize;

		dprintf("shellcode base is 0x%llx", (ULONG_PTR)g_shellCodeBase);
	} while (false);
}


void SetScInfoAndRestoreBp()
{
	SetShellcodeInfo();
	RestoreBpList();
}


void OnBreadPoint(CBTYPE cbType, void* callbackInfo)
{
	PLUG_CB_BREAKPOINT* pBpInfo = (PLUG_CB_BREAKPOINT*)callbackInfo;
	do
	{
		if (!pBpInfo)
		{
			break;
		}


	} while (false);
}

void OnProcessCreate(CBTYPE cbType, void* callbackInfo)
{
	do
	{
		PLUG_CB_CREATEPROCESS* pCreateInfo = (PLUG_CB_CREATEPROCESS*)callbackInfo;
		if (!pCreateInfo)
		{
			break;
		}

		g_hDbgProcess = pCreateInfo->CreateProcessInfo->hProcess;

	} while (false);
}

void OnProcessExit(CBTYPE cbType, void* callbackInfo)
{
	do 
	{
		PLUG_CB_EXITPROCESS* pExitInfo = (PLUG_CB_EXITPROCESS*)callbackInfo;
		if (!pExitInfo)
		{
			break;
		}

		dprintf("save relative breakpoints.");
		SaveBpList();
	} while (false);
}


PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
	dprintf("RelaBP loaded.\n");
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
	g_shellCodeBase = NULL;
	g_shellCodeSize = 0;
	g_hDbgProcess = NULL;
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch (info->hEntry)
	{
	case MENU_DISASM_SETINFO:
		SetShellcodeInfo();
		break;
	case MENU_DISASM_RESTOREBP:
		RestoreBpList();
		break;
	case MENU_DISASM_SET_AND_RESTORE:
		SetScInfoAndRestoreBp();
		break;
	default:
		break;
	}
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
	initStruct->pluginVersion = PLUGIN_VERSION;
	initStruct->sdkVersion = PLUG_SDKVERSION;
	strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
	g_pluginHandle = initStruct->pluginHandle;

	_plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, OnBreadPoint);
	_plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, OnProcessCreate);
	_plugin_registercallback(g_pluginHandle, CB_EXITPROCESS, OnProcessExit);
	return true;
}

PLUG_EXPORT bool plugstop()
{
	return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
	g_hMenuDisasm = setupStruct->hMenuDisasm;
	_plugin_menuaddentry(g_hMenuDisasm, MENU_DISASM_SETINFO, "&Set shellcode info");
	_plugin_menuaddentry(g_hMenuDisasm, MENU_DISASM_RESTOREBP, "&Restore breakpoints");
	_plugin_menuaddentry(g_hMenuDisasm, MENU_DISASM_SET_AND_RESTORE, "&Set info then restore bp");
}