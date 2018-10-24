#include "stdafx.h"

#include "SimpleOpt.h"
#include "S1Dbg.h"
#include "context.h"
#include "util.h"
#include <string>

#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))

ULONG g_RefCount = 0;
BOOL block = false;
std::string driverToFail;
PDEBUG_CLIENT4 gDebugClient;

class EventCallbacks : public DebugBaseEventCallbacks
{
public:

    // IUnknown.
    STDMETHOD_(ULONG, AddRef)(
        THIS
        );

    STDMETHOD_(ULONG, Release)(
        THIS
        );

    // IDebugEventCallbacks.

    STDMETHOD(GetInterestMask)(
        THIS_
        OUT PULONG Mask
        );

    STDMETHOD(LoadModule)(
        THIS_
        __in ULONG64 ImageFileHandle,
        __in ULONG64 BaseOffset,
        __in ULONG ModuleSize,
        __in_opt PCSTR ModuleName,
        __in_opt PCSTR ImageName,
        __in ULONG CheckSum,
        __in ULONG TimeDateStamp
        );
};

STDMETHODIMP_(ULONG)
EventCallbacks::AddRef(THIS)
{
    DEBUGPRINT(__FUNCTION__"()\n");

    InterlockedIncrement(&g_RefCount);

    return 1;
}

STDMETHODIMP_(ULONG)
EventCallbacks::Release(THIS)
{
    DEBUGPRINT(__FUNCTION__"()\n");

    return 0;
}

STDMETHODIMP
EventCallbacks::GetInterestMask(
    THIS_
    OUT PULONG Mask)
{
    *Mask = DEBUG_EVENT_LOAD_MODULE;
    return S_OK;
}

STDMETHODIMP EventCallbacks::LoadModule(
    THIS_
    __in ULONG64 ImageFileHandle,
    __in ULONG64 BaseOffset,
    __in ULONG ModuleSize,
    __in_opt PCSTR ModuleName,
    __in_opt PCSTR ImageName,
    __in ULONG CheckSum,
    __in ULONG TimeDateStamp
)
{
    DEBUGPRINT("Load module %s\n", ImageName);

    if (!block || driverToFail.empty()) {
        return DEBUG_STATUS_NO_CHANGE;
    }

    if (!_stricmp(ImageName, driverToFail.c_str())) {
        // Fail driver load
        auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(BaseOffset);

        IMAGE_DOS_HEADER dosHeader{};
        ULONG out = 0;
        ExtensionApis.lpReadProcessMemoryRoutine((ULONG64)pDosHeader, &dosHeader, sizeof(IMAGE_DOS_HEADER), &out);

        auto pNtHeader64 = static_cast<PIMAGE_NT_HEADERS64>(Add2Ptr(pDosHeader, dosHeader.e_lfanew));
        IMAGE_NT_HEADERS64 ntHeaders{};
        ExtensionApis.lpReadProcessMemoryRoutine((ULONG64)pNtHeader64, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &out);

        auto pEntryPoint = Add2Ptr(pDosHeader, ntHeaders.OptionalHeader.AddressOfEntryPoint);
        //auto moduleEnd = Add2Ptr(BaseOffset, ntHeaders.OptionalHeader.SizeOfImage);

        auto error_code = STATUS_ACCESS_VIOLATION;
        auto failureCodeBytes = reinterpret_cast<PBYTE>(&error_code);
        BYTE retCode[] = {
            // mov eax, FailureCode
            0xB8, failureCodeBytes[0], failureCodeBytes[1], failureCodeBytes[2], failureCodeBytes[3],
            // ret
            0xC3
        };

        ExtensionApis.lpWriteProcessMemoryRoutine((ULONG64)pEntryPoint, &retCode, sizeof(retCode), &out);
        DEBUGPRINT("Wrote to process memory. Output: %d\n", out);
    }

    return DEBUG_STATUS_NO_CHANGE;
}

//#define USE_TABULAR_FOR_FREELIST

// globals
WINDBG_EXTENSION_APIS   ExtensionApis = {0};

#ifdef _DEBUG
BOOL g_bDebug = TRUE;
#else
BOOL g_bDebug = FALSE;
#endif



// command line option ids
CSimpleOptA::SOption g_pp_opts[] = {
    HELP_OPTS,
    { OPT_PP_RAWHDR,    "-r",       SO_NONE },
    { OPT_PP_RAWHDR,    "--raw",    SO_NONE },
    SO_END_OF_OPTIONS
};

HRESULT CALLBACK fail(PDEBUG_CLIENT4 pClient, PCSTR args)
{
    HRESULT ret = S_OK;

    char **argv = NULL;
    int argc;
    CMD_CTX ctx;
    CSimpleOptA cs;

    // initialize the command context
    if (FAILED(ret = InitCmdCtx(&ctx, pClient)))
        return ret;

    argv = MakeCmdline("!fail", args, &argc);
    if (argv == NULL)
    {
        ret = E_OUTOFMEMORY;
        goto cleanup;
    }

    if (argc != 2) {
        OutputDml(&ctx, "Usage: !fail drivername.sys");
        goto cleanup;
    }

    if (*args && (!_stricmp(args, "clean") || !_stricmp(args, "disable"))) {
        block = false;
        driverToFail = nullptr;
    }
    else if (*args) {
        block = true;
        driverToFail = args;
        OutputDml(&ctx, "Will prevent driver %s from loading \n", driverToFail.c_str());
    }
    
    
cleanup:
    if (argv != NULL)
        free(argv);

    ReleaseCmdCtx(&ctx);
    return ret;
}

// The entry point for the extension
extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    HRESULT ret = S_OK;
    PDEBUG_CLIENT4 pDebugClient;
    PDEBUG_CONTROL pDebugControl;
    CMD_CTX ctx;

    EventCallbacks* g_EventCb = new EventCallbacks();
    IDebugEventCallbacks* pCallbacks = NULL;

    if (FAILED(ret = DebugCreate(__uuidof(IDebugClient4),(PVOID *)&pDebugClient)))
        return ret;

    if (FAILED(ret = pDebugClient->QueryInterface(__uuidof(IDebugControl),(PVOID *)&pDebugControl)))
        return ret;

    ExtensionApis.nSize = sizeof(ExtensionApis);

    gDebugClient = pDebugClient;
    //pDebugControl->GetWindbgExtensionApis32((PWINDBG_EXTENSION_APIS32) &ExtensionApis);
    pDebugControl->GetWindbgExtensionApis64((PWINDBG_EXTENSION_APIS64) &ExtensionApis);
    pDebugControl->Release();

    auto hr = g_EventCb->QueryInterface(__uuidof(IDebugEventCallbacks), (PVOID*)&pCallbacks);
    if (FAILED(hr)) {
        DEBUGPRINT("Failed to query interface, hr = %d", hr);
        return hr;
    }

    g_EventCb->Release();

    DEBUGPRINT("DebugExtensionInitialize: Retrieved ExtensionApis\n");

    hr = pDebugClient->SetEventCallbacks(pCallbacks);
    if (FAILED(hr)) {
        DEBUGPRINT("Failed to set event, hr = %d", hr);
        return hr;
    }

    pCallbacks->Release();

    /*if (SUCCEEDED(ret = InitCmdCtx(&ctx, pDebugClient)))
    {
        ShowBanner(&ctx);
        ReleaseCmdCtx(&ctx);
    }*/

    //pDebugClient->Release();
    return ret;
}


extern "C" HRESULT CALLBACK DebugExtensionUninitialize(void)
{
    gDebugClient->Release();
    DEBUGPRINT("DebugExtensionUninitialize\n");
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


