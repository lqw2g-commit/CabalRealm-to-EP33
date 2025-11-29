#include "Base.h"
#include "Proc/Proc.h"
#include "DLLSec.h"
#include "Memory/Memory.h"
#include "Basic/Basic.h"
#include "PacketManager/PacketManager.h"
#include <future>
#include <tlhelp32.h>
#include <strsafe.h>
#include <iostream>
#include <winternl.h>

std::shared_ptr<sAuth> DLLSec::pSecAuth;

std::vector<std::string> DLLSec::vWindowToFind =
{
    //XorStr("x button"),
    //XorStr("macro recorder"),
    //XorStr("macro recorder jitbit"),
    //XorStr("macro recorder 2.0"),
    //XorStr("Smart macro"),
    //XorStr("macro expert"),
    //XorStr("AutoHotkey"),
    //XorStr("SteerMouse"),
    //XorStr("XMouse+"),
    //XorStr("X-Mouse"),
    //XorStr("XMouse"),
    //XorStr("Mouse Manager"),
    //XorStr("Pinnacle Game Profiler"),
    //XorStr("SlickRun"),
    //XorStr("SharpKeys"),
    //XorStr("Key Remapper"),
    //XorStr("InputMapper"),
    //XorStr("JoyToKey"),
    //XorStr("Xpadder"),
    //XorStr("TouchCursor")
};

std::vector<sC2S_WINDOWDETECTED> DLLSec::vQueueLogs;
/*
INT64 DLLSec::XignCode::LastThreadTick = 0;
NtQueryInformationThread_t DLLSec::XignCode::NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA(XorStr("ntdll.dll")), XorStr("NtQueryInformationThread"));
NtTerminateThread_t DLLSec::XignCode::NtTerminateThread = (NtTerminateThread_t)GetProcAddress(GetModuleHandleA(XorStr("ntdll.dll")), XorStr("NtTerminateThread"));

std::vector<sModule> DLLSec::XignCode::vXignCodeModules
{
#ifndef XIGNCODE_VERSION_NA
#ifndef XIGNCODE_LOAD_X3_XEM
    {XorStr("xcorona.xem"), 0x15287, nullptr, {}}
#else
    {XorStr("x3.xem"), 0x0, nullptr, {}}
#endif
#else
#ifndef XIGNCODE_LOAD_X3_XEM
    {XorStr("xcorona.xem"), 0x15287, nullptr, {}}
#else
    {XorStr("x3.xem"), 0x0, nullptr, {}}
#endif
#endif
}; */

char DLLSec::RecvChannelList(sS2C_GROUPLIST* pS2C_GROUPLIST, size_t size, void* unk)
{
    VM_STARTV(__FUNCTION__);
    typedef char(__cdecl* TChannelList)(sS2C_GROUPLIST*, size_t, void*);
    TChannelList ChannelList = (TChannelList)0x0093E7AF;

    DWORD* pGameTime = (DWORD*)0x00CE7EAC;
    BYTE* bGameTime = (BYTE*)(*pGameTime + 0x3C8);

    if ((pSecAuth) && (pSecAuth->SecAuth[1] && pSecAuth->SecKey[1]) && ((pSecAuth->SecAuth[1] ^ pSecAuth->xOR[1]) == pSecAuth->SecKey[1]) && (pSecAuth->Count[0] == pSecAuth->Count[1]))
    {
        if (pS2C_GROUPLIST->bServerCount)
        {
            for (int i = 0, j = 0; i < pS2C_GROUPLIST->bServerCount; i++)
            {
                sS2C_SERVERLIST* pServerList = (sS2C_SERVERLIST*)&((BYTE*)&pS2C_GROUPLIST->pServerList)[j];
                for (int k = 0; k < pServerList->bChannelCount; k++)
                {
                    if (IPServer.compare(pServerList->pS2C_CHANNELLIST[k].WorldHost) != 0)
                        while (true);
                }
                j += (sizeof(sS2C_SERVERINFO) + (sizeof(sS2C_CHANNELLIST) * pServerList->bChannelCount));
            }

            std::async([bGameTime]()
                {
                    pSecAuth->xOR[2] = (((BYTE*)&pSecAuth->SecAuth[1])[0]);
                    pSecAuth->SecKey[2] = *((INT64**)&bGameTime)[0];
                    pSecAuth->SecAuth[2] = pSecAuth->SecKey[2] ^ pSecAuth->xOR[2];
                    pSecAuth->Count[2] = pSecAuth->Count[0];
                });
        }
        else
            ZeroMemory(pS2C_GROUPLIST, pS2C_GROUPLIST->wPayLoadLen);

    }
    else while (true);

    return ChannelList(pS2C_GROUPLIST, size, unk);
    VM_END;
}

bool __fastcall DLLSec::LoginSvrConnect(SOCKET GameSocket, void* n, char* cp, SOCKET hostshort)
{
    VM_STARTV(__FUNCTION__);
    typedef int(__thiscall* t_this) (SOCKET, const char*, SOCKET);
    t_this FnIpOri = (t_this)0x00668F66;

    if (IPServer.compare(cp) == 0 && ((pSecAuth) && pSecAuth->SecAuth[0] && pSecAuth->SecKey[0]) && ((pSecAuth->SecAuth[0] ^ pSecAuth->xOR[0]) == pSecAuth->SecKey[0]) && (pSecAuth->Count[0] == pSecAuth->Count[1] + 1))
    {
        std::async([]()
        {
            pSecAuth->xOR[1] = (((BYTE*)&pSecAuth->SecAuth[0])[0]);
            pSecAuth->SecKey[1] = GetTickCount64();
            pSecAuth->SecAuth[1] = pSecAuth->SecKey[1] ^ pSecAuth->xOR[1];
            pSecAuth->Count[1]++;
        });

        return FnIpOri(GameSocket, IPServer.c_str(), hostshort);
    }

    return false;
    VM_END;
}

void DLLSec::GetIpByEnc()
{
    VM_STARTV(__FUNCTION__);
    typedef char* (__cdecl* TGetIP)(char*, int);
    TGetIP GetIP = (TGetIP)0x006053D4;

    typedef void(__cdecl* TLoginSvr)();
    TLoginSvr LoginSvr = (TLoginSvr)0x0093FD70;

    if (IPServer.compare(GetIP(XorStr("1_Login_Addr"), 0)) == 0 && (pSecAuth))
    {
        DWORD* pGameTime = (DWORD*)0x00CE7EAC;
        BYTE* bGameTime = (BYTE*)(*pGameTime + 0x3C8);

        std::async([bGameTime]()
        {
            pSecAuth->xOR[0] = bGameTime[5];
            pSecAuth->SecKey[0] = *((INT64**)&bGameTime)[0];
            pSecAuth->SecAuth[0] = pSecAuth->SecKey[0] ^ pSecAuth->xOR[0];
            pSecAuth->Count[0]++;
        });

        return LoginSvr();
    }
    VM_END;
}
/*
bool DLLSec::XignCode::CheckModules()
{
    VM_STARTV(__FUNCTION__);
#ifndef DEV_MODE
    typedef const char* (__cdecl* TGetHash)(char*, DWORD, DWORD);
    TGetHash GetHash = TGetHash(0x0066DF4F);

    for (auto& Module : vXignCodeModules)
    {
        HMODULE HANDLE = GetModuleHandleA(Module.Name.c_str());
        if (!HANDLE)
            return false;

        if (*reinterpret_cast<DWORD*>(ModuleAddr) != reinterpret_cast<DWORD>(HANDLE))
            return false;

        TCHAR szModName[MAX_PATH] = {};
        if (GetModuleFileNameA(HANDLE, szModName, sizeof(szModName)) == ERROR_SUCCESS)
            return false;

        Module.pModule = HANDLE;
        GetThreadList(reinterpret_cast<DWORD>(HANDLE), Module.ThreadStart);
    }
#endif
    return true;
    VM_END;
}

void DLLSec::XignCode::GetThreadList(DWORD StartAddr, DWORD offset)
{
    VM_STARTV(__FUNCTION__);
#ifndef XIGNCODE_LOAD_X3_XEM
    DWORD threadStartAddress = StartAddr + offset;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te32 = {};
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32))
    {
        DWORD CurPid = GetCurrentProcessId();
        DWORD CurThreadId = GetCurrentThreadId();
        do
        {
            if (te32.th32OwnerProcessID == CurPid && te32.th32ThreadID != CurThreadId)
            {
                if (HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID))
                {
                    if (NtQueryInformationThread)
                    {
                        PVOID startAddr = nullptr;
                        NTSTATUS status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(startAddr), nullptr);
                        if (reinterpret_cast<DWORD>(startAddr) == threadStartAddress)
                        {
                            auto it = std::find_if(vXignCodeModules.begin(), vXignCodeModules.end(), [StartAddr](const sModule& p) {return reinterpret_cast<DWORD>(p.pModule) == StartAddr; });
                            if (it != vXignCodeModules.end())
                                it->pThreadInfo.push_back(std::make_pair(hThread, te32.th32ThreadID));
                        }
                    }
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
#endif
    VM_END;
}

BOOL DLLSec::XignCode::CheckThreadList()
{
    VM_STARTM(__FUNCTION__);
#ifndef DEV_MODE
#ifndef XIGNCODE_LOAD_X3_XEM
    INT64 curTick = GetTickCount64();
    if (curTick - LastThreadTick >= ThreadInterval)
    {
        for (auto& Module : vXignCodeModules)
        {
            if (!Module.pThreadInfo.size() || Module.pThreadInfo.size() < 2)
                return FALSE;

            for (auto& hThread : Module.pThreadInfo)
            {
                if (NtQueryInformationThread)
                {
                    THREAD_TIMES_INFORMATION Times = {};
                    ULONG TimesLen = 0;
                    NTSTATUS TIMES_STATUS = NtQueryInformationThread(hThread.first, ThreadTimes, &Times, sizeof(Times), &TimesLen);

                    if (TIMES_STATUS == STATUS_SUCCESS && (Times.ExitTime.LowPart != 0 || Times.ExitTime.HighPart != 0))
                        return FALSE;

                    /*    THREAD_BASIC_INFORMATION TBasicInfo        = {};
                        ULONG TBasicInfoLen                        = 0;
                        NTSTATUS TBASICINFO_STATUS                = NtQueryInformationThread(hThread.first, ThreadBasicInformation, &TBasicInfo, sizeof(TBasicInfo), &TBasicInfoLen);

                        if (TBASICINFO_STATUS == STATUS_SUCCESS && (TBasicInfo.ExitStatus == STATUS_PENDING))
                            NtTerminateThread(GetCurrentThread(), 0);
                }
            }
        }

        LastThreadTick = curTick;
    }
#endif
#endif
    return TRUE;
    VM_END;
} */

std::unordered_map<DWORD, std::pair<std::string, WORD>> DLLSec::Proxy::mProxyList
{
    {0x009458E7, {XorStr("192.168.1.10"), 35002}}, //ChatNode
    {0x009A0D5B, {XorStr("192.168.1.10"), 35001}}, //Agent-Shop
    {0x007D5135, {XorStr("192.168.1.10"), 38109}}, //StunSvr
    {0x0099F198, {XorStr("192.168.1.10"), 0}}      //WorldSvr use port 0 for multiple services, and send the original port from .ini
};

bool __fastcall DLLSec::Proxy::CreateConnection(SOCKET GameSocket, void* n, const char* Host, WORD Port)
{
    VM_STARTV(__FUNCTION__);
    typedef bool(__thiscall* t_CreateConnection)(SOCKET, const char*, WORD);
    t_CreateConnection CreateConnection_ = (t_CreateConnection)0x00668F66;

    auto it = mProxyList.find(reinterpret_cast<DWORD>(_ReturnAddress()) - 5);
    if (it != mProxyList.end())
    {
        std::cout << "Proxy: " << std::hex << it->first << std::dec << " IP: " << it->second.first.c_str() << " Port: " << (it->second.second ? it->second.second : Port) << std::endl;
        return CreateConnection_(GameSocket, it->second.first.c_str(), it->second.second ? it->second.second : Port);
    }

    return CreateConnection_(GameSocket, Host, Port);

    VM_END;
}

HWND DLLSec::FindWindowPartialName(const char* pWindowName, char* pFullWindowName)
{
    VM_STARTM(__FUNCTION__);
    char szTempName[256];
    char szTempName2[256];
    char szNameWindow[256];
    int iLenTitle = 0;

    ZeroMemory(szNameWindow, 256);
    for (int i = 0; i < lstrlenA(pWindowName); i++)
        szNameWindow[i] = tolower(pWindowName[i]);

    HWND hWndTemp = FindWindowA(NULL, NULL);
    while (hWndTemp != 0)
    {
        iLenTitle = GetWindowTextA(hWndTemp, szTempName, 255);
        StringCchCopyA(szTempName2, _countof(szTempName2), szTempName);

        for (int i = 0; i < lstrlenA(szTempName); i++)
            szTempName[i] = tolower(szTempName[i]);

        if (lstrlenA(szTempName) && strstr(szTempName, szNameWindow))
        {
            StringCchCopyA(pFullWindowName, 256, szTempName2);
            break;
        }
        hWndTemp = GetWindow(hWndTemp, GW_HWNDNEXT);
    }

    return hWndTemp;
    VM_END;
}

void DLLSec::CheckBlockScreen()
{
    VM_STARTM(__FUNCTION__);
    //static INT64 LastTickCheckScreen = 0;
    static std::future<void> fAsync;
    while (true)
    {
        //if (LastTickCheckScreen < GetTickCount64())
        {
            if (vQueueLogs.size())
            {
                if (USERDATACONTEXT* pUserDataCtx = USERDATACONTEXT::GetpUserDataCtx())
                {
                    if (pUserDataCtx->GetOnLogged())
                    {
                        sC2S_WINDOWDETECTED& C2S_WindowDetected = vQueueLogs.back();
                        PacketManager::Send(::World, &C2S_WindowDetected, C2S_WindowDetected.wPayLoadLen);
                        vQueueLogs.pop_back();
                        fAsync = std::async([]() {TerminateProcess(GetCurrentProcess(), 0); });
                    }
                }
            }
            char szTempName[256] = {};

            for (auto& window : vWindowToFind)
            {
                if (FindWindowPartialName(window.c_str(), szTempName))
                {
                    USERDATACONTEXT* pUserDataCtx = USERDATACONTEXT::GetpUserDataCtx();
                    if (pUserDataCtx && pUserDataCtx->GetOnLogged())
                    {
                        sC2S_WINDOWDETECTED C2S_WindowDetected(szTempName);
                        PacketManager::Send(::World, &C2S_WindowDetected, C2S_WindowDetected.wPayLoadLen);
                        fAsync = std::async([]() {TerminateProcess(GetCurrentProcess(), 0); });
                    }
                    else
                    {
                        sC2S_WINDOWDETECTED C2S_WindowDetected(szTempName);
                        vQueueLogs.push_back(C2S_WindowDetected);
                    }
                }
            }
            Sleep(1000);
            //LastTickCheckScreen = GetTickCount64() + 1000;
        }
    }
    VM_END;
}

void* DLLSec::CreateThreadFakeAddr(void* Thread, int size)
{
    DWORD dwThreadAddr = GetTickCount();
    DWORD dwOld;
    VirtualProtect((void*)dwThreadAddr, size, PAGE_EXECUTE_READWRITE, &dwOld);
    CONTEXT ctx;
    HANDLE dwThread = CreateRemoteThread(GetCurrentProcess(), 0, 0, (LPTHREAD_START_ROUTINE)dwThreadAddr, 0, 0, 0);
    SuspendThread(dwThread);
    ctx.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(dwThread, &ctx);
    ctx.Eax = (DWORD)Thread;
    ctx.ContextFlags = CONTEXT_INTEGER;
    SetThreadContext(dwThread, &ctx);
    ResumeThread(dwThread);
    return (void*)ctx.Eax;
}

void DLLSec::SetHooks()
{
    VM_STARTU(__FUNCTION__);
    using namespace Memory;
    pSecAuth = std::make_shared<sAuth>();
    Memory::WriteValue<DWORD>(0x093D10B, reinterpret_cast<DWORD>(DLLSec::GetIpByEnc));
    //HookFunc<HookType::CALL>(LoginSvrConnect, 0x0093FD9B);
    //HookFunc<HookType::CALL>(Proxy::CreateConnection, { 0x009458E7, 0x009A0D5B, 0x007D5135, 0x0099F198 });
    //CreateThreadFakeAddr(CheckBlockScreen, 0x2000);
    VM_END;
}
