#pragma once
#include "Base.h"
#include "PacketManager/ProtosDef.h"
#include "3rdparty/Encrypt/EncryptString.h"
#include <winternl.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef LONG(NTAPI* NtQueryInformationThread_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtTerminateThread_t)(HANDLE, NTSTATUS);

struct sAuth
{
    INT64 SecAuth[3];
    INT64 SecKey[3];
    DWORD xOR[3];
    DWORD Count[3];
    sAuth()
    {
        memset(&SecAuth, 0, sizeof(SecAuth));
        memset(&SecKey, 0, sizeof(SecKey));
        memset(&xOR, 0, sizeof(xOR));
        memset(&Count, 0, sizeof(Count));
    }
};

struct sModule
{
    std::string Name;
    DWORD ThreadStart;
    HMODULE pModule;
    std::vector<std::pair<HANDLE, DWORD>> pThreadInfo;
};

namespace DLLSec
{
    extern std::shared_ptr<sAuth>pSecAuth;
    extern std::vector<std::string> vWindowToFind;
    extern std::vector<sC2S_WINDOWDETECTED> vQueueLogs;
    const static std::string IPServer = XorStr("192.168.1.10");

    char RecvChannelList(sS2C_GROUPLIST* pS2C_GROUPLIST, size_t size, void* unk);
    bool __fastcall LoginSvrConnect(SOCKET GameSocket, void* n, char* cp, SOCKET hostshort);
    void GetIpByEnc();
    HWND FindWindowPartialName(const char* pWindowName, char* pFullWindowName);
    void CheckBlockScreen();
    void* CreateThreadFakeAddr(void* Thread, int size);
    /*
    namespace XignCode
    {
        extern NtQueryInformationThread_t NtQueryInformationThread;
        extern NtTerminateThread_t NtTerminateThread;
        typedef enum _THREADINFOCLASS
        {
            ThreadBasicInformation,
            ThreadTimes,
            ThreadPriority,
            ThreadBasePriority,
            ThreadAffinityMask,
            ThreadImpersonationToken,
            ThreadDescriptorTableEntry,
            ThreadEnableAlignmentFaultFixup,
            ThreadEventPair_Reusable,
            ThreadQuerySetWin32StartAddress,
            ThreadZeroTlsCell,
            ThreadPerformanceCount,
            ThreadAmILastThread,
            ThreadIdealProcessor,
            ThreadPriorityBoost,
            ThreadSetTlsArrayAddress,
            ThreadIsIoPending,
            ThreadHideFromDebugger,
            ThreadBreakOnTermination,
            MaxThreadInfoClass
        } THREADINFOCLASS;

        typedef struct _THREAD_BASIC_INFORMATION {
            NTSTATUS                ExitStatus;
            PVOID                   TebBaseAddress;
            CLIENT_ID               ClientId;
            KAFFINITY               AffinityMask;
            KPRIORITY               Priority;
            KPRIORITY               BasePriority;
        } THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

        typedef struct _THREAD_TIMES_INFORMATION {
            LARGE_INTEGER           CreationTime;
            LARGE_INTEGER           ExitTime;
            LARGE_INTEGER           KernelTime;
            LARGE_INTEGER           UserTime;
        } THREAD_TIMES_INFORMATION, * PTHREAD_TIMES_INFORMATION;

        const DWORD ModuleAddr = 0x1180E68;
        extern std::vector<sModule> vXignCodeModules;
        const DWORD64 ThreadInterval = 1000;
        extern INT64 LastThreadTick;
        //bool CheckModules();
        //void GetThreadList(DWORD StartAddr, DWORD offset);
        //BOOL CheckThreadList();
    }
    */
    namespace Proxy
    {
        extern std::unordered_map<DWORD, std::pair<std::string, WORD>> mProxyList;
        bool __fastcall CreateConnection(SOCKET GameSocket, void* n, const char* Host, WORD Port);
    }

    void SetHooks();
}
