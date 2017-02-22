#define _WIN32_WINNT 0x0600 // _WIN32_WINNT_VISTA

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <sdkddkver.h>
#include <windows.h>

#include <memory>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <evntprov.h>
#include <evntrace.h>
#include <winmeta.h>
#include <versionhelpers.h>

#define MAX_SESSIONS 64
#define MAX_SESSION_NAME_LEN 1024
#define MAX_LOGFILE_PATH_LEN 1024

// {6239D424-9F3C-4216-B439-B8214FAB6523}
static const GUID provider_guid0 =
{ 0x6239d424, 0x9f3c, 0x4216, { 0xb4, 0x39, 0xb8, 0x21, 0x4f, 0xab, 0x65, 0x23 } };

// {F7688AF6-9B7B-413B-8AB9-7CD9D5B608FB}
static const GUID provider_guid1 =
{ 0xf7688af6, 0x9b7b, 0x413b, { 0x8a, 0xb9, 0x7c, 0xd9, 0xd5, 0xb6, 0x8, 0xfb } };

// {0CD0986F-6D0A-4409-B558-AF8B51FDF660}
static const GUID provider_guid2 =
{ 0xcd0986f, 0x6d0a, 0x4409, { 0xb5, 0x58, 0xaf, 0x8b, 0x51, 0xfd, 0xf6, 0x60 } };

void NTAPI provider_callback0(
    LPCGUID                  SourceId,
    ULONG                    IsEnabled,
    UCHAR                    Level,
    ULONGLONG                MatchAnyKeyword,
    ULONGLONG                MatchAllKeywords,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID                    CallbackContext
)
{
    std::wcout << L"Callback #0: " << IsEnabled << L" " << std::hex << std::setw(8) << std::setfill(L'0') << reinterpret_cast<uintptr_t>(CallbackContext) << std::endl;
}

void NTAPI provider_callback1(
    LPCGUID                  SourceId,
    ULONG                    IsEnabled,
    UCHAR                    Level,
    ULONGLONG                MatchAnyKeyword,
    ULONGLONG                MatchAllKeywords,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID                    CallbackContext
)
{
    std::wcout << L"Callback #1: " << IsEnabled << L" " << std::hex << std::setw(8) << std::setfill(L'0') << reinterpret_cast<uintptr_t>(CallbackContext) << std::endl;
}

void NTAPI provider_callback2(
    LPCGUID                  SourceId,
    ULONG                    IsEnabled,
    UCHAR                    Level,
    ULONGLONG                MatchAnyKeyword,
    ULONGLONG                MatchAllKeywords,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID                    CallbackContext
)
{
    std::wcout << L"Callback #2: " << IsEnabled << L" " << std::hex << std::setw(8) << std::setfill(L'0') << reinterpret_cast<uintptr_t>(CallbackContext) << std::endl;
}

static uintptr_t const base_context =
#if defined(_WIN64)
    0xFEDC0000BA980000;
#else
    0xFEDC0000;
#endif

static struct
{
    GUID const * guid;
    PENABLECALLBACK callback;
    PVOID context;
} const providers[] =
{
    { &provider_guid0, provider_callback0, reinterpret_cast<PVOID>(base_context + 0) },
    { &provider_guid1, provider_callback1, reinterpret_cast<PVOID>(base_context + 1) },
    { &provider_guid2, provider_callback2, reinterpret_cast<PVOID>(base_context + 2) },
};
static size_t const providers_count = _countof(providers);

namespace std {

std::basic_ostream<wchar_t> & operator<<(std::basic_ostream<wchar_t> & out, GUID const & guid)
{
    out << std::hex <<
        std::setw(8) << std::setfill(L'0') << guid.Data1 << L"-" <<
        std::setw(4) << std::setfill(L'0') << guid.Data2 << L"-" <<
        std::setw(4) << std::setfill(L'0') << guid.Data3 << L"-" <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[0]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[1]) << L"-" <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[2]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[3]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[4]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[5]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[6]) <<
        std::setw(2) << std::setfill(L'0') << static_cast<uint16_t>(guid.Data4[7]);
    return out;
}

}

void dump_sessions()
{
    ULONG code;
    PEVENT_TRACE_PROPERTIES props[MAX_SESSIONS];
    ULONG const prop_size = sizeof(EVENT_TRACE_PROPERTIES) +
        MAX_SESSION_NAME_LEN * sizeof(wchar_t) +
        MAX_LOGFILE_PATH_LEN * sizeof(wchar_t);
    auto const buf_size = MAX_SESSIONS * prop_size;
    auto const buf = std::make_unique<uint8_t[]>(buf_size);
    memset(buf.get(), 0, buf_size);
    for (auto n = 0u; n < MAX_SESSIONS; ++n)
    {
        auto const prop = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buf.get() + prop_size * n);
        prop->Wnode.BufferSize = prop_size;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        prop->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAX_SESSION_NAME_LEN * sizeof(wchar_t);
        props[n] = prop;
    }
    ULONG props_count;
    if (code = QueryAllTracesW(props, _countof(props), &props_count), ERROR_SUCCESS != code)
    {
        std::wcerr << L"ERROR: " << std::dec << code << std::endl;
        std::abort();
    }
    for (ULONG n = 0; n < props_count; ++n)
    {
        auto const prop = props[n];
        auto const log_file_name = reinterpret_cast<wchar_t const *>(reinterpret_cast<uint8_t const *>(prop) + prop->LogFileNameOffset);
        auto const logger_name = reinterpret_cast<wchar_t const *>(reinterpret_cast<uint8_t const *>(prop) + prop->LoggerNameOffset);
        std::wcout <<
            std::dec << std::setw(2) << n << L": " <<
            prop->EventsLost << " " <<
            prop->NumberOfBuffers << " " <<
            prop->FreeBuffers << " " <<
            logger_name << std::endl;
        if (*log_file_name)
            std::wcout << L"    " << log_file_name << std::endl;
    }
}

void dump_providers()
{
    ULONG code;
    static size_t const max_buf_size = 1024 * 1024;
    auto const buf = std::make_unique<uint8_t[]>(max_buf_size);
    ULONG buf_size;
    if (code = EnumerateTraceGuidsEx(TraceGuidQueryProcess, nullptr, 0, buf.get(), max_buf_size, &buf_size), ERROR_SUCCESS != code)
    {
        std::wcerr << L"ERROR in EnumerateTraceGuidsEx(TraceGuidQueryProcess): " << std::dec << code << std::endl;
        std::abort();
    }

    std::wcout << std::dec  << GetCurrentProcessId() << std::endl;
    static size_t const max_buf2_size = 1024 * 1024;
    auto const buf2 = std::make_unique<uint8_t[]>(max_buf2_size);
    for (GUID const * guid = reinterpret_cast<GUID const *>(buf.get()), * const ep = reinterpret_cast<GUID const *>(buf.get() + buf_size); guid < ep; ++guid)
    {
        std::wcout << std::hex << *guid << std::endl;

        ULONG buf2_size;
        if (code = EnumerateTraceGuidsEx(TraceGuidQueryInfo, const_cast<GUID *>(guid), sizeof(GUID), buf2.get(), max_buf2_size, &buf2_size), ERROR_SUCCESS != code)
        {
            std::wcerr << L"ERROR in EnumerateTraceGuidsEx(TraceGuidQueryInfo): " << std::dec << code << std::endl;
            std::abort();
        }
        auto const tgi = reinterpret_cast<TRACE_GUID_INFO const *>(buf2.get());
        auto tpii = reinterpret_cast<TRACE_PROVIDER_INSTANCE_INFO const *>(tgi + 1);
        for (ULONG n = 0; n < tgi->InstanceCount;++n)
            //if (tpii->Pid == GetCurrentProcessId())
            {
                //std::wcout << L"  " << std::dec << n << L": " << tpii->Pid << std::hex << L" 0x" << tpii->Flags << std::endl;
                auto tei = reinterpret_cast<TRACE_ENABLE_INFO const *>(tpii + 1);
                for (ULONG m = 0; m < tpii->EnableCount; ++m, ++tei)
                    if (tei->IsEnabled)
                        std::wcout << L"    " << std::dec << m << L": " << tpii->Pid << std::endl;

                if (!tpii->NextOffset)
                    break;
                tpii = reinterpret_cast<TRACE_PROVIDER_INSTANCE_INFO const *>(reinterpret_cast<uint8_t const *>(tpii) + tpii->NextOffset);
            }
    }
}

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

struct etw_cb_params
{
  PVOID           CallbackContext;
  PENABLECALLBACK EnableCallback;
};

struct EtwRegEntry_win_vista
{
/* Win32 Win64 - offsets */
/*   0x0   0x0 */ GUID  ProviderId;
/*  0x10  0x10 */ PVOID unk1;
/*  0x14  0x18 */ WORD  InUse;
/*  0x18  0x1C */ DWORD Index;
/*  0x1C  0x20 */ PVOID InternalCallback;
/*  0x20  0x28 */ etw_cb_params *Params;
/*  0x24  0x30 */ DWORD type;
/*  0xB8  0xC8 - total size */
};

struct EtwRegEntry_win_7
{
/* Win32 Win64 - offsets */
/*   0x0   0x0 */ GUID  ProviderId;
/*  0x10  0x10 */ PVOID unk1;
/*  0x14  0x18 */ WORD  InUse;
/*  0x18  0x1C */ DWORD Index;
/*  0x1C  0x20 */ RTL_CRITICAL_SECTION Lock;
/*  0x34  0x48 */ PVOID InternalCallback;
/*  0x38  0x50 */ etw_cb_params *Params;
/*  0x3C  0x58 */ DWORD type;
/*  0xD0  0xF0 - total size */
};

struct EtwRegEntry_win_8
{
/* Win32 Win64 - offsets */
/*   0x0   0x0 */ RTL_BALANCED_NODE Node;
/* Etw reg entry  */
#if defined(_WIN64)
    __declspec(align(16))
#endif
/*   0xC  0x20 */ GUID  ProviderId;
/*  0x28  0x48 */ PVOID InternalCallback;
/*  0x2C  0x50 */ PVOID CallbackContext;
/*  0x34  0x5C */ WORD  Index;
/*  0x36  0x5E */ WORD  Type;
};

bool is_valid_rw_region(void const * const ptr, size_t const size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
    {
        std::wcerr << L"ERROR in VirtualQuery: " << std::dec << GetLastError() << std::endl;
        std::abort();
    }
    if (mbi.State & MEM_FREE)
        return false;
    if (!(
        mbi.Protect & PAGE_READWRITE ||
        mbi.Protect & PAGE_WRITECOPY))
        return false;
    return reinterpret_cast<uintptr_t>(ptr) + size <= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
}

bool is_valid_rx_region(void const * const ptr, size_t const size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
    {
        std::wcerr << L"ERROR in VirtualQuery: " << std::dec << GetLastError() << std::endl;
        std::abort();
    }
    if (mbi.State & MEM_FREE)
        return false;
    if (!(
        mbi.Protect & PAGE_EXECUTE_READ ||
        mbi.Protect & PAGE_EXECUTE_READWRITE ||
        mbi.Protect & PAGE_EXECUTE_WRITECOPY))
        return false;
    return reinterpret_cast<uintptr_t>(ptr) + size <= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
}

inline bool maskedcmp(uint8_t const * dst, uint8_t const * src, uint8_t const * msk, size_t size)
{
    while (size-- > 0)
    {
        if ((*msk & *src++) != (*msk & *dst++))
            return false;
        ++msk;
    }
    return true;
}

EtwRegEntry_win_8 const * get_provider_entry_win_8(REGHANDLE const rh)
{
    std::wcout << L"win_8 crack" << std::endl;
    auto const ptr = reinterpret_cast<uint8_t const *>(
#if defined(_WIN64)
        rh & 0xFFFFFFFFFFFFull
#else
        static_cast<uint32_t>(rh)
#endif
        );
    std::wcout << L"EtwRegEntry_win_8: " << std::hex << std::setw(2 * sizeof(void *)) << std::setfill(L'0') << ptr << std::endl;
    if (!is_valid_rw_region(ptr, sizeof(EtwRegEntry_win_8)))
    {
        std::wcerr << L"ERROR in is_valid_rw_region: EtwRegEntry_win_8" << std::endl;
        std::abort();
    }
    return reinterpret_cast<EtwRegEntry_win_8 const *>(ptr);
}

void const * get_provider_entry_base_win_vista_or_7(REGHANDLE const rh)
{
#if defined(_M_X64)
    // Win7 x64:
    // ntdll!EtwEventProviderEnabled:
    // 00000000`77075c60 4533c9          xor     r9d,r9d
    // 00000000`77075c63 4c8bd1          mov     r10,rcx
    // 00000000`77075c66 66413bc9        cmp     cx,r9w
    // 00000000`77075c6a 0f84e34a0600    je      ntdll!EtwEventProviderEnabled+0x32 (00000000`770da753)
    // 00000000`77075c70 488bc1          mov     rax,rcx
    // 00000000`77075c73 48c1e820        shr     rax,20h
    // 00000000`77075c77 3d00080000      cmp     eax,800h
    // 00000000`77075c7c 0f83d14a0600    jae     ntdll!EtwEventProviderEnabled+0x32 (00000000`770da753)
    // 00000000`77075c82 488d0df7d11200  lea     rcx,[ntdll!EtwpRegList (00000000`771a2e80)]
    // 00000000`77075c89 488b0cc1        mov     rcx,qword ptr [rcx+rax*8]
    // 00000000`77075c8d 493bc9          cmp     rcx,r9
    // 00000000`77075c90 0f84c54a0600    je      ntdll!EtwEventProviderEnabled+0x3a (00000000`770da75b)
    static size_t const position = 3;
    static uint8_t const pattern[] =
        {
            0x48, 0x8d, 0x0d, 0xff, 0xff, 0xff, 0xff,
            0x48, 0x8b, 0x0c, 0xc1,
            0x49, 0x3b, 0xc9
        };
    static uint8_t const mask[sizeof(pattern)] =
        {
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff
        };
    static size_t const fn_size = 64;
#elif defined(_M_IX86)
    // Win7 x86:
    // ntdll!EtwEventProviderEnabled:
    // 7732b16c 8bff            mov     edi,edi
    // 7732b16e 55              push    ebp
    // 7732b16f 8bec            mov     ebp,esp
    // 7732b171 8b4d08          mov     ecx,dword ptr [ebp+8]
    // 7732b174 6685c9          test    cx,cx
    // 7732b177 741c            je      ntdll!EtwEventProviderEnabled+0x29 (7732b195)
    // 7732b179 8b450c          mov     eax,dword ptr [ebp+0Ch]
    // 7732b17c 3d00080000      cmp     eax,800h
    // 7732b181 7312            jae     ntdll!EtwEventProviderEnabled+0x29 (7732b195)
    // 7732b183 8b0485e0563577  mov     eax,dword ptr ntdll!EtwpRegList (773556e0)[eax*4]
    // 7732b18a 85c0            test    eax,eax
    // 7732b18c 740d            je      ntdll!EtwEventProviderEnabled+0x2f (7732b19b)
    static size_t const position = 3;
    static uint8_t const pattern[] =
        {
            0x8b, 0x04, 0x85, 0xff, 0xff, 0xff, 0xff,
            0x85, 0xc0
        };
    static uint8_t const mask[] =
        {
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff
        };
    static size_t const fn_size = 48;
#else
#error Unknown architecture
#endif

    auto const fn = reinterpret_cast<uint8_t const *>(&EventProviderEnabled);
    std::wcout << L"ntdll!EtwEventProviderEnabled: " << std::hex << std::setw(2 * sizeof(void *)) << std::setfill(L'0') << fn << std::endl;
    if (!is_valid_rx_region(fn, sizeof(pattern) + fn_size))
    {
        std::wcerr << L"ERROR in is_valid_rx_region: ntdll!EtwEventProviderEnabled" << std::endl;
        std::abort();
    }

    for (size_t n = 0; n < fn_size; ++n)
    {
        auto const dst = fn + n;
        static_assert(sizeof(pattern) == sizeof(mask), "The pattern size should be the same as the make size");
        if (maskedcmp(dst, pattern, mask, sizeof(pattern)))
        {
            auto const op = dst + position;
            auto const entries = reinterpret_cast<void const * const *>(
#if defined(_M_X64)
                op + sizeof(uint32_t) + *reinterpret_cast<uint32_t const *>(op));
#elif defined(_M_IX86)
                *reinterpret_cast<uint32_t const *>(op));
#else
#error Unknown architecture
#endif
            std::wcout << L"ntdll!EtwpRegList: " << std::hex << std::setw(2 * sizeof(void *)) << std::setfill(L'0') << entries << std::endl;
            auto const index = static_cast<uint32_t>(rh >> 32);
            if (!is_valid_rw_region(entries, sizeof(void *) * (index + 1)))
            {
                std::wcerr << L"ERROR in is_valid_rw_region: ntdll!EtwpRegList" << std::endl;
                std::abort();
            }
            return entries[index];
        }
    }

    std::wcerr << L"ERROR: failed to excavate ntdll!EtwpRegList" << std::endl;
    std::abort();
}

EtwRegEntry_win_7 const * get_provider_entry_win_7(REGHANDLE const rh)
{
    std::wcout << L"win_7 crack" << std::endl;
    auto const entry = get_provider_entry_base_win_vista_or_7(rh);
    std::wcout << L"EtwRegEntry_win_7: " << std::hex << std::setw(2 * sizeof(void *)) << std::setfill(L'0') << entry << std::endl;
    if (!is_valid_rw_region(entry, sizeof(EtwRegEntry_win_7)))
    {
        std::wcerr << L"ERROR in is_valid_rw_region: EtwRegEntry_win_7" << std::endl;
        std::abort();
    }
    return static_cast<EtwRegEntry_win_7 const *>(entry);
}

EtwRegEntry_win_vista const * get_provider_entry_win_vista(REGHANDLE const rh)
{
    std::wcout << L"win_vista crack" << std::endl;
    auto const entry = get_provider_entry_base_win_vista_or_7(rh);
    std::wcout << L"EtwRegEntry_win_vista: " << std::hex << std::setw(2 * sizeof(void *)) << std::setfill(L'0') << entry << std::endl;
    if (!is_valid_rw_region(entry, sizeof(EtwRegEntry_win_vista)))
    {
        std::wcerr << L"ERROR in is_valid_rw_region: EtwRegEntry_win_vista" << std::endl;
        std::abort();
    }
    return static_cast<EtwRegEntry_win_vista const *>(entry);
}

void get_provider_info(REGHANDLE const rh, GUID const * & guid, PVOID & callback, PVOID & context)
{
    std::wcout << L"Excavate provider GUID from REGHANDLE: " << std::hex << std::setw(2 * sizeof(rh)) << std::setfill(L'0') << rh << std::endl;
    if (IsWindows8OrGreater())
    {
        auto const entry = get_provider_entry_win_8(rh);
        guid = &entry->ProviderId;
        callback = entry->InternalCallback;
        context = entry->CallbackContext;
    }
    else if (IsWindows7OrGreater())
    {
        auto const entry = get_provider_entry_win_7(rh);
        guid = &entry->ProviderId;
        callback = entry->InternalCallback;
        context = entry->Params->CallbackContext;
    }
    else if (IsWindowsVistaOrGreater())
    {
        auto const entry = get_provider_entry_win_vista(rh);
        guid = &entry->ProviderId;
        callback = entry->InternalCallback;
        context = entry->Params->CallbackContext;
    }
    else
    {
        std::wcerr << L"ERROR: unsupported OS" << std::endl;
        std::abort();
    }
}

std::wstring create_etw_file()
{
    wchar_t buf[MAX_LOGFILE_PATH_LEN];
    auto buf_len = GetTempPathW(_countof(buf), buf);
    if (!buf_len)
    {
        std::wcerr << L"ERROR in GetTempPathW: " << std::dec << GetLastError() << std::endl;
        std::abort();
    }

    std::wstringstream out;
    out << buf;

    if (buf[buf_len - 1] != L'\\')
        out << L'\\';

    out << L"in_proc_etw_" << std::dec << GetCurrentProcessId() << L".etl";
    if (out.fail())
    {
        std::wcerr << L"ERROR in std::wstringstream" << std::endl;
        std::abort();
    }
    return out.str();
}

// {83C2C192-2E19-44B2-8D8E-3167AFFBAA3F}
static const GUID session_guid =
{ 0x83c2c192, 0x2e19, 0x44b2, { 0x8d, 0x8e, 0x31, 0x67, 0xaf, 0xfb, 0xaa, 0x3f } };

static auto const name = L"QQQ";

void wmain()
{
    try
    {
        ULONG code;

        REGHANDLE rhs[providers_count];
        for (size_t n = 0; n < providers_count; ++n)
        {
            std::wcout << L"EventRegister #" << std::dec << n << std::endl;
            if (code = EventRegister(providers[n].guid, providers[n].callback, providers[n].context, &rhs[n]), ERROR_SUCCESS != code)
            {
                std::wcerr << L"ERROR in EventRegister: " << std::dec << code << std::endl;
                std::abort();
            }
        }

        std::wcout << L"StartTraceW" << std::endl;
        TRACEHANDLE th;
        ULONG const prop_size = sizeof(EVENT_TRACE_PROPERTIES) +
            MAX_SESSION_NAME_LEN * sizeof(wchar_t) +
            MAX_LOGFILE_PATH_LEN * sizeof(wchar_t);
        auto const buf = std::make_unique<uint8_t[]>(prop_size);
        memset(buf.get(), 0, prop_size);
        auto const prop = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(buf.get());
        prop->Wnode.BufferSize = prop_size;
        prop->Wnode.Guid = session_guid;
        prop->Wnode.ClientContext = 1;
        prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop->BufferSize = 4; // in Kb
        prop->MinimumBuffers = 1;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        prop->LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC;
        prop->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAX_SESSION_NAME_LEN * sizeof(wchar_t);

        // Note: See https://msdn.microsoft.com/en-us/library/windows/desktop/dd392330.aspx
        //       Windows 7 and Windows Server 2008 R2
        //
        //       The following features were added in this release:
        //
        //       The ability to specify the EVENT_TRACE_BUFFERING_MODE or EVENT_TRACE_FILE_MODE_NEWFILE logging mode
        //       with the EVENT_TRACE_PRIVATE_LOGGER_MODE logging mode (see Logging Mode Constants).
        if (IsWindows7OrGreater())
        {
            prop->BufferSize = 1; // in Kb
            prop->MinimumBuffers = 1;
            prop->LogFileMode |= EVENT_TRACE_BUFFERING_MODE;
            std::wcout << L"use circular buffer" << std::endl;
        }
        else
        {
            prop->MaximumFileSize = 1;  // in Mb
            prop->LogFileMode |= EVENT_TRACE_FILE_MODE_CIRCULAR;

            auto const file_src = create_etw_file();
            auto const file_dst = reinterpret_cast<wchar_t *>(buf.get() + prop->LogFileNameOffset);
            auto const err = wcscpy_s(file_dst, MAX_LOGFILE_PATH_LEN, file_src.c_str());
            if (err)
            {
                std::wcerr << L"ERROR in wcscpy_s: " << std::dec << err << std::endl;
                std::abort();
            }
            std::wcout << L"use circular file: " << file_src << std::endl;
        }

        if (code = StartTraceW(&th, name, prop), ERROR_SUCCESS != code)
        {
            std::wcerr << L"ERROR in StartTraceW: " << std::dec << code << std::endl;
            std::abort();
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            auto const is_active_before = EventProviderEnabled(rhs[n], WINEVENT_LEVEL_INFO, 0);
            std::wcout << L"EventProviderEnabled #"<< std::dec << n << L": " << static_cast<unsigned>(is_active_before) << std::endl;
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            std::wcout << L"EnableTraceEx #" << std::dec << n << std::endl;
            if (code = EnableTraceEx(providers[n].guid, nullptr, th, true, TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr), ERROR_SUCCESS != code)
            {
                std::wcerr << L"ERROR in EnableTraceEx: " << std::dec << code << std::endl;
                std::abort();
            }
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            auto const is_active_after = EventProviderEnabled(rhs[n], WINEVENT_LEVEL_INFO, 0);
            std::wcout << L"EventProviderEnabled #"<< std::dec << n << L": " << static_cast<unsigned>(is_active_after) << std::endl;
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            std::wcout << L"EventWrite #" << std::dec << n << std::endl;
            EVENT_DESCRIPTOR ed;
            memset(&ed, 0, sizeof(ed));
            ed.Id = 12345;
            ed.Version = 1;
            ed.Opcode = 20;
            EVENT_DATA_DESCRIPTOR edd;
            memset(&edd, 0, sizeof(edd));
            static uint64_t const payload = 0xFEDCBA9876543210;
            edd.Size = sizeof(payload);
            edd.Ptr = reinterpret_cast<ULONGLONG>(&payload);
            if (code = EventWrite(rhs[n], &ed, 1, &edd), ERROR_SUCCESS != code)
            {
                std::wcerr << L"ERROR in EventWrite: " << std::dec << code << std::endl;
                std::abort();
            }
        }

        std::wcout << L"StopTraceW" << std::endl;
        if (code = StopTraceW(th, name, prop), ERROR_SUCCESS != code)
        {
            std::wcerr << L"ERROR in StopTraceW: " << std::dec << code << std::endl;
            std::abort();
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            std::wcout << L"get_provider_info #" << std::dec << n  << std::endl;
            GUID const * provider_guid;
            PVOID callback;
            PVOID context;
            get_provider_info(rhs[n], provider_guid, callback, context);
            std::wcout << L"provider_guid #" << std::dec << n  << L": " << *provider_guid << L" "
                << std::hex << std::setw(2 * sizeof (void *)) << std::setfill(L'0') << reinterpret_cast<uintptr_t>(callback) << L" "
                << std::hex << std::setw(2 * sizeof (void *)) << std::setfill(L'0') << reinterpret_cast<uintptr_t>(context) << std::endl;
            if (callback == providers[n].callback)
                std::wcout << L"original callback" << std::endl;
            else
                std::wcout << L"proxy callback" << std::endl;
            if (!IsEqualGUID(*provider_guid, *providers[n].guid))
            {
                std::wcerr << L"ERROR in get_provider_info:: guid" << std::endl;
                std::abort();
            }
            if (context != providers[n].context)
            {
                std::wcerr << L"ERROR in get_provider_info: context" << std::endl;
                std::abort();
            }
        }

        for (size_t n = 0; n < providers_count; ++n)
        {
            std::wcout << L"EventUnregister #" << std::dec << n << std::endl;
            if (code = EventUnregister(rhs[n]), ERROR_SUCCESS != code)
            {
                std::wcerr << L"ERROR in EventUnregister: " << std::dec << code << std::endl;
                std::abort();
            }
        }
    }
    catch (std::exception const & ex)
    {
        std::wcerr << L"ERROR:" << ex.what() << std::endl;
        std::abort();
    }
    catch (...)
    {
        std::wcerr << L"ERROR" << std::endl;
        std::abort();
    }
}
