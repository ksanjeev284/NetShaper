/* Shared usermode/kernel IOCTL interface for NetShaper callout driver. */
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
typedef unsigned __int64 UINT64;
typedef unsigned __int32 UINT32;
typedef unsigned short   UINT16;
typedef unsigned char    UINT8;
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define NS_DEVICE_NAME      L"\\Device\\NetShaperCallout"
#define NS_SYMLINK_NAME     L"\\DosDevices\\NetShaperCallout"
#define NS_WIN32_DEVICE_W   L"\\\\.\\NetShaperCallout"

#define NS_DRIVER_VERSION   0x00020000  /* 2.0.0 — callout classify */

#define FILE_DEVICE_NETSHAPER  0x9C40
#define NS_IOCTL(_code) CTL_CODE(FILE_DEVICE_NETSHAPER, _code, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NS_GET_VERSION        NS_IOCTL(0x800)
#define IOCTL_NS_GET_STATS          NS_IOCTL(0x801)
#define IOCTL_NS_SET_LIMITS         NS_IOCTL(0x802)
#define IOCTL_NS_CLEAR_LIMITS       NS_IOCTL(0x803)
#define IOCTL_NS_SET_ENABLED        NS_IOCTL(0x804)
#define IOCTL_NS_SET_PID_LIMITS     NS_IOCTL(0x805)

#pragma pack(push, 1)

typedef struct _NS_VERSION_INFO {
    UINT32 DriverVersion;
    UINT32 ApiVersion;
    UINT32 Flags;           /* bit0 = callout registered, bit1 = classify active */
    UINT32 Reserved;
    char   BuildStamp[32];
} NS_VERSION_INFO;

typedef struct _NS_DRIVER_STATS {
    UINT64 FlowsTracked;
    UINT64 PacketsSeen;
    UINT64 PacketsDelayed;  /* packets blocked due to over-limit (TCP backoff) */
    UINT64 BytesSeen;
    UINT64 BytesLimited;    /* bytes that hit a limit rule */
    UINT32 ActiveLimits;
    UINT32 Enabled;
} NS_DRIVER_STATS;

#define NS_MAX_LIMITS 64
#define NS_MAX_PATH_CHARS 260
#define NS_MAX_PID_LIMITS 128

/* Path-contains limit (slow path match helper / future ALE app-id) */
typedef struct _NS_LIMIT_ENTRY {
    WCHAR PathContains[NS_MAX_PATH_CHARS];
    UINT64 BytesPerSec;
    UINT32 Direction;       /* 1=in 2=out 3=both */
    UINT32 Flags;
} NS_LIMIT_ENTRY;

typedef struct _NS_LIMIT_TABLE {
    UINT32 Count;
    UINT32 Reserved;
    NS_LIMIT_ENTRY Entries[NS_MAX_LIMITS];
} NS_LIMIT_TABLE;

/* Fast-path PID limits (usermode resolves processes) */
typedef struct _NS_PID_LIMIT_ENTRY {
    UINT32 ProcessId;
    UINT32 Direction;       /* 1=in 2=out 3=both */
    UINT64 BytesPerSec;
    UINT32 Flags;
    UINT32 Reserved;
} NS_PID_LIMIT_ENTRY;

typedef struct _NS_PID_LIMIT_TABLE {
    UINT32 Count;
    UINT32 Reserved;
    NS_PID_LIMIT_ENTRY Entries[NS_MAX_PID_LIMITS];
} NS_PID_LIMIT_TABLE;

typedef struct _NS_SET_ENABLED {
    UINT32 Enabled;
} NS_SET_ENABLED;

#pragma pack(pop)

/* Flag bits for version.Flags */
#define NS_FLAG_CALLOUT_REGISTERED  0x1
#define NS_FLAG_CLASSIFY_ACTIVE     0x2
