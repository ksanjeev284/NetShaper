/*
 * NetShaperCallout — KMDF + WFP callout rate limiter
 *
 * OUTBOUND_TRANSPORT_V4/V6 classify:
 *   process ID from metadata → PID limit table → token bucket
 *   under limit: PERMIT; over: BLOCK (TCP backoff)
 *
 * Build with WDK 10+. Production: EV + Microsoft attestation signing.
 */
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "../include/ns_ioctl.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD NetShaperEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL NetShaperEvtIoDeviceControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP NetShaperEvtDeviceCleanup;

typedef struct _NS_BUCKET {
    INT64 Tokens;
    INT64 Capacity;
    INT64 FillPerSec;
    LARGE_INTEGER LastQpc;
} NS_BUCKET;

typedef struct _NS_PID_RUNTIME {
    UINT32 ProcessId;
    UINT32 Direction;
    UINT64 BytesPerSec;
    NS_BUCKET Bucket;
    UINT32 InUse;
} NS_PID_RUNTIME;

#define NS_MAX_RUNTIME NS_MAX_PID_LIMITS

typedef struct _DEVICE_CONTEXT {
    UINT32 Enabled;
    NS_DRIVER_STATS Stats;
    NS_LIMIT_TABLE PathLimits;
    NS_PID_RUNTIME PidRuntime[NS_MAX_RUNTIME];
    UINT32 PidCount;
    /* Protects PidRuntime + buckets (classify and IOCTL share this). */
    KSPIN_LOCK TableLock;

    HANDLE EngineHandle;
    UINT32 CalloutIdV4;
    UINT32 CalloutIdV6;
    UINT64 FilterIdV4;
    UINT64 FilterIdV6;
    UINT32 CalloutRegistered;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

static PDEVICE_CONTEXT g_DeviceCtx = NULL;

static const GUID NS_PROVIDER_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x01 } };
static const GUID NS_SUBLAYER_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x02 } };
static const GUID NS_CALLOUT_V4_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x03 } };
static const GUID NS_CALLOUT_V6_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x04 } };
static const GUID NS_FILTER_V4_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x05 } };
static const GUID NS_FILTER_V6_KEY =
{ 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x06 } };

/* Caller must hold TableLock. */
static VOID NsBucketInit(NS_BUCKET* b, UINT64 bytesPerSec)
{
    b->FillPerSec = (INT64)(bytesPerSec > 0 ? bytesPerSec : 1);
    b->Capacity = b->FillPerSec + (b->FillPerSec / 4);
    b->Tokens = b->Capacity / 2;
    KeQueryPerformanceCounter(&b->LastQpc);
}

/* Caller must hold TableLock. */
static VOID NsBucketRefill(NS_BUCKET* b)
{
    LARGE_INTEGER now, freq;
    INT64 delta, add;
    now = KeQueryPerformanceCounter(&freq);
    if (freq.QuadPart <= 0) return;
    delta = now.QuadPart - b->LastQpc.QuadPart;
    if (delta <= 0) return;
    add = (b->FillPerSec * delta) / freq.QuadPart;
    if (add > 0) {
        b->Tokens += add;
        if (b->Tokens > b->Capacity) b->Tokens = b->Capacity;
        b->LastQpc = now;
    }
}

/* Caller must hold TableLock. */
static BOOLEAN NsBucketConsume(NS_BUCKET* b, UINT32 bytes)
{
    NsBucketRefill(b);
    if (b->Tokens >= (INT64)bytes) {
        b->Tokens -= (INT64)bytes;
        return TRUE;
    }
    b->Tokens = 0;
    return FALSE;
}

/* Caller must hold TableLock. */
static PNS_PID_RUNTIME NsFindPid(PDEVICE_CONTEXT ctx, UINT32 pid)
{
    UINT32 i;
    for (i = 0; i < NS_MAX_RUNTIME; i++) {
        if (ctx->PidRuntime[i].InUse && ctx->PidRuntime[i].ProcessId == pid)
            return &ctx->PidRuntime[i];
    }
    return NULL;
}

static VOID NTAPI
NsClassifyOut(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    PDEVICE_CONTEXT ctx = g_DeviceCtx;
    UINT32 pid = 0;
    UINT32 nbytes = 1500;
    PNS_PID_RUNTIME rt;
    KIRQL irql;
    BOOLEAN permit = TRUE;

    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* Respect prior callouts that already decided. */
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
        return;

    if (!ctx || !ctx->Enabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    InterlockedIncrement64((LONG64*)&ctx->Stats.PacketsSeen);

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
        pid = (UINT32)inMetaValues->processId;

    if (layerData) {
        PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        if (nb) {
            nbytes = NET_BUFFER_DATA_LENGTH(nb);
            if (nbytes == 0) nbytes = 64;
        }
    }

    InterlockedAdd64((LONG64*)&ctx->Stats.BytesSeen, (LONG64)nbytes);

    if (pid == 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    KeAcquireSpinLock(&ctx->TableLock, &irql);
    rt = NsFindPid(ctx, pid);
    if (rt && rt->Direction != 1 /* skip inbound-only on outbound layer */) {
        InterlockedAdd64((LONG64*)&ctx->Stats.BytesLimited, (LONG64)nbytes);
        permit = NsBucketConsume(&rt->Bucket, nbytes);
        if (!permit)
            InterlockedIncrement64((LONG64*)&ctx->Stats.PacketsDelayed);
    }
    KeReleaseSpinLock(&ctx->TableLock, irql);

    if (permit) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    } else {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

static NTSTATUS NTAPI
NsNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI
NsFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
    if (g_DeviceCtx)
        InterlockedIncrement64((LONG64*)&g_DeviceCtx->Stats.FlowsTracked);
}

static VOID NsUnregisterCallouts(PDEVICE_CONTEXT ctx)
{
    if (ctx->EngineHandle) {
        if (ctx->FilterIdV4)
            FwpmFilterDeleteById0(ctx->EngineHandle, ctx->FilterIdV4);
        if (ctx->FilterIdV6)
            FwpmFilterDeleteById0(ctx->EngineHandle, ctx->FilterIdV6);
        FwpmCalloutDeleteByKey0(ctx->EngineHandle, &NS_CALLOUT_V4_KEY);
        FwpmCalloutDeleteByKey0(ctx->EngineHandle, &NS_CALLOUT_V6_KEY);
        FwpmSubLayerDeleteByKey0(ctx->EngineHandle, &NS_SUBLAYER_KEY);
        FwpmProviderDeleteByKey0(ctx->EngineHandle, &NS_PROVIDER_KEY);
        FwpmEngineClose0(ctx->EngineHandle);
        ctx->EngineHandle = NULL;
    }
    if (ctx->CalloutIdV4) {
        FwpsCalloutUnregisterById0(ctx->CalloutIdV4);
        ctx->CalloutIdV4 = 0;
    }
    if (ctx->CalloutIdV6) {
        FwpsCalloutUnregisterById0(ctx->CalloutIdV6);
        ctx->CalloutIdV6 = 0;
    }
    ctx->CalloutRegistered = 0;
    ctx->FilterIdV4 = 0;
    ctx->FilterIdV6 = 0;
}

static NTSTATUS NsRegisterCallouts(WDFDEVICE device, PDEVICE_CONTEXT ctx)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPM_PROVIDER0 provider = { 0 };
    FWPM_SUBLAYER0 sublayer = { 0 };
    FWPS_CALLOUT0 s4 = { 0 }, s6 = { 0 };
    FWPM_CALLOUT0 m4 = { 0 }, m6 = { 0 };
    FWPM_FILTER0 f4 = { 0 }, f6 = { 0 };
    PDEVICE_OBJECT devObj = WdfDeviceWdmGetDeviceObject(device);

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &ctx->EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin0(ctx->EngineHandle, 0);
    if (!NT_SUCCESS(status)) goto close;

    provider.providerKey = NS_PROVIDER_KEY;
    provider.displayData.name = L"NetShaper";
    provider.displayData.description = L"NetShaper WFP provider";
    status = FwpmProviderAdd0(ctx->EngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    sublayer.subLayerKey = NS_SUBLAYER_KEY;
    sublayer.displayData.name = L"NetShaper Sublayer";
    sublayer.providerKey = (GUID*)&NS_PROVIDER_KEY;
    sublayer.weight = 0x7FFF;
    status = FwpmSubLayerAdd0(ctx->EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    s4.calloutKey = NS_CALLOUT_V4_KEY;
    s4.classifyFn = NsClassifyOut;
    s4.notifyFn = NsNotify;
    s4.flowDeleteFn = NsFlowDelete;
    status = FwpsCalloutRegister0(devObj, &s4, &ctx->CalloutIdV4);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    s6.calloutKey = NS_CALLOUT_V6_KEY;
    s6.classifyFn = NsClassifyOut;
    s6.notifyFn = NsNotify;
    s6.flowDeleteFn = NsFlowDelete;
    status = FwpsCalloutRegister0(devObj, &s6, &ctx->CalloutIdV6);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    m4.calloutKey = NS_CALLOUT_V4_KEY;
    m4.displayData.name = L"NetShaper Outbound V4";
    m4.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    m4.providerKey = (GUID*)&NS_PROVIDER_KEY;
    status = FwpmCalloutAdd0(ctx->EngineHandle, &m4, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    m6.calloutKey = NS_CALLOUT_V6_KEY;
    m6.displayData.name = L"NetShaper Outbound V6";
    m6.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
    m6.providerKey = (GUID*)&NS_PROVIDER_KEY;
    status = FwpmCalloutAdd0(ctx->EngineHandle, &m6, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    f4.filterKey = NS_FILTER_V4_KEY;
    f4.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    f4.subLayerKey = NS_SUBLAYER_KEY;
    f4.displayData.name = L"NetShaper limit filter v4";
    f4.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    f4.action.calloutKey = NS_CALLOUT_V4_KEY;
    f4.weight.type = FWP_EMPTY;
    status = FwpmFilterAdd0(ctx->EngineHandle, &f4, NULL, &ctx->FilterIdV4);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    f6.filterKey = NS_FILTER_V6_KEY;
    f6.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
    f6.subLayerKey = NS_SUBLAYER_KEY;
    f6.displayData.name = L"NetShaper limit filter v6";
    f6.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    f6.action.calloutKey = NS_CALLOUT_V6_KEY;
    f6.weight.type = FWP_EMPTY;
    status = FwpmFilterAdd0(ctx->EngineHandle, &f6, NULL, &ctx->FilterIdV6);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto abort;

    status = FwpmTransactionCommit0(ctx->EngineHandle);
    if (!NT_SUCCESS(status)) goto close;

    ctx->CalloutRegistered = 1;
    return STATUS_SUCCESS;

abort:
    FwpmTransactionAbort0(ctx->EngineHandle);
close:
    NsUnregisterCallouts(ctx);
    return status;
}

static VOID NsInitCtx(PDEVICE_CONTEXT ctx)
{
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Enabled = 1;
    KeInitializeSpinLock(&ctx->TableLock);
}

NTSTATUS
NetShaperEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_IO_QUEUE_CONFIG qcfg;
    PDEVICE_CONTEXT ctx;

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_NETSHAPER);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, DEVICE_CONTEXT);
    attrs.EvtCleanupCallback = NetShaperEvtDeviceCleanup;

    status = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(status)) return status;

    ctx = DeviceGetContext(device);
    NsInitCtx(ctx);
    g_DeviceCtx = ctx;

    {
        DECLARE_CONST_UNICODE_STRING(sym, NS_SYMLINK_NAME);
        status = WdfDeviceCreateSymbolicLink(device, &sym);
        if (!NT_SUCCESS(status)) return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qcfg, WdfIoQueueDispatchParallel);
    qcfg.EvtIoDeviceControl = NetShaperEvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &qcfg, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;

    /* Best-effort WFP registration */
    (void)NsRegisterCallouts(device, ctx);
    return STATUS_SUCCESS;
}

VOID
NetShaperEvtDeviceCleanup(_In_ WDFOBJECT Object)
{
    PDEVICE_CONTEXT ctx = DeviceGetContext(Object);
    NsUnregisterCallouts(ctx);
    if (g_DeviceCtx == ctx)
        g_DeviceCtx = NULL;
}

VOID
NetShaperEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    PDEVICE_CONTEXT ctx = DeviceGetContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inBuf = NULL;
    PVOID outBuf = NULL;
    size_t outLen = 0;
    UNREFERENCED_PARAMETER(OutputBufferLength);

    switch (IoControlCode) {
    case IOCTL_NS_GET_VERSION: {
        NS_VERSION_INFO* v;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(NS_VERSION_INFO), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;
        v = (NS_VERSION_INFO*)outBuf;
        RtlZeroMemory(v, sizeof(*v));
        v->DriverVersion = NS_DRIVER_VERSION;
        v->ApiVersion = 2;
        if (ctx->CalloutRegistered)
            v->Flags = NS_FLAG_CALLOUT_REGISTERED | NS_FLAG_CLASSIFY_ACTIVE;
        RtlCopyMemory(v->BuildStamp, "NetShaperCallout-2.0", 20);
        WdfRequestSetInformation(Request, sizeof(NS_VERSION_INFO));
        break;
    }
    case IOCTL_NS_GET_STATS: {
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(NS_DRIVER_STATS), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;
        ctx->Stats.Enabled = ctx->Enabled;
        ctx->Stats.ActiveLimits = ctx->PidCount;
        RtlCopyMemory(outBuf, &ctx->Stats, sizeof(NS_DRIVER_STATS));
        WdfRequestSetInformation(Request, sizeof(NS_DRIVER_STATS));
        break;
    }
    case IOCTL_NS_SET_ENABLED: {
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(NS_SET_ENABLED), &inBuf, NULL);
        if (!NT_SUCCESS(status)) break;
        ctx->Enabled = ((NS_SET_ENABLED*)inBuf)->Enabled ? 1u : 0u;
        break;
    }
    case IOCTL_NS_CLEAR_LIMITS: {
        KIRQL irql;
        UINT32 i;
        KeAcquireSpinLock(&ctx->TableLock, &irql);
        for (i = 0; i < NS_MAX_RUNTIME; i++)
            ctx->PidRuntime[i].InUse = 0;
        ctx->PidCount = 0;
        RtlZeroMemory(&ctx->PathLimits, sizeof(ctx->PathLimits));
        KeReleaseSpinLock(&ctx->TableLock, irql);
        break;
    }
    case IOCTL_NS_SET_LIMITS: {
        NS_LIMIT_TABLE* t;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(UINT32) * 2, &inBuf, NULL);
        if (!NT_SUCCESS(status)) break;
        t = (NS_LIMIT_TABLE*)inBuf;
        if (t->Count > NS_MAX_LIMITS) { status = STATUS_INVALID_PARAMETER; break; }
        {
            size_t need = FIELD_OFFSET(NS_LIMIT_TABLE, Entries) + t->Count * sizeof(NS_LIMIT_ENTRY);
            if (InputBufferLength < need) { status = STATUS_BUFFER_TOO_SMALL; break; }
            RtlCopyMemory(&ctx->PathLimits, t, need);
        }
        break;
    }
    case IOCTL_NS_SET_PID_LIMITS: {
        NS_PID_LIMIT_TABLE* t;
        UINT32 i, n;
        KIRQL irql;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(UINT32) * 2, &inBuf, NULL);
        if (!NT_SUCCESS(status)) break;
        t = (NS_PID_LIMIT_TABLE*)inBuf;
        if (t->Count > NS_MAX_PID_LIMITS) { status = STATUS_INVALID_PARAMETER; break; }
        {
            size_t need = FIELD_OFFSET(NS_PID_LIMIT_TABLE, Entries) + t->Count * sizeof(NS_PID_LIMIT_ENTRY);
            if (InputBufferLength < need) { status = STATUS_BUFFER_TOO_SMALL; break; }
        }
        KeAcquireSpinLock(&ctx->TableLock, &irql);
        for (i = 0; i < NS_MAX_RUNTIME; i++)
            ctx->PidRuntime[i].InUse = 0;
        n = t->Count;
        for (i = 0; i < n; i++) {
            ctx->PidRuntime[i].InUse = 1;
            ctx->PidRuntime[i].ProcessId = t->Entries[i].ProcessId;
            ctx->PidRuntime[i].Direction = t->Entries[i].Direction;
            ctx->PidRuntime[i].BytesPerSec = t->Entries[i].BytesPerSec;
            NsBucketInit(&ctx->PidRuntime[i].Bucket, t->Entries[i].BytesPerSec);
        }
        ctx->PidCount = n;
        KeReleaseSpinLock(&ctx->TableLock, irql);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestComplete(Request, status);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, NetShaperEvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
