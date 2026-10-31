#ifndef MESH_AUDIO_BRIDGE_H
#define MESH_AUDIO_BRIDGE_H

// Included by runtime_host_contract.c. Streams the default render endpoint's speaker output
// (WASAPI shared-mode loopback) as framed Opus packets, alongside an active remote-desktop
// session. The broker/user split mirrors clipboard_bridge.h: a session-0 broker re-launches
// itself into the target user session (WTSQueryUserToken + CreateProcessAsUserW) because
// loopback capture must run inside the interactive session, then relays the child's packet
// stream to the agent on stdout. Capture never touches the microphone, nothing is written to
// disk and no audio content is logged.
//
// Command-line grammar (rundll32 hosts the service DLL). The agent (modules/desktop-audio.js)
// launches only the first two forms; the third is launched by the broker, not the agent:
//
//   rundll32.exe "<ServiceDll>",MeshAudioBridgeW local
//       Capture on the current process (agent already runs in a user session). Packets go to
//       stdout; the helper exits on stdin EOF or a broken stdout pipe.
//
//   rundll32.exe "<ServiceDll>",MeshAudioBridgeW tsid=<sessionId>
//       Session-0 broker for interactive session <sessionId> (1..0xFFFFFFFE). Relays the user
//       child's packet stream to stdout; exits on stdin EOF, child exit or a broken stdout pipe.
//
//   rundll32.exe "<ServiceDll>",MeshAudioBridgeW user <pipeName> <brokerPid> <sessionId>
//       User-session capture child. <pipeName> must equal \\.\pipe\MeshAudio_<brokerPid>. It
//       verifies the pipe's server PID and its own session, then writes packets to the pipe and
//       exits when the pipe breaks. Not an agent-reachable entry point (ILibProcessPipe only
//       approves "local" and "tsid=").
//
// Packet wire format (helper stdout == one concatenated stream; the agent frames it), all
// little-endian, 16-byte header:
//   off0  u8  version (= 1)
//   off1  u8  type (1 CONFIG, 2 AUDIO, 3 SILENCE, 4 STATUS)
//   off2  u16 flags (bit0 DISCONTINUITY: first packet after start / device change / gap)
//   off4  u32 sequence (increments per packet, wraps)
//   off8  u32 timestamp_ms (ms since capture start, wraps)
//   off12 u32 payload length (<= 4096)
// Payloads:
//   CONFIG  : u32 codec(1=Opus), u32 sampleRate(48000), u16 channels(2), u16 frameMs(20),
//             u32 bitrate(64000)  -- 16 bytes; sent first and again after any format/device change.
//   AUDIO   : exactly one Opus packet (20 ms, 48 kHz stereo, RESTRICTED_LOWDELAY, CBR 64 kbps).
//   SILENCE : empty; emitted every 250 ms while loopback delivers nothing.
//   STATUS  : u32 code (Win32/HRESULT) then UTF-8 reason (<= 256 bytes); sent before an
//             unrecoverable exit. Reasons are fixed diagnostic strings, never audio content.
//
// The WASAPI loopback capture structure (default endpoint, ~10 ms polling, format conversion,
// IMMNotificationClient re-init) follows the design of Chromium's remoting AudioCapturerWin
// (remoting/host/audio_capturer_win.cc, BSD-3-Clause). No source is copied verbatim.

#define COBJMACROS
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <mmreg.h>
#include <ksmedia.h>
#include <signal.h>
#include <opus.h>

// The SDK only declares these GUIDs; their definitions live in uuid.lib / ksguid.lib, which the
// service DLL does not link, and defining INITGUID here would emit every GUID declared by every
// header in this translation unit. Define the few the helper uses locally with the SDK values.
static const CLSID MeshAudio_CLSID_MMDeviceEnumerator = { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const IID MeshAudio_IID_IMMDeviceEnumerator = { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };
static const IID MeshAudio_IID_IMMNotificationClient = { 0x7991EEC9, 0x7E89, 0x4D85, { 0x83, 0x90, 0x6C, 0x70, 0x3C, 0xEC, 0x60, 0xC0 } };
static const IID MeshAudio_IID_IAudioClient = { 0x1CB9AD4C, 0xDBFA, 0x4C32, { 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2 } };
static const IID MeshAudio_IID_IAudioCaptureClient = { 0xC8ADBD64, 0xE71E, 0x48A0, { 0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17 } };
static const GUID MeshAudio_SUBTYPE_PCM = { 0x00000001, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
static const GUID MeshAudio_SUBTYPE_IEEE_FLOAT = { 0x00000003, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

#define MESH_AUDIO_PIPE_PREFIX_W        L"\\\\.\\pipe\\MeshAudio_"
#define MESH_AUDIO_IO_MS                15000UL
#define MESH_AUDIO_VERSION              1
#define MESH_AUDIO_TYPE_CONFIG          1
#define MESH_AUDIO_TYPE_AUDIO           2
#define MESH_AUDIO_TYPE_SILENCE         3
#define MESH_AUDIO_TYPE_STATUS          4
#define MESH_AUDIO_FLAG_DISCONTINUITY   0x0001
#define MESH_AUDIO_CODEC_OPUS           1
#define MESH_AUDIO_SAMPLE_RATE          48000
#define MESH_AUDIO_CHANNELS             2
#define MESH_AUDIO_FRAME_MS             20
// 48 kHz * 20 ms = 960 samples per channel; interleaved stereo is 1920 int16.
#define MESH_AUDIO_FRAME_SAMPLES        960
#define MESH_AUDIO_FRAME_INTERLEAVED    (MESH_AUDIO_FRAME_SAMPLES * MESH_AUDIO_CHANNELS)
#define MESH_AUDIO_BITRATE              64000
#define MESH_AUDIO_HEADER_SIZE          16
#define MESH_AUDIO_MAX_PAYLOAD          4096
#define MESH_AUDIO_SILENCE_MS           250UL
#define MESH_AUDIO_POLL_MS              10UL
#define MESH_AUDIO_RELAY_BUFFER         8192
// Capture buffer request; shared mode treats this as a lower bound (100-ns units => 200 ms).
#define MESH_AUDIO_BUFFER_DURATION      2000000LL
// Bounded re-init attempts after a default-device change before giving up fail-closed.
#define MESH_AUDIO_REINIT_ATTEMPTS      25
// Distinct capture-child exit code for a libopus hardening abort (ENABLE_HARDENING => abort()).
#define MESH_AUDIO_EXIT_ABORT           0xA0D10B07UL

typedef struct MeshAudioWriter { HANDLE handle; BOOL overlapped; } MeshAudioWriter;

static DWORD MeshAudio_WriteAll(MeshAudioWriter* writer, const void* data, DWORD length)
{
    const BYTE* cursor = (const BYTE*)data;
    ULONGLONG deadline = GetTickCount64() + MESH_AUDIO_IO_MS;
    while (length != 0)
    {
        DWORD count = 0, error = ERROR_SUCCESS;
        OVERLAPPED ov = {0};
        BOOL ok;
        if (writer->overlapped)
        {
            ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (ov.hEvent == NULL) { return GetLastError(); }
        }
        ok = WriteFile(writer->handle, cursor, length, &count, writer->overlapped ? &ov : NULL);
        if (!ok && writer->overlapped && GetLastError() == ERROR_IO_PENDING)
        {
            ULONGLONG now = GetTickCount64();
            DWORD wait = WaitForSingleObject(ov.hEvent, now < deadline ? (DWORD)(deadline - now) : 0);
            if (wait != WAIT_OBJECT_0)
            {
                error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
                CancelIoEx(writer->handle, &ov);
                GetOverlappedResult(writer->handle, &ov, &count, TRUE);
            }
            else if (!GetOverlappedResult(writer->handle, &ov, &count, FALSE)) { error = GetLastError(); }
        }
        else if (!ok) { error = GetLastError(); }
        if (ov.hEvent != NULL) { CloseHandle(ov.hEvent); }
        if (error != ERROR_SUCCESS) { return error; }
        if (count == 0) { return ERROR_BROKEN_PIPE; }
        if (count > length) { return ERROR_INVALID_DATA; }
        cursor += count;
        length -= count;
        if (length != 0 && GetTickCount64() >= deadline) { return ERROR_TIMEOUT; }
    }
    return ERROR_SUCCESS;
}

static void MeshAudio_PutLE16(BYTE* out, WORD value) { out[0] = (BYTE)(value & 0xFF); out[1] = (BYTE)((value >> 8) & 0xFF); }
static void MeshAudio_PutLE32(BYTE* out, DWORD value)
{
    out[0] = (BYTE)(value & 0xFF); out[1] = (BYTE)((value >> 8) & 0xFF);
    out[2] = (BYTE)((value >> 16) & 0xFF); out[3] = (BYTE)((value >> 24) & 0xFF);
}

static DWORD MeshAudio_WritePacket(MeshAudioWriter* writer, BYTE type, WORD flags, DWORD sequence,
    DWORD timestampMs, const void* payload, DWORD payloadLength)
{
    BYTE header[MESH_AUDIO_HEADER_SIZE];
    DWORD error;
    if (payloadLength > MESH_AUDIO_MAX_PAYLOAD) { return ERROR_INVALID_DATA; }
    header[0] = MESH_AUDIO_VERSION;
    header[1] = type;
    MeshAudio_PutLE16(header + 2, flags);
    MeshAudio_PutLE32(header + 4, sequence);
    MeshAudio_PutLE32(header + 8, timestampMs);
    MeshAudio_PutLE32(header + 12, payloadLength);
    error = MeshAudio_WriteAll(writer, header, sizeof(header));
    if (error == ERROR_SUCCESS && payloadLength != 0) { error = MeshAudio_WriteAll(writer, payload, payloadLength); }
    return error;
}

// Capture state. One instance drives a single endpoint; the WASAPI objects are rebuilt in place
// on a default-device change so the sequence/timeline and the Opus encoder survive the switch.
typedef struct MeshAudioCapture
{
    MeshAudioWriter* writer;
    HANDLE stopEvent;           // Signalled when the parent closes stdin (graceful stop).
    HANDLE deviceChangedEvent;  // Signalled by the notification client on default-device change.
    IMMDeviceEnumerator* enumerator;
    IMMNotificationClient notify;
    IMMDevice* device;
    IAudioClient* client;
    IAudioCaptureClient* capture;
    OpusEncoder* encoder;
    BOOL notifyRegistered;
    BOOL started;
    BOOL autoConvert;           // Engine delivers our requested s16 48 kHz stereo directly.
    BOOL sourceIsFloat;         // Fallback path: source is 32-bit float PCM.
    WORD sourceChannels;        // Fallback path: source channel count (>= 1).
    opus_int16 frame[MESH_AUDIO_FRAME_INTERLEAVED];
    UINT32 frameFill;           // Interleaved int16 samples accumulated toward one 20 ms frame.
    DWORD sequence;
    ULONGLONG startTick;
    BOOL pendingDiscontinuity;  // Next AUDIO packet marks a start/device-change/gap boundary.
} MeshAudioCapture;

// --- IMMNotificationClient: only OnDefaultDeviceChanged is acted on; the rest are no-ops. ---
static MeshAudioCapture* MeshAudio_NotifyOwner(IMMNotificationClient* self)
{
    return (MeshAudioCapture*)((BYTE*)self - offsetof(MeshAudioCapture, notify));
}
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_QueryInterface(IMMNotificationClient* self, REFIID riid, void** ppv)
{
    if (ppv == NULL) { return E_POINTER; }
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &MeshAudio_IID_IMMNotificationClient))
    { *ppv = self; return S_OK; }
    *ppv = NULL;
    return E_NOINTERFACE;
}
// The object has the capture's lifetime; ref-counting keeps COM contract without owning memory.
static ULONG STDMETHODCALLTYPE MeshAudio_Notify_AddRef(IMMNotificationClient* self) { UNREFERENCED_PARAMETER(self); return 1; }
static ULONG STDMETHODCALLTYPE MeshAudio_Notify_Release(IMMNotificationClient* self) { UNREFERENCED_PARAMETER(self); return 1; }
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_OnDefaultDeviceChanged(IMMNotificationClient* self, EDataFlow flow, ERole role, LPCWSTR id)
{
    MeshAudioCapture* owner = MeshAudio_NotifyOwner(self);
    UNREFERENCED_PARAMETER(id);
    if (flow == eRender && (role == eConsole || role == eMultimedia)) { SetEvent(owner->deviceChangedEvent); }
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_OnDeviceAdded(IMMNotificationClient* self, LPCWSTR id) { UNREFERENCED_PARAMETER(self); UNREFERENCED_PARAMETER(id); return S_OK; }
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_OnDeviceRemoved(IMMNotificationClient* self, LPCWSTR id) { UNREFERENCED_PARAMETER(self); UNREFERENCED_PARAMETER(id); return S_OK; }
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_OnDeviceStateChanged(IMMNotificationClient* self, LPCWSTR id, DWORD state) { UNREFERENCED_PARAMETER(self); UNREFERENCED_PARAMETER(id); UNREFERENCED_PARAMETER(state); return S_OK; }
static HRESULT STDMETHODCALLTYPE MeshAudio_Notify_OnPropertyValueChanged(IMMNotificationClient* self, LPCWSTR id, const PROPERTYKEY key) { UNREFERENCED_PARAMETER(self); UNREFERENCED_PARAMETER(id); (void)key; return S_OK; }

static const IMMNotificationClientVtbl MeshAudio_NotifyVtbl =
{
    MeshAudio_Notify_QueryInterface,
    MeshAudio_Notify_AddRef,
    MeshAudio_Notify_Release,
    MeshAudio_Notify_OnDeviceStateChanged,
    MeshAudio_Notify_OnDeviceAdded,
    MeshAudio_Notify_OnDeviceRemoved,
    MeshAudio_Notify_OnDefaultDeviceChanged,
    MeshAudio_Notify_OnPropertyValueChanged
};

static DWORD MeshAudio_Timestamp(const MeshAudioCapture* c) { return (DWORD)(GetTickCount64() - c->startTick); }

static DWORD MeshAudio_EmitConfig(MeshAudioCapture* c)
{
    BYTE payload[16];
    MeshAudio_PutLE32(payload + 0, MESH_AUDIO_CODEC_OPUS);
    MeshAudio_PutLE32(payload + 4, MESH_AUDIO_SAMPLE_RATE);
    MeshAudio_PutLE16(payload + 8, MESH_AUDIO_CHANNELS);
    MeshAudio_PutLE16(payload + 10, MESH_AUDIO_FRAME_MS);
    MeshAudio_PutLE32(payload + 12, MESH_AUDIO_BITRATE);
    return MeshAudio_WritePacket(c->writer, MESH_AUDIO_TYPE_CONFIG, MESH_AUDIO_FLAG_DISCONTINUITY,
        c->sequence++, MeshAudio_Timestamp(c), payload, sizeof(payload));
}

// STATUS reasons are fixed ASCII diagnostics chosen at the call site; never audio content.
static DWORD MeshAudio_EmitStatus(MeshAudioCapture* c, DWORD code, const char* reason)
{
    BYTE payload[4 + 256];
    size_t reasonLen = (reason != NULL) ? strlen(reason) : 0;
    if (reasonLen > 256) { reasonLen = 256; }
    MeshAudio_PutLE32(payload, code);
    if (reasonLen != 0) { memcpy(payload + 4, reason, reasonLen); }
    return MeshAudio_WritePacket(c->writer, MESH_AUDIO_TYPE_STATUS, 0, c->sequence++,
        MeshAudio_Timestamp(c), payload, (DWORD)(4 + reasonLen));
}

static DWORD MeshAudio_EmitSilence(MeshAudioCapture* c)
{
    WORD flags = c->pendingDiscontinuity ? MESH_AUDIO_FLAG_DISCONTINUITY : 0;
    DWORD error = MeshAudio_WritePacket(c->writer, MESH_AUDIO_TYPE_SILENCE, flags, c->sequence++, MeshAudio_Timestamp(c), NULL, 0);
    if (error == ERROR_SUCCESS) { c->pendingDiscontinuity = FALSE; }
    return error;
}

static DWORD MeshAudio_EmitFrame(MeshAudioCapture* c)
{
    unsigned char opus[MESH_AUDIO_MAX_PAYLOAD];
    WORD flags = c->pendingDiscontinuity ? MESH_AUDIO_FLAG_DISCONTINUITY : 0;
    int encoded = opus_encode(c->encoder, c->frame, MESH_AUDIO_FRAME_SAMPLES, opus, (opus_int32)sizeof(opus));
    DWORD error;
    if (encoded < 0) { return MeshAudio_EmitStatus(c, (DWORD)(-encoded), "opus-encode-failed"), ERROR_INVALID_DATA; }
    if (encoded == 0) { c->pendingDiscontinuity = FALSE; return ERROR_SUCCESS; }
    error = MeshAudio_WritePacket(c->writer, MESH_AUDIO_TYPE_AUDIO, flags, c->sequence++, MeshAudio_Timestamp(c), opus, (DWORD)encoded);
    if (error == ERROR_SUCCESS) { c->pendingDiscontinuity = FALSE; }
    return error;
}

static opus_int16 MeshAudio_ClampFloat(float value)
{
    float scaled = value * 32767.0f;
    if (scaled > 32767.0f) { scaled = 32767.0f; }
    else if (scaled < -32768.0f) { scaled = -32768.0f; }
    return (opus_int16)(scaled >= 0.0f ? scaled + 0.5f : scaled - 0.5f);
}

// Appends one WASAPI buffer, converting to interleaved s16 stereo and flushing each full 20 ms
// frame. The AUTOCONVERTPCM path (primary) already delivers that format; the fallback handles
// 32-bit float or 16-bit PCM at 48 kHz, taking the first two channels (mono is duplicated).
static DWORD MeshAudio_Append(MeshAudioCapture* c, const BYTE* data, UINT32 frames, BOOL silent)
{
    UINT32 i;
    for (i = 0; i < frames; ++i)
    {
        opus_int16 left, right;
        if (silent) { left = 0; right = 0; }
        else if (c->autoConvert)
        {
            const opus_int16* s = (const opus_int16*)data;
            left = s[i * MESH_AUDIO_CHANNELS];
            right = s[i * MESH_AUDIO_CHANNELS + 1];
        }
        else if (c->sourceIsFloat)
        {
            const float* s = (const float*)data;
            float fl = s[i * c->sourceChannels];
            float fr = (c->sourceChannels >= 2) ? s[i * c->sourceChannels + 1] : fl;
            left = MeshAudio_ClampFloat(fl);
            right = MeshAudio_ClampFloat(fr);
        }
        else
        {
            const opus_int16* s = (const opus_int16*)data;
            left = s[i * c->sourceChannels];
            right = (c->sourceChannels >= 2) ? s[i * c->sourceChannels + 1] : left;
        }
        c->frame[c->frameFill++] = left;
        c->frame[c->frameFill++] = right;
        if (c->frameFill == MESH_AUDIO_FRAME_INTERLEAVED)
        {
            DWORD error = MeshAudio_EmitFrame(c);
            c->frameFill = 0;
            if (error != ERROR_SUCCESS) { return error; }
        }
    }
    return ERROR_SUCCESS;
}

static void MeshAudio_ReleaseEndpoint(MeshAudioCapture* c)
{
    if (c->client != NULL && c->started) { IAudioClient_Stop(c->client); c->started = FALSE; }
    if (c->capture != NULL) { IAudioCaptureClient_Release(c->capture); c->capture = NULL; }
    if (c->client != NULL) { IAudioClient_Release(c->client); c->client = NULL; }
    if (c->device != NULL) { IMMDevice_Release(c->device); c->device = NULL; }
    c->frameFill = 0;
}

// Acquires the default render endpoint and initialises shared-mode loopback, first requesting
// AUTOCONVERTPCM to 48 kHz/stereo/s16, then falling back to the mix format when the engine
// refuses the conversion. Returns an HRESULT (S_OK on success).
static HRESULT MeshAudio_InitEndpoint(MeshAudioCapture* c)
{
    WAVEFORMATEX requested;
    WAVEFORMATEX* mix = NULL;
    HRESULT hr;
    MeshAudio_ReleaseEndpoint(c);
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(c->enumerator, eRender, eConsole, &c->device);
    if (FAILED(hr)) { return hr; }
    hr = IMMDevice_Activate(c->device, &MeshAudio_IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&c->client);
    if (FAILED(hr)) { MeshAudio_ReleaseEndpoint(c); return hr; }

    ZeroMemory(&requested, sizeof(requested));
    requested.wFormatTag = WAVE_FORMAT_PCM;
    requested.nChannels = MESH_AUDIO_CHANNELS;
    requested.nSamplesPerSec = MESH_AUDIO_SAMPLE_RATE;
    requested.wBitsPerSample = 16;
    requested.nBlockAlign = (WORD)(requested.nChannels * requested.wBitsPerSample / 8);
    requested.nAvgBytesPerSec = requested.nSamplesPerSec * requested.nBlockAlign;
    hr = IAudioClient_Initialize(c->client, AUDCLNT_SHAREMODE_SHARED,
        AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
        MESH_AUDIO_BUFFER_DURATION, 0, &requested, NULL);
    if (SUCCEEDED(hr))
    {
        c->autoConvert = TRUE;
        c->sourceIsFloat = FALSE;
        c->sourceChannels = MESH_AUDIO_CHANNELS;
    }
    else
    {
        // Fallback: capture the shared mix format and convert in-process. Only 48 kHz sources
        // are supported here; anything else needs the engine resampler, which just failed.
        HRESULT mixHr = IAudioClient_GetMixFormat(c->client, &mix);
        if (FAILED(mixHr)) { MeshAudio_ReleaseEndpoint(c); return mixHr; }
        if (mix->nSamplesPerSec != MESH_AUDIO_SAMPLE_RATE || mix->nChannels < 1)
        { CoTaskMemFree(mix); MeshAudio_ReleaseEndpoint(c); return AUDCLNT_E_UNSUPPORTED_FORMAT; }
        if (mix->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
            (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
             IsEqualGUID(&((WAVEFORMATEXTENSIBLE*)mix)->SubFormat, &MeshAudio_SUBTYPE_IEEE_FLOAT)))
        { c->sourceIsFloat = TRUE; }
        else if (mix->wBitsPerSample == 16 &&
            (mix->wFormatTag == WAVE_FORMAT_PCM ||
             (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
              IsEqualGUID(&((WAVEFORMATEXTENSIBLE*)mix)->SubFormat, &MeshAudio_SUBTYPE_PCM))))
        { c->sourceIsFloat = FALSE; }
        else { CoTaskMemFree(mix); MeshAudio_ReleaseEndpoint(c); return AUDCLNT_E_UNSUPPORTED_FORMAT; }
        c->autoConvert = FALSE;
        c->sourceChannels = mix->nChannels;
        hr = IAudioClient_Initialize(c->client, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
            MESH_AUDIO_BUFFER_DURATION, 0, mix, NULL);
        CoTaskMemFree(mix);
        if (FAILED(hr)) { MeshAudio_ReleaseEndpoint(c); return hr; }
    }

    hr = IAudioClient_GetService(c->client, &MeshAudio_IID_IAudioCaptureClient, (void**)&c->capture);
    if (FAILED(hr)) { MeshAudio_ReleaseEndpoint(c); return hr; }
    hr = IAudioClient_Start(c->client);
    if (FAILED(hr)) { MeshAudio_ReleaseEndpoint(c); return hr; }
    c->started = TRUE;
    return S_OK;
}

// Re-acquires the default endpoint after a device change or invalidation, retrying briefly while
// the OS settles on a new default. Emits a CONFIG boundary on success; STATUS then fail on giving up.
static DWORD MeshAudio_Reinit(MeshAudioCapture* c)
{
    int attempt;
    HRESULT hr = AUDCLNT_E_DEVICE_INVALIDATED;
    for (attempt = 0; attempt < MESH_AUDIO_REINIT_ATTEMPTS; ++attempt)
    {
        if (WaitForSingleObject(c->stopEvent, 0) == WAIT_OBJECT_0) { return ERROR_SUCCESS; }
        ResetEvent(c->deviceChangedEvent);
        hr = MeshAudio_InitEndpoint(c);
        if (SUCCEEDED(hr)) { break; }
        if (WaitForSingleObject(c->stopEvent, 200) == WAIT_OBJECT_0) { return ERROR_SUCCESS; }
    }
    if (FAILED(hr)) { MeshAudio_EmitStatus(c, (DWORD)hr, "audio-device-reinit-failed"); return (DWORD)hr; }
    c->pendingDiscontinuity = TRUE;
    return MeshAudio_EmitConfig(c);
}

// Main capture loop: COM + enumerator + encoder + notification client, then poll the loopback
// endpoint, emitting AUDIO frames while data flows and a SILENCE heartbeat while it does not.
static DWORD MeshAudio_RunCapture(MeshAudioWriter* writer, HANDLE stopEvent)
{
    MeshAudioCapture capture;
    DWORD error = ERROR_SUCCESS;
    int opusError = OPUS_OK;
    HRESULT hr;
    ULONGLONG nextSilence;
    BOOL comReady = FALSE;

    ZeroMemory(&capture, sizeof(capture));
    capture.writer = writer;
    capture.stopEvent = stopEvent;
    capture.notify.lpVtbl = (IMMNotificationClientVtbl*)&MeshAudio_NotifyVtbl;
    capture.startTick = GetTickCount64();
    capture.pendingDiscontinuity = TRUE;

    capture.deviceChangedEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (capture.deviceChangedEvent == NULL) { return GetLastError(); }

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { error = (DWORD)hr; goto cleanup; }
    comReady = (hr != RPC_E_CHANGED_MODE);

    capture.encoder = opus_encoder_create(MESH_AUDIO_SAMPLE_RATE, MESH_AUDIO_CHANNELS, OPUS_APPLICATION_RESTRICTED_LOWDELAY, &opusError);
    if (capture.encoder == NULL || opusError != OPUS_OK) { error = ERROR_NOT_ENOUGH_MEMORY; goto cleanup; }
    opus_encoder_ctl(capture.encoder, OPUS_SET_BITRATE(MESH_AUDIO_BITRATE));
    opus_encoder_ctl(capture.encoder, OPUS_SET_VBR(0));

    hr = CoCreateInstance(&MeshAudio_CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, &MeshAudio_IID_IMMDeviceEnumerator, (void**)&capture.enumerator);
    if (FAILED(hr)) { error = (DWORD)hr; goto cleanup; }
    if (SUCCEEDED(IMMDeviceEnumerator_RegisterEndpointNotificationCallback(capture.enumerator, &capture.notify)))
    { capture.notifyRegistered = TRUE; }

    hr = MeshAudio_InitEndpoint(&capture);
    if (FAILED(hr))
    {
        MeshAudioWriter* w = capture.writer;
        BYTE payload[4 + 32];
        MeshAudio_PutLE32(payload, (DWORD)hr);
        memcpy(payload + 4, "audio-device-init-failed", 24);
        MeshAudio_WritePacket(w, MESH_AUDIO_TYPE_STATUS, 0, capture.sequence++, MeshAudio_Timestamp(&capture), payload, 4 + 24);
        error = (DWORD)hr;
        goto cleanup;
    }

    error = MeshAudio_EmitConfig(&capture);
    if (error != ERROR_SUCCESS) { goto cleanup; }
    nextSilence = GetTickCount64() + MESH_AUDIO_SILENCE_MS;

    for (;;)
    {
        UINT32 packetFrames = 0;
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) { break; }
        if (WaitForSingleObject(capture.deviceChangedEvent, 0) == WAIT_OBJECT_0)
        {
            error = MeshAudio_Reinit(&capture);
            if (error != ERROR_SUCCESS || WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) { break; }
            nextSilence = GetTickCount64() + MESH_AUDIO_SILENCE_MS;
            continue;
        }
        hr = IAudioCaptureClient_GetNextPacketSize(capture.capture, &packetFrames);
        if (hr == AUDCLNT_E_DEVICE_INVALIDATED)
        {
            error = MeshAudio_Reinit(&capture);
            if (error != ERROR_SUCCESS || WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) { break; }
            nextSilence = GetTickCount64() + MESH_AUDIO_SILENCE_MS;
            continue;
        }
        if (FAILED(hr)) { MeshAudio_EmitStatus(&capture, (DWORD)hr, "audio-capture-failed"); error = (DWORD)hr; break; }

        if (packetFrames == 0)
        {
            HANDLE waits[2] = { stopEvent, capture.deviceChangedEvent };
            if (GetTickCount64() >= nextSilence)
            {
                error = MeshAudio_EmitSilence(&capture);
                if (error != ERROR_SUCCESS) { break; }
                nextSilence = GetTickCount64() + MESH_AUDIO_SILENCE_MS;
            }
            if (WaitForMultipleObjects(2, waits, FALSE, MESH_AUDIO_POLL_MS) == WAIT_OBJECT_0) { break; }
            continue;
        }

        while (packetFrames != 0)
        {
            BYTE* data = NULL;
            UINT32 frames = 0;
            DWORD flags = 0;
            hr = IAudioCaptureClient_GetBuffer(capture.capture, &data, &frames, &flags, NULL, NULL);
            if (hr == AUDCLNT_S_BUFFER_EMPTY) { break; }
            if (FAILED(hr)) { break; }
            if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) { capture.pendingDiscontinuity = TRUE; }
            error = MeshAudio_Append(&capture, data, frames, (flags & AUDCLNT_BUFFERFLAGS_SILENT) ? TRUE : FALSE);
            IAudioCaptureClient_ReleaseBuffer(capture.capture, frames);
            if (error != ERROR_SUCCESS) { break; }
            hr = IAudioCaptureClient_GetNextPacketSize(capture.capture, &packetFrames);
            if (FAILED(hr)) { break; }
        }
        if (error != ERROR_SUCCESS) { break; }
        if (hr == AUDCLNT_E_DEVICE_INVALIDATED)
        {
            error = MeshAudio_Reinit(&capture);
            if (error != ERROR_SUCCESS || WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) { break; }
        }
        else if (FAILED(hr))
        {
            // Any other GetBuffer / GetNextPacketSize failure would otherwise retry at once with no wait.
            MeshAudio_EmitStatus(&capture, (DWORD)hr, "audio-capture-failed");
            error = (DWORD)hr;
            break;
        }
        nextSilence = GetTickCount64() + MESH_AUDIO_SILENCE_MS;
    }

cleanup:
    MeshAudio_ReleaseEndpoint(&capture);
    if (capture.notifyRegistered) { IMMDeviceEnumerator_UnregisterEndpointNotificationCallback(capture.enumerator, &capture.notify); }
    if (capture.enumerator != NULL) { IMMDeviceEnumerator_Release(capture.enumerator); }
    if (capture.encoder != NULL) { opus_encoder_destroy(capture.encoder); }
    if (comReady) { CoUninitialize(); }
    if (capture.deviceChangedEvent != NULL) { CloseHandle(capture.deviceChangedEvent); }
    return error;
}

// libopus is vendored with ENABLE_HARDENING, so an internal fault calls abort(). The capture
// child runs in the interactive user session, so suppress the WER/CRT crash UI and turn an abort
// into a quiet, distinct process exit; the broker then reports it on its normal failure path
// rather than leaving a dialog on the user's desktop or hanging.
static void MeshAudio_OnAbort(int signalNumber) { UNREFERENCED_PARAMETER(signalNumber); ExitProcess(MESH_AUDIO_EXIT_ABORT); }
static void MeshAudio_SuppressCrashUI(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#if defined(_MSC_VER)
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    signal(SIGABRT, MeshAudio_OnAbort);
}

// Watches the inherited stdin for EOF so the helper exits when the agent closes the pipe.
static DWORD WINAPI MeshAudio_StdinWatch(LPVOID parameter)
{
    HANDLE stopEvent = (HANDLE)parameter;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    BYTE scratch[64];
    DWORD read = 0;
    for (;;)
    {
        if (input == NULL || input == INVALID_HANDLE_VALUE) { break; }
        if (!ReadFile(input, scratch, sizeof(scratch), &read, NULL) || read == 0) { break; }
    }
    SetEvent(stopEvent);
    return 0;
}

// "local": capture directly on the current (user-session) process; packets go to stdout.
static DWORD MeshAudio_Local(void)
{
    MeshAudioWriter writer;
    HANDLE stopEvent, watcher;
    DWORD session = 0, error;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session == 0) { return ERROR_ACCESS_DENIED; }
    MeshAudio_SuppressCrashUI();
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) { return GetLastError(); }
    writer.handle = GetStdHandle(STD_OUTPUT_HANDLE);
    writer.overlapped = FALSE;
    watcher = CreateThread(NULL, 0, MeshAudio_StdinWatch, stopEvent, 0, NULL);
    error = MeshAudio_RunCapture(&writer, stopEvent);
    SetEvent(stopEvent);
    if (watcher != NULL) { WaitForSingleObject(watcher, 1000); CloseHandle(watcher); }
    CloseHandle(stopEvent);
    return error;
}

// "user ...": the broker-launched capture child. Connects to the broker pipe, verifies the
// server PID and its own session, then streams packets to the pipe until it breaks. The child is
// created without inherited handles, so it has no stdin to watch: it stops when a write to the
// broker pipe fails (at the latest on the next SILENCE heartbeat) or when the broker's
// kill-on-close job ends it.
static DWORD MeshAudio_User(const wchar_t* pipeName, DWORD brokerPid, DWORD sessionId)
{
    MeshAudioWriter writer;
    HANDLE pipe = INVALID_HANDLE_VALUE, stopEvent = NULL;
    ULONG serverPid = 0;
    DWORD actualSession = 0, error = ERROR_ACCESS_DENIED;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &actualSession) || actualSession != sessionId || sessionId == 0) { return error; }
    MeshAudio_SuppressCrashUI();
    if (!WaitNamedPipeW(pipeName, MESH_AUDIO_IO_MS)) { return GetLastError(); }
    pipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) { return GetLastError(); }
    if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid != brokerPid) { CloseHandle(pipe); return ERROR_ACCESS_DENIED; }
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) { error = GetLastError(); CloseHandle(pipe); return error; }
    writer.handle = pipe;
    writer.overlapped = TRUE;
    error = MeshAudio_RunCapture(&writer, stopEvent);
    CloseHandle(stopEvent);
    CloseHandle(pipe);
    return error;
}

// Relays the user child's packet stream to stdout, stopping on stdin EOF or a break on either
// pipe. The broker is a transparent byte relay; the agent frames the stream. Child exit is not
// checked before a read: a child that writes STATUS and exits leaves those bytes in the pipe, and
// they must be drained before the read reports the broken pipe.
static DWORD MeshAudio_Relay(HANDLE pipe, HANDLE child, HANDLE stdinEof)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    BYTE buffer[MESH_AUDIO_RELAY_BUFFER];
    OVERLAPPED ov = {0};
    DWORD error = ERROR_SUCCESS;
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) { return GetLastError(); }
    for (;;)
    {
        DWORD read = 0, written = 0;
        BOOL ok;
        if (WaitForSingleObject(stdinEof, 0) == WAIT_OBJECT_0) { break; }
        ResetEvent(ov.hEvent);
        ok = ReadFile(pipe, buffer, sizeof(buffer), &read, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING)
        {
            HANDLE waits[3] = { ov.hEvent, child, stdinEof };
            DWORD wait = WaitForMultipleObjects(3, waits, FALSE, INFINITE);
            if (wait != WAIT_OBJECT_0)
            {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &read, TRUE);
                break;
            }
            if (!GetOverlappedResult(pipe, &ov, &read, FALSE)) { error = GetLastError(); break; }
        }
        else if (!ok) { error = GetLastError(); break; }
        if (read == 0) { error = ERROR_BROKEN_PIPE; break; }
        if (!WriteFile(output, buffer, read, &written, NULL) || written != read) { error = GetLastError(); break; }
    }
    CloseHandle(ov.hEvent);
    return error;
}

// Session-0 broker: launches the capture child into the target user session under a
// kill-on-close job object, exactly like the clipboard broker, then relays its stream.
static DWORD MeshAudio_Broker(DWORD sessionId, HINSTANCE module)
{
    HANDLE token = NULL, pipe = INVALID_HANDLE_VALUE, job = NULL, stdinEof = NULL, watcher = NULL;
    PROCESS_INFORMATION child = {0};
    STARTUPINFOW startup = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    MeshProcessTokenSnapshot snapshot;
    LPWSTR sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, FALSE};
    wchar_t pipeName[128], sddl[256], host[MAX_PATH], dll[MAX_PATH * 4], command[4096];
    DWORD error = ERROR_ACCESS_DENIED;
    OVERLAPPED connect = {0};
    ULONG clientPid = 0;
    BOOL connected;
    if (!MeshProcessToken_Open(MeshProcessToken_SessionUser, sessionId, &token) ||
        !MeshProcessToken_Read(token, &snapshot) || !ConvertSidToStringSidW((PSID)snapshot.sid, &sid))
    { error = GetLastError(); goto cleanup; }
    swprintf_s(pipeName, _countof(pipeName), L"\\\\.\\pipe\\MeshAudio_%lu", GetCurrentProcessId());
    swprintf_s(sddl, _countof(sddl), L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)", sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, NULL))
    { error = GetLastError(); goto cleanup; }
    attributes.lpSecurityDescriptor = descriptor;
    pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes);
    if (pipe == INVALID_HANDLE_VALUE) { error = GetLastError(); goto cleanup; }
    job = CreateJobObjectW(NULL, NULL);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job == NULL || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    { error = GetLastError(); goto cleanup; }
    if (!MeshRuntimeHost_GetSystemHostPathW(host, _countof(host)) ||
        GetModuleFileNameW(module, dll, _countof(dll)) == 0 || wcslen(dll) >= _countof(dll) - 1)
    { error = ERROR_INVALID_NAME; goto cleanup; }
    if (FAILED(StringCchPrintfW(command, _countof(command), L"\"%ls\" \"%ls\",MeshAudioBridgeW user %ls %lu %lu",
        host, dll, pipeName, GetCurrentProcessId(), sessionId))) { error = ERROR_BUFFER_OVERFLOW; goto cleanup; }
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_FORCEOFFFEEDBACK; // no "app starting" cursor for this hidden helper
    startup.lpDesktop = L"winsta0\\default";
    if (!CreateProcessAsUserW(token, host, command, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child))
    { error = GetLastError(); goto cleanup; }
    if (!AssignProcessToJobObject(job, child.hProcess)) { error = GetLastError(); goto cleanup; }
    if (!MeshProcessToken_VerifyChildAndResume(MeshProcessToken_SessionUser, token, &child))
    { error = GetLastError(); goto cleanup; }
    connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (connect.hEvent == NULL) { error = GetLastError(); goto cleanup; }
    connected = ConnectNamedPipe(pipe, &connect);
    if (!connected)
    {
        error = GetLastError();
        if (error == ERROR_IO_PENDING)
        {
            HANDLE waits[2] = {connect.hEvent, child.hProcess};
            DWORD wait = WaitForMultipleObjects(2, waits, FALSE, MESH_AUDIO_IO_MS), count;
            if (wait != WAIT_OBJECT_0)
            {
                error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_BROKEN_PIPE;
                CancelIoEx(pipe, &connect); GetOverlappedResult(pipe, &connect, &count, TRUE);
                goto cleanup;
            }
            if (!GetOverlappedResult(pipe, &connect, &count, FALSE)) { error = GetLastError(); goto cleanup; }
        }
        else if (error != ERROR_PIPE_CONNECTED) { goto cleanup; }
    }
    if (!GetNamedPipeClientProcessId(pipe, &clientPid) || clientPid != child.dwProcessId) { error = ERROR_ACCESS_DENIED; goto cleanup; }
    stdinEof = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stdinEof == NULL) { error = GetLastError(); goto cleanup; }
    watcher = CreateThread(NULL, 0, MeshAudio_StdinWatch, stdinEof, 0, NULL);
    error = MeshAudio_Relay(pipe, child.hProcess, stdinEof);
cleanup:
    // Closing the kill-on-close job terminates the capture child; mirror the clipboard broker.
    if (child.hProcess != NULL)
    {
        if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) { TerminateProcess(child.hProcess, error); }
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hProcess);
    }
    if (child.hThread != NULL) { CloseHandle(child.hThread); }
    if (stdinEof != NULL) { SetEvent(stdinEof); }
    if (watcher != NULL) { WaitForSingleObject(watcher, 1000); CloseHandle(watcher); }
    if (job != NULL) { CloseHandle(job); }
    if (stdinEof != NULL) { CloseHandle(stdinEof); }
    if (connect.hEvent != NULL) { CloseHandle(connect.hEvent); }
    if (pipe != INVALID_HANDLE_VALUE) { CloseHandle(pipe); }
    if (descriptor != NULL) { LocalFree(descriptor); }
    if (sid != NULL) { LocalFree(sid); }
    if (token != NULL) { CloseHandle(token); }
    return error;
}

static DWORD MeshAudio_Run(const wchar_t* tail, HINSTANCE module)
{
    const wchar_t* cursor = tail;
    wchar_t mode[32], pipe[128], pidText[16], sessionText[16], extra[2];
    DWORD session, pid;
    if (!MeshRuntimeHost_CopyNextTokenW(&cursor, mode, _countof(mode))) { return ERROR_INVALID_PARAMETER; }
    if (wcscmp(mode, L"local") == 0 || wcsncmp(mode, L"tsid=", 5) == 0)
    {
        if (MeshRuntimeHost_CopyNextTokenW(&cursor, extra, _countof(extra)) || GetLastError() != ERROR_NO_MORE_ITEMS)
        { return ERROR_INVALID_PARAMETER; }
        if (wcscmp(mode, L"local") == 0) { return MeshAudio_Local(); }
        if (!MeshConsoleBridge_ParseUnsignedTokenW(mode + 5, 1, 0xFFFFFFFEUL, &session)) { return ERROR_INVALID_PARAMETER; }
        return MeshAudio_Broker(session, module);
    }
    if (wcscmp(mode, L"user") != 0 ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, pipe, _countof(pipe)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, pidText, _countof(pidText)) ||
        !MeshRuntimeHost_CopyNextTokenW(&cursor, sessionText, _countof(sessionText)) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(pidText, 1, 0xFFFFFFFEUL, &pid) ||
        !MeshConsoleBridge_ParseUnsignedTokenW(sessionText, 1, 0xFFFFFFFEUL, &session)) { return ERROR_INVALID_PARAMETER; }
    swprintf_s(mode, _countof(mode), L"%lu", pid);
    {
        wchar_t expected[128];
        swprintf_s(expected, _countof(expected), L"\\\\.\\pipe\\MeshAudio_%ls", mode);
        if (wcscmp(pipe, expected) != 0 || MeshRuntimeHost_CopyNextTokenW(&cursor, extra, _countof(extra)) ||
            GetLastError() != ERROR_NO_MORE_ITEMS) { return ERROR_INVALID_PARAMETER; }
    }
    return MeshAudio_User(pipe, pid, session);
}
#endif
