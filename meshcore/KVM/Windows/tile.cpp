/*   
Copyright 2006 - 2022 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#if defined(_LINKVM)

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_5.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
#include "tile.h"
#include <gdiplus.h>
#include "meshcore/meshdefines.h"

// Runtime-load optional graphics capture APIs so startup does not depend on DXGI/D3D11 exports.
typedef HRESULT(WINAPI* PFN_CreateDXGIFactory1)(REFIID riid, void** ppFactory);
typedef HRESULT(WINAPI* PFN_D3D11CreateDevice)(IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags, const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels, UINT SDKVersion, ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel, ID3D11DeviceContext** ppImmediateContext);
typedef HRESULT(WINAPI* PFN_CreateDirect3D11DeviceFromDXGIDevice)(IDXGIDevice* dxgiDevice, IInspectable** inspectable);

static PFN_CreateDXGIFactory1 g_pfnCreateDXGIFactory1 = NULL;
static PFN_D3D11CreateDevice g_pfnD3D11CreateDevice = NULL;
static PFN_CreateDirect3D11DeviceFromDXGIDevice g_pfnCreateDirect3D11DeviceFromDXGIDevice = NULL;

static HMODULE g_hDxgi = NULL;
static HMODULE g_hD3D11 = NULL;
static LONG gGraphicsRuntimeLoaded = 0;

static void tile_load_graphics_runtime()
{
	if (InterlockedCompareExchange(&gGraphicsRuntimeLoaded, 1, 0) != 0) { return; }
	g_hDxgi = LoadLibraryA("dxgi.dll");
	if (g_hDxgi != NULL) { g_pfnCreateDXGIFactory1 = (PFN_CreateDXGIFactory1)GetProcAddress(g_hDxgi, "CreateDXGIFactory1"); }

	g_hD3D11 = LoadLibraryA("d3d11.dll");
	if (g_hD3D11 != NULL)
	{
		g_pfnD3D11CreateDevice = (PFN_D3D11CreateDevice)GetProcAddress(g_hD3D11, "D3D11CreateDevice");
		g_pfnCreateDirect3D11DeviceFromDXGIDevice = (PFN_CreateDirect3D11DeviceFromDXGIDevice)GetProcAddress(g_hD3D11, "CreateDirect3D11DeviceFromDXGIDevice");
	}
}

static HRESULT tile_create_dxgi_factory1(REFIID riid, void** ppFactory)
{
	tile_load_graphics_runtime();
	return (g_pfnCreateDXGIFactory1 != NULL) ? g_pfnCreateDXGIFactory1(riid, ppFactory) : E_NOTIMPL;
}

static HRESULT tile_d3d11_create_device(IDXGIAdapter* adapter, D3D_DRIVER_TYPE driverType, HMODULE software, UINT flags, const D3D_FEATURE_LEVEL* featureLevels, UINT featureLevelCount, UINT sdkVersion, ID3D11Device** device, D3D_FEATURE_LEVEL* featureLevel, ID3D11DeviceContext** context)
{
	tile_load_graphics_runtime();
	return (g_pfnD3D11CreateDevice != NULL) ? g_pfnD3D11CreateDevice(adapter, driverType, software, flags, featureLevels, featureLevelCount, sdkVersion, device, featureLevel, context) : E_NOTIMPL;
}

static HRESULT tile_create_direct3d11_device_from_dxgi_device(IDXGIDevice* dxgiDevice, IInspectable** inspectable)
{
	tile_load_graphics_runtime();
	return (g_pfnCreateDirect3D11DeviceFromDXGIDevice != NULL) ? g_pfnCreateDirect3D11DeviceFromDXGIDevice(dxgiDevice, inspectable) : E_NOTIMPL;
}
using namespace Gdiplus;
namespace wg = winrt::Windows::Graphics;
namespace wgc = winrt::Windows::Graphics::Capture;
namespace wd = winrt::Windows::Graphics::DirectX;
namespace wd3d = winrt::Windows::Graphics::DirectX::Direct3D11;

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

// #define KVMDEBUGENABLED 1

#ifdef KVMDEBUGENABLED
extern "C"
{
extern void KvmCriticalLog(const char* msg, const char* file, int line, int user1, int user2);
#define KVMDEBUG(m,u) { KvmCriticalLog(m, __FILE__, __LINE__, u, GetLastError()); printf("TVMMSG: %s (%d,%d).\r\n", m, (int)u, (int)GetLastError()); }
#define KVMDEBUG2(x) x
}
#else
#define KVMDEBUG(m, u)
#define KVMDEBUG2(x)
#endif

extern "C"
{
#include "microstack/ILibCrypto.h"
extern int TILE_WIDTH;
extern int TILE_HEIGHT;
extern int SCREEN_WIDTH;
extern int SCREEN_HEIGHT;
extern int SCREEN_X;
extern int SCREEN_Y;
extern int SCREEN_COUNT;
extern int SCREEN_SEL_TARGET;
extern int SCALED_WIDTH;
extern int SCALED_HEIGHT;
extern int PIXEL_SIZE;
extern int TILE_WIDTH_COUNT;
extern int TILE_HEIGHT_COUNT;
extern int COMPRESSION_RATIO;
extern volatile LONG SCALING_FACTOR;
extern volatile LONG SCALING_FACTOR_NEW;
extern int FRAME_RATE_TIMER;
extern tileInfo_t **tileInfo;
extern int g_shutdown;
extern int gKvmDesktopCaptureReady;
void KVM_TraceStartupF(const char* format, ...);
}

// Used with setting up a GDI+ session.
GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR gdiplusToken;
HDC hDesktopDC;
HDC hCaptureDC;
HBITMAP hCapturedBitmap;
//HDC hdc;
CLSID encoderClsid;
ULONG encCompression = 50; // Image compression
EncoderParameters encParam;
LPVOID tilebuffer = NULL;
unsigned int tilebuffersize = 0;

enum KvmCaptureBackend
{
	KvmCaptureBackend_GDI = 0,
	KvmCaptureBackend_DXGI = 1,
	KvmCaptureBackend_WGC = 2
};

typedef struct DxgiCaptureState
{
	IDXGIAdapter1* adapter;
	IDXGIOutput* output;
	IDXGIOutput1* output1;
	IDXGIOutput5* output5;
	IDXGIOutputDuplication* duplication;
	ID3D11Device* device;
	ID3D11DeviceContext* context;
	ID3D11Texture2D* stagingTexture;
	UINT sourceWidth;
	UINT sourceHeight;
	DXGI_MODE_ROTATION rotation;
	int targetScreen;
	int screenX;
	int screenY;
	int screenWidth;
	int screenHeight;
	int retryDelayMs;
	int idleFramePolls;
	ULONGLONG nextRetryTick;
	unsigned char* lastFrame;
	size_t lastFrameSize;
	char duplicatePath[32];
}DxgiCaptureState;

struct WgcCaptureState
{
	ID3D11Device* device = NULL;
	ID3D11DeviceContext* context = NULL;
	ID3D11Texture2D* stagingTexture = NULL;
	wd3d::IDirect3DDevice winrtDevice{ nullptr };
	wgc::GraphicsCaptureItem item{ nullptr };
	wgc::Direct3D11CaptureFramePool framePool{ nullptr };
	wgc::GraphicsCaptureSession session{ nullptr };
	winrt::event_token frameArrivedToken{};
	HANDLE frameArrivedEvent = NULL;
	HMONITOR targetMonitor = NULL;
	UINT sourceWidth = 0;
	UINT sourceHeight = 0;
	int targetScreen = 0;
	int screenX = 0;
	int screenY = 0;
	int screenWidth = 0;
	int screenHeight = 0;
	int retryDelayMs = 0;
	ULONGLONG nextRetryTick = 0;
	int idleFramePolls = 0;
	unsigned char* lastFrame = NULL;
	size_t lastFrameSize = 0;
	char activateReason[32] = { 0 };
};

static DxgiCaptureState gDxgiCapture = { 0 };
static WgcCaptureState gWgcCapture = { };
static KvmCaptureBackend gCaptureBackend = KvmCaptureBackend_GDI;
static char gCaptureBackendReason[128] = "gdi:init";
static int gCaptureBackendOverride = -1;
static int gDxgiSimulateUnsupported = 0;
static int gDxgiSimulateAccessLostOnce = 0;
static int gDxgiSimulateAccessLostConsumed = 0;
static int gWgcSimulateUnavailable = 0;
static int gWinRtApartmentInitialized = 0;
static int gWinRtApartmentNeedsUninit = 0;
static LONG gTileTraceCounter = 0;
static const int TILE_CAPTURE_RETRY_INITIAL_DELAY_MS = 250;
static const int TILE_CAPTURE_RETRY_MAX_DELAY_MS = 3000;
static const UINT TILE_DXGI_INITIAL_FRAME_WAIT_MS = 16;
static const UINT TILE_DXGI_RETRY_FRAME_WAIT_MS = 33;
static const int TILE_DXGI_FRAME_READY_ATTEMPTS = 4;
static const int TILE_DXGI_IDLE_RESET_THRESHOLD = 4;
static const DWORD TILE_WGC_FRAME_WAIT_TIMEOUT_MS = 250;
static const int TILE_WGC_IDLE_RESET_THRESHOLD = 4;
static const UINT TILE_DXGI_ONESHOT_FRAME_WAIT_MS = 500;
static const int TILE_DXGI_ONESHOT_FRAME_READY_ATTEMPTS = 3;

int adjust_screen_size(int pixles);

template<typename T> static void tile_safe_release(T** value)
{
	if (value != NULL && *value != NULL)
	{
		(*value)->Release();
		*value = NULL;
	}
}

static int tile_read_env_bool(const char* name, int defaultValue)
{
	char value[32];
	DWORD len = GetEnvironmentVariableA(name, value, (DWORD)sizeof(value));
	if (len == 0 || len >= sizeof(value)) { return defaultValue; }
	if (_stricmp(value, "1") == 0 || _stricmp(value, "true") == 0 || _stricmp(value, "yes") == 0 || _stricmp(value, "on") == 0) { return 1; }
	if (_stricmp(value, "0") == 0 || _stricmp(value, "false") == 0 || _stricmp(value, "no") == 0 || _stricmp(value, "off") == 0) { return 0; }
	return defaultValue;
}

static void tile_tracef(const char* format, ...)
{
	char buffer[512];
	char pathBuffer[MAX_PATH] = { 0 };
	int len = 0;
	int enabled = 0;
	va_list args;
	HANDLE stderrHandle = INVALID_HANDLE_VALUE;
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	DWORD written = 0;

	enabled = (GetEnvironmentVariableA("STEALTH_KVM_TRACE_TILE", NULL, 0) > 0) ? 1 : 0;
	if (enabled == 0 || format == NULL) { return; }
	if (InterlockedIncrement(&gTileTraceCounter) > 128) { return; }

	va_start(args, format);
	len = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
	va_end(args);
	if (len <= 0) { return; }
	if (len > (int)sizeof(buffer) - 3) { len = (int)sizeof(buffer) - 3; }
	if (len == 0 || buffer[len - 1] != '\n')
	{
		buffer[len++] = '\r';
		buffer[len++] = '\n';
		buffer[len] = 0;
	}

	OutputDebugStringA(buffer);
	stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
	if (stderrHandle != NULL && stderrHandle != INVALID_HANDLE_VALUE)
	{
		WriteFile(stderrHandle, buffer, (DWORD)len, &written, NULL);
	}
	if (GetTempPathA((DWORD)_countof(pathBuffer), pathBuffer) > 0 &&
		strcat_s(pathBuffer, sizeof(pathBuffer), "meshagent_tile_trace.log") == 0)
	{
		fileHandle = CreateFileA(pathBuffer, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fileHandle != INVALID_HANDLE_VALUE)
		{
			WriteFile(fileHandle, buffer, (DWORD)len, &written, NULL);
			CloseHandle(fileHandle);
		}
	}
}

static int tile_read_capture_backend_override()
{
	char value[32];
	DWORD len = GetEnvironmentVariableA("STEALTH_KVM_CAPTURE_BACKEND", value, (DWORD)sizeof(value));
	if (len == 0 || len >= sizeof(value)) { return -1; }
	if (_stricmp(value, "gdi") == 0) { return 0; }
	if (_stricmp(value, "dxgi") == 0) { return 1; }
	if (_stricmp(value, "wgc") == 0) { return 2; }
	if (_stricmp(value, "auto") == 0) { return -1; }
	return -1;
}

static void tile_set_capture_backend(KvmCaptureBackend backend, const char* reason)
{
	const char* backendName = "gdi";
	gCaptureBackend = backend;
	if (reason == NULL)
	{
		switch (backend)
		{
		case KvmCaptureBackend_DXGI: reason = "dxgi:active"; break;
		case KvmCaptureBackend_WGC: reason = "wgc:active"; break;
		default: reason = "gdi:active"; break;
		}
	}
	switch (backend)
	{
	case KvmCaptureBackend_DXGI: backendName = "dxgi"; break;
	case KvmCaptureBackend_WGC: backendName = "wgc"; break;
	default: break;
	}
	strcpy_s(gCaptureBackendReason, sizeof(gCaptureBackendReason), reason);
	tile_tracef("capture backend=%s reason=%s", backendName, gCaptureBackendReason);
}

static const char* tile_dxgi_reason_from_hresult(HRESULT hr)
{
	switch (hr)
	{
	case DXGI_ERROR_UNSUPPORTED: return "gdi:dxgi-unsupported";
	case DXGI_ERROR_ACCESS_LOST: return "gdi:dxgi-access-lost";
	case DXGI_ERROR_NOT_CURRENTLY_AVAILABLE: return "gdi:dxgi-busy";
	case DXGI_ERROR_SESSION_DISCONNECTED: return "gdi:dxgi-session-disconnected";
	case E_ACCESSDENIED: return "gdi:dxgi-access-denied";
	default: return "gdi:dxgi-error";
	}
}

static int tile_capture_next_retry_delay_ms(int currentDelay)
{
	int delay = (currentDelay == 0) ? TILE_CAPTURE_RETRY_INITIAL_DELAY_MS : currentDelay;
	return delay > TILE_CAPTURE_RETRY_MAX_DELAY_MS ? TILE_CAPTURE_RETRY_MAX_DELAY_MS : delay;
}

static HRESULT tile_dxgi_release_frame(IDXGIOutputDuplication* duplication, IDXGIResource** desktopResource)
{
	HRESULT hr = S_OK;

	if (desktopResource != NULL && *desktopResource != NULL)
	{
		(*desktopResource)->Release();
		*desktopResource = NULL;
	}
	if (duplication != NULL)
	{
		hr = duplication->ReleaseFrame();
	}
	return hr;
}

static void tile_dxgi_release_runtime(int clearCache)
{
	tile_safe_release(&gDxgiCapture.stagingTexture);
	tile_safe_release(&gDxgiCapture.duplication);
	tile_safe_release(&gDxgiCapture.output5);
	tile_safe_release(&gDxgiCapture.output1);
	tile_safe_release(&gDxgiCapture.output);
	tile_safe_release(&gDxgiCapture.context);
	tile_safe_release(&gDxgiCapture.device);
	tile_safe_release(&gDxgiCapture.adapter);
	gDxgiCapture.sourceWidth = 0;
	gDxgiCapture.sourceHeight = 0;
	gDxgiCapture.rotation = DXGI_MODE_ROTATION_UNSPECIFIED;
	gDxgiCapture.targetScreen = 0;
	gDxgiCapture.screenX = 0;
	gDxgiCapture.screenY = 0;
	gDxgiCapture.screenWidth = 0;
	gDxgiCapture.screenHeight = 0;
	gDxgiCapture.duplicatePath[0] = 0;
	gDxgiCapture.idleFramePolls = 0;
	if (clearCache && gDxgiCapture.lastFrame != NULL)
	{
		free(gDxgiCapture.lastFrame);
		gDxgiCapture.lastFrame = NULL;
		gDxgiCapture.lastFrameSize = 0;
	}
}

static void tile_dxgi_schedule_retry_ex(const char* reason, int clearCache)
{
	int delay = tile_capture_next_retry_delay_ms(gDxgiCapture.retryDelayMs);
	gDxgiCapture.nextRetryTick = GetTickCount64() + (ULONGLONG)delay;
	gDxgiCapture.retryDelayMs = delay < TILE_CAPTURE_RETRY_MAX_DELAY_MS ? (delay * 2) : TILE_CAPTURE_RETRY_MAX_DELAY_MS;
	tile_dxgi_release_runtime(clearCache);
	tile_set_capture_backend(KvmCaptureBackend_GDI, reason);
}

static void tile_dxgi_schedule_retry(const char* reason)
{
	tile_dxgi_schedule_retry_ex(reason, 0);
}

static int tile_wgc_ensure_apartment()
{
	HRESULT hr;

	if (gWinRtApartmentInitialized != 0) { return 1; }
	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr) || hr == S_FALSE)
	{
		gWinRtApartmentNeedsUninit = 1;
		gWinRtApartmentInitialized = 1;
		return 1;
	}
	if (hr == RPC_E_CHANGED_MODE)
	{
		gWinRtApartmentNeedsUninit = 0;
		gWinRtApartmentInitialized = 1;
		return 1;
	}
	return 0;
}

static void tile_wgc_release_runtime(int clearCache)
{
	if (gWgcCapture.framePool)
	{
		try
		{
			if (gWgcCapture.frameArrivedToken.value != 0)
			{
				gWgcCapture.framePool.FrameArrived(gWgcCapture.frameArrivedToken);
			}
		}
		catch (...) {}
		gWgcCapture.frameArrivedToken = {};
		try { gWgcCapture.framePool.Close(); } catch (...) {}
		gWgcCapture.framePool = nullptr;
	}
	if (gWgcCapture.session)
	{
		try { gWgcCapture.session.Close(); } catch (...) {}
		gWgcCapture.session = nullptr;
	}
	gWgcCapture.item = nullptr;
	gWgcCapture.winrtDevice = nullptr;
	if (gWgcCapture.frameArrivedEvent != NULL)
	{
		CloseHandle(gWgcCapture.frameArrivedEvent);
		gWgcCapture.frameArrivedEvent = NULL;
	}
	tile_safe_release(&gWgcCapture.stagingTexture);
	tile_safe_release(&gWgcCapture.context);
	tile_safe_release(&gWgcCapture.device);
	gWgcCapture.targetMonitor = NULL;
	gWgcCapture.sourceWidth = 0;
	gWgcCapture.sourceHeight = 0;
	gWgcCapture.targetScreen = 0;
	gWgcCapture.screenX = 0;
	gWgcCapture.screenY = 0;
	gWgcCapture.screenWidth = 0;
	gWgcCapture.screenHeight = 0;
	gWgcCapture.idleFramePolls = 0;
	gWgcCapture.activateReason[0] = 0;
	if (clearCache && gWgcCapture.lastFrame != NULL)
	{
		free(gWgcCapture.lastFrame);
		gWgcCapture.lastFrame = NULL;
		gWgcCapture.lastFrameSize = 0;
	}
}

static void tile_wgc_schedule_retry_ex(const char* reason, int clearCache)
{
	int delay = tile_capture_next_retry_delay_ms(gWgcCapture.retryDelayMs);
	gWgcCapture.nextRetryTick = GetTickCount64() + (ULONGLONG)delay;
	gWgcCapture.retryDelayMs = delay < TILE_CAPTURE_RETRY_MAX_DELAY_MS ? (delay * 2) : TILE_CAPTURE_RETRY_MAX_DELAY_MS;
	tile_wgc_release_runtime(clearCache);
	tile_set_capture_backend(KvmCaptureBackend_GDI, reason);
}

static void tile_wgc_schedule_retry(const char* reason)
{
	tile_wgc_schedule_retry_ex(reason, 0);
}

static int tile_wgc_copy_cached_frame(void** buffer, long long* bufferSize);

static int tile_wgc_handle_idle_frame(void** buffer, long long* bufferSize, const char* gdiReason, const char* cachedReason)
{
	++gWgcCapture.idleFramePolls;
	if (gWgcCapture.idleFramePolls >= TILE_WGC_IDLE_RESET_THRESHOLD)
	{
		tile_wgc_schedule_retry_ex(gdiReason, 1);
		return 0;
	}
	if (tile_wgc_copy_cached_frame(buffer, bufferSize) != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_WGC, cachedReason != NULL ? cachedReason : "wgc:cached");
		return 1;
	}
	tile_set_capture_backend(KvmCaptureBackend_GDI, gdiReason);
	return 0;
}

static int tile_dxgi_target_changed()
{
	return gDxgiCapture.duplication != NULL &&
		(gDxgiCapture.targetScreen != SCREEN_SEL_TARGET ||
			gDxgiCapture.screenX != SCREEN_X ||
			gDxgiCapture.screenY != SCREEN_Y ||
			gDxgiCapture.screenWidth != SCREEN_WIDTH ||
			gDxgiCapture.screenHeight != SCREEN_HEIGHT);
}

static int tile_wgc_target_changed()
{
	return gWgcCapture.framePool &&
		(gWgcCapture.targetScreen != SCREEN_SEL_TARGET ||
			gWgcCapture.screenX != SCREEN_X ||
			gWgcCapture.screenY != SCREEN_Y ||
			gWgcCapture.screenWidth != SCREEN_WIDTH ||
			gWgcCapture.screenHeight != SCREEN_HEIGHT);
}

static int tile_dxgi_reason_allows_wgc_fallback()
{
	if (_strnicmp(gCaptureBackendReason, "gdi:dxgi-", 9) != 0) { return 0; }
	if (_stricmp(gCaptureBackendReason, "gdi:dxgi-timeout") == 0) { return 0; }
	return 1;
}

static int tile_current_desktop_name(char* buffer, DWORD bufferLen);

static HMONITOR tile_current_monitor()
{
	POINT point;

	point.x = SCREEN_X + 1;
	point.y = SCREEN_Y + 1;
	return MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST);
}

static int tile_wgc_create_item_for_monitor(HMONITOR monitor, wgc::GraphicsCaptureItem& item)
{
	if (monitor == NULL) { return 0; }
	try
	{
		auto factory = winrt::get_activation_factory<wgc::GraphicsCaptureItem>();
		auto interop = factory.as<IGraphicsCaptureItemInterop>();
		winrt::check_hresult(interop->CreateForMonitor(
			monitor,
			winrt::guid_of<wgc::GraphicsCaptureItem>(),
			winrt::put_abi(item)));
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}

static int tile_wgc_create_item_for_window(HWND window, wgc::GraphicsCaptureItem& item)
{
	if (window == NULL) { return 0; }
	try
	{
		auto factory = winrt::get_activation_factory<wgc::GraphicsCaptureItem>();
		auto interop = factory.as<IGraphicsCaptureItemInterop>();
		winrt::check_hresult(interop->CreateForWindow(
			window,
			winrt::guid_of<wgc::GraphicsCaptureItem>(),
			winrt::put_abi(item)));
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}

static int tile_wgc_is_supported()
{
	if (gWgcSimulateUnavailable != 0) { return 0; }
	if (!tile_wgc_ensure_apartment()) { return 0; }
	try
	{
		return wgc::GraphicsCaptureSession::IsSupported() ? 1 : 0;
	}
	catch (...)
	{
		return 0;
	}
}

static int tile_should_attempt_wgc()
{
	char desktopName[64];

	if (gCaptureBackendOverride == 0 || gCaptureBackendOverride == 1) { return 0; }
	if (SCALING_FACTOR != 1024)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:wgc-scaled");
		return 0;
	}
	if (GetSystemMetrics(SM_REMOTESESSION) != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:wgc-remote-session");
		return 0;
	}
	if (SCREEN_SEL_TARGET == 0 && SCREEN_COUNT > 1)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:wgc-virtual-desktop");
		return 0;
	}
	if (tile_current_desktop_name(desktopName, sizeof(desktopName)) != 0 && _stricmp(desktopName, "Default") != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:wgc-non-default-desktop");
		return 0;
	}
	if (!tile_wgc_is_supported())
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, gWgcSimulateUnavailable != 0 ? "gdi:wgc-simulated-unavailable" : "gdi:wgc-unavailable");
		return 0;
	}
	if (GetTickCount64() < gWgcCapture.nextRetryTick)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:wgc-backoff");
		return 0;
	}
	return 1;
}

static HRESULT tile_wgc_create_staging_texture(UINT width, UINT height)
{
	D3D11_TEXTURE2D_DESC textureDesc;

	if (gWgcCapture.device == NULL) { return E_POINTER; }
	ZeroMemory(&textureDesc, sizeof(textureDesc));
	textureDesc.Width = width;
	textureDesc.Height = height;
	textureDesc.MipLevels = 1;
	textureDesc.ArraySize = 1;
	textureDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	textureDesc.SampleDesc.Count = 1;
	textureDesc.Usage = D3D11_USAGE_STAGING;
	textureDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

	tile_safe_release(&gWgcCapture.stagingTexture);
	return gWgcCapture.device->CreateTexture2D(&textureDesc, NULL, &gWgcCapture.stagingTexture);
}

static int tile_wgc_copy_cached_frame(void** buffer, long long* bufferSize)
{
	if (gWgcCapture.lastFrame == NULL || gWgcCapture.lastFrameSize == 0) { return 0; }
	*buffer = malloc(gWgcCapture.lastFrameSize);
	if (*buffer == NULL) { return 0; }
	memcpy_s(*buffer, gWgcCapture.lastFrameSize, gWgcCapture.lastFrame, gWgcCapture.lastFrameSize);
	*bufferSize = (long long)gWgcCapture.lastFrameSize;
	PIXEL_SIZE = 4;
	return 1;
}

static void tile_wgc_cache_frame(const void* buffer, size_t bufferSize)
{
	if (buffer == NULL || bufferSize == 0) { return; }
	if (gWgcCapture.lastFrame == NULL || gWgcCapture.lastFrameSize != bufferSize)
	{
		if (gWgcCapture.lastFrame != NULL) { free(gWgcCapture.lastFrame); }
		gWgcCapture.lastFrame = (unsigned char*)malloc(bufferSize);
		if (gWgcCapture.lastFrame == NULL)
		{
			gWgcCapture.lastFrameSize = 0;
			return;
		}
		gWgcCapture.lastFrameSize = bufferSize;
	}
	memcpy_s(gWgcCapture.lastFrame, gWgcCapture.lastFrameSize, buffer, bufferSize);
}

static int tile_current_desktop_name(char* buffer, DWORD bufferLen)
{
	HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
	if (desktop == NULL || buffer == NULL || bufferLen == 0) { return 0; }
	buffer[0] = 0;
	return GetUserObjectInformationA(desktop, UOI_NAME, buffer, bufferLen, NULL) ? 1 : 0;
}

static HRESULT tile_find_adapter_for_monitor(HMONITOR monitor, IDXGIAdapter1** adapterOut)
{
	if (monitor == NULL || adapterOut == NULL) { return E_INVALIDARG; }
	*adapterOut = NULL;

	IDXGIFactory1* factory = NULL;
	HRESULT hr = tile_create_dxgi_factory1(__uuidof(IDXGIFactory1), (void**)&factory);
	if (FAILED(hr) || factory == NULL) { return hr; }

	for (UINT adapterIndex = 0; ; ++adapterIndex)
	{
		IDXGIAdapter1* adapter = NULL;
		hr = factory->EnumAdapters1(adapterIndex, &adapter);
		if (hr == DXGI_ERROR_NOT_FOUND) { break; }
		if (FAILED(hr) || adapter == NULL) { continue; }

		for (UINT outputIndex = 0; ; ++outputIndex)
		{
			IDXGIOutput* output = NULL;
			hr = adapter->EnumOutputs(outputIndex, &output);
			if (hr == DXGI_ERROR_NOT_FOUND) { break; }
			if (FAILED(hr) || output == NULL) { continue; }

			DXGI_OUTPUT_DESC desc;
			ZeroMemory(&desc, sizeof(desc));
			if (SUCCEEDED(output->GetDesc(&desc)) && desc.Monitor == monitor)
			{
				output->Release();
				*adapterOut = adapter;
				factory->Release();
				return S_OK;
			}
			output->Release();
		}
		adapter->Release();
	}

	factory->Release();
	return DXGI_ERROR_NOT_FOUND;
}

static int tile_should_attempt_dxgi()
{
	char desktopName[64];

	if (gCaptureBackendOverride == 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:forced");
		return 0;
	}
	if (SCALING_FACTOR != 1024)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:scaled");
		return 0;
	}
	if (GetSystemMetrics(SM_REMOTESESSION) != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:remote-session");
		return 0;
	}
	if (SCREEN_SEL_TARGET == 0 && SCREEN_COUNT > 1)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:virtual-desktop");
		return 0;
	}
	if (tile_current_desktop_name(desktopName, sizeof(desktopName)) != 0 && _stricmp(desktopName, "Default") != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:non-default-desktop");
		return 0;
	}
	if (gDxgiSimulateUnsupported != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:dxgi-simulated-unsupported");
		return 0;
	}
	if (GetTickCount64() < gDxgiCapture.nextRetryTick)
	{
		tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:dxgi-backoff");
		return 0;
	}
	return 1;
}

static HRESULT tile_dxgi_find_matching_output(IDXGIAdapter1** adapterOut, IDXGIOutput** outputOut)
{
	IDXGIFactory1* factory = NULL;
	HRESULT hr = tile_create_dxgi_factory1(__uuidof(IDXGIFactory1), (void**)&factory);
	if (FAILED(hr)) { return hr; }

	for (UINT adapterIndex = 0; ; ++adapterIndex)
	{
		IDXGIAdapter1* adapter = NULL;
		hr = factory->EnumAdapters1(adapterIndex, &adapter);
		if (hr == DXGI_ERROR_NOT_FOUND)
		{
			break;
		}
		if (FAILED(hr) || adapter == NULL)
		{
			continue;
		}

		for (UINT outputIndex = 0; ; ++outputIndex)
		{
			IDXGIOutput* output = NULL;
			DXGI_OUTPUT_DESC outputDesc;
			hr = adapter->EnumOutputs(outputIndex, &output);
			if (hr == DXGI_ERROR_NOT_FOUND)
			{
				break;
			}
			if (FAILED(hr) || output == NULL)
			{
				continue;
			}

			ZeroMemory(&outputDesc, sizeof(outputDesc));
			if (SUCCEEDED(output->GetDesc(&outputDesc)))
			{
				int width = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
				int height = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;
				if (outputDesc.DesktopCoordinates.left == SCREEN_X &&
					outputDesc.DesktopCoordinates.top == SCREEN_Y &&
					width == SCREEN_WIDTH &&
					height == SCREEN_HEIGHT)
				{
					*adapterOut = adapter;
					*outputOut = output;
					factory->Release();
					return S_OK;
				}
			}

			output->Release();
		}

		adapter->Release();
	}

	factory->Release();
	return DXGI_ERROR_NOT_FOUND;
}

static HRESULT tile_dxgi_create_staging_texture(UINT width, UINT height)
{
	D3D11_TEXTURE2D_DESC textureDesc;

	if (gDxgiCapture.device == NULL) { return E_POINTER; }
	ZeroMemory(&textureDesc, sizeof(textureDesc));
	textureDesc.Width = width;
	textureDesc.Height = height;
	textureDesc.MipLevels = 1;
	textureDesc.ArraySize = 1;
	textureDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	textureDesc.SampleDesc.Count = 1;
	textureDesc.Usage = D3D11_USAGE_STAGING;
	textureDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

	tile_safe_release(&gDxgiCapture.stagingTexture);
	return gDxgiCapture.device->CreateTexture2D(&textureDesc, NULL, &gDxgiCapture.stagingTexture);
}

static int tile_dxgi_initialize()
{
	IDXGIAdapter1* adapter = NULL;
	IDXGIOutput* output = NULL;
	IDXGIOutput1* output1 = NULL;
	IDXGIOutput5* output5 = NULL;
	IDXGIOutputDuplication* duplication = NULL;
	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_9_1;
	D3D_FEATURE_LEVEL featureLevels[] =
	{
		D3D_FEATURE_LEVEL_11_1,
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0,
		D3D_FEATURE_LEVEL_9_3,
		D3D_FEATURE_LEVEL_9_1
	};
	HRESULT hr;

	hr = tile_dxgi_find_matching_output(&adapter, &output);
	if (FAILED(hr))
	{
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	hr = tile_d3d11_create_device(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, featureLevels, ARRAYSIZE(featureLevels), D3D11_SDK_VERSION, &gDxgiCapture.device, &featureLevel, &gDxgiCapture.context);
	if (FAILED(hr))
	{
		if (output != NULL) { output->Release(); }
		if (adapter != NULL) { adapter->Release(); }
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);
	if (FAILED(hr))
	{
		if (output != NULL) { output->Release(); }
		if (adapter != NULL) { adapter->Release(); }
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	(void)output->QueryInterface(__uuidof(IDXGIOutput5), (void**)&output5);

	if (output5 != NULL)
	{
		DXGI_FORMAT formats[] = { DXGI_FORMAT_B8G8R8A8_UNORM };
		hr = output5->DuplicateOutput1(gDxgiCapture.device, 0, ARRAYSIZE(formats), formats, &duplication);
		if (SUCCEEDED(hr))
		{
			strcpy_s(gDxgiCapture.duplicatePath, sizeof(gDxgiCapture.duplicatePath), "dxgi:duplicateoutput1");
		}
	}
	if (duplication == NULL)
	{
		hr = output1->DuplicateOutput(gDxgiCapture.device, &duplication);
		if (SUCCEEDED(hr))
		{
			strcpy_s(gDxgiCapture.duplicatePath, sizeof(gDxgiCapture.duplicatePath), "dxgi:duplicateoutput");
		}
	}
	if (FAILED(hr) || duplication == NULL)
	{
		if (output5 != NULL) { output5->Release(); }
		output1->Release();
		output->Release();
		adapter->Release();
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	DXGI_OUTDUPL_DESC duplicationDesc;
	ZeroMemory(&duplicationDesc, sizeof(duplicationDesc));
	duplication->GetDesc(&duplicationDesc);
	if (duplicationDesc.Rotation != DXGI_MODE_ROTATION_IDENTITY)
	{
		duplication->Release();
		if (output5 != NULL) { output5->Release(); }
		output1->Release();
		output->Release();
		adapter->Release();
		tile_dxgi_schedule_retry("gdi:dxgi-rotation");
		return 0;
	}
	if (duplicationDesc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM &&
		duplicationDesc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM_SRGB)
	{
		duplication->Release();
		if (output5 != NULL) { output5->Release(); }
		output1->Release();
		output->Release();
		adapter->Release();
		tile_dxgi_schedule_retry("gdi:dxgi-format");
		return 0;
	}

	gDxgiCapture.adapter = adapter;
	gDxgiCapture.output = output;
	gDxgiCapture.output1 = output1;
	gDxgiCapture.output5 = output5;
	gDxgiCapture.duplication = duplication;
	gDxgiCapture.sourceWidth = duplicationDesc.ModeDesc.Width;
	gDxgiCapture.sourceHeight = duplicationDesc.ModeDesc.Height;
	gDxgiCapture.rotation = duplicationDesc.Rotation;
	gDxgiCapture.targetScreen = SCREEN_SEL_TARGET;
	gDxgiCapture.screenX = SCREEN_X;
	gDxgiCapture.screenY = SCREEN_Y;
	gDxgiCapture.screenWidth = SCREEN_WIDTH;
	gDxgiCapture.screenHeight = SCREEN_HEIGHT;
	gDxgiCapture.retryDelayMs = TILE_CAPTURE_RETRY_INITIAL_DELAY_MS;
	gDxgiCapture.nextRetryTick = 0;
	gDxgiCapture.idleFramePolls = 0;

	hr = tile_dxgi_create_staging_texture(gDxgiCapture.sourceWidth, gDxgiCapture.sourceHeight);
	if (FAILED(hr))
	{
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	tile_set_capture_backend(KvmCaptureBackend_DXGI, gDxgiCapture.duplicatePath);
	return 1;
}

static int tile_dxgi_copy_cached_frame(void** buffer, long long* bufferSize)
{
	if (gDxgiCapture.lastFrame == NULL || gDxgiCapture.lastFrameSize == 0) { return 0; }
	*buffer = malloc(gDxgiCapture.lastFrameSize);
	if (*buffer == NULL) { return 0; }
	memcpy_s(*buffer, gDxgiCapture.lastFrameSize, gDxgiCapture.lastFrame, gDxgiCapture.lastFrameSize);
	*bufferSize = (long long)gDxgiCapture.lastFrameSize;
	PIXEL_SIZE = 4;
	return 1;
}

static int tile_dxgi_handle_idle_frame(void** buffer, long long* bufferSize, const char* gdiReason, const char* cachedReason)
{
	++gDxgiCapture.idleFramePolls;
	if (gDxgiCapture.idleFramePolls >= TILE_DXGI_IDLE_RESET_THRESHOLD)
	{
		tile_dxgi_schedule_retry_ex(gdiReason, 1);
		return 0;
	}
	if (tile_dxgi_copy_cached_frame(buffer, bufferSize) != 0)
	{
		tile_set_capture_backend(KvmCaptureBackend_DXGI, cachedReason != NULL ? cachedReason : "dxgi:cached");
		return 1;
	}
	tile_set_capture_backend(KvmCaptureBackend_GDI, gdiReason);
	return 0;
}

static void tile_dxgi_cache_frame(const void* buffer, size_t bufferSize)
{
	if (buffer == NULL || bufferSize == 0) { return; }
	if (gDxgiCapture.lastFrame == NULL || gDxgiCapture.lastFrameSize != bufferSize)
	{
		if (gDxgiCapture.lastFrame != NULL) { free(gDxgiCapture.lastFrame); }
		gDxgiCapture.lastFrame = (unsigned char*)malloc(bufferSize);
		if (gDxgiCapture.lastFrame == NULL)
		{
			gDxgiCapture.lastFrameSize = 0;
			return;
		}
		gDxgiCapture.lastFrameSize = bufferSize;
	}
	memcpy_s(gDxgiCapture.lastFrame, gDxgiCapture.lastFrameSize, buffer, bufferSize);
}

static int tile_dxgi_capture_frame(void** buffer, long long* bufferSize)
{
	IDXGIResource* desktopResource = NULL;
	ID3D11Texture2D* desktopTexture = NULL;
	DXGI_OUTDUPL_FRAME_INFO frameInfo;
	D3D11_MAPPED_SUBRESOURCE mapped;
	HRESULT hr;
	int acquireAttempt;
	unsigned char* frameBuffer = NULL;
	size_t frameSize;
	size_t rowSize;
	size_t paddedRowSize;
	UINT paddedWidth;
	UINT paddedHeight;
	HRESULT releaseHr;

	if (gDxgiCapture.duplication == NULL || gDxgiCapture.context == NULL || gDxgiCapture.stagingTexture == NULL)
	{
		tile_dxgi_schedule_retry("gdi:dxgi-not-ready");
		return 0;
	}

	ZeroMemory(&frameInfo, sizeof(frameInfo));
	for (acquireAttempt = 0; acquireAttempt < TILE_DXGI_FRAME_READY_ATTEMPTS; ++acquireAttempt)
	{
		hr = gDxgiCapture.duplication->AcquireNextFrame(acquireAttempt == 0 ? TILE_DXGI_INITIAL_FRAME_WAIT_MS : TILE_DXGI_RETRY_FRAME_WAIT_MS, &frameInfo, &desktopResource);
		if (gDxgiSimulateAccessLostOnce != 0 && gDxgiSimulateAccessLostConsumed == 0)
		{
			gDxgiSimulateAccessLostConsumed = 1;
			hr = DXGI_ERROR_ACCESS_LOST;
		}
		if (hr == DXGI_ERROR_WAIT_TIMEOUT)
		{
			return tile_dxgi_handle_idle_frame(buffer, bufferSize, "gdi:dxgi-timeout", "dxgi:cached-timeout");
		}
		if (FAILED(hr))
		{
			tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
			return 0;
		}

		// The desktop-duplication sample treats LastPresentTime==0 as "no real desktop frame yet".
		// Accepting it seeds the baseline with an all-black surface on some systems.
		if (desktopResource != NULL && frameInfo.LastPresentTime.QuadPart != 0)
		{
			break;
		}

		releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
		ZeroMemory(&frameInfo, sizeof(frameInfo));
		if (FAILED(releaseHr))
		{
			tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(releaseHr));
			return 0;
		}
	}
	if (desktopResource == NULL || frameInfo.LastPresentTime.QuadPart == 0)
	{
		return tile_dxgi_handle_idle_frame(buffer, bufferSize, "gdi:dxgi-no-present", "dxgi:cached-no-present");
	}

	hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
	if (FAILED(hr) || desktopTexture == NULL)
	{
		releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
		if (FAILED(releaseHr))
		{
			tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(releaseHr));
			return 0;
		}
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	gDxgiCapture.context->CopyResource(gDxgiCapture.stagingTexture, desktopTexture);
	ZeroMemory(&mapped, sizeof(mapped));
	hr = gDxgiCapture.context->Map(gDxgiCapture.stagingTexture, 0, D3D11_MAP_READ, 0, &mapped);
	if (FAILED(hr))
	{
		releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
		desktopTexture->Release();
		if (FAILED(releaseHr))
		{
			tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(releaseHr));
			return 0;
		}
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(hr));
		return 0;
	}

	paddedWidth = (UINT)adjust_screen_size((int)gDxgiCapture.sourceWidth);
	paddedHeight = (UINT)adjust_screen_size((int)gDxgiCapture.sourceHeight);
	frameSize = (size_t)paddedWidth * (size_t)paddedHeight * 4;
	rowSize = (size_t)gDxgiCapture.sourceWidth * 4;
	paddedRowSize = (size_t)paddedWidth * 4;
	frameBuffer = (unsigned char*)calloc(1, frameSize);
	if (frameBuffer == NULL)
	{
		gDxgiCapture.context->Unmap(gDxgiCapture.stagingTexture, 0);
		releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
		desktopTexture->Release();
		if (FAILED(releaseHr))
		{
			tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(releaseHr));
			return 0;
		}
		tile_dxgi_schedule_retry("gdi:dxgi-memory");
		return 0;
	}

	for (UINT row = 0; row < gDxgiCapture.sourceHeight; ++row)
	{
		const unsigned char* srcRow = (const unsigned char*)mapped.pData + ((size_t)row * mapped.RowPitch);
		unsigned char* dstRow = frameBuffer + ((size_t)(paddedHeight - row - 1) * paddedRowSize);
		memcpy_s(dstRow, paddedRowSize, srcRow, rowSize);
	}

	gDxgiCapture.context->Unmap(gDxgiCapture.stagingTexture, 0);
	releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
	desktopTexture->Release();
	if (FAILED(releaseHr))
	{
		free(frameBuffer);
		tile_dxgi_schedule_retry(tile_dxgi_reason_from_hresult(releaseHr));
		return 0;
	}

	tile_dxgi_cache_frame(frameBuffer, frameSize);
	*buffer = frameBuffer;
	*bufferSize = (long long)frameSize;
	PIXEL_SIZE = 4;
	gDxgiCapture.retryDelayMs = TILE_CAPTURE_RETRY_INITIAL_DELAY_MS;
	gDxgiCapture.nextRetryTick = 0;
	gDxgiCapture.idleFramePolls = 0;
	tile_set_capture_backend(KvmCaptureBackend_DXGI, gDxgiCapture.duplicatePath);
	return 1;
}

static int tile_wgc_initialize(const char* activateReason)
{
	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_9_1;
	D3D_FEATURE_LEVEL featureLevels[] =
	{
		D3D_FEATURE_LEVEL_11_1,
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0,
		D3D_FEATURE_LEVEL_9_3,
		D3D_FEATURE_LEVEL_9_1
	};
	winrt::com_ptr<IDXGIDevice> dxgiDevice;
	winrt::com_ptr<IInspectable> inspectableDevice;
	wg::SizeInt32 itemSize{};
	HRESULT hr;

	if (!tile_should_attempt_wgc()) { return 0; }

	tile_wgc_release_runtime(0);
	gWgcCapture.frameArrivedEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (gWgcCapture.frameArrivedEvent == NULL)
	{
		tile_wgc_schedule_retry("gdi:wgc-event");
		return 0;
	}

	gWgcCapture.targetMonitor = tile_current_monitor();

	// Find the DXGI adapter that owns the target monitor (multi-GPU correctness)
	{
		IDXGIAdapter1* targetAdapter = NULL;
		if (gWgcCapture.targetMonitor != NULL &&
			SUCCEEDED(tile_find_adapter_for_monitor(gWgcCapture.targetMonitor, &targetAdapter)) &&
			targetAdapter != NULL)
		{
			hr = tile_d3d11_create_device(
				targetAdapter,
				D3D_DRIVER_TYPE_UNKNOWN,
				NULL,
				D3D11_CREATE_DEVICE_BGRA_SUPPORT,
				featureLevels,
				ARRAYSIZE(featureLevels),
				D3D11_SDK_VERSION,
				&gWgcCapture.device,
				&featureLevel,
				&gWgcCapture.context);
			targetAdapter->Release();
		}
		else
		{
			hr = tile_d3d11_create_device(
				NULL,
				D3D_DRIVER_TYPE_HARDWARE,
				NULL,
				D3D11_CREATE_DEVICE_BGRA_SUPPORT,
				featureLevels,
				ARRAYSIZE(featureLevels),
				D3D11_SDK_VERSION,
				&gWgcCapture.device,
				&featureLevel,
				&gWgcCapture.context);
		}
	}
	if (FAILED(hr) || gWgcCapture.device == NULL || gWgcCapture.context == NULL)
	{
		tile_wgc_schedule_retry("gdi:wgc-device");
		return 0;
	}

	hr = gWgcCapture.device->QueryInterface(__uuidof(IDXGIDevice), dxgiDevice.put_void());
	if (FAILED(hr) || dxgiDevice == nullptr)
	{
		tile_wgc_schedule_retry("gdi:wgc-dxgi-device");
		return 0;
	}

	hr = tile_create_direct3d11_device_from_dxgi_device(dxgiDevice.get(), inspectableDevice.put());
	if (FAILED(hr) || inspectableDevice == nullptr)
	{
		tile_wgc_schedule_retry("gdi:wgc-winrt-device");
		return 0;
	}
	gWgcCapture.winrtDevice = inspectableDevice.as<wd3d::IDirect3DDevice>();
	if (gWgcCapture.targetMonitor == NULL || !tile_wgc_create_item_for_monitor(gWgcCapture.targetMonitor, gWgcCapture.item))
	{
		tile_wgc_schedule_retry("gdi:wgc-item");
		return 0;
	}

	itemSize = gWgcCapture.item.Size();
	if (itemSize.Width <= 0 || itemSize.Height <= 0)
	{
		tile_wgc_schedule_retry("gdi:wgc-size");
		return 0;
	}

	try
	{
		gWgcCapture.framePool = wgc::Direct3D11CaptureFramePool::CreateFreeThreaded(
			gWgcCapture.winrtDevice,
			wd::DirectXPixelFormat::B8G8R8A8UIntNormalized,
			2,
			itemSize);
		gWgcCapture.session = gWgcCapture.framePool.CreateCaptureSession(gWgcCapture.item);
		if (auto session2 = gWgcCapture.session.try_as<wgc::IGraphicsCaptureSession2>())
		{
			session2.IsCursorCaptureEnabled(true);
		}
		gWgcCapture.frameArrivedToken = gWgcCapture.framePool.FrameArrived([]
			(wgc::Direct3D11CaptureFramePool const&, winrt::Windows::Foundation::IInspectable const&)
		{
			if (gWgcCapture.frameArrivedEvent != NULL)
			{
				SetEvent(gWgcCapture.frameArrivedEvent);
			}
		});
		gWgcCapture.session.StartCapture();
	}
	catch (...)
	{
		tile_wgc_schedule_retry("gdi:wgc-session");
		return 0;
	}

	gWgcCapture.sourceWidth = (UINT)itemSize.Width;
	gWgcCapture.sourceHeight = (UINT)itemSize.Height;
	gWgcCapture.targetScreen = SCREEN_SEL_TARGET;
	gWgcCapture.screenX = SCREEN_X;
	gWgcCapture.screenY = SCREEN_Y;
	gWgcCapture.screenWidth = SCREEN_WIDTH;
	gWgcCapture.screenHeight = SCREEN_HEIGHT;
	gWgcCapture.retryDelayMs = TILE_CAPTURE_RETRY_INITIAL_DELAY_MS;
	gWgcCapture.nextRetryTick = 0;
	gWgcCapture.idleFramePolls = 0;
	strcpy_s(gWgcCapture.activateReason, sizeof(gWgcCapture.activateReason), activateReason != NULL ? activateReason : "wgc:active");

	hr = tile_wgc_create_staging_texture(gWgcCapture.sourceWidth, gWgcCapture.sourceHeight);
	if (FAILED(hr))
	{
		tile_wgc_schedule_retry("gdi:wgc-staging");
		return 0;
	}

	tile_set_capture_backend(KvmCaptureBackend_WGC, gWgcCapture.activateReason);
	return 1;
}

static int tile_wgc_capture_frame(void** buffer, long long* bufferSize)
{
	DWORD waitResult;
	winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame frame{ nullptr };
	wg::SizeInt32 contentSize{};
	winrt::com_ptr<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess> interfaceAccess;
	winrt::com_ptr<ID3D11Texture2D> sourceTexture;
	D3D11_MAPPED_SUBRESOURCE mapped;
	HRESULT hr;
	unsigned char* frameBuffer = NULL;
	size_t frameSize;
	size_t rowSize;
	size_t paddedRowSize;
	UINT paddedWidth;
	UINT paddedHeight;

	if (!gWgcCapture.framePool || gWgcCapture.stagingTexture == NULL || gWgcCapture.context == NULL || gWgcCapture.frameArrivedEvent == NULL)
	{
		tile_wgc_schedule_retry("gdi:wgc-not-ready");
		return 0;
	}

	waitResult = WaitForSingleObject(gWgcCapture.frameArrivedEvent, TILE_WGC_FRAME_WAIT_TIMEOUT_MS);
	if (waitResult == WAIT_TIMEOUT)
	{
		return tile_wgc_handle_idle_frame(buffer, bufferSize, "gdi:wgc-timeout", "wgc:cached-timeout");
	}
	if (waitResult != WAIT_OBJECT_0)
	{
		tile_wgc_schedule_retry("gdi:wgc-event-wait");
		return 0;
	}

	try
	{
		frame = gWgcCapture.framePool.TryGetNextFrame();
	}
	catch (...)
	{
		tile_wgc_schedule_retry("gdi:wgc-frame");
		return 0;
	}
	if (!frame)
	{
		return tile_wgc_handle_idle_frame(buffer, bufferSize, "gdi:wgc-empty", "wgc:cached-empty");
	}

	contentSize = frame.ContentSize();
	if (contentSize.Width <= 0 || contentSize.Height <= 0)
	{
		tile_wgc_schedule_retry("gdi:wgc-size");
		return 0;
	}
	if ((UINT)contentSize.Width != gWgcCapture.sourceWidth || (UINT)contentSize.Height != gWgcCapture.sourceHeight)
	{
		gWgcCapture.sourceWidth = (UINT)contentSize.Width;
		gWgcCapture.sourceHeight = (UINT)contentSize.Height;
		hr = tile_wgc_create_staging_texture(gWgcCapture.sourceWidth, gWgcCapture.sourceHeight);
		if (FAILED(hr))
		{
			tile_wgc_schedule_retry("gdi:wgc-staging");
			return 0;
		}
		try
		{
			gWgcCapture.framePool.Recreate(
				gWgcCapture.winrtDevice,
				wd::DirectXPixelFormat::B8G8R8A8UIntNormalized,
				2,
				contentSize);
		}
		catch (...)
		{
			tile_wgc_schedule_retry("gdi:wgc-recreate");
			return 0;
		}
	}

	interfaceAccess = frame.Surface().as<Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
	if (interfaceAccess == nullptr)
	{
		tile_wgc_schedule_retry("gdi:wgc-surface");
		return 0;
	}
	hr = interfaceAccess->GetInterface(__uuidof(ID3D11Texture2D), sourceTexture.put_void());
	if (FAILED(hr) || sourceTexture == nullptr)
	{
		tile_wgc_schedule_retry("gdi:wgc-texture");
		return 0;
	}

	gWgcCapture.context->CopyResource(gWgcCapture.stagingTexture, sourceTexture.get());
	ZeroMemory(&mapped, sizeof(mapped));
	hr = gWgcCapture.context->Map(gWgcCapture.stagingTexture, 0, D3D11_MAP_READ, 0, &mapped);
	if (FAILED(hr))
	{
		tile_wgc_schedule_retry("gdi:wgc-map");
		return 0;
	}

	paddedWidth = (UINT)adjust_screen_size((int)gWgcCapture.sourceWidth);
	paddedHeight = (UINT)adjust_screen_size((int)gWgcCapture.sourceHeight);
	frameSize = (size_t)paddedWidth * (size_t)paddedHeight * 4;
	rowSize = (size_t)gWgcCapture.sourceWidth * 4;
	paddedRowSize = (size_t)paddedWidth * 4;
	frameBuffer = (unsigned char*)calloc(1, frameSize);
	if (frameBuffer == NULL)
	{
		gWgcCapture.context->Unmap(gWgcCapture.stagingTexture, 0);
		tile_wgc_schedule_retry("gdi:wgc-memory");
		return 0;
	}

	for (UINT row = 0; row < gWgcCapture.sourceHeight; ++row)
	{
		const unsigned char* srcRow = (const unsigned char*)mapped.pData + ((size_t)row * mapped.RowPitch);
		unsigned char* dstRow = frameBuffer + ((size_t)(paddedHeight - row - 1) * paddedRowSize);
		memcpy_s(dstRow, paddedRowSize, srcRow, rowSize);
	}

	gWgcCapture.context->Unmap(gWgcCapture.stagingTexture, 0);

	// Explicitly close the frame to release the GPU buffer back to the frame pool promptly
	try { frame.Close(); } catch (...) {}
	frame = nullptr;

	tile_wgc_cache_frame(frameBuffer, frameSize);
	*buffer = frameBuffer;
	*bufferSize = (long long)frameSize;
	PIXEL_SIZE = 4;
	gWgcCapture.retryDelayMs = TILE_CAPTURE_RETRY_INITIAL_DELAY_MS;
	gWgcCapture.nextRetryTick = 0;
	gWgcCapture.idleFramePolls = 0;
	tile_set_capture_backend(KvmCaptureBackend_WGC, gWgcCapture.activateReason[0] != 0 ? gWgcCapture.activateReason : "wgc:active");
	return 1;
}

static int tile_try_capture_dxgi(void** buffer, long long* bufferSize)
{
	if (tile_should_attempt_dxgi() == 0) { return 0; }
	if (tile_dxgi_target_changed())
	{
		tile_dxgi_release_runtime(0);
	}
	if (gDxgiCapture.duplication == NULL && !tile_dxgi_initialize())
	{
		return 0;
	}
	return tile_dxgi_capture_frame(buffer, bufferSize) != 0 ? 1 : 0;
}

static int tile_try_capture_wgc(void** buffer, long long* bufferSize, const char* activateReason)
{
	if (tile_should_attempt_wgc() == 0) { return 0; }
	if (tile_wgc_target_changed())
	{
		tile_wgc_release_runtime(0);
	}
	if (!gWgcCapture.framePool && !tile_wgc_initialize(activateReason))
	{
		return 0;
	}
	return tile_wgc_capture_frame(buffer, bufferSize) != 0 ? 1 : 0;
}

static int get_desktop_buffer_gdi(void **buffer, long long *bufferSize, long* mouseMove)
{
	BITMAPINFO bmpInfo;

	*buffer = NULL;
	*bufferSize = 0;

	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	if ((hDesktopDC = GetDC(NULL)) == NULL) { KVMDEBUG("GetDC(NULL) returned NULL", 0); return 1; }
	if (hCapturedBitmap) DeleteObject(hCapturedBitmap);
	if ((hCapturedBitmap = CreateCompatibleBitmap(hDesktopDC, adjust_screen_size(SCALED_WIDTH), adjust_screen_size(SCALED_HEIGHT))) == NULL)
	{
		KVMDEBUG("CreateCompatibleBitmap() returned NULL", 0);
		return 1;
	}

	if (SelectObject(hCaptureDC, hCapturedBitmap) == NULL) { KVMDEBUG("SelectObject() failed", 0); return(1); }
	if (SCALING_FACTOR == 1024)
	{
		if (BitBlt(hCaptureDC, 0, 0, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, SRCCOPY) == FALSE)
		{
			KVMDEBUG("BitBlt() returned FALSE", 0);
			return 1;
		}
		if (mouseMove[0] != 0)
		{
			CURSORINFO info = { 0 };
			BITMAP bm;
			ICONINFO ii;
			info.cbSize = sizeof(info);
			GetCursorInfo(&info);
			if (GetIconInfo(info.hCursor, &ii))
			{
				if (GetObject(ii.hbmMask, sizeof(bm), &bm) == sizeof(bm))
				{
					HDC hdcScreen = GetDC(NULL);
					if (hdcScreen != NULL)
					{
						HDC hdcMem = CreateCompatibleDC(hdcScreen);
						HBITMAP hbmCanvas = CreateCompatibleBitmap(hdcScreen, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2));
						if (hdcMem != NULL && hbmCanvas != NULL)
						{
							HGDIOBJ hbmold = SelectObject(hdcMem, hbmCanvas);

							DrawIconEx(hdcMem, 0, 0, info.hCursor, bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), 0, NULL, DI_NORMAL);
							BitBlt(hCaptureDC, mouseMove[1], mouseMove[2], bm.bmWidth, ii.hbmColor ? bm.bmHeight : (bm.bmHeight / 2), hdcMem, 0, 0, SRCINVERT);

							SelectObject(hdcMem, hbmold);
						}
						if (hbmCanvas != NULL) { DeleteObject(hbmCanvas); }
						if (hdcMem != NULL) { DeleteDC(hdcMem); }
						ReleaseDC(NULL, hdcScreen);
					}
				}
				// Free GDI bitmaps returned by GetIconInfo to prevent handle leak
				if (ii.hbmMask != NULL) { DeleteObject(ii.hbmMask); }
				if (ii.hbmColor != NULL) { DeleteObject(ii.hbmColor); }
			}
		}
	}
	else
	{
		if (SetStretchBltMode(hCaptureDC, HALFTONE) == 0) { KVMDEBUG("SetStretchBltMode() failed", 0); return(1); }
		if (StretchBlt(hCaptureDC, 0, 0, adjust_screen_size(SCALED_WIDTH), adjust_screen_size(SCALED_HEIGHT), hDesktopDC, SCREEN_X, SCREEN_Y, adjust_screen_size(SCREEN_WIDTH), adjust_screen_size(SCREEN_HEIGHT), SRCCOPY) == FALSE)
		{
			KVMDEBUG("StretchBlt() returned FALSE", 0);
			return 1;
		}
	}

	ZeroMemory(&bmpInfo, sizeof(BITMAPINFO));
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);

	if (GetDIBits(hDesktopDC, hCapturedBitmap, 0, 0, NULL, &bmpInfo, DIB_RGB_COLORS) == 0)
	{
		KVMDEBUG("GetDIBits() failed", 0);
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return(1);
	}

	if (bmpInfo.bmiHeader.biSizeImage <= 0)
	{
		bmpInfo.bmiHeader.biSizeImage = bmpInfo.bmiHeader.biWidth * abs(bmpInfo.bmiHeader.biHeight) * (bmpInfo.bmiHeader.biBitCount + 7) / 8;
	}

	*bufferSize = bmpInfo.bmiHeader.biSizeImage;
	PIXEL_SIZE = bmpInfo.bmiHeader.biBitCount / 8;
	if ((*buffer = malloc((size_t)*bufferSize)) == NULL) { KVMDEBUG("malloc() failed", 0); return 1; }

	bmpInfo.bmiHeader.biCompression = BI_RGB;
	if (GetDIBits(hDesktopDC, hCapturedBitmap, 0, bmpInfo.bmiHeader.biHeight, *buffer, &bmpInfo, DIB_RGB_COLORS) == 0) { KVMDEBUG("GetDIBits() failed", 0); free(*buffer); return(1); }

	tile_tracef("tile:gdi-capture size=%lld pixel=%d scaled=%dx%d screen=%dx%d", *bufferSize, PIXEL_SIZE, SCALED_WIDTH, SCALED_HEIGHT, SCREEN_WIDTH, SCREEN_HEIGHT);
	return 0;
}

// Used to obtain the GUID for the image encoder.
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	unsigned int num = 0, size = 0;
	ImageCodecInfo* pImageCodecInfo = NULL;

	GetImageEncodersSize(&num, &size);
	if (size == 0) return -1;

	if ((pImageCodecInfo = (ImageCodecInfo*)(malloc(size))) == NULL) return -1;
	GetImageEncoders(num, size, pImageCodecInfo);

	for (unsigned int j = 0; j < num; ++j)
	{
		if (wcsncmp(pImageCodecInfo[j].MimeType, format, size) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;
		}
	}

	free(pImageCodecInfo);
	return -1;
}

// Adjusts the screen size(width or height) to be exactly divisible by TILE_WIDTH
int adjust_screen_size(int pixles) 
{
	int extra = pixles % TILE_WIDTH; // Assuming tile width and height will remain the same.
	if (extra != 0) return pixles + TILE_WIDTH - extra;
	return pixles;
}

// Extracts the required tile buffer from the desktop buffer
int get_tile_buffer(int x, int y, void **buffer, void *desktop, int tilewidth, int tileheight) 
{
	void *target = *buffer;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		memcpy_s(target, tilebuffersize, (const void *)((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE) ), (size_t)(tilewidth * PIXEL_SIZE));
		target = (void *) ((unsigned char *)target + tilewidth * PIXEL_SIZE);
	}
	return 0;
}

int tile_crc(int x, int y, void *desktop, int tilewidth, int tileheight) 
{
	int crc = 0;
	for (int height = adjust_screen_size(SCALED_HEIGHT) - y - tileheight; height < adjust_screen_size(SCALED_HEIGHT) - y; height++)
	{
		crc = util_crc(((unsigned char *)desktop + (((height * adjust_screen_size(SCALED_WIDTH)) + x) * PIXEL_SIZE) ), (size_t)(tilewidth * PIXEL_SIZE), crc);
	}
	return crc;
}

// This function returns 0 and *buffer != NULL if everything was good. retval = jpegsize if the captured image was too large.
int calc_opt_compr_send(int x, int y, int captureWidth, int captureHeight, void* desktop, void ** buffer, long long *bufferSize) 
{
	BITMAPINFO bmpInfo;
	LARGE_INTEGER Offset;
	BITMAPFILEHEADER bmpFileHeader;
	*buffer = NULL;
	*bufferSize = 0;

	KVMDEBUG("calc_opt_compr_send()", 0);

	// Get the bmpInfo structure
	bmpInfo = get_bmp_info(captureWidth, captureHeight);

	// Make sure a tile buffer is available. Most of the time, this is skipped.
	if (tilebuffersize != bmpInfo.bmiHeader.biSizeImage)
	{
		if (tilebuffer != NULL) free(tilebuffer);
		tilebuffersize = bmpInfo.bmiHeader.biSizeImage;
		if ((tilebuffer = malloc(tilebuffersize)) == NULL) return 0;
	}

	// Get the final coalesced tile
	get_tile_buffer(x, y, &tilebuffer, desktop, captureWidth, captureHeight);

	bmpFileHeader.bfReserved1 = 0;
	bmpFileHeader.bfReserved2 = 0;
	bmpFileHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpInfo.bmiHeader.biSizeImage;
	bmpFileHeader.bfType = 'MB';
	bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	// Construct stream object.
	IStream* bmpStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&bmpStream) != S_OK)
	{
		KVMDEBUG("CreateStreamOnHGlobal() failed", 0);
		tile_tracef("tile:CreateStreamOnHGlobal(bmp) failed err=%lu", GetLastError());
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Write entire contents of the source BMP into this stream.
	bmpStream->Write(&bmpFileHeader, sizeof(BITMAPFILEHEADER), NULL);
	bmpStream->Write(&bmpInfo, sizeof(BITMAPINFOHEADER), NULL);
	bmpStream->Write(tilebuffer, bmpInfo.bmiHeader.biSizeImage, NULL);

	// Move the stream pointer to the beginning of the stream.
	Offset.QuadPart = 0;
	if (bmpStream->Seek(Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		KVMDEBUG("bmpStream->Seek() failed", 0);
		tile_tracef("tile:bmpStream->Seek(start) failed err=%lu", GetLastError());
		bmpStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Construct GDI+ Image object from the BMP stream.
	Gdiplus::Image* DIBImage = Gdiplus::Image::FromStream(bmpStream);

	// Create stream to receive the encoded JPEG.
	IStream* jpegStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, (LPSTREAM*)&jpegStream) != S_OK)
	{
		KVMDEBUG("CreateStreamOnHGlobal() failed", 0);
		tile_tracef("tile:CreateStreamOnHGlobal(jpeg) failed err=%lu", GetLastError());
		delete DIBImage;
		bmpStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Save image stream into the stream object.
	Status SaveStatus = DIBImage->Save(jpegStream, &encoderClsid, &encParam);
	if (SaveStatus != S_OK)
	{
		KVMDEBUG("DIBImage->Save() failed", 0);
		tile_tracef("tile:DIBImage->Save failed status=%d err=%lu", (int)SaveStatus, GetLastError());
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Get the size of the output stream
	ULARGE_INTEGER Size;
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_END, &Size) != S_OK)
	{
		KVMDEBUG("jpegStream->Save() failed", 0);
		tile_tracef("tile:jpegStream->Seek(end) failed err=%lu", GetLastError());
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}       

	// Move the image stream's pointer to its beginning.
	Offset.QuadPart = 0;
	if (jpegStream->Seek(Offset, STREAM_SEEK_SET, NULL) != S_OK)
	{
		KVMDEBUG("jpegStream->Seek() failed", 0);
		tile_tracef("tile:jpegStream->Seek(start) failed err=%lu", GetLastError());
		delete DIBImage;
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}        

	// Check if the tile is too large to send
	DWORD jpegSize = (DWORD)Size.QuadPart;

	//if (jpegSize > 65500)
	//{
	//	KVMDEBUG("jpegSize > 65500", jpegSize);
	//	delete DIBImage;
	//	*bufferSize = 0;
	//	// ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
	//	return jpegSize;
	//}

	// Save the image stream in memory.
	char* Tile = (char*)ILibMemory_Allocate(jpegSize > 65500 ? (jpegSize + 16):(jpegSize + 8), 0, NULL, NULL);
	if (jpegStream->Read(Tile + (jpegSize > 65500 ? 16 : 8), jpegSize, NULL) != S_OK)
	{
		KVMDEBUG("jpegStream->Read() failed", 0);
		tile_tracef("tile:jpegStream->Read failed err=%lu", GetLastError());
		delete DIBImage;
		free(Tile);
		bmpStream->Release();
		jpegStream->Release();
		ILibCriticalLog(NULL, __FILE__, __LINE__, 252, GetLastError());
		return 0;
	}

	// Cleanup
	delete DIBImage;
	bmpStream->Release();
	jpegStream->Release();

	*buffer = (unsigned char*)Tile;
	*bufferSize = jpegSize + (jpegSize > 65500 ? 16 : 8);

	// Place the header
	if (jpegSize > 65500)
	{
		((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_JUMBO);		// Write the type
		((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
		((unsigned int*)*buffer)[1]   = (unsigned int)htonl(jpegSize + 8);						// Size of the Next Packet
		((unsigned short*)*buffer)[4] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
		((unsigned short*)*buffer)[5] = 0;														// RESERVED
		((unsigned short*)*buffer)[6] = (unsigned short)htons((unsigned short)x);				// X position
		((unsigned short*)*buffer)[7] = (unsigned short)htons((unsigned short)y);				// Y position
	}
	else
	{
		((unsigned short*)*buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PICTURE);	// Write the type
		((unsigned short*)*buffer)[1] = (unsigned short)htons((unsigned short)*bufferSize);		// Write the size
		((unsigned short*)*buffer)[2] = (unsigned short)htons((unsigned short)x);				// X position
		((unsigned short*)*buffer)[3] = (unsigned short)htons((unsigned short)y);				// Y position
	}
	tile_tracef("tile:jpeg-ready x=%d y=%d width=%d height=%d bytes=%lld", x, y, captureWidth, captureHeight, *bufferSize);
	return 0;
}


extern "C"
{

//Fetches the encoded jpeg tile at the given location. The neighboring tiles are coalesed to form a larger jpeg before returning.
int get_tile_at(int x, int y, void** buffer, long long *bufferSize, void *desktop, int row, int col)
{	
	int CRC;
	int rightcol = col;		// Used in coalescing. Indicates the right-most column to be coalesced.
	int botrow = row;		// Used in coalescing. Indicates the bottom-most row to be coalesced.
	int r_x = x;
	int r_y = y;
	int captureWidth = TILE_WIDTH;
	int captureHeight = TILE_HEIGHT;

	*buffer = NULL;			// If anything fails, this will be the indication.
	*bufferSize = 0;

	if (tileInfo[row][col].flags == (char)TILE_TODO) // First check whether the tile-crc needs to be calcualted or not.
	{ 
		// Compute CRC on the contents of the bitmap; Proceed with image encoding only if the CRC is different.
		if ((CRC = tile_crc(x, y, desktop, TILE_WIDTH, TILE_HEIGHT)) == tileInfo[row][col].crc) return 0;
		tileInfo[row][col].crc = CRC; // Update the tile CRC in the global data structure.
	}

	tileInfo[row][col].flags = (char)TILE_MARKED_NOT_SENT;


	// COALESCING SECTION

	// First got to the right most changed tile and record it
	while (rightcol + 1 < TILE_WIDTH_COUNT)
	{
		rightcol++;
		r_x = rightcol * TILE_WIDTH;
		
		CRC = tileInfo[row][rightcol].crc;

		if (tileInfo[row][rightcol].flags == (char)TILE_TODO) {
			// Compute CRC on the contents of the bitmap.
			CRC = tile_crc(r_x, y, desktop, TILE_WIDTH, TILE_HEIGHT);
		}

		if (CRC != tileInfo[row][rightcol].crc || tileInfo[row][rightcol].flags == (char)TILE_MARKED_NOT_SENT) // If the tile has changed, increment the capturewidth.
		{
			tileInfo[row][rightcol].crc = CRC; 
			// Here we check whether the size of the coalesced bitmap is greater than the threshold (65500)
			//if ((captureWidth + TILE_WIDTH) * TILE_HEIGHT * PIXEL_SIZE / COMPRESSION_RATIO > 65500) { 
			//	tileInfo[row][rightcol].flags = (char)TILE_MARKED_NOT_SENT;
			//	--rightcol;
			//	break;
			//}

			tileInfo[row][rightcol].flags = (char)TILE_MARKED_NOT_SENT;
			captureWidth += TILE_WIDTH;
		} 
		else
		{
			tileInfo[row][rightcol].flags = (char)TILE_DONT_SEND;
			--rightcol;
			break;
		}
	}

	// int TOLERANCE = (rightcol - col) / 4;

	// Now go to the bottom tiles, check if they have changed and record them
	//while ((botrow + 1 < TILE_HEIGHT_COUNT) && ((captureHeight + TILE_HEIGHT) * captureWidth * PIXEL_SIZE / COMPRESSION_RATIO <= 65500))
	while ((botrow + 1 < TILE_HEIGHT_COUNT))
	{
		botrow++;
		r_y = botrow * TILE_HEIGHT;
		int fail = 0;
		r_x = x;

		// int missCount = 0;

		for (int rcol = col; rcol <= rightcol; rcol++) {

			CRC = tileInfo[botrow][rcol].crc;
			if (tileInfo[botrow][rcol].flags == (char)TILE_TODO)
			{
				// Compute CRC on the contents of the bitmap; Proceed with image encoding only if the CRC is different.
				CRC = tile_crc(r_x, r_y, desktop, TILE_WIDTH, TILE_HEIGHT);
			}

			if (CRC != tileInfo[botrow][rcol].crc || tileInfo[botrow][rcol].flags == (char)TILE_MARKED_NOT_SENT)
			{
				tileInfo[botrow][rcol].flags = (char)TILE_MARKED_NOT_SENT;
				tileInfo[botrow][rcol].crc = CRC;
				r_x += TILE_WIDTH;
			}
			else
			{
				/*// Keep this part commented. Adding tolerance adds to the complexity of this code.
				missCount++;

				if (missCount > TOLERANCE) {
					fail = 1;
					for (int i = col; i < rcol; i++) {
						if (tileInfo[botrow][i].flags == (char)TILE_SKIPPED) {
							tileInfo[botrow][i].flags = (char)TILE_DONT_SEND;
						} 
						else {
							tileInfo[botrow][i].flags = (char)TILE_MARKED_NOT_SENT;
						}
					}
					tileInfo[botrow][rcol].flags = (char)TILE_DONT_SEND;
					botrow--;
					break;
				}
				else {
					tileInfo[botrow][rcol].flags = (char)TILE_SKIPPED;
					tileInfo[botrow][rcol].crc = CRC;
					r_x += TILE_WIDTH;
				}*/
				fail = 1;
				for (int i = col; i < rcol; i++)
				{
					tileInfo[botrow][i].flags = (char)TILE_MARKED_NOT_SENT;
				}
				tileInfo[botrow][rcol].flags = (char)TILE_DONT_SEND;
				botrow--;
				break;
			}
		}

		if (!fail)
		{
			captureHeight += TILE_HEIGHT;
		}
		else
		{
			break;
		}
	}

	int retval = 0;
	int firstTime = 1;

	// This loop is used to adjust the COMPRESSION_RATIO. This loop runs only once most of the time.
	do {
		// retval here is 0 if everything was good. It is > 0 if it contains the size of the jpeg that was created and not sent.
		retval = calc_opt_compr_send(x, y, captureWidth, captureHeight, desktop, buffer, bufferSize);
		if (retval == 0 && *bufferSize == 0) break;
		if (retval != 0)
		{
			if (firstTime)
			{
				// Re-adjust the compression ratio.
				//COMPRESSION_RATIO = (int)(((double)COMPRESSION_RATIO/(double)retval) * 60000);//Magic number: 60000 ~= 65500
				//if (COMPRESSION_RATIO <= 1) COMPRESSION_RATIO = 2;
				firstTime = 0;
			}

			if (botrow > row) // First time, try reducing the height.
			{ 
				botrow = row + ((botrow - row + 1) / 2);
				captureHeight = (botrow - row + 1) * TILE_HEIGHT;
			}
			else if (rightcol > col) // If it is not possible, reduce the width
			{
				rightcol = col + ((rightcol - col + 1) / 2);
				captureWidth = (rightcol - col + 1) * TILE_WIDTH;
			} 
			else
			{   // This never happens, but just in case.
				retval = 0;
				break;
			}

		}
	} while (*buffer == NULL);

	if (*buffer == NULL)
	{
		tile_tracef("tile:get_tile_at empty x=%d y=%d row=%d col=%d width=%d height=%d retval=%d", x, y, row, col, captureWidth, captureHeight, retval);
	}

	// Set the flags to TILE_SENT
	if (*buffer != NULL) {
		for (int r = row; r <= botrow; r++) {
			for (int c = col; c <= rightcol; c++) {
				tileInfo[r][c].flags = (char)TILE_SENT;
			}
		}
	}

	return retval;
}

// This function captures the entire desktop buffer to scan.
// Counter for consecutive GDI failures used to trigger automatic DXGI/WGC
// escalation when the GDI-forced override cannot capture (e.g. session-0
// desktops that lack a display surface until a DXGI device is created).
// Follows the RustDesk pattern: preferred backend gets N attempts, then
// the capture path automatically tries every available backend before
// returning failure to the caller.
static int gGdiEscalationFailures = 0;
#define GDI_ESCALATION_THRESHOLD 3

int get_desktop_buffer(void **buffer, long long *bufferSize, long* mouseMove)
{
	*buffer = NULL;
	*bufferSize = 0;
	if (g_shutdown) { return 1; }
	if (!gKvmDesktopCaptureReady)
	{
		KVM_TraceStartupF("KVM capture: target desktop is not accessible; skipping capture backends");
		return 1;
	}

	if (gCaptureBackendOverride == 2)
	{
		KVM_TraceStartupF("KVM capture: trying WGC forced");
		if (tile_try_capture_wgc(buffer, bufferSize, "wgc:forced") != 0)
		{
			KVM_TraceStartupF("KVM capture: WGC forced succeeded size=%lld", *bufferSize);
			return 0;
		}
		if (g_shutdown) { return 1; }
		KVM_TraceStartupF("KVM capture: trying DXGI after forced WGC failure");
		if (tile_try_capture_dxgi(buffer, bufferSize) != 0)
		{
			KVM_TraceStartupF("KVM capture: DXGI after forced WGC failure succeeded size=%lld", *bufferSize);
			return 0;
		}
		if (g_shutdown) { return 1; }
		KVM_TraceStartupF("KVM capture: trying GDI after forced WGC/DXGI failure");
		return get_desktop_buffer_gdi(buffer, bufferSize, mouseMove);
	}

	KVM_TraceStartupF("KVM capture: trying DXGI");
	if (tile_try_capture_dxgi(buffer, bufferSize) != 0)
	{
		// DXGI succeeded — clear any stale WGC backoff so it's ready as fallback
		gWgcCapture.retryDelayMs = 0;
		gWgcCapture.nextRetryTick = 0;
		gGdiEscalationFailures = 0;
		KVM_TraceStartupF("KVM capture: DXGI succeeded size=%lld", *bufferSize);
		return 0;
	}
	if (g_shutdown) { return 1; }

	if (gCaptureBackendOverride != 1 && tile_dxgi_reason_allows_wgc_fallback() != 0)
	{
		KVM_TraceStartupF("KVM capture: trying WGC fallback");
		if (tile_try_capture_wgc(buffer, bufferSize, "wgc:auto-fallback") != 0)
		{
			gGdiEscalationFailures = 0;
			KVM_TraceStartupF("KVM capture: WGC fallback succeeded size=%lld", *bufferSize);
			return 0;
		}
	}
	if (g_shutdown) { return 1; }

	KVM_TraceStartupF("KVM capture: trying GDI");
	if (get_desktop_buffer_gdi(buffer, bufferSize, mouseMove) == 0)
	{
		gGdiEscalationFailures = 0;
		KVM_TraceStartupF("KVM capture: GDI succeeded size=%lld", *bufferSize);
		return 0;
	}
	if (g_shutdown) { return 1; }
	KVM_TraceStartupF("KVM capture: GDI failed override=%d failures=%d", gCaptureBackendOverride, gGdiEscalationFailures + 1);

	// GDI failed.  If DXGI/WGC were skipped because of a GDI-forced override,
	// escalate to them after a few consecutive GDI failures.  Creating the
	// DXGI device + output duplication often primes the display adapter on
	// session-0 desktops, which then makes subsequent GDI calls succeed too.
	// This follows RustDesk (auto-escalate after N failures) and FreeRDP
	// (never abort on a single backend failure) patterns.
	if (gCaptureBackendOverride == 0)
	{
		++gGdiEscalationFailures;
		if (gGdiEscalationFailures >= GDI_ESCALATION_THRESHOLD)
		{
			// Temporarily bypass the GDI-only guard to let DXGI initialize.
			// Clear any stale backoff so tile_should_attempt_dxgi proceeds.
			gDxgiCapture.nextRetryTick = 0;
			gDxgiCapture.retryDelayMs = 0;

			int savedOverride = gCaptureBackendOverride;
			gCaptureBackendOverride = -1;

			KVM_TraceStartupF("KVM capture: trying DXGI escalation after GDI failures");
			if (tile_try_capture_dxgi(buffer, bufferSize) != 0)
			{
				gCaptureBackendOverride = savedOverride;
				tile_set_capture_backend(KvmCaptureBackend_DXGI, "dxgi:gdi-escalation");
				KVM_TraceStartupF("KVM capture: DXGI escalation succeeded size=%lld", *bufferSize);
				return 0;
			}
			if (g_shutdown)
			{
				gCaptureBackendOverride = savedOverride;
				return 1;
			}

			// DXGI didn't produce a frame but its initialization may have
			// primed the adapter.  Retry GDI once before giving up.
			gCaptureBackendOverride = savedOverride;
			KVM_TraceStartupF("KVM capture: retrying GDI after DXGI escalation");
			if (get_desktop_buffer_gdi(buffer, bufferSize, mouseMove) == 0)
			{
				tile_set_capture_backend(KvmCaptureBackend_GDI, "gdi:post-escalation");
				gGdiEscalationFailures = 0;
				KVM_TraceStartupF("KVM capture: post-escalation GDI succeeded size=%lld", *bufferSize);
				return 0;
			}
		}
	}

	KVM_TraceStartupF("KVM capture: all backends failed");
	return 1;
}

// Creates a BITMAPINFO object with required width and height
BITMAPINFO get_bmp_info(int width, int height)
{
	BITMAPINFO bmpInfo;

	ZeroMemory(&bmpInfo, sizeof(BITMAPINFO));
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmpInfo.bmiHeader.biBitCount = (WORD)(PIXEL_SIZE * 8);
	bmpInfo.bmiHeader.biSize = 40;
	bmpInfo.bmiHeader.biHeight = height;
	bmpInfo.bmiHeader.biWidth = width;
	bmpInfo.bmiHeader.biSizeImage = height * width * PIXEL_SIZE;
	bmpInfo.bmiHeader.biPlanes = 1;

	return bmpInfo;
}

short initialize_gdiplus()
{
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	tile_dxgi_release_runtime(1);
	tile_wgc_release_runtime(1);
	gCaptureBackendOverride = tile_read_capture_backend_override();
	gDxgiSimulateUnsupported = tile_read_env_bool("STEALTH_KVM_DXGI_SIMULATE_UNSUPPORTED", 0);
	gDxgiSimulateAccessLostOnce = tile_read_env_bool("STEALTH_KVM_DXGI_SIMULATE_ACCESS_LOST_ONCE", 0);
	gDxgiSimulateAccessLostConsumed = 0;
	gWgcSimulateUnavailable = tile_read_env_bool("STEALTH_KVM_WGC_SIMULATE_UNAVAILABLE", 0);
	gGdiEscalationFailures = 0;
	tile_set_capture_backend(KvmCaptureBackend_GDI, gCaptureBackendOverride == 0 ? "gdi:forced" : "gdi:init");

	TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH;
	TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT;
	COMPRESSION_RATIO = 100;
	FRAME_RATE_TIMER = 50;
	InterlockedExchange(&SCALING_FACTOR, 1024);
	InterlockedExchange(&SCALING_FACTOR_NEW, 1024);

	if (SCREEN_WIDTH > 0 && SCREEN_HEIGHT > 0)
	{
		SCALED_WIDTH = SCREEN_WIDTH;
		SCALED_HEIGHT = SCREEN_HEIGHT;
	}
	else
	{
		SCALED_WIDTH = SCREEN_WIDTH = GetSystemMetrics(SM_CXSCREEN);
		SCALED_HEIGHT = SCREEN_HEIGHT = GetSystemMetrics(SM_CYSCREEN);
	}

	if ((hDesktopDC = GetDC(NULL)) == NULL) { KVMDEBUG("GetDC() failed", 0); return 0; }
	if ((hCaptureDC = CreateCompatibleDC(hDesktopDC)) == NULL) { KVMDEBUG("CreateCompatibleDC() failed", 0); ReleaseDC(NULL, hDesktopDC); hDesktopDC = NULL; return 0; }
	if ((hCapturedBitmap = CreateCompatibleBitmap(hDesktopDC, SCALED_WIDTH, SCALED_HEIGHT)) == NULL) { KVMDEBUG("CreateCompatibleBitmap() failed", 0); DeleteDC(hCaptureDC); hCaptureDC = NULL; ReleaseDC(NULL, hDesktopDC); hDesktopDC = NULL; return 0; }
	if (SelectObject(hCaptureDC, hCapturedBitmap) == NULL) { KVMDEBUG("SelectObject() failed", 0); }
	
	// Find encoder and setup encoder parameters
	GetEncoderClsid(L"image/jpeg", &encoderClsid);
	encParam.Count = 1;
	encParam.Parameter[0].Guid = EncoderQuality;
	encParam.Parameter[0].Type = EncoderParameterValueTypeLong;
	encParam.Parameter[0].NumberOfValues = 1;
	encParam.Parameter[0].Value = &encCompression;

	return 1;
}

void teardown_gdiplus()
{
	if (tilebuffer) free(tilebuffer);
	tilebuffersize = 0;
	tilebuffer = NULL;
	tile_dxgi_release_runtime(1);
	tile_wgc_release_runtime(1);
	if (gWinRtApartmentInitialized != 0 && gWinRtApartmentNeedsUninit != 0)
	{
		CoUninitialize();
	}
	gWinRtApartmentInitialized = 0;
	gWinRtApartmentNeedsUninit = 0;
	GdiplusShutdown(gdiplusToken);
	DeleteDC(hCaptureDC);
	DeleteObject(hCapturedBitmap);
	if (hDesktopDC) ReleaseDC(NULL, hDesktopDC);
	hDesktopDC = NULL;
}

void set_tile_compression(int type, int level)
{
	encCompression = level;
	if (encCompression < 1) { encCompression = 1; } // Guard against bad values.
	if (encCompression > 90) { encCompression = 90; }
	if (tilebuffer == NULL) { KVMDEBUG("set_tile_compression(), tilebuffer == NULL.", 0); return; }
	KVMDEBUG("set_tile_compression() type", type);
	KVMDEBUG("set_tile_compression() level", level);

	switch (type)
	{
		case 1: { GetEncoderClsid(L"image/jpeg", &encoderClsid); break; }
		case 2: { GetEncoderClsid(L"image/png", &encoderClsid); break; }
		case 3: { GetEncoderClsid(L"image/tiff", &encoderClsid); break; }
	}
}

const char* get_capture_backend_name()
{
	switch (gCaptureBackend)
	{
	case KvmCaptureBackend_DXGI: return "dxgi";
	case KvmCaptureBackend_WGC: return "wgc";
	default: return "gdi";
	}
}

const char* get_capture_backend_reason()
{
	return gCaptureBackendReason;
}

// One-shot DXGI capture for pre-protection evidence.
// Creates a temporary DXGI duplication session, captures one frame, tears it down.
// Returns 1 on success with a malloc'd BGRA buffer in *buffer. Caller must free.
// Returns 0 if DXGI is unavailable (caller should fall back to GDI BitBlt).
int capture_desktop_dxgi_oneshot(void** buffer, int* outWidth, int* outHeight)
{
	IDXGIFactory1* factory = NULL;
	IDXGIAdapter1* adapter = NULL;
	IDXGIOutput* output = NULL;
	IDXGIOutput1* output1 = NULL;
	IDXGIOutput5* output5 = NULL;
	IDXGIOutputDuplication* duplication = NULL;
	ID3D11Device* device = NULL;
	ID3D11DeviceContext* context = NULL;
	ID3D11Texture2D* staging = NULL;
	IDXGIResource* desktopResource = NULL;
	ID3D11Texture2D* desktopTexture = NULL;
	DXGI_OUTDUPL_FRAME_INFO frameInfo;
	D3D11_MAPPED_SUBRESOURCE mapped;
	DXGI_OUTDUPL_DESC duplDesc;
	D3D11_TEXTURE2D_DESC texDesc;
	HRESULT hr;
	HRESULT releaseHr;
	int result = 0;
	UINT captureWidth = 0, captureHeight = 0;
	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_9_1;
	D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0 };

	if (buffer == NULL || outWidth == NULL || outHeight == NULL) { return 0; }
	*buffer = NULL; *outWidth = 0; *outHeight = 0;

	// Skip if in a remote session (DXGI Desktop Duplication doesn't work in RDP)
	if (GetSystemMetrics(SM_REMOTESESSION) != 0) { return 0; }

	hr = tile_create_dxgi_factory1(__uuidof(IDXGIFactory1), (void**)&factory);
	if (FAILED(hr) || factory == NULL) { return 0; }

	// Find primary adapter and output
	hr = factory->EnumAdapters1(0, &adapter);
	if (FAILED(hr) || adapter == NULL) { factory->Release(); return 0; }

	hr = adapter->EnumOutputs(0, &output);
	if (FAILED(hr) || output == NULL) { adapter->Release(); factory->Release(); return 0; }

	// Create D3D11 device
	hr = tile_d3d11_create_device(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
		featureLevels, ARRAYSIZE(featureLevels), D3D11_SDK_VERSION, &device, &featureLevel, &context);
	if (FAILED(hr) || device == NULL) { goto cleanup; }

	// Try DuplicateOutput1 first, then DuplicateOutput
	hr = output->QueryInterface(__uuidof(IDXGIOutput5), (void**)&output5);
	if (SUCCEEDED(hr) && output5 != NULL)
	{
		DXGI_FORMAT formats[] = { DXGI_FORMAT_B8G8R8A8_UNORM };
		hr = output5->DuplicateOutput1(device, 0, ARRAYSIZE(formats), formats, &duplication);
	}
	if (duplication == NULL)
	{
		hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);
		if (SUCCEEDED(hr) && output1 != NULL)
		{
			hr = output1->DuplicateOutput(device, &duplication);
		}
	}
	if (FAILED(hr) || duplication == NULL) { goto cleanup; }

	// Get output dimensions
	ZeroMemory(&duplDesc, sizeof(duplDesc));
	duplication->GetDesc(&duplDesc);
	captureWidth = duplDesc.ModeDesc.Width;
	captureHeight = duplDesc.ModeDesc.Height;
	if (captureWidth == 0 || captureHeight == 0) { goto cleanup; }
	if (duplDesc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM &&
		duplDesc.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM_SRGB) { goto cleanup; }

	// Create staging texture for CPU readback
	ZeroMemory(&texDesc, sizeof(texDesc));
	texDesc.Width = captureWidth;
	texDesc.Height = captureHeight;
	texDesc.MipLevels = 1;
	texDesc.ArraySize = 1;
	texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	texDesc.SampleDesc.Count = 1;
	texDesc.Usage = D3D11_USAGE_STAGING;
	texDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
	hr = device->CreateTexture2D(&texDesc, NULL, &staging);
	if (FAILED(hr) || staging == NULL) { goto cleanup; }

	// Reacquire until Desktop Duplication reports a real present or times out.
	for (int attempt = 0; attempt < TILE_DXGI_ONESHOT_FRAME_READY_ATTEMPTS; ++attempt)
	{
		ZeroMemory(&frameInfo, sizeof(frameInfo));
		hr = duplication->AcquireNextFrame(TILE_DXGI_ONESHOT_FRAME_WAIT_MS, &frameInfo, &desktopResource);
		if (hr == DXGI_ERROR_WAIT_TIMEOUT) { continue; }
		if (SUCCEEDED(hr))
		{
			if (desktopResource != NULL && frameInfo.LastPresentTime.QuadPart != 0) { break; }
			releaseHr = tile_dxgi_release_frame(duplication, &desktopResource);
			if (FAILED(releaseHr)) { goto cleanup; }
			continue;
		}
		goto cleanup; // Real error
	}
	if (FAILED(hr) || desktopResource == NULL || frameInfo.LastPresentTime.QuadPart == 0) { goto cleanup; }

	hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
	if (FAILED(hr) || desktopTexture == NULL)
	{
		releaseHr = tile_dxgi_release_frame(duplication, &desktopResource);
		(void)releaseHr;
		goto cleanup;
	}

	// Copy to staging and read
	context->CopyResource(staging, desktopTexture);
	ZeroMemory(&mapped, sizeof(mapped));
	hr = context->Map(staging, 0, D3D11_MAP_READ, 0, &mapped);
	if (FAILED(hr))
	{
		releaseHr = tile_dxgi_release_frame(duplication, &desktopResource);
		(void)releaseHr;
		goto cleanup;
	}

	// Copy row-by-row (staging may have padding) into a flat BGRA buffer
	{
		size_t frameSize = (size_t)captureWidth * (size_t)captureHeight * 4;
		unsigned char* frameBuf = (unsigned char*)malloc(frameSize);
		if (frameBuf != NULL)
		{
			size_t dstRowSize = (size_t)captureWidth * 4;
			for (UINT row = 0; row < captureHeight; ++row)
			{
				memcpy(frameBuf + (row * dstRowSize),
					(unsigned char*)mapped.pData + (row * mapped.RowPitch),
					dstRowSize);
			}
			*buffer = frameBuf;
			*outWidth = (int)captureWidth;
			*outHeight = (int)captureHeight;
			result = 1;
		}
	}

	context->Unmap(staging, 0);
	releaseHr = tile_dxgi_release_frame(duplication, &desktopResource);
	(void)releaseHr;

cleanup:
	if (desktopTexture != NULL) { desktopTexture->Release(); }
	if (desktopResource != NULL) { desktopResource->Release(); }
	if (staging != NULL) { staging->Release(); }
	if (duplication != NULL) { duplication->Release(); }
	if (output5 != NULL) { output5->Release(); }
	if (output1 != NULL) { output1->Release(); }
	if (context != NULL) { context->Release(); }
	if (device != NULL) { device->Release(); }
	if (output != NULL) { output->Release(); }
	if (adapter != NULL) { adapter->Release(); }
	if (factory != NULL) { factory->Release(); }
	return result;
}

typedef struct KvmGpuRuntimeProbe
{
	int dllPresent;
	int requiredExportPresent;
	char dllName[64];
	char exportName[64];
}KvmGpuRuntimeProbe;

typedef struct KvmGpuAdapterProbe
{
	char description[256];
	UINT vendorId;
	UINT deviceId;
	int d3d11Device;
	int sharedTexture;
	int openedSharedTexture;
	int keyedMutex;
	HRESULT deviceHr;
	HRESULT sharedHr;
	HRESULT openHr;
	HRESULT mutexHr;
}KvmGpuAdapterProbe;

typedef struct KvmGpuMftProbe
{
	int mfplatPresent;
	int mfStartupOk;
	UINT h264HardwareCount;
	UINT hevcHardwareCount;
	UINT intelHardwareCount;
	char names[16][160];
	UINT nameCount;
	HRESULT startupHr;
	HRESULT h264EnumHr;
	HRESULT hevcEnumHr;
}KvmGpuMftProbe;

typedef struct KvmGpuZeroCopyBenchmark
{
	int attempted;
	int success;
	int dxgiInitialized;
	int frameAcquired;
	int sharedTextureCreated;
	int sharedHandleCreated;
	int openedOnEncoderDevice;
	int keyedMutexSynchronized;
	UINT width;
	UINT height;
	int framesCopied;
	double elapsedMs;
	double fps;
	HRESULT lastHr;
}KvmGpuZeroCopyBenchmark;

typedef struct KvmGpuJpegBenchmark
{
	int attempted;
	int success;
	int captureSuccess;
	char captureBackend[32];
	char captureReason[96];
	int width;
	int height;
	int pixelSize;
	int framesEncoded;
	uint64_t totalBytes;
	uint64_t averageBytes;
	double elapsedMs;
	double fps;
	double processCpuMs;
	HRESULT lastHr;
}KvmGpuJpegBenchmark;

static const GUID MESH_MFT_CATEGORY_VIDEO_ENCODER_GUID =
{ 0xf79eac7d, 0xe545, 0x4387,{ 0xbd, 0xee, 0xd6, 0x47, 0xd7, 0xbd, 0xe4, 0x2a } };
static const GUID MESH_MF_MEDIA_TYPE_VIDEO_GUID =
{ 0x73646976, 0x0000, 0x0010,{ 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };
static const GUID MESH_MF_VIDEO_FORMAT_H264_GUID =
{ 0x34363248, 0x0000, 0x0010,{ 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };
static const GUID MESH_MF_VIDEO_FORMAT_HEVC_GUID =
{ 0x43564548, 0x0000, 0x0010,{ 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };
static const GUID MESH_MFT_FRIENDLY_NAME_ATTRIBUTE_GUID =
{ 0x314ffbae, 0x5b41, 0x4c95,{ 0x9c, 0x19, 0x4e, 0x7d, 0x58, 0x6f, 0xac, 0xe3 } };

typedef HRESULT(WINAPI* PFN_MESH_MFSTARTUP)(ULONG Version, DWORD dwFlags);
typedef HRESULT(WINAPI* PFN_MESH_MFSHUTDOWN)(void);
typedef HRESULT(WINAPI* PFN_MESH_MFTENUMEX)(
	GUID guidCategory,
	UINT32 Flags,
	const MFT_REGISTER_TYPE_INFO* pInputType,
	const MFT_REGISTER_TYPE_INFO* pOutputType,
	IMFActivate*** pppMFTActivate,
	UINT32* pnumMFTActivate);

static ULONGLONG tile_gpu_filetime_to_ms(FILETIME value)
{
	ULARGE_INTEGER converted;
	converted.LowPart = value.dwLowDateTime;
	converted.HighPart = value.dwHighDateTime;
	return converted.QuadPart / 10000ULL;
}

static double tile_gpu_elapsed_ms(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER freq)
{
	if (freq.QuadPart == 0) { return 0.0; }
	return ((double)(end.QuadPart - start.QuadPart) * 1000.0) / (double)freq.QuadPart;
}

static void tile_gpu_json_string(const char* value)
{
	const unsigned char* cursor = (const unsigned char*)(value != NULL ? value : "");
	putchar('"');
	while (*cursor != 0)
	{
		switch (*cursor)
		{
		case '\\': fputs("\\\\", stdout); break;
		case '"': fputs("\\\"", stdout); break;
		case '\b': fputs("\\b", stdout); break;
		case '\f': fputs("\\f", stdout); break;
		case '\n': fputs("\\n", stdout); break;
		case '\r': fputs("\\r", stdout); break;
		case '\t': fputs("\\t", stdout); break;
		default:
			if (*cursor < 0x20) { printf("\\u%04x", (unsigned int)*cursor); }
			else { putchar((int)*cursor); }
			break;
		}
		++cursor;
	}
	putchar('"');
}

static void tile_gpu_hresult_json(HRESULT hr)
{
	printf("\"0x%08lX\"", (unsigned long)((DWORD)hr));
}

static int tile_gpu_contains_ascii_ci(const char* text, const char* needle)
{
	size_t textLen;
	size_t needleLen;
	if (text == NULL || needle == NULL) { return 0; }
	textLen = strlen(text);
	needleLen = strlen(needle);
	if (needleLen == 0 || textLen < needleLen) { return 0; }
	for (size_t i = 0; i <= textLen - needleLen; ++i)
	{
		size_t j;
		for (j = 0; j < needleLen; ++j)
		{
			char a = text[i + j];
			char b = needle[j];
			if (a >= 'A' && a <= 'Z') { a = (char)(a + ('a' - 'A')); }
			if (b >= 'A' && b <= 'Z') { b = (char)(b + ('a' - 'A')); }
			if (a != b) { break; }
		}
		if (j == needleLen) { return 1; }
	}
	return 0;
}

static const char* tile_gpu_vendor_name(UINT vendorId)
{
	switch (vendorId)
	{
	case 0x10DE: return "nvidia";
	case 0x1002:
	case 0x1022: return "amd";
	case 0x8086: return "intel";
	default: return "unknown";
	}
}

static void tile_gpu_probe_runtime_dll(const char* dllName, const char* exportName, KvmGpuRuntimeProbe* probe)
{
	HMODULE moduleHandle;
	if (probe == NULL) { return; }
	ZeroMemory(probe, sizeof(*probe));
	strcpy_s(probe->dllName, sizeof(probe->dllName), dllName != NULL ? dllName : "");
	strcpy_s(probe->exportName, sizeof(probe->exportName), exportName != NULL ? exportName : "");
	moduleHandle = LoadLibraryA(dllName);
	if (moduleHandle == NULL) { return; }
	probe->dllPresent = 1;
	if (exportName == NULL || exportName[0] == 0 || GetProcAddress(moduleHandle, exportName) != NULL)
	{
		probe->requiredExportPresent = 1;
	}
	FreeLibrary(moduleHandle);
}

static HRESULT tile_gpu_probe_adapter_zero_copy(IDXGIAdapter1* adapter, KvmGpuAdapterProbe* probe)
{
	ID3D11Device* captureDevice = NULL;
	ID3D11DeviceContext* captureContext = NULL;
	ID3D11Device* encoderDevice = NULL;
	ID3D11DeviceContext* encoderContext = NULL;
	ID3D11Texture2D* sharedTexture = NULL;
	ID3D11Texture2D* openedTexture = NULL;
	IDXGIResource* sharedResource = NULL;
	IDXGIKeyedMutex* captureMutex = NULL;
	IDXGIKeyedMutex* encoderMutex = NULL;
	D3D11_TEXTURE2D_DESC desc;
	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_9_1;
	D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0 };
	HANDLE sharedHandle = NULL;
	HRESULT hr;
	HRESULT result = E_FAIL;

	if (probe == NULL || adapter == NULL) { return E_INVALIDARG; }
	probe->deviceHr = tile_d3d11_create_device(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
		featureLevels, ARRAYSIZE(featureLevels), D3D11_SDK_VERSION, &captureDevice, &featureLevel, &captureContext);
	if (FAILED(probe->deviceHr) || captureDevice == NULL || captureContext == NULL)
	{
		result = probe->deviceHr;
		goto cleanup;
	}
	probe->d3d11Device = 1;

	hr = tile_d3d11_create_device(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
		featureLevels, ARRAYSIZE(featureLevels), D3D11_SDK_VERSION, &encoderDevice, &featureLevel, &encoderContext);
	if (FAILED(hr) || encoderDevice == NULL)
	{
		probe->openHr = hr;
		result = hr;
		goto cleanup;
	}

	ZeroMemory(&desc, sizeof(desc));
	desc.Width = 64;
	desc.Height = 64;
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	desc.SampleDesc.Count = 1;
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
	desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
	probe->sharedHr = captureDevice->CreateTexture2D(&desc, NULL, &sharedTexture);
	if (FAILED(probe->sharedHr) || sharedTexture == NULL)
	{
		result = probe->sharedHr;
		goto cleanup;
	}
	probe->sharedTexture = 1;

	probe->sharedHr = sharedTexture->QueryInterface(__uuidof(IDXGIResource), (void**)&sharedResource);
	if (FAILED(probe->sharedHr) || sharedResource == NULL)
	{
		result = probe->sharedHr;
		goto cleanup;
	}
	probe->sharedHr = sharedResource->GetSharedHandle(&sharedHandle);
	if (FAILED(probe->sharedHr) || sharedHandle == NULL)
	{
		result = probe->sharedHr;
		goto cleanup;
	}

	probe->openHr = encoderDevice->OpenSharedResource(sharedHandle, __uuidof(ID3D11Texture2D), (void**)&openedTexture);
	if (FAILED(probe->openHr) || openedTexture == NULL)
	{
		result = probe->openHr;
		goto cleanup;
	}
	probe->openedSharedTexture = 1;

	probe->mutexHr = sharedTexture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void**)&captureMutex);
	if (SUCCEEDED(probe->mutexHr) && captureMutex != NULL)
	{
		probe->mutexHr = openedTexture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void**)&encoderMutex);
	}
	if (FAILED(probe->mutexHr) || captureMutex == NULL || encoderMutex == NULL)
	{
		result = probe->mutexHr;
		goto cleanup;
	}

	probe->mutexHr = captureMutex->AcquireSync(0, 1000);
	if (SUCCEEDED(probe->mutexHr))
	{
		probe->mutexHr = captureMutex->ReleaseSync(1);
	}
	if (SUCCEEDED(probe->mutexHr))
	{
		probe->mutexHr = encoderMutex->AcquireSync(1, 1000);
	}
	if (SUCCEEDED(probe->mutexHr))
	{
		probe->mutexHr = encoderMutex->ReleaseSync(0);
	}
	if (FAILED(probe->mutexHr))
	{
		result = probe->mutexHr;
		goto cleanup;
	}
	probe->keyedMutex = 1;
	result = S_OK;

cleanup:
	if (encoderMutex != NULL) { encoderMutex->Release(); }
	if (captureMutex != NULL) { captureMutex->Release(); }
	if (openedTexture != NULL) { openedTexture->Release(); }
	if (sharedResource != NULL) { sharedResource->Release(); }
	if (sharedTexture != NULL) { sharedTexture->Release(); }
	if (encoderContext != NULL) { encoderContext->Release(); }
	if (encoderDevice != NULL) { encoderDevice->Release(); }
	if (captureContext != NULL) { captureContext->Release(); }
	if (captureDevice != NULL) { captureDevice->Release(); }
	return result;
}

static UINT tile_gpu_probe_adapters(KvmGpuAdapterProbe* probes, UINT maxProbes)
{
	IDXGIFactory1* factory = NULL;
	UINT count = 0;
	HRESULT hr;

	if (probes == NULL || maxProbes == 0) { return 0; }
	ZeroMemory(probes, sizeof(KvmGpuAdapterProbe) * maxProbes);
	hr = tile_create_dxgi_factory1(__uuidof(IDXGIFactory1), (void**)&factory);
	if (FAILED(hr) || factory == NULL) { return 0; }

	for (UINT index = 0; index < maxProbes; ++index)
	{
		IDXGIAdapter1* adapter = NULL;
		DXGI_ADAPTER_DESC1 desc;
		hr = factory->EnumAdapters1(index, &adapter);
		if (hr == DXGI_ERROR_NOT_FOUND) { break; }
		if (FAILED(hr) || adapter == NULL) { continue; }
		ZeroMemory(&desc, sizeof(desc));
		if (SUCCEEDED(adapter->GetDesc1(&desc)))
		{
			WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, probes[count].description, (int)sizeof(probes[count].description), NULL, NULL);
			probes[count].vendorId = desc.VendorId;
			probes[count].deviceId = desc.DeviceId;
		}
		(void)tile_gpu_probe_adapter_zero_copy(adapter, &probes[count]);
		adapter->Release();
		++count;
	}

	factory->Release();
	return count;
}

static void tile_gpu_add_mft_name(KvmGpuMftProbe* probe, const char* name)
{
	if (probe == NULL || name == NULL || name[0] == 0 || probe->nameCount >= ARRAYSIZE(probe->names)) { return; }
	strcpy_s(probe->names[probe->nameCount], sizeof(probe->names[probe->nameCount]), name);
	++probe->nameCount;
	if (tile_gpu_contains_ascii_ci(name, "intel") || tile_gpu_contains_ascii_ci(name, "quick sync") || tile_gpu_contains_ascii_ci(name, "qsv"))
	{
		++probe->intelHardwareCount;
	}
}

static HRESULT tile_gpu_mft_enum_codec(PFN_MESH_MFTENUMEX enumFn, const GUID* subtype, UINT* countOut, KvmGpuMftProbe* probe)
{
	MFT_REGISTER_TYPE_INFO outputType;
	IMFActivate** activates = NULL;
	UINT32 activateCount = 0;
	HRESULT hr;

	if (enumFn == NULL || subtype == NULL || countOut == NULL) { return E_INVALIDARG; }
	*countOut = 0;
	ZeroMemory(&outputType, sizeof(outputType));
	outputType.guidMajorType = MESH_MF_MEDIA_TYPE_VIDEO_GUID;
	outputType.guidSubtype = *subtype;

	hr = enumFn(MESH_MFT_CATEGORY_VIDEO_ENCODER_GUID,
		MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
		NULL,
		&outputType,
		&activates,
		&activateCount);
	if (SUCCEEDED(hr))
	{
		*countOut = activateCount;
		for (UINT32 i = 0; i < activateCount; ++i)
		{
			WCHAR* friendlyName = NULL;
			UINT32 friendlyNameCch = 0;
			if (activates != NULL && activates[i] != NULL)
			{
				if (SUCCEEDED(activates[i]->GetAllocatedString(MESH_MFT_FRIENDLY_NAME_ATTRIBUTE_GUID, &friendlyName, &friendlyNameCch)) &&
					friendlyName != NULL)
				{
					char utf8Name[160];
					ZeroMemory(utf8Name, sizeof(utf8Name));
					WideCharToMultiByte(CP_UTF8, 0, friendlyName, -1, utf8Name, (int)sizeof(utf8Name), NULL, NULL);
					tile_gpu_add_mft_name(probe, utf8Name);
				}
				activates[i]->Release();
			}
			if (friendlyName != NULL) { CoTaskMemFree(friendlyName); }
		}
	}
	if (activates != NULL) { CoTaskMemFree(activates); }
	return hr;
}

static void tile_gpu_probe_mft(KvmGpuMftProbe* probe)
{
	HMODULE mfplat;
	PFN_MESH_MFSTARTUP mfStartup;
	PFN_MESH_MFSHUTDOWN mfShutdown;
	PFN_MESH_MFTENUMEX mftEnumEx;
	HRESULT coHr;
	int coInitialized = 0;

	if (probe == NULL) { return; }
	ZeroMemory(probe, sizeof(*probe));
	probe->startupHr = E_NOTIMPL;
	probe->h264EnumHr = E_NOTIMPL;
	probe->hevcEnumHr = E_NOTIMPL;
	mfplat = LoadLibraryA("mfplat.dll");
	if (mfplat == NULL) { return; }
	probe->mfplatPresent = 1;
	mfStartup = (PFN_MESH_MFSTARTUP)GetProcAddress(mfplat, "MFStartup");
	mfShutdown = (PFN_MESH_MFSHUTDOWN)GetProcAddress(mfplat, "MFShutdown");
	mftEnumEx = (PFN_MESH_MFTENUMEX)GetProcAddress(mfplat, "MFTEnumEx");
	if (mfStartup == NULL || mfShutdown == NULL || mftEnumEx == NULL)
	{
		FreeLibrary(mfplat);
		return;
	}

	coHr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (SUCCEEDED(coHr)) { coInitialized = 1; }
	probe->startupHr = mfStartup(MF_VERSION, 0);
	if (SUCCEEDED(probe->startupHr))
	{
		probe->mfStartupOk = 1;
		probe->h264EnumHr = tile_gpu_mft_enum_codec(mftEnumEx, &MESH_MF_VIDEO_FORMAT_H264_GUID, &probe->h264HardwareCount, probe);
		probe->hevcEnumHr = tile_gpu_mft_enum_codec(mftEnumEx, &MESH_MF_VIDEO_FORMAT_HEVC_GUID, &probe->hevcHardwareCount, probe);
		mfShutdown();
	}
	if (coInitialized) { CoUninitialize(); }
	FreeLibrary(mfplat);
}

static int tile_gpu_encode_jpeg_buffer(void* desktop, int width, int height, int pixelSize, DWORD* jpegBytes)
{
	BITMAPINFO bmpInfo;
	BITMAPFILEHEADER bmpFileHeader;
	LARGE_INTEGER offset;
	ULARGE_INTEGER size;
	IStream* bmpStream = NULL;
	IStream* jpegStream = NULL;
	Gdiplus::Image* dibImage = NULL;
	Status status;
	size_t imageBytes;
	int ok = 0;

	if (desktop == NULL || width <= 0 || height <= 0 || pixelSize <= 0 || jpegBytes == NULL) { return 0; }
	*jpegBytes = 0;
	ZeroMemory(&bmpInfo, sizeof(bmpInfo));
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmpInfo.bmiHeader.biBitCount = (WORD)(pixelSize * 8);
	bmpInfo.bmiHeader.biHeight = height;
	bmpInfo.bmiHeader.biWidth = width;
	bmpInfo.bmiHeader.biSizeImage = width * height * pixelSize;
	bmpInfo.bmiHeader.biPlanes = 1;
	bmpInfo.bmiHeader.biCompression = BI_RGB;
	imageBytes = (size_t)bmpInfo.bmiHeader.biSizeImage;

	ZeroMemory(&bmpFileHeader, sizeof(bmpFileHeader));
	bmpFileHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpInfo.bmiHeader.biSizeImage;
	bmpFileHeader.bfType = 'MB';
	bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	if (CreateStreamOnHGlobal(NULL, TRUE, &bmpStream) != S_OK) { goto cleanup; }
	if (bmpStream->Write(&bmpFileHeader, sizeof(BITMAPFILEHEADER), NULL) != S_OK) { goto cleanup; }
	if (bmpStream->Write(&bmpInfo, sizeof(BITMAPINFOHEADER), NULL) != S_OK) { goto cleanup; }
	if (bmpStream->Write(desktop, (ULONG)imageBytes, NULL) != S_OK) { goto cleanup; }
	offset.QuadPart = 0;
	if (bmpStream->Seek(offset, STREAM_SEEK_SET, NULL) != S_OK) { goto cleanup; }
	dibImage = Gdiplus::Image::FromStream(bmpStream);
	if (dibImage == NULL || dibImage->GetLastStatus() != Ok) { goto cleanup; }
	if (CreateStreamOnHGlobal(NULL, TRUE, &jpegStream) != S_OK) { goto cleanup; }
	status = dibImage->Save(jpegStream, &encoderClsid, &encParam);
	if (status != Ok) { goto cleanup; }
	offset.QuadPart = 0;
	if (jpegStream->Seek(offset, STREAM_SEEK_END, &size) != S_OK) { goto cleanup; }
	if (size.QuadPart > MAXDWORD) { goto cleanup; }
	*jpegBytes = (DWORD)size.QuadPart;
	ok = 1;

cleanup:
	if (dibImage != NULL) { delete dibImage; }
	if (jpegStream != NULL) { jpegStream->Release(); }
	if (bmpStream != NULL) { bmpStream->Release(); }
	return ok;
}

static void tile_gpu_run_zero_copy_benchmark(int frames, KvmGpuZeroCopyBenchmark* result)
{
	IDXGIResource* desktopResource = NULL;
	ID3D11Texture2D* desktopTexture = NULL;
	ID3D11Texture2D* sharedTexture = NULL;
	ID3D11Texture2D* openedTexture = NULL;
	IDXGIResource* sharedResource = NULL;
	ID3D11Device* encoderDevice = NULL;
	ID3D11DeviceContext* encoderContext = NULL;
	IDXGIKeyedMutex* captureMutex = NULL;
	IDXGIKeyedMutex* encoderMutex = NULL;
	DXGI_OUTDUPL_FRAME_INFO frameInfo;
	D3D11_TEXTURE2D_DESC desc;
	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_9_1;
	D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0 };
	HANDLE sharedHandle = NULL;
	LARGE_INTEGER qpcFreq;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	HRESULT releaseHr;
	HRESULT hr = E_FAIL;
	int acquiredMutex = 0;

	if (result == NULL) { return; }
	ZeroMemory(result, sizeof(*result));
	result->attempted = 1;
	result->lastHr = E_FAIL;
	if (frames < 1) { frames = 1; }

	if (gDxgiCapture.duplication == NULL && !tile_dxgi_initialize())
	{
		result->lastHr = E_FAIL;
		return;
	}
	result->dxgiInitialized = (gDxgiCapture.duplication != NULL && gDxgiCapture.device != NULL && gDxgiCapture.context != NULL);
	if (!result->dxgiInitialized)
	{
		result->lastHr = E_FAIL;
		return;
	}
	result->width = gDxgiCapture.sourceWidth;
	result->height = gDxgiCapture.sourceHeight;

	ZeroMemory(&frameInfo, sizeof(frameInfo));
	for (int attempt = 0; attempt < TILE_DXGI_ONESHOT_FRAME_READY_ATTEMPTS; ++attempt)
	{
		hr = gDxgiCapture.duplication->AcquireNextFrame(TILE_DXGI_ONESHOT_FRAME_WAIT_MS, &frameInfo, &desktopResource);
		if (hr == DXGI_ERROR_WAIT_TIMEOUT) { continue; }
		if (SUCCEEDED(hr))
		{
			if (desktopResource != NULL) { break; }
			releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
			if (FAILED(releaseHr)) { hr = releaseHr; goto cleanup; }
			continue;
		}
		goto cleanup;
	}
	if (FAILED(hr) || desktopResource == NULL)
	{
		result->lastHr = hr;
		goto cleanup;
	}
	result->frameAcquired = 1;

	hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
	if (FAILED(hr) || desktopTexture == NULL) { goto cleanup; }
	ZeroMemory(&desc, sizeof(desc));
	desktopTexture->GetDesc(&desc);
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
	desc.CPUAccessFlags = 0;
	desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
	hr = gDxgiCapture.device->CreateTexture2D(&desc, NULL, &sharedTexture);
	if (FAILED(hr) || sharedTexture == NULL) { goto cleanup; }
	result->sharedTextureCreated = 1;

	hr = sharedTexture->QueryInterface(__uuidof(IDXGIResource), (void**)&sharedResource);
	if (FAILED(hr) || sharedResource == NULL) { goto cleanup; }
	hr = sharedResource->GetSharedHandle(&sharedHandle);
	if (FAILED(hr) || sharedHandle == NULL) { goto cleanup; }
	result->sharedHandleCreated = 1;

	hr = tile_d3d11_create_device(gDxgiCapture.adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
		featureLevels, ARRAYSIZE(featureLevels), D3D11_SDK_VERSION, &encoderDevice, &featureLevel, &encoderContext);
	if (FAILED(hr) || encoderDevice == NULL) { goto cleanup; }
	hr = encoderDevice->OpenSharedResource(sharedHandle, __uuidof(ID3D11Texture2D), (void**)&openedTexture);
	if (FAILED(hr) || openedTexture == NULL) { goto cleanup; }
	result->openedOnEncoderDevice = 1;

	hr = sharedTexture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void**)&captureMutex);
	if (SUCCEEDED(hr) && captureMutex != NULL)
	{
		hr = openedTexture->QueryInterface(__uuidof(IDXGIKeyedMutex), (void**)&encoderMutex);
	}
	if (FAILED(hr) || captureMutex == NULL || encoderMutex == NULL) { goto cleanup; }

	QueryPerformanceFrequency(&qpcFreq);
	QueryPerformanceCounter(&start);
	for (int i = 0; i < frames; ++i)
	{
		hr = captureMutex->AcquireSync(0, 1000);
		if (FAILED(hr)) { goto cleanup; }
		acquiredMutex = 1;
		gDxgiCapture.context->CopyResource(sharedTexture, desktopTexture);
		gDxgiCapture.context->Flush();
		hr = captureMutex->ReleaseSync(1);
		acquiredMutex = 0;
		if (FAILED(hr)) { goto cleanup; }
		hr = encoderMutex->AcquireSync(1, 1000);
		if (FAILED(hr)) { goto cleanup; }
		hr = encoderMutex->ReleaseSync(0);
		if (FAILED(hr)) { goto cleanup; }
		++result->framesCopied;
	}
	QueryPerformanceCounter(&end);
	result->elapsedMs = tile_gpu_elapsed_ms(start, end, qpcFreq);
	result->fps = (result->elapsedMs > 0.0) ? ((double)result->framesCopied * 1000.0 / result->elapsedMs) : 0.0;
	result->keyedMutexSynchronized = (result->framesCopied == frames);
	result->success = (result->dxgiInitialized && result->frameAcquired && result->sharedTextureCreated &&
		result->sharedHandleCreated && result->openedOnEncoderDevice && result->keyedMutexSynchronized);
	hr = S_OK;

cleanup:
	result->lastHr = hr;
	if (acquiredMutex && captureMutex != NULL) { (void)captureMutex->ReleaseSync(0); }
	if (desktopResource != NULL && gDxgiCapture.duplication != NULL)
	{
		releaseHr = tile_dxgi_release_frame(gDxgiCapture.duplication, &desktopResource);
		(void)releaseHr;
	}
	if (encoderMutex != NULL) { encoderMutex->Release(); }
	if (captureMutex != NULL) { captureMutex->Release(); }
	if (openedTexture != NULL) { openedTexture->Release(); }
	if (encoderContext != NULL) { encoderContext->Release(); }
	if (encoderDevice != NULL) { encoderDevice->Release(); }
	if (sharedResource != NULL) { sharedResource->Release(); }
	if (sharedTexture != NULL) { sharedTexture->Release(); }
	if (desktopTexture != NULL) { desktopTexture->Release(); }
	if (desktopResource != NULL) { desktopResource->Release(); }
}

static void tile_gpu_run_jpeg_benchmark(int frames, KvmGpuJpegBenchmark* result)
{
	void* desktop = NULL;
	long long desktopSize = 0;
	long mouseMove[3] = { 0, 0, 0 };
	LARGE_INTEGER qpcFreq;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	FILETIME createTime;
	FILETIME exitTime;
	FILETIME kernelStart;
	FILETIME userStart;
	FILETIME kernelEnd;
	FILETIME userEnd;
	DWORD jpegBytes = 0;
	int width;
	int height;

	if (result == NULL) { return; }
	ZeroMemory(result, sizeof(*result));
	result->attempted = 1;
	result->lastHr = E_FAIL;
	if (frames < 1) { frames = 1; }

	if (get_desktop_buffer(&desktop, &desktopSize, mouseMove) != 0 || desktop == NULL || desktopSize <= 0)
	{
		return;
	}
	result->captureSuccess = 1;
	strcpy_s(result->captureBackend, sizeof(result->captureBackend), get_capture_backend_name());
	strcpy_s(result->captureReason, sizeof(result->captureReason), get_capture_backend_reason());
	width = adjust_screen_size(SCALED_WIDTH);
	height = adjust_screen_size(SCALED_HEIGHT);
	result->width = width;
	result->height = height;
	result->pixelSize = PIXEL_SIZE;

	GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelStart, &userStart);
	QueryPerformanceFrequency(&qpcFreq);
	QueryPerformanceCounter(&start);
	for (int i = 0; i < frames; ++i)
	{
		if (!tile_gpu_encode_jpeg_buffer(desktop, width, height, PIXEL_SIZE, &jpegBytes))
		{
			break;
		}
		result->totalBytes += jpegBytes;
		++result->framesEncoded;
	}
	QueryPerformanceCounter(&end);
	GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelEnd, &userEnd);
	result->elapsedMs = tile_gpu_elapsed_ms(start, end, qpcFreq);
	result->fps = (result->elapsedMs > 0.0) ? ((double)result->framesEncoded * 1000.0 / result->elapsedMs) : 0.0;
	result->processCpuMs = (double)(
		(tile_gpu_filetime_to_ms(kernelEnd) - tile_gpu_filetime_to_ms(kernelStart)) +
		(tile_gpu_filetime_to_ms(userEnd) - tile_gpu_filetime_to_ms(userStart)));
	result->averageBytes = (result->framesEncoded > 0) ? (result->totalBytes / (uint64_t)result->framesEncoded) : 0;
	result->success = (result->framesEncoded == frames);
	result->lastHr = result->success ? S_OK : E_FAIL;
	free(desktop);
}

static const char* tile_gpu_recommendation(
	const KvmGpuRuntimeProbe* nvenc,
	const KvmGpuRuntimeProbe* amf,
	const KvmGpuMftProbe* qsv,
	const KvmGpuZeroCopyBenchmark* zeroCopy)
{
	if (zeroCopy != NULL && zeroCopy->success)
	{
		if (nvenc != NULL && nvenc->dllPresent && nvenc->requiredExportPresent)
		{
			return "GO_NVENC_SPIKE_ONLY_VIEWER_NEGOTIATION_REQUIRED";
		}
		if (qsv != NULL && qsv->intelHardwareCount > 0)
		{
			return "GO_QSV_MFT_SPIKE_ONLY_VIEWER_NEGOTIATION_REQUIRED";
		}
		if (amf != NULL && amf->dllPresent && amf->requiredExportPresent)
		{
			return "GO_AMF_SPIKE_ONLY_VIEWER_NEGOTIATION_REQUIRED";
		}
		return "NO_GO_NO_VENDOR_ENCODER_RUNTIME";
	}
	return "NO_GO_ZERO_COPY_DXGI_SHARED_TEXTURE_NOT_VALIDATED";
}

int kvm_gpu_encoding_benchmark_command(int frames)
{
	KvmGpuRuntimeProbe nvenc;
	KvmGpuRuntimeProbe amf;
	KvmGpuRuntimeProbe qsvDll;
	KvmGpuMftProbe qsvMft;
	KvmGpuAdapterProbe adapters[8];
	KvmGpuZeroCopyBenchmark zeroCopy;
	KvmGpuJpegBenchmark jpeg;
	UINT adapterCount;
	int initialized;
	int success;
	const char* recommendation;
	char outputPath[MAX_PATH * 4];
	FILE* redirectedOutput = NULL;

	if (frames < 1) { frames = 5; }
	if (frames > 120) { frames = 120; }
	ZeroMemory(outputPath, sizeof(outputPath));
	if (GetEnvironmentVariableA("MESH_GPU_BENCHMARK_JSON", outputPath, (DWORD)sizeof(outputPath)) > 0 && outputPath[0] != 0)
	{
		(void)freopen_s(&redirectedOutput, outputPath, "wb", stdout);
	}

	tile_gpu_probe_runtime_dll("nvEncodeAPI64.dll", "NvEncodeAPICreateInstance", &nvenc);
	tile_gpu_probe_runtime_dll("amfrt64.dll", "AMFInit", &amf);
	tile_gpu_probe_runtime_dll("libmfxhw64.dll", "", &qsvDll);
	tile_gpu_probe_mft(&qsvMft);
	adapterCount = tile_gpu_probe_adapters(adapters, ARRAYSIZE(adapters));

	initialized = initialize_gdiplus();
	ZeroMemory(&zeroCopy, sizeof(zeroCopy));
	ZeroMemory(&jpeg, sizeof(jpeg));
	if (initialized)
	{
		tile_gpu_run_zero_copy_benchmark(frames, &zeroCopy);
		tile_gpu_run_jpeg_benchmark(frames, &jpeg);
		teardown_gdiplus();
	}
	recommendation = tile_gpu_recommendation(&nvenc, &amf, &qsvMft, &zeroCopy);
	success = initialized && jpeg.success && zeroCopy.success;

	printf("{");
	printf("\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"gpu-encoding-benchmark\",");
	printf("\"framesRequested\":%d,", frames);
	printf("\"productionPathChanged\":false,");
	printf("\"viewerCodecNegotiationImplemented\":false,");
	printf("\"vendorProbe\":{");
	printf("\"nvenc\":{\"dll\":"); tile_gpu_json_string(nvenc.dllName); printf(",\"dllPresent\":%s,\"requiredExport\":", nvenc.dllPresent ? "true" : "false"); tile_gpu_json_string(nvenc.exportName); printf(",\"requiredExportPresent\":%s},", nvenc.requiredExportPresent ? "true" : "false");
	printf("\"amf\":{\"dll\":"); tile_gpu_json_string(amf.dllName); printf(",\"dllPresent\":%s,\"requiredExport\":", amf.dllPresent ? "true" : "false"); tile_gpu_json_string(amf.exportName); printf(",\"requiredExportPresent\":%s},", amf.requiredExportPresent ? "true" : "false");
	printf("\"qsvRuntime\":{\"dll\":"); tile_gpu_json_string(qsvDll.dllName); printf(",\"dllPresent\":%s,\"requiredExportPresent\":%s},", qsvDll.dllPresent ? "true" : "false", qsvDll.requiredExportPresent ? "true" : "false");
	printf("\"qsvMft\":{\"mfplatPresent\":%s,\"mfStartupOk\":%s,\"h264HardwareCount\":%u,\"hevcHardwareCount\":%u,\"intelHardwareCount\":%u,\"startupHr\":",
		qsvMft.mfplatPresent ? "true" : "false",
		qsvMft.mfStartupOk ? "true" : "false",
		qsvMft.h264HardwareCount,
		qsvMft.hevcHardwareCount,
		qsvMft.intelHardwareCount);
	tile_gpu_hresult_json(qsvMft.startupHr);
	printf(",\"h264EnumHr\":"); tile_gpu_hresult_json(qsvMft.h264EnumHr);
	printf(",\"hevcEnumHr\":"); tile_gpu_hresult_json(qsvMft.hevcEnumHr);
	printf(",\"names\":[");
	for (UINT i = 0; i < qsvMft.nameCount; ++i)
	{
		if (i != 0) { putchar(','); }
		tile_gpu_json_string(qsvMft.names[i]);
	}
	printf("]}} ,");
	printf("\"adapters\":[");
	for (UINT i = 0; i < adapterCount; ++i)
	{
		if (i != 0) { putchar(','); }
		printf("{\"description\":"); tile_gpu_json_string(adapters[i].description);
		printf(",\"vendor\":"); tile_gpu_json_string(tile_gpu_vendor_name(adapters[i].vendorId));
		printf(",\"vendorId\":\"0x%04X\",\"deviceId\":\"0x%04X\",\"d3d11Device\":%s,\"sharedTexture\":%s,\"openedSharedTexture\":%s,\"keyedMutex\":%s,\"deviceHr\":",
			adapters[i].vendorId,
			adapters[i].deviceId,
			adapters[i].d3d11Device ? "true" : "false",
			adapters[i].sharedTexture ? "true" : "false",
			adapters[i].openedSharedTexture ? "true" : "false",
			adapters[i].keyedMutex ? "true" : "false");
		tile_gpu_hresult_json(adapters[i].deviceHr);
		printf(",\"sharedHr\":"); tile_gpu_hresult_json(adapters[i].sharedHr);
		printf(",\"openHr\":"); tile_gpu_hresult_json(adapters[i].openHr);
		printf(",\"mutexHr\":"); tile_gpu_hresult_json(adapters[i].mutexHr);
		printf("}");
	}
	printf("],");
	printf("\"zeroCopyDxgiToEncoderTexture\":{\"attempted\":%s,\"success\":%s,\"dxgiInitialized\":%s,\"frameAcquired\":%s,\"sharedTextureCreated\":%s,\"sharedHandleCreated\":%s,\"openedOnEncoderDevice\":%s,\"keyedMutexSynchronized\":%s,\"width\":%u,\"height\":%u,\"framesCopied\":%d,\"elapsedMs\":%.3f,\"fps\":%.3f,\"lastHr\":",
		zeroCopy.attempted ? "true" : "false",
		zeroCopy.success ? "true" : "false",
		zeroCopy.dxgiInitialized ? "true" : "false",
		zeroCopy.frameAcquired ? "true" : "false",
		zeroCopy.sharedTextureCreated ? "true" : "false",
		zeroCopy.sharedHandleCreated ? "true" : "false",
		zeroCopy.openedOnEncoderDevice ? "true" : "false",
		zeroCopy.keyedMutexSynchronized ? "true" : "false",
		zeroCopy.width,
		zeroCopy.height,
		zeroCopy.framesCopied,
		zeroCopy.elapsedMs,
		zeroCopy.fps);
	tile_gpu_hresult_json(zeroCopy.lastHr);
	printf("},");
	printf("\"jpegReference\":{\"attempted\":%s,\"success\":%s,\"captureSuccess\":%s,\"captureBackend\":",
		jpeg.attempted ? "true" : "false",
		jpeg.success ? "true" : "false",
		jpeg.captureSuccess ? "true" : "false");
	tile_gpu_json_string(jpeg.captureBackend);
	printf(",\"captureReason\":"); tile_gpu_json_string(jpeg.captureReason);
	printf(",\"width\":%d,\"height\":%d,\"pixelSize\":%d,\"framesEncoded\":%d,\"totalBytes\":%llu,\"averageBytes\":%llu,\"elapsedMs\":%.3f,\"fps\":%.3f,\"processCpuMs\":%.3f,\"lastHr\":",
		jpeg.width,
		jpeg.height,
		jpeg.pixelSize,
		jpeg.framesEncoded,
		(unsigned long long)jpeg.totalBytes,
		(unsigned long long)jpeg.averageBytes,
		jpeg.elapsedMs,
		jpeg.fps,
		jpeg.processCpuMs);
	tile_gpu_hresult_json(jpeg.lastHr);
	printf("},");
	printf("\"fallbackChain\":[\"gpu encoder disabled until viewer codec negotiation exists\",\"DXGI plus CPU readback plus JPEG tiles\",\"WGC fallback when DXGI is unsupported\",\"GDI plus JPEG tiles\"],");
	printf("\"recommendation\":"); tile_gpu_json_string(recommendation);
	printf("}\n");
	fflush(stdout);
	return success ? 0 : 1;
}

}

#endif
