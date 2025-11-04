#pragma once

#include <windows.h>
#include <string>
#include <vector>

// Resource identifiers
#define IDR_SVCHOST_DLL     101
#define IDR_PROVISIONING    102

struct InstallOptions
{
    bool install = true;
    bool uninstall = false;
    bool status = false;
    bool update = false;
    bool firewall = true;
    bool verbose = false;
    std::wstring mshOverride;
};

std::wstring GetBrandString(const wchar_t* value);
std::wstring GetInstallRoot();
std::wstring GetLogDirectory();
std::wstring GetDllPath();
std::wstring GetMshPath();

void LogLine(const std::wstring& message);
void LogHresult(const std::wstring& message, HRESULT hr);

bool EnsureDirectoryTree(const std::wstring& path);
bool WriteBufferToFile(const std::wstring& destination, const uint8_t* data, size_t length);
bool ExtractResourceToFile(WORD resourceId, const wchar_t* type, const std::wstring& destination);
bool CopyFileIfDifferent(const std::wstring& source, const std::wstring& destination);

bool InstallService(const InstallOptions& options);
bool UninstallService(const InstallOptions& options);
bool UpdateService(const InstallOptions& options);
bool QueryServiceStatusInfo();

bool StageProvisioning(const InstallOptions& options);
bool EnsureFirewallRules(const std::wstring& servicePath, bool enable);

InstallOptions ParseArguments(int argc, wchar_t** argv);

