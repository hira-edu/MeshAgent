#ifndef FAULT_RECOVERY_H
#define FAULT_RECOVERY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL FaultRecovery_FormatServiceStopEventXPath(
    const wchar_t* serviceEventName,
    wchar_t* eventXPath,
    size_t eventXPathCch);

BOOL FaultRecovery_CreateAutorunTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* triggerKeyword,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL FaultRecovery_CreateServiceRecoveryTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL FaultRecovery_ServiceRecoveryTaskMatches(
    const wchar_t* taskPath,
    const wchar_t* serviceName,
    const wchar_t* eventXPath);

BOOL FaultRecovery_DeleteTask(const wchar_t* taskPath);

/* TRUE means inspection succeeded; presence is returned separately. */
BOOL FaultRecovery_QueryTasksByPrefix(const wchar_t* taskPrefix, BOOL* present);
BOOL FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(
    const wchar_t* filterPrefix, const wchar_t* consumerPrefix, BOOL* present);

BOOL FaultRecovery_DeleteTasksByPrefix(
    const wchar_t* servicePrefix,
    const wchar_t* token,
    DWORD* removedCount);

BOOL FaultRecovery_TaskExists(const wchar_t* taskPath);

BOOL FaultRecovery_FindTaskByPrefix(
    const wchar_t* taskPrefix,
    const wchar_t* token,
    wchar_t* outTaskPath,
    size_t outTaskPathCch);

BOOL FaultRecovery_CreateServiceRecoveryMonitor(
    const wchar_t* serviceName,
    const wchar_t* namespacePath,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch);

BOOL FaultRecovery_ServiceRecoveryMonitorMatches(
    const wchar_t* filterName,
    const wchar_t* consumerName,
    const wchar_t* serviceName,
    const wchar_t* namespacePath);

BOOL FaultRecovery_RemoveServiceRecoveryMonitor(
    const wchar_t* filterName,
    const wchar_t* consumerName);

BOOL FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    DWORD* removedFilters,
    DWORD* removedConsumers);

BOOL FaultRecovery_FindServiceRecoveryMonitorsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch);

BOOL FaultRecovery_ServiceRecoveryMonitorExists(
    const wchar_t* filterName,
    const wchar_t* consumerName);

#ifdef __cplusplus
}
#endif

#endif /* MESH_SERVICE_SERVICE_RESILIENCE_H */
