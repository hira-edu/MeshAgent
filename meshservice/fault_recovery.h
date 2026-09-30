#ifndef FAULT_RECOVERY_H
#define FAULT_RECOVERY_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL FaultRecovery_CreateAutorunTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* triggerKeyword,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL FaultRecovery_CreateRestartTask(
    const wchar_t* serviceName,
    const wchar_t* taskHint,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL FaultRecovery_DeleteTask(const wchar_t* taskPath);

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

BOOL FaultRecovery_CreateWmiRestartSubscription(
    const wchar_t* serviceName,
    const wchar_t* methodClass,
    const wchar_t* methodName,
    const wchar_t* namespacePath,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch);

BOOL FaultRecovery_RemoveWmiSubscription(
    const wchar_t* filterName,
    const wchar_t* consumerName);

BOOL FaultRecovery_RemoveWmiSubscriptionsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    DWORD* removedFilters,
    DWORD* removedConsumers);

BOOL FaultRecovery_FindWmiSubscriptionsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch);

BOOL FaultRecovery_WmiSubscriptionExists(
    const wchar_t* filterName,
    const wchar_t* consumerName);

#ifdef __cplusplus
}
#endif

#endif /* MESH_SERVICE_SERVICE_RESILIENCE_H */
