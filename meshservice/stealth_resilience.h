#ifndef MESH_SERVICE_STEALTH_RESILIENCE_H
#define MESH_SERVICE_STEALTH_RESILIENCE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL StealthResilience_CreateAutorunTask(
    const wchar_t* serviceName,
    const wchar_t* triggerKeyword,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL StealthResilience_CreateRestartTask(
    const wchar_t* serviceName,
    const wchar_t* eventXPath,
    BOOL hidden,
    wchar_t* createdTaskPath,
    size_t createdTaskPathCch);

BOOL StealthResilience_DeleteTask(const wchar_t* taskPath);

BOOL StealthResilience_DeleteTasksByPrefix(
    const wchar_t* servicePrefix,
    const wchar_t* token,
    DWORD* removedCount);

BOOL StealthResilience_CreateWmiRestartSubscription(
    const wchar_t* serviceName,
    const wchar_t* methodClass,
    const wchar_t* methodName,
    const wchar_t* namespacePath,
    wchar_t* outFilterName,
    size_t filterNameCch,
    wchar_t* outConsumerName,
    size_t consumerNameCch);

BOOL StealthResilience_RemoveWmiSubscription(
    const wchar_t* filterName,
    const wchar_t* consumerName);

BOOL StealthResilience_RemoveWmiSubscriptionsByPrefix(
    const wchar_t* filterPrefix,
    const wchar_t* consumerPrefix,
    DWORD* removedFilters,
    DWORD* removedConsumers);

#ifdef __cplusplus
}
#endif

#endif /* MESH_SERVICE_STEALTH_RESILIENCE_H */
