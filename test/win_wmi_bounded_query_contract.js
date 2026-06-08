const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractSpan(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    if (start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span: ${startMarker}`);
    }
    return source.slice(start, end);
}

function main() {
    const wmiPath = path.resolve('modules', 'win-wmi.js');
    const source = fs.readFileSync(wmiPath, 'utf8');
    const syncQuery = extractSpan(source, 'function query(resourceString, queryString, fields, options)', 'module.exports');
    const enumerateProperties = extractSpan(source, 'function enumerateProperties(j, fields)', 'function queryAsync');

    const checks = {
        syncQueryUsesSemisynchronousForwardOnlyFlags:
            source.includes('const WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;') &&
            source.includes('const WBEM_FLAG_FORWARD_ONLY = 0x20;') &&
            source.includes('const WBEM_QUERY_FLAGS = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;') &&
            syncQuery.includes('ExecQuery(services.Deref(), language, query, WBEM_QUERY_FLAGS, 0, results)'),
        syncQueryHasFiniteEnumerationTimeout:
            source.includes('const WBEM_DEFAULT_QUERY_TIMEOUT_MS = 15000;') &&
            source.includes('function _queryTimeoutMs(options)') &&
            syncQuery.includes('var timeoutMs = _queryTimeoutMs(options);') &&
            syncQuery.includes('Next(results.Deref(), timeoutMs, 1, result, returnedCount)') &&
            !syncQuery.includes('WBEM_INFINITE'),
        timeoutReturnsCollectedRowsInsteadOfThrowing:
            source.includes('const WBEM_S_TIMEDOUT = 0x00040004;') &&
            syncQuery.includes('nextResult == WBEM_S_TIMEDOUT') &&
            syncQuery.includes('if (nextResult == WBEM_S_FALSE || nextResult == WBEM_S_TIMEDOUT || count == 0) { break; }'),
        comInterfacesReleasedInFinally:
            syncQuery.includes('finally') &&
            syncQuery.includes('_releaseComPointer(results.Deref(), results.funcs);') &&
            syncQuery.includes('_releaseComPointer(services.Deref(), services.funcs);') &&
            syncQuery.includes('_releaseComPointer(locator, locator.funcs);'),
        enumeratedObjectsReleasedPerRow:
            syncQuery.includes('ret.push(enumerateProperties(result, fields));') &&
            syncQuery.includes('_releaseComPointer(result.Deref(), result.funcs);') &&
            syncQuery.includes('result = GM.CreatePointer();'),
        variantAndSafeArrayMemoryIsReleased:
            source.includes("OleAut32.CreateMethod('SafeArrayUnaccessData');") &&
            source.includes("OleAut32.CreateMethod('SafeArrayDestroy');") &&
            source.includes("OleAut32.CreateMethod('VariantClear');") &&
            enumerateProperties.includes('OleAut32.SafeArrayUnaccessData(namesArray);') &&
            enumerateProperties.includes('OleAut32.SafeArrayDestroy(namesArray);') &&
            enumerateProperties.includes('OleAut32.VariantClear(tmp1);'),
        asyncQueryDoesNotRequestBidirectionalEnumeration:
            source.includes('ExecQueryAsync(handlers.services.Deref(), language, query, WBEM_QUERY_FLAGS, 0, handlers)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({
        success: true,
        wmiPath,
        checks
    }, null, 2) + '\n');
}

main();
