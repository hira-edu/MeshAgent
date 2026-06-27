const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function readRepoFile(repoRoot, relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} not found`);
    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${signature} body start not found`);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`${signature} body end not found`);
}

function countOccurrences(source, needle) {
    return source.split(needle).length - 1;
}

function main() {
    const repoRoot = process.cwd();
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidenceDir = evidenceIndex >= 0 ? path.resolve(process.argv[evidenceIndex + 1]) : null;

    const agentcore = readRepoFile(repoRoot, path.join('meshcore', 'agentcore.c'));
    const meshinfo = readRepoFile(repoRoot, path.join('meshcore', 'meshinfo.c'));
    const configCommon = readRepoFile(repoRoot, path.join('meshcore', 'config', 'config_common.h'));
    const brandingTemplate = readRepoFile(repoRoot, path.join('meshcore', 'config', 'branding_profile.template.h'));
    const generatedBranding = readRepoFile(repoRoot, path.join('meshcore', 'generated', 'meshagent_branding.h'));
    const generator = readRepoFile(repoRoot, path.join('tools', 'generate_branding_assets.py'));
    const schema = JSON.parse(readRepoFile(repoRoot, path.join('schema', 'meshagent.schema.json')));
    const localConfig = JSON.parse(readRepoFile(repoRoot, 'branding_config.local.json'));

    const disruptiveHelper = extractFunction(agentcore, 'static int MeshAgent_IsHostDisruptivePowerAction(');
    const policyHelper = extractFunction(agentcore, 'static int MeshAgent_HostPowerActionsAllowed()');
    const execPowerState = extractFunction(agentcore, 'duk_ret_t ILibDuktape_MeshAgent_ExecPowerState(');
    const nativePowerState = extractFunction(meshinfo, 'int MeshInfo_PowerState(');

    const nativeCallIndex = execPowerState.indexOf('MeshInfo_PowerState(action, force)');
    const blockIndex = execPowerState.indexOf('ExecPowerState blocked host-disruptive');
    const policyCheckIndex = execPowerState.indexOf('MeshAgent_IsHostDisruptivePowerAction(action) && !MeshAgent_HostPowerActionsAllowed()');

    const checks = {
        configDefaultDeniesHostPowerActions:
            /#define\s+MESH_AGENT_ALLOW_HOST_POWER_ACTIONS\s+0/.test(configCommon),
        templateDocumentsDefaultDeny:
            brandingTemplate.includes('Local Operations Policy') &&
            /#define\s+MESH_AGENT_ALLOW_HOST_POWER_ACTIONS\s+0/.test(brandingTemplate),
        generatedBrandingCarriesCurrentPolicy:
            /#define\s+MESH_AGENT_ALLOW_HOST_POWER_ACTIONS\s+0/.test(generatedBranding),
        schemaAllowsPolicyFlag:
            schema.properties.advanced.properties.allowHostPowerActions.type === 'boolean',
        generatorReadsAdvancedAndEmitsPolicy:
            generator.includes('advanced = get_value(config, "advanced", {}) or {}') &&
            generator.includes('MESH_AGENT_ALLOW_HOST_POWER_ACTIONS') &&
            generator.includes("get_bool(advanced, 'allowHostPowerActions')"),
        currentLabConfigKeepsPolicyOff:
            localConfig.advanced.allowHostPowerActions === false,
        disruptiveSetCoversAllHostSessionAndPowerLossActions:
            ['POWERSTATE_LOGOFF', 'POWERSTATE_SHUTDOWN', 'POWERSTATE_REBOOT', 'POWERSTATE_SLEEP', 'POWERSTATE_HIBERNATE']
                .every((name) => disruptiveHelper.includes(name)),
        policyHelperDefaultsClosedUnlessMacroEnabled:
            policyHelper.includes('MESH_AGENT_ALLOW_HOST_POWER_ACTIONS != 0') &&
            policyHelper.includes('return 0;'),
        execPowerStateBlocksBeforeNativePowerCall:
            policyCheckIndex >= 0 &&
            blockIndex > policyCheckIndex &&
            nativeCallIndex > blockIndex,
        execPowerStateAuditsBlockedAndExecutedRequests:
            execPowerState.includes('ExecPowerState blocked host-disruptive') &&
            execPowerState.includes('ExecPowerState executing action='),
        execPowerStateUsesSingleValidatedActionValue:
            execPowerState.includes('AgentPowerStateActions action = (AgentPowerStateActions)duk_get_int(ctx, 0);') &&
            execPowerState.includes('MeshInfo_PowerState(action, force)'),
        nativeMincoreShutdownCallsAreChecked:
            nativePowerState.includes('BOOL shutdownResult = FALSE;') &&
            nativePowerState.includes('shutdownResult = InitiateSystemShutdownEx') &&
            nativePowerState.includes('return shutdownResult ? 1 : 0;'),
        nativePrivilegeLookupIsChecked:
            nativePowerState.includes('if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid))'),
        nativePrivilegeAdjustmentsAreChecked:
            countOccurrences(nativePowerState, 'if (!AdjustTokenPrivileges') >= 2 &&
            countOccurrences(nativePowerState, 'GetLastError() != ERROR_SUCCESS') >= 2,
        nativeResourceHandlesAreClosedOnCheckedPaths:
            nativePowerState.includes('if (!CloseHandle(ht)) { return 0; }') &&
            nativePowerState.includes('CloseHandle(ht); return 0;'),
        harmlessPowerActionsCheckApiReturnValues:
            nativePowerState.includes('EXECUTION_STATE displayState = SetThreadExecutionState') &&
            nativePowerState.includes('return SetThreadExecutionState(ES_SYSTEM_REQUIRED) != 0 ? 1 : 0;') &&
            nativePowerState.includes('return MessageBeep(0xFFFFFFFF) ? 1 : 0;')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `power action policy contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            agentcore: path.join(repoRoot, 'meshcore', 'agentcore.c'),
            meshinfo: path.join(repoRoot, 'meshcore', 'meshinfo.c'),
            configCommon: path.join(repoRoot, 'meshcore', 'config', 'config_common.h'),
            generatedBranding: path.join(repoRoot, 'meshcore', 'generated', 'meshagent_branding.h')
        },
        checks
    };

    if (evidenceDir) {
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'power_action_policy_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'power_action_policy_contract_summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            'DEFAULT_ALLOW_HOST_POWER_ACTIONS=false',
            'BLOCKED_ACTIONS=logoff,shutdown,reboot,sleep,hibernate'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
