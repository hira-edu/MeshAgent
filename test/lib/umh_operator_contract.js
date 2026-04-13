(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.UMHOperatorContract = factory();
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    var controlOpMap = {
        status: 'status',
        listprocesses: 'listProcesses',
        getflowcontract: 'getFlowContract',
        getcapabilities: 'getCapabilities',
        getpolicy: 'getPolicy',
        getconfig: 'getConfig',
        inject: 'inject',
        injectall: 'injectAll',
        telemetry: 'telemetry',
        repair: 'repair',
        setpolicy: 'setPolicy',
        setconfig: 'setConfig',
        profileprocess: 'profileProcess',
        hookprofile: 'hookProfile',
        methodpolicy: 'methodPolicy',
        safetystate: 'safetyState',
        securityboundary: 'securityBoundary',
        injecttargetset: 'injectTargetSet',
        cleartargetscope: 'clearTargetScope',
        lockdownbypass: 'lockdownBypass',
        examsoftbypass: 'examsoftBypass',
        ipcbypass: 'ipcBypass'
    };

    var pidRequiredOps = {
        inject: 1,
        telemetry: 1,
        repair: 1,
        disable: 1,
        profileprocess: 1,
        registerprotectedpid: 1,
        unregisterprotectedpid: 1
    };

    var stateChangingOps = {
        inject: 1,
        injectall: 1,
        telemetry: 1,
        repair: 1,
        setpolicy: 1,
        setconfig: 1,
        injecttargetset: 1,
        cleartargetscope: 1,
        lockdownbypass: 1,
        examsoftbypass: 1,
        ipcbypass: 1
    };

    var flowScopedOps = { injecttargetset: 1, injectall: 1, cleartargetscope: 1 };

    var defaultFlowContract = {
        protocol: 'umh-control',
        contractVersion: '2026-03-05',
        flowProfile: 'report-driven-lockdown-v1',
        requiredHeaders: [
            'x-umh-contract-version',
            'x-umh-flow-profile',
            'x-umh-run-id',
            'x-umh-client',
            'x-umh-target-tag',
            'x-umh-method-key'
        ]
    };

    var actionAllowedByOp = {
        ipcbypass: { listtargets: 'list-targets', status: 'status', disable: 'disable', enable: 'enable' },
        lockdownbypass: { status: 'status', apply: 'apply', applyharness: 'apply-harness', revert: 'revert', revertharness: 'revert-harness' },
        examsoftbypass: { status: 'status', secureenter: 'secure-enter', secureexit: 'secure-exit' }
    };

    var protectedScreenActions = {
        lockdownBypass: ['apply', 'apply-harness'],
        examsoftBypass: ['secure-enter']
    };

    var operationOrder = [
        'install',
        'uninstall',
        'serviceStatus',
        'verify',
        'status',
        'listProcesses',
        'getFlowContract',
        'getCapabilities',
        'getPolicy',
        'getConfig',
        'uiSnapshot',
        'profileProcess',
        'methodPolicy',
        'safetyState',
        'hookProfile',
        'securityBoundary',
        'inject',
        'injectTargetSet',
        'injectAll',
        'telemetry',
        'repair',
        'setPolicy',
        'setConfig',
        'clearTargetScope',
        'ipcBypass',
        'lockdownBypass',
        'examsoftBypass'
    ];

    function cloneValue(value) {
        if (value == null || typeof value !== 'object') { return value; }
        if (value instanceof Array) {
            var arr = [];
            for (var i = 0; i < value.length; ++i) { arr.push(cloneValue(value[i])); }
            return arr;
        }
        var copy = {};
        for (var key in value) { copy[key] = cloneValue(value[key]); }
        return copy;
    }

    function normalizeToken(value) {
        if (typeof value !== 'string' || value.length === 0) { return null; }
        return value.toLowerCase().split('-').join('').split('_').join('').split(' ').join('');
    }

    function canonicalControlOp(value) {
        var key = normalizeToken(value);
        if (key == null) { return null; }
        return controlOpMap[key] || null;
    }

    function canonicalAction(op, action) {
        var opKey = normalizeToken(op);
        if (opKey == null) { return null; }
        var allowed = actionAllowedByOp[opKey];
        if (allowed == null) { return null; }
        var actionKey = normalizeToken(action);
        if (actionKey == null) { return null; }
        return allowed[actionKey] || null;
    }

    function parsePositiveInt(value) {
        if (typeof value === 'number') {
            if (value > 0 && Math.floor(value) === value) { return value; }
            return null;
        }
        if (typeof value !== 'string') { return null; }
        if (!/^[0-9]+$/.test(value.trim())) { return null; }
        var parsed = parseInt(value, 10);
        return (parsed > 0) ? parsed : null;
    }

    function parsePidList(value) {
        var items = [];
        if (value instanceof Array) {
            for (var i = 0; i < value.length; ++i) {
                var pidValue = parsePositiveInt(value[i]);
                if (pidValue != null) { items.push(pidValue); }
            }
            return items;
        }
        if (typeof value !== 'string' || value.trim().length === 0) { return items; }
        var parts = value.split(',');
        for (var j = 0; j < parts.length; ++j) {
            var pid = parsePositiveInt(parts[j].trim());
            if (pid != null) { items.push(pid); }
        }
        return items;
    }

    function toConsoleValue(field, value) {
        if (value == null) { return null; }
        if (field.type === 'json') { return JSON.stringify(value); }
        if (field.type === 'csv' && value instanceof Array) { return value.join(','); }
        return String(value);
    }

    var operations = {
        install: {
            id: 'install',
            category: 'lifecycle',
            command: 'install',
            renderMode: 'lifecycle-text',
            fields: [
                { name: 'url', flag: '--url', type: 'text' },
                { name: 'pin', flag: '--pin', type: 'text' },
                { name: 'insecure', flag: '--insecure', type: 'boolean' }
            ],
            sampleInput: { url: 'https://mesh.example.invalid/userfiles/umh/MasterService.exe', pin: 'a'.repeat(96) },
            sampleResponse: 'umhctl: downloading from https://mesh.example.invalid/userfiles/umh/MasterService.exe ...'
        },
        uninstall: {
            id: 'uninstall',
            category: 'lifecycle',
            command: 'uninstall',
            renderMode: 'lifecycle-text',
            fields: [],
            sampleInput: {},
            sampleResponse: 'umhctl: uninstalling ...'
        },
        serviceStatus: {
            id: 'serviceStatus',
            category: 'lifecycle',
            command: 'status',
            renderMode: 'lifecycle-text',
            serviceStatus: true,
            fields: [],
            sampleInput: {},
            sampleResponse: 'umhctl service status (exit 0):\r\n{"ok":true,"state":"running"}'
        },
        verify: {
            id: 'verify',
            category: 'lifecycle',
            command: 'verify',
            renderMode: 'lifecycle-text',
            fields: [],
            sampleInput: {},
            sampleResponse: 'umhctl: verifying service status ...'
        },
        status: {
            id: 'status',
            category: 'query',
            command: 'status',
            renderMode: 'control-json',
            controlOp: 'status',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { healthy: true, pipe: 'ready' } }
        },
        listProcesses: {
            id: 'listProcesses',
            category: 'query',
            command: 'listProcesses',
            renderMode: 'control-json',
            controlOp: 'listProcesses',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: [{ pid: 4242, name: 'examclient.exe' }] }
        },
        getFlowContract: {
            id: 'getFlowContract',
            category: 'query',
            command: 'getFlowContract',
            renderMode: 'control-json',
            controlOp: 'getFlowContract',
            fields: [],
            sampleInput: {},
            sampleResponse: {
                ok: true,
                data: {
                    protocol: defaultFlowContract.protocol,
                    contract_version: defaultFlowContract.contractVersion,
                    flow_profile: defaultFlowContract.flowProfile,
                    required_headers: defaultFlowContract.requiredHeaders.slice(0)
                }
            }
        },
        getCapabilities: {
            id: 'getCapabilities',
            category: 'query',
            command: 'getCapabilities',
            renderMode: 'control-json',
            controlOp: 'getCapabilities',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { supported_ops: ['status', 'inject', 'ipcBypass'] } }
        },
        getPolicy: {
            id: 'getPolicy',
            category: 'query',
            command: 'getPolicy',
            renderMode: 'control-json',
            controlOp: 'getPolicy',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { lockdown: false, examsoft: false } }
        },
        getConfig: {
            id: 'getConfig',
            category: 'query',
            command: 'getConfig',
            renderMode: 'control-json',
            controlOp: 'getConfig',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: '{"profile":"lab","capture":"dxgi"}' }
        },
        uiSnapshot: {
            id: 'uiSnapshot',
            category: 'query',
            command: 'uiSnapshot',
            renderMode: 'snapshot-json',
            uiSnapshot: true,
            fields: [
                { name: 'pid', flag: '--pid', type: 'number' }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: {
                ok: true,
                data: {
                    requested_pid: 4242,
                    status: { healthy: true },
                    flow_contract: {
                        protocol: defaultFlowContract.protocol,
                        contract_version: defaultFlowContract.contractVersion,
                        flow_profile: defaultFlowContract.flowProfile,
                        required_headers: defaultFlowContract.requiredHeaders.slice(0)
                    }
                },
                meta: { sections: { status: { ok: true }, flow_contract: { ok: true } } }
            }
        },
        profileProcess: {
            id: 'profileProcess',
            category: 'query',
            command: 'profileProcess',
            renderMode: 'control-json',
            controlOp: 'profileProcess',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number', required: true }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: { ok: true, data: { pid: 4242, profile: 'exam-client' } }
        },
        methodPolicy: {
            id: 'methodPolicy',
            category: 'query',
            command: 'methodPolicy',
            renderMode: 'control-json',
            controlOp: 'methodPolicy',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number' }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: { ok: true, data: { default_order_resolved: true, effective_order: ['standard'], methods: [{ key: 'standard', allowed: true }] } }
        },
        safetyState: {
            id: 'safetyState',
            category: 'query',
            command: 'safetyState',
            renderMode: 'control-json',
            controlOp: 'safetyState',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { active_scope: false, destructive_controls_supported: false } }
        },
        hookProfile: {
            id: 'hookProfile',
            category: 'query',
            command: 'hookProfile',
            renderMode: 'control-json',
            controlOp: 'hookProfile',
            fields: [
                { name: 'target', flag: '--target', type: 'text' },
                { name: 'exe', flag: '--exe', type: 'text' }
            ],
            sampleInput: { target: 'lockdown_browser', exe: 'LockDownBrowser.exe' },
            sampleResponse: { ok: true, data: { resolved_target_tag: 'lockdown_browser', resolved_layer_policy_id: 'respondus-lockdown-layer-v1' } }
        },
        securityBoundary: {
            id: 'securityBoundary',
            category: 'query',
            command: 'securityBoundary',
            renderMode: 'control-json',
            controlOp: 'securityBoundary',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number' },
                { name: 'target', flag: '--target', type: 'text' }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: { ok: true, data: { role: 'browser-main', target_tag: 'lockdown_browser' } }
        },
        inject: {
            id: 'inject',
            category: 'mutation',
            command: 'inject',
            renderMode: 'control-json',
            controlOp: 'inject',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number', required: true },
                { name: 'method', flag: '--method', type: 'text' },
                { name: 'technique', flag: '--technique', type: 'text' }
            ],
            sampleInput: { pid: 4242, method: 'load-library', technique: 'remote-thread' },
            sampleResponse: { ok: true, data: { pid: 4242, injected: true } }
        },
        injectTargetSet: {
            id: 'injectTargetSet',
            category: 'mutation',
            command: 'injectTargetSet',
            renderMode: 'control-json',
            controlOp: 'injectTargetSet',
            fields: [
                { name: 'pids', flag: '--pids', type: 'csv', required: true },
                { name: 'runId', flag: '--run-id', type: 'text' },
                { name: 'targetTag', flag: '--target-tag', type: 'text' },
                { name: 'methodKey', flag: '--method-key', type: 'text' }
            ],
            sampleInput: { pids: '4242,5252', runId: 'run-lab-100', targetTag: 'screen-quizapp', methodKey: 'remote-thread' },
            sampleResponse: { ok: true, data: { target_pids: [4242, 5252] } }
        },
        injectAll: {
            id: 'injectAll',
            category: 'mutation',
            command: 'injectAll',
            renderMode: 'control-json',
            controlOp: 'injectAll',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { mode: 'all' } }
        },
        telemetry: {
            id: 'telemetry',
            category: 'mutation',
            command: 'telemetry',
            renderMode: 'control-json',
            controlOp: 'telemetry',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number', required: true }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: { ok: true, data: { pid: 4242, telemetry: 'updated' } }
        },
        repair: {
            id: 'repair',
            category: 'mutation',
            command: 'repair',
            renderMode: 'control-json',
            controlOp: 'repair',
            fields: [
                { name: 'pid', flag: '--pid', type: 'number', required: true }
            ],
            sampleInput: { pid: 4242 },
            sampleResponse: { ok: true, data: { pid: 4242, repaired: true } }
        },
        setPolicy: {
            id: 'setPolicy',
            category: 'mutation',
            command: 'setPolicy',
            renderMode: 'control-json',
            controlOp: 'setPolicy',
            fields: [
                { name: 'policy', flag: '--policy', type: 'text', required: true }
            ],
            sampleInput: { policy: '{"lockdown":true}' },
            sampleResponse: { ok: true, data: { policy: 'updated' } }
        },
        setConfig: {
            id: 'setConfig',
            category: 'mutation',
            command: 'setConfig',
            renderMode: 'control-json',
            controlOp: 'setConfig',
            fields: [
                { name: 'content', flag: '--content', type: 'text', required: true }
            ],
            sampleInput: { content: '{"capture":"dxgi"}' },
            sampleResponse: { ok: true, data: { config: 'updated' } }
        },
        clearTargetScope: {
            id: 'clearTargetScope',
            category: 'mutation',
            command: 'clearTargetScope',
            renderMode: 'control-json',
            controlOp: 'clearTargetScope',
            fields: [],
            sampleInput: {},
            sampleResponse: { ok: true, data: { cleared: true } }
        },
        ipcBypass: {
            id: 'ipcBypass',
            category: 'bypass',
            command: 'ipcBypass',
            renderMode: 'control-json',
            controlOp: 'ipcBypass',
            fields: [
                { name: 'action', flag: '--action', type: 'select', options: ['list-targets', 'status', 'disable', 'enable'] },
                { name: 'target', flag: '--target', type: 'text' },
                { name: 'domain', flag: '--domain', type: 'select', options: ['screen', 'input', 'network', 'process', 'all'] }
            ],
            sampleInput: { action: 'enable', target: 'adapter-blue', domain: 'screen' },
            sampleResponse: { ok: true, data: { action: 'enable', target: 'adapter-blue', domain: 'screen' } }
        },
        lockdownBypass: {
            id: 'lockdownBypass',
            category: 'bypass',
            command: 'lockdownBypass',
            renderMode: 'control-json',
            controlOp: 'lockdownBypass',
            fields: [
                { name: 'action', flag: '--action', type: 'select', options: ['status', 'apply', 'apply-harness', 'revert', 'revert-harness'] }
            ],
            sampleInput: { action: 'apply-harness' },
            sampleResponse: { ok: true, data: { action: 'apply-harness', state: 'applied' } }
        },
        examsoftBypass: {
            id: 'examsoftBypass',
            category: 'bypass',
            command: 'examsoftBypass',
            renderMode: 'control-json',
            controlOp: 'examsoftBypass',
            fields: [
                { name: 'action', flag: '--action', type: 'select', options: ['status', 'secure-enter', 'secure-exit'] }
            ],
            sampleInput: { action: 'secure-enter' },
            sampleResponse: { ok: true, data: { action: 'secure-enter', state: 'entered' } }
        }
    };

    var surfaceLayouts = {
        desktop: {
            id: 'desktop',
            label: 'MeshCentral desktop device page',
            groups: [
                { id: 'lifecycle', label: 'Lifecycle', operations: ['install', 'uninstall', 'serviceStatus', 'verify'] },
                { id: 'query', label: 'Query', operations: ['status', 'listProcesses', 'getFlowContract', 'getCapabilities', 'getPolicy', 'getConfig', 'uiSnapshot', 'profileProcess', 'methodPolicy', 'safetyState', 'hookProfile', 'securityBoundary'] },
                { id: 'mutation', label: 'Mutation', operations: ['inject', 'injectTargetSet', 'injectAll', 'telemetry', 'repair', 'setPolicy', 'setConfig', 'clearTargetScope'] },
                { id: 'bypass', label: 'Bypass', operations: ['ipcBypass', 'lockdownBypass', 'examsoftBypass'] }
            ]
        },
        mobile: {
            id: 'mobile',
            label: 'MeshCentral mobile device page',
            groups: [
                { id: 'lifecycle', label: 'Lifecycle', operations: ['install', 'uninstall', 'serviceStatus', 'verify'] },
                { id: 'query', label: 'Query', operations: ['status', 'listProcesses', 'getFlowContract', 'getCapabilities', 'getPolicy', 'getConfig', 'uiSnapshot', 'profileProcess', 'methodPolicy', 'safetyState', 'hookProfile', 'securityBoundary'] },
                { id: 'mutation', label: 'Mutation', operations: ['inject', 'injectTargetSet', 'injectAll', 'telemetry', 'repair', 'setPolicy', 'setConfig', 'clearTargetScope'] },
                { id: 'bypass', label: 'Bypass', operations: ['ipcBypass', 'lockdownBypass', 'examsoftBypass'] }
            ]
        }
    };

    var helpFragments = [
        'Lifecycle:',
        '  umhctl install [--url <url>] [--pin <sha384>] [--insecure]',
        '  umhctl uninstall',
        '  umhctl status --service',
        '  umhctl verify',
        'Control pipe - query:',
        '  umhctl status | listProcesses | getFlowContract | getCapabilities',
        '  umhctl getPolicy | getConfig | safetyState',
        '  umhctl uiSnapshot [--pid <pid>]',
        '  umhctl profileProcess --pid <pid>',
        '  umhctl methodPolicy [--pid <pid>]',
        '  umhctl hookProfile --target <tag> [--exe <path>]',
        '  umhctl securityBoundary [--pid <pid>] [--target <tag>]',
        'Control pipe - mutation:',
        '  umhctl inject --pid <pid> [--method <m>] [--technique <t>]',
        '  umhctl injectTargetSet --pids <csv> [--run-id <id>] [--target-tag <tag>] [--method-key <key>]',
        '  umhctl injectAll',
        '  umhctl telemetry --pid <pid>',
        '  umhctl repair --pid <pid>',
        '  umhctl setPolicy --policy <json>',
        '  umhctl setConfig --content <json-or-text>',
        '  umhctl clearTargetScope',
        'Bypass:',
        '  umhctl ipcBypass --action <list-targets|status|disable|enable> [--target <adapter>] [--domain <screen|input|network|process|all>]',
        '  umhctl lockdownBypass --action <status|apply|apply-harness|revert|revert-harness>',
        '  umhctl examsoftBypass --action <status|secure-enter|secure-exit>',
        'Raw JSON:',
        '  umhctl --json \'{"op":"status"}\''
    ];

    var uiSnapshotSections = ['status', 'flow_contract', 'capabilities', 'processes', 'policy', 'config', 'safety_state', 'process_profile', 'method_policy', 'security_boundary'];

    var consoleCases = [
        { name: 'status-query', op: 'status', args: {}, expected: { op: 'status' } },
        { name: 'profile-process', op: 'profileProcess', args: { pid: 4242 }, expected: { op: 'profileProcess', pid: 4242 } },
        { name: 'method-policy', op: 'methodPolicy', args: { pid: 4242 }, expected: { op: 'methodPolicy', pid: 4242 } },
        { name: 'hook-profile', op: 'hookProfile', args: { target: 'lockdown_browser', exe: 'LockDownBrowser.exe' }, expected: { op: 'hookProfile', target: 'lockdown_browser', exe: 'LockDownBrowser.exe' } },
        { name: 'security-boundary', op: 'securityBoundary', args: { pid: 4242 }, expected: { op: 'securityBoundary', pid: 4242 } },
        { name: 'inject-target-set', op: 'injectTargetSet', args: { pids: '101,202', 'run-id': 'run-lab-100', 'target-tag': 'screen-quizapp', 'method-key': 'remote-thread' }, expected: { op: 'injectTargetSet', target_pids: [101, 202], headers: { 'x-umh-run-id': 'run-lab-100', 'x-umh-target-tag': 'screen-quizapp', 'x-umh-method-key': 'remote-thread' } } },
        { name: 'ipc-bypass', op: 'ipcBypass', args: { action: 'enable', target: 'adapter-blue', domain: 'screen' }, expected: { op: 'ipcBypass', action: 'enable', target: 'adapter-blue', domain: 'screen' } },
        { name: 'lockdown-default-status', op: 'lockdownBypass', args: {}, expected: { op: 'lockdownBypass', action: 'status' } }
    ];

    var rawJsonCases = [
        { name: 'get-policy', payload: { op: 'getPolicy' }, expected: { op: 'getPolicy' } },
        { name: 'inject-json', payload: { op: 'inject', pid: 5151, method: 'load-library', technique: 'remote-thread' }, expected: { op: 'inject', pid: 5151, method: 'load-library', technique: 'remote-thread' } },
        { name: 'method-policy-json', payload: { op: 'methodPolicy', pid: 5151 }, expected: { op: 'methodPolicy', pid: 5151 } },
        { name: 'lockdown-json', payload: { op: 'lockdownBypass', action: 'apply-harness' }, expected: { op: 'lockdownBypass', action: 'apply-harness' } },
        { name: 'ipc-list-targets-json', payload: { op: 'ipcBypass', action: 'list-targets' }, expected: { op: 'ipcBypass', action: 'list-targets' } }
    ];

    function buildControlRequest(op, options) {
        var canonicalOp = canonicalControlOp(op);
        if (canonicalOp == null) { throw new Error('Unsupported control op: ' + op); }

        var opKey = normalizeToken(canonicalOp);
        var input = options || {};
        var controlReq = { op: canonicalOp };

        if (input.pid != null) {
            var pid = parsePositiveInt(input.pid);
            if (pid == null) { throw new Error('Invalid pid'); }
            controlReq.pid = pid;
        }
        if (pidRequiredOps[opKey] === 1 && controlReq.pid == null) {
            throw new Error(canonicalOp + ' requires pid');
        }

        if (actionAllowedByOp[opKey] != null) {
            var actionValue = (input.action == null || String(input.action).trim().length === 0) ? 'status' : input.action;
            var canonicalAct = canonicalAction(canonicalOp, actionValue);
            if (canonicalAct == null) { throw new Error('Invalid action for ' + canonicalOp); }
            controlReq.action = canonicalAct;
        }

        if (input.method != null) { controlReq.method = String(input.method); }
        if (input.technique != null) { controlReq.technique = String(input.technique); }
        if (input.content != null) { controlReq.content = String(input.content); }
        if (input.config != null && controlReq.content == null) { controlReq.content = String(input.config); }
        if (input.policy != null) { controlReq.policy = String(input.policy); }
        if (input.setpolicy != null && controlReq.policy == null) { controlReq.policy = String(input.setpolicy); }

        if (input.flags != null) {
            if (typeof input.flags !== 'object' || input.flags == null || (input.flags instanceof Array)) {
                throw new Error('flags must be an object');
            }
            controlReq.flags = cloneValue(input.flags);
        }

        var headers = {};
        var hasHeaders = false;
        if (input.runId != null) { headers['x-umh-run-id'] = String(input.runId); hasHeaders = true; }
        if (input.targetTag != null) { headers['x-umh-target-tag'] = String(input.targetTag); hasHeaders = true; }
        if (input.methodKey != null) { headers['x-umh-method-key'] = String(input.methodKey); hasHeaders = true; }
        if (input.contractVersion != null) { headers['x-umh-contract-version'] = String(input.contractVersion); hasHeaders = true; }
        if (input.flowProfile != null) { headers['x-umh-flow-profile'] = String(input.flowProfile); hasHeaders = true; }
        if (input.client != null) { headers['x-umh-client'] = String(input.client); hasHeaders = true; }
        if (hasHeaders) { controlReq.headers = headers; }

        if (input.reason != null) { controlReq.reason = String(input.reason); }
        if (input.target != null) { controlReq.target = String(input.target); }
        if (input.domain != null) { controlReq.domain = String(input.domain); }
        if (input.exe != null) { controlReq.exe = String(input.exe); }

        var targetPids = parsePidList(input.targetPids || input.pids);
        if (targetPids.length > 0) { controlReq.target_pids = targetPids; }

        if (opKey === 'injecttargetset' && controlReq.target_pids == null && controlReq.pid != null) {
            controlReq.target_pids = [controlReq.pid];
            delete controlReq.pid;
        }
        if (opKey === 'setpolicy' && (typeof controlReq.policy !== 'string' || controlReq.policy.trim().length === 0)) { throw new Error('setPolicy requires policy'); }
        if (opKey === 'setconfig' && (typeof controlReq.content !== 'string' || controlReq.content.length === 0)) { throw new Error('setConfig requires content'); }
        if (opKey === 'ipcbypass' && controlReq.action !== 'list-targets') {
            if (typeof controlReq.target !== 'string' || controlReq.target.trim().length === 0) { throw new Error('ipcBypass requires target'); }
            if (typeof controlReq.domain !== 'string' || controlReq.domain.trim().length === 0) { throw new Error('ipcBypass requires domain'); }
        }

        return controlReq;
    }

    function buildConsoleCommand(operationId, options) {
        var op = operations[operationId];
        if (op == null) { throw new Error('Unknown operation id: ' + operationId); }

        var tokens = ['umhctl', op.command];
        if (op.serviceStatus === true) {
            tokens.push('--service');
            return tokens.join(' ');
        }

        var input = options || {};
        for (var i = 0; i < op.fields.length; ++i) {
            var field = op.fields[i];
            var value = input[field.name];
            if (value == null || value === false || value === '') { continue; }
            if (field.type === 'boolean') {
                if (value === true) { tokens.push(field.flag); }
                continue;
            }
            tokens.push(field.flag);
            tokens.push(toConsoleValue(field, value));
        }
        return tokens.join(' ');
    }

    function buildRawJson(operationId, options) {
        var op = operations[operationId];
        if (op == null || op.controlOp == null) { return null; }
        return buildControlRequest(op.controlOp, options);
    }

    function buildDispatchPlan(operationId, options) {
        var op = operations[operationId];
        if (op == null) { throw new Error('Unknown operation id: ' + operationId); }
        return {
            operationId: op.id,
            category: op.category,
            renderMode: op.renderMode,
            consoleCommand: buildConsoleCommand(op.id, options || {}),
            controlRequest: buildRawJson(op.id, options || {}),
            sampleResponse: cloneValue(op.sampleResponse)
        };
    }

    function getOperation(operationId) {
        var op = operations[operationId];
        return (op == null) ? null : cloneValue(op);
    }

    function listOperations() {
        var list = [];
        for (var i = 0; i < operationOrder.length; ++i) {
            list.push(getOperation(operationOrder[i]));
        }
        return list;
    }

    function getSurfaceLayout(surfaceId) {
        var layout = surfaceLayouts[surfaceId] || surfaceLayouts.desktop;
        return cloneValue(layout);
    }

    return {
        controlOpMap: cloneValue(controlOpMap),
        pidRequiredOps: cloneValue(pidRequiredOps),
        stateChangingOps: cloneValue(stateChangingOps),
        flowScopedOps: cloneValue(flowScopedOps),
        defaultFlowContract: cloneValue(defaultFlowContract),
        actionAllowedByOp: cloneValue(actionAllowedByOp),
        protectedScreenActions: cloneValue(protectedScreenActions),
        operations: cloneValue(operations),
        operationOrder: operationOrder.slice(0),
        surfaceLayouts: cloneValue(surfaceLayouts),
        helpFragments: helpFragments.slice(0),
        uiSnapshotSections: uiSnapshotSections.slice(0),
        consoleCases: cloneValue(consoleCases),
        rawJsonCases: cloneValue(rawJsonCases),
        normalizeToken: normalizeToken,
        canonicalControlOp: canonicalControlOp,
        canonicalAction: canonicalAction,
        buildControlRequest: buildControlRequest,
        buildConsoleCommand: buildConsoleCommand,
        buildRawJson: buildRawJson,
        buildDispatchPlan: buildDispatchPlan,
        getOperation: getOperation,
        getSurfaceLayout: getSurfaceLayout,
        listOperations: listOperations
    };
}));
