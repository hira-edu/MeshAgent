const fs = require('fs');
const path = require('path');
const contract = require('./lib/umh_operator_contract');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function renderPlan(operationId, input) {
    const plan = contract.buildDispatchPlan(operationId, input);
    return {
        operationId,
        consoleCommand: plan.consoleCommand,
        controlRequest: plan.controlRequest,
        renderMode: plan.renderMode
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const matrix = [];

    for (const surfaceId of ['desktop', 'mobile']) {
        const layout = contract.getSurfaceLayout(surfaceId);
        for (const group of layout.groups) {
            for (const operationId of group.operations) {
                const operation = contract.getOperation(operationId);
                matrix.push({
                    surface: surfaceId,
                    group: group.id,
                    operationId,
                    command: renderPlan(operationId, operation.sampleInput || {}).consoleCommand,
                    request: renderPlan(operationId, operation.sampleInput || {}).controlRequest,
                    renderMode: operation.renderMode
                });
            }
        }
    }

    const desktopInjectTargetSet = renderPlan('injectTargetSet', contract.getOperation('injectTargetSet').sampleInput);
    const mobileInjectTargetSet = renderPlan('injectTargetSet', contract.getOperation('injectTargetSet').sampleInput);
    const desktopHookControl = renderPlan('hookControl', contract.getOperation('hookControl').sampleInput);
    const mobileHookControl = renderPlan('hookControl', contract.getOperation('hookControl').sampleInput);

    const report = {
        generatedUtc: new Date().toISOString(),
        success: JSON.stringify(desktopInjectTargetSet) === JSON.stringify(mobileInjectTargetSet)
            && JSON.stringify(desktopHookControl) === JSON.stringify(mobileHookControl),
        matrixCount: matrix.length,
        desktopMobileParity: {
            injectTargetSet: JSON.stringify(desktopInjectTargetSet) === JSON.stringify(mobileInjectTargetSet),
            hookControl: JSON.stringify(desktopHookControl) === JSON.stringify(mobileHookControl)
        },
        matrix
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'umh_type4_matrix.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SUCCESS=${report.success}`,
            `MATRIX_COUNT=${report.matrixCount}`,
            `DESKTOP_MOBILE_PARITY_INJECTTARGETSET=${report.desktopMobileParity.injectTargetSet}`,
            `DESKTOP_MOBILE_PARITY_HOOKCONTROL=${report.desktopMobileParity.hookControl}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }

    if (!report.success) {
        process.exitCode = 1;
    }
}

main();
