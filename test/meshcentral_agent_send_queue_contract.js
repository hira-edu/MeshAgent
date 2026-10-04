const fs = require('fs');
const path = require('path');

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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const multiplexPath = path.resolve('..', 'MeshCentral', 'meshdesktopmultiplex.js');
    const source = fs.readFileSync(multiplexPath, 'utf8');
    const sendToAgentStart = source.indexOf('    obj.sendToAgent = function (data) {');
    const sendToAgentEnd = sendToAgentStart >= 0 ? source.indexOf('    // Send more data to the agent', sendToAgentStart) : -1;
    const sendToAgentBlock = sendToAgentStart >= 0 && sendToAgentEnd > sendToAgentStart ? source.slice(sendToAgentStart, sendToAgentEnd) : '';

    const checks = {
        sendToAgentLocated: sendToAgentBlock.length > 0,
        queueBacklogUsesLength: sendToAgentBlock.includes('if (obj.agent.sendQueue.length > 10) {'),
        // The completion callback is bound to the agent the data was sent to, so a stalled agent that was
        // replaced cannot advance (or stall) the replacement's queue when its late write callback fires.
        marksSendingBeforeSend: sendToAgentBlock.includes('const agent = obj.agent;') &&
            sendToAgentBlock.includes('agent.sending = true;') &&
            sendToAgentBlock.includes('agent.ws.send(data, function () { sendAgentNext(agent); });') &&
            sendToAgentBlock.indexOf('agent.sending = true;') < sendToAgentBlock.indexOf('agent.ws.send(data, function () { sendAgentNext(agent); });'),
        fixesAgentOutTrafficAccounting: source.includes('if (peer.agentOutTraffic) { outTraffc += peer.agentOutTraffic; }')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        multiplexPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_agent_send_queue_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `MULTIPLEX_PATH=${multiplexPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
