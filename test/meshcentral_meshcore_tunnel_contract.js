// Static contract for the agent core tunnel handlers in ../MeshCentral/agents/meshcore.js.
// Pins fixes that have no runtime harness on the server side: the consent-accepted desktop toast
// must target the viewer's session, and the forced guest disconnect log must not throw.
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const corePath = path.resolve(process.argv[2] || path.join(__dirname, '..', '..', 'MeshCentral', 'agents', 'meshcore.js'));
const source = fs.readFileSync(corePath, 'utf8');

function count(text) { return source.split(text).length - 1; }

const checks = {
    // kvm_consentpromise_resolved runs with `this.ws`, there is no `tsid` in scope. A bare `tsid` is a
    // ReferenceError swallowed by the try/catch, so the toast after an accepted consent was never shown.
    consentAcceptedToastUsesViewerSession: count("require('toaster').Toast(notifyTitle, notifyMessage, this.ws.tsid)") === 1,
    consentAcceptedToastHasNoBareTsid: count("Toast(notifyTitle, notifyMessage, tsid)") === 0,
    // The endtunnel handler logs the guest name from the server command, not an undefined global.
    endTunnelGuestNameComesFromCommand: count("if (data.guestname != null) { xusername += '/' + data.guestname; }") === 1,
    endTunnelHasNoBareGuestName: count("xusername += '/' + guestname;") === 0,
    // Relay tunnel errors carry the error object into the console message.
    tunnelErrorHandlerReceivesError: count('function tunnel_onError(e)') === 1
};

const failed = Object.keys(checks).filter(k => checks[k] !== true);
console.log(JSON.stringify({ corePath, checks, failed }, null, 2));
assert.strictEqual(failed.length, 0, 'meshcore tunnel contract failed: ' + failed.join(', '));
