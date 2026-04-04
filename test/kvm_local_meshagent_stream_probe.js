var fs = require('fs');

function makePacket(type, payload)
{
    var body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || []);
    var packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    if (body.length > 0) { body.copy(packet, 4); }
    return packet;
}

function nowMs()
{
    return Date.now();
}

function readUInt16BEFromArray(data, offset)
{
    return (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
}

function normalizeChunk(chunk)
{
    var i;
    var output = [];

    if (chunk == null) { return output; }
    if (Buffer.isBuffer(chunk))
    {
        for (i = 0; i < chunk.length; ++i) { output.push(chunk[i] & 0xFF); }
        return output;
    }
    if (typeof chunk.length === 'number')
    {
        for (i = 0; i < chunk.length; ++i) { output.push(chunk[i] & 0xFF); }
        return output;
    }
    return output;
}

var report = {
    startedUtc: new Date().toISOString(),
    apiSource: null,
    hasKvm: null,
    streamAvailable: false,
    streamOpened: false,
    streamError: null,
    packets: 0,
    bytes: 0,
    packetTypes: {},
    firstPackets: [],
    gotScreen: false,
    gotPicture: false,
    gotDisplayInfo: false,
    gotInputLock: false,
    durationMs: 0
};

var startTime = nowMs();
var finished = false;

function finish(exitCode)
{
    if (finished) { return; }
    finished = true;
    report.durationMs = nowMs() - startTime;
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(exitCode);
}

function recordPacket(packet)
{
    var type = readUInt16BEFromArray(packet, 0);
    report.packets += 1;
    report.bytes += packet.length;
    report.packetTypes[type] = (report.packetTypes[type] || 0) + 1;
    if (report.firstPackets.length < 16)
    {
        report.firstPackets.push({
            type: type,
            size: packet.length
        });
    }
    if (type === 7) { report.gotScreen = true; }
    if (type === 3) { report.gotPicture = true; }
    if (type === 11) { report.gotDisplayInfo = true; }
    if (type === 87) { report.gotInputLock = true; }
}

try
{
    var desktopApiOwner = null;
    var desktopApiMethod = null;
    try
    {
        var meshAgent = require('MeshAgent');
        report.apiSource = 'MeshAgent';
        report.hasKvm = meshAgent.hasKVM;
        desktopApiOwner = meshAgent;
        desktopApiMethod = meshAgent.GetRemoteDesktopStream;
    }
    catch (meshAgentErr)
    {
        if (typeof startMeshAgent === 'function')
        {
            try
            {
                startMeshAgent();
                var startedMeshAgent = require('MeshAgent');
                report.apiSource = 'MeshAgent(started)';
                report.hasKvm = startedMeshAgent.hasKVM;
                desktopApiOwner = startedMeshAgent;
                desktopApiMethod = startedMeshAgent.GetRemoteDesktopStream;
            }
            catch (startErr)
            {
                report.streamError = 'startMeshAgent failed: ' + startErr;
            }
        }
        if (desktopApiMethod == null)
        {
            var meshDesktop = require('meshDesktop');
            report.apiSource = 'meshDesktop';
            report.hasKvm = 1;
            desktopApiOwner = meshDesktop;
            desktopApiMethod = meshDesktop.getRemoteDesktopStream;
        }
    }
    if (desktopApiOwner == null || typeof desktopApiMethod !== 'function')
    {
        report.streamError = 'GetRemoteDesktopStream unavailable';
        finish(2);
    }

    var stream = desktopApiMethod.call(desktopApiOwner);
    if (stream == null)
    {
        report.streamError = 'GetRemoteDesktopStream returned null';
        finish(3);
    }

    report.streamAvailable = true;
    report.streamOpened = true;

    var pending = [];
    stream.on('data', function (chunk)
    {
        var bytes = normalizeChunk(chunk);
        if (bytes.length === 0) { return; }
        pending = pending.concat(bytes);
        while (pending.length >= 4)
        {
            var packetLen = readUInt16BEFromArray(pending, 2);
            if (packetLen < 4 || packetLen > pending.length) { break; }
            var packet = pending.slice(0, packetLen);
            recordPacket(packet);
            pending = pending.slice(packetLen);
        }
    });
    stream.on('error', function (err)
    {
        if (report.streamError == null) { report.streamError = '' + err; }
    });
    stream.on('end', function ()
    {
        if (!finished)
        {
            if (!report.gotScreen && report.streamError == null) { report.streamError = 'stream ended before screen packet'; }
            finish(report.gotScreen ? 0 : 4);
        }
    });

    // Match the browser startup contract: compression, unpause, input-lock query, refresh.
    stream.write(makePacket(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));
    stream.write(makePacket(8, [0]));
    stream.write(makePacket(87, [2]));
    stream.write(makePacket(6, []));

    setTimeout(function ()
    {
        try { stream.end(); } catch (e) { }
    }, 4000);
    setTimeout(function ()
    {
        if (!report.gotScreen && report.streamError == null) { report.streamError = 'timed out waiting for screen packet'; }
        finish((report.gotScreen && report.gotPicture) ? 0 : 5);
    }, 7000);
}
catch (e)
{
    report.streamError = '' + e;
    finish(1);
}
