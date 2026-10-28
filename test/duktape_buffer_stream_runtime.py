#!/usr/bin/env python3
"""Run Buffer.from(buffer) and Duplex write-chunk checks in a built MeshAgent runtime.

CORE-25: Buffer.from(buffer) must copy the visible bytes (a slice copies only the
slice) instead of returning an empty buffer. CORE-48: a stream created with
decodeStrings: true hands _write a Buffer for every chunk, text included; streams
without it keep their existing chunk types.

Usage: duktape_buffer_stream_runtime.py [--console PATH]
The default is the x64 Release MeshConsole in this checkout.
"""
import argparse
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

SCRIPT = r'''
var failures = [];
function check(value, reason) { if (!value) { failures.push(reason); } }
function isBuf(value) { return (value instanceof Buffer) || (Buffer.isBuffer && Buffer.isBuffer(value)); }
function hex(value) { return value.toString('hex').toLowerCase(); }
try {
    var text = Buffer.from('hello world');
    var copy = Buffer.from(text);
    check(isBuf(copy) && copy.length == 11 && copy.toString() == 'hello world', 'Buffer.from(buffer) copies the bytes (got length ' + copy.length + ')');
    copy[0] = 0x48;
    check(text[0] == 0x68, 'Buffer.from(buffer) returns a copy, not a view of the source');
    var slice = Buffer.from(text.slice(6));
    check(slice.length == 5 && slice.toString() == 'world', 'Buffer.from(slice) copies only the slice');
    var binary = Buffer.alloc(6); binary[0] = 0; binary[1] = 255; binary[2] = 0x80; binary[3] = 0; binary[4] = 0x7f; binary[5] = 1;
    check(hex(Buffer.from(binary)) == '00ff80007f01', 'Buffer.from(buffer) keeps zero and high bytes');
    check(Buffer.from(Buffer.alloc(0)).length == 0, 'Buffer.from(empty buffer) is empty');
    check(Buffer.from('abc').toString() == 'abc' && hex(Buffer.from('6869', 'hex')) == '6869', 'string forms are unchanged');

    var Duplex = require('stream').Duplex;
    var decoded = [];
    var d1 = new Duplex({
        decodeStrings: true,
        write: function (chunk, flush) { decoded.push({ buffer: isBuf(chunk), held: Buffer.from(chunk) }); flush(); },
        final: function (done) { done(); },
        read: function () { }
    });
    d1.write('héllo');
    d1.write(Buffer.from('xyz'));
    check(decoded.length == 2, 'decodeStrings stream received both writes');
    check(decoded.length == 2 && decoded[0].buffer && decoded[1].buffer, 'decodeStrings stream receives Buffer chunks only');
    check(decoded.length == 2 && hex(decoded[0].held) == hex(Buffer.from('héllo', 'utf8')), 'decoded text chunk carries the UTF-8 bytes');
    check(decoded.length == 2 && decoded[1].held.toString() == 'xyz', 'a chunk copied with Buffer.from survives the write call');

    var legacy = [];
    var d2 = new Duplex({
        write: function (chunk, flush) { legacy.push(typeof chunk == 'string' ? 'string' : (isBuf(chunk) ? 'buffer' : typeof chunk)); flush(); },
        final: function (done) { done(); },
        read: function () { }
    });
    d2.write('abc');
    d2.write(Buffer.from('abc'));
    check(legacy.join(',') == 'string,buffer', 'streams without decodeStrings keep their chunk types (' + legacy.join(',') + ')');

    var w = require('stream').Writable;
    var writableChunks = [];
    var w1 = new w({ decodeStrings: true, write: function (chunk, flush) { writableChunks.push(isBuf(chunk) ? chunk.toString() : '!' + typeof chunk); flush(); }, final: function (done) { done(); } });
    w1.write('plain');
    check(writableChunks.join(',') == 'plain', 'decodeStrings Writable receives Buffer chunks (' + writableChunks.join(',') + ')');
} catch (e) {
    failures.push('exception: ' + e);
}
if (failures.length == 0) { console.log('PASS: Buffer.from(buffer) copies; decodeStrings streams receive Buffer chunks; other streams unchanged'); process.exit(0); }
console.log('FAIL: ' + failures.join(' | '));
process.exit(1);
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--console', type=pathlib.Path, default=ROOT / 'meshconsole/Release/MeshConsole64.exe')
    args = parser.parse_args()
    console = args.console.resolve()
    if not console.is_file():
        parser.error('MeshAgent console not found: %s (build meshconsole Release|x64 or pass --console)' % console)
    with tempfile.TemporaryDirectory(prefix='mesh-buffer-stream-') as folder:
        script = pathlib.Path(folder) / 'buffer_stream.js'
        script.write_text(SCRIPT, encoding='utf-8')
        try:
            result = subprocess.run([str(console), str(script)], cwd=folder, timeout=30,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except subprocess.TimeoutExpired as error:
            sys.exit('Runtime timed out; output: %r' % (error.output,))
    print(result.stdout, end='')
    if result.returncode != 0 or 'PASS:' not in result.stdout:
        sys.exit('Buffer/stream runtime checks failed (exit %d)' % result.returncode)


if __name__ == '__main__':
    main()
