/*
Copyright 2020 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
var EOCDR = 101010256;
var CDR = 33639248;
var LFR = 67324752;

var promise = require('promise');
var duplex = require('stream').Duplex;

function checkFolderPath(dest)
{
    if (process.platform == 'win32')
    {
        dest = dest.split('/').join('\\');
    }
    else
    {
        dest = dest.split('\\').join('/');
    }
    var tokens = dest.split(process.platform == 'win32' ? '\\' : '/');
    
    var base = tokens.shift();
    while(tokens.length > 1)
    {
        base += ((process.platform == 'win32' ? '\\' : '/') + tokens.shift());
        if(!require('fs').existsSync(base))
        {
            require('fs').mkdirSync(base);
        }
    }
}
function extractNext(p)
{
    if (p.pending.length == 0) { p.source.close(); p._res(); return; }
    var next = p.pending.pop();
    var dest = p.baseFolder + (process.platform == 'win32' ? '\\' : '/') + next;
    if (process.platform == 'win32')
    {
        dest = dest.split('/').join('\\');
    }
    else
    {
        dest = dest.split('\\').join('/');
    }
    console.info1('Extracting: ' + dest);
    try
    {
        checkFolderPath(dest);
    }
    catch(e)
    {
        p.source.close();
        p._rej(e);
        return;
    }

    p._stream = p.source.getStream(next);
    p._output = require('fs').createWriteStream(dest, { flags: 'wb' });
    p._output.name = next;
    p._output.promise = p;
    p._output.on('close', function ()
    {
        if (this.promise._stream.crc != this.promise.source.crc(this.name))
        {
            this.promise._rej('CRC Check failed');
            return;
        }
        extractNext(this.promise);
    });
    p._stream.pipe(p._output);
}

function zippedObject(table)
{
    this._ObjectID = 'zip-reader.zippedObject';
    this._table = table;
    for (var jx in table)
    {
        this._FD = table[jx].fd;
        break;
    }
    Object.defineProperty(this, 'files', {
        get: function ()
        {
            var ret = [];
            var i;
            for(i in this._table)
            {
                ret.push(this._table[i].name);
            }
            return (ret);
        }
    });
    this.crc = function crc(name)
    {
        return (this._table[name].crc);
    };
    this.size = function size(name)
    {
        return (this._table[name].uncompressedSize);
    };
    this.getStream = function getStream(name)
    {
        var info = this._table[name];
        if (!info) { throw ('not found'); }

        var ret;

        if (info.compression == 0)
        {
            console.info1('No Compression!');
            ret = new duplex(
            {
                write: function (chunk, flush)
                {
                    console.info1('Pass/Thru: ' + chunk.length + ' bytes');
                    this.crc = crc32(chunk, this.crc);
                    if(this._pushOK)
                    {
                        this._pushOK = this.push(chunk);
                        if (this._pushOK)
                        {
                            flush();
                            this._flush = null;
                        }
                        else
                        {
                            this._flush = flush;
                        }
                    }
                    else
                    {
                        this._pendingData.push(chunk);
                        this._flush = flush;
                    }
                },
                final: function (flush)
                {
                    if (this._pushOK)
                    {
                        this.push(null);
                        flush();
                    }
                    else
                    {
                        this._ended = true;
                    }
                },
                read: function (size)
                {
                    this._pushOK = true;
                    while (this._pendingData.length > 0 && (this._pushOK = this.push(this._pendingData.shift())));
                    if (this._pushOK)
                    {
                        if(this._flush)
                        {
                            this._flush(); 
                            this._flush = null;
                        }
                        else
                        {
                            this.emit('drain');
                        }
                    }
                    
                }
            });
            ret.bufferMode = 1;
            ret._pendingData = [];
            ret._pushOK = false;
            ret._ended = false;
            ret._flush = null;
            ret.crc = 0;
            ret.pause();
        }
        else
        {
            ret = require('compressed-stream').createDecompressor({ WBITS: -15 });
        }
        ret._info = info;
        ret._readSink = function _readSink(err, bytesRead, buffer)
        {
            console.info2('read ' + bytesRead + ' bytes [ERR: ' + err + ']', _readSink.self._bytesLeft);
            if ((err != null && err != 0) || (bytesRead <= 0 && _readSink.self._bytesLeft > 0))
            {
                _readSink.self.emit('error', err || 'Unexpected end of ZIP entry');
                return;
            }
            _readSink.self._bytesLeft -= bytesRead;
            _readSink.self.write(buffer.slice(0, bytesRead), function ()
            {
                // Done Writing, so read the next block
                if(this._bytesLeft == 0)
                {
                    console.info1('DONE Reading This record');
                    // No More Data
                    this.end();
                }
                else
                {
                    // More Data To Read
                    console.info2('Requesting More Data: ' + this._bytesLeft, this._ObjectID);
                    require('fs').read(this._info.fd, { buffer: this._buffer, length: this._bytesLeft > 4096 ? 4096 : this._bytesLeft },
                        this._readSink);
                }
            });
        };
        ret._readSink.self = ret;
        ret._localHeaderSink = function _localHeaderSink(err, bytesRead, buffer)
        {
            if ((err != null && err != 0) || bytesRead < 30 || buffer.readUInt32LE(0) != LFR)
            {
                _localHeaderSink.self.emit('error', err || 'Invalid ZIP local header');
                return;
            }
            console.info1(buffer.readUInt32LE(0) == LFR);
            console.info1('General Purpose Flag: ' + buffer.readUInt16LE(6));
            console.info1('Compression Method: ' + buffer.readUInt16LE(8));
            console.info1('FileName Length: ' + buffer.readUInt16LE(26));
            console.info1('Extra Length: ' + buffer.readUInt16LE(28));
            _localHeaderSink.self._info.uncompressedCRC = buffer.readUInt32LE(14);

            console.info1('Requesting to read: ' + (_localHeaderSink.self._bytesLeft > 4096 ? 4096 : _localHeaderSink.self._bytesLeft) + ' bytes');

            var dataPosition = _localHeaderSink.self._info.offset + 30 + buffer.readUInt16LE(26) + buffer.readUInt16LE(28);
            if (dataPosition + _localHeaderSink.self._info.compressedSize > _localHeaderSink.self._info.archiveLength)
            {
                _localHeaderSink.self.emit('error', 'ZIP entry extends beyond archive');
                return;
            }
            require('fs').read(_localHeaderSink.self._info.fd,
                {
                    buffer: _localHeaderSink.self._buffer,
                    length: _localHeaderSink.self._bytesLeft > 4096 ? 4096 : _localHeaderSink.self._bytesLeft,
                    position: dataPosition
                }, _localHeaderSink.self._readSink);
        };
        ret._localHeaderSink.self = ret;
        ret.once('drain', function ()
        {
            this._bytesLeft = this._info.compressedSize;
            this._buffer = Buffer.alloc(4096);
            console.info1('Local Header @ ' + this._info.offset);
            console.info1(' -> Compressed Size = ' + this._bytesLeft);
            require('fs').read(this._info.fd, { buffer: Buffer.alloc(30), position: this._info.offset }, this._localHeaderSink);
        });
        return (ret);
    };
    this.extractAll = function extractAll(destFolder)
    {
        if (process.platform == 'win32')
        {
            if (!destFolder.includes(':\\')) { destFolder = process.cwd() + destFolder; }
        }
        else
        {
            if (!destFolder.startsWith('/')) { destFolder = process.cwd() + destFolder; }
        }

        var i;
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        if (destFolder.endsWith(process.platform == 'win32' ? '\\' : '/')) { destFolder = destFolder.substring(0, destFolder.length - 1); }
        ret.source = this;
        ret.baseFolder = destFolder;
        ret.pending = [];
        for (i in this.files)
        {
            ret.pending.push(this.files[i]);
        }

        extractNext(ret);
        return (ret);
    };
    this._extractAllStreams2 = function _extractAllStreams2(prom)
    {
        if (prom.files.length == 0)
        {
            // finished
            prom._res(prom.results);
            this.close();
            return;
        }
        prom.results.push({ name: prom.files.pop() });
        prom.results.peek().stream = this.getStream(prom.results.peek().name);
        prom.results.peek().stream.ret = prom;
        prom.results.peek().stream.on('data', function (c)
        {
            console.info2('DATA: ' + c.length);
            if (this._buf == null)
            {
                this._buf = Buffer.concat([c]);
            }
            else
            {
                this._buf = Buffer.concat([this._buf, c]);
            }
        });
        prom.results.peek().stream.on('end', function ()
        {
            console.info2('End of current stream');
            this.ret.results.peek().buffer = this._buf;
            this.ret.z._extractAllStreams2(this.ret);
        });
    };
    this.extractAllStreams = function extractAllStreams()
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.files = this.files;
        ret.results = [];
        ret.z = this;
        this._extractAllStreams2(ret);
        return (ret);
    };
    this._readLocalHeaderSink = function _readLocalHeaderSink(err, bytesRead, buffer)
    {
        var info = _readLocalHeaderSink.info;

        console.info1('Local File Record -> ');
        var filenameLength = buffer.readUInt32LE(26);
        console.info1('   General Purpose Flag: ' + buffer.readUInt16LE(6));
        console.info1('   CRC-32 of uncompressed data: ' + buffer.readUInt32LE(14));
        console.info1('   Compression Method: ' + buffer.readUInt16LE(8));
        console.info1('   Compressed Size: ' + buffer.readUInt32LE(18));
        console.info1('   Uncompressed Size: ' + buffer.readUInt32LE(22));
        console.info1('   Last Modification Time: ' + buffer.readUInt16LE(10));
        console.info1('   Last Modification Date: ' + buffer.readUInt16LE(12));
        console.info1('   Extra Field Length: ' + buffer.readUInt16LE(28));
        require('fs').read(info.fd, { buffer: Buffer.alloc(filenameLength) }, function (e, b, f)
        {
            console.info1('   File Name: ' + f.toString());
            require('fs').read(info.fd, { buffer: Buffer.alloc(10) }, function (e2, b2, f2)
            {
                console.info1('   Compressed Data Sample: ' + f2.toString('hex'));
            });
        });
    };
    this._readLocalHeaderSink.self = this;
    this.readLocalHeader = function readLocalHeader(name)
    {
        var info = this._table[name];
        this._readLocalHeaderSink.info = info;
        require('fs').read(info.fd, { buffer: Buffer.alloc(30), position: info.offset }, this._readLocalHeaderSink);
    };

    this.close = function close()
    {
        if (this._FD != null)
        {
            require('fs').closeSync(this._FD);
            this._FD = null;
            this._table = null;
        }
    }
    require('events').EventEmitter.call(this);
    this.on('~', function () { this.close(); });
}

function read(path)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (typeof (path) == 'string')
    {
        if (!require('fs').existsSync(path))
        {
            ret._rej('File not found');
            return (ret);
        }

        ret._len = require('fs').statSync(path).size;
        ret._fd = require('fs').openSync(path, require('fs').constants.O_RDONLY);
    }
    else
    {
        ret._len = path.length;
        ret._fd = { _ObjectID: 'fs.bufferDescriptor', buffer: path, position: 0 };
    }
    ret._settled = false;
    ret._fail = function _fail(reason)
    {
        if (this._settled) { return; }
        this._settled = true;
        if (typeof this._fd == 'number') { try { require('fs').closeSync(this._fd); } catch (ignored) { } }
        this._rej(reason);
    };
    ret._cdr = function _cdr(err, bytesRead, buffer)
    {
        var table = {};
        if ((err != null && err != 0) || bytesRead != buffer.length)
        {
            _cdr.self._fail(err || 'Unexpected end of ZIP central directory');
            return;
        }
        buffer = buffer.slice(0, bytesRead);
        while (buffer.length > 0)
        {
            if (buffer.length < 46 || buffer.readUInt32LE() != CDR) { _cdr.self._fail('Parse Error'); return; }
            var nameLength = buffer.readUInt16LE(28);
            var efLength = buffer.readUInt16LE(30);
            var comLength = buffer.readUInt16LE(32);
            var recordLength = 46 + nameLength + efLength + comLength;
            if (recordLength > buffer.length) { _cdr.self._fail('Truncated ZIP central directory record'); return; }
            var name = buffer.slice(46, 46 + nameLength).toString();
            var namebuf = buffer.slice(46, 46 + nameLength);
            var efs = (buffer.readUInt16LE(8) & 2048) == 2048;

            console.info1('Central Directory Record:');
            console.info1('   Version: ' + buffer.readUInt16LE(4));
            console.info1('   Minimum: ' + buffer.readUInt16LE(6));
            console.info1('   General Purpose Flags: ' + buffer.readUInt16LE(8));
            console.info1('   EFS: ' + efs);
            console.info1('   Name: ' + name);
            console.info1('   CRC-32 of Uncompressed data: ' + buffer.readUInt32LE(16));
            console.info1('   Uncompressed Size: ' + buffer.readUInt32LE(24));
            console.info1('   Compressed Size: ' + buffer.readUInt32LE(20));
            console.info1('   File Last Modification Time: ' + buffer.readUInt16LE(12));
            console.info1('   File Last Modification Date: ' + buffer.readUInt16LE(14));
            console.info1('   Internal Attributes: ' + buffer.readUInt16LE(36));
            console.info1('   External Attributes: ' + buffer.readUInt32LE(38));
            console.info1('   Local Header at: ' + buffer.readUInt32LE(42));
            
            if (buffer.readUInt32LE(16) != 0)
            {
                table[name] =
                    {
                        name: name,
                        compressedSize: buffer.readUInt32LE(20),
                        uncompressedSize: buffer.readUInt32LE(24),
                        offset: buffer.readUInt32LE(42),
                        fd: _cdr.self._fd,
                        archiveLength: _cdr.self._len,
                        compression: buffer.readUInt16LE(10),
                        crc: buffer.readUInt32LE(16)
                    };
            }
            buffer = buffer.slice(recordLength);
        }

        _cdr.self._settled = true;
        _cdr.self._res(new zippedObject(table));
    };
    ret._eocdr = function _eocdr(err, bytesRead, buffer)
    {
        var record;
        var i;
        if ((err != null && err != 0) || bytesRead < 22)
        {
            _eocdr.self._fail(err || 'ZIP end-of-central-directory record is missing');
            return;
        }
        buffer = buffer.slice(0, bytesRead);

        for (i = buffer.length - 22; i >= 0; --i)
        {
            if ((record = buffer.slice(i)).readUInt32LE() == EOCDR)
            {
                if ((22 + record.readUInt16LE(20)) > record.length) { continue; }
                console.info1('Found Start of ECD Record ' + (buffer.length - i) + ' bytes from end of file');
                console.info1('-------------------------');
                console.info1('  Disk #: ' + record.readUInt16LE(4));
                console.info1('  Number of Central Directory Records on this disc: ' + record.readUInt16LE(8));
                console.info1('  Total number of Central Directory Records: ' + record.readUInt16LE(10));
                console.info1('  Size of Central Directory: ' + record.readUInt32LE(12) + ' bytes');
                console.info1('  Central Directory Records should be at offset: ' + record.readUInt32LE(16));

                var centralDirectorySize = record.readUInt32LE(12);
                var centralDirectoryOffset = record.readUInt32LE(16);
                if (centralDirectorySize == 0 || centralDirectoryOffset + centralDirectorySize > _eocdr.self._len)
                {
                    _eocdr.self._fail('Invalid ZIP central directory bounds');
                    return;
                }
                require('fs').read(_eocdr.self._fd, { buffer: Buffer.alloc(centralDirectorySize), position: centralDirectoryOffset }, _eocdr.self._cdr);
                return;
            }
        }
        _eocdr.self._fail('ZIP end-of-central-directory record is missing');
    };
    ret._cdr.self = ret;
    ret._eocdr.self = ret;
    var tailLength = ret._len > 65557 ? 65557 : ret._len;
    require('fs').read(ret._fd, { buffer: Buffer.alloc(tailLength), position: ret._len - tailLength }, ret._eocdr);
    return(ret);
}

function isZip(path)
{
    if (require('fs').statSync(path).size < 30) { return (false); }
    var fd = require('fs').openSync(path, 'rb');
    var jsFile = Buffer.alloc(4);
    var bytesRead = require('fs').readSync(fd, jsFile, { position: 0 });
    require('fs').closeSync(fd);

    if (bytesRead == 4 && jsFile[0] == 0x50 && jsFile[1] == 0x4B && jsFile[2] == 0x03 && jsFile[3] == 0x04)
    {
        return (true);
    }
    return (false);
}

module.exports = { read: read, isZip: isZip };
