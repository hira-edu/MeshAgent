#!/usr/bin/env python3
"""Re-embed agent JavaScript modules into microscript/ILibDuktape_Polyfills.c.

Each named module is compressed from modules/<name>.js and replaces its existing
entry. It stays on one line while the statement fits MSVC's string literal limit
and uses the chunked form otherwise, matching modules/code-utils.js output.

The embedded date is the module's version. MeshCentral core overrides carry their
file's modification time, and an override dated later than the embedded copy
replaces it on agents, so a re-embedded module defaults to the current UTC time.

    python3 tools/embed_modules.py user-sessions service-manager
    python3 tools/embed_modules.py --date 2026-10-07T00:00:00.000Z clipboard
"""
import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import re
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
POLYFILLS = ROOT / 'microscript' / 'ILibDuktape_Polyfills.c'
MODULES = ROOT / 'modules'
MSVC_STRING_LITERAL_LIMIT = 16300
CHUNK = 16000
DATE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')


def encode(source):
    return base64.b64encode(zlib.compress(source, 6)).decode('ascii')


def render(name, payload, date):
    single = (f"\tduk_peval_string_noresult(ctx, \"addCompressedModule('{name}', "
              f"Buffer.from('{payload}', 'base64'), '{date}');\");")
    if len(single.strip()) <= MSVC_STRING_LITERAL_LIMIT:
        return [single]
    var = '_' + name.replace('-', '')
    lines = [f'\tchar *{var} = ILibMemory_Allocate({len(payload) + 1}, 0, NULL, NULL);']
    for offset in range(0, len(payload), CHUNK):
        chunk = payload[offset:offset + CHUNK]
        lines.append(f'\tmemcpy_s({var} + {offset}, {len(payload) - offset}, "{chunk}", {len(chunk)});')
    lines.append(f'\t{var}[{len(payload)}] = 0;')
    lines.append(f'\tILibDuktape_AddCompressedModuleEx(ctx, "{name}", {var}, "{date}");')
    lines.append(f'\tfree({var});')
    return lines


def locate(lines, name):
    """Return the [start, end) line range of the module's single existing entry."""
    single = [i for i, line in enumerate(lines) if f"addCompressedModule('{name}', Buffer.from(" in line]
    chunked = [i for i, line in enumerate(lines) if f'ILibDuktape_AddCompressedModuleEx(ctx, "{name}", ' in line]
    if len(single) + len(chunked) != 1:
        raise ValueError(f'{name}: expected exactly one embedded entry, found {len(single) + len(chunked)}')
    if single:
        return single[0], single[0] + 1
    add = chunked[0]
    var = re.search(r'ILibDuktape_AddCompressedModuleEx\(ctx, "[^"]+", (_\w+)', lines[add]).group(1)
    start = add
    while start > 0 and not lines[start].lstrip().startswith(f'char *{var} = ILibMemory_Allocate('):
        start -= 1
    end = add + 1
    if not lines[start].lstrip().startswith(f'char *{var} = ') or lines[end].strip() != f'free({var});':
        raise ValueError(f'{name}: chunked entry for {var} is not in the expected layout')
    return start, end + 1


def embed(polyfills_text, sources, date):
    """Return polyfills_text with each name in sources (name -> bytes) re-embedded."""
    lines = polyfills_text.split('\n')
    for name, source in sources.items():
        start, end = locate(lines, name)
        lines[start:end] = render(name, encode(source), date)
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('modules', nargs='+', help='module names, as in modules/<name>.js')
    parser.add_argument('--date', help='embedded version date (default: now, UTC)')
    args = parser.parse_args(argv)
    date = args.date or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    if not DATE.match(date):
        parser.error('--date must look like 2026-10-07T00:00:00.000Z')
    sources = {}
    for name in args.modules:
        path = MODULES / f'{name}.js'
        if not path.is_file():
            parser.error(f'missing module source: {path}')
        sources[name] = path.read_bytes()
    POLYFILLS.write_text(embed(POLYFILLS.read_text(encoding='utf-8'), sources, date), encoding='utf-8')
    for name in sources:
        print(f'embedded {name} ({date})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
