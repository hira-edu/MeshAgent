#!/usr/bin/env python3
"""Round-trip tools/embed_modules.py on a disposable copy of the tree.

Re-embeds a chunked module, a single-line module and a module that outgrows the
single-line form, then runs the embedded-module parity contract on the copy. The
repository's own ILibDuktape_Polyfills.c is not modified.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import embed_modules  # noqa: E402

DATE = '2099-01-02T03:04:05.000Z'

with tempfile.TemporaryDirectory(prefix='mesh-embed-') as directory:
    copy = Path(directory)
    (copy / 'microscript').mkdir()
    shutil.copytree(ROOT / 'modules', copy / 'modules')
    # Pseudo-random bytes do not compress, so this module must switch to the chunked form.
    grown = (b'// grown module\n' + b''.join(
        ('module.exports.v%d = "%s";\n' % (i, os.urandom(24).hex())).encode() for i in range(600)))
    (copy / 'modules' / 'win-registry.js').write_bytes(grown)
    original = (ROOT / 'microscript' / 'ILibDuktape_Polyfills.c').read_text(encoding='utf-8')
    sources = {name: (copy / 'modules' / f'{name}.js').read_bytes()
               for name in ('service-manager', 'user-sessions', 'win-registry')}
    updated = embed_modules.embed(original, sources, DATE)
    (copy / 'microscript' / 'ILibDuktape_Polyfills.c').write_text(updated, encoding='utf-8')

    # Re-embedding the same bytes and date again must not change anything.
    assert embed_modules.embed(updated, sources, DATE) == updated, 'embedding is not idempotent'
    assert 'ILibDuktape_AddCompressedModuleEx(ctx, "win-registry", _winregistry, "%s");' % DATE in updated
    removed = set(original.split('\n')) - set(updated.split('\n'))
    assert all(any(token in line for token in ("'service-manager'", '_servicemanager', "'user-sessions'", "'win-registry'"))
               for line in removed), 'lines outside the re-embedded entries changed'

    evidence = copy / 'evidence'
    result = subprocess.run(['node', str(ROOT / 'test' / 'embedded_module_source_parity_contract.js'),
                             '--root', str(copy), '--evidence', str(evidence)],
                            capture_output=True, text=True)
    report = json.loads((evidence / 'embedded_module_source_parity_contract.json').read_text())
    assert result.returncode == 0, result.stdout + result.stderr
    by_name = {module['name']: module for module in report['modules']}
    for name in sources:
        assert by_name[name]['matchesSource'] is True, name
        assert by_name[name]['timestamp'] == DATE, (name, by_name[name]['timestamp'])
    assert by_name['service-manager']['form'] == 'chunked'
    assert by_name['user-sessions']['form'] == 'single-line-compressed'
    assert by_name['win-registry']['form'] == 'chunked'

print('PASS: chunked, single-line and grown modules re-embedded with their date; parity contract passes; idempotent')
