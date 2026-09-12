"""Verify complete server transfers against the native Windows hash implementation."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-source', type=pathlib.Path, default=ROOT.parent / 'MeshCentral/meshagent.js')
    parser.add_argument('--console', type=pathlib.Path, default=ROOT / 'meshconsole/Release/MeshConsole64.exe')
    parser.add_argument('--package', action='append', required=True, type=pathlib.Path)
    parser.add_argument('--evidence', required=True, type=pathlib.Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    # Read the production trailer identity; it is data, not an enrollment policy.
    source = (ROOT / 'meshcore/agentcore.c').read_text()
    guid = bytes(int(x, 16) for x in re.search(r'char exeNullPolicyGuid\[\] = \{([^}]+)', source)[1].split(','))
    assert len(guid) == 16
    paths = []
    for index, package in enumerate(args.package):
        original = package.resolve()
        paths.append(original)
        appended = evidence / f'{index}-random-policy.exe'
        policy = b'0123456789abcdef0123456789abcdef01234567'
        appended.write_bytes(original.read_bytes() + policy + len(policy).to_bytes(4, 'big') + guid)
        paths.append(appended)
    script = 'var p=' + json.dumps([str(p) for p in paths]) + ';var r=[];'
    script += 'for(var i=0;i<p.length;i++){r.push({path:p[i],nativeSha384:getSHA384FileHash(p[i]).toString("hex").toLowerCase()});}console.log(JSON.stringify(r));process.exit(0);'
    result = subprocess.run([str(args.console.resolve()), '-exec', script], capture_output=True, text=True,
                            cwd=evidence, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    (evidence / 'native-stdout.txt').write_text(result.stdout)
    (evidence / 'native-stderr.txt').write_text(result.stderr)
    assert result.returncode == 0, 'Native hash process failed; see evidence'
    rows = json.loads(result.stdout)
    for index, row in enumerate(rows):
        row['name'] = f'{index}-{pathlib.Path(row["path"]).name}'
        row['rawSha384'] = hashlib.sha384(pathlib.Path(row['path']).read_bytes()).hexdigest()
        if index % 2:
            assert row['nativeSha384'] == rows[index - 1]['nativeSha384'], 'Native policy normalization changed'
            assert row['rawSha384'] != row['nativeSha384'], 'Fixture must expose whole-file versus native hash distinction'
    report = evidence / 'native-hashes.json'
    report.write_text(json.dumps(rows, indent=2))
    result = subprocess.run(['node', str(ROOT / 'test/meshcentral_native_update_transfer_runtime.js'),
                             str(args.server_source.resolve()), str(report)], capture_output=True, text=True, timeout=30)
    (evidence / 'transfer-results.json').write_text(result.stdout)
    (evidence / 'transfer-stderr.txt').write_text(result.stderr)
    print(result.stdout)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
