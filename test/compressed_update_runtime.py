"""Exercise native update extraction and streaming output boundaries without installing."""
import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


class StreamingZip(io.BytesIO):
    def seekable(self):
        return False

    def seek(self, *args):
        raise io.UnsupportedOperation("streaming ZIP")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", type=pathlib.Path, default=ROOT / "meshconsole/Release/MeshConsole64.exe")
    parser.add_argument("--zip", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    cases = []
    for size in [16383, 16384, 16385, 32768, 1048576]:
        content = b"A" * size
        for streaming in [False, True]:
            buffer = StreamingZip() if streaming else io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("meshagent", content)
            cases.append((str(size) + ("-descriptor" if streaming else "-header"), buffer.getvalue(), content))
    for index, path in enumerate(args.zip):
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) != 1:
                raise ValueError("Expected one update entry")
            content = archive.read(archive.infolist()[0])
        cases.append(("captured-" + str(index), path.read_bytes(), content))
    rows = []
    for label, data, expected in cases:
        package = evidence / (label + ".pkg")
        package.write_bytes(data)
        code = "require('update-helper').start(" + json.dumps(str(package)) + ").then(function(){console.log('complete');process.exit(0);},function(e){console.log('failed:'+e);process.exit(1);});"
        code += "setTimeout(function(){console.log('timeout');process.exit(2);},2000);"
        result = subprocess.run([str(args.console.resolve()), "-exec", code], cwd=evidence, capture_output=True,
                                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        (evidence / (label + ".stdout.txt")).write_bytes(result.stdout)
        (evidence / (label + ".stderr.txt")).write_bytes(result.stderr)
        actual = package.read_bytes()
        ok = result.returncode == 0 and actual == expected and not package.with_name(package.name + "_unzipped").exists()
        rows.append({"case": label, "exitCode": result.returncode, "expectedBytes": len(expected), "actualBytes": len(actual),
                     "expectedSha256": hashlib.sha256(expected).hexdigest(), "actualSha256": hashlib.sha256(actual).hexdigest(), "ok": ok})
        print(("PASS " if ok else "FAIL ") + label)
    # Force repeated pauses while one compressed input chunk still has output.
    # This exercises resume-buffer ownership and the no-buffer resume branch.
    content = b"resume-buffer ownership\n" * 50000
    package = evidence / "backpressure.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("meshagent", content)
    output = evidence / "backpressure.out"
    code = "var fs=require('fs'),parts=[];require('zip-reader').read(" + json.dumps(str(package)) + ").then(function(z){"
    code += "var s=z.getStream(z.files[0]);s.on('end',function(){fs.writeFileSync(" + json.dumps(str(output)) + ",Buffer.concat(parts));z.close();console.log('complete');process.exit(0);});"
    code += "s.on('data',function(c){var b=Buffer.alloc(c.length);c.copy(b);parts.push(b);s.pause();setImmediate(function(){s.resume();});});});"
    code += "setTimeout(function(){console.log('timeout');process.exit(2);},5000);"
    result = subprocess.run([str(args.console.resolve()), "-exec", code], cwd=evidence, capture_output=True,
                            timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    (evidence / "backpressure.stdout.txt").write_bytes(result.stdout)
    (evidence / "backpressure.stderr.txt").write_bytes(result.stderr)
    ok = result.returncode == 0 and output.exists() and output.read_bytes() == content
    rows.append({"case": "backpressure", "exitCode": result.returncode, "ok": ok})
    print(("PASS " if ok else "FAIL ") + "backpressure")
    report = {"ok": all(row["ok"] for row in rows), "installerExecuted": False, "rows": rows}
    (evidence / "results.json").write_text(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
