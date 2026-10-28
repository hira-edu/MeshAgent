#!/usr/bin/env python3
"""Populate the pinned stock upstream MeshCentral package that tests compare the fork against.

Tests read it through meshcentral_paths.upstream_package_dir() (Python) or
upstreamPackageDir() (Node). They never download it; this tool is the only writer.

    python test/lib/fetch_upstream_reference.py              # download the pinned npm tarball
    python test/lib/fetch_upstream_reference.py --tarball F  # use a local copy of it instead
    python test/lib/fetch_upstream_reference.py --pin test/lib/meshcentral_production_reference.json
                                                             # the package production runs (duplicate layout A)

The tarball must match the sha512 integrity in meshcentral_upstream_reference.json, and the
extracted tree must match its treeDigest and fileCount, before anything replaces the cache.
The cache is <MeshAgent>/artifacts/meshcentral-upstream (git-ignored), or MESHCENTRAL_UPSTREAM_CACHE.
Only regular files and folders under package/ are accepted; links, devices, absolute or
escaping paths and duplicate entries fail the run.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import meshcentral_paths  # noqa: E402

MAX_TARBALL_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024


class FetchError(RuntimeError):
    pass


def integrity_of(path):
    digest = hashlib.sha512()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def download(url, target):
    if not url.startswith("https://"):
        raise FetchError(f"Refusing a non-HTTPS tarball URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "MeshAgent-fetch-upstream-reference"})
    total = 0
    with urllib.request.urlopen(request, timeout=120) as response, open(target, "wb") as out:
        if response.status != 200:
            raise FetchError(f"Download of {url} returned HTTP {response.status}")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TARBALL_BYTES:
                raise FetchError(f"Download of {url} exceeds {MAX_TARBALL_BYTES} bytes")
            out.write(chunk)
    return total


def safe_relative(name):
    """Map a tarball member name to a path relative to package/, or raise."""
    posix = PurePosixPath(name)
    if posix.is_absolute() or "\\" in name or ":" in name:
        raise FetchError(f"Tarball member has an unsafe name: {name!r}")
    parts = posix.parts
    if not parts or parts[0] != "package":
        raise FetchError(f"Tarball member is outside package/: {name!r}")
    rest = parts[1:]
    if any(part in ("", ".", "..") for part in rest):
        raise FetchError(f"Tarball member has an unsafe name: {name!r}")
    return PurePosixPath(*rest) if rest else None


def extract(tarball, destination):
    """Extract package/ into destination (which must not exist yet). Returns the file count."""
    destination.mkdir(parents=True)
    seen = set()
    written = 0
    count = 0
    with tarfile.open(tarball, mode="r:gz") as archive:
        for member in archive:
            rel = safe_relative(member.name)
            if member.isdir():
                if rel is not None:
                    (destination / rel).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise FetchError(f"Tarball member {member.name!r} is not a regular file or folder (type {member.type!r})")
            if rel is None:
                raise FetchError(f"Tarball member {member.name!r} is a file named package")
            key = rel.as_posix().lower()  # Windows folds case; a package must not rely on it.
            if key in seen:
                raise FetchError(f"Tarball has a duplicate entry: {member.name!r}")
            seen.add(key)
            written += member.size
            if written > MAX_TREE_BYTES:
                raise FetchError(f"Extracted tree exceeds {MAX_TREE_BYTES} bytes")
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise FetchError(f"Cannot read tarball member {member.name!r}")
            with source, open(target, "xb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
            count += 1
    return count


def populate(pin, tarball_arg, env=None, meshagent_root=None, pin_path=None):
    """Verify the cache, or fill it from the pinned tarball. Raises FetchError or MeshCentralPathError."""
    ref_dir = meshcentral_paths.reference_dir(pin, env, meshagent_root)
    cache_root = ref_dir.parent
    try:
        meshcentral_paths.upstream_package_dir(env, meshagent_root, pin_path)
        print(f"OK {pin['name']} {pin['version']} reference already present and verified: {ref_dir / 'package'}")
        return
    except meshcentral_paths.MeshCentralPathError as error:
        print(f"Populating: {error}")
    if ref_dir.exists() and not (ref_dir / meshcentral_paths.REFERENCE_MARKER).is_file() and any(ref_dir.iterdir()):
        raise FetchError(f"{ref_dir} exists, is not empty and has no {meshcentral_paths.REFERENCE_MARKER}, "
                         "so this tool did not make it. Move it away and run again.")
    cache_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".fetch-", dir=cache_root))
    try:
        if tarball_arg:
            tarball = Path(tarball_arg).resolve()
            if not tarball.is_file():
                raise FetchError(f"--tarball {tarball} is not a file")
            print(f"Using local tarball {tarball}")
        else:
            tarball = work / "upstream.tgz"
            size = download(pin["tarball"], tarball)
            print(f"Downloaded {pin['tarball']} ({size} bytes)")
        actual = integrity_of(tarball)
        if actual != pin["integrity"]:
            raise FetchError(f"Tarball integrity {actual} does not match the pinned {pin['integrity']}")
        print(f"Tarball integrity matches the pin: {actual}")
        staged = work / "reference"
        count = extract(tarball, staged / "package")
        digest, walked = meshcentral_paths.tree_digest(staged / "package")
        if walked != count:
            raise FetchError(f"Extracted {count} files but found {walked} on disk")
        if digest != pin["treeDigest"] or count != pin["fileCount"]:
            raise FetchError(f"Extracted tree {digest} with {count} files does not match the pinned "
                             f"{pin['treeDigest']} with {pin['fileCount']} files")
        marker = {field: pin[field] for field in ("name", "version", "tarball", "integrity", "treeDigest", "fileCount")}
        (staged / meshcentral_paths.REFERENCE_MARKER).write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")
        if ref_dir.exists():
            retired = work / "previous"
            os.replace(ref_dir, retired)
        os.replace(staged, ref_dir)
    finally:
        shutil.rmtree(work, ignore_errors=False)
    meshcentral_paths._VERIFIED_UPSTREAM.clear()
    package = meshcentral_paths.upstream_package_dir(env, meshagent_root, pin_path)
    print(f"OK {pin['name']} {pin['version']} reference verified ({pin['fileCount']} files, {pin['treeDigest']}): {package}")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tarball", help="local copy of the pinned npm tarball (verified against the pin)")
    parser.add_argument("--pin", help="pin file to fetch (default test/lib/meshcentral_upstream_reference.json)")
    parser.add_argument("--print-tree-digest", metavar="DIR",
                        help="print treeDigest and fileCount of an extracted package folder and exit (for updating the pin)")
    args = parser.parse_args(argv)
    if args.print_tree_digest:
        digest, count = meshcentral_paths.tree_digest(Path(args.print_tree_digest))
        print(json.dumps({"treeDigest": digest, "fileCount": count}))
        return 0
    try:
        pin = meshcentral_paths.load_reference_pin(args.pin)
        populate(pin, args.tarball, pin_path=args.pin)
    except (FetchError, OSError, tarfile.TarError, meshcentral_paths.MeshCentralPathError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
