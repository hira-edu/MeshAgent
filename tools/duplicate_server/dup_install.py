"""Checksum-verified portable installs of Node and MongoDB under the runtime root."""
import shutil
import subprocess
import zipfile
from pathlib import Path

from dup_common import (
    DOWNLOADS, TOOLS, DupError, log, sha256_file,
    NODE_ZIP, NODE_URL, NODE_SHASUMS_URL, NODE_ZIP_SHA256, NODE_HOME, NODE_EXE, NODE_VERSION,
    MONGO_ZIP, MONGO_URL, MONGO_SHA_URL, MONGO_ZIP_SHA256, MONGO_HOME, MONGOD_EXE, MONGO_VERSION,
)


CURL = Path(r"C:\Windows\System32\curl.exe")


def curl(args, timeout):
    """Windows' own curl: fails on HTTP errors, follows redirects, retries and resumes."""
    if not CURL.is_file():
        raise DupError(f"{CURL} not found")
    result = subprocess.run([str(CURL), "--fail", "--location", "--silent", "--show-error", "--retry", "5",
                             "--retry-all-errors", *args], capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise DupError(f"curl {args[-1]} failed ({result.returncode}): {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def fetch_text(url):
    return curl([url], timeout=120).decode("utf-8")


def download(url, target):
    """Download to <target>.part (resuming a partial file), then rename. The result is always verified."""
    target = Path(target)
    if target.is_file():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    log(f"  downloading {url}")
    curl(["--continue-at", "-", "--output", str(part), url], timeout=7200)
    part.replace(target)
    return target


def published_node_sha256(shasums_text):
    for line in shasums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == NODE_ZIP:
            return parts[0].lower()
    raise DupError(f"{NODE_ZIP} is not listed in {NODE_SHASUMS_URL}")


def published_mongo_sha256(sha_text):
    parts = sha_text.split()
    if len(parts) != 2 or parts[1] != MONGO_ZIP:
        raise DupError(f"Unexpected MongoDB checksum file format from {MONGO_SHA_URL}: {sha_text!r}")
    return parts[0].lower()


def verify(path, published, pinned):
    """The file must match both the publisher's checksum and the pin recorded here."""
    actual = sha256_file(path)
    if published != pinned:
        raise DupError(f"Published checksum for {Path(path).name} ({published}) differs from the pin ({pinned})")
    if actual != published:
        raise DupError(f"Checksum mismatch for {path}: got {actual}, expected {published}")
    return actual


def extract_zip(zip_path, expected_top, destination):
    """Extract a zip whose single top-level folder is expected_top into destination."""
    destination = Path(destination)
    final = destination / expected_top
    if final.exists():
        raise DupError(f"{final} already exists; run teardown or remove it first")
    staging = destination / (expected_top + ".extracting")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    with zipfile.ZipFile(zip_path) as archive:
        tops = set()
        for member in archive.namelist():
            resolved = (staging / member).resolve()
            if not resolved.is_relative_to(staging.resolve()):
                raise DupError(f"Unsafe path in {zip_path}: {member}")
            tops.add(member.replace("\\", "/").split("/", 1)[0])
        if tops != {expected_top}:
            raise DupError(f"{zip_path} top-level entries {sorted(tops)} != [{expected_top}]")
        archive.extractall(staging)
    (staging / expected_top).replace(final)
    staging.rmdir()
    return final


def install_node():
    shasums = fetch_text(NODE_SHASUMS_URL)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    (DOWNLOADS / f"SHASUMS256-node-v{NODE_VERSION}.txt").write_bytes(shasums.encode("utf-8"))
    published = published_node_sha256(shasums)
    zip_path = download(NODE_URL, DOWNLOADS / NODE_ZIP)
    digest = verify(zip_path, published, NODE_ZIP_SHA256)
    if NODE_EXE.is_file():
        log(f"  node already extracted at {NODE_HOME}")
    else:
        extract_zip(zip_path, NODE_HOME.name, TOOLS)
    if not NODE_EXE.is_file():
        raise DupError(f"node.exe missing after extraction: {NODE_EXE}")
    return {"name": "node", "version": NODE_VERSION, "zip": NODE_ZIP, "sha256": digest,
            "checksum_source": NODE_SHASUMS_URL, "home": str(NODE_HOME)}


def install_mongo():
    published = published_mongo_sha256(fetch_text(MONGO_SHA_URL))
    zip_path = download(MONGO_URL, DOWNLOADS / MONGO_ZIP)
    digest = verify(zip_path, published, MONGO_ZIP_SHA256)
    if MONGOD_EXE.is_file():
        log(f"  mongod already extracted at {MONGO_HOME}")
    else:
        extract_zip(zip_path, MONGO_HOME.name, TOOLS)
    if not MONGOD_EXE.is_file():
        raise DupError(f"mongod.exe missing after extraction: {MONGOD_EXE}")
    return {"name": "mongodb", "version": MONGO_VERSION, "zip": MONGO_ZIP, "sha256": digest,
            "checksum_source": MONGO_SHA_URL, "home": str(MONGO_HOME)}
