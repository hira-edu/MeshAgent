"""Checksum-verified portable installs of Node, MongoDB and the MongoDB Database Tools under the runtime root."""
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

from dup_common import (
    DOWNLOADS, TOOLS, DupError, log, sha256_file,
    MONGO_ZIP, MONGO_URL, MONGO_SHA_URL, MONGO_ZIP_SHA256, MONGO_HOME, MONGOD_EXE, MONGO_VERSION,
    MONGO_TOOLS_ZIP, MONGO_TOOLS_URL, MONGO_TOOLS_FEED_URL, MONGO_TOOLS_ZIP_SHA256, MONGO_TOOLS_HOME, MONGODUMP_EXE,
    MONGO_TOOLS_VERSION,
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


def published_node_sha256(runtime, shasums_text):
    for line in shasums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == runtime.zip:
            return parts[0].lower()
    raise DupError(f"{runtime.zip} is not listed in {runtime.shasums_url}")


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


def install_node(runtime):
    """One pinned portable Node (dup_common.NodeRuntime): SHASUMS256.txt from nodejs.org, the zip, both
    checked against the pin, then extracted under the runtime root."""
    shasums = fetch_text(runtime.shasums_url)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    (DOWNLOADS / f"SHASUMS256-node-v{runtime.version}.txt").write_bytes(shasums.encode("utf-8"))
    published = published_node_sha256(runtime, shasums)
    zip_path = download(runtime.url, DOWNLOADS / runtime.zip)
    digest = verify(zip_path, published, runtime.zip_sha256)
    if runtime.exe.is_file():
        log(f"  node {runtime.version} already extracted at {runtime.home}")
    else:
        extract_zip(zip_path, runtime.home.name, TOOLS)
    if not runtime.exe.is_file():
        raise DupError(f"node.exe missing after extraction: {runtime.exe}")
    return {"name": "node", "version": runtime.version, "zip": runtime.zip, "sha256": digest,
            "checksum_source": runtime.shasums_url, "home": str(runtime.home)}


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


def published_mongo_tools_sha256(feed_text):
    """The sha256 MongoDB publishes for the pinned Database Tools zip in its release feed."""
    feed = json.loads(feed_text)
    for version in feed.get("versions", []):
        for download in version.get("downloads", []):
            archive = download.get("archive") or {}
            if archive.get("url") == MONGO_TOOLS_URL:
                if version.get("version") != MONGO_TOOLS_VERSION or not archive.get("sha256"):
                    raise DupError(f"{MONGO_TOOLS_FEED_URL} lists {MONGO_TOOLS_URL} without a sha256 for {MONGO_TOOLS_VERSION}")
                return archive["sha256"].lower()
    raise DupError(f"{MONGO_TOOLS_ZIP} is not listed in {MONGO_TOOLS_FEED_URL}")


def install_mongo_tools():
    """mongodump for MeshCentral's autobackup (production runs it from PATH; the duplicate names it in
    autobackup.mongodumppath because it changes no PATH)."""
    feed = fetch_text(MONGO_TOOLS_FEED_URL)
    published = published_mongo_tools_sha256(feed)
    zip_path = download(MONGO_TOOLS_URL, DOWNLOADS / MONGO_TOOLS_ZIP)
    digest = verify(zip_path, published, MONGO_TOOLS_ZIP_SHA256)
    if MONGODUMP_EXE.is_file():
        log(f"  mongodump already extracted at {MONGO_TOOLS_HOME}")
    else:
        extract_zip(zip_path, MONGO_TOOLS_HOME.name, TOOLS)
    if not MONGODUMP_EXE.is_file():
        raise DupError(f"mongodump.exe missing after extraction: {MONGODUMP_EXE}")
    return {"name": "mongodb-database-tools", "version": MONGO_TOOLS_VERSION, "zip": MONGO_TOOLS_ZIP, "sha256": digest,
            "checksum_source": MONGO_TOOLS_FEED_URL, "home": str(MONGO_TOOLS_HOME)}
