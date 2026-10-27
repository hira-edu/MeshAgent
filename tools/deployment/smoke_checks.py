"""Release smoke assertions shared by the image smoke test and duplicate-server runs (T22).

A release passes only when the running server proves it is the reviewed fork build:

- the image-size mitigation preload ran (its log marker is present);
- the served MeshCentral version equals the manifest's reviewed version;
- the installed package carries the manifest's forkRevision;
- every agent core the manifest lists is served with the manifest's SHA-384;
- for every agent binary the manifest lists, the file MeshCentral selects on disk is the manifest's
  path with the manifest's sha256. The file on disk is compared, never /meshagents?id= output,
  which for Windows agents carries a policy block that changes at every start.

Manifest fields used (all required here; release_manager accepts manifests without them):

    "forkRevision": "<40-hex git sha>",
    "reviewedUpstreamVersion": "1.2.5",
    "agentCoreHashes": {"windows-amd64": "<sha384 hex of the served core>", ...},
    "agentBinaries": {"4": {"localname": "MeshService64.exe", "unsigned": true,
                            "path": "node_modules/meshcentral/agents/MeshService64.exe",
                            "sha256": "<hex>"}, ...}

Agent binary paths are relative to the install root (/opt/meshcentral in the image).
"""
from html.parser import HTMLParser
import http.cookiejar
import json
from pathlib import PurePosixPath
import re
import urllib.error
import urllib.parse
import urllib.request

HARDEN_MARKER = 'harden-image-size: disabled unpatched parsers: icns, jxl, jxl-stream, heif'
# A ~showversion redirect the smoke configuration defines (webserver.js handleDomainRedirect).
VERSION_PATH = 'release-smoke-version'
PACKAGE_DIR = 'node_modules/meshcentral'
DATA_DIR = 'meshcentral-data'
SHA256 = re.compile(r'[0-9a-f]{64}')
SHA384 = re.compile(r'[0-9a-f]{96}')


class SmokeFailure(RuntimeError):
    """One or more smoke assertions failed; the message lists each of them."""


def expectations(manifest):
    """Validate and return the identity the release must prove: version, revision, cores, agents."""
    problems = []
    version = manifest.get('meshcentral_version')
    reviewed = manifest.get('reviewedUpstreamVersion', version)
    if not isinstance(version, str) or reviewed != version:
        problems.append('manifest reviewedUpstreamVersion ' + repr(reviewed) + ' does not match meshcentral_version ' +
                        repr(version))
    revision = manifest.get('forkRevision')
    if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision):
        problems.append('manifest forkRevision is missing or not a full git sha; images built before the fork '
                        'cannot pass the fork smoke test')
    cores = manifest.get('agentCoreHashes')
    if not isinstance(cores, dict) or not cores or not all(
            isinstance(name, str) and isinstance(digest, str) and SHA384.fullmatch(digest)
            for name, digest in cores.items()):
        problems.append('manifest agentCoreHashes must map each served core name to its lowercase SHA-384')
    agents = manifest.get('agentBinaries')
    if not isinstance(agents, dict) or not agents:
        problems.append('manifest agentBinaries must list the agent binaries the server selects')
        agents = {}
    for archid, entry in agents.items():
        valid = (archid.isdigit() and isinstance(entry, dict) and
                 set(entry) == {'localname', 'unsigned', 'path', 'sha256'} and
                 isinstance(entry['localname'], str) and '/' not in entry['localname'] and
                 isinstance(entry['unsigned'], bool) and isinstance(entry['path'], str) and
                 isinstance(entry['sha256'], str) and SHA256.fullmatch(entry['sha256']))
        if valid:
            path = PurePosixPath(entry['path'])
            valid = not path.is_absolute() and '..' not in path.parts and path.name == entry['localname']
        if not valid:
            problems.append('manifest agentBinaries[' + repr(archid) + '] needs localname, unsigned, a relative '
                            'path ending in localname, and a lowercase sha256')
    if problems:
        raise SmokeFailure('Release manifest cannot be smoke tested:\n  ' + '\n  '.join(problems))
    return {'version': version, 'forkRevision': revision, 'cores': cores, 'agents': agents}


def selected_agent_path(entry, exists):
    """The file MeshCentral serves for one architecture of the default domain.

    Mirrors meshcentral.js 1.2.5:3620-3629: the package agents folder, replaced by
    meshcentral-data/signedagents and then meshcentral-data/agents when present, unless the
    architecture is marked unsigned. ``exists`` answers for a path relative to the install root.
    """
    name = entry['localname']
    path = PACKAGE_DIR + '/agents/' + name
    if not entry['unsigned']:
        for candidate in (DATA_DIR + '/signedagents/' + name, DATA_DIR + '/agents/' + name):
            if exists(candidate):
                path = candidate
    return path


def check_preload(log_text):
    if HARDEN_MARKER not in log_text:
        return ['image-size mitigation preload did not run: the server log lacks "' + HARDEN_MARKER + '"']
    return []


def check_served_version(body, expected):
    actual = body.strip()
    if actual != 'MeshCentral v' + expected['version']:
        return ['served version ' + repr(actual) + ' is not MeshCentral v' + expected['version']]
    return []


def check_fork_revision(package_json, expected):
    try:
        revision = json.loads(package_json).get('forkRevision')
    except ValueError as error:
        return ['installed package.json is not valid JSON: ' + str(error)]
    if revision != expected['forkRevision']:
        return ['installed package forkRevision ' + repr(revision) + ' is not the manifest ' +
                expected['forkRevision']]
    return []


class _CoreTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = [], None, None

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self.row = []
        elif tag == 'td' and self.row is not None:
            self.cell = ''

    def handle_endtag(self, tag):
        if tag == 'td' and self.cell is not None:
            self.row.append(self.cell.strip())
            self.cell = None
        elif tag == 'tr' and self.row is not None:
            if self.row:
                self.rows.append(self.row)
            self.row = None

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data


def parse_core_hashes(html):
    """Parse /meshagents?cores=1 (webserver.js 1.2.5:6548-6556) into {core name: sha384 hex}."""
    table = _CoreTable()
    table.feed(html)
    cores = {}
    for row in table.rows:
        if len(row) != 4 or not SHA384.fullmatch(row[3]):
            raise SmokeFailure('Unexpected agent core table row: ' + repr(row))
        cores[row[0].replace('\xa0', ' ')] = row[3]
    if not cores:
        raise SmokeFailure('The server listed no agent cores')
    return cores


def check_core_hashes(served, expected):
    problems = []
    for name, digest in sorted(expected['cores'].items()):
        if name not in served:
            problems.append('agent core ' + repr(name) + ' is not served')
        elif served[name] != digest:
            problems.append('agent core ' + repr(name) + ' is served with SHA-384 ' + served[name] +
                            ', manifest expects ' + digest)
    return problems


def check_agent_binaries(expected, exists, sha256):
    """``exists`` and ``sha256`` read a path relative to the install root on the server's disk."""
    problems = []
    for archid, entry in sorted(expected['agents'].items(), key=lambda item: int(item[0])):
        selected = selected_agent_path(entry, exists)
        if selected != entry['path']:
            problems.append('agent ' + archid + ': MeshCentral selects ' + selected + ', manifest expects ' +
                            entry['path'])
        elif not exists(selected):
            problems.append('agent ' + archid + ': ' + selected + ' does not exist, so it is not served')
        else:
            actual = sha256(selected)
            if actual != entry['sha256']:
                problems.append('agent ' + archid + ': ' + selected + ' has sha256 ' + actual +
                                ', manifest expects ' + entry['sha256'])
    return problems


class Server:
    """HTTP access to a running MeshCentral (plain HTTP behind tlsoffload, as in the smoke config)."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/') + '/'
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, path, timeout=10):
        with self.opener.open(self.base_url + path, timeout=timeout) as response:
            return response.read().decode('utf-8')

    def login(self, username, password):
        body = urllib.parse.urlencode({'action': 'login', 'username': username, 'password': password}).encode()
        with self.opener.open(self.base_url + 'login', data=body, timeout=10) as response:
            response.read()

    def core_hashes(self):
        try:
            page = self.get('meshagents?cores=1')
        except urllib.error.HTTPError as error:
            raise SmokeFailure('Agent core list unavailable (HTTP ' + str(error.code) + '); the smoke login failed')
        return parse_core_hashes(page)


def run_checks(manifest, server, credentials, log_text, package_json, exists, sha256):
    """Run every assertion against a running server and raise SmokeFailure listing all failures."""
    expected = expectations(manifest)
    problems = check_preload(log_text)
    problems += check_served_version(server.get(VERSION_PATH), expected)
    problems += check_fork_revision(package_json, expected)
    server.login(*credentials)
    problems += check_core_hashes(server.core_hashes(), expected)
    problems += check_agent_binaries(expected, exists, sha256)
    if problems:
        raise SmokeFailure('Release smoke assertions failed:\n  ' + '\n  '.join(problems))
    return expected
