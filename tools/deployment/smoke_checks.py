"""Release smoke assertions shared by the image smoke test and duplicate-server runs (T22).

A release passes only when the running server proves it is the reviewed fork build, installed from
the fork tarball and nothing else:

- image-size is not installed (the fork sizes tiles and recordings itself; D4, DEP-21);
- the served MeshCentral version equals the manifest's reviewed version;
- the installed package is the manifest's tarball (npm's installed-package record holds its sha512
  integrity), dated by the manifest's packagedCommit (agents/module-versions.json), and carries the
  `daemon` marker that keeps self-update off (D6, PRD-11);
- the installed agents/agent-defaults.json pins exactly the manifest's agentBinaries (same MeshAgent
  build, file names, sizes and SHA384);
- every agent core the manifest lists is served with the manifest's SHA-384;
- for every agent architecture the manifest lists, MeshCentral selects the package file (never a
  meshcentral-data copy), that file has the pinned size and SHA384, and for architectures served
  unsigned, GET /meshagents?id=<id> returns exactly those bytes.

Release manifest (schema 2, written into the image by release_image.js; release_manager validates
its identity fields and shadowAllowlist):

    "schema": 2,
    "meshcentral_version": "1.3.1", "reviewedUpstreamVersion": "1.3.1",
    "forkRevision": "<40-hex MeshCentral commit the image was built from>",
    "package": {"tarball": "meshcentral-1.3.1.tgz", "integrity": "sha512-...",
                "packagedCommit": "<40-hex last commit that changed packaged content>"},
    "agentBuild": {"repository": "hira-edu/MeshAgent", "commit": "<40 hex>"},
    "agentCoreHashes": {"windows-amt": "<sha384 hex of the served core>", ...},
    "agentBinaries": {"4": {"localname": "MeshService64.exe", "unsigned": true,
                            "path": "node_modules/meshcentral/agents/MeshService64.exe",
                            "size": 15707648, "sha384": "<hex>"}, ...},
    "shadowAllowlist": []

Paths are relative to the install root (/opt/meshcentral in the image).
"""
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request

# A ~showversion redirect the smoke configuration defines (webserver.js handleDomainRedirect).
VERSION_PATH = 'release-smoke-version'
PACKAGE_DIR = 'node_modules/meshcentral'
DATA_DIR = 'meshcentral-data'
# npm's record of the installed tree (written by npm ci), the pack step's module manifest, the agent pins
# and the D6 self-update marker, all relative to the install root.
INSTALLED_LOCK = 'node_modules/.package-lock.json'
MODULE_VERSIONS = PACKAGE_DIR + '/agents/module-versions.json'
AGENT_PINS = PACKAGE_DIR + '/agents/agent-defaults.json'
AGENT_PINS_SCHEMA = 'meshcentral-fork-agents/1'
DAEMON_MARKER = PACKAGE_DIR + '/daemon'
# Install-root paths where npm would place image-size; the fork's package tree has none.
IMAGE_SIZE_PATHS = ('node_modules/image-size', 'node_modules/meshcentral/node_modules/image-size')
MANIFEST_SCHEMA = 2
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?')
COMMIT = re.compile(r'[0-9a-f]{40}')
INTEGRITY = re.compile(r'sha512-[A-Za-z0-9+/]{86}==')
SHA384 = re.compile(r'[0-9a-f]{96}')


class SmokeFailure(RuntimeError):
    """One or more smoke assertions failed; the message lists each of them."""


def expectations(manifest):
    """Validate and return the identity the release must prove."""
    problems = []
    if manifest.get('schema') != MANIFEST_SCHEMA:
        problems.append('manifest schema ' + repr(manifest.get('schema')) + ' is not 2; images built before the '
                        'fork tarball release cannot pass the fork smoke test')
    version = manifest.get('meshcentral_version')
    reviewed = manifest.get('reviewedUpstreamVersion')
    if not isinstance(version, str) or not VERSION.fullmatch(version) or reviewed != version:
        problems.append('manifest reviewedUpstreamVersion ' + repr(reviewed) + ' does not match meshcentral_version ' +
                        repr(version))
    revision = manifest.get('forkRevision')
    if not isinstance(revision, str) or not COMMIT.fullmatch(revision):
        problems.append('manifest forkRevision is missing or not a full git sha')
    package = manifest.get('package')
    if not (isinstance(package, dict) and set(package) == {'tarball', 'integrity', 'packagedCommit'} and
            package['tarball'] == 'meshcentral-' + str(version) + '.tgz' and
            isinstance(package['integrity'], str) and INTEGRITY.fullmatch(package['integrity']) and
            isinstance(package['packagedCommit'], str) and COMMIT.fullmatch(package['packagedCommit'])):
        problems.append('manifest package must give the tarball meshcentral-<version>.tgz, its sha512 integrity '
                        'and the packagedCommit')
    build = manifest.get('agentBuild')
    if not (isinstance(build, dict) and set(build) == {'repository', 'commit'} and isinstance(build['repository'], str)
            and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', build['repository']) and
            isinstance(build['commit'], str) and COMMIT.fullmatch(build['commit'])):
        problems.append('manifest agentBuild must name the MeshAgent repository and commit of the pinned agents')
    cores = manifest.get('agentCoreHashes')
    if not isinstance(cores, dict) or not cores or not all(
            isinstance(name, str) and isinstance(digest, str) and SHA384.fullmatch(digest)
            for name, digest in cores.items()):
        problems.append('manifest agentCoreHashes must map each served core name to its lowercase SHA-384')
    agents = manifest.get('agentBinaries')
    if not isinstance(agents, dict) or not agents:
        problems.append('manifest agentBinaries must list the agent binaries the server serves')
        agents = {}
    pins = {}
    for archid, entry in agents.items():
        valid = (archid.isdigit() and isinstance(entry, dict) and
                 set(entry) == {'localname', 'unsigned', 'path', 'size', 'sha384'} and
                 isinstance(entry['localname'], str) and
                 re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', entry['localname']) is not None and
                 isinstance(entry['unsigned'], bool) and
                 entry['path'] == PACKAGE_DIR + '/agents/' + entry['localname'] and
                 isinstance(entry['size'], int) and not isinstance(entry['size'], bool) and entry['size'] > 0 and
                 isinstance(entry['sha384'], str) and SHA384.fullmatch(entry['sha384']) is not None)
        if not valid:
            problems.append('manifest agentBinaries[' + repr(archid) + '] needs localname, unsigned, the package path '
                            + PACKAGE_DIR + '/agents/<localname>, size and a lowercase sha384')
            continue
        pin = (entry['size'], entry['sha384'])
        if pins.setdefault(entry['localname'], pin) != pin:
            problems.append('manifest agentBinaries give ' + entry['localname'] + ' two different pins')
    if problems:
        raise SmokeFailure('Release manifest cannot be smoke tested:\n  ' + '\n  '.join(problems))
    return {'version': version, 'forkRevision': revision, 'package': package, 'agentBuild': build,
            'cores': cores, 'agents': agents, 'pins': pins}


def selected_agent_path(entry, exists):
    """The file the fork serves for one architecture of the default domain.

    Mirrors the fork's updateMeshAgentsTable (meshcentral.js): a meshcentral-data/agents copy wins for an
    architecture not marked unsigned; otherwise the package file, replaced by a server-signed
    meshcentral-data/signedagents copy for signed architectures. ``exists`` answers for a path relative
    to the install root.
    """
    name = entry['localname']
    if not entry['unsigned']:
        for candidate in (DATA_DIR + '/agents/' + name, DATA_DIR + '/signedagents/' + name):
            if exists(candidate):
                return candidate
    return PACKAGE_DIR + '/agents/' + name


def check_no_image_size(files):
    """image-size has unpatched parser advisories and the fork no longer uses it; it must not be installed."""
    return [path + ' is installed; the fork package tree must not contain image-size'
            for path in IMAGE_SIZE_PATHS if files.exists(path)]


def check_served_version(body, expected):
    actual = body.strip()
    if actual != 'MeshCentral v' + expected['version']:
        return ['served version ' + repr(actual) + ' is not MeshCentral v' + expected['version']]
    return []


def _read_json(files, relative, problems):
    if not files.exists(relative):
        problems.append(relative + ' is missing')
        return None
    try:
        return json.loads(files.read(relative))
    except ValueError as error:
        problems.append(relative + ' is not valid JSON: ' + str(error))
        return None


def check_installed_package(files, expected):
    """The installed node_modules/meshcentral is the manifest's tarball, with the self-update marker."""
    problems = []
    package = expected['package']
    lock = _read_json(files, INSTALLED_LOCK, problems)
    if lock is not None:
        installed = (lock.get('packages') or {}).get(PACKAGE_DIR) or {}
        if installed.get('version') != expected['version']:
            problems.append('installed meshcentral version ' + repr(installed.get('version')) + ' is not ' +
                            expected['version'])
        if installed.get('integrity') != package['integrity']:
            problems.append('installed meshcentral integrity ' + repr(installed.get('integrity')) +
                            ' is not the manifest tarball ' + package['integrity'])
    versions = _read_json(files, MODULE_VERSIONS, problems)
    if versions is not None and versions.get('commit') != package['packagedCommit']:
        problems.append(MODULE_VERSIONS + ' dates the package by ' + repr(versions.get('commit')) +
                        ', manifest packagedCommit is ' + package['packagedCommit'])
    if not files.exists(DAEMON_MARKER):
        problems.append(DAEMON_MARKER + ' is missing, so the server would allow self-update (D6)')
    return problems


def check_agent_pins(files, expected):
    """The package's own pins are the manifest's agentBinaries."""
    problems = []
    pins = _read_json(files, AGENT_PINS, problems)
    if pins is None:
        return problems
    if not isinstance(pins, dict) or pins.get('schema') != AGENT_PINS_SCHEMA or not isinstance(pins.get('files'), list):
        return [AGENT_PINS + ' is not a fork agent manifest (' + AGENT_PINS_SCHEMA + ')']
    if pins.get('build') != expected['agentBuild']:
        problems.append(AGENT_PINS + ' pins build ' + repr(pins.get('build')) + ', manifest agentBuild is ' +
                        repr(expected['agentBuild']))
    installed = {}
    for pin in pins['files']:
        if isinstance(pin, dict):
            installed[pin.get('filename')] = (pin.get('size'), pin.get('sha384'))
    for name in sorted(set(installed) | set(expected['pins']), key=str):
        if installed.get(name) != expected['pins'].get(name):
            problems.append('agent pin ' + str(name) + ': package pins ' + repr(installed.get(name)) +
                            ', manifest expects ' + repr(expected['pins'].get(name)))
    return problems


def check_agent_binaries(expected, files):
    """The selected on-disk file of every listed architecture is the pinned package file."""
    problems = []
    for archid, entry in sorted(expected['agents'].items(), key=lambda item: int(item[0])):
        selected = selected_agent_path(entry, files.exists)
        if selected != entry['path']:
            problems.append('agent ' + archid + ': MeshCentral selects ' + selected + ', not the package file ' +
                            entry['path'])
        elif not files.exists(selected):
            problems.append('agent ' + archid + ': ' + selected + ' does not exist, so it is not served')
        else:
            size, digest = files.digest(selected)
            if (size, digest) != (entry['size'], entry['sha384']):
                problems.append('agent ' + archid + ': ' + selected + ' has ' + str(size) + ' bytes, SHA384 ' +
                                digest + '; pinned ' + str(entry['size']) + ' bytes, SHA384 ' + entry['sha384'])
    return problems


def check_served_agents(server, expected):
    """Architectures served unsigned are sent byte for byte: no policy block is appended to them."""
    problems = []
    for archid, entry in sorted(expected['agents'].items(), key=lambda item: int(item[0])):
        if not entry['unsigned']:
            continue
        try:
            data = server.agent(archid)
        except SmokeFailure as error:
            problems.append('agent ' + archid + ': ' + str(error))
            continue
        digest = hashlib.sha384(data).hexdigest()
        if (len(data), digest) != (entry['size'], entry['sha384']):
            problems.append('agent ' + archid + ': /meshagents?id=' + archid + ' served ' + str(len(data)) +
                            ' bytes, SHA384 ' + digest + '; pinned ' + str(entry['size']) + ' bytes, SHA384 ' +
                            entry['sha384'])
    return problems


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
    """Parse /meshagents?cores=1 (webserver.js handleMeshAgentRequest) into {core name: sha384 hex}."""
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


class Server:
    """HTTP access to a running MeshCentral (plain HTTP behind tlsoffload, as in the smoke config)."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/') + '/'
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get_bytes(self, path, timeout=10):
        with self.opener.open(self.base_url + path, timeout=timeout) as response:
            return response.read()

    def get(self, path, timeout=10):
        return self.get_bytes(path, timeout).decode('utf-8')

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

    def agent(self, archid):
        try:
            return self.get_bytes('meshagents?id=' + archid, timeout=60)
        except urllib.error.HTTPError as error:
            raise SmokeFailure('/meshagents?id=' + archid + ' returned HTTP ' + str(error.code))


def run_checks(manifest, server, credentials, files):
    """Run every assertion against a running server and raise SmokeFailure listing all failures.

    ``files`` reads the server's install root: exists(relative), read(relative) -> text and
    digest(relative) -> (size, sha384 hex).
    """
    expected = expectations(manifest)
    problems = check_no_image_size(files)
    problems += check_served_version(server.get(VERSION_PATH), expected)
    problems += check_installed_package(files, expected)
    problems += check_agent_pins(files, expected)
    server.login(*credentials)
    problems += check_core_hashes(server.core_hashes(), expected)
    problems += check_agent_binaries(expected, files)
    problems += check_served_agents(server, expected)
    if problems:
        raise SmokeFailure('Release smoke assertions failed:\n  ' + '\n  '.join(problems))
    return expected
