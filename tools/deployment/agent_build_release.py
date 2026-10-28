"""Publish and fetch the pinned MeshAgent Windows builds through private GitHub releases.

MeshCentral pins the fork's Windows service builds in agents/agent-defaults.json (schema
meshcentral-fork-agents/1: the MeshAgent build commit plus size and SHA384 per file). The binaries are
provisioned, so they never enter the public MeshAgent or MeshCentral git history; they are stored as
assets of a release in the private hook repository. The release tag is derived from the pins and the
build channel (MESHAGENT_CHANNEL of the build: production, or preview for the agent variant whose
machine-wide identities are suffixed so it coexists with a production agent):

    production  meshagent-<build commit>-<first 16 hex of the SHA256 of the canonical pins>
    preview     meshagent-preview-<build commit>-<first 16 hex of the SHA256 of the canonical pins>

so every pinned build has exactly one release, a rebuild of the same commit gets its own, the two
channels' releases never share a tag, and a reader holding agents/agent-defaults.json and knowing its
channel (MeshCentral main = production, MeshCentral preview = preview) knows where its bytes are. The release carries each pinned file
under its pinned name plus meshcentral-agent-defaults.json (the pins).

    python tools/deployment/agent_build_release.py fetch --store hira-edu/hook \
        --pins <MeshCentral>/agents/agent-defaults.json --output <empty folder> [--channel preview]
    python tools/deployment/agent_build_release.py publish --store hira-edu/hook \
        --pins <meshcentral-agent-defaults.json> --directory <folder with the pinned files> [--channel preview]

--channel defaults to production.

The token comes from AGENT_BUILDS_TOKEN (contents read for fetch, contents write for publish) and is
never printed. fetch writes a file only after its size and SHA384 match the pin; any missing release,
missing asset, unexpected asset or mismatch fails and leaves no fetched file behind. publish verifies
the local files first, creates a draft, uploads, publishes, and then fetches the release back and
verifies it. A release that already exists for the same pins is verified, never replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 'meshcentral-fork-agents/1'
BUILD_REPOSITORY = 'hira-edu/MeshAgent'
PINS_ASSET = 'meshcentral-agent-defaults.json'
TOKEN_VARIABLE = 'AGENT_BUILDS_TOKEN'
API = 'https://api.github.com'
UPLOADS = 'https://uploads.github.com'
TIMEOUT_SECONDS = 120
CHUNK = 1024 * 1024
MAX_FILE_SIZE = 512 * 1024 * 1024
SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
STORE_NAME = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
CHANNELS = ('production', 'preview')
TAG_PREFIX = {'production': 'meshagent-', 'preview': 'meshagent-preview-'}


class AgentBuildError(Exception):
    """A failure the caller must see; the message names what is missing or wrong."""


# ---------------------------------------------------------------------------------------------------
# Pins


def parse_pins(document, source):
    """Validate a meshcentral-fork-agents/1 document and return (build, files) for a non-empty pin set."""
    if not isinstance(document, dict) or document.get('schema') != SCHEMA:
        raise AgentBuildError(f'{source} is not a fork agent manifest (schema "{SCHEMA}")')
    extra = sorted(set(document) - {'schema', 'build', 'files'})
    if extra:
        raise AgentBuildError(f'{source} has unknown field(s): {", ".join(extra)}')
    files = document.get('files')
    if not isinstance(files, list) or not files:
        raise AgentBuildError(f'{source} pins no agent binary, so there is nothing to fetch or publish')
    build = document.get('build')
    if (not isinstance(build, dict) or sorted(build) != ['commit', 'repository']
            or not isinstance(build['repository'], str) or not isinstance(build['commit'], str)
            or not re.fullmatch(r'[0-9a-f]{40}', build['commit'])):
        raise AgentBuildError(f'{source}: "build" must name the MeshAgent repository and the full commit')
    if build['repository'] != BUILD_REPOSITORY:
        raise AgentBuildError(f'{source} pins a build of {build["repository"]}; the store holds '
                              f'{BUILD_REPOSITORY} builds only')
    pins, seen = [], set()
    for entry in files:
        if not isinstance(entry, dict) or sorted(entry) != ['filename', 'sha384', 'size']:
            raise AgentBuildError(f'{source}: every pin needs exactly filename, size and sha384')
        name, size, digest = entry['filename'], entry['size'], entry['sha384']
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or name == PINS_ASSET:
            raise AgentBuildError(f'{source}: invalid pinned file name {name!r}')
        if name.lower() in seen:
            raise AgentBuildError(f'{source}: {name} is pinned more than once')
        if (isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_FILE_SIZE
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{96}', digest)):
            raise AgentBuildError(f'{source}: invalid size or SHA384 for {name}')
        seen.add(name.lower())
        pins.append({'filename': name, 'size': size, 'sha384': digest})
    pins.sort(key=lambda pin: pin['filename'])
    return {'repository': build['repository'], 'commit': build['commit']}, pins


def load_pins(path):
    path = Path(path)
    try:
        text = path.read_text(encoding='utf-8')
    except FileNotFoundError:
        raise AgentBuildError(f'pins file missing: {path}') from None
    try:
        document = json.loads(text)
    except ValueError as error:
        raise AgentBuildError(f'{path} is not valid JSON: {error}') from None
    return parse_pins(document, str(path))


def canonical_pins(build, pins):
    """The pins as one deterministic document (independent of the source file's order and layout)."""
    return {'schema': SCHEMA, 'build': dict(build), 'files': [dict(pin) for pin in pins]}


def release_tag(build, pins, channel='production'):
    if channel not in TAG_PREFIX:
        raise AgentBuildError(f'unknown build channel {channel!r}; expected one of {", ".join(CHANNELS)}')
    text = json.dumps(canonical_pins(build, pins), sort_keys=True, separators=(',', ':'))
    return f'{TAG_PREFIX[channel]}{build["commit"]}-{hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]}'


def pins_asset_bytes(build, pins):
    return (json.dumps(canonical_pins(build, pins), indent=2) + '\n').encode('utf-8')


def check_file(path, pin):
    """None when the file matches its pin, otherwise why not."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        return 'missing or not a regular file'
    size = path.stat().st_size
    if size != pin['size']:
        return f'{size} bytes, pinned {pin["size"]}'
    digest = hashlib.sha384()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b''):
            digest.update(chunk)
    found = digest.hexdigest()
    return None if found == pin['sha384'] else f'SHA384 {found}, pinned {pin["sha384"]}'


# ---------------------------------------------------------------------------------------------------
# Store: GitHub releases of one repository


class GitHubStore:
    """Releases of one private repository, through the GitHub REST API."""

    def __init__(self, repository, token, opener=None):
        if not STORE_NAME.fullmatch(repository or ''):
            raise AgentBuildError(f'invalid store repository {repository!r}; expected owner/name')
        if not token:
            raise AgentBuildError(f'{TOKEN_VARIABLE} is empty')
        self.repository = repository
        self._token = token
        self._open = opener or urllib.request.urlopen

    def _request(self, method, url, body=None, accept='application/vnd.github+json', content_type=None):
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header('Accept', accept)
        request.add_header('X-GitHub-Api-Version', '2022-11-28')
        request.add_header('User-Agent', 'meshagent-agent-build-release')
        if content_type:
            request.add_header('Content-Type', content_type)
        # Not forwarded on redirects: asset downloads redirect to a pre-signed storage URL.
        request.add_unredirected_header('Authorization', 'Bearer ' + self._token)
        return request

    def _call(self, method, url, what, body=None, accept='application/vnd.github+json', content_type=None,
              missing_ok=False):
        request = self._request(method, url, body, accept, content_type)
        try:
            response = self._open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            error.close()
            if missing_ok and error.code == 404:
                return None
            raise AgentBuildError(f'{what}: GitHub answered HTTP {error.code} {error.reason}') from None
        except urllib.error.URLError as error:
            raise AgentBuildError(f'{what}: {error.reason}') from None
        return response

    def _json(self, method, url, what, payload=None, missing_ok=False):
        body = None if payload is None else json.dumps(payload).encode('utf-8')
        response = self._call(method, url, what, body, content_type='application/json' if body else None,
                              missing_ok=missing_ok)
        if response is None:
            return None
        with response:
            data = response.read()
        return json.loads(data) if data else {}

    def check_access(self):
        # GitHub answers 404 for a private repository the token cannot see, so a missing release is only
        # meaningful once the repository itself is readable.
        if self._json('GET', f'{API}/repos/{self.repository}', f'read {self.repository}', missing_ok=True) is None:
            raise AgentBuildError(f'the token in {TOKEN_VARIABLE} cannot read {self.repository} '
                                  '(the GitHub App is not installed on it, or lacks Contents read)')

    def release(self, tag):
        path = urllib.parse.quote(tag, safe='')
        return self._json('GET', f'{API}/repos/{self.repository}/releases/tags/{path}',
                          f'read release {tag} of {self.repository}', missing_ok=True)

    def download(self, asset, sink):
        response = self._call('GET', f'{API}/repos/{self.repository}/releases/assets/{int(asset["id"])}',
                              f'download {asset["name"]} from {self.repository}', accept='application/octet-stream')
        with response:
            for chunk in iter(lambda: response.read(CHUNK), b''):
                sink(chunk)

    def create_draft(self, tag, title, notes):
        return self._json('POST', f'{API}/repos/{self.repository}/releases', f'create release {tag}',
                          {'tag_name': tag, 'name': title, 'body': notes, 'draft': True,
                           'prerelease': False, 'make_latest': 'false'})

    def upload(self, release, name, data):
        query = urllib.parse.urlencode({'name': name})
        response = self._call('POST', f'{UPLOADS}/repos/{self.repository}/releases/{int(release["id"])}/assets?{query}',
                              f'upload {name}', body=data, content_type='application/octet-stream')
        with response:
            return json.loads(response.read())

    def publish(self, release):
        return self._json('PATCH', f'{API}/repos/{self.repository}/releases/{int(release["id"])}',
                          f'publish release {release.get("tag_name")}', {'draft': False})

    def delete(self, release):
        response = self._call('DELETE', f'{API}/repos/{self.repository}/releases/{int(release["id"])}',
                              f'delete draft release {release.get("tag_name")}')
        response.close()


# ---------------------------------------------------------------------------------------------------
# Operations


def _describe(build, tag, store):
    return f'{build["repository"]} {build["commit"]} (release {tag} in {store.repository})'


def fetch(store, build, pins, output, log=print, channel='production'):
    """Download every pinned file into output (new or empty) and verify it; returns the release tag."""
    tag = release_tag(build, pins, channel)
    output = Path(output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise AgentBuildError(f'output folder {output} must be new or empty')
    store.check_access()
    release = store.release(tag)
    if release is None:
        raise AgentBuildError(f'{store.repository} has no release {tag} for the pinned {channel} build '
                              f'{build["repository"]} {build["commit"]}; publish it with '
                              f'"agent_build_release.py publish" from the build the pins were taken from')
    if release.get('draft'):
        raise AgentBuildError(f'release {tag} in {store.repository} is still a draft')
    assets = {}
    for asset in release.get('assets') or []:
        if asset.get('name') in assets:
            raise AgentBuildError(f'release {tag} lists asset {asset.get("name")} twice')
        assets[asset.get('name')] = asset
    expected = {pin['filename'] for pin in pins} | {PINS_ASSET}
    unexpected = sorted(set(assets) - expected, key=str)
    if unexpected:
        raise AgentBuildError(f'release {tag} holds asset(s) the pins do not name: {", ".join(map(str, unexpected))}')
    missing = [pin['filename'] for pin in pins if pin['filename'] not in assets]
    if missing:
        raise AgentBuildError(f'release {tag} lacks pinned asset(s): {", ".join(missing)}')
    output.mkdir(parents=True, exist_ok=True)
    written = []
    try:
        for pin in pins:
            asset = assets[pin['filename']]
            if asset.get('size') != pin['size']:
                raise AgentBuildError(f'{pin["filename"]} in release {tag} is {asset.get("size")} bytes, '
                                      f'pinned {pin["size"]}')
            final = output / pin['filename']
            partial = output / (pin['filename'] + '.partial')
            written.append(partial)
            digest, size = hashlib.sha384(), 0
            with partial.open('xb') as handle:
                def sink(chunk):
                    nonlocal size
                    size += len(chunk)
                    if size > pin['size']:
                        raise AgentBuildError(f'{pin["filename"]} from release {tag} is larger than its pin '
                                              f'({pin["size"]} bytes)')
                    digest.update(chunk)
                    handle.write(chunk)
                store.download(asset, sink)
            found = digest.hexdigest()
            if size != pin['size'] or found != pin['sha384']:
                raise AgentBuildError(f'{pin["filename"]} from release {tag} does not match its pin: '
                                      f'{size} bytes SHA384 {found}, pinned {pin["size"]} bytes SHA384 {pin["sha384"]}')
            partial.replace(final)
            written[-1] = final
            log(f'verified {pin["filename"]} {pin["size"]} bytes SHA384 {pin["sha384"]}')
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    log(f'Fetched {len(pins)} pinned builds of {_describe(build, tag, store)} into {output}')
    return tag


def _verify_round_trip(store, build, pins, log, channel):
    with tempfile.TemporaryDirectory(prefix='agent-builds-verify-') as folder:
        fetch(store, build, pins, Path(folder) / 'fetched', log=lambda _message: None, channel=channel)
    log('verified the published release by fetching it back')


def publish(store, build, pins, directory, log=print, channel='production'):
    """Store the pinned files from directory as the release for these pins; returns the release tag."""
    directory = Path(directory)
    problems = []
    for pin in pins:
        problem = check_file(directory / pin['filename'], pin)
        if problem:
            problems.append(f'{directory / pin["filename"]}: {problem}')
    if problems:
        raise AgentBuildError('the local files do not match the pins:\n' + '\n'.join(problems))
    tag = release_tag(build, pins, channel)
    store.check_access()
    if store.release(tag) is not None:
        log(f'{store.repository} already has release {tag}; verifying it instead of replacing it')
        _verify_round_trip(store, build, pins, log, channel)
        return tag
    title = f'MeshAgent {"preview " if channel == "preview" else ""}build {build["commit"][:12]}'
    notes = '\n'.join([f'{channel.capitalize()} Windows service builds of {build["repository"]} {build["commit"]}, pinned by '
                       f'MeshCentral agents/agent-defaults.json as in {PINS_ASSET}.', ''] +
                      [f'- `{pin["filename"]}` {pin["size"]} bytes, SHA384 `{pin["sha384"]}`' for pin in pins])
    draft = store.create_draft(tag, title, notes)
    try:
        for pin in pins:
            data = (directory / pin['filename']).read_bytes()
            if len(data) != pin['size'] or hashlib.sha384(data).hexdigest() != pin['sha384']:
                raise AgentBuildError(f'{pin["filename"]} changed after it was verified')
            uploaded = store.upload(draft, pin['filename'], data)
            if uploaded.get('name') != pin['filename'] or uploaded.get('size') != pin['size']:
                raise AgentBuildError(f'upload of {pin["filename"]} was stored as {uploaded.get("name")} '
                                      f'with {uploaded.get("size")} bytes')
            log(f'uploaded {pin["filename"]}')
        uploaded = store.upload(draft, PINS_ASSET, pins_asset_bytes(build, pins))
        if uploaded.get('name') != PINS_ASSET:
            raise AgentBuildError(f'upload of {PINS_ASSET} was stored as {uploaded.get("name")}')
        store.publish(draft)
    except BaseException as error:
        try:
            store.delete(draft)
            log(f'deleted the incomplete draft release {tag}')
        except AgentBuildError as cleanup:
            raise AgentBuildError(f'{error}; the incomplete draft release {tag} could not be deleted '
                                  f'({cleanup}); delete it in {store.repository}') from None
        raise
    log(f'Published {len(pins)} pinned builds of {_describe(build, tag, store)}')
    _verify_round_trip(store, build, pins, log, channel)
    return tag


# ---------------------------------------------------------------------------------------------------
# Command line


def main(argv=None, environ=None, store_factory=GitHubStore):
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='command', required=True)
    fetch_parser = commands.add_parser('fetch', help='download and verify the pinned builds')
    fetch_parser.add_argument('--output', required=True, help='new or empty folder for the pinned files')
    publish_parser = commands.add_parser('publish', help='store the pinned builds as a release')
    publish_parser.add_argument('--directory', required=True, help='folder holding the pinned files')
    for sub in (fetch_parser, publish_parser):
        sub.add_argument('--store', required=True, help='private repository holding the builds (owner/name)')
        sub.add_argument('--pins', required=True, help='a meshcentral-fork-agents/1 manifest')
        sub.add_argument('--channel', choices=CHANNELS, default='production',
                         help='build channel of the pinned files (names the release tag)')
    args = parser.parse_args(argv)
    try:
        build, pins = load_pins(args.pins)
        token = environ.get(TOKEN_VARIABLE, '')
        if not token.strip():
            raise AgentBuildError(f'{TOKEN_VARIABLE} is not set: it must hold a token that can read '
                                  f'(fetch) or write (publish) the releases of {args.store}')
        store = store_factory(args.store, token.strip())
        if args.command == 'fetch':
            fetch(store, build, pins, args.output, channel=args.channel)
        else:
            publish(store, build, pins, args.directory, channel=args.channel)
    except AgentBuildError as error:
        message = f'agent builds: {error}'
        print(message, file=sys.stderr)
        if environ.get('GITHUB_ACTIONS') == 'true':
            escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print(f'::error title=Pinned agent builds::{escaped}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
