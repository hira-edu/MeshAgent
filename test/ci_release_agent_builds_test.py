"""Offline tests for tools/deployment/agent_build_release.py; no network, no GitHub, no real builds."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('agent_build_release', ROOT / 'tools/deployment/agent_build_release.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)

COMMIT = '366e4a64fe1a19f9f5ded2f6f7baede2c0f6d264'
STORE = 'hira-edu/hook'
TOKEN = 'fixture-token-must-never-appear'
BUILDS = {
    'MeshService.exe': b'MZ x86 fixture build' * 50,
    'MeshService64.exe': b'MZ x64 fixture build' * 70,
    'MeshServiceARM64.exe': b'MZ arm64 fixture build' * 90,
}


def pins_document(builds=BUILDS, commit=COMMIT, repository='hira-edu/MeshAgent'):
    return {'schema': TOOL.SCHEMA, 'build': {'repository': repository, 'commit': commit},
            'files': [{'filename': name, 'size': len(data), 'sha384': hashlib.sha384(data).hexdigest()}
                      for name, data in builds.items()]}


class FakeStore:
    """Releases of one repository, in memory, with the GitHubStore interface."""

    def __init__(self, repository=STORE, accessible=True):
        self.repository = repository
        self.accessible = accessible
        self.releases = {}
        self.blobs = {}
        self.calls = []
        self.fail_upload = None
        self.next_id = 1

    def _id(self):
        self.next_id += 1
        return self.next_id

    def add_release(self, tag, files, draft=False):
        release = {'id': self._id(), 'tag_name': tag, 'draft': draft, 'assets': []}
        for name, data in files.items():
            asset_id = self._id()
            self.blobs[asset_id] = data
            release['assets'].append({'id': asset_id, 'name': name, 'size': len(data)})
        self.releases[tag] = release
        return release

    def check_access(self):
        self.calls.append('check_access')
        if not self.accessible:
            raise TOOL.AgentBuildError(f'the token in {TOOL.TOKEN_VARIABLE} cannot read {self.repository}')

    def release(self, tag):
        self.calls.append(('release', tag))
        release = self.releases.get(tag)
        return None if release is None or release['draft'] else release

    def download(self, asset, sink):
        self.calls.append(('download', asset['name']))
        data = self.blobs[asset['id']]
        for offset in range(0, len(data), 7):
            sink(data[offset:offset + 7])

    def create_draft(self, tag, title, notes):
        self.calls.append(('create_draft', tag))
        return self.add_release(tag, {}, draft=True)

    def upload(self, release, name, data):
        self.calls.append(('upload', name))
        if self.fail_upload == name:
            raise TOOL.AgentBuildError(f'upload {name}: GitHub answered HTTP 502 Bad Gateway')
        asset_id = self._id()
        self.blobs[asset_id] = bytes(data)
        asset = {'id': asset_id, 'name': name, 'size': len(data)}
        release['assets'].append(asset)
        return dict(asset)

    def publish(self, release):
        self.calls.append(('publish', release['tag_name']))
        release['draft'] = False

    def delete(self, release):
        self.calls.append(('delete', release['tag_name']))
        del self.releases[release['tag_name']]


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build, self.pins = TOOL.parse_pins(pins_document(), 'fixture pins')
        self.tag = TOOL.release_tag(self.build, self.pins)
        self.messages = []

    def log(self, message):
        self.messages.append(message)

    def published_store(self, files=None):
        store = FakeStore()
        store.add_release(self.tag, dict(BUILDS, **{TOOL.PINS_ASSET: TOOL.pins_asset_bytes(self.build, self.pins)})
                          if files is None else files)
        return store

    def build_folder(self, builds=BUILDS):
        folder = self.root / 'builds'
        folder.mkdir()
        for name, data in builds.items():
            (folder / name).write_bytes(data)
        return folder

    def write_pins(self, document):
        path = self.root / 'agent-defaults.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        return path


class PinsTests(Fixture):
    def test_tag_depends_only_on_the_pins(self):
        reordered = pins_document()
        reordered['files'].reverse()
        build, pins = TOOL.parse_pins(json.loads(json.dumps(reordered, indent=4)), 'reordered')
        self.assertEqual(TOOL.release_tag(build, pins), self.tag)
        self.assertRegex(self.tag, r'^meshagent-' + COMMIT + r'-[0-9a-f]{16}$')
        rebuilt = dict(BUILDS, **{'MeshService64.exe': b'MZ another build of the same commit'})
        build, pins = TOOL.parse_pins(pins_document(rebuilt), 'rebuild')
        self.assertNotEqual(TOOL.release_tag(build, pins), self.tag)

    def test_preview_builds_have_their_own_tag_namespace(self):
        preview = TOOL.release_tag(self.build, self.pins, 'preview')
        self.assertRegex(preview, r'^meshagent-preview-' + COMMIT + r'-[0-9a-f]{16}$')
        # Same pins hash; only the prefix names the channel, and production's tag is unchanged.
        self.assertEqual(preview.rsplit('-', 1)[1], self.tag.rsplit('-', 1)[1])
        self.assertEqual(TOOL.release_tag(self.build, self.pins, 'production'), self.tag)
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'unknown build channel'):
            TOOL.release_tag(self.build, self.pins, 'staging')

    def test_invalid_pins_are_refused(self):
        cases = {
            'pins no agent binary': dict(pins_document(), build=None, files=[]),
            'not a fork agent manifest': dict(pins_document(), schema='other'),
            'unknown field': dict(pins_document(), releases=[]),
            'full commit': pins_document(commit='366e4a64'),
            'store holds hira-edu/MeshAgent builds only': pins_document(repository='someone/MeshAgent'),
            'pinned more than once': dict(pins_document(), files=pins_document()['files'] * 2),
            'invalid pinned file name': dict(pins_document(), files=[dict(pins_document()['files'][0], filename='../x.exe')]),
            'invalid size or SHA384': dict(pins_document(), files=[dict(pins_document()['files'][0], size=0)]),
        }
        for expected, document in cases.items():
            with self.subTest(expected), self.assertRaisesRegex(TOOL.AgentBuildError, expected):
                TOOL.parse_pins(document, 'fixture')

    def test_missing_pins_file_is_named(self):
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'pins file missing: .*absent.json'):
            TOOL.load_pins(self.root / 'absent.json')


class FetchTests(Fixture):
    def test_fetch_writes_exactly_the_pinned_bytes(self):
        output = self.root / 'out'
        tag = TOOL.fetch(self.published_store(), self.build, self.pins, output, log=self.log)
        self.assertEqual(tag, self.tag)
        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, BUILDS)
        self.assertIn('Fetched 3 pinned builds', self.messages[-1])

    def test_mismatched_bytes_fail_and_leave_nothing(self):
        tampered = dict(BUILDS, **{'MeshService64.exe': b'MZ x64 fixture builX' * 70})
        output = self.root / 'out'
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService64.exe from release .* does not match its pin'):
            TOOL.fetch(self.published_store(tampered), self.build, self.pins, output, log=self.log)
        self.assertEqual(list(output.iterdir()), [])

    def test_oversized_download_is_stopped(self):
        store = self.published_store()
        asset = next(a for a in store.releases[self.tag]['assets'] if a['name'] == 'MeshService.exe')
        store.blobs[asset['id']] += b'extra'
        output = self.root / 'out'
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService.exe from release .* is larger than its pin'):
            TOOL.fetch(store, self.build, self.pins, output, log=self.log)
        self.assertEqual(list(output.iterdir()), [])

    def test_asset_size_mismatch_fails_before_download(self):
        store = self.published_store()
        next(a for a in store.releases[self.tag]['assets'] if a['name'] == 'MeshService.exe')['size'] += 1
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService.exe in release .* bytes, pinned'):
            TOOL.fetch(store, self.build, self.pins, self.root / 'out', log=self.log)
        self.assertNotIn(('download', 'MeshService.exe'), store.calls)

    def test_missing_asset_is_named(self):
        files = {name: data for name, data in BUILDS.items() if name != 'MeshServiceARM64.exe'}
        with self.assertRaisesRegex(TOOL.AgentBuildError, f'release {self.tag} lacks pinned asset\\(s\\): MeshServiceARM64.exe'):
            TOOL.fetch(self.published_store(files), self.build, self.pins, self.root / 'out', log=self.log)

    def test_unexpected_asset_is_refused(self):
        files = dict(BUILDS, **{'MeshCmd.exe': b'MZ not pinned'})
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'holds asset\\(s\\) the pins do not name: MeshCmd.exe'):
            TOOL.fetch(self.published_store(files), self.build, self.pins, self.root / 'out', log=self.log)

    def test_missing_release_names_tag_and_commit(self):
        with self.assertRaisesRegex(TOOL.AgentBuildError, f'{STORE} has no release {self.tag} .*{COMMIT}.*publish'):
            TOOL.fetch(FakeStore(), self.build, self.pins, self.root / 'out', log=self.log)

    def test_draft_release_is_not_used(self):
        store = self.published_store()
        store.releases[self.tag]['draft'] = True
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'has no release'):
            TOOL.fetch(store, self.build, self.pins, self.root / 'out', log=self.log)

    def test_unreadable_store_is_named(self):
        with self.assertRaisesRegex(TOOL.AgentBuildError, f'cannot read {STORE}'):
            TOOL.fetch(FakeStore(accessible=False), self.build, self.pins, self.root / 'out', log=self.log)

    def test_non_empty_output_is_refused(self):
        output = self.root / 'out'
        output.mkdir()
        (output / 'MeshService.exe').write_bytes(b'stale')
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'must be new or empty'):
            TOOL.fetch(self.published_store(), self.build, self.pins, output, log=self.log)


class PublishTests(Fixture):
    def test_publish_creates_uploads_publishes_and_verifies(self):
        store = FakeStore()
        tag = TOOL.publish(store, self.build, self.pins, self.build_folder(), log=self.log)
        self.assertEqual(tag, self.tag)
        release = store.releases[tag]
        self.assertFalse(release['draft'])
        stored = {a['name']: store.blobs[a['id']] for a in release['assets']}
        self.assertEqual(stored, dict(BUILDS, **{TOOL.PINS_ASSET: TOOL.pins_asset_bytes(self.build, self.pins)}))
        self.assertEqual(TOOL.parse_pins(json.loads(stored[TOOL.PINS_ASSET]), 'asset'), (self.build, self.pins))
        names = [c[0] if isinstance(c, tuple) else c for c in store.calls]
        self.assertLess(names.index('create_draft'), names.index('upload'))
        self.assertLess(max(i for i, n in enumerate(names) if n == 'upload'), names.index('publish'))
        self.assertIn('download', names[names.index('publish'):])
        self.assertIn('verified the published release by fetching it back', self.messages)

    def test_local_mismatch_fails_before_any_store_call(self):
        folder = self.build_folder(dict(BUILDS, **{'MeshService.exe': b'MZ different'}))
        store = FakeStore()
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService.exe: .*bytes, pinned'):
            TOOL.publish(store, self.build, self.pins, folder, log=self.log)
        (folder / 'MeshService.exe').unlink()
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService.exe: missing'):
            TOOL.publish(store, self.build, self.pins, folder, log=self.log)
        self.assertEqual(store.calls, [])

    def test_existing_release_is_verified_not_replaced(self):
        store = self.published_store()
        before = json.dumps(store.releases, sort_keys=True)
        TOOL.publish(store, self.build, self.pins, self.build_folder(), log=self.log)
        self.assertEqual(json.dumps(store.releases, sort_keys=True), before)
        self.assertFalse(any(isinstance(c, tuple) and c[0] in ('create_draft', 'upload', 'delete') for c in store.calls))

    def test_existing_release_with_other_bytes_fails(self):
        store = self.published_store(dict(BUILDS, **{'MeshService.exe': b'MZ x86 fixture builX' * 50}))
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'MeshService.exe from release .* does not match its pin'):
            TOOL.publish(store, self.build, self.pins, self.build_folder(), log=self.log)

    def test_failed_upload_deletes_the_draft(self):
        store = FakeStore()
        store.fail_upload = 'MeshService64.exe'
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'HTTP 502'):
            TOOL.publish(store, self.build, self.pins, self.build_folder(), log=self.log)
        self.assertEqual(store.releases, {})
        self.assertIn(('delete', self.tag), store.calls)
        self.assertNotIn(('publish', self.tag), store.calls)


class CommandLineTests(Fixture):
    def run_main(self, argv, environ, store):
        stderr, stdout = io.StringIO(), io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            status = TOOL.main(argv, environ, store_factory=lambda repository, token: store)
        self.stdout = stdout.getvalue()
        return status, stderr.getvalue()

    def test_channels_never_fetch_each_others_release(self):
        store = FakeStore()
        tag = TOOL.publish(store, self.build, self.pins, self.build_folder(), log=self.log, channel='preview')
        self.assertTrue(tag.startswith('meshagent-preview-'))
        TOOL.fetch(store, self.build, self.pins, self.root / 'preview', log=self.log, channel='preview')
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'has no release ' + self.tag + ' for the pinned production'):
            TOOL.fetch(store, self.build, self.pins, self.root / 'production', log=self.log)
        environ = {TOOL.TOKEN_VARIABLE: TOKEN}
        pins = self.write_pins(pins_document())
        status, error = self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'cli'),
                                       '--channel', 'preview'], environ, store)
        self.assertEqual((status, error), (0, ''))
        with self.assertRaises(SystemExit):
            self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'bad'),
                           '--channel', 'staging'], environ, store)

    def test_failure_is_annotated_under_github_actions(self):
        pins = self.write_pins(pins_document())
        files = {name: data for name, data in BUILDS.items() if name != 'MeshService.exe'}
        status, error = self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'out')],
                                      {TOOL.TOKEN_VARIABLE: TOKEN, 'GITHUB_ACTIONS': 'true'}, self.published_store(files))
        self.assertEqual(status, 1)
        self.assertIn('lacks pinned asset(s): MeshService.exe', error)
        self.assertRegex(self.stdout, r'(?m)^::error title=Pinned agent builds::agent builds: release .* lacks pinned asset')

    def test_missing_token_fails_and_names_the_variable(self):
        pins = self.write_pins(pins_document())
        for environ in ({}, {TOOL.TOKEN_VARIABLE: '  '}):
            status, error = self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'out')],
                                          environ, self.published_store())
            self.assertEqual(status, 1)
            self.assertIn(f'{TOOL.TOKEN_VARIABLE} is not set', error)
        self.assertFalse((self.root / 'out').exists())

    def test_fetch_and_failure_exit_codes(self):
        pins = self.write_pins(pins_document())
        environ = {TOOL.TOKEN_VARIABLE: TOKEN}
        status, error = self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'ok')],
                                      environ, self.published_store())
        self.assertEqual((status, error), (0, ''))
        status, error = self.run_main(['fetch', '--store', STORE, '--pins', str(pins), '--output', str(self.root / 'none')],
                                      environ, FakeStore())
        self.assertEqual(status, 1)
        self.assertIn('has no release', error)
        self.assertNotIn(TOKEN, error)


class FakeResponse(io.BytesIO):
    def __init__(self, data=b''):
        super().__init__(data)
        self.status = 200


class GitHubStoreTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.answers = {}

    def opener(self, request, timeout):
        self.requests.append(request)
        answer = self.answers.get((request.get_method(), request.full_url))
        if isinstance(answer, int):
            raise urllib.error.HTTPError(request.full_url, answer, 'Fixture', {}, None)
        if answer is None:
            raise AssertionError(f'unexpected request {request.get_method()} {request.full_url}')
        return FakeResponse(answer)

    def test_token_is_sent_only_to_the_api_and_never_redirected(self):
        store = TOOL.GitHubStore(STORE, TOKEN, opener=self.opener)
        url = f'{TOOL.API}/repos/{STORE}/releases/assets/7'
        self.answers[('GET', url)] = b'bytes'
        chunks = []
        store.download({'id': 7, 'name': 'MeshService.exe'}, chunks.append)
        self.assertEqual(b''.join(chunks), b'bytes')
        request = self.requests[-1]
        self.assertEqual(request.get_header('Accept'), 'application/octet-stream')
        self.assertEqual(request.unredirected_hdrs.get('Authorization'), 'Bearer ' + TOKEN)
        self.assertNotIn('Authorization', request.headers)

    def test_inaccessible_store_and_http_errors_name_the_problem_without_the_token(self):
        store = TOOL.GitHubStore(STORE, TOKEN, opener=self.opener)
        self.answers[('GET', f'{TOOL.API}/repos/{STORE}')] = 404
        with self.assertRaisesRegex(TOOL.AgentBuildError, f'cannot read {STORE}') as caught:
            store.check_access()
        self.assertNotIn(TOKEN, str(caught.exception))
        self.answers[('GET', f'{TOOL.API}/repos/{STORE}')] = 401
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'HTTP 401') as caught:
            store.check_access()
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_release_lookup(self):
        store = TOOL.GitHubStore(STORE, TOKEN, opener=self.opener)
        self.answers[('GET', f'{TOOL.API}/repos/{STORE}/releases/tags/meshagent-x')] = 404
        self.assertIsNone(store.release('meshagent-x'))
        self.answers[('GET', f'{TOOL.API}/repos/{STORE}/releases/tags/meshagent-y')] = b'{"id": 3, "assets": []}'
        self.assertEqual(store.release('meshagent-y'), {'id': 3, 'assets': []})
        self.answers[('GET', f'{TOOL.API}/repos/{STORE}/releases/tags/meshagent-z')] = 500
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'HTTP 500'):
            store.release('meshagent-z')

    def test_invalid_store_and_empty_token_are_refused(self):
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'invalid store repository'):
            TOOL.GitHubStore('hook', TOKEN)
        with self.assertRaisesRegex(TOOL.AgentBuildError, 'is empty'):
            TOOL.GitHubStore(STORE, '')


if __name__ == '__main__':
    unittest.main()
