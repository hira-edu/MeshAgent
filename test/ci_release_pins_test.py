"""Offline tests for tools/deployment/release_pins.py: the coordinated release's agent-build plan and the
MeshCentral pin/lock commits. No network and no real pack: a disposable git repository stands in for
MeshCentral and a deterministic stand-in replaces pack.js (the tarball changes exactly when packaged
content or the pins change, as pack.js's does)."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_pins', ROOT / 'tools/deployment/release_pins.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
BUILDS = TOOL.builds

MESHAGENT = 'a' * 40
OTHER_MESHAGENT = 'd' * 40
RUNTIME = 'c' * 40
OTHER_RUNTIME = 'e' * 40
MESHCENTRAL = 'hira-edu/MeshCentral'
HOOK = 'hira-edu/hook'
RUN_URL = 'https://github.com/hira-edu/hook/actions/runs/123/attempts/1'
STORE = 'hira-edu/hook'
GIT_IDENTITY = {'GIT_AUTHOR_NAME': 'release-fixture[bot]', 'GIT_AUTHOR_EMAIL': 'release-fixture@example.invalid',
                'GIT_COMMITTER_NAME': 'release-fixture[bot]', 'GIT_COMMITTER_EMAIL': 'release-fixture@example.invalid'}


def pins_document(commit=MESHAGENT, seed='one'):
    files = []
    for name in ('MeshService.exe', 'MeshService64.exe', 'MeshServiceARM64.exe'):
        data = (name + seed).encode() * 40
        files.append({'filename': name, 'size': len(data), 'sha384': hashlib.sha384(data).hexdigest()})
    return {'schema': BUILDS.SCHEMA, 'build': {'repository': 'hira-edu/MeshAgent', 'commit': commit}, 'files': files}


PREVIEW_DIGESTS = set()


def preview_document(commit=MESHAGENT, seed='one'):
    """Pins of a preview-variant build, as the fake pins_channel below recognises them."""
    document = pins_document(commit, 'preview-' + seed)
    PREVIEW_DIGESTS.update(entry['sha384'] for entry in document['files'])
    return document


def fake_pins_channel(build, pins):
    return 'preview' if pins[0]['sha384'] in PREVIEW_DIGESTS else 'production'


def with_variants():
    """agent_build_release.py with preview variant support (the preview-agent interface)."""
    return mock.patch.object(BUILDS, 'pins_channel', fake_pins_channel, create=True)


def pins_text(document):
    return json.dumps(document, indent=2) + '\n'


def parsed(document):
    return BUILDS.parse_pins(document, 'fixture')


def record_message(document, runtime=RUNTIME, meshagent=None, channel='production'):
    build, pins = parsed(document)
    return ('Pin\n\nbody\n\n'
            f'Agent-Build-Release: {BUILDS.release_tag(build, pins)}\n'
            f'Agent-Build-MeshAgent: {meshagent or build["commit"]}\n'
            f'Agent-Build-Runtime: {runtime}\n'
            f'Release-Pipeline-Run: {RUN_URL}\n'
            f'Release-Pipeline-Channel: {channel}\n')


class RecordTests(unittest.TestCase):
    def test_trailers_are_the_last_paragraph_of_key_value_lines(self):
        self.assertEqual(TOOL.trailers('Subject\n\nBody text\n\nA-B: 1\nC: two words\n'),
                         {'A-B': '1', 'C': 'two words'})
        self.assertEqual(TOOL.trailers('Subject\n\nA: 1\nnot a trailer\n'), {})
        self.assertEqual(TOOL.trailers('Subject\n\nA: 1\nA: 2\n'), {})
        self.assertEqual(TOOL.trailers(''), {})

    def test_build_runtime_requires_the_record_of_exactly_these_pins(self):
        document = pins_document()
        build, pins = parsed(document)
        self.assertEqual(TOOL.build_runtime(record_message(document), build, pins), RUNTIME)
        self.assertIsNone(TOOL.build_runtime(record_message(pins_document(seed='two')), build, pins))
        self.assertIsNone(TOOL.build_runtime(record_message(document, meshagent=OTHER_MESHAGENT), build, pins))
        self.assertIsNone(TOOL.build_runtime(record_message(document, runtime='not-a-sha'), build, pins))
        self.assertIsNone(TOOL.build_runtime('Agent pins by hand\n', build, pins))

    def test_keep_pinned_always_reuses(self):
        build, _ = parsed(pins_document())
        self.assertEqual(TOOL.decide('keep-pinned', build, None, OTHER_MESHAGENT, OTHER_RUNTIME), ('reuse', []))

    def test_rebuild_on_change_rebuilds_only_when_a_build_input_moved(self):
        build, _ = parsed(pins_document())
        self.assertEqual(TOOL.decide('rebuild-on-change', build, RUNTIME, MESHAGENT, RUNTIME), ('reuse', []))
        action, reasons = TOOL.decide('rebuild-on-change', build, RUNTIME, OTHER_MESHAGENT, RUNTIME)
        self.assertEqual(action, 'rebuild')
        self.assertIn('MeshAgent main is ' + OTHER_MESHAGENT, reasons[0])
        action, reasons = TOOL.decide('rebuild-on-change', build, RUNTIME, MESHAGENT, OTHER_RUNTIME)
        self.assertEqual(action, 'rebuild')
        self.assertIn('hook main is ' + OTHER_RUNTIME, reasons[0])
        action, reasons = TOOL.decide('rebuild-on-change', build, None, MESHAGENT, RUNTIME)
        self.assertEqual(action, 'rebuild')
        self.assertIn('no pipeline record', reasons[0])

    def test_pins_of_the_other_channel_are_never_reused(self):
        build, _ = parsed(pins_document())
        # A preview release always rebuilds on change, whatever the production policy says.
        self.assertEqual(TOOL.decide('keep-pinned', build, RUNTIME, MESHAGENT, RUNTIME, 'preview', 'preview'),
                         ('reuse', []))
        action, reasons = TOOL.decide('keep-pinned', build, RUNTIME, OTHER_MESHAGENT, RUNTIME, 'preview', 'preview')
        self.assertEqual(action, 'rebuild')
        self.assertIn('MeshAgent of the preview channel is ' + OTHER_MESHAGENT, reasons[0])
        # Production pins in a preview release (MeshCentral has no preview branch yet): rebuild.
        action, reasons = TOOL.decide('keep-pinned', build, RUNTIME, MESHAGENT, RUNTIME, 'preview', 'production')
        self.assertEqual(action, 'rebuild')
        self.assertIn('MeshCentral pins a production agent build; this is a preview release', reasons[0])
        # Preview pins on MeshCentral main: rebuild-on-change rebuilds, keep-pinned stops with the reason.
        action, reasons = TOOL.decide('rebuild-on-change', build, RUNTIME, MESHAGENT, RUNTIME, 'production', 'preview')
        self.assertEqual(action, 'rebuild')
        self.assertIn('MeshCentral pins a preview agent build', reasons[0])
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'MeshCentral main pins a preview agent build'):
            TOOL.decide('keep-pinned', build, RUNTIME, MESHAGENT, RUNTIME, 'production', 'preview')

    def test_preview_channel_needs_variant_support(self):
        saved = BUILDS.__dict__.pop('pins_channel', None)
        try:
            self.assertEqual(TOOL.pins_channel(*parsed(pins_document())), 'production')
            TOOL.require_channel('production')
            with self.assertRaisesRegex(TOOL.ReleasePinsError, 'cannot tell them apart yet'):
                TOOL.require_channel('preview')
        finally:
            if saved is not None:
                BUILDS.pins_channel = saved
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'CHANNEL must be one of'):
            TOOL.require_channel('staging')
        with with_variants():
            TOOL.require_channel('preview')
            self.assertEqual(TOOL.pins_channel(*parsed(preview_document())), 'preview')


class FakeReader:
    """GitHub REST answers by path, standing in for GitHubReader."""

    def __init__(self, answers):
        self.answers = answers
        self.paths = []

    def get(self, path, what, raw=False, missing_ok=False):
        self.paths.append(path)
        for prefix, answer in self.answers.items():
            if path.startswith(prefix):
                if answer is None and missing_ok:
                    return None
                if isinstance(answer, Exception):
                    raise answer
                return pins_text(answer).encode() if raw else answer
        raise AssertionError('unexpected GitHub request ' + path)


class PlanTests(unittest.TestCase):
    def environ(self, **overrides):
        values = {'CHANNEL': 'production', 'AGENT_BUILD_POLICY': 'rebuild-on-change', 'MESHCENTRAL_REPOSITORY': MESHCENTRAL,
                  'GITHUB_REPOSITORY': HOOK, 'MESHAGENT_SHA': MESHAGENT, 'MESHCENTRAL_SHA': 'b' * 40,
                  'RUNTIME_COMPONENT_SHA': RUNTIME}
        values.update(overrides)
        return values

    def sources(self, release=None, record=None, deployed=None):
        release = release or pins_document()
        answers = {f'/repos/{MESHCENTRAL}/contents/{TOOL.PINS_PATH}?ref=' + 'b' * 40: release,
                   f'/repos/{MESHCENTRAL}/commits?': [{'sha': 'f' * 40, 'commit': {
                       'message': record if record is not None else record_message(release)}}]}
        if deployed is not None:
            answers[f'/repos/{MESHCENTRAL}/contents/{TOOL.PINS_PATH}?ref=' + '9' * 40] = deployed
        return FakeReader(answers)

    def deployments(self, entries, environment='production'):
        answers = {f'/repos/{HOOK}/deployments?environment={environment}&': [{'id': number} for number, _, _ in entries]}
        for number, state, url in entries:
            answers[f'/repos/{HOOK}/deployments/{number}/statuses'] = [{'state': state, 'environment_url': url}]
        return FakeReader(answers)

    def deployed_url(self, sha='9' * 40):
        return f'https://github.com/{MESHCENTRAL}/commit/{sha}'

    def test_policy_variable_is_required_and_named(self):
        for value in ('', 'always', None):
            environ = self.environ(AGENT_BUILD_POLICY=value) if value is not None else {
                k: v for k, v in self.environ().items() if k != 'AGENT_BUILD_POLICY'}
            with self.assertRaisesRegex(TOOL.ReleasePinsError, 'AGENT_BUILD_POLICY must be one of'):
                TOOL.plan(environ, self.sources(), self.deployments([]))

    def test_invalid_shas_and_repositories_are_refused(self):
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'MESHCENTRAL_SHA'):
            TOOL.plan(self.environ(MESHCENTRAL_SHA='main'), self.sources(), self.deployments([]))
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'GITHUB_REPOSITORY'):
            TOOL.plan(self.environ(GITHUB_REPOSITORY=''), self.sources(), self.deployments([]))

    def test_meshcentral_only_change_reuses_the_recorded_build(self):
        result = TOOL.plan(self.environ(), self.sources(), self.deployments([]))
        self.assertEqual(result['agents'], 'reuse')
        self.assertEqual(result['pinned_build'], MESHAGENT)
        self.assertEqual(result['pinned_runtime'], RUNTIME)
        build, pins = parsed(pins_document())
        self.assertEqual(result['pinned_release'], BUILDS.release_tag(build, pins))

    def test_new_meshagent_or_hook_commit_rebuilds(self):
        result = TOOL.plan(self.environ(MESHAGENT_SHA=OTHER_MESHAGENT), self.sources(), self.deployments([]))
        self.assertEqual(result['agents'], 'rebuild')
        result = TOOL.plan(self.environ(RUNTIME_COMPONENT_SHA=OTHER_RUNTIME), self.sources(), self.deployments([]))
        self.assertEqual(result['agents'], 'rebuild')
        self.assertIn('rebuilds the agents', result['fleet_notice'])
        result = TOOL.plan(self.environ(AGENT_BUILD_POLICY='keep-pinned', MESHAGENT_SHA=OTHER_MESHAGENT),
                           self.sources(), self.deployments([]))
        self.assertEqual(result['agents'], 'reuse')

    def test_pins_by_hand_rebuild_under_rebuild_on_change(self):
        result = TOOL.plan(self.environ(), self.sources(record='Agent pins by hand\n'), self.deployments([]))
        self.assertEqual(result['agents'], 'rebuild')
        self.assertEqual(result['pinned_runtime'], '')

    def test_missing_pins_fail(self):
        sources = FakeReader({f'/repos/{MESHCENTRAL}/contents/': None})
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'has no agents/agent-defaults.json'):
            TOOL.plan(self.environ(), sources, self.deployments([]))

    def test_fleet_statement_compares_with_the_last_successful_deployment(self):
        same = TOOL.plan(self.environ(), self.sources(deployed=pins_document()),
                         self.deployments([(7, 'success', self.deployed_url())]))
        self.assertEqual(same['fleet_update'], 'no')
        changed = TOOL.plan(self.environ(), self.sources(deployed=pins_document(commit=OTHER_MESHAGENT, seed='old')),
                            self.deployments([(8, 'failure', ''), (7, 'success', self.deployed_url())]))
        self.assertEqual(changed['fleet_update'], 'yes')
        self.assertIn('FLEET UPDATE', changed['fleet_notice'])
        self.assertIn(OTHER_MESHAGENT[:12], changed['fleet_notice'])
        self.assertIn('enable_fleet_update', changed['fleet_notice'])
        none = TOOL.plan(self.environ(), self.sources(), self.deployments([(8, 'failure', '')]))
        self.assertEqual(none['fleet_update'], 'unknown')
        self.assertIn('no successful production deployment', none['fleet_notice'])
        unrecorded = TOOL.plan(self.environ(), self.sources(), self.deployments([(6, 'success', '')]))
        self.assertEqual(unrecorded['fleet_update'], 'unknown')
        self.assertIn('did not record its MeshCentral commit', unrecorded['fleet_notice'])
        foreign = TOOL.plan(self.environ(), self.sources(),
                            self.deployments([(6, 'success', 'https://github.com/other/repo/commit/' + '9' * 40)]))
        self.assertEqual(foreign['fleet_update'], 'unknown')

    def test_main_writes_outputs_summary_and_annotates_a_fleet_update(self):
        with tempfile.TemporaryDirectory() as folder:
            output, summary = Path(folder) / 'output', Path(folder) / 'summary'
            environ = dict(self.environ(), GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                           GITHUB_ACTIONS='true', SOURCES_TOKEN='x', DEPLOYMENTS_TOKEN='y')
            readers = iter([self.sources(), self.deployments([])])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = TOOL.main(['plan'], environ, reader_factory=lambda token, what: next(readers))
            self.assertEqual(code, 0)
            values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertEqual(values['agents'], 'reuse')
            self.assertEqual(values['fleet_update'], 'unknown')
            self.assertIn('::warning title=Fleet update::', stdout.getvalue())
            self.assertIn('### Fleet', summary.read_text())

    def test_main_failure_is_annotated_and_exits_1(self):
        environ = dict(self.environ(AGENT_BUILD_POLICY=''), GITHUB_ACTIONS='true', SOURCES_TOKEN='x',
                       DEPLOYMENTS_TOKEN='y')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = TOOL.main(['plan'], environ,
                             reader_factory=lambda token, what: self.sources())
        self.assertEqual(code, 1)
        self.assertIn('::error title=Release pins::', stdout.getvalue())

    def test_preview_release_reads_preview_pins_and_preview_deployments(self):
        with with_variants():
            release = preview_document()
            result = TOOL.plan(self.environ(CHANNEL='preview', AGENT_BUILD_POLICY='keep-pinned'),
                               self.sources(release=release, record=record_message(release, channel='preview'),
                                            deployed=release),
                               self.deployments([(3, 'success', self.deployed_url())], environment='preview'))
            self.assertEqual((result['channel'], result['pinned_channel'], result['agents']),
                             ('preview', 'preview', 'reuse'))
            self.assertEqual(result['fleet_update'], 'no')
            self.assertIn('preview channel', TOOL.plan_summary(result))
            # Production pins (MeshCentral main as the preview fallback) are rebuilt as the preview variant.
            fallback = TOOL.plan(self.environ(CHANNEL='preview'), self.sources(),
                                 self.deployments([], environment='preview'))
            self.assertEqual(fallback['agents'], 'rebuild')
            self.assertIn('no successful preview deployment', fallback['fleet_notice'])
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'cannot tell them apart yet'):
            TOOL.plan(self.environ(CHANNEL='preview'), self.sources(), self.deployments([], environment='preview'))

    def test_reader_refuses_a_missing_token(self):
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'no token to read MeshCentral'):
            TOOL.GitHubReader('', 'MeshCentral')


def git(repository, *args):
    return subprocess.run(['git', '-C', str(repository), *args], check=True, capture_output=True, text=True,
                          env=dict(os.environ, **GIT_IDENTITY)).stdout


class FakePack:
    """pack.js stand-in: the tarball depends on the last commit outside deploy/ and on the pins."""

    def __init__(self):
        self.calls = []
        self.drift = None

    def __call__(self, clone, agents):
        head = git(clone, 'rev-parse', 'HEAD').strip()
        packaged = git(clone, 'log', '-1', '--format=%H', '--', '.', ':(exclude)deploy').strip()
        pins = (Path(clone) / TOOL.PINS_PATH).read_bytes()
        self.calls.append(head)
        digest = hashlib.sha512(packaged.encode() + pins + (self.drift or '').encode()).digest()
        build, files = BUILDS.parse_pins(json.loads(pins), 'pack')
        return {'tarball': 'deploy/dist/meshcentral-1.3.1.tgz', 'version': '1.3.1', 'commit': head,
                'integrity': 'sha512-' + base64.b64encode(digest).decode(), 'packagedCommit': packaged,
                'agentBuild': build, 'agents': list(reversed(files)), 'platform': 'linux', 'node': 'v24.22.1',
                'npm': '11.19.1'}


PACKAGE = {'name': 'meshcentral', 'version': '1.3.1', 'license': 'Apache-2.0', 'bin': {'meshcentral': 'bin/meshcentral'},
           'dependencies': {'express': '4.22.2'}, 'engines': {'node': '>=20.0.0'}}


class RelockTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.clone = self.root / 'MeshCentral'
        self.agents = self.root / 'agent-builds'
        self.agents.mkdir()
        for patch in (mock.patch.dict(os.environ, GIT_IDENTITY),):
            patch.start()
            self.addCleanup(patch.stop)
        self.pack = FakePack()
        subprocess.run(['git', 'init', '--quiet', '--initial-branch=main', str(self.clone)], check=True)
        (self.clone / 'agents').mkdir()
        (self.clone / 'deploy').mkdir()
        (self.clone / 'package.json').write_text(json.dumps(PACKAGE, indent=2) + '\n')
        (self.clone / 'meshcentral.js').write_text('// server\n')
        (self.clone / TOOL.PINS_PATH).write_text(pins_text(pins_document()))
        (self.clone / TOOL.DEPLOY_PACKAGE_PATH).write_text(json.dumps(
            {'name': 'meshcentral-deploy', 'dependencies': {'meshcentral': 'file:dist/meshcentral-1.3.1.tgz'}}) + '\n')
        self.write_lock('sha512-' + 'A' * 86 + '==')
        git(self.clone, 'add', '-A')
        git(self.clone, 'commit', '--quiet', '-m', 'Content\n\nAgent pins by hand')
        self.lock_to_pack('Lock by hand')
        self.base = self.head()
        self.pack.calls.clear()

    def write_lock(self, integrity, entry_overrides=None):
        entry = {'version': '1.3.1', 'resolved': 'file:dist/meshcentral-1.3.1.tgz', 'integrity': integrity,
                 'license': 'Apache-2.0', 'dependencies': {'express': '4.22.2'},
                 'bin': {'meshcentral': 'bin/meshcentral'}, 'engines': {'node': '>=20.0.0'}}
        entry.update(entry_overrides or {})
        lock = {'name': 'meshcentral-deploy', 'lockfileVersion': 3, 'packages': {
            '': {'dependencies': {'meshcentral': 'file:dist/meshcentral-1.3.1.tgz'}},
            'node_modules/meshcentral': entry,
            'node_modules/express': {'version': '4.22.2', 'integrity': 'sha512-' + 'B' * 86 + '=='}}}
        (self.clone / TOOL.LOCK_PATH).write_text(json.dumps(lock, indent=2) + '\n')

    def lock_to_pack(self, message):
        self.write_lock(self.pack(self.clone, self.agents)['integrity'])
        git(self.clone, 'commit', '--quiet', '-am', message)

    def head(self):
        return git(self.clone, 'rev-parse', 'HEAD').strip()

    def pins_file(self, document):
        path = self.root / 'release-pins.json'
        path.write_text(pins_text(document))
        return path

    def relock(self, document=None, expect_head=None, meshagent=MESHAGENT, runtime=RUNTIME, channel='production'):
        return TOOL.relock(self.clone, self.pins_file(document or pins_document()), self.agents,
                           expect_head or self.head(), meshagent, runtime, RUN_URL, STORE, pack=self.pack,
                           log=lambda message: None, channel=channel)

    def locked(self):
        return json.loads((self.clone / TOOL.LOCK_PATH).read_text())['packages'][TOOL.LOCK_ENTRY]['integrity']

    def test_consistent_pins_and_lock_commit_nothing(self):
        result = self.relock()
        self.assertFalse(result['changed'])
        self.assertEqual(result['meshcentral_sha'], self.base)
        self.assertEqual(self.head(), self.base)
        self.assertEqual(self.pack.calls, [self.base])

    def test_packaged_change_without_lock_gets_a_lock_commit_only(self):
        (self.clone / 'meshcentral.js').write_text('// server, changed\n')
        git(self.clone, 'commit', '--quiet', '-am', 'Change the server')
        human = self.head()
        old_lock = (self.clone / TOOL.LOCK_PATH).read_text()
        result = self.relock()
        self.assertTrue(result['changed'])
        self.assertFalse(result['pins_changed'])
        self.assertTrue(result['lock_changed'])
        self.assertEqual(git(self.clone, 'rev-parse', 'HEAD~1').strip(), human)
        self.assertEqual(git(self.clone, 'diff', '--name-only', 'HEAD~1', 'HEAD').split(), [TOOL.LOCK_PATH])
        new_lock = (self.clone / TOOL.LOCK_PATH).read_text()
        self.assertEqual(len([1 for a, b in zip(old_lock.splitlines(), new_lock.splitlines()) if a != b]), 1)
        self.assertEqual(self.locked(), result['integrity'])
        message = git(self.clone, 'log', '-1', '--format=%B')
        self.assertEqual(TOOL.trailers(message), {TOOL.TRAILER_LOCK: result['integrity'], TOOL.TRAILER_RUN: RUN_URL,
                                                  TOOL.TRAILER_CHANNEL: 'production'})
        # The pushed head reproduces: the next release finds the lock consistent and commits nothing.
        self.assertFalse(self.relock()['changed'])

    def test_new_build_gets_a_pin_commit_then_a_lock_commit_with_its_record(self):
        document = pins_document(commit=OTHER_MESHAGENT, seed='two')
        result = self.relock(document, meshagent=OTHER_MESHAGENT, runtime=OTHER_RUNTIME)
        self.assertTrue(result['pins_changed'] and result['lock_changed'])
        pin_commit = git(self.clone, 'rev-parse', 'HEAD~1').strip()
        self.assertEqual(git(self.clone, 'rev-parse', 'HEAD~2').strip(), self.base)
        self.assertEqual(git(self.clone, 'diff', '--name-only', 'HEAD~2', 'HEAD~1').split(), [TOOL.PINS_PATH])
        self.assertEqual((self.clone / TOOL.PINS_PATH).read_text(), pins_text(document))
        build, pins = parsed(document)
        record = TOOL.trailers(git(self.clone, 'log', '-1', '--format=%B', pin_commit))
        self.assertEqual(record, {TOOL.TRAILER_RELEASE: BUILDS.release_tag(build, pins),
                                  TOOL.TRAILER_MESHAGENT: OTHER_MESHAGENT, TOOL.TRAILER_RUNTIME: OTHER_RUNTIME,
                                  TOOL.TRAILER_RUN: RUN_URL, TOOL.TRAILER_CHANNEL: 'production'})
        # The plan reads the same record back and reuses the build next time.
        self.assertEqual(TOOL.build_runtime(git(self.clone, 'log', '-1', '--format=%B', '--', TOOL.PINS_PATH),
                                            build, pins), OTHER_RUNTIME)
        # Packed at the pin commit (modules dated by it), then again at the lock commit.
        self.assertEqual(self.pack.calls[-2:], [pin_commit, self.head()])
        self.assertFalse(self.relock(document, meshagent=OTHER_MESHAGENT, runtime=OTHER_RUNTIME)['changed'])

    def test_a_build_of_another_meshagent_commit_is_not_pinned(self):
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'refusing to pin a build of MeshAgent ' + OTHER_MESHAGENT):
            self.relock(pins_document(commit=OTHER_MESHAGENT, seed='two'))
        self.assertEqual(self.head(), self.base)

    def test_loop_guard_refuses_a_second_pin_of_the_same_sources(self):
        first = pins_document(commit=OTHER_MESHAGENT, seed='two')
        self.relock(first, meshagent=OTHER_MESHAGENT, runtime=OTHER_RUNTIME)
        head = self.head()
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'loop guard: MeshCentral already pins'):
            self.relock(pins_document(commit=OTHER_MESHAGENT, seed='three'), meshagent=OTHER_MESHAGENT,
                        runtime=OTHER_RUNTIME)
        self.assertEqual(self.head(), head)
        # A newer hook commit is a new build input: pinning its build is allowed.
        self.assertTrue(self.relock(pins_document(commit=OTHER_MESHAGENT, seed='three'), meshagent=OTHER_MESHAGENT,
                                    runtime=RUNTIME)['pins_changed'])

    def test_channels_never_mix_and_the_loop_guard_is_per_channel(self):
        with with_variants():
            # A production release refuses preview pins, and the reverse.
            with self.assertRaisesRegex(TOOL.ReleasePinsError, 'refusing to pin a preview agent build in a production'):
                self.relock(preview_document(commit=OTHER_MESHAGENT), meshagent=OTHER_MESHAGENT)
            with self.assertRaisesRegex(TOOL.ReleasePinsError, 'refusing to pin a production agent build in a preview'):
                self.relock(pins_document(commit=OTHER_MESHAGENT, seed='two'), meshagent=OTHER_MESHAGENT,
                            channel='preview')
            self.assertEqual(self.head(), self.base)
            # Production pins of MeshAgent X / hook Y, then the preview build of the same sources (a preview
            # release falling back to main): a different channel is a new build, not a loop.
            self.relock(pins_document(commit=OTHER_MESHAGENT, seed='two'), meshagent=OTHER_MESHAGENT,
                        runtime=OTHER_RUNTIME)
            preview = preview_document(commit=OTHER_MESHAGENT)
            result = self.relock(preview, meshagent=OTHER_MESHAGENT, runtime=OTHER_RUNTIME, channel='preview')
            self.assertTrue(result['pins_changed'])
            record = TOOL.trailers(git(self.clone, 'log', '-1', '--format=%B', '--', TOOL.PINS_PATH))
            self.assertEqual(record[TOOL.TRAILER_CHANNEL], 'preview')
            self.assertIn('Pin the preview MeshAgent build', git(self.clone, 'log', '-1', '--format=%s', '--',
                                                                 TOOL.PINS_PATH))
            with self.assertRaisesRegex(TOOL.ReleasePinsError, 'loop guard'):
                self.relock(preview_document(commit=OTHER_MESHAGENT, seed='again'), meshagent=OTHER_MESHAGENT,
                            runtime=OTHER_RUNTIME, channel='preview')
            self.assertFalse(self.relock(preview, meshagent=OTHER_MESHAGENT, runtime=OTHER_RUNTIME,
                                         channel='preview')['changed'])

    def test_loop_guard_refuses_to_relock_over_its_own_unreproducible_lock(self):
        (self.clone / 'meshcentral.js').write_text('// server, changed\n')
        git(self.clone, 'commit', '--quiet', '-am', 'Change the server')
        self.relock()
        head = self.head()
        self.pack.drift = 'nondeterministic'
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'loop guard: .* own lock commit'):
            self.relock()
        self.assertEqual(self.head(), head)
        # New pins over the pipeline's lock commit legitimately need a new lock.
        self.pack.drift = None
        self.assertTrue(self.relock(pins_document(commit=OTHER_MESHAGENT, seed='two'), meshagent=OTHER_MESHAGENT,
                                    runtime=OTHER_RUNTIME)['lock_changed'])

    def test_unreproducible_second_pack_is_not_pushed(self):
        (self.clone / 'meshcentral.js').write_text('// server, changed\n')
        git(self.clone, 'commit', '--quiet', '-am', 'Change the server')
        pack = self.pack

        def drifting(clone, agents):
            pack.drift = None if not pack.calls else 'second'
            return pack(clone, agents)
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'second Linux pack'):
            TOOL.relock(self.clone, self.pins_file(pins_document()), self.agents, self.head(), MESHAGENT, RUNTIME,
                        RUN_URL, STORE, pack=drifting, log=lambda message: None)

    def test_dependency_changes_are_left_to_a_reviewed_npm_lock(self):
        package = dict(PACKAGE, dependencies={'express': '4.22.2', 'ws': '8.0.0'})
        (self.clone / 'package.json').write_text(json.dumps(package, indent=2) + '\n')
        git(self.clone, 'commit', '--quiet', '-am', 'Add a dependency')
        head = self.head()
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'more than the tarball integrity \\(dependencies\\)'):
            self.relock()
        self.assertEqual(self.head(), head)

    def test_unknown_lock_entry_fields_are_refused(self):
        self.write_lock(self.locked(), {'hasInstallScript': True})
        git(self.clone, 'commit', '--quiet', '-am', 'Lock with an install script')
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'hasInstallScript'):
            self.relock()

    def test_clone_must_be_the_resolved_clean_commit(self):
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'not the resolved'):
            self.relock(expect_head='0' * 40)
        (self.clone / 'meshcentral.js').write_text('// uncommitted\n')
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'changes to tracked files'):
            self.relock()

    def test_arguments_are_validated(self):
        with self.assertRaisesRegex(TOOL.ReleasePinsError, '--run-url'):
            TOOL.relock(self.clone, self.pins_file(pins_document()), self.agents, self.head(), MESHAGENT, RUNTIME,
                        'https://example.invalid/run', STORE, pack=self.pack)
        with self.assertRaisesRegex(TOOL.ReleasePinsError, '--meshagent-sha'):
            self.relock(meshagent='main')

    def test_pack_of_other_pins_is_refused(self):
        def wrong(clone, agents):
            record = self.pack(clone, agents)
            record['agents'] = record['agents'][:2]
            return record
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'other than the pins'):
            TOOL.relock(self.clone, self.pins_file(pins_document()), self.agents, self.head(), MESHAGENT, RUNTIME,
                        RUN_URL, STORE, pack=wrong)

    def test_pack_record_parsing(self):
        record = self.pack(self.clone, self.agents)
        text = 'deploy/dist/meshcentral-1.3.1.tgz: 3 files\n' + json.dumps(record, indent=2) + '\n'
        self.assertEqual(TOOL.pack_record(text), record)
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'no --json record'):
            TOOL.pack_record('no record')
        broken = dict(record, integrity='sha256-x')
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'not a sha512 integrity'):
            TOOL.pack_record(json.dumps(broken, indent=2))

    def test_main_relock_writes_outputs(self):
        (self.clone / 'meshcentral.js').write_text('// server, changed\n')
        git(self.clone, 'commit', '--quiet', '-am', 'Change the server')
        output = self.root / 'output'
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = TOOL.main(['relock', '--meshcentral', str(self.clone), '--pins', str(self.pins_file(pins_document())),
                              '--agents', str(self.agents), '--expect-head', self.head(), '--meshagent-sha', MESHAGENT,
                              '--runtime-sha', RUNTIME, '--run-url', RUN_URL, '--store', STORE,
                              '--channel', 'production'],
                             {'GITHUB_OUTPUT': str(output)}, pack=self.pack)
        self.assertEqual(code, 0)
        values = dict(line.split('=', 1) for line in output.read_text().splitlines())
        self.assertEqual(values['changed'], 'true')
        self.assertEqual(values['pins_changed'], 'false')
        self.assertEqual(values['meshcentral_sha'], self.head())



class ConfirmTests(unittest.TestCase):
    DIGEST = 'sha256:' + '1' * 64

    def environ(self, **overrides):
        values = {'CHANNEL': 'production', 'DEPLOY_DIGEST': self.DIGEST, 'GITHUB_REPOSITORY': HOOK,
                  'MESHAGENT_SHA': MESHAGENT, 'MESHCENTRAL_SHA': 'b' * 40, 'RUNTIME_COMPONENT_SHA': RUNTIME,
                  'PINNED_RELEASE': 'meshagent-' + MESHAGENT + '-0123456789abcdef', 'FLEET_UPDATE': 'no',
                  'FLEET_CONFIRMATION': 'unchanged', 'FLEET_NOTICE': 'Agent build unchanged'}
        values.update(overrides)
        return values

    def labels(self, **overrides):
        values = {TOOL.LABEL_SOURCE: 'https://github.com/' + HOOK, TOOL.LABEL_CHANNEL: 'production',
                  TOOL.LABEL_MESHAGENT: MESHAGENT, TOOL.LABEL_MESHCENTRAL: 'b' * 40, TOOL.LABEL_RUNTIME: RUNTIME,
                  TOOL.LABEL_AGENT_BUILD: 'meshagent-' + MESHAGENT + '-0123456789abcdef'}
        values.update(overrides)
        return values

    def test_the_image_of_the_current_heads_with_a_matching_confirmation_is_confirmed(self):
        text = TOOL.confirm(self.environ(), self.labels())
        self.assertIn('Deployment confirmed', text)
        self.assertIn(self.DIGEST, text)
        self.assertIn('Fleet confirmed as changed',
                      TOOL.confirm(self.environ(FLEET_UPDATE='yes', FLEET_CONFIRMATION='changed'), self.labels()))

    def test_an_image_of_other_sources_or_another_channel_is_refused(self):
        for label, value in ((TOOL.LABEL_MESHAGENT, OTHER_MESHAGENT), (TOOL.LABEL_MESHCENTRAL, '9' * 40),
                             (TOOL.LABEL_RUNTIME, OTHER_RUNTIME), (TOOL.LABEL_CHANNEL, 'preview'),
                             (TOOL.LABEL_SOURCE, 'https://github.com/other/hook'),
                             (TOOL.LABEL_AGENT_BUILD, 'meshagent-' + MESHAGENT + '-ffffffffffffffff')):
            with self.subTest(label=label), self.assertRaisesRegex(TOOL.ReleasePinsError, 'is not the production release'):
                TOOL.confirm(self.environ(), self.labels(**{label: value}))
        missing = self.labels()
        del missing[TOOL.LABEL_CHANNEL]
        with self.assertRaisesRegex(TOOL.ReleasePinsError, TOOL.LABEL_CHANNEL):
            TOOL.confirm(self.environ(), missing)
        with self.assertRaisesRegex(TOOL.ReleasePinsError, 'has no labels'):
            TOOL.confirm(self.environ(), None)

    def test_the_fleet_confirmation_must_match_the_plan(self):
        for fleet, wrong in (('no', 'changed'), ('yes', 'unchanged'), ('unknown', 'unchanged'), ('no', '')):
            with self.subTest(fleet=fleet), self.assertRaisesRegex(TOOL.ReleasePinsError, 'fleet_update was confirmed'):
                TOOL.confirm(self.environ(FLEET_UPDATE=fleet, FLEET_CONFIRMATION=wrong), self.labels())
        TOOL.confirm(self.environ(FLEET_UPDATE='unknown', FLEET_CONFIRMATION='changed'), self.labels())

    def test_inputs_are_validated(self):
        for key, value, reason in (('DEPLOY_DIGEST', 'latest', 'DEPLOY_DIGEST'), ('CHANNEL', '', 'CHANNEL'),
                                   ('MESHCENTRAL_SHA', 'main', 'MESHCENTRAL_SHA'), ('PINNED_RELEASE', '', 'PINNED_RELEASE'),
                                   ('FLEET_UPDATE', 'maybe', 'FLEET_UPDATE')):
            with self.subTest(key=key), self.assertRaisesRegex(TOOL.ReleasePinsError, reason):
                TOOL.confirm(self.environ(**{key: value}), self.labels())

    def test_main_confirm_reads_the_labels_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            labels, summary = Path(folder) / 'labels.json', Path(folder) / 'summary'
            labels.write_text(json.dumps(self.labels()))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(TOOL.main(['confirm', '--labels', str(labels)],
                                           dict(self.environ(), GITHUB_STEP_SUMMARY=str(summary))), 0)
            self.assertIn('Deployment confirmed', summary.read_text())
            labels.write_text('not json')
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(TOOL.main(['confirm', '--labels', str(labels)], self.environ()), 1)


if __name__ == '__main__':
    unittest.main()
