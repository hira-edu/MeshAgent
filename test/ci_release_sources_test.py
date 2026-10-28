"""Exercise sibling source selection and safe synchronization using disposable repos."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCES = load('sources', 'tools/resolve_deploy_sources.py')
RESOLVE_HEAD = SOURCES.head
SYNC = load('sync', 'tools/sync_sibling_repos.py')
SEND = load('send_release', 'tools/deployment/send_release.py')


AGENT, CENTRAL, HOOK = 'owner/MeshAgent', 'owner/MeshCentral', 'owner/hook'


class SourceSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.event = self.root / 'event.json'
        self.output = self.root / 'output'
        self.heads = {AGENT: 'a' * 40, CENTRAL: 'b' * 40, HOOK: 'c' * 40}
        # Preview branches: none until a test creates one.
        self.preview = {}
        self.dispatch(AGENT, 'a' * 40, 'main')
        environment = {'GITHUB_REPOSITORY': HOOK, 'GITHUB_SHA': 'c' * 40,
                       'MESHAGENT_REPOSITORY': AGENT, 'MESHCENTRAL_REPOSITORY': CENTRAL,
                       'RUNTIME_COMPONENT_REPOSITORY': HOOK,
                       'GITHUB_EVENT_NAME': 'repository_dispatch', 'GITHUB_EVENT_PATH': str(self.event),
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_OUTPUT': str(self.output),
                       'GITHUB_TRIGGERING_ACTOR': 'operator', 'CHANNEL': 'production',
                       'MESHAGENT_SHA': 'a' * 40, 'MESHCENTRAL_SHA': 'b' * 40, 'RUNTIME_COMPONENT_SHA': 'c' * 40}
        for patch in (mock.patch.dict(os.environ, environment),
                      mock.patch.object(SOURCES, 'head', side_effect=self.heads.__getitem__),
                      mock.patch.object(SOURCES, 'branch_head', side_effect=self.branch_head)):
            patch.start()
            self.addCleanup(patch.stop)

    def branch_head(self, repository, branch):
        self.assertEqual(branch, 'preview')
        return self.preview.get(repository)

    def dispatch(self, repository, sha, branch):
        payload = {'repository': repository, 'sha': sha}
        if branch is not None:
            payload['branch'] = branch
        self.event.write_text(json.dumps({'repository': {'default_branch': 'main'}, 'client_payload': payload}))

    def manual(self, ref='refs/heads/main', **inputs):
        self.event.write_text(json.dumps({'repository': {'default_branch': 'main'}, 'inputs': inputs}))
        return mock.patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': ref})

    def invoke(self, *arguments):
        with mock.patch.object(sys, 'argv', ['resolve', *arguments]):
            SOURCES.main()

    def outputs(self):
        return dict(line.split('=', 1) for line in self.output.read_text().splitlines())

    def test_repository_head_requires_main_as_default_branch(self):
        with mock.patch.object(SOURCES, 'api', side_effect=[{'default_branch': 'master'}]):
            with self.assertRaisesRegex(ValueError, 'require main'):
                RESOLVE_HEAD('owner/MeshAgent')

    def test_agent_event_freezes_all_sibling_commits_of_the_production_channel(self):
        self.preview = {AGENT: '1' * 40, CENTRAL: '2' * 40, HOOK: '3' * 40}
        self.invoke()
        result = self.outputs()
        self.assertEqual(result['channel'], 'production')
        self.assertEqual(result['mode'], 'build')
        self.assertEqual(result['meshagent_sha'], 'a' * 40)
        self.assertEqual(result['meshcentral_sha'], 'b' * 40)
        self.assertEqual(result['runtime_sha'], 'c' * 40)
        self.assertEqual(result['meshcentral_branch'], 'main')

    def test_production_builds_never_request_a_deployment(self):
        for event_name in ('repository_dispatch', 'push'):
            with self.subTest(event=event_name), mock.patch.dict(os.environ, {
                    'GITHUB_EVENT_NAME': event_name, 'AUTO_DEPLOY': 'true', 'PREVIEW_AUTO_DEPLOY': 'true'}):
                if self.output.exists():
                    self.output.unlink()
                self.invoke()
                self.assertEqual(self.outputs()['deploy_requested'], 'false')
                self.assertEqual(self.outputs()['mode'], 'build')
        with self.manual():
            self.output.unlink()
            self.invoke()
        self.assertEqual((self.outputs()['mode'], self.outputs()['deploy_requested']), ('build', 'false'))

    def test_a_person_deploys_production_by_digest_with_a_fleet_confirmation(self):
        digest = 'sha256:' + '1' * 64
        summary = self.root / 'summary'
        with self.manual(deploy_digest=digest, fleet_update='unchanged'), \
                mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            self.invoke()
        result = self.outputs()
        self.assertEqual((result['channel'], result['mode'], result['deploy_requested']), ('production', 'deploy', 'true'))
        self.assertEqual((result['deploy_digest'], result['fleet_confirmation']), (digest, 'unchanged'))
        self.assertIn('Requested deployment of `' + digest + '`', summary.read_text())

    def test_deploy_requests_fail_closed(self):
        digest = 'sha256:' + '1' * 64
        cases = [({'deploy_digest': 'latest', 'fleet_update': 'unchanged'}, {}, 'deploy_digest'),
                 ({'deploy_digest': 'sha256:' + 'A' * 64, 'fleet_update': 'unchanged'}, {}, 'deploy_digest'),
                 ({'deploy_digest': digest}, {}, 'fleet_update'),
                 ({'deploy_digest': digest, 'fleet_update': 'maybe'}, {}, 'fleet_update'),
                 ({'deploy_digest': digest, 'fleet_update': 'changed'}, {'GITHUB_TRIGGERING_ACTOR': 'release-app[bot]'},
                  'started by a person'),
                 ({'deploy_digest': digest, 'fleet_update': 'changed'}, {'GITHUB_TRIGGERING_ACTOR': ''},
                  'started by a person')]
        for inputs, environment, reason in cases:
            with self.subTest(inputs=inputs, environment=environment), self.manual(**inputs), \
                    mock.patch.dict(os.environ, environment), self.assertRaisesRegex(ValueError, reason):
                self.invoke()
            self.assertFalse(self.output.exists())

    def test_only_main_and_preview_runs_release(self):
        for ref in ('refs/tags/v1', 'refs/heads/feature', 'refs/pull/1/merge', 'refs/heads/master'):
            with self.subTest(ref=ref), self.manual(ref=ref), self.assertRaisesRegex(ValueError, 'main or preview only'):
                self.invoke()
        with mock.patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'pull_request'}), \
                self.assertRaisesRegex(ValueError, 'does not start'):
            self.invoke()
        self.event.write_text(json.dumps({'repository': {'default_branch': 'master'},
                                          'client_payload': {'repository': AGENT, 'sha': 'a' * 40, 'branch': 'main'}}))
        with self.assertRaisesRegex(ValueError, 'default branch'):
            self.invoke()
        self.assertFalse(self.output.exists())

    def test_invalid_dispatch_never_produces_output(self):
        for repository, sha, branch in [('outside/repo', 'c' * 40, 'main'), (AGENT, 'not-a-sha', 'main'),
                                        (AGENT, 'a' * 40, None), (AGENT, 'a' * 40, 'feature'), (HOOK, 'c' * 40, 'main')]:
            self.dispatch(repository, sha, branch)
            with self.subTest(repository=repository, sha=sha, branch=branch), self.assertRaisesRegex(ValueError, 'Dispatch'):
                self.invoke()
            self.assertFalse(self.output.exists())
        self.dispatch(AGENT, 'a' * 40, 'main')
        with mock.patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/preview'}), \
                self.assertRaisesRegex(ValueError, 'must run on main'):
            self.invoke()

    def test_out_of_order_notification_builds_current_sources(self):
        self.dispatch(AGENT, 'd' * 40, 'main')
        self.invoke()
        self.assertEqual(self.outputs()['meshagent_sha'], 'a' * 40)
        # The notification is recorded as the trigger; the build uses the frozen heads.
        self.assertEqual(self.outputs()['trigger'], 'repository_dispatch owner/MeshAgent@' + 'd' * 40)

    def test_trigger_and_frozen_sources_are_recorded_in_the_run_summary(self):
        summary = self.root / 'summary'
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            self.invoke()
        text = summary.read_text()
        self.assertIn('### Release sources (production channel)', text)
        for name, sha in self.heads.items():
            self.assertIn('| ' + name + ' | main | `' + sha + '` |', text)
        self.assertIn('Triggered by repository_dispatch owner/MeshAgent@' + 'a' * 40, text)
        self.assertIn('Production is never deployed by a build', text)
        self.assertNotIn('Fallback', text)

    def test_own_push_is_the_trigger(self):
        self.event.write_text(json.dumps({'repository': {'default_branch': 'main'}}))
        with mock.patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'push'}):
            self.invoke()
        self.assertEqual(self.outputs()['trigger'], 'push owner/hook@' + 'c' * 40)

    def test_preview_dispatch_takes_every_preview_branch(self):
        self.preview = {AGENT: '1' * 40, CENTRAL: '2' * 40, HOOK: '3' * 40}
        self.dispatch(CENTRAL, '2' * 40, 'preview')
        self.invoke()
        result = self.outputs()
        self.assertEqual(result['channel'], 'preview')
        self.assertEqual((result['meshagent_sha'], result['meshcentral_sha'], result['runtime_sha']),
                         ('1' * 40, '2' * 40, '3' * 40))
        self.assertEqual(result['meshcentral_branch'], 'preview')
        self.assertEqual(result['deploy_requested'], 'false')
        with mock.patch.dict(os.environ, {'PREVIEW_AUTO_DEPLOY': 'true'}):
            self.output.unlink()
            self.invoke()
        self.assertEqual((self.outputs()['mode'], self.outputs()['deploy_requested']), ('build', 'true'))

    def test_preview_falls_back_to_main_and_says_so(self):
        self.preview = {AGENT: '1' * 40}
        summary = self.root / 'summary'
        self.dispatch(AGENT, '1' * 40, 'preview')
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}):
            self.invoke()
        result = self.outputs()
        self.assertEqual((result['meshagent_sha'], result['meshcentral_sha'], result['runtime_sha']),
                         ('1' * 40, 'b' * 40, 'c' * 40))
        # Preview pins never go to MeshCentral main: the pin commits create its preview branch.
        self.assertEqual(result['meshcentral_branch'], 'preview')
        text = summary.read_text()
        self.assertIn('| owner/MeshAgent | preview | `' + '1' * 40 + '` |', text)
        self.assertIn('**Fallback:** owner/MeshCentral has no `preview` branch; this preview release uses its `main`.',
                      text)
        self.assertIn('**Fallback:** owner/hook has no `preview` branch', text)
        self.assertIn('create the `preview` branch of owner/MeshCentral', text)
        self.assertIn('PREVIEW_AUTO_DEPLOY is not true', text)

    def test_preview_push_of_hook_builds_its_own_commit(self):
        self.preview = {HOOK: '3' * 40}
        self.event.write_text(json.dumps({'repository': {'default_branch': 'main'}}))
        with mock.patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/preview',
                                          'GITHUB_SHA': '3' * 40}):
            self.invoke()
        result = self.outputs()
        self.assertEqual((result['channel'], result['runtime_sha'], result['meshagent_sha']),
                         ('preview', '3' * 40, 'a' * 40))
        self.assertEqual(result['trigger'], 'push owner/hook@' + '3' * 40)

    def test_coordinator_must_be_the_runtime_repository(self):
        with mock.patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/other'}), \
                self.assertRaisesRegex(ValueError, 'private runtime repository'):
            self.invoke()

    def test_each_newer_channel_head_blocks_stale_promotion(self):
        self.invoke('--check-current')
        for repository in self.heads:
            original = self.heads[repository]
            self.heads[repository] = 'd' * 40
            with self.subTest(repository=repository), self.assertRaisesRegex(ValueError, 'newer'):
                self.invoke('--check-current')
            self.heads[repository] = original
        # Preview: the preview branches count, and a preview branch created since the run is a newer head.
        self.preview = {AGENT: '1' * 40}
        with mock.patch.dict(os.environ, {'CHANNEL': 'preview', 'MESHAGENT_SHA': '1' * 40}):
            self.invoke('--check-current')
            self.preview[CENTRAL] = '2' * 40
            with self.assertRaisesRegex(ValueError, 'newer owner/MeshCentral commit exists on preview'):
                self.invoke('--check-current')


class ControllerCommandTests(unittest.TestCase):
    def test_each_channel_sends_only_its_controller_command(self):
        digest = 'sha256:' + 'a' * 64
        self.assertEqual(SEND.controller_command('production', digest), 'deploy ' + digest)
        self.assertEqual(SEND.controller_command('preview', digest), 'deploy-preview ' + digest)
        for channel, value in (('staging', digest), ('', digest), ('production', 'latest'),
                               ('preview', digest + '; id'), ('production', 'sha256:' + 'a' * 63)):
            with self.subTest(channel=channel, value=value), self.assertRaises(ValueError):
                SEND.controller_command(channel, value)

    def test_missing_channel_is_refused_before_ssh(self):
        environment = {'SSH_HOST': 'vps.example', 'SSH_USER': 'deploy', 'SSH_PRIVATE_KEY': 'key',
                       'SSH_KNOWN_HOSTS': 'hosts', 'RELEASE_DIGEST': 'sha256:' + 'a' * 64,
                       'REGISTRY_TOKEN': 'token', 'REGISTRY_USERNAME': 'user'}
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(SEND.subprocess, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'RELEASE_CHANNEL'):
            SEND.main()
        run.assert_not_called()


class SynchronizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.local = self.root / 'local'
        self.local.mkdir()
        self.remotes = {}
        for name in SYNC.REPOSITORIES:
            remote = self.root / (name + '-remote')
            self.git('init', '-q', '-b', 'main', str(remote))
            self.git('-C', str(remote), 'config', 'user.name', 'Fixture')
            self.git('-C', str(remote), 'config', 'user.email', 'fixture@example.invalid')
            (remote / 'file').write_text('one')
            self.git('-C', str(remote), 'add', 'file')
            self.git('-C', str(remote), 'commit', '-qm', 'one')
            self.git('clone', '-q', str(remote), str(self.local / name))
            self.remotes[name] = remote

    def git(self, *arguments):
        return subprocess.check_output(['git', *arguments], text=True).strip()

    def update_remote(self, name):
        remote = self.remotes[name]
        (remote / 'file').write_text('two')
        self.git('-C', str(remote), 'commit', '-qam', 'two')

    def test_clean_siblings_fast_forward_to_fetched_commits(self):
        for name in SYNC.REPOSITORIES:
            self.update_remote(name)
        SYNC.sync(self.local)
        for name in SYNC.REPOSITORIES:
            self.assertEqual((self.local / name / 'file').read_text(), 'two')

    def test_dirty_later_sibling_prevents_all_worktree_changes(self):
        self.update_remote('MeshAgent')
        (self.local / 'hook/untracked').write_text('keep me')
        with self.assertRaisesRegex(ValueError, 'local changes'):
            SYNC.sync(self.local)
        self.assertEqual((self.local / 'MeshAgent/file').read_text(), 'one')
        self.assertEqual((self.local / 'hook/untracked').read_text(), 'keep me')


if __name__ == '__main__':
    unittest.main()
