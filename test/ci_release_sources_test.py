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


class SourceSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.event = self.root / 'event.json'
        self.output = self.root / 'output'
        self.heads = {'owner/MeshAgent': 'a' * 40, 'owner/MeshCentral': 'b' * 40, 'owner/hook': 'c' * 40}
        event = {'repository': {'default_branch': 'main'},
                 'client_payload': {'repository': 'owner/MeshAgent', 'sha': 'a' * 40}}
        self.event.write_text(json.dumps(event))
        environment = {'GITHUB_REPOSITORY': 'owner/hook', 'GITHUB_SHA': 'c' * 40,
                       'MESHAGENT_REPOSITORY': 'owner/MeshAgent', 'MESHAGENT_SHA': 'a' * 40,
                       'MESHCENTRAL_REPOSITORY': 'owner/MeshCentral', 'RUNTIME_COMPONENT_REPOSITORY': 'owner/hook',
                       'GITHUB_EVENT_NAME': 'repository_dispatch', 'GITHUB_EVENT_PATH': str(self.event),
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_OUTPUT': str(self.output), 'AUTO_DEPLOY': 'true',
                       'MESHCENTRAL_SHA': 'b' * 40, 'RUNTIME_COMPONENT_SHA': 'c' * 40}
        for patch in (mock.patch.dict(os.environ, environment), mock.patch.object(SOURCES, 'head', side_effect=self.heads.__getitem__)):
            patch.start()
            self.addCleanup(patch.stop)

    def invoke(self, *arguments):
        with mock.patch.object(sys, 'argv', ['resolve', *arguments]):
            SOURCES.main()

    def test_repository_head_requires_main_as_default_branch(self):
        with mock.patch.object(SOURCES, 'api', side_effect=[{'default_branch': 'master'}]):
            with self.assertRaisesRegex(ValueError, 'require main'):
                RESOLVE_HEAD('owner/MeshAgent')

    def test_agent_event_freezes_all_sibling_commits(self):
        self.invoke()
        result = self.output.read_text()
        self.assertIn('deploy_requested=true', result)
        self.assertIn('meshagent_sha=' + 'a' * 40, result)
        self.assertIn('meshcentral_sha=' + 'b' * 40, result)
        self.assertIn('runtime_sha=' + 'c' * 40, result)
        self.assertIn('superseded=false', result)

    def test_stale_run_fails_unless_the_coordinator_reports_superseded_runs(self):
        for repository in ('owner/MeshAgent', 'owner/hook'):
            original = self.heads[repository]
            self.heads[repository] = 'd' * 40
            with self.subTest(repository=repository):
                self.output.unlink(missing_ok=True)
                with self.assertRaisesRegex(ValueError, 'stale'):
                    self.invoke()
                self.assertFalse(self.output.exists())
                with mock.patch.dict(os.environ, {'REPORT_SUPERSEDED': 'true'}):
                    self.invoke()
                result = self.output.read_text()
                self.assertIn('deploy_requested=false', result)
                self.assertIn('superseded=true', result)
            self.heads[repository] = original

    def test_invalid_dispatch_never_produces_deploy_output(self):
        for repository, sha in [('outside/repo', 'c' * 40), ('owner/MeshAgent', 'not-a-sha')]:
            self.event.write_text(json.dumps({'repository': {'default_branch': 'main'},
                                            'client_payload': {'repository': repository, 'sha': sha}}))
            with self.assertRaises(ValueError):
                self.invoke()
            self.assertFalse(self.output.exists())

    def test_out_of_order_notification_builds_current_sources(self):
        self.event.write_text(json.dumps({'repository': {'default_branch': 'main'},
                                         'client_payload': {'repository': 'owner/MeshAgent', 'sha': 'd' * 40}}))
        self.invoke()
        self.assertIn('meshagent_sha=' + 'a' * 40, self.output.read_text())

    def test_each_newer_repository_head_blocks_stale_promotion(self):
        self.invoke('--check-current')
        for repository in self.heads:
            original = self.heads[repository]
            self.heads[repository] = 'd' * 40
            with self.subTest(repository=repository), self.assertRaisesRegex(ValueError, 'newer'):
                self.invoke('--check-current')
            self.heads[repository] = original

    def test_reporting_coordinator_gets_current_flag_instead_of_failure(self):
        with mock.patch.dict(os.environ, {'REPORT_SUPERSEDED': 'true'}):
            self.invoke('--check-current')
            self.assertEqual(self.output.read_text(), 'current=true\n')
            for repository in self.heads:
                original = self.heads[repository]
                self.heads[repository] = 'd' * 40
                with self.subTest(repository=repository):
                    self.output.unlink()
                    self.invoke('--check-current')
                    self.assertEqual(self.output.read_text(), 'current=false\n')
                self.heads[repository] = original


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
