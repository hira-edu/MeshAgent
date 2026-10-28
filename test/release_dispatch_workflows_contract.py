"""The public repositories' requests for the coordinated release in hook (docs/DEPLOYMENT.md).

A push to MeshAgent main (.github/workflows/build-release.yml) or MeshCentral main
(.github/workflows/request-release.yml, in the MeshCentral fork checkout located by
test/lib/meshcentral_paths.py) dispatches sibling-source-updated with the pushed commit to hook, using a
short-lived release-app token that can write hook contents only. A missing app credential fails with a
named reason, and the release-app's own pin/lock pushes to MeshCentral dispatch like any other push: the
release they start is the one that ships them (loops are refused in hook, by release_pins.py relock).
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'test' / 'lib'))
import meshcentral_paths  # noqa: E402

CHECK = '      - name: Require the release app credential\n'
TOKEN = '      - name: Create a short-lived dispatch token\n'


def read(path):
    return Path(path).read_text(encoding='utf-8-sig').replace('\r\n', '\n')


class DispatchWorkflowContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {
            'MeshAgent build-release.yml': read(ROOT / '.github/workflows/build-release.yml'),
            'MeshCentral request-release.yml': read(
                meshcentral_paths.meshcentral_root() / '.github/workflows/request-release.yml'),
        }

    def each(self):
        return [(name, source, source.split('\n  dispatch:\n', 1)[1]) for name, source in self.workflows.items()]

    def test_main_pushes_and_manual_runs_request_a_release(self):
        for name, source, dispatch in self.each():
            with self.subTest(workflow=name):
                self.assertRegex(source, r'(?m)^  push:\n    branches: \[main\]$')
                self.assertRegex(source, r'(?m)^  workflow_dispatch:$')
                self.assertIn("github.ref == 'refs/heads/main'", dispatch)
                self.assertIn("github.event.repository.default_branch == 'main'", dispatch)
                self.assertIn('permissions:\n  contents: read\n', source)
                self.assertIn('  cancel-in-progress: false\n', source)

    def test_missing_app_credential_fails_with_a_named_reason(self):
        for name, source, dispatch in self.each():
            with self.subTest(workflow=name):
                self.assertIn(CHECK, dispatch)
                check = dispatch.split(CHECK, 1)[1].split('\n      - name:', 1)[0]
                self.assertIn('RELEASE_APP_ID: ${{ vars.RELEASE_APP_ID }}', check)
                self.assertIn("RELEASE_APP_PRIVATE_KEY_SET: ${{ secrets.RELEASE_APP_PRIVATE_KEY != '' }}", check)
                self.assertIn('::error title=Release dispatch::', check)
                self.assertIn('exit 1', check)
                self.assertLess(dispatch.index(CHECK), dispatch.index(TOKEN))
                self.assertNotIn('|| github.token', source)
                self.assertNotIn('continue-on-error', source)

    def test_dispatch_token_writes_hook_only_and_sends_the_pushed_commit(self):
        for name, source, dispatch in self.each():
            with self.subTest(workflow=name):
                token = dispatch.split(TOKEN, 1)[1].split('\n      - name:', 1)[0]
                self.assertIn('repositories: hook\n', token)
                self.assertIn('permission-contents: write', token)
                self.assertEqual(len(re.findall(r'permission-[a-z-]+:', source)), 1)
                self.assertIn("'event_type': 'sibling-source-updated'", dispatch)
                self.assertIn("'repository': os.environ['GITHUB_REPOSITORY'], 'sha': os.environ['GITHUB_SHA']", dispatch)
                self.assertIn('gh api --method POST "repos/$COORDINATOR/dispatches" --input request.json', dispatch)

    def test_pipeline_commits_dispatch_like_any_push(self):
        # The release app's pin/lock commits to MeshCentral start the release that ships them.
        for name, source, dispatch in self.each():
            with self.subTest(workflow=name):
                self.assertNotIn('github.actor', source)
                self.assertNotIn('[bot]', source)


if __name__ == '__main__':
    unittest.main()
