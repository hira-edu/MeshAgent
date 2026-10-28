"""Coordinated release: decide the agent builds, and commit the MeshCentral pins and lock from a Linux pack.

hook's coordinated-release.yml runs this tool twice per release:

    python tools/deployment/release_pins.py plan
        In resolve-sources. Decides whether this release rebuilds the Windows agents or reuses the build
        that MeshCentral agents/agent-defaults.json pins, and whether promoting the release changes the
        agent build the fleet is offered (compared with the last successful production deployment).

    python tools/deployment/release_pins.py relock --meshcentral <full clone> --pins <file> --agents <dir> ...
        In pin-release, on Linux. Makes agents/agent-defaults.json equal the given pins and
        deploy/package-lock.json lock the Linux pack of the result, as at most two local commits
        (pins, then lock), and reports whether anything changed. The workflow pushes those commits to
        MeshCentral main; that push starts the release that builds and deploys them.

Agent builds (policy from the AGENT_BUILD_POLICY variable of hook, required):
  keep-pinned        always reuse the pinned build (no fleet change from a MeshAgent or hook push).
  rebuild-on-change  rebuild when MeshAgent main is not the pinned build's commit, or hook main is not the
                     hook commit that built it. That hook commit is read from the trailers of the
                     MeshCentral commit that last changed agents/agent-defaults.json, which this tool writes:

      Agent-Build-Release: meshagent-<commit>-<pins hash>   (agent_build_release.py release tag)
      Agent-Build-MeshAgent: <MeshAgent commit>
      Agent-Build-Runtime: <hook commit>
      Release-Pipeline-Run: <run URL>

                     A pin without that record (for example one committed by hand) counts as built by an
                     unknown hook commit, so the next release rebuilds.

Loop guards: relock refuses to pin a second build of the same MeshAgent and hook commits over its own pin
commit, and refuses to re-lock over its own lock commit (a Linux pack that does not reproduce). Every
failure names its reason and exits 1; nothing is skipped.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_build_release as builds  # noqa: E402

POLICY_VARIABLE = 'AGENT_BUILD_POLICY'
POLICIES = ('rebuild-on-change', 'keep-pinned')
PINS_PATH = 'agents/agent-defaults.json'
LOCK_PATH = 'deploy/package-lock.json'
DEPLOY_PACKAGE_PATH = 'deploy/package.json'
LOCK_ENTRY = 'node_modules/meshcentral'
TRAILER_RELEASE = 'Agent-Build-Release'
TRAILER_MESHAGENT = 'Agent-Build-MeshAgent'
TRAILER_RUNTIME = 'Agent-Build-Runtime'
TRAILER_RUN = 'Release-Pipeline-Run'
TRAILER_LOCK = 'Release-Pipeline-Lock'
ENVIRONMENT = 'production'
API = 'https://api.github.com'
SHA = re.compile(r'^[0-9a-f]{40}$')
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
RUN_URL = re.compile(r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/\d+(/attempts/\d+)?$')
TRAILER_LINE = re.compile(r'^([A-Za-z0-9][A-Za-z0-9-]*): (\S.*)$')
# Fields npm copies from the packed package.json into the lock entry of a file: dependency.
DERIVED_LOCK_FIELDS = ('version', 'license', 'dependencies', 'optionalDependencies', 'peerDependencies', 'bin',
                       'engines')
LOCK_ENTRY_FIELDS = set(DERIVED_LOCK_FIELDS) | {'resolved', 'integrity'}
TIMEOUT_SECONDS = 60


class ReleasePinsError(Exception):
    """A failure the run must stop on; the message names what is wrong."""


# ---------------------------------------------------------------------------------------------------
# Commit records


def trailers(message):
    """The trailers of a commit message: its last paragraph when every line there is `Key: value`."""
    paragraphs = [part for part in re.split(r'\n\s*\n', (message or '').strip()) if part.strip()]
    if not paragraphs:
        return {}
    found = {}
    for line in paragraphs[-1].splitlines():
        match = TRAILER_LINE.match(line.strip())
        if not match or match.group(1) in found:
            return {}
        found[match.group(1)] = match.group(2).strip()
    return found


def build_runtime(message, build, pins):
    """The hook commit that built the pinned build, when message is the pipeline's record of these pins."""
    record = trailers(message)
    if (record.get(TRAILER_RELEASE) == builds.release_tag(build, pins)
            and record.get(TRAILER_MESHAGENT) == build['commit']
            and SHA.match(record.get(TRAILER_RUNTIME, ''))):
        return record[TRAILER_RUNTIME]
    return None


def decide(policy, build, runtime_record, meshagent_sha, runtime_sha):
    """('rebuild' | 'reuse', reasons): reasons say why a rebuild-on-change release rebuilds."""
    if policy == 'keep-pinned':
        return 'reuse', []
    reasons = []
    if build['commit'] != meshagent_sha:
        reasons.append(f'MeshAgent main is {meshagent_sha}; the pinned build is of {build["commit"]}')
    if runtime_record is None:
        reasons.append('the pinned build has no pipeline record of the hook commit that built it')
    elif runtime_record != runtime_sha:
        reasons.append(f'hook main is {runtime_sha}; the pinned build was built by hook {runtime_record}')
    return ('rebuild' if reasons else 'reuse'), reasons


def same_build(left, right):
    return builds.canonical_pins(*left) == builds.canonical_pins(*right)


def describe_build(build, pins):
    return f'{build["repository"]} {build["commit"][:12]} ({builds.release_tag(build, pins)})'


# ---------------------------------------------------------------------------------------------------
# plan


class GitHubReader:
    """GET-only REST client; the token is sent to api.github.com only and never printed."""

    def __init__(self, token, what, opener=None):
        if not (token or '').strip():
            raise ReleasePinsError(f'no token to read {what}')
        self._token = token.strip()
        self._open = opener or urllib.request.urlopen

    def get(self, path, what, raw=False, missing_ok=False):
        request = urllib.request.Request(API + path)
        request.add_header('Accept', 'application/vnd.github.raw+json' if raw else 'application/vnd.github+json')
        request.add_header('X-GitHub-Api-Version', '2022-11-28')
        request.add_header('User-Agent', 'meshagent-release-pins')
        request.add_unredirected_header('Authorization', 'Bearer ' + self._token)
        try:
            response = self._open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            error.close()
            if missing_ok and error.code == 404:
                return None
            raise ReleasePinsError(f'{what}: GitHub answered HTTP {error.code} {error.reason}') from None
        except urllib.error.URLError as error:
            raise ReleasePinsError(f'{what}: {error.reason}') from None
        with response:
            data = response.read()
        if raw:
            return data
        try:
            return json.loads(data)
        except ValueError:
            raise ReleasePinsError(f'{what}: GitHub answered with something that is not JSON') from None


def pins_at(reader, repository, sha):
    what = f'read {PINS_PATH} of {repository} {sha}'
    data = reader.get(f'/repos/{repository}/contents/{PINS_PATH}?ref={sha}', what, raw=True, missing_ok=True)
    if data is None:
        raise ReleasePinsError(f'{repository} {sha} has no {PINS_PATH}; the release serves only pinned agent builds')
    try:
        document = json.loads(data.decode('utf-8'))
    except ValueError as error:
        raise ReleasePinsError(f'{PINS_PATH} of {repository} {sha} is not JSON: {error}') from None
    try:
        return builds.parse_pins(document, f'{PINS_PATH} of {repository} {sha}')
    except builds.AgentBuildError as error:
        raise ReleasePinsError(str(error)) from None


def pin_record_at(reader, repository, sha):
    """(commit, message) of the last commit at sha that changed agents/agent-defaults.json."""
    query = urllib.parse.urlencode({'sha': sha, 'path': PINS_PATH, 'per_page': 1})
    commits = reader.get(f'/repos/{repository}/commits?{query}', f'read the history of {PINS_PATH} in {repository}')
    if not isinstance(commits, list) or not commits:
        raise ReleasePinsError(f'{repository} {sha}: no commit changed {PINS_PATH}')
    commit = commits[0]
    return commit.get('sha'), (commit.get('commit') or {}).get('message', '')


def deployed_meshcentral(reader, coordinator, meshcentral):
    """(MeshCentral commit, note) of the last successful production deployment, or (None, why not)."""
    query = urllib.parse.urlencode({'environment': ENVIRONMENT, 'per_page': 100})
    deployments = reader.get(f'/repos/{coordinator}/deployments?{query}',
                             f'read the {ENVIRONMENT} deployments of {coordinator}')
    if not isinstance(deployments, list):
        raise ReleasePinsError(f'the {ENVIRONMENT} deployments of {coordinator} are not a list')
    url = re.compile(r'^https://github\.com/' + re.escape(meshcentral) + r'/commit/([0-9a-f]{40})$', re.IGNORECASE)
    for deployment in deployments:
        statuses = reader.get(f'/repos/{coordinator}/deployments/{int(deployment["id"])}/statuses?per_page=1',
                              f'read the status of {ENVIRONMENT} deployment {deployment["id"]}')
        if not statuses or statuses[0].get('state') != 'success':
            continue
        match = url.match(statuses[0].get('environment_url') or '')
        if not match:
            return None, (f'the last successful {ENVIRONMENT} deployment ({deployment["id"]}) did not record '
                          'its MeshCentral commit')
        return match.group(1).lower(), f'{ENVIRONMENT} deployment {deployment["id"]}'
    return None, f'no successful {ENVIRONMENT} deployment of this pipeline is recorded'


def fleet_statement(release, deployed, deployed_note):
    """('yes' | 'no' | 'unknown', one-line notice) for promoting a release with these pins."""
    if deployed is None:
        return 'unknown', (f'Agent build {describe_build(*release)}: {deployed_note}, so treat promotion as a fleet '
                           'update; production keeps whatever it serves today only if that is this build.')
    if same_build(release, deployed):
        return 'no', f'Agent build unchanged: {describe_build(*release)} is already deployed; no fleet update.'
    return 'yes', (f'FLEET UPDATE: the pinned agent build changes from {describe_build(*deployed)} to '
                   f'{describe_build(*release)}. Every connected agent is offered the new build when the '
                   'controller policy enable_fleet_update is true.')


def plan(environ, sources, deployments):
    policy = environ.get(POLICY_VARIABLE, '').strip()
    if policy not in POLICIES:
        raise ReleasePinsError(f'repository variable {POLICY_VARIABLE} must be one of {", ".join(POLICIES)} '
                               f'(found {policy or "nothing"})')
    names = {}
    for key in ('MESHCENTRAL_REPOSITORY', 'GITHUB_REPOSITORY'):
        names[key] = environ.get(key, '')
        if not REPOSITORY.match(names[key]):
            raise ReleasePinsError(f'{key} must name a repository as owner/name')
    shas = {}
    for key in ('MESHAGENT_SHA', 'MESHCENTRAL_SHA', 'RUNTIME_COMPONENT_SHA'):
        shas[key] = environ.get(key, '')
        if not SHA.match(shas[key]):
            raise ReleasePinsError(f'{key} must be a full commit sha')
    meshcentral = names['MESHCENTRAL_REPOSITORY']
    build, pins = pins_at(sources, meshcentral, shas['MESHCENTRAL_SHA'])
    record_commit, message = pin_record_at(sources, meshcentral, shas['MESHCENTRAL_SHA'])
    runtime_record = build_runtime(message, build, pins)
    action, reasons = decide(policy, build, runtime_record, shas['MESHAGENT_SHA'], shas['RUNTIME_COMPONENT_SHA'])
    deployed_sha, note = deployed_meshcentral(deployments, names['GITHUB_REPOSITORY'], meshcentral)
    deployed = pins_at(sources, meshcentral, deployed_sha) if deployed_sha else None
    fleet, notice = fleet_statement((build, pins), deployed, note)
    if action == 'rebuild':
        notice = ('This release rebuilds the agents: a new build is committed to MeshCentral and the release of '
                  'that commit states the fleet change. If the rebuild reproduces the pinned bytes: ' + notice)
    return {
        'agents': action,
        'pinned_release': builds.release_tag(build, pins),
        'pinned_build': build['commit'],
        'pin_record': record_commit or '',
        'pinned_runtime': runtime_record or '',
        'fleet_update': fleet,
        'fleet_notice': notice,
        'reasons': reasons,
        'policy': policy,
    }


def plan_summary(result):
    lines = ['### Agent builds', '',
             f'- Policy `{POLICY_VARIABLE}`: `{result["policy"]}`',
             f'- Pinned build: `{result["pinned_release"]}` (pinned by MeshCentral commit `{result["pin_record"]}`; '
             f'built by hook `{result["pinned_runtime"] or "unknown"}`)',
             f'- Decision: **{result["agents"]}**']
    lines += [f'  - {reason}' for reason in result['reasons']]
    lines += ['', '### Fleet', '', result['fleet_notice'], '']
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------------------------------
# relock


def git(clone, *args, stdin=None):
    result = subprocess.run(['git', '-C', str(clone), *args], input=stdin, capture_output=True, text=True,
                            encoding='utf-8', check=False)
    if result.returncode != 0:
        raise ReleasePinsError(f'git {" ".join(args)} failed: {result.stderr.strip() or result.stdout.strip()}')
    return result.stdout


def run_pack(clone, agents):
    """Pack MeshCentral with pack.js --agents --json and return its record."""
    result = subprocess.run(['node', 'deploy/scripts/pack.js', '--agents', str(agents), '--json'], cwd=str(clone),
                            capture_output=True, text=True, encoding='utf-8', check=False)
    if result.returncode != 0:
        detail = '\n'.join((result.stderr or result.stdout).strip().splitlines()[-20:])
        raise ReleasePinsError(f'pack.js --agents failed:\n{detail}')
    return pack_record(result.stdout)


def pack_record(text):
    """The record pack.js --json prints after its summary lines (as release_image.js reads it)."""
    match = re.search(r'^\{$', text, re.MULTILINE)
    if not match:
        raise ReleasePinsError('pack.js printed no --json record')
    try:
        record = json.loads(text[match.start():])
    except ValueError as error:
        raise ReleasePinsError(f'the pack record is not JSON: {error}') from None
    for key in ('tarball', 'version', 'commit', 'integrity', 'packagedCommit', 'agentBuild', 'agents', 'platform',
                'node', 'npm'):
        if record.get(key) in (None, ''):
            raise ReleasePinsError(f'the pack record has no {key}')
    if not SHA.match(record['commit']) or not SHA.match(record['packagedCommit']):
        raise ReleasePinsError('the pack record commits are not full git shas')
    if not re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==', record['integrity']):
        raise ReleasePinsError(f'the pack record integrity {record["integrity"]!r} is not a sha512 integrity')
    return record


def check_pack(record, head, build, pins):
    if record['commit'] != head:
        raise ReleasePinsError(f'pack.js packed {record["commit"]}, not {head}')
    packed = sorted(({'filename': a.get('filename'), 'size': a.get('size'), 'sha384': a.get('sha384')}
                     for a in record['agents']), key=lambda pin: str(pin['filename']))
    if record['agentBuild'] != build or packed != pins:
        raise ReleasePinsError('pack.js packed agent builds other than the pins this release ships')


def locked_entry(clone, record):
    """(lock text, locked integrity) after checking that only the tarball integrity can differ."""
    version = record['version']
    expected = f'file:dist/meshcentral-{version}.tgz'
    if record['tarball'] != f'deploy/dist/meshcentral-{version}.tgz':
        raise ReleasePinsError(f'unexpected pack output {record["tarball"]}')
    deploy_package = json.loads((Path(clone) / DEPLOY_PACKAGE_PATH).read_text(encoding='utf-8'))
    if deploy_package.get('dependencies', {}).get('meshcentral') != expected:
        raise ReleasePinsError(f'{DEPLOY_PACKAGE_PATH} does not install {expected}')
    text = (Path(clone) / LOCK_PATH).read_text(encoding='utf-8')
    lock = json.loads(text)
    packages = lock.get('packages') or {}
    if (packages.get('') or {}).get('dependencies', {}).get('meshcentral') != expected:
        raise ReleasePinsError(f'{LOCK_PATH} does not lock {expected} for the deploy package')
    entry = packages.get(LOCK_ENTRY)
    if not isinstance(entry, dict) or entry.get('resolved') != expected:
        raise ReleasePinsError(f'{LOCK_PATH} has no {LOCK_ENTRY} entry resolved from {expected}')
    package = json.loads(git(clone, 'show', 'HEAD:package.json'))
    unknown = sorted(set(entry) - LOCK_ENTRY_FIELDS)
    changed = [field for field in DERIVED_LOCK_FIELDS if entry.get(field) != package.get(field)]
    if unknown or changed:
        raise ReleasePinsError(
            f'{LOCK_PATH} {LOCK_ENTRY} differs from package.json in more than the tarball integrity '
            f'({", ".join(changed + unknown)}). The pipeline re-pins only the tarball; lock the dependency '
            'change with npm on Linux in a reviewed MeshCentral commit.')
    return text, entry.get('integrity')


def last_pin_message(clone):
    return git(clone, 'log', '-1', '--format=%B', '--', PINS_PATH)


def commit(clone, path, message):
    git(clone, 'add', '--', path)
    git(clone, 'commit', '--quiet', '--file=-', stdin=message)
    return git(clone, 'rev-parse', 'HEAD').strip()


def pin_message(build, pins, meshagent_sha, runtime_sha, run_url, store):
    tag = builds.release_tag(build, pins)
    files = '\n'.join(f'  {pin["filename"]} {pin["size"]} bytes, SHA384 {pin["sha384"]}' for pin in pins)
    return (f'Pin the MeshAgent build {build["commit"][:12]} for the coordinated release\n\n'
            f'agents/agent-defaults.json pins the Windows service builds of\n'
            f'{build["repository"]} {build["commit"]} that passed\n'
            f'release_bundle_gate.js in the coordinated release, stored as release\n'
            f'{tag} of {store}:\n{files}\n\n'
            'A release with these pins is a fleet update: the controller offers the\n'
            'new build to every connected agent when enable_fleet_update is true.\n\n'
            f'{TRAILER_RELEASE}: {tag}\n'
            f'{TRAILER_MESHAGENT}: {meshagent_sha}\n'
            f'{TRAILER_RUNTIME}: {runtime_sha}\n'
            f'{TRAILER_RUN}: {run_url}\n')


def lock_message(record, run_url):
    platform = 'Linux' if record['platform'] == 'linux' else record['platform']
    return (f'Lock the fork tarball from a {platform} pack of {record["commit"][:12]}\n\n'
            f'{LOCK_PATH} pins {record["tarball"].split("/")[-1]},\n'
            f'{record["integrity"]}\n'
            f'(modules dated by {record["packagedCommit"][:12]}; agents: {len(record["agents"])} pinned builds of\n'
            f'{record["agentBuild"]["repository"]} {record["agentBuild"]["commit"][:12]}). Packed by pack.js --agents\n'
            f'with Node {record["node"]} / npm {record["npm"]} on {record["platform"]}.\n\n'
            f'{TRAILER_LOCK}: {record["integrity"]}\n'
            f'{TRAILER_RUN}: {run_url}\n')


def relock(clone, pins_file, agents, expect_head, meshagent_sha, runtime_sha, run_url, store, pack=run_pack,
           log=print):
    for name, value in (('--expect-head', expect_head), ('--meshagent-sha', meshagent_sha),
                        ('--runtime-sha', runtime_sha)):
        if not SHA.match(value or ''):
            raise ReleasePinsError(f'{name} must be a full commit sha')
    if not RUN_URL.match(run_url or ''):
        raise ReleasePinsError('--run-url must be the URL of the GitHub Actions run')
    clone = Path(clone)
    head = git(clone, 'rev-parse', 'HEAD').strip()
    if head != expect_head:
        raise ReleasePinsError(f'the MeshCentral clone is at {head}, not the resolved {expect_head}')
    if git(clone, 'status', '--porcelain', '--untracked-files=no').strip():
        raise ReleasePinsError('the MeshCentral clone has changes to tracked files')
    head_message = git(clone, 'log', '-1', '--format=%B', head)
    try:
        wanted_bytes = Path(pins_file).read_bytes()
        build, pins = builds.load_pins(pins_file)
        current = builds.load_pins(clone / PINS_PATH)
    except builds.AgentBuildError as error:
        raise ReleasePinsError(str(error)) from None
    result = {'pins_changed': False, 'lock_changed': False, 'release': builds.release_tag(build, pins)}

    if not same_build((build, pins), current):
        if build['commit'] != meshagent_sha:
            raise ReleasePinsError(f'refusing to pin a build of MeshAgent {build["commit"]}: this release resolved '
                                   f'MeshAgent {meshagent_sha}')
        previous = trailers(last_pin_message(clone))
        if (previous.get(TRAILER_MESHAGENT) == meshagent_sha and previous.get(TRAILER_RUNTIME) == runtime_sha):
            raise ReleasePinsError(
                f'loop guard: MeshCentral already pins a pipeline build of MeshAgent {meshagent_sha} and hook '
                f'{runtime_sha} ({previous.get(TRAILER_RELEASE)}); refusing to pin another build of the same sources')
        (clone / PINS_PATH).write_bytes(wanted_bytes)
        head = commit(clone, PINS_PATH, pin_message(build, pins, meshagent_sha, runtime_sha, run_url, store))
        result['pins_changed'] = True
        log(f'committed {PINS_PATH}: {describe_build(build, pins)} ({head})')

    record = pack(clone, agents)
    check_pack(record, head, build, pins)
    lock_text, locked = locked_entry(clone, record)
    if locked != record['integrity']:
        # Over the pipeline's own lock commit, with the same pins, a different pack means it does not reproduce.
        if not result['pins_changed'] and f'{TRAILER_LOCK}: ' in head_message:
            raise ReleasePinsError(
                f'loop guard: {expect_head} is the pipeline\'s own lock commit, yet the Linux pack gives '
                f'{record["integrity"]}, not the locked {locked}. The pack does not reproduce; not re-locking again.')
        old = f'"integrity": "{locked}"'
        if lock_text.count(old) != 1:
            raise ReleasePinsError(f'{LOCK_PATH} does not hold the locked integrity exactly once')
        updated = lock_text.replace(old, f'"integrity": "{record["integrity"]}"')
        before, after = json.loads(lock_text), json.loads(updated)
        before['packages'][LOCK_ENTRY]['integrity'] = record['integrity']
        if before != after:
            raise ReleasePinsError(f'updating {LOCK_PATH} changed more than the {LOCK_ENTRY} integrity')
        (clone / LOCK_PATH).write_text(updated, encoding='utf-8', newline='')
        head = commit(clone, LOCK_PATH, lock_message(record, run_url))
        result['lock_changed'] = True
        log(f'committed {LOCK_PATH}: {record["integrity"]} ({head})')

    if result['pins_changed'] or result['lock_changed']:
        # The commits to push must reproduce: the lock commit is outside the package, so a pack of it gives
        # the same tarball, and the next release finds pins and lock consistent and commits nothing.
        again = pack(clone, agents)
        check_pack(again, head, build, pins)
        if again['integrity'] != record['integrity'] or locked_entry(clone, again)[1] != again['integrity']:
            raise ReleasePinsError(f'a second Linux pack at {head} gives {again["integrity"]}, not the locked '
                                   f'{record["integrity"]}; not pushing an unreproducible lock')
    result.update({'changed': result['pins_changed'] or result['lock_changed'], 'meshcentral_sha': head,
                   'integrity': record['integrity'], 'packaged_commit': record['packagedCommit']})
    return result


def relock_summary(result, expect_head):
    if not result['changed']:
        return ('### MeshCentral pins and lock\n\n'
                f'`{expect_head}` already pins `{result["release"]}` and locks the Linux pack '
                f'`{result["integrity"]}`; nothing to commit.\n')
    parts = []
    if result['pins_changed']:
        parts.append(f'pins `{result["release"]}`')
    if result['lock_changed']:
        parts.append(f'locks `{result["integrity"]}`')
    return ('### MeshCentral pins and lock\n\n'
            f'New MeshCentral head `{result["meshcentral_sha"]}` on top of `{expect_head}` {" and ".join(parts)}. '
            'After the push, the release continues in the coordinated release that this MeshCentral push starts; '
            'this run builds no image and deploys nothing.\n')


# ---------------------------------------------------------------------------------------------------
# Command line


def write_outputs(path, values):
    if not path:
        return
    with open(path, 'a', encoding='utf-8') as stream:
        for key, value in values.items():
            text = str(value).lower() if isinstance(value, bool) else str(value)
            if '\n' in text or '\r' in text:
                raise ReleasePinsError(f'output {key} spans lines')
            stream.write(f'{key}={text}\n')


def write_summary(path, text):
    if path:
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write(text)


def main(argv=None, environ=None, reader_factory=GitHubReader, pack=run_pack):
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('plan', help='decide rebuild or reuse, and state the fleet change')
    relock_parser = commands.add_parser('relock', help='commit the pins and the Linux lock locally')
    relock_parser.add_argument('--meshcentral', required=True, help='full MeshCentral clone at the resolved commit')
    relock_parser.add_argument('--pins', required=True, help='the meshcentral-fork-agents/1 pins this release ships')
    relock_parser.add_argument('--agents', required=True, help='the pinned builds, as agent_build_release.py fetched them')
    relock_parser.add_argument('--expect-head', required=True)
    relock_parser.add_argument('--meshagent-sha', required=True)
    relock_parser.add_argument('--runtime-sha', required=True)
    relock_parser.add_argument('--run-url', required=True)
    relock_parser.add_argument('--store', required=True, help='repository whose releases hold the builds')
    args = parser.parse_args(argv)
    try:
        if args.command == 'plan':
            sources = reader_factory(environ.get('SOURCES_TOKEN', ''), 'MeshCentral (SOURCES_TOKEN)')
            deployments = reader_factory(environ.get('DEPLOYMENTS_TOKEN', ''),
                                         'the production deployments (DEPLOYMENTS_TOKEN)')
            result = plan(environ, sources, deployments)
            write_outputs(environ.get('GITHUB_OUTPUT'), {key: result[key] for key in (
                'agents', 'pinned_release', 'pinned_build', 'fleet_update', 'fleet_notice')})
            write_summary(environ.get('GITHUB_STEP_SUMMARY'), plan_summary(result))
            print(plan_summary(result))
            if result['fleet_update'] != 'no' and environ.get('GITHUB_ACTIONS') == 'true':
                print(f'::warning title=Fleet update::{result["fleet_notice"]}')
        else:
            result = relock(args.meshcentral, args.pins, args.agents, args.expect_head, args.meshagent_sha,
                            args.runtime_sha, args.run_url, args.store, pack=pack)
            write_outputs(environ.get('GITHUB_OUTPUT'), {key: result[key] for key in (
                'changed', 'pins_changed', 'lock_changed', 'meshcentral_sha', 'integrity')})
            write_summary(environ.get('GITHUB_STEP_SUMMARY'), relock_summary(result, args.expect_head))
            print(relock_summary(result, args.expect_head))
    except ReleasePinsError as error:
        message = f'release pins: {error}'
        print(message, file=sys.stderr)
        if environ.get('GITHUB_ACTIONS') == 'true':
            escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print(f'::error title=Release pins::{escaped}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
