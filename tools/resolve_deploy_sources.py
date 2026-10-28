"""Resolve the channel, the mode and the exact commits of one coordinated release run in hook.

Channels: branch `main` is the production channel, branch `preview` the preview channel, in all three
repositories (MeshAgent, MeshCentral, hook). A run of a channel takes each repository's branch of that
channel; a repository without a `preview` branch contributes its `main`, and the run summary says so.

What starts a run, and its channel:
    push to hook main / preview          that branch; hook is the pushed commit
    repository_dispatch                  client_payload.branch (main or preview) of the MeshAgent or
                                         MeshCentral push that dispatched it. It is a wake-up signal: the
                                         run builds the current heads, even when an older notification
                                         arrives last.
    workflow_dispatch on main / preview  that branch; hook is the commit the run executes

Modes:
    build   (every run without deploy_digest) build what the heads need, pin and lock MeshCentral, build
            and smoke-test the image, publish its digest in the run summary. A preview build then deploys
            it when the repository variable PREVIEW_AUTO_DEPLOY is true; a production build never deploys.
    deploy  (workflow_dispatch with deploy_digest, started by a person, not an app) promote that digest:
            the run checks the image was built from the current heads of the channel, smoke-tests it
            again and checks the operator's fleet confirmation before the controller is called. This is
            the production approval: GitHub environment reviewers are not available on hook's plan.

    python tools/resolve_deploy_sources.py                  write the run's outputs (GITHUB_OUTPUT)
    python tools/resolve_deploy_sources.py --check-current  fail when a channel head moved since
                                                            (CHANNEL, MESHAGENT_SHA, MESHCENTRAL_SHA,
                                                            RUNTIME_COMPONENT_SHA)
"""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

CHANNELS = {'main': 'production', 'preview': 'preview'}
BRANCHES = {channel: branch for branch, channel in CHANNELS.items()}
DEFAULT_BRANCH = 'main'
SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
FLEET_CONFIRMATIONS = ('unchanged', 'changed')


def api(path, missing_ok=False):
    request = urllib.request.Request('https://api.github.com/repos/' + path, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        error.close()
        if missing_ok and error.code == 404:
            return None
        raise ValueError('GitHub answered HTTP {} {} for {}'.format(error.code, error.reason, path)) from None


def checked(repository):
    if not REPOSITORY.fullmatch(repository or ''):
        raise ValueError('Invalid repository name: {!r}'.format(repository))
    return repository


def head(repository):
    """The head of main, which must be the default branch."""
    checked(repository)
    branch = api(repository)['default_branch']
    if branch != DEFAULT_BRANCH:
        raise ValueError('Coordinated releases require main as the default branch: ' + repository)
    return api(repository + '/commits/' + urllib.parse.quote(branch, safe=''))['sha']


def branch_head(repository, branch):
    """The head of a branch, or None when the repository has no such branch."""
    found = api(checked(repository) + '/branches/' + urllib.parse.quote(branch, safe=''), missing_ok=True)
    return None if found is None else found['commit']['sha']


def channel_head(repository, channel):
    """(commit, branch used): the channel's branch, or main when a repository has no preview branch."""
    if channel not in BRANCHES:
        raise ValueError('Unknown channel: {!r}'.format(channel))
    if channel == 'production':
        return head(repository), DEFAULT_BRANCH
    sha = branch_head(repository, BRANCHES[channel])
    if sha is None:
        return head(repository), DEFAULT_BRANCH
    return sha, BRANCHES[channel]


def run_branch(environment):
    ref = environment.get('GITHUB_REF', '')
    branch = ref[len('refs/heads/'):] if ref.startswith('refs/heads/') else ''
    if branch not in CHANNELS:
        raise ValueError('Coordinated releases run on main or preview only, not ' + (ref or 'no ref'))
    return branch


def plan_run(event_name, event, environment):
    """The run's channel, mode, deployment request and trigger, before any source is read.

    Raises ValueError for any run that may not release: wrong default branch, untrusted ref, an unknown
    dispatch, a deploy request that is not a person's manual run, or a malformed digest/confirmation.
    """
    if event['repository']['default_branch'] != DEFAULT_BRANCH:
        raise ValueError('Coordinated releases require main as the default branch of the coordinator')
    if event_name not in ('push', 'repository_dispatch', 'workflow_dispatch'):
        raise ValueError('Event {} does not start a coordinated release'.format(event_name))
    branch = run_branch(environment)
    trigger = (environment['GITHUB_REPOSITORY'], environment['GITHUB_SHA'])
    if event_name == 'repository_dispatch':
        # repository_dispatch always runs hook's default branch; the payload names the channel.
        if branch != DEFAULT_BRANCH:
            raise ValueError('A dispatched release must run on main')
        payload = event.get('client_payload') or {}
        allowed = (environment['MESHCENTRAL_REPOSITORY'], environment['MESHAGENT_REPOSITORY'])
        if (payload.get('repository') not in allowed or not SHA.fullmatch(str(payload.get('sha', ''))) or
                payload.get('branch') not in CHANNELS):
            raise ValueError('Dispatch must identify an approved sibling, a commit SHA and a branch '
                             '(main or preview)')
        branch = payload['branch']
        trigger = (payload['repository'], payload['sha'])
    inputs = event.get('inputs') or {}
    digest = str(inputs.get('deploy_digest') or '').strip() if event_name == 'workflow_dispatch' else ''
    result = {'channel': CHANNELS[branch], 'mode': 'build', 'deploy': False, 'deploy_digest': '',
              'fleet_confirmation': '', 'trigger': '{} {}@{}'.format(event_name, *trigger)}
    if digest:
        actor = environment.get('GITHUB_TRIGGERING_ACTOR', '')
        if not actor or actor.endswith('[bot]'):
            raise ValueError('A deployment must be started by a person (triggering actor {!r})'.format(actor))
        if not DIGEST.fullmatch(digest):
            raise ValueError('deploy_digest must be sha256:<64 lowercase hex>, the digest of a release image')
        confirmation = str(inputs.get('fleet_update') or '').strip()
        if confirmation not in FLEET_CONFIRMATIONS:
            raise ValueError('fleet_update must confirm whether the pinned agent build is unchanged or changed')
        result.update({'mode': 'deploy', 'deploy': True, 'deploy_digest': digest,
                       'fleet_confirmation': confirmation})
    elif result['channel'] == 'preview' and environment.get('PREVIEW_AUTO_DEPLOY') == 'true':
        result['deploy'] = True
    return result


def resolve(run, environment):
    """The frozen commits of the run's channel, and the branch each one came from."""
    channel = run['channel']
    repositories = {'meshagent': environment['MESHAGENT_REPOSITORY'],
                    'meshcentral': environment['MESHCENTRAL_REPOSITORY'],
                    'runtime': environment['RUNTIME_COMPONENT_REPOSITORY']}
    if environment['GITHUB_REPOSITORY'] != repositories['runtime']:
        raise ValueError('Run the coordinator in the private runtime repository')
    sources = {}
    for key in ('meshagent', 'meshcentral'):
        sources[key] = channel_head(repositories[key], channel)
    if environment['GITHUB_EVENT_NAME'] == 'repository_dispatch':
        # The run executes hook main's workflow and builds the channel's hook commit.
        sources['runtime'] = channel_head(repositories['runtime'], channel)
    else:
        # A push or manual run of hook main/preview builds the commit it executes. A newer hook commit
        # starts its own run; pinning and deployment refuse this one if it is stale by then.
        sources['runtime'] = (environment['GITHUB_SHA'], run_branch(environment))
    return repositories, sources


def check_current(environment):
    channel = environment['CHANNEL']
    for repository_key, sha_key in (('MESHAGENT_REPOSITORY', 'MESHAGENT_SHA'),
                                    ('MESHCENTRAL_REPOSITORY', 'MESHCENTRAL_SHA'),
                                    ('RUNTIME_COMPONENT_REPOSITORY', 'RUNTIME_COMPONENT_SHA')):
        current, branch = channel_head(environment[repository_key], channel)
        if current != environment[sha_key]:
            raise ValueError('A newer {} commit exists on {} ({}); refusing a stale release of {}'.format(
                environment[repository_key], branch, current, environment[sha_key]))


def summary(run, repositories, sources):
    channel = run['channel']
    lines = ['### Release sources ({} channel)'.format(channel), '',
             '| Repository | Branch | Commit |', '| --- | --- | --- |']
    for key in ('meshagent', 'meshcentral', 'runtime'):
        sha, branch = sources[key]
        lines.append('| {} | {} | `{}` |'.format(repositories[key], branch, sha))
    lines.append('')
    for key in ('meshagent', 'meshcentral', 'runtime'):
        if sources[key][1] != BRANCHES[channel]:
            lines.append('**Fallback:** {} has no `{}` branch; this {} release uses its `main`.'.format(
                repositories[key], BRANCHES[channel], channel))
    if channel == 'preview' and sources['meshcentral'][1] != BRANCHES[channel]:
        lines.append('Pin and lock commits for the preview agent builds create the `preview` branch of {} '
                     'from that commit.'.format(repositories['meshcentral']))
    lines.append('')
    lines.append('Triggered by {}; mode: {}.'.format(run['trigger'], run['mode']))
    if run['mode'] == 'deploy':
        lines.append('Requested deployment of `{}` with the fleet confirmed as {}.'.format(
            run['deploy_digest'], run['fleet_confirmation']))
    elif run['deploy']:
        lines.append('The smoke-tested image deploys to the preview server (PREVIEW_AUTO_DEPLOY).')
    elif channel == 'preview':
        lines.append('The image is not deployed: repository variable PREVIEW_AUTO_DEPLOY is not true.')
    else:
        lines.append('Production is never deployed by a build. To promote the image this run publishes, start '
                     'this workflow manually on main with deploy_digest and fleet_update.')
    return '\n'.join(lines) + '\n\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--check-current', action='store_true')
    args = parser.parse_args()
    env = os.environ
    if args.check_current:
        check_current(env)
        return
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    run = plan_run(env['GITHUB_EVENT_NAME'], event, env)
    repositories, sources = resolve(run, env)
    outputs = {
        'channel': run['channel'],
        'mode': run['mode'],
        'deploy_requested': str(run['deploy']).lower(),
        'deploy_digest': run['deploy_digest'],
        'fleet_confirmation': run['fleet_confirmation'],
        'meshagent_sha': sources['meshagent'][0],
        'meshcentral_sha': sources['meshcentral'][0],
        'runtime_sha': sources['runtime'][0],
        # Pin and lock commits always go to the channel's branch (created from main on a preview fallback).
        'meshcentral_branch': BRANCHES[run['channel']],
        'trigger': run['trigger'],
    }
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        for key, value in outputs.items():
            stream.write('{}={}\n'.format(key, value))
    if env.get('GITHUB_STEP_SUMMARY'):
        with open(env['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(summary(run, repositories, sources))


if __name__ == '__main__':
    main()
