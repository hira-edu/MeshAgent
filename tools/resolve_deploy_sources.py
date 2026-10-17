"""Resolve trusted default-branch commits before building a coordinated release."""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.request
import urllib.parse


def api(path):
    request = urllib.request.Request('https://api.github.com/repos/' + path, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def head(repository):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository name')
    branch = api(repository)['default_branch']
    if branch != 'main':
        raise ValueError('Coordinated releases require main as the default branch: ' + repository)
    return api(repository + '/commits/' + urllib.parse.quote(branch, safe=''))['sha']


def requested(event_name, event, environment):
    if event['repository']['default_branch'] != 'main':
        return False
    default_ref = 'refs/heads/main'
    trusted_branch = environment['GITHUB_REF'] == default_ref
    if event_name == 'workflow_dispatch':
        return trusted_branch and str(event.get('inputs', {}).get('deploy_to_server', 'false')).lower() == 'true'
    return trusted_branch and event_name in ('push', 'repository_dispatch') and environment.get('AUTO_DEPLOY') == 'true'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-current', action='store_true')
    args = parser.parse_args()
    env = os.environ
    repository = env['MESHCENTRAL_REPOSITORY']
    runtime_repository = env['RUNTIME_COMPONENT_REPOSITORY']
    agent_repository = env['MESHAGENT_REPOSITORY']
    if args.check_current:
        if (head(agent_repository) != env['MESHAGENT_SHA'] or
                head(repository) != env['MESHCENTRAL_SHA'] or
                head(runtime_repository) != env['RUNTIME_COMPONENT_SHA']):
            raise ValueError('A newer default-branch commit exists; refusing a stale deployment')
        return
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    deploy = requested(env['GITHUB_EVENT_NAME'], event, env)
    agent_sha = env['MESHAGENT_SHA']
    central_sha = head(repository)
    if env['GITHUB_REPOSITORY'] != runtime_repository:
        raise ValueError('Run the coordinator in the private runtime repository')
    runtime_sha = env['GITHUB_SHA']
    if deploy:
        if env['GITHUB_EVENT_NAME'] == 'repository_dispatch':
            payload = event.get('client_payload', {})
            expected = {repository: central_sha, agent_repository: agent_sha}
            if payload.get('repository') not in expected or not re.fullmatch(r'[0-9a-f]{40}', payload.get('sha', '')):
                raise ValueError('Dispatch must identify an approved sibling and a commit SHA')
            # Dispatch delivery order is not guaranteed. Treat it as a wake-up signal;
            # build the frozen current heads even when an older notification arrives last.
        if head(runtime_repository) != runtime_sha or head(agent_repository) != agent_sha:
            raise ValueError('Refusing a stale coordinated release')
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        stream.write('deploy_requested=' + str(deploy).lower() + '\n')
        stream.write('meshagent_sha=' + agent_sha + '\n')
        stream.write('meshcentral_sha=' + central_sha + '\n')
        stream.write('runtime_sha=' + runtime_sha + '\n')


if __name__ == '__main__':
    main()
