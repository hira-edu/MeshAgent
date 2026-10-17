"""Refuse publishing provisioned agents into an existing public container package."""
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
owner = event['repository']['owner']
kind = 'orgs' if owner['type'] == 'Organization' else 'users'
url = f'https://api.github.com/{kind}/{owner["login"]}/packages/container/meshcentral-release'
request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                                              'Accept': 'application/vnd.github+json'})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        package = json.load(response)
    if package['visibility'] != 'private':
        raise SystemExit('Provisioned agent images must use a private GHCR package')
except urllib.error.HTTPError as error:
    # GitHub creates new container packages private by default.
    if error.code != 404 or os.environ.get('REQUIRE_PACKAGE_EXISTS') == 'true':
        raise
