"""Publish an already signature-verified package; never execute package files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPO = 'GameRisker/lattice-node-releases'
FILES = {'deepseek-node-agent-windows-amd64.exe', 't07-node-release-windows-amd64.exe',
         'install.ps1', 'deepseek-manifest-windows.json', 'deepseek-manifest-windows.json.sig',
         'release.pub.pem', 'release-index.json', 'release-index.json.sig', 'SHA256SUMS'}


def gh(*args):
    # Never log credentials, HTTP response bodies, or shell-expand input.
    result = subprocess.run(['gh', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError('GitHub operation failed; inspect draft state before retry')
    return result.stdout


def inventory(directory):
    paths = list(Path(directory).iterdir())
    if {p.name for p in paths} != FILES or any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Invalid signed package inventory')
    return {p.name: (p.stat().st_size, 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths}


def check_remote(release, expected, tag):
    if release.get('draft') is not True or release.get('tag_name') != tag:
        raise ValueError('Expected new draft')
    assets = release.get('assets', [])
    if len(assets) != len(expected) or {a.get('name') for a in assets} != set(expected):
        raise ValueError('Remote inventory mismatch; remains draft')
    for asset in assets:
        if (asset.get('size'), asset.get('digest')) != expected[asset['name']]:
            raise ValueError('Remote digest mismatch; remains draft')


def publish(directory, tag, source_sha, workflow_sha):
    if not re.fullmatch(r'v[0-9]{4}\.[0-9]{2}\.[0-9]{2}-deepseek-windows-selfuse[0-9]+', tag):
        raise ValueError('Invalid tag')
    if not re.fullmatch(r'[a-f0-9]{40}', source_sha):
        raise ValueError('Invalid source')
    if not re.fullmatch(r'[a-f0-9]{40}', workflow_sha):
        raise ValueError('Invalid workflow commit')
    expected = inventory(directory)
    refs = json.loads(gh('api', f'repos/{REPO}/git/matching-refs/tags/{tag}'))
    if any(r.get('ref') == 'refs/tags/' + tag for r in refs):
        raise ValueError('Tag exists; never overwrite')
    assets = [str(Path(directory) / name) for name in sorted(FILES)]
    notes = (f'DeepSeek Windows self-use. Source SHA: {source_sha}. '
             'Independent self-use trust; production trust unchanged. '
             'Signed artifact integrity checked. Full install/Harness/pairing/startup/model NOT_RUN.')
    gh('release', 'create', tag, *assets, '--repo', REPO, '--draft', '--target', workflow_sha, '--title', tag, '--notes', notes)
    release = json.loads(gh('api', f'repos/{REPO}/releases/tags/{tag}'))
    check_remote(release, expected, tag)
    gh('release', 'edit', tag, '--repo', REPO, '--draft=false')
    final = json.loads(gh('api', f'repos/{REPO}/releases/tags/{tag}'))
    if final.get('draft') is not False or final.get('id') != release.get('id'):
        raise ValueError('Published state not verified')
    # Check final assets as well without weakening the draft-only validation helper.
    check_remote({**final, 'draft': True}, expected, tag)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dir', required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--source-sha', required=True)
    p.add_argument('--workflow-sha', required=True)
    a = p.parse_args()
    try:
        if not os.environ.get('GH_TOKEN'):
            raise ValueError('Token unavailable')
        publish(a.dir, a.tag, a.source_sha, a.workflow_sha)
    except Exception:
        p.exit(1, 'Publication failed or uncertain; check draft/release before taking further action.\n')
