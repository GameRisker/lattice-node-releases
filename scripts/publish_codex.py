"""Publish an already signature-verified package; never execute package files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPO = 'GameRisker/lattice-node-releases'
FILES = {'install.sh', 'manifest-v2.json', 'manifest-v2.json.sig',
         'release.pub.pem', 'release-index.json', 'release-index.json.sig', 'SHA256SUMS'} | {
    f'{kind}-{platform}' for kind in ('codex-node-agent', 't07-node-release')
    for platform in ('darwin-arm64', 'linux-amd64', 'linux-arm64')}


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
    result = {}
    total = 0
    for path in paths:
        size = path.stat().st_size
        if not 0 < size <= 256 * 1024 * 1024:
            raise ValueError('Invalid asset size')
        total += size
        if total > 512 * 1024 * 1024:
            raise ValueError('Package too large')
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        result[path.name] = (size, 'sha256:' + digest)
    return result


def load_verified_inventory(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 64 * 1024:
        raise ValueError('Expected verifier inventory file')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate inventory field')
            result[key] = value
        return result
    data = json.loads(path.read_text(), object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != FILES:
        raise ValueError('Verifier inventory mismatch')
    expected = {}
    for name, item in data.items():
        if (not isinstance(item, dict) or set(item) != {'size', 'sha256'}
                or type(item['size']) is not int or not 0 < item['size'] <= 256 * 1024 * 1024
                or not isinstance(item['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', item['sha256'])):
            raise ValueError('Invalid verified inventory record')
        expected[name] = (item['size'], 'sha256:' + item['sha256'])
    return expected


def check_remote(release, expected, tag):
    if release.get('draft') is not True or release.get('tag_name') != tag:
        raise ValueError('Expected new draft')
    assets = release.get('assets', [])
    if len(assets) != len(expected) or {a.get('name') for a in assets} != set(expected):
        raise ValueError('Remote inventory mismatch; remains draft')
    for asset in assets:
        if (asset.get('size'), asset.get('digest')) != expected[asset['name']]:
            raise ValueError('Remote digest mismatch; remains draft')


def publish(directory, tag, source_sha, workflow_sha, verified_inventory):
    if not re.fullmatch(r'v[0-9]{4}\.[0-9]{2}\.[0-9]{2}-codex-unix-root2-[1-9][0-9]*', tag):
        raise ValueError('Invalid tag')
    if not re.fullmatch(r'[a-f0-9]{40}', source_sha):
        raise ValueError('Invalid source')
    if not re.fullmatch(r'[a-f0-9]{40}', workflow_sha):
        raise ValueError('Invalid workflow commit')
    expected = load_verified_inventory(verified_inventory)
    if inventory(directory) != expected:
        raise ValueError('Package changed after cryptographic verification')
    refs = json.loads(gh('api', f'repos/{REPO}/git/matching-refs/tags/{tag}'))
    if any(r.get('ref') == 'refs/tags/' + tag for r in refs):
        raise ValueError('Tag exists; never overwrite')
    assets = [str(Path(directory) / name) for name in sorted(FILES)]
    notes = (f'Codex Unix root2 new-install channel. Source SHA: {source_sha}. '
             'Independent self-use trust; production trust unchanged. '
             'Signed artifact integrity checked. Real root2 installation/pairing/supervisor-upgrade/rollback/model NOT_RUN. Legacy installers and identities unchanged.')
    gh('release', 'create', tag, *assets, '--repo', REPO, '--draft', '--latest=false', '--target', workflow_sha, '--title', tag, '--notes', notes)
    release = json.loads(gh('api', f'repos/{REPO}/releases/tags/{tag}'))
    check_remote(release, expected, tag)
    gh('release', 'edit', tag, '--repo', REPO, '--draft=false', '--latest=false')
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
    p.add_argument('--verified-inventory', required=True)
    a = p.parse_args()
    try:
        if not os.environ.get('GH_TOKEN'):
            raise ValueError('Token unavailable')
        publish(a.dir, a.tag, a.source_sha, a.workflow_sha, a.verified_inventory)
    except Exception:
        p.exit(1, 'Publication failed or uncertain; check draft/release before taking further action.\n')
