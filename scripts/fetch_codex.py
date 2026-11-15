"""Fetch one reviewed private build as inert bytes. Never unpack or execute it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPO = 'GameRisker/lattice'
API = 'https://api.github.com'
WORKFLOW = '.github/workflows/codex-unix-build.yml'
MAX_BYTES = 512 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024


class InvalidArtifact(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def positive(value):
    if not re.fullmatch(r'[1-9][0-9]{0,19}', str(value)):
        raise InvalidArtifact('Invalid numeric identifier')
    return int(value)


def digest(value, length=64):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{%d}' % length, value):
        raise InvalidArtifact('Invalid reviewed digest')
    return value


def bounded_read(response, limit):
    data = response.read(limit + 1)
    if len(data) > limit:
        raise InvalidArtifact('Response exceeds size limit')
    return data


class Client:
    def __init__(self, token, opener=None):
        if not token or '\n' in token or '\r' in token:
            raise InvalidArtifact('GitHub App token missing or invalid')
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(self, path):
        # Only our fixed repository's read-only run/artifact resources are legal.
        if not re.fullmatch(r'/repos/GameRisker/lattice/actions/(runs/[1-9][0-9]*|artifacts/[1-9][0-9]*(/zip)?)', path):
            raise InvalidArtifact('API endpoint not permitted')
        return urllib.request.Request(API + path, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'lattice-reviewed-artifact-reader',
        })

    def metadata(self, path):
        with self.opener.open(self.request(path), timeout=60) as response:
            if response.status != 200:
                raise InvalidArtifact('Metadata unavailable')
            return json.loads(bounded_read(response, MAX_JSON))

    def archive(self, artifact_id):
        # Do not allow urllib to forward Authorization to a signed storage URL.
        request = self.request(f'/repos/{REPO}/actions/artifacts/{positive(artifact_id)}/zip')
        try:
            response = self.opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            try:
                if error.code != 302:
                    raise InvalidArtifact('Archive redirect unavailable') from None
                location = error.headers.get('Location', '')
            finally:
                error.close()
        else:
            response.close()
            raise InvalidArtifact('Expected GitHub archive redirect')
        parts = urllib.parse.urlsplit(location)
        host = (parts.hostname or '').lower()
        if (parts.scheme != 'https' or parts.username or parts.password or parts.fragment
                or parts.port not in (None, 443)
                or not (host.endswith('.blob.core.windows.net') or host.endswith('.githubusercontent.com'))):
            raise InvalidArtifact('Archive storage origin not permitted')
        # Fresh request has no token/cookies; further redirects are rejected.
        response = self.opener.open(urllib.request.Request(location, headers={
            'User-Agent': 'lattice-reviewed-artifact-reader'}), timeout=60)
        if response.status != 200:
            response.close()
            raise InvalidArtifact('Archive unavailable')
        return response


def validate_metadata(run, artifact, run_id, artifact_id, source_sha, archive_sha):
    run_id, artifact_id = positive(run_id), positive(artifact_id)
    digest(source_sha, 40)
    digest(archive_sha)
    if not isinstance(run, dict) or not isinstance(artifact, dict):
        raise InvalidArtifact('Metadata must be objects')
    repo, head_repo = run.get('repository') or {}, run.get('head_repository') or {}
    if (run.get('id') != run_id or repo.get('full_name') != REPO
            or head_repo.get('full_name') != REPO or not isinstance(repo.get('id'), int)
            or repo.get('id') != head_repo.get('id') or run.get('head_branch') != 'main'
            or run.get('head_sha') != source_sha or run.get('event') != 'workflow_dispatch'
            or run.get('run_attempt') != 1 or run.get('status') != 'completed'
            or run.get('conclusion') != 'success' or run.get('path') != WORKFLOW):
        raise InvalidArtifact('Build does not match approved source and workflow')
    origin = artifact.get('workflow_run') or {}
    size = artifact.get('size_in_bytes')
    if (artifact.get('id') != artifact_id or artifact.get('expired') is not False
            or artifact.get('name') != f'codex-unix-root2-unsigned-{run_id}'
            or artifact.get('digest') != 'sha256:' + archive_sha
            or type(size) is not int or not 0 < size < MAX_BYTES
            or origin.get('id') != run_id or origin.get('head_sha') != source_sha
            or origin.get('head_branch') != 'main' or origin.get('repository_id') != repo['id']
            or origin.get('head_repository_id') != repo['id']):
        raise InvalidArtifact('Artifact does not match approved build and digest')


def fetch(client, run_id, artifact_id, source_sha, archive_sha, out):
    run_id, artifact_id = positive(run_id), positive(artifact_id)
    digest(source_sha, 40)
    digest(archive_sha)
    run = client.metadata(f'/repos/{REPO}/actions/runs/{run_id}')
    artifact = client.metadata(f'/repos/{REPO}/actions/artifacts/{artifact_id}')
    validate_metadata(run, artifact, run_id, artifact_id, source_sha, archive_sha)
    out = Path(out)
    if out.exists() or out.is_symlink():
        raise InvalidArtifact('Output already exists')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.artifact-', dir=out.parent, delete=False) as target:
            temporary = target.name
            hasher = hashlib.sha256()
            total = 0
            with client.archive(artifact_id) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total >= MAX_BYTES:
                        raise InvalidArtifact('Archive exceeds size limit')
                    hasher.update(chunk)
                    target.write(chunk)
            if not total or hasher.hexdigest() != archive_sha:
                raise InvalidArtifact('Downloaded archive digest mismatch')
            target.flush()
            os.fsync(target.fileno())
        # Fail if another process has created output. Never replace an existing file.
        os.link(temporary, out)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--artifact-id', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--artifact-sha256', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        token = os.environ.pop('GH_TOKEN', '')
        fetch(Client(token), args.run_id, args.artifact_id, args.source_sha,
              args.artifact_sha256, args.out)
    except Exception:
        # Do not print signed URLs, tokens, API payloads or private build metadata.
        parser.exit(1, 'Reviewed artifact fetch failed; no verified output produced.\n')


if __name__ == '__main__':
    main()
