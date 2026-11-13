import copy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import urllib.error
from email.message import Message

import fetch as reader

PAYLOAD = b'not executed zip bytes'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
SHA = 'a' * 40
RUN = {'id': 12, 'repository': {'full_name': reader.REPO, 'id': 100},
       'head_repository': {'full_name': reader.REPO, 'id': 100}, 'head_branch': 'main',
       'head_sha': SHA, 'event': 'workflow_dispatch', 'run_attempt': 1,
       'status': 'completed', 'conclusion': 'success', 'path': reader.WORKFLOW}
ART = {'id': 34, 'expired': False, 'name': 'deepseek-windows-unsigned-12',
       'digest': 'sha256:' + DIGEST, 'size_in_bytes': len(PAYLOAD),
       'workflow_run': {'id': 12, 'head_sha': SHA, 'head_branch': 'main',
                        'repository_id': 100, 'head_repository_id': 100}}


class Response(io.BytesIO):
    status = 200


class FakeClient:
    def __init__(self, payload=PAYLOAD):
        self.payload = payload
    def metadata(self, path):
        return copy.deepcopy(RUN if '/runs/' in path else ART)
    def archive(self, artifact_id):
        return Response(self.payload)


class RedirectOpener:
    def __init__(self, target='https://example.blob.core.windows.net/artifact?sig=secret'):
        self.requests = []
        self.target = target
    def open(self, request, timeout):
        self.requests.append(request)
        if len(self.requests) == 1:
            headers = Message()
            headers['Location'] = self.target
            raise urllib.error.HTTPError(request.full_url, 302, 'redirect', headers, io.BytesIO())
        return Response(PAYLOAD)


class Tests(unittest.TestCase):
    def test_approved_metadata(self):
        reader.validate_metadata(RUN, ART, 12, 34, SHA, DIGEST)

    def test_bad_run_fields(self):
        for field, value in [('id', 99), ('head_branch', 'dev'), ('head_sha', 'b'*40),
                             ('event', 'pull_request'), ('run_attempt', 2),
                             ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('path', '.github/workflows/other.yml')]:
            with self.subTest(field=field):
                run = copy.deepcopy(RUN)
                run[field] = value
                with self.assertRaises(reader.InvalidArtifact):
                    reader.validate_metadata(run, ART, 12, 34, SHA, DIGEST)

    def test_wrong_repository(self):
        for field in ['repository', 'head_repository']:
            run = copy.deepcopy(RUN)
            run[field]['full_name'] = 'attacker/lattice'
            with self.assertRaises(reader.InvalidArtifact):
                reader.validate_metadata(run, ART, 12, 34, SHA, DIGEST)

    def test_bad_artifact_fields(self):
        for field, value in [('id', 99), ('expired', True), ('name', 'latest'),
                             ('digest', 'sha256:'+'b'*64), ('size_in_bytes', reader.MAX_BYTES),
                             ('size_in_bytes', True)]:
            with self.subTest(field=field):
                artifact = copy.deepcopy(ART)
                artifact[field] = value
                with self.assertRaises(reader.InvalidArtifact):
                    reader.validate_metadata(RUN, artifact, 12, 34, SHA, DIGEST)

    def test_wrong_artifact_origin(self):
        for field, value in [('id', 13), ('head_sha', 'b'*40), ('head_branch', 'dev'),
                             ('repository_id', 101), ('head_repository_id', 101)]:
            artifact = copy.deepcopy(ART)
            artifact['workflow_run'][field] = value
            with self.assertRaises(reader.InvalidArtifact):
                reader.validate_metadata(RUN, artifact, 12, 34, SHA, DIGEST)

    def test_fetch_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)/'archive.zip'
            reader.fetch(FakeClient(), 12, 34, SHA, DIGEST, out)
            self.assertEqual(out.read_bytes(), PAYLOAD)
            self.assertEqual(list(Path(directory).iterdir()), [out])

    def test_bad_bytes_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)/'archive.zip'
            with self.assertRaises(reader.InvalidArtifact):
                reader.fetch(FakeClient(b'bad'), 12, 34, SHA, DIGEST, out)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)/'archive.zip'
            out.write_bytes(b'existing')
            with self.assertRaises(reader.InvalidArtifact):
                reader.fetch(FakeClient(), 12, 34, SHA, DIGEST, out)
            self.assertEqual(out.read_bytes(), b'existing')

    def test_redirect_has_no_authorization(self):
        opener = RedirectOpener()
        with reader.Client('test-token', opener).archive(34) as response:
            self.assertEqual(response.read(), PAYLOAD)
        self.assertEqual(opener.requests[0].get_header('Authorization'), 'Bearer test-token')
        self.assertIsNone(opener.requests[1].get_header('Authorization'))
        self.assertEqual(opener.requests[1].full_url, opener.target)

    def test_redirect_rejects_other_origins(self):
        for url in ['http://x.blob.core.windows.net/a', 'https://evil.test/a',
                    'https://user:pass@x.blob.core.windows.net/a',
                    'https://x.blob.core.windows.net:8080/a',
                    'https://x.blob.core.windows.net.evil.test/a']:
            opener = RedirectOpener(url)
            with self.assertRaises(reader.InvalidArtifact):
                reader.Client('token', opener).archive(34)
            self.assertEqual(len(opener.requests), 1)

    def test_api_endpoint_allowlist(self):
        client = reader.Client('token')
        for path in ['/user', '/repos/other/repo/actions/runs/12',
                     '/repos/GameRisker/lattice/actions/runs/12?url=bad']:
            with self.assertRaises(reader.InvalidArtifact):
                client.request(path)

    def test_bounds_and_inputs(self):
        with self.assertRaises(reader.InvalidArtifact):
            reader.bounded_read(io.BytesIO(b'1234'), 3)
        for value in ['../12', '0', '-1', '1e3', True]:
            with self.assertRaises(reader.InvalidArtifact):
                reader.positive(value)
        with self.assertRaises(reader.InvalidArtifact):
            reader.digest('A'*64)


if __name__ == '__main__':
    unittest.main()
