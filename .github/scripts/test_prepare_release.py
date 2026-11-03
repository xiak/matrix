#!/usr/bin/env python3
"""Publication-boundary tests; no GitHub mutation or network access is permitted."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import zipfile


RELEASE_BOUNDARY = runpy.run_path(str(Path(__file__).with_name('prepare-release.py')))
PREPARE = RELEASE_BOUNDARY['main']
REQUIRE_ACCEPTED_SOURCE = RELEASE_BOUNDARY['require_accepted_source']
REAL_RUN = subprocess.run


class AcceptedSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = '1' * 40
        self.runs = {name: [{'head_sha': self.source, 'head_branch': 'main',
                            'event': event, 'status': 'completed', 'conclusion': 'success'}]
                     for name, event in (('verification.yml', 'push'),
                                         ('product-onboarding.yml', 'workflow_dispatch'))}
        self.observed_workflows = []

    def api(self, request, **_kwargs):
        url = urllib.parse.urlsplit(request.full_url)
        self.assertEqual(url.scheme, 'https')
        self.assertEqual(url.netloc, 'api.github.com')
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(urllib.parse.parse_qs(url.query),
                         {'head_sha': [self.source], 'branch': ['main'], 'per_page': ['1']})
        workflow = url.path.split('/')[-2]
        self.assertIn(workflow, self.runs)
        self.observed_workflows.append(workflow)
        return io.BytesIO(json.dumps({'workflow_runs': self.runs[workflow]}).encode())

    def accept(self):
        with mock.patch('urllib.request.urlopen', side_effect=self.api):
            REQUIRE_ACCEPTED_SOURCE('release-fixture/matrix', self.source, 'fixture-no-real-token')

    def test_both_exact_main_workflows_must_complete_successfully(self):
        self.accept()
        self.assertEqual(set(self.observed_workflows), set(self.runs))

    def test_pr_other_branch_or_other_source_cannot_accept_a_release(self):
        for workflow in self.runs:
            accepted = self.runs[workflow][0].copy()
            for change in ({'event': 'pull_request'}, {'event': 'pull_request_target'},
                           {'head_branch': 'feat/candidate'}, {'head_sha': '2' * 40}):
                with self.subTest(workflow=workflow, change=change):
                    self.runs[workflow] = [{**accepted, **change}]
                    with self.assertRaisesRegex(SystemExit, 'exact-source main acceptance'):
                        self.accept()
            self.runs[workflow] = [accepted]

    def test_missing_unfinished_failed_or_ambiguous_runs_are_rejected(self):
        for workflow in self.runs:
            accepted = self.runs[workflow][0].copy()
            for runs in ([], [accepted, accepted], [{}], [None], None,
                         [{**accepted, 'status': 'in_progress', 'conclusion': None}],
                         [{**accepted, 'conclusion': 'failure'}],
                         [{**accepted, 'conclusion': 'skipped'}]):
                with self.subTest(workflow=workflow, runs=runs):
                    self.runs[workflow] = runs
                    with self.assertRaisesRegex(SystemExit, 'exact-source main acceptance'):
                        self.accept()
            self.runs[workflow] = [accepted]

    def test_unavailable_metadata_is_not_treated_as_acceptance(self):
        failure = urllib.error.HTTPError('https://github.invalid/fixture', 404,
                                         'fixture missing', {}, io.BytesIO())
        with mock.patch('urllib.request.urlopen', side_effect=failure):
            with self.assertRaisesRegex(SystemExit, 'metadata is unavailable'):
                REQUIRE_ACCEPTED_SOURCE('release-fixture/matrix', self.source, 'fixture-no-real-token')

    def test_invalid_or_oversized_metadata_is_rejected(self):
        for body in (b'not json', b'[]', b'{}', b'null', b' ' * (1024 * 1024 + 1)):
            with self.subTest(bytes=len(body)):
                with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(body)):
                    with self.assertRaisesRegex(SystemExit, 'metadata is (invalid|oversized)'):
                        REQUIRE_ACCEPTED_SOURCE('release-fixture/matrix', self.source, 'fixture-no-real-token')


class ReleaseDeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='matrix-release-boundary-')
        self.root = Path(temporary.name).resolve()
        if self.root.parent != Path(tempfile.gettempdir()).resolve():
            raise RuntimeError('test cleanup root is outside the temporary directory')
        self.addCleanup(temporary.cleanup)
        self.delivery = self.root / 'delivery'
        self.delivery.mkdir()
        self.version = 'v0.3.0'
        self.source = '1' * 40
        self.archive = f'matrix-{self.version}-linux-amd64.tar.gz'
        self.private = self.root / 'test-only-private.pem'
        REAL_RUN(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(self.private)],
                 check=True, capture_output=True)
        public = REAL_RUN(['openssl', 'pkey', '-in', str(self.private), '-pubout', '-outform', 'DER'],
                          check=True, capture_output=True).stdout[-32:]
        self.trust = json.dumps({
            'apiVersion': 'installation.matrix.xiak.com/v1', 'kind': 'ReleaseTrustRoot',
            'keyId': 'release-boundary-test', 'algorithm': 'Ed25519',
            'publicKey': base64.b64encode(public).decode(),
            'publicKeyFingerprint': 'sha256:' + hashlib.sha256(public).hexdigest(),
        }, separators=(',', ':'))
        (self.delivery / 'release-trust.json').write_text(self.trust, encoding='utf-8')
        self.manifest = {
            'release': {'sourceCommit': self.source, 'version': self.version},
            'signer': {'keyId': 'release-boundary-test', 'algorithm': 'Ed25519'},
        }
        self.sign_manifest()
        # The native lifecycle owns real bundle contents and tar-mode checks.
        # These bytes exercise the independent transport and publication boundary.
        payload = b'accepted signed bundle transport fixture'
        (self.delivery / (self.archive + '.part-000')).write_bytes(payload[:20])
        (self.delivery / (self.archive + '.part-001')).write_bytes(payload[20:])
        (self.delivery / 'bundle.sha256').write_text(
            hashlib.sha256(payload).hexdigest() + '  ' + self.archive + '\n', encoding='ascii')
        with zipfile.ZipFile(self.delivery / 'acceptance-evidence.zip', 'w') as evidence:
            evidence.writestr('fixture.json', '{"status":"test-fixture"}')
        self.refresh_checksums()
        self.environment = {
            'RUNNER_TEMP': str(self.root), 'RELEASE_VERSION': self.version,
            'GITHUB_REPOSITORY': 'release-fixture/matrix', 'GITHUB_SHA': self.source,
            'GITHUB_RUN_ID': '123', 'GH_TOKEN': 'fixture-no-real-token',
            'MATRIX_RELEASE_TRUST_ROOT': self.trust,
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary.md'),
        }
        self.release = None
        self.tag = None
        self.assets = []
        self.commands = []
        self.lose_upload_response = False
        self.corrupt_uploaded_digest = False

    def sign_manifest(self):
        (self.delivery / 'release.json').write_text(json.dumps(self.manifest), encoding='utf-8')
        REAL_RUN(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.private),
                  '-in', str(self.delivery / 'release.json'), '-out', str(self.delivery / 'release.sig')],
                 check=True, capture_output=True)

    def refresh_checksums(self):
        entries = [hashlib.sha256(item.read_bytes()).hexdigest() + '  ' + item.name + '\n'
                   for item in sorted(self.delivery.iterdir()) if item.name != 'SHA256SUMS']
        (self.delivery / 'SHA256SUMS').write_text(''.join(entries), encoding='ascii')

    def api(self, request, **_kwargs):
        url = request.full_url
        prefix = 'https://api.github.com/repos/release-fixture/matrix/'
        self.assertTrue(url.startswith(prefix))
        route = url[len(prefix):]
        if route == 'git/ref/tags/' + self.version:
            value = self.tag
        elif route == 'releases/tags/' + self.version:
            value = self.release
        elif route == 'releases/1/assets?per_page=100':
            value = self.assets
            if self.corrupt_uploaded_digest and value:
                value = [{**item, 'digest': 'sha256:' + '0' * 64} for item in value]
        else:
            self.fail('unexpected GitHub operation: ' + route)
        if value is None:
            raise urllib.error.HTTPError(url, 404, 'fixture missing', {}, io.BytesIO())
        return io.BytesIO(json.dumps(value).encode())

    def command(self, arguments, **kwargs):
        if arguments[0] == 'openssl':
            return REAL_RUN(arguments, capture_output=True, **kwargs)
        self.assertEqual(arguments[0], 'gh')
        self.commands.append(arguments)
        if arguments[1:3] == ['release', 'create']:
            self.assertIn('--draft', arguments)
            self.assertEqual(arguments[arguments.index('--target') + 1], self.source)
            notes = Path(arguments[arguments.index('--notes-file') + 1]).read_text(encoding='utf-8')
            self.release = {'id': 1, 'draft': True, 'target_commitish': self.source,
                            'body': notes, 'html_url': 'https://github.invalid/release-fixture/draft'}
        elif arguments[1:3] == ['release', 'upload']:
            item = Path(arguments[4])
            self.assertNotIn(item.name, {asset['name'] for asset in self.assets})
            self.assets.append({'name': item.name, 'state': 'uploaded', 'size': item.stat().st_size,
                                'digest': 'sha256:' + hashlib.sha256(item.read_bytes()).hexdigest()})
            if self.lose_upload_response:
                self.lose_upload_response = False
                raise subprocess.CalledProcessError(1, arguments)
        else:
            self.fail('publication or unrelated GitHub mutation is forbidden in this driver')
        return subprocess.CompletedProcess(arguments, 0)

    def prepare(self):
        with mock.patch.dict(os.environ, self.environment), \
                mock.patch('urllib.request.urlopen', side_effect=self.api), \
                mock.patch('subprocess.run', side_effect=self.command):
            PREPARE()

    def test_signed_exact_delivery_becomes_only_an_unpublished_draft(self):
        self.prepare()
        self.assertTrue(self.release['draft'])
        self.assertEqual({a['name'] for a in self.assets}, {p.name for p in self.delivery.iterdir()})
        self.assertIn('\n```sh\nsha256sum --check', self.release['body'])
        self.assertTrue((self.root / 'summary.md').is_file())

    def test_damaged_signature_is_rejected_even_with_updated_transport_checksums(self):
        (self.delivery / 'release.sig').write_bytes(b'X' * 64)
        self.refresh_checksums()
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_changed_chunk_cannot_redefine_the_accepted_bundle(self):
        (self.delivery / (self.archive + '.part-000')).write_bytes(b'changed bytes')
        self.refresh_checksums()
        with self.assertRaisesRegex(SystemExit, 'assembled release bundle differs'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_unexpected_private_file_is_never_uploaded(self):
        (self.delivery / 'signer.json').write_text('test-only-private-material')
        with self.assertRaisesRegex(SystemExit, 'unexpected release delivery inventory'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_checksum_inventory_cannot_name_paths_outside_delivery(self):
        (self.delivery / 'SHA256SUMS').write_text('0' * 64 + '  ../test-only-private.pem\n')
        with self.assertRaisesRegex(SystemExit, 'invalid release checksum inventory'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_foreign_source_and_upgrade_only_manifest_are_rejected(self):
        for change in ({'sourceCommit': '2' * 40}, {'version': 'v0.2.0'}, {'previousId': 'prior-release'}):
            with self.subTest(change=change):
                self.manifest['release'] = {'sourceCommit': self.source, 'version': self.version, **change}
                self.sign_manifest()
                self.refresh_checksums()
                with self.assertRaisesRegex(SystemExit, 'not this source fresh-install release'):
                    self.prepare()
                self.assertEqual(self.commands, [])

    def test_protected_trust_must_match_byte_for_byte(self):
        self.environment['MATRIX_RELEASE_TRUST_ROOT'] = self.trust + '\n'
        with self.assertRaisesRegex(SystemExit, 'trust differs from protected configuration'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_existing_tag_for_another_source_is_preserved(self):
        self.tag = {'object': {'type': 'commit', 'sha': '2' * 40}}
        with self.assertRaisesRegex(SystemExit, 'tag already identifies a different source'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_existing_publication_is_never_modified(self):
        self.prepare()
        self.release['draft'] = False
        self.commands.clear()
        with self.assertRaisesRegex(SystemExit, 'not the matching unpublished draft'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_changed_draft_body_is_not_claimed_as_owned_delivery(self):
        self.prepare()
        self.release['body'] = 'maintainer-owned notes'
        self.commands.clear()
        with self.assertRaisesRegex(SystemExit, 'not the matching unpublished draft'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_different_existing_asset_is_never_overwritten(self):
        self.prepare()
        self.assets[0]['digest'] = 'sha256:' + '0' * 64
        self.commands.clear()
        with self.assertRaisesRegex(SystemExit, 'existing release asset differs'):
            self.prepare()
        self.assertEqual(self.commands, [])

    def test_upload_response_loss_resumes_only_missing_matching_assets(self):
        self.lose_upload_response = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()
        retained = list(self.assets)
        self.commands.clear()
        self.prepare()
        self.assertTrue(self.release['draft'])
        self.assertTrue(all(asset in self.assets for asset in retained))
        self.assertEqual(len(self.assets), len(list(self.delivery.iterdir())))

    def test_uploaded_digest_mismatch_cannot_be_reported_as_verified(self):
        self.corrupt_uploaded_digest = True
        with self.assertRaisesRegex(SystemExit, 'uploaded release bytes differ'):
            self.prepare()
        self.assertTrue(self.release['draft'])
        self.assertFalse((self.root / 'summary.md').exists())


if __name__ == '__main__':
    unittest.main()
