#!/usr/bin/env python3
"""Verify an accepted signed delivery and prepare its exact unpublished GitHub Release."""


def require_accepted_source(repo, source, token):
    import json, urllib.parse, urllib.request
    query = urllib.parse.urlencode({'head_sha': source, 'branch': 'main', 'per_page': 1})
    for workflow in ('verification.yml', 'product-onboarding.yml'):
        url = f'https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs?{query}'
        request = urllib.request.Request(url, headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(1024 * 1024 + 1)
        except OSError:
            raise SystemExit('independent acceptance metadata is unavailable: ' + workflow) from None
        if len(body) > 1024 * 1024:
            raise SystemExit('independent acceptance metadata is oversized: ' + workflow)
        try:
            runs = json.loads(body)['workflow_runs']
        except (ValueError, KeyError, TypeError):
            raise SystemExit('independent acceptance metadata is invalid: ' + workflow) from None
        # PR metadata names its head SHA, but checkout normally tests a synthetic
        # merge commit. Only direct main-branch executions accept release source.
        if (not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict)
                or runs[0].get('head_sha') != source or runs[0].get('head_branch') != 'main'
                or runs[0].get('event') not in ('push', 'workflow_dispatch')
                or runs[0].get('status') != 'completed' or runs[0].get('conclusion') != 'success'):
            raise SystemExit('exact-source main acceptance is required: ' + workflow)


def restore_accepted_delivery(repo, run_id, token, root):
    """Recover only a retained delivery whose original native gate succeeded."""
    import hashlib, json, re, shutil, stat, subprocess, urllib.request, zipfile
    if not re.fullmatch(r'[1-9][0-9]{0,19}', run_id):
        raise SystemExit('invalid accepted run identity')

    def api(route):
        request = urllib.request.Request(f'https://api.github.com/repos/{repo}/{route}', headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(1024 * 1024 + 1)
        except OSError:
            raise SystemExit('accepted delivery metadata is unavailable') from None
        if len(body) > 1024 * 1024:
            raise SystemExit('accepted delivery metadata is oversized')
        try:
            return json.loads(body)
        except ValueError:
            raise SystemExit('accepted delivery metadata is invalid') from None

    run = api('actions/runs/' + run_id)
    if (not isinstance(run, dict) or run.get('id') != int(run_id)
            or run.get('path') != '.github/workflows/offline-release.yml'
            or run.get('head_branch') != 'main' or run.get('event') != 'workflow_dispatch'
            or run.get('status') != 'completed' or run.get('conclusion') not in ('success', 'failure')
            or not isinstance(run.get('head_sha'), str)
            or not re.fullmatch(r'[0-9a-f]{40}', run.get('head_sha', ''))):
        raise SystemExit('recovery requires an original completed main release dispatch')
    source = run['head_sha']
    require_accepted_source(repo, source, token)
    jobs = api(f'actions/runs/{run_id}/jobs?per_page=100')
    if (not isinstance(jobs, dict) or not isinstance(jobs.get('jobs'), list)
            or len(jobs['jobs']) != jobs.get('total_count') or len(jobs['jobs']) >= 100
            or any(not isinstance(job, dict) for job in jobs['jobs'])):
        raise SystemExit('incomplete accepted job inventory')
    native = [job for job in jobs['jobs'] if job.get('name') == 'native-offline-lifecycle']
    if len(native) != 1 or native[0].get('status') != 'completed' or native[0].get('conclusion') != 'success':
        raise SystemExit('original native release acceptance did not succeed')
    inventory = api(f'actions/runs/{run_id}/artifacts?per_page=100')
    if (not isinstance(inventory, dict) or not isinstance(inventory.get('artifacts'), list)
            or len(inventory['artifacts']) != inventory.get('total_count') or len(inventory['artifacts']) >= 100
            or any(not isinstance(item, dict) for item in inventory['artifacts'])):
        raise SystemExit('incomplete accepted artifact inventory')
    artifacts = [item for item in inventory['artifacts'] if item.get('name') == 'offline-release-delivery']
    if len(artifacts) != 1:
        raise SystemExit('exactly one original accepted delivery is required')
    artifact = artifacts[0]
    identity = artifact.get('workflow_run', {})
    if (artifact.get('expired') is not False or type(artifact.get('id')) is not int or artifact['id'] <= 0
            or type(artifact.get('size_in_bytes')) is not int or not 0 < artifact['size_in_bytes'] <= 8 * 1024**3
            or not isinstance(artifact.get('digest'), str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', ''))
            or not isinstance(identity, dict) or identity.get('id') != int(run_id)
            or identity.get('head_sha') != source or identity.get('head_branch') != 'main'):
        raise SystemExit('retained delivery does not identify the accepted run')
    archive = root / 'accepted-delivery.zip'
    with archive.open('xb') as output:
        subprocess.run(['gh', 'api', f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip'],
                       stdout=output, check=True, timeout=900)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if archive.stat().st_size != artifact['size_in_bytes'] or 'sha256:' + digest.hexdigest() != artifact['digest']:
        raise SystemExit('retained delivery transport integrity failed')
    delivery = root / 'delivery'
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if (not 0 < len(entries) <= 90 or len({item.filename for item in entries}) != len(entries)
                or sum(item.file_size for item in entries) > 8 * 1024**3
                or any(not re.fullmatch(r'[A-Za-z0-9._-]+', item.filename) or item.filename in ('.', '..')
                       or item.is_dir() or not 0 < item.file_size < 2 * 1024**3
                       or stat.S_ISLNK(item.external_attr >> 16) for item in entries)):
            raise SystemExit('unsafe retained delivery archive')
        delivery.mkdir(mode=0o700)
        for item in entries:
            with bundle.open(item) as incoming, (delivery / item.filename).open('xb') as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
    # Extraction verifies ZIP CRCs; the ordinary publication path still checks
    # exact inventory, protected trust, signature, source, version and every byte.
    return source, run_id


def main(accepted_run_id=None):
    import base64, hashlib, json, os, pathlib, re, subprocess, urllib.error, urllib.request
    root = pathlib.Path(os.environ['RUNNER_TEMP'])
    delivery = root / 'delivery'
    version, repo, source = os.environ['RELEASE_VERSION'], os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA']
    acceptance_run = os.environ['GITHUB_RUN_ID']
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise SystemExit('invalid release version')
    if accepted_run_id is not None:
        source, acceptance_run = restore_accepted_delivery(repo, accepted_run_id, os.environ['GH_TOKEN'], root)
    archive = f'matrix-{version}-linux-amd64.tar.gz'
    metadata = {'release-trust.json', 'release.json', 'release.sig', 'bundle.sha256',
                'SHA256SUMS', 'acceptance-evidence.zip'}
    files = sorted(delivery.iterdir())
    parts = [p for p in files if re.fullmatch(re.escape(archive) + r'\.part-[0-9]{3}', p.name)]
    if not parts or len(files) > 90 or {p.name for p in files} != metadata | {p.name for p in parts}:
        raise SystemExit('unexpected release delivery inventory')
    if [p.name for p in parts] != [f'{archive}.part-{n:03d}' for n in range(len(parts))]:
        raise SystemExit('release delivery chunks are not contiguous')
    for item in files:
        if item.is_symlink() or not item.is_file() or not 0 < item.stat().st_size < 2 * 1024**3:
            raise SystemExit('unsafe release delivery file')
    if (any((delivery / name).stat().st_size > 1024 * 1024 for name in metadata - {'acceptance-evidence.zip'})
            or (delivery / 'acceptance-evidence.zip').stat().st_size > 32 * 1024 * 1024):
        raise SystemExit('oversized release delivery metadata')
    checksums = {}
    for item in files:
        digest = hashlib.sha256()
        with item.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        checksums[item.name] = digest.hexdigest()
    declared = {}
    for line in (delivery / 'SHA256SUMS').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]+)', line)
        if not match or match[2] in declared:
            raise SystemExit('invalid release checksum inventory')
        declared[match[2]] = match[1]
    if declared != {name: digest for name, digest in checksums.items() if name != 'SHA256SUMS'}:
        raise SystemExit('release checksums differ from delivery')
    archive_digest = hashlib.sha256()
    for part in parts:
        with part.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                archive_digest.update(chunk)
    if (delivery / 'bundle.sha256').read_text() != f'{archive_digest.hexdigest()}  {archive}\n':
        raise SystemExit('assembled release bundle differs from acceptance')
    trust_bytes = (delivery / 'release-trust.json').read_bytes()
    if trust_bytes != os.environ['MATRIX_RELEASE_TRUST_ROOT'].encode():
        raise SystemExit('release trust differs from protected configuration')
    trust = json.loads(trust_bytes)
    manifest = json.loads((delivery / 'release.json').read_bytes())
    if manifest['release']['sourceCommit'] != source or manifest['release']['version'] != version or manifest['release'].get('previousId'):
        raise SystemExit('delivery is not this source fresh-install release')
    if manifest['signer']['keyId'] != trust['keyId'] or manifest['signer']['algorithm'] != trust['algorithm']:
        raise SystemExit('release signing identity differs')
    public_key = base64.b64decode(trust['publicKey'], validate=True)
    if len(public_key) != 32:
        raise SystemExit('invalid release verification key')
    # RFC 8410 Ed25519 SubjectPublicKeyInfo; only public bytes are written.
    public_path = root / 'release-public.der'
    public_path.write_bytes(bytes.fromhex('302a300506032b6570032100') + public_key)
    subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(public_path),
                    '-rawin', '-in', str(delivery / 'release.json'), '-sigfile', str(delivery / 'release.sig')], check=True)
    headers = {'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'}
    def api(route):
        request = urllib.request.Request(f'https://api.github.com/repos/{repo}/{route}', headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise SystemExit('oversized release metadata response')
                return json.loads(body)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise SystemExit('release metadata request failed')
    existing_tag = api('git/ref/tags/' + version)
    if existing_tag is not None and (existing_tag['object']['type'] != 'commit' or existing_tag['object']['sha'] != source):
        raise SystemExit('release tag already identifies a different source')
    notes = root / 'release-notes.md'
    notes.write_text(f'''本安装包提供 Elasticsearch、Logstash、Kibana 和 Redis 的统一纳管，沿用平台的权限、配额、任务及审计流程。

    支持 Linux amd64 宿主 Docker，无需 DinD。本包用于全新安装；旧私有候选不能据此直接升级。Redis 为单节点 AOF；平台备份不替代产品业务数据备份。

    源码：`{source}`。完整离线安装、升级回滚、恢复、引擎重启及浏览器验收：[运行证据](https://github.com/{repo}/actions/runs/{acceptance_run})。
    实际验收报告和 12 张页面截图保存在本 Release 的 `acceptance-evidence.zip` 中。

    下载本 Release 的全部附件，放在同一目录执行：

    ```sh
    sha256sum --check SHA256SUMS
    cat {archive}.part-* > {archive}
    sha256sum --check bundle.sha256
    mkdir -m 700 matrix-release
    tar --extract --gzip --file {archive} --directory matrix-release
    ```

    然后按[安装与首次使用手册](https://github.com/{repo}/blob/{source}/docs/user-guide/getting-started.md)准备主机和安全邮件配置。产品团队请看[接入手册](https://github.com/{repo}/blob/{source}/docs/product-guide/managed-service-onboarding.md)。

    发布信任指纹：`{trust['publicKeyFingerprint']}`。接受前请与可信交付方核对；压缩包校验值不能代替签名信任。
    '''.replace('\n    ', '\n'), encoding='utf-8')
    def find_release():
        # Tag lookup can return 404 for a draft which already exists. The
        # authenticated release list includes drafts; finish bounded pagination
        # before authorizing creation so retries cannot duplicate an older one.
        matches = []
        for page in range(1, 11):
            releases = api(f'releases?per_page=100&page={page}')
            if (not isinstance(releases, list) or len(releases) > 100
                    or any(not isinstance(item, dict) or not isinstance(item.get('tag_name'), str)
                           or type(item.get('id')) is not int or item['id'] <= 0 for item in releases)):
                raise SystemExit('invalid release listing')
            matches.extend(item for item in releases if item['tag_name'] == version)
            if len(releases) < 100:
                break
        else:
            raise SystemExit('release listing exceeds the lookup bound')
        if len(matches) > 1:
            raise SystemExit('ambiguous release identity')
        return matches[0] if matches else None

    existing_release = find_release()
    if existing_release is None:
        subprocess.run(['gh', 'release', 'create', version, '--repo', repo, '--target', source, '--draft',
                        '--title', 'Matrix ' + version, '--notes-file', str(notes)], check=True)
        existing_release = find_release()
    if (not existing_release or not existing_release['draft'] or existing_release['target_commitish'] != source
            or existing_release.get('body') != notes.read_text(encoding='utf-8')):
        raise SystemExit('release is not the matching unpublished draft')
    release_id = existing_release['id']
    existing_assets = api(f'releases/{release_id}/assets?per_page=100')
    expected_names = set(checksums)
    if (not isinstance(existing_assets, list) or any(a['name'] not in expected_names for a in existing_assets)
            or len({a['name'] for a in existing_assets}) != len(existing_assets)):
        raise SystemExit('unexpected existing release assets')
    for asset in existing_assets:
        if asset['state'] != 'uploaded' or asset.get('digest') != 'sha256:' + checksums[asset['name']]:
            raise SystemExit('existing release asset differs; no asset was overwritten')
    uploaded_names = {a['name'] for a in existing_assets}
    for item in files:
        if item.name not in uploaded_names:
            subprocess.run(['gh', 'release', 'upload', version, str(item), '--repo', repo], check=True)
    actual = api(f'releases/{release_id}/assets?per_page=100')
    if not isinstance(actual, list) or len(actual) != len(files) or {a['name'] for a in actual} != expected_names:
        raise SystemExit('uploaded release inventory differs')
    for asset in actual:
        item = delivery / asset['name']
        if asset['state'] != 'uploaded' or asset['size'] != item.stat().st_size or asset.get('digest') != 'sha256:' + checksums[item.name]:
            raise SystemExit('uploaded release bytes differ')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write(f'Verified draft Release: {existing_release["html_url"]}\n\nSource: `{source}`. All uploaded asset sizes and SHA-256 digests match the accepted delivery. The draft remains unpublished for final review.\n')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-run', help='Recover the exact retained delivery of an accepted main dispatch')
    main(parser.parse_args().resume_run)
