#!/usr/bin/env python3
"""Verify real SMTP delivery and isolation of the operator-owned demo mailbox.

Only synthetic messages to the fixed internal recipient are submitted.
Reports contain checks only, never credentials, message bodies or codes.
"""
import base64
import json
import os
import pathlib
import smtplib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

CONFIG = pathlib.Path('/etc/matrix-demo-mail')
CHANNEL = pathlib.Path('/etc/matrix/security-mail.json')
RECIPIENT = 'receiver@demo.matrix.test'
checks = []


def require(condition, name):
    if not condition:
        raise RuntimeError(name)
    checks.append(name)


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('docker-observation-unavailable')
    return result.stdout


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root-required')
    channel = json.loads(CHANNEL.read_text())
    access = json.loads((CONFIG / 'operator-access.json').read_text())
    context = ssl.create_default_context(cadata=channel['trustedCaPem'])
    client_container = json.loads(docker('inspect', 'matrix-demo-mail'))[0]
    network = json.loads(docker('network', 'inspect', 'matrix-demo-mail-internal'))[0]
    require(client_container['State']['Running'], 'mailbox-running')
    require(network['Internal'] and len(client_container['NetworkSettings']['Networks']) == 1, 'internal-network-only')
    require(not client_container['HostConfig']['Privileged'] and client_container['HostConfig']['ReadonlyRootfs'], 'restricted-container')
    require(all(mount['Destination'] != '/var/run/docker.sock' for mount in client_container['Mounts']), 'no-docker-socket')
    require(not client_container['HostConfig']['PortBindings'], 'no-docker-published-ports')
    for name, expected in (('ui', ['127.0.0.1:8025']), ('smtp', ['127.0.0.1:2525', channel['host'] + ':2525'])):
        unit = 'matrix-demo-mail-' + name + '.socket'
        unit_path = pathlib.Path('/etc/systemd/system') / unit
        listeners = [line.split('=', 1)[1] for line in unit_path.read_text().splitlines() if line.startswith('ListenStream=')]
        state = subprocess.run(['systemctl', 'is-active', '--quiet', unit], capture_output=True)
        require(sorted(listeners) == sorted(expected) and state.returncode == 0, name + '-private-host-socket')
    environment = dict(entry.split('=', 1) for entry in client_container['Config']['Env'] if '=' in entry)
    require(not any(environment.get(name) for name in ('MP_SMTP_RELAY_HOST', 'MP_SMTP_RELAY_CONFIG',
            'MP_SMTP_RELAY_MATCHING', 'MP_SMTP_FORWARD_HOST', 'MP_SMTP_FORWARD_CONFIG')) and
            environment.get('MP_SMTP_RELAY_ALL') == 'false', 'relay-and-forwarding-unconfigured')
    pid = str(client_container['State']['Pid'])
    no_route = subprocess.run(['nsenter', '-t', pid, '-n', 'ip', 'route', 'show', 'default'], capture_output=True, timeout=10)
    require(no_route.returncode == 0 and not no_route.stdout.strip(), 'no-default-route')
    egress_probe = (
        "import socket,sys\n"
        "try:\n socket.create_connection(('1.1.1.1',443),timeout=2).close()\n"
        "except OSError as error:\n sys.exit(0 if error.errno==101 else 2)\n"
        "sys.exit(1)\n"
    )
    external = subprocess.run(['nsenter', '-t', pid, '-n', '/usr/bin/python3', '-c', egress_probe], capture_output=True, timeout=5)
    require(external.returncode == 0, 'internet-egress-unreachable')

    def smtp(authenticate=True):
        client = smtplib.SMTP(channel['host'], channel['port'], timeout=8)
        client.ehlo()
        client.starttls(context=context)
        client.ehlo()
        if authenticate:
            # Match the production adapter's exact SASL mechanism.
            client.auth('PLAIN', lambda challenge=None: '\0' + channel['username'] + '\0' + channel['password'])
        return client

    with smtplib.SMTP(channel['host'], channel['port'], timeout=8) as client:
        client.ehlo()
        code, _ = client.mail(channel['from'])
        require(code >= 500, 'plaintext-submission-rejected')
    with smtp(False) as client:
        code, _ = client.mail(channel['from'])
        if code < 500:
            code, _ = client.rcpt(RECIPIENT)
        require(code >= 500, 'unauthenticated-submission-rejected')
    with smtp(False) as client:
        rejected = False
        try:
            client.auth('PLAIN', lambda challenge=None: '\0' + channel['username'] + '\0invalid-demo-test-password')
        except smtplib.SMTPAuthenticationError:
            rejected = True
        require(rejected, 'incorrect-password-rejected')
    with smtp() as client:
        require(client.mail(channel['from'])[0] == 250, 'authenticated-sender-accepted')
        require(client.rcpt('external-test@example.net')[0] >= 500, 'external-recipient-rejected')
        client.rset()
        client.mail(channel['from'])
        require(client.rcpt('unlisted@demo.matrix.test')[0] >= 500, 'unlisted-internal-recipient-rejected')
    subject = 'Matrix internal mail verification ' + uuid.uuid4().hex
    body = 'Synthetic internal-only delivery check. No real user information.'
    message = ('From: ' + channel['from'] + '\r\nTo: ' + RECIPIENT + '\r\nSubject: ' + subject +
               '\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n' + body + '\r\n')
    with smtp() as client:
        require(client.sendmail(channel['from'], [RECIPIENT], message) == {}, 'authenticated-tls-delivery-accepted')

    auth = 'Basic ' + base64.b64encode((access['username'] + ':' + access['password']).encode()).decode()

    def mailbox(endpoint, authenticated=True):
        request = urllib.request.Request('http://127.0.0.1:8025' + endpoint)
        if authenticated:
            request.add_header('Authorization', auth)
        with urllib.request.urlopen(request, timeout=8) as response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError('mailbox-observation-oversized')
            return json.loads(data)

    rejected = False
    try:
        mailbox('/api/v1/messages', False)
    except urllib.error.HTTPError as error:
        rejected = error.code == 401
    require(rejected, 'mailbox-read-requires-authentication')
    matches = []
    for _ in range(10):
        messages = mailbox('/api/v1/messages')['messages']
        matches = [item for item in messages if item['Subject'] == subject]
        if matches:
            break
        time.sleep(0.5)
    require(len(matches) == 1, 'message-stored-once-in-internal-mailbox')
    item = mailbox('/api/v1/message/' + matches[0]['ID'])
    require(body in item['Text'] and channel['password'] not in json.dumps(item), 'stored-message-matches-without-credential')
    print(json.dumps({'status': 'passed', 'checks': checks, 'externalDelivery': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'failed', 'checks': checks, 'category': type(error).__name__,
                          'failedCheck': str(error) if isinstance(error, RuntimeError) else None}), file=sys.stderr)
        sys.exit(1)
