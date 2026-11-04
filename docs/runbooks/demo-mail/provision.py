#!/usr/bin/env python3
"""Provision the operator-owned, internal-only demo mailbox from the runbook.

This is not a Matrix runtime component or an Internet mail delivery service.
Run once as root on the dedicated Linux Docker host. Secrets stay on that host.
Use --renew-certificate for annual leaf renewal under the existing private CA.
Use --allow-matrix-client after installation when UFW blocks the mail client.
"""
import ipaddress
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys

IMAGE = 'axllent/mailpit@sha256:9b3a463be15354c0f0eba91697d80e3e0d8a5623ef0e627cacc836bc17fd5231'
CONFIG = pathlib.Path('/etc/matrix-demo-mail')
DATA = pathlib.Path('/var/lib/matrix-demo-mail')
CHANNEL = pathlib.Path('/etc/matrix/security-mail.json')
CONTAINER = 'matrix-demo-mail'
NETWORK = 'matrix-demo-mail-internal'
RECIPIENT = 'receiver@demo.matrix.test'


def command(args, input_bytes=None):
    result = subprocess.run(args, input=input_bytes, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError('required host command failed: ' + pathlib.Path(args[0]).name)
    return result.stdout


def write(path, content):
    with path.open('xb') as target:
        target.write(content.encode() if isinstance(content, str) else content)
    path.chmod(0o600)


def matrix_mail_client():
    identifiers = command(['docker', 'ps', '-q', '--filter',
                           'label=com.docker.compose.service=iam-notification-dispatcher']).decode().split()
    if len(identifiers) != 1:
        raise RuntimeError('exactly one running Matrix notification dispatcher is required')
    client = json.loads(command(['docker', 'inspect', identifiers[0]]))[0]
    labels = client['Config']['Labels']
    if labels.get('com.xiak.matrix.managed') != 'true' or not labels.get('com.xiak.matrix.installation'):
        raise RuntimeError('notification dispatcher ownership is unavailable')
    eligible = []
    for name in client['NetworkSettings']['Networks']:
        network = json.loads(command(['docker', 'network', 'inspect', name]))[0]
        owned = network.get('Labels') or {}
        if owned.get('com.docker.compose.network') != 'mail-egress':
            continue
        if (network['Driver'] != 'bridge' or network['Internal'] or
                any(owned.get(key) != labels.get(key) for key in
                    ('com.docker.compose.project', 'com.xiak.matrix.installation'))):
            raise RuntimeError('notification egress network ownership differs')
        ranges = [ipaddress.ip_network(item['Subnet']) for item in network['IPAM']['Config']
                  if item.get('Subnet') and ipaddress.ip_network(item['Subnet']).version == 4]
        if len(ranges) != 1 or not ranges[0].is_private or ranges[0].prefixlen < 16:
            raise RuntimeError('one bounded private notification egress subnet is required')
        address = ipaddress.ip_interface(network['Containers'][client['Id']]['IPv4Address']).ip
        if address not in ranges[0]:
            raise RuntimeError('notification client is outside its egress subnet')
        bridge = network['Options'].get('com.docker.network.bridge.name') or 'br-' + network['Id'][:12]
        links = json.loads(command(['ip', '-j', '-d', 'link', 'show', 'dev', bridge]))
        if len(links) != 1 or links[0].get('linkinfo', {}).get('info_kind') != 'bridge':
            raise RuntimeError('notification egress bridge is unavailable')
        eligible.append((client, bridge, str(ranges[0])))
    if len(eligible) != 1:
        raise RuntimeError('one owned notification egress network is required')
    return eligible[0]


def allow_matrix_client():
    client, bridge, subnet = matrix_mail_client()
    channel = json.loads(CHANNEL.read_text())
    docker_bridge = json.loads(command(['docker', 'network', 'inspect', 'bridge']))[0]
    gateway = docker_bridge['IPAM']['Config'][0]['Gateway']
    if (channel['host'] != gateway or channel['port'] != 2525 or
            channel['tlsMode'] != 'STARTTLS' or not ipaddress.ip_address(gateway).is_private):
        raise RuntimeError('existing demo SMTP listener differs')
    status = subprocess.run(['ufw', 'status'], capture_output=True, timeout=15,
                            env=dict(os.environ, LC_ALL='C'))
    if status.returncode or b'Status: active' not in status.stdout:
        raise RuntimeError('this repair requires an already active UFW firewall')
    # Restrict interface, source subnet, destination address, protocol and port.
    # Keep UFW enabled and preserve every unrelated host rule.
    command(['ufw', 'allow', 'in', 'on', bridge, 'from', subnet, 'to', gateway,
             'port', '2525', 'proto', 'tcp', 'comment', 'Matrix internal demo SMTP'])
    print(json.dumps({'status': 'matrix-client-authorized', 'firewall': 'ufw',
                      'scope': 'notification-egress-only', 'externalDelivery': False}))


def free_subnet():
    occupied = []
    networks = command(['docker', 'network', 'ls', '-q']).decode().split()
    for network in json.loads(command(['docker', 'network', 'inspect', *networks])):
        for item in network.get('IPAM', {}).get('Config') or []:
            if item.get('Subnet'):
                occupied.append(ipaddress.ip_network(item['Subnet']))
    for route in json.loads(command(['ip', '-j', 'route', 'show', 'table', 'all'])):
        if route.get('dst') and route['dst'] != 'default':
            occupied.append(ipaddress.ip_network(route['dst'], strict=False))
    for candidate in ipaddress.ip_network('172.30.240.0/20').subnets(new_prefix=28):
        if not any(item.version == 4 and candidate.overlaps(item) for item in occupied):
            return candidate
    raise RuntimeError('no unused private demo mailbox subnet available')


def install_proxies(gateway, mailbox_ip):
    # Docker internal networks intentionally do not publish container ports.
    # Host sockets bridge only these two fixed destinations; TLS stays end to
    # end, and the mailbox still has no default route or Internet access.
    proxy = pathlib.Path('/usr/lib/systemd/systemd-socket-proxyd')
    if not proxy.is_file():
        proxy = pathlib.Path('/lib/systemd/systemd-socket-proxyd')
    if not proxy.is_file():
        raise RuntimeError('systemd socket proxy is required')
    for name, destination, listeners in (
        ('smtp', 1025, ['127.0.0.1:2525', gateway + ':2525']),
        ('ui', 8025, ['127.0.0.1:8025']),
    ):
        unit = 'matrix-demo-mail-' + name
        # Sockets precede sockets.target/basic.target; Docker starts afterwards.
        # Bind the private address before its bridge exists. Only the activated
        # proxy service waits for Docker, avoiding a boot ordering cycle.
        socket_text = ('[Unit]\nDescription=Matrix private demo mail ' + name + '\n'
                       'Requires=docker.service\nPartOf=docker.service\n\n[Socket]\n' +
                       ''.join('ListenStream=' + listener + '\n' for listener in listeners) +
                       'FreeBind=yes\nNoDelay=true\n\n[Install]\nWantedBy=multi-user.target\n')
        service_text = ('[Unit]\nDescription=Matrix private demo mail proxy\n'
                        'After=docker.service ' + unit + '.socket\nRequires=docker.service\nBindsTo=' + unit + '.socket\n\n[Service]\n'
                        'ExecStart=' + str(proxy) + ' --exit-idle-time=300s ' + mailbox_ip + ':' + str(destination) + '\n'
                        'DynamicUser=true\nNoNewPrivileges=true\nPrivateTmp=true\n'
                        'ProtectSystem=strict\nProtectHome=true\nCapabilityBoundingSet=\n')
        for suffix, content in (('.socket', socket_text), ('.service', service_text)):
            path = pathlib.Path('/etc/systemd/system') / (unit + suffix)
            write(path, content)
            path.chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', 'matrix-demo-mail-smtp.socket', 'matrix-demo-mail-ui.socket'])


def renew_certificate():
    authority = CONFIG / 'authority'
    runtime = CONFIG / 'runtime'
    # Keep the CA, SMTP identity, password and installation input unchanged.
    # A CA with less than a year remaining needs a planned trust migration.
    command(['openssl', 'x509', '-in', str(authority / 'ca.crt'),
             '-checkend', str(365 * 24 * 3600), '-noout'])
    certificate = command(['openssl', 'x509', '-req', '-in', str(authority / 'server.csr'),
                           '-CA', str(authority / 'ca.crt'), '-CAkey', str(authority / 'ca.key'),
                           '-CAserial', str(authority / 'ca.srl'), '-days', '365', '-sha256',
                           '-extfile', str(authority / 'server.ext')])
    pending = runtime / 'server.crt.new'
    write(pending, certificate)
    command(['openssl', 'verify', '-CAfile', str(authority / 'ca.crt'), str(pending)])
    pending.replace(runtime / 'server.crt')
    command(['docker', 'compose', '-f', str(CONFIG / 'compose.json'), 'restart', 'mailbox'])
    print(json.dumps({'status': 'certificate-renewed', 'verifyRequired': True}))


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or sys.argv[1:] not in ([], ['--renew-certificate'], ['--allow-matrix-client']):
        raise RuntimeError('run as root with no argument, --renew-certificate or --allow-matrix-client')
    os.umask(0o077)
    if sys.argv[1:] == ['--allow-matrix-client']:
        allow_matrix_client()
        return
    if sys.argv[1:] == ['--renew-certificate']:
        renew_certificate()
        return
    for path in (CONFIG, DATA, CHANNEL):
        if path.exists() or path.is_symlink():
            raise RuntimeError('demo mail configuration or data already exists; preserve it')
    for kind, name in (('container', CONTAINER), ('network', NETWORK)):
        existing = subprocess.run(['docker', kind, 'inspect', name], capture_output=True)
        if existing.returncode == 0:
            raise RuntimeError('a demo mail Docker object already exists; preserve it')
    command(['docker', 'image', 'inspect', IMAGE])
    bridge = json.loads(command(['docker', 'network', 'inspect', 'bridge']))[0]
    gateway = bridge['IPAM']['Config'][0]['Gateway']
    address = ipaddress.ip_address(gateway)
    if address.version != 4 or not address.is_private or address.is_loopback:
        raise RuntimeError('a private IPv4 Docker host bridge is required')
    for host, port in (('127.0.0.1', 2525), (gateway, 2525), ('127.0.0.1', 8025)):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((host, port))
    subnet = free_subnet()
    mailbox_ip = str(subnet.network_address + 2)
    CONFIG.mkdir(mode=0o700)
    DATA.mkdir(mode=0o700)
    runtime = CONFIG / 'runtime'
    authority = CONFIG / 'authority'
    runtime.mkdir(mode=0o700)
    authority.mkdir(mode=0o700)
    if CHANNEL.parent.is_symlink():
        raise RuntimeError('unsafe Matrix configuration directory')
    CHANNEL.parent.mkdir(mode=0o700, exist_ok=True)
    if CHANNEL.parent.stat().st_uid != 0 or CHANNEL.parent.stat().st_mode & 0o077:
        raise RuntimeError('Matrix configuration directory must be root-only')

    command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
             'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-days', '3650',
             '-subj', '/CN=Matrix demo mail private CA',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-keyout', str(authority / 'ca.key'), '-out', str(authority / 'ca.crt')])
    command(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
             'ec_paramgen_curve:P-256', '-nodes', '-sha256',
             '-subj', '/CN=matrix-demo-mail.test',
             '-keyout', str(runtime / 'server.key'), '-out', str(authority / 'server.csr')])
    write(authority / 'server.ext',
          'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
          'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:matrix-demo-mail.test,IP:127.0.0.1,IP:' + gateway + '\n')
    command(['openssl', 'x509', '-req', '-in', str(authority / 'server.csr'),
             '-CA', str(authority / 'ca.crt'), '-CAkey', str(authority / 'ca.key'),
             '-CAcreateserial', '-days', '365', '-sha256',
             '-extfile', str(authority / 'server.ext'), '-out', str(runtime / 'server.crt')])
    for path in list(authority.iterdir()) + list(runtime.iterdir()):
        path.chmod(0o600)

    smtp_password = secrets.token_urlsafe(32)
    ui_password = secrets.token_urlsafe(32)
    smtp_user = 'matrix-demo'
    ui_user = 'demo-admin'
    for filename, user, password in (('smtp-auth', smtp_user, smtp_password), ('ui-auth', ui_user, ui_password)):
        password_hash = command(['openssl', 'passwd', '-6', '-stdin'], (password + '\n').encode()).strip()
        write(runtime / filename, user.encode() + b':' + password_hash + b'\n')
    write(CONFIG / 'operator-access.json', json.dumps({'username': ui_user, 'password': ui_password}, separators=(',', ':')))
    # All values here are constrained ASCII. This insertion order, compact JSON
    # and PEM escaping match the installation owner's canonical wire encoding.
    channel = {
        'apiVersion': 'installation.matrix.xiak.com/v1',
        'kind': 'SecurityMailConfiguration',
        'host': gateway, 'port': 2525, 'tlsMode': 'STARTTLS',
        'username': smtp_user, 'password': smtp_password,
        'from': 'matrix@demo.matrix.test',
        'trustedCaPem': (authority / 'ca.crt').read_text(),
    }
    write(CHANNEL, json.dumps(channel, ensure_ascii=False, separators=(',', ':')))
    smtp_password = ui_password = ''
    channel.clear()
    environment = {
        'MP_DATABASE': '/data/mailpit.db',
        'MP_MAX_MESSAGES': '100', 'MP_MAX_AGE': '24h', 'MP_MAX_MESSAGE_SIZE': '1',
        'MP_DISABLE_VERSION_CHECK': 'true', 'MP_QUIET': 'true',
        'MP_LABEL': 'Matrix internal demo mailbox - external delivery disabled',
        'MP_UI_AUTH_FILE': '/run/matrix-mail/ui-auth',
        'MP_ALLOWED_HOSTS': '127.0.0.1,localhost,127.0.0.1:8025,localhost:8025,127.0.0.1:18025,localhost:18025',
        'MP_BLOCK_REMOTE_CSS_AND_FONTS': 'true',
        'MP_SMTP_AUTH_FILE': '/run/matrix-mail/smtp-auth',
        'MP_SMTP_TLS_CERT': '/run/matrix-mail/server.crt',
        'MP_SMTP_TLS_KEY': '/run/matrix-mail/server.key',
        'MP_SMTP_REQUIRE_STARTTLS': 'true',
        'MP_SMTP_AUTH_ACCEPT_ANY': 'false', 'MP_SMTP_AUTH_ALLOW_INSECURE': 'false',
        'MP_SMTP_ALLOWED_RECIPIENTS': '^receiver@demo[.]matrix[.]test$',
        'MP_SMTP_IGNORE_REJECTED_RECIPIENTS': 'false',
        'MP_SMTP_MAX_RECIPIENTS': '1', 'MP_SMTP_DISABLE_RDNS': 'true',
        'MP_SMTP_RELAY_ALL': 'false',
    }
    compose = {
        'name': 'matrix-demo-mail',
        'services': {'mailbox': {
            'image': IMAGE, 'container_name': CONTAINER, 'restart': 'unless-stopped',
            'user': '0:0', 'read_only': True, 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'],
            'mem_limit': '256m', 'cpus': 0.5, 'pids_limit': 64,
            'tmpfs': ['/tmp:rw,noexec,nosuid,size=67108864'],
            'environment': environment,
            'volumes': [str(DATA) + ':/data', str(runtime) + ':/run/matrix-mail:ro'],
            'networks': {'internal': {'ipv4_address': mailbox_ip}},
            'labels': {'com.xiak.matrix.demo-mail': 'true'},
            'logging': {'driver': 'json-file', 'options': {'max-size': '2m', 'max-file': '2'}},
        }},
        'networks': {'internal': {
            'name': NETWORK, 'driver': 'bridge', 'internal': True,
            'ipam': {'config': [{'subnet': str(subnet)}]},
            'labels': {'com.xiak.matrix.demo-mail': 'true'},
        }},
    }
    write(CONFIG / 'compose.json', json.dumps(compose, indent=2) + '\n')
    command(['docker', 'compose', '-f', str(CONFIG / 'compose.json'), 'up', '-d', '--pull', 'never'])
    install_proxies(gateway, mailbox_ip)
    print(json.dumps({'status': 'started', 'recipient': RECIPIENT, 'externalDelivery': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No subprocess stderr, configuration values or credentials are logged.
        print(json.dumps({'status': 'failed', 'category': type(error).__name__,
                          'errno': getattr(error, 'errno', None),
                          'reason': str(error) if isinstance(error, RuntimeError) else None}), file=sys.stderr)
        sys.exit(1)
