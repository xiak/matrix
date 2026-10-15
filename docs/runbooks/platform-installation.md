# Platform installation and operating user

This runbook answers one operational question only: which Linux identity runs
each Matrix platform lifecycle command. The release contract and acceptance
status remain owned by
[FEAT-005](../features/FEAT-005-offline-platform-lifecycle.md).

## Required decision for this release

**For the current production release, use the root profile.** The supported
operator sequence is:

1. a named human administrator logs in with their own Linux account;
2. that administrator runs `sudo -i` once;
3. the prompt changes to `root#`;
4. every `mx platform install`, `verify`, `status`, `backup`, `upgrade`,
   `rollback`, `recover`, and `support` command is run from that root shell.

Do not create a Linux `matrix` account for the recommended root profile. Do
not set or enable a root password merely for Matrix, and do not enable remote
root SSH login. The named administrator continues to authenticate with the
host's existing SSH key, password, MFA, and `sudo` policy.

The optional non-root profile below is documented so its ownership contract
is unambiguous, but it has not passed the complete signed lifecycle gate and
is **not** the current production recommendation.

## Who runs each command

The shell prompt shown at the start of each example line states the required
identity. The prompt text itself is not part of the command to copy.

| Example prompt | Where the command is entered | Effective identity of the command | Permitted use |
| --- | --- | --- | --- |
| `admin$` | A named human administrator's login shell | That administrator, except for the command following `sudo` | Enter `sudo -i`, or invoke the optional profile with `sudo -u matrix --` |
| `root#` | The root shell reached with `sudo -i`, or an already authenticated local root console | UID 0 (`root`) | All host preparation and every lifecycle command in the recommended profile |
| `matrix$` | A non-interactive process started with `sudo -u matrix --` | Locked service account `matrix` | Optional non-root profile only; never an interactive login |

If a command block starts with `admin$ sudo -i`, every following `root#` line
must be run **after** that command, in the resulting root shell. If an optional
example starts with `admin$ sudo -u matrix --`, the human enters the command
from their own shell but `sudo` executes `mx` as the `matrix` service account.
Never omit that prefix in the optional profile.

Linux operating-system accounts are separate from Matrix IAM accounts. The
password of a Matrix tenant owner, sub-user, or platform operator is never a
Linux login password and cannot be used to run these host commands.

## Password and account policy

| Profile | Human login | Identity that executes `mx` | Password | Current status |
| --- | --- | --- | --- | --- |
| Recommended root | A named administrator using `sudo -i`, or an already authenticated root console | OS `root` | Matrix creates no Linux password; the administrator uses the host's existing root or `sudo` authentication | **Use this profile for production** |
| Optional service account | A named administrator using `sudo -u matrix -- ...` | Locked `matrix` service account | **No password**; interactive login stays disabled | Evaluation only; the full signed lifecycle gate is not accepted |
| Password-based human fallback | A separately named human such as `matrix-operator` | Still the locked `matrix` service account through audited `sudo -u matrix -- ...` | Password belongs only to the named human; never set one on the shared `matrix` account | Optional site policy within the unaccepted non-root profile |

Choosing the root profile does not require enabling remote SSH login for
`root`. A named human administrator may authenticate with their own account,
run `sudo -i` once, and then execute the complete lifecycle in that root shell.
Matrix neither creates nor manages Linux login passwords.

This is the current release recommendation because Matrix deliberately uses
the local `/var/run/docker.sock`, and the PaaS worker receives that same socket
to manage product workloads. Membership in the host `docker` group grants
root-level control of that daemon; changing only the CLI username does not
create a privilege boundary. The current signed install, upgrade, rollback,
backup, recovery and restart gates use the root operator profile.

`--root` means the absolute Matrix installation directory. It does not mean
the operating-system root account. Regardless of the chosen operator name,
the following invariant applies:

> The same effective UID that creates the Matrix installation root must run
> every later `mx platform` command. Do not install as root and later operate
> as another user, or the reverse.

Matrix requires the installation root and its managed files to remain owned by
that UID with owner-only permissions. Do not repair an identity mismatch with
`chown -R`; use the supported backup/recovery or reinstall path instead.

## Recommended root profile

The release bundle, public trust root and protected security-mail input are
obtained through the authenticated delivery channel and staged outside the
empty installation root. Example paths below must be replaced with the real
staged paths and public origin.

```console
admin$ sudo -i
root# umask 077
root# install -d -o root -g root -m 0700 /var/lib/matrix
root# test -S /var/run/docker.sock
root# docker version
root# docker compose version
root# /usr/local/sbin/mx --format json platform install \
  --bundle /srv/matrix-release \
  --root /var/lib/matrix \
  --trust-key /etc/matrix/release-trust.json \
  --security-mail-configuration /etc/matrix/security-mail.json \
  --northbound-origin https://matrix.example.com:443
root# /usr/local/sbin/mx --format json platform verify --root /var/lib/matrix
root# /usr/local/sbin/mx --format json platform status --root /var/lib/matrix
```

If the console is already an authenticated root shell, omit `sudo -i`. From
`umask 077` onward, every command in this section runs as `root`; do not exit
back to the administrator shell between lifecycle commands and then run `mx`
without `sudo`.

Keep using the same root identity for subsequent operations:

```console
root# /usr/local/sbin/mx --format json platform backup --root /var/lib/matrix
root# /usr/local/sbin/mx --format json platform upgrade \
  --bundle /srv/matrix-release-next \
  --root /var/lib/matrix \
  --security-mail-configuration /etc/matrix/security-mail.json
root# /usr/local/sbin/mx --format json platform rollback --root /var/lib/matrix
root# /usr/local/sbin/mx --format json platform recover \
  --root /var/lib/matrix \
  --backup backup-REPLACE_WITH_VERIFIED_ID
root# /usr/local/sbin/mx --format json platform support \
  --root /var/lib/matrix \
  --output /var/tmp/matrix-support.json
```

Do not place the bundle, trust root, security-mail input or support output
inside `/var/lib/matrix`. The installation root is Matrix-owned state, must be
empty before a fresh install, and is not an operator scratch directory.

## Optional non-root operator profile

This profile is useful for stable file ownership and separating named human
administrators from the Matrix lifecycle identity. With the currently fixed
rootful Docker socket it is **not** a least-privilege boundary: the `matrix`
account remains host-root-equivalent while it can control Docker. The full
signed lifecycle gate for this profile has not yet been accepted, so use the
root profile for the current production release.

All account-creation commands in this section run once at a `root#` prompt.
Create one locked, non-login service account. It must not have a password;
`passwd -l` locks password authentication rather than asking for a new
password:

```console
root# groupadd --system matrix
root# useradd --system \
  --gid matrix \
  --home-dir /var/lib/matrix \
  --no-create-home \
  --shell /usr/sbin/nologin \
  matrix
root# passwd -l matrix
root# install -d -o matrix -g matrix -m 0700 /var/lib/matrix
root# install -o root -g matrix -m 0750 ./mx /usr/local/sbin/mx
root# usermod -aG docker matrix
root# sudo -u matrix -- id
root# sudo -u matrix -- docker version
root# sudo -u matrix -- docker compose version
```

Stop here if these checks fail. After group membership is effective, a named
administrator invokes the install and **every later** lifecycle command as
that same service account. The administrator must never run `mx` directly
under their own UID:

```console
admin$ sudo -u matrix -- /usr/local/sbin/mx --format json platform install \
  --bundle /srv/matrix-release \
  --root /var/lib/matrix \
  --trust-key /etc/matrix/release-trust.json \
  --security-mail-configuration /etc/matrix/security-mail.json \
  --northbound-origin https://matrix.example.com:443
admin$ sudo -u matrix -- /usr/local/sbin/mx --format json platform verify \
  --root /var/lib/matrix
```

The staged bundle and input files must be readable by `matrix`; the protected
security-mail file must not be readable by group or other users. Do not give
the shared service account an interactive password merely to run these
commands. Human administrators should authenticate with their own accounts
and use audited `sudo -u matrix` execution.

Do **not** run `passwd matrix`. That would set a password hash, while the
configured `/usr/sbin/nologin` shell would still reject interactive login. Do
not turn
this shared service identity into a human login. If an organization requires
password-based administration, create a separately named human operator and
delegate audited `sudo -u matrix` execution instead. The following commands
run at a `root#` prompt; only `passwd matrix-operator` prompts twice, and the
password belongs to that human account:

```console
root# useradd --create-home --shell /bin/bash matrix-operator
root# passwd matrix-operator
```

The password does not grant Matrix access by itself. The site's administrator
must separately authorize `matrix-operator` in the audited `sudo` policy to
run `/usr/local/sbin/mx` as target user `matrix`, and should verify that policy
before installation:

```console
root# sudo -l -U matrix-operator
matrix-operator$ sudo -u matrix -- /usr/local/sbin/mx --help
```

SSH keys and MFA are preferred over that password fallback. The human account
must not own `/var/lib/matrix`, must not join the `docker` group, and must not
invoke `mx` under its own UID. Do not use `su - matrix`: the service account is
intentionally non-login, and the supported invocation is `sudo -u matrix --`.

## Unsupported identity combinations

- Do not alternate `sudo mx ...` and unprivileged `mx ...` commands.
- Do not change ownership of an existing installation root to switch modes.
- Do not point Matrix at a remote Docker daemon or caller-selected Docker
  context. The current provider fixes the local Unix socket.
- Do not describe the `docker` group as least privilege. Docker documents that
  it grants root-level daemon control.
- Rootless Docker is not the current Matrix release profile: Matrix fixes
  `/var/run/docker.sock` in both lifecycle execution and generated topology.

## Verification basis

The current root profile is exercised by the signed FEAT-005 lifecycle gates.
The account-creation commands above were also executed in an isolated Linux
fixture: `matrix` had a locked password, the installation root was
`0700 matrix:matrix`, the bootstrap executable was `0750 root:matrix`, and the
same CLI returned the expected `PLATFORM_NOT_INSTALLED` precondition as both
root and the owning non-root UID on an empty root. That lightweight check does
not replace the missing full signed non-root lifecycle gate.

Docker's security model is documented in its official
[Linux post-installation guidance](https://docs.docker.com/engine/install/linux-postinstall/)
and [Docker Engine security guide](https://docs.docker.com/engine/security/).
