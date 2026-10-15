# Matrix 平台安装与 Linux 执行用户

本 runbook 只回答一个运维问题：每条 Matrix 平台生命周期命令应由哪个
Linux 身份执行。发布契约和验收状态仍由
[FEAT-005](../features/FEAT-005-offline-platform-lifecycle.md) 统一拥有。

## 先看结论

**当前生产发布只推荐 root 运行模式。** 推荐操作顺序如下：

1. 运维人员使用自己的实名 Linux 账号登录主机；
2. 在自己的终端执行一次 `sudo -i`；
3. 确认提示符已经变成 `root#`；
4. 主机准备命令，以及所有 `mx platform install`、`verify`、`status`、
   `backup`、`upgrade`、`rollback`、`recover` 和 `support` 命令，都在这个
   `root#` shell 中执行。

推荐模式**不要求**创建 Linux `matrix` 用户，不要求给 `root` 设置或启用
密码，也不要求开放 root 远程 SSH。运维人员继续使用自己的 SSH 密钥、
密码、MFA 和主机现有的 `sudo` 策略登录，然后通过 `sudo -i` 取得本次操作
所需的 root 身份。

非 root 模式目前只作为评估方案保留，尚未通过完整签名生命周期门禁，
**不能作为当前生产部署方案**。

如果只需要作一个部署选择，到这里即可停止比较：生产环境选择 root 模式。
本文后面的非 root 命令用于说明未来可验收路径和现场评估方式，不是与 root
模式并列的生产推荐。

## 命令前缀就是执行身份

本文每条示例命令开头的提示符明确表示执行身份；提示符本身不要复制到
终端中。

| 示例提示符 | 在哪里输入 | 命令的有效 Linux 身份 | 用途 |
| --- | --- | --- | --- |
| `admin$` | 实名运维人员自己的登录 shell | 默认是该运维人员；`sudo` 后面的命令除外 | 执行 `sudo -i`，或在非 root 评估模式中执行 `sudo -u matrix -- ...` |
| `root#` | 执行 `sudo -i` 后得到的 shell，或已经认证的本地 root 控制台 | UID 0（`root`） | 推荐模式的全部主机准备和 Matrix 生命周期命令 |
| `matrix-operator$` | 可选的实名人工操作员 shell | `matrix-operator`；`sudo -u matrix --` 后的命令实际以 `matrix` 执行 | 仅用于站点必须采用密码登录且选择非 root 评估模式的场景 |

看到下面这样的命令块：

```console
admin$ sudo -i
root# umask 077
root# /usr/local/sbin/mx --format json platform status --root /var/lib/matrix
```

含义是先在运维人员自己的 shell 中执行 `sudo -i`，再在得到的 root shell
中执行后两条命令。不要把 `admin$` 或 `root#` 当成命令的一部分。

在非 root 评估模式中，运维人员仍从自己的 shell 输入命令，但每条 `mx`
命令都必须保留 `sudo -u matrix --` 前缀；`sudo` 会让该命令以锁定的
`matrix` 服务账号运行。不能省略此前缀，也不能直接登录 `matrix`。

Linux 操作系统账号与 Matrix IAM 账号完全独立。Matrix 租户 Root、子账号
或平台操作员的密码都不是 Linux 登录密码，也不能用来执行这些主机命令。

## 用户与密码规则

| 模式 | 人员如何登录 | 谁实际执行 `mx` | 是否创建密码 | 当前状态 |
| --- | --- | --- | --- | --- |
| 推荐 root 模式 | 实名运维人员登录后执行 `sudo -i`，或使用已认证的本地 root 控制台 | OS `root` | Matrix 不创建 Linux 密码；继续使用主机现有的人员认证和 `sudo` 规则 | **当前生产部署使用此模式** |
| 非 root 服务账号模式 | 实名运维人员执行 `sudo -u matrix -- ...` | 锁定的 `matrix` 服务账号 | `matrix` **不设置密码**，并保持禁止交互登录 | 仅评估；完整签名生命周期门禁尚未验收 |
| 密码型人工账号后备方案 | 单独创建实名账号，例如 `matrix-operator` | 仍通过 `sudo -u matrix -- ...` 让 `matrix` 执行 | 密码只属于 `matrix-operator`；绝不给共享的 `matrix` 服务账号设置密码 | 仅属于未验收的非 root 评估模式 |

选择 root 模式不等于开放 root 远程登录。推荐做法始终是实名人员先登录，
再执行一次 `sudo -i`。Matrix 本身不创建或管理 Linux 登录密码。

当前必须推荐 root 模式，是因为 Matrix 固定使用本机
`/var/run/docker.sock`，PaaS worker 也通过同一个 socket 管理产品工作负载。
加入主机 `docker` 组本身就具有该 Docker daemon 的 root 级控制能力，
只把 CLI 换成非 root 用户并不能形成真正的最小权限边界。当前签名安装、
升级、回滚、备份、恢复和重启门禁实际验收的也是 root 操作模式。

`--root` 参数表示 Matrix 安装目录的绝对路径，并不是指操作系统的 root
账号。无论选择哪种操作身份，都必须遵守以下不变量：

> 创建 Matrix 安装目录的有效 UID，必须执行此后每一条 `mx platform`
> 命令。不能先用 root 安装再换成其他用户运维，也不能反过来操作。

Matrix 要求安装目录及其托管文件始终归该 UID 所有，并保持仅 owner 可访问
的权限。不要用 `chown -R` 修补身份混用；应使用受支持的备份/恢复或重新安装
路径。

## 推荐的 root 模式

发布包、公开信任根和受保护的安全邮件配置应通过经过认证的交付通道取得，
并放在空安装目录之外。下面的示例路径和公开访问地址必须替换为现场真实值。
这一节只有第一行在实名运维账号的 shell 中执行；执行 `sudo -i` 后，其余每一
行都必须在同一个 `root#` shell 中执行。

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

如果当前控制台已经是认证后的 root shell，可以省略 `sudo -i`。从
`umask 077` 开始，本节所有命令都以 root 执行；不要在生命周期操作中途退出
到普通运维人员 shell 后直接运行没有 `sudo` 的 `mx`。

后续操作继续使用同一个 root 身份：

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

不要把发布包、信任根、安全邮件配置或 support 输出放入
`/var/lib/matrix`。安装目录是 Matrix 托管状态，全新安装前必须为空，不能
作为运维人员的临时工作目录。

## 可选的非 root 操作模式

这个模式可以固定文件 owner，并把实名运维人员与 Matrix 生命周期身份分开。
但是在当前固定使用 rootful Docker socket 的前提下，它**不是**最小权限
边界：只要 `matrix` 能控制 Docker，它仍等价于拥有主机 root 能力。该模式
尚未通过完整签名生命周期门禁，因此当前生产发布仍必须使用 root 模式。

本节所有账号创建命令都只执行一次，并且必须在 `root#` 提示符下执行。
创建一个锁定、不可登录的服务账号。该账号不得设置密码；`passwd -l` 是
锁定密码认证，不会要求创建新密码：

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

任一检查失败都应立即停止。组成员关系生效后，实名运维人员必须让安装命令
和**此后所有**生命周期命令都以同一个 `matrix` 服务账号执行。运维人员
不得直接用自己的 UID 运行 `mx`：

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

暂存的发布包和输入文件必须可由 `matrix` 读取；受保护的安全邮件配置不能
允许 group 或 other 读取。不要为了执行这些命令而给共享服务账号设置交互
密码。人工运维人员应使用自己的账号完成认证，再通过可审计的
`sudo -u matrix` 执行。

**不要**执行 `passwd matrix`。它只会写入密码哈希，而配置的
`/usr/sbin/nologin` 仍会拒绝交互登录；不能把这个共享服务身份变成人工
登录账号。如果组织策略要求使用密码运维，应另建一个实名人工账号，再向
它委派可审计的 `sudo -u matrix` 权限。下面两条命令都在 `root#` 下执行；
只有 `passwd matrix-operator` 会要求输入两次密码，且该密码只属于这个
人工账号：

```console
root# useradd --create-home --shell /bin/bash matrix-operator
root# passwd matrix-operator
```

仅设置密码不会自动授予 Matrix 操作权。站点管理员必须另外在可审计的
`sudo` 策略中允许 `matrix-operator` 以目标用户 `matrix` 运行
`/usr/local/sbin/mx`，并在安装前验证该策略：

```console
root# sudo -l -U matrix-operator
matrix-operator$ sudo -u matrix -- /usr/local/sbin/mx --help
```

SSH 密钥和 MFA 优先于密码后备方案。人工账号不能拥有 `/var/lib/matrix`，
不能加入 `docker` 组，也不能用自己的 UID 直接运行 `mx`。不要使用
`su - matrix`：该服务账号被有意配置为不可登录，受支持的调用方式只有
`sudo -u matrix --`。

## 不支持的身份组合

- 不要交替执行 `sudo mx ...` 和非特权 `mx ...`。
- 不要通过修改现有安装目录的 owner 来切换 root/非 root 模式。
- 不要让 Matrix 连接远程 Docker daemon 或调用方指定的 Docker context；
  当前 provider 固定使用本地 Unix socket。
- 不要把 `docker` 组描述为最小权限；Docker 官方文档明确说明它授予 daemon
  的 root 级控制能力。
- Rootless Docker 不属于当前 Matrix 发布 profile；生命周期执行和生成的
  topology 都固定使用 `/var/run/docker.sock`。

## 验证依据

当前 root 模式已由 FEAT-005 的签名生命周期门禁实跑。上述账号创建命令也
在隔离 Linux fixture 中执行过：`matrix` 密码保持锁定，安装目录权限为
`0700 matrix:matrix`，bootstrap 可执行文件权限为 `0750 root:matrix`；
同一 CLI 分别以 root 和拥有目录的非 root UID 在空目录上运行时，均返回预期
的 `PLATFORM_NOT_INSTALLED` 前置条件。这个轻量检查不能替代尚未完成的非
root 完整签名生命周期门禁。

Docker 的安全模型见官方
[Linux 安装后配置说明](https://docs.docker.com/engine/install/linux-postinstall/)
和 [Docker Engine 安全指南](https://docs.docker.com/engine/security/)。
