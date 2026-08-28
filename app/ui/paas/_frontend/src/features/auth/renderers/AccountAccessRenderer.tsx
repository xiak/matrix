"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { Building2, KeyRound, Plus, RefreshCcw, ShieldCheck, UserRound, Users } from "lucide-react";
import { Badge, Button, Card, Input, Select, Typography } from "@ui/xiak";
import { AccountAccessProvider, useAccountAccess } from "../application/AccountAccessProvider";
import { useSession } from "../application/SessionProvider";
import { userRoles, type UserRole } from "../domain/accounts";
import type { AccountRepository } from "../repositories/iamRepository";
import { roleDescriptions, roleLabels, type AccountAccessScene, type AccountUserScene, type TenantAccountScene } from "../scenes/accountAccessScene";
import styles from "./AccountAccessRenderer.module.css";

const loginPattern = "[a-z][a-z0-9._\\-]{2,63}";
const aliasPattern = "[a-z][a-z0-9\\-]{1,61}[a-z0-9]";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className={styles.field}><span>{label}</span>{children}</label>;
}

function PasswordField({ value, onChange }: { value: string; onChange(value: string): void }) {
  return <Field label="初始密码">
    <Input autoComplete="new-password" maxLength={128} minLength={14} onChange={(event) => onChange(event.target.value)} required type="password" value={value} />
    <small>14–128 字节，不含空格，至少包含大写、小写、数字、符号中的三类。首次登录必须修改。</small>
  </Field>;
}

function CreateAccountForm({ tenant, onClose }: { tenant: boolean; onClose(): void }) {
  const access = useAccountAccess();
  const [password, setPassword] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const loginName = String(fields.get("loginName") ?? "").trim();
    const displayName = String(fields.get("displayName") ?? "").trim();
    const initialPassword = password;
    setPassword("");
    const accepted = await access.execute(tenant ? {
      kind: "create-organization", id: String(fields.get("accountId") ?? "").trim(),
      displayName: String(fields.get("accountName") ?? "").trim(),
      administratorLoginName: loginName, administratorDisplayName: displayName, initialPassword
    } : { kind: "create-user", loginName, displayName, initialPassword, initialRole: (fields.get("role") || undefined) as UserRole | undefined });
    if (accepted) onClose();
  }
  return <Card>
    <Card.Header><Typography.Title as="h2" level={3}>{tenant ? "开通租户账号" : "创建子用户"}</Typography.Title></Card.Header>
    <Card.Body>
      <form aria-label={tenant ? "开通租户账号" : "创建子用户"} className={styles.form} onSubmit={submit}>
        {tenant ? <>
          <Field label="租户 ID"><Input autoComplete="off" maxLength={128} name="accountId" pattern="[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}" placeholder="例如 team-alpha" required /><small>资源与安全归属。创建后不可更改，也是子账号登录的稳定后缀。</small></Field>
          <Field label="租户名称"><Input maxLength={128} name="accountName" required /></Field>
        </> : null}
        <Field label={tenant ? "主账号登录名" : "子用户名"}><Input autoComplete="off" maxLength={64} minLength={3} name="loginName" pattern={loginPattern} placeholder={tenant ? "例如 team-admin" : "例如 developer"} required /><small>以小写字母开头，可包含小写字母、数字、点、下划线和短横线。{tenant ? "主账号登录名全平台唯一。" : "仅填写用户名，不包含 @ 后缀。"}</small></Field>
        <Field label="用户显示名称"><Input maxLength={128} name="displayName" required /></Field>
        {!tenant ? <Field label="初始权限"><Select defaultValue="" name="role"><option value="">暂不授权（默认）</option>{userRoles.map((role) => <option key={role} value={role}>{roleLabels[role]}</option>)}</Select><small>默认只可登录查看自身账号信息。选择角色后，权限对本租户的相应资源生效，不限于该用户创建的资源。</small></Field> : null}
        <PasswordField onChange={setPassword} value={password} />
        <p className={styles.note}>{tenant ? "新租户拥有独立主账号与资源空间。主账号不获得平台权限，开通者也不获得该租户的资源权限。请通过安全渠道交付初始密码。" : "子用户按授权使用所属租户的资源与配额，不是另一个租户。请通过安全渠道交付初始密码。"}</p>
        <div className={styles.actions}>
          <Button disabled={access.busy || access.loading || !password} type="submit">{access.busy ? "正在创建…" : tenant ? "确认开通" : "创建用户"}</Button>
          <Button disabled={access.busy} onClick={onClose} variant="ghost">取消</Button>
        </div>
      </form>
    </Card.Body>
  </Card>;
}

function UserAccess({ user, onClose }: { user: AccountUserScene; onClose(): void }) {
  const access = useAccountAccess();
  const [password, setPassword] = useState("");
  const [confirmStatus, setConfirmStatus] = useState(false);
  const [resettingPassword, setResettingPassword] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<UserRole | "">("");
  const availableRoles = userRoles.filter((role) => !user.bindings.some((binding) => binding.role === role));
  const role = selectedRole && availableRoles.includes(selectedRole) ? selectedRole : "";
  const disabled = access.busy || access.loading;

  async function resetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const initialPassword = password;
    setPassword("");
    if (await access.execute({ kind: "reset-password", principalId: user.id, resourceVersion: user.resourceVersion, initialPassword })) setResettingPassword(false);
  }
  return <Card>
    <Card.Header className={styles.cardHeader}>
      <div><Typography.Title as="h2" level={3}>{user.name}</Typography.Title><Typography.Text tone="muted">{user.qualifiedName}</Typography.Text></div>
      <Button onClick={onClose} size="small" variant="ghost">关闭详情</Button>
    </Card.Header>
    <Card.Body className={styles.detail}>
      <div className={styles.sectionHeading}><ShieldCheck aria-hidden="true" /><strong>已授予权限（内置角色）</strong></div>
      <p className={styles.note}>租户角色的授权范围为所属租户的资源，不是“仅自己创建的资源”。管理员交接通过授予、撤销子用户角色完成，不转让原主账号。</p>
      <ul className={styles.bindingList}>
        {user.bindings.map((binding) => <li key={binding.id}>
          <span>{binding.label}</span>
          {binding.role === "PLATFORM_OPERATOR" ? <span>由平台权限管理</span> : revokeId === binding.id ? <div className={styles.actions}>
            <span>立即撤销？</span><Button disabled={disabled} onClick={async () => { if (await access.execute({ kind: "revoke-role", bindingId: binding.id })) setRevokeId(null); }} size="small" variant="danger">确认撤销</Button>
            <Button disabled={disabled} onClick={() => setRevokeId(null)} size="small" variant="ghost">取消</Button>
          </div> : <Button aria-label={`撤销${binding.label}`} disabled={disabled} onClick={() => setRevokeId(binding.id)} size="small" variant="ghost">撤销</Button>}
        </li>)}
      </ul>
      {user.bindings.length === 0 ? <p className={styles.note}>尚未授予角色。用户可登录查看自身账号，但不能访问受保护资源。</p> : null}
      {availableRoles.length > 0 ? <form className={styles.inlineForm} onSubmit={async (event) => {
        event.preventDefault();
        if (role && await access.execute({ kind: "grant-role", principalId: user.id, role })) setSelectedRole("");
      }}>
        <Field label="授予角色"><Select disabled={disabled} onChange={(event) => setSelectedRole(event.target.value as UserRole | "")} required value={role}><option disabled value="">请选择角色</option>{availableRoles.map((item) => <option key={item} value={item}>{roleLabels[item]}</option>)}</Select></Field>
        <Button disabled={disabled || !role} type="submit" variant="secondary">授予角色</Button>
      </form> : null}
      <div className={styles.sectionHeading}><KeyRound aria-hidden="true" /><strong>登录与安全</strong></div>
      {user.credentialProtection ? <p className={styles.note}>{user.credentialProtection === "platform" ? "该用户有未撤销的平台角色绑定，即使已禁用，也不能通过租户成员管理启用、禁用或重置密码。平台凭证恢复须走离线流程。" : "不能通过子用户管理禁用或重置当前登录用户。"}</p> : <>
        <div className={styles.actions}>
          <Button disabled={disabled} onClick={() => { setConfirmStatus(true); setResettingPassword(false); setPassword(""); }} variant="secondary">{user.enabled ? "禁用用户" : "启用用户"}</Button>
          <Button disabled={disabled} onClick={() => { setResettingPassword(true); setConfirmStatus(false); }} variant="secondary">重置密码</Button>
        </div>
        {confirmStatus ? <div className={styles.confirmation}>
          <p>{user.enabled ? "禁用将撤销该用户的现有会话，下一次受保护请求即被拒绝；不会删除租户资源或停止已有工作负载。" : "启用后可使用有效密码重新登录；已撤销的会话不会恢复。"}</p>
          <div className={styles.actions}>
            <Button disabled={disabled} onClick={async () => { if (await access.execute({ kind: "set-status", principalId: user.id, status: user.enabled ? "DISABLED" : "ACTIVE", resourceVersion: user.resourceVersion })) setConfirmStatus(false); }} variant={user.enabled ? "danger" : "primary"}>{user.enabled ? "确认禁用" : "确认启用"}</Button>
            <Button disabled={disabled} onClick={() => setConfirmStatus(false)} variant="ghost">取消</Button>
          </div>
        </div> : null}
        {resettingPassword ? <form className={styles.form} onSubmit={resetPassword}>
          <PasswordField onChange={setPassword} value={password} />
          <p className={styles.note}>重置将撤销所有现有会话。用户下次登录必须修改初始密码；禁用状态不会被自动解除。</p>
          <div className={styles.actions}><Button disabled={disabled || !password} type="submit">确认重置密码</Button><Button disabled={disabled} onClick={() => { setResettingPassword(false); setPassword(""); }} variant="ghost">取消</Button></div>
        </form> : null}
      </>}
    </Card.Body>
  </Card>;
}

function UserDirectory({ scene }: { scene: AccountAccessScene }) {
  const access = useAccountAccess();
  const [creating, setCreating] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = scene.users.find((user) => user.id === selectedId);
  return <div className={styles.stack}>
    <Card>
      <Card.Header className={styles.cardHeader}>
        <div><Typography.Title as="h2" level={3}>子用户</Typography.Title><Typography.Text tone="muted">独立身份与凭据，按授权访问所属租户的资源</Typography.Text></div>
        <Button disabled={access.busy || access.loading} onClick={() => { setCreating(true); setSelectedId(null); }} size="small"><Plus aria-hidden="true" />创建用户</Button>
      </Card.Header>
      <div aria-label="租户用户列表" className={styles.tableWrap} role="region" tabIndex={0}>
        <table className={styles.table}>
          <thead><tr><th>用户</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>{scene.users.map((user) => <tr key={user.id}>
            <td><strong>{user.name}</strong><small>{user.qualifiedName}</small></td>
            <td><div className={styles.roleTags}>{user.bindings.length ? user.bindings.map((binding) => <Badge key={binding.id} status="neutral">{binding.label}</Badge>) : "未授权"}</div></td>
            <td><Badge status={user.enabled ? "success" : "neutral"}>{user.statusLabel}</Badge></td>
            <td><Button aria-label={`管理 ${user.loginName}`} disabled={access.busy || access.loading} onClick={() => { setSelectedId(user.id); setCreating(false); }} size="small" variant="ghost">管理</Button></td>
          </tr>)}</tbody>
        </table>
        {!scene.users.length ? <p className={styles.empty}>当前页没有子用户。可创建子用户并按需授予权限。</p> : null}
      </div>
      <Card.Footer><span className={styles.note}>每页最多 100 名子用户；主账号信息见用户设置</span><div className={styles.actions}><Button disabled={access.busy || access.loading} onClick={() => { setSelectedId(null); access.usersPage(""); }} size="small" variant="ghost">首页</Button><Button disabled={access.busy || access.loading || !scene.nextUserPage} onClick={() => { setSelectedId(null); access.usersPage(scene.nextUserPage!); }} size="small" variant="secondary">下一页</Button></div></Card.Footer>
    </Card>
    {creating ? <CreateAccountForm onClose={() => setCreating(false)} tenant={false} /> : null}
    {selected ? <UserAccess key={`${selected.id}:${selected.resourceVersion}`} onClose={() => setSelectedId(null)} user={selected} /> : null}
  </div>;
}

function PasswordSettings() {
  const session = useSession();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [revokeOthers, setRevokeOthers] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const pending = session.phase === "updating-password" || session.phase === "revoking";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setMessage(null);
    session.clearError();
    if (newPassword !== confirmation) {
      setFormError("两次输入的新密码不一致");
      return;
    }
    const submission = session.changePassword(currentPassword, newPassword, revokeOthers);
    setCurrentPassword("");
    setNewPassword("");
    setConfirmation("");
    if (await submission) {
      setMessage(revokeOthers
        ? "密码已更新，其他登录会话已退出，当前会话保留。"
        : "密码已更新，当前会话及其他仍有效的登录会话保留。");
    }
  }

  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>修改登录密码</Typography.Title><Typography.Text tone="muted">仅修改当前登录账号的密码</Typography.Text></div></Card.Header>
    <Card.Body>
      <form className={styles.form} onSubmit={submit}>
        <Field label="当前密码"><Input autoComplete="current-password" disabled={pending} maxLength={128} onChange={(event) => setCurrentPassword(event.target.value)} required type="password" value={currentPassword} /></Field>
        <Field label="新密码"><Input aria-describedby="account-password-policy" autoComplete="new-password" disabled={pending} maxLength={128} minLength={14} onChange={(event) => setNewPassword(event.target.value)} required type="password" value={newPassword} /></Field>
        <Field label="确认新密码"><Input autoComplete="new-password" disabled={pending} maxLength={128} minLength={14} onChange={(event) => setConfirmation(event.target.value)} required type="password" value={confirmation} /></Field>
        <p className={styles.note} id="account-password-policy">14–128 字节，不含空格，至少包含大写、小写、数字、符号中的三类。</p>
        <label className={styles.sessionOption}><Input checked={revokeOthers} className={styles.sessionCheckbox} disabled={pending} onChange={(event) => setRevokeOthers(event.target.checked)} type="checkbox" /><span>同时退出其他登录会话（推荐）</span></label>
        <p className={styles.note}>当前会话保留。不勾选时仅保留其他仍有效的会话，已退出或已撤销的会话不会恢复。</p>
        {formError ? <p className={styles.error} role="alert">{formError}</p> : null}
        {message ? <p className={styles.success} role="status">{message}</p> : null}
        <div><Button disabled={pending || !currentPassword || !newPassword || !confirmation} type="submit">{pending ? "正在更新密码…" : "更新密码"}</Button></div>
      </form>
    </Card.Body>
  </Card>;
}

function UserSettings({ scene }: { scene: AccountAccessScene }) {
  const access = useAccountAccess();
  const [alias, setAlias] = useState(scene.loginAlias ?? "");
  return <div className={styles.stack}>
    <PasswordSettings />
    <Card>
    <Card.Header className={styles.cardHeader}><div><Typography.Title as="h2" level={3}>主账号别名</Typography.Title><Typography.Text tone="muted">主账号的专属登录标识</Typography.Text></div><Badge status={scene.loginAlias ? "success" : "neutral"}>{scene.loginAlias ? "已设置" : "未设置"}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <p className={styles.note}>子用户可使用别名替代租户 ID 登录。它不是邮箱、域名，也不是主账号的用户名。</p>
      <dl className={styles.facts}>
        <div><dt>租户 ID</dt><dd><Typography.Code>{scene.accountId}</Typography.Code></dd></div>
        <div><dt>主账号登录名</dt><dd>{scene.primaryLoginName}</dd></div>
        <div><dt>固定 ID 登录</dt><dd><Typography.Code>username@{scene.accountId}</Typography.Code></dd></div>
        <div><dt>别名登录</dt><dd>{scene.loginAlias ? <Typography.Code>username@{scene.loginAlias}</Typography.Code> : "设置别名后可用"}</dd></div>
      </dl>
      {scene.canManage ? <form className={styles.form} onSubmit={async (event) => { event.preventDefault(); await access.execute({ kind: "set-alias", alias: alias.trim(), resourceVersion: scene.accountVersion }); }}>
        <Field label="主账号别名"><Input autoComplete="off" maxLength={63} minLength={3} onChange={(event) => setAlias(event.target.value)} pattern={aliasPattern} placeholder="例如 acme" required value={alias} /><small>3–63 位，以小写字母开头，可包含数字和短横线，结尾不能是短横线。全平台唯一。</small></Field>
        <p className={styles.note}>修改后旧别名不能用于登录，并为本租户保留。现有会话与资源归属不变，租户 ID 登录仍然有效。</p>
        <div><Button disabled={access.busy || access.loading || !alias.trim() || alias.trim() === scene.loginAlias} type="submit">{access.busy ? "正在保存…" : "保存别名"}</Button></div>
      </form> : <p className={styles.note}>请联系所属主账号的管理员设置或修改别名。</p>}
    </Card.Body>
    </Card>
  </div>;
}

function TenantAccess({ account, onClose }: { account: TenantAccountScene; onClose(): void }) {
  const access = useAccountAccess();
  const [confirmation, setConfirmation] = useState<"status" | "recovery" | null>(null);
  const [password, setPassword] = useState("");
  const disabled = access.busy || access.loading;
  function cancel() { setConfirmation(null); setPassword(""); }

  async function recover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const initialPassword = password;
    setPassword("");
    if (await access.execute({ kind: "recover-primary", organizationId: account.id,
      principalId: account.primaryPrincipalId, initialPassword, resourceVersion: account.resourceVersion })) cancel();
  }

  return <Card>
    <Card.Header className={styles.cardHeader}><div><Typography.Title as="h2" level={3}>{account.name}</Typography.Title><Typography.Text tone="muted">租户访问与原主账号恢复</Typography.Text></div><Button onClick={onClose} size="small" variant="ghost">关闭租户详情</Button></Card.Header>
    <Card.Body className={styles.detail}>
      <dl className={styles.facts}>
        <div><dt>租户 ID</dt><dd><Typography.Code>{account.id}</Typography.Code></dd></div>
        <div><dt>主账号登录名</dt><dd>{account.primaryLoginName}</dd></div>
        <div><dt>原主账号用户 ID</dt><dd><Typography.Code>{account.primaryPrincipalId}</Typography.Code></dd></div>
        <div><dt>访问状态</dt><dd><Badge status={account.enabled ? "success" : "neutral"}>{account.enabled ? "正常" : "已停用"}</Badge></dd></div>
        <div><dt>资源版本</dt><dd>{account.resourceVersion}</dd></div>
      </dl>
      <p className={styles.note}>这里只管理租户元数据，不授予租户资源、Secret 或审计读取权限。安装服务所属租户不能停用，由 IAM 校验。</p>
      <div className={styles.actions}>
        <Button disabled={disabled} onClick={() => { setConfirmation("status"); setPassword(""); }} variant="secondary">{account.enabled ? "停用租户" : "恢复租户访问"}</Button>
        <Button disabled={disabled} onClick={() => { setConfirmation("recovery"); setPassword(""); }} variant="secondary">恢复原主账号</Button>
      </div>
      {confirmation === "status" ? <div className={styles.confirmation}>
        <p>{account.enabled ? "确认停用此租户？下一次受保护请求将被拒绝，新变更被冻结，现有会话被撤销。不删除数据、不停止已有工作负载，也不取消已接受的 Operation 或历史审计投递。" : "确认恢复此租户的访问？用户须重新登录；已撤销的会话或角色不会恢复。"}</p>
        <div className={styles.actions}>
          <Button disabled={disabled} onClick={async () => {
            if (await access.execute({ kind: "set-organization-status", organizationId: account.id,
              status: account.enabled ? "DISABLED" : "ACTIVE", resourceVersion: account.resourceVersion })) cancel();
          }} variant={account.enabled ? "danger" : "primary"}>{account.enabled ? "确认停用租户" : "确认恢复访问"}</Button>
          <Button disabled={disabled} onClick={cancel} variant="ghost">取消</Button>
        </div>
      </div> : null}
      {confirmation === "recovery" ? <form aria-label="恢复原主账号" className={styles.form} onSubmit={recover}>
        <p className={styles.note}>仅恢复上方原主账号的凭证和租户管理员权限，不把子账号提升为主账号，也不授予平台角色。有未撤销平台角色绑定的身份必须走离线恢复。</p>
        <PasswordField onChange={setPassword} value={password} />
        <p className={styles.note}>确认后将启用原主账号、撤销其旧会话，下次登录必须改密。不会自动恢复租户访问。请通过安全渠道交付临时密码。</p>
        <div className={styles.actions}><Button disabled={disabled || !password} type="submit" variant="danger">确认恢复原主账号</Button><Button disabled={disabled} onClick={cancel} variant="ghost">取消</Button></div>
      </form> : null}
    </Card.Body>
  </Card>;
}

function TenantDirectory({ scene }: { scene: AccountAccessScene }) {
  const access = useAccountAccess();
  const [creating, setCreating] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = scene.accounts.find((account) => account.id === selectedId);
  return <div className={styles.stack}>
    <Card>
      <Card.Header className={styles.cardHeader}><div><Typography.Title as="h2" level={3}>租户账号</Typography.Title><Typography.Text tone="muted">平台运营者管理租户生命周期；不等于租户管理员</Typography.Text></div><Button disabled={access.busy || access.loading} onClick={() => { setCreating(true); setSelectedId(null); }} size="small"><Plus aria-hidden="true" />开通租户</Button></Card.Header>
      <div aria-label="租户账号列表" className={styles.tableWrap} role="region" tabIndex={0}>
        <table className={styles.table}><thead><tr><th>租户</th><th>主账号登录名</th><th>主账号别名</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>{scene.accounts.map((account) => <tr key={account.id}><td><strong>{account.name}</strong><small>{account.id}</small></td><td>{account.primaryLoginName}</td><td>{account.loginAlias ?? "未设置"}</td><td><Badge status={account.enabled ? "success" : "neutral"}>{account.enabled ? "正常" : "已停用"}</Badge></td><td><Button aria-label={`管理租户 ${account.id}`} disabled={access.busy || access.loading} onClick={() => { setSelectedId(account.id); setCreating(false); }} size="small" variant="ghost">管理</Button></td></tr>)}</tbody>
        </table>
        {!scene.accounts.length ? <p className={styles.empty}>当前页没有租户。</p> : null}
      </div>
      <Card.Footer><span className={styles.note}>开通不等于跨租户授权</span><div className={styles.actions}><Button disabled={access.busy || access.loading} onClick={() => { setSelectedId(null); setCreating(false); access.accountsPage(""); }} size="small" variant="ghost">首页</Button><Button disabled={access.busy || access.loading || !scene.nextAccountPage} onClick={() => { setSelectedId(null); setCreating(false); access.accountsPage(scene.nextAccountPage!); }} size="small" variant="secondary">下一页</Button></div></Card.Footer>
    </Card>
    {creating ? <CreateAccountForm onClose={() => setCreating(false)} tenant /> : null}
    {selected ? <TenantAccess account={selected} key={`${selected.id}:${selected.resourceVersion}`} onClose={() => setSelectedId(null)} /> : null}
  </div>;
}

function PermissionCatalog() {
  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>权限</Typography.Title><Typography.Text tone="muted">当前提供四种租户级内置角色</Typography.Text></div></Card.Header>
    <Card.Body className={styles.detail}>
      <p className={styles.note}>未授权默认拒绝。主账号和子用户创建的资源都归租户，配额也归租户，不随创建者停用而改变；不同租户默认不能互相访问。</p>
      <dl className={styles.permissionList}>{userRoles.map((role) => <div key={role}><dt>{roleLabels[role]}</dt><dd>{roleDescriptions[role]}</dd></div>)}</dl>
      <p className={styles.note}>当前尚未提供用户组、自定义策略、项目或实例级授权、跨账号角色切换。资源隔离由服务端鉴权执行，不依赖菜单隐藏。</p>
    </Card.Body>
  </Card>;
}

function AccountAccessContent() {
  const access = useAccountAccess();
  const scene = access.scene;
  const [selection, setSelection] = useState<"users" | "permissions" | "settings" | "tenants">("users");
  const fallback = scene?.canManage ? "users" : scene?.canCreateOrganizations ? "tenants" : "settings";
  const tab = (selection === "users" && !scene?.canManage) || (selection === "tenants" && !scene?.canCreateOrganizations) ? fallback : selection;
  return <section aria-label="账号与权限" aria-busy={access.loading || access.busy} className={styles.stack}>
    <div className={styles.toolbar}>
      <div aria-label="访问管理页面" className={styles.tabs} role="group">
        {scene?.canManage ? <Button aria-pressed={tab === "users"} onClick={() => setSelection("users")} variant={tab === "users" ? "secondary" : "ghost"}><Users aria-hidden="true" />用户</Button> : null}
        {scene ? <Button aria-pressed={tab === "permissions"} onClick={() => setSelection("permissions")} variant={tab === "permissions" ? "secondary" : "ghost"}><ShieldCheck aria-hidden="true" />权限</Button> : null}
        <Button aria-pressed={tab === "settings"} onClick={() => setSelection("settings")} variant={tab === "settings" ? "secondary" : "ghost"}><UserRound aria-hidden="true" />用户设置</Button>
        {scene?.canCreateOrganizations ? <Button aria-pressed={tab === "tenants"} onClick={() => setSelection("tenants")} variant={tab === "tenants" ? "secondary" : "ghost"}><Building2 aria-hidden="true" />租户管理</Button> : null}
      </div>
      <Button aria-label="刷新账号信息" disabled={access.loading || access.busy} onClick={access.reload} size="small" variant="ghost"><RefreshCcw aria-hidden="true" />刷新</Button>
    </div>
    {access.error ? <p className={styles.error} role="alert">{access.error}</p> : null}
    {access.success ? <p className={styles.success} role="status">{access.success}</p> : null}
    {access.loading ? <p className={styles.note} role="status">正在读取 IAM 账号信息…</p> : null}
    {scene ? <>
      <div className={styles.identity}>
        <ShieldCheck aria-hidden="true" />
        <div><small>所属租户 · 资源归属</small><strong>{scene.accountName}</strong><small>{scene.accountId}</small></div>
        <div><small>当前登录用户</small><strong>{scene.identityLabel}<Badge status="info">{scene.isPrimary ? "主账号" : "IAM 子用户"}</Badge></strong><small>{scene.roles.join(" · ") || "尚未授予业务权限"}</small></div>
      </div>
      {tab === "users" ? <UserDirectory scene={scene} /> : tab === "tenants" ? <TenantDirectory scene={scene} /> : tab === "permissions" ? <PermissionCatalog /> : <UserSettings key={scene.accountVersion} scene={scene} />}
    </> : null}
  </section>;
}

export function AccountAccessRenderer({ repository }: { repository?: AccountRepository }) {
  return <AccountAccessProvider repository={repository}><AccountAccessContent /></AccountAccessProvider>;
}
