# FEAT-IAM-004：用户组与授权委派

- 状态：设计；未实施/未验收。
- 依赖：002、003。
- Owner：IAM 组、成员关系、策略附件。

## 需求和接口

| ID | 行为 | 目标资源 API |
| --- | --- | --- |
| IAM-GRP-01 | 组创建/改名/详情/列表/删除，账号内唯一名称 | groups |
| IAM-GRP-02 | User 加入/移除组，幂等和 resourceVersion 冲突 | groups/{id}/memberships |
| IAM-GRP-03 | 策略关联/撤销与权限来源查询 | groups/{id}/policy-attachments |
| IAM-GRP-04 | 直接+组授权求并，Deny 与边界仍生效 | 同一 PDP，无 group 本地判断 |
| IAM-GRP-05 | 移除成员/删除组在下次受保护请求生效 | 当前事务快照重新装载 |

## 详细设计与事务

groups 与 memberships 保存独立 ID、Account、版本、状态。成员仅为当前 User；Root、ServiceIdentity、Role、嵌套 Group 拒绝。组无凭据、无业务资源归属。删除组只撤销成员关系和组附件，不删用户、不转移资源。

写入按 account → 用户 ID 有序 → group → policy/attachment 锁。membership 和 success outbox 同事务；同一个目标的并发加入/移除结果由预期版本决定。批量写入有上限并全事务失败，不能部分跨账号成功。委派者必须具备明确成员/附件管理 Action；不能通过 Group 给自己绕过边界或平台 scope。

## 验收

真实 HTTP 双账号同名组，跨账号 User/Policy/Group ID 拒绝；直接/继承来源区分；重复加入与并发删除/撤销可解释；移组下次请求失权；root/service/role 入组失败；当前 actor 失权在事务效果前拒绝。覆盖 unit、architecture、PG18、security、独立进程和对应浏览器路径。
