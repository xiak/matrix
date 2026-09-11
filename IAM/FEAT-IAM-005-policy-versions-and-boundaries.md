# FEAT-IAM-005：自定义策略、条件与权限边界

- 状态：设计；未实施/未验收。
- 依赖：002、004、001 的目录。
- Owner：IAM 策略语言、分析器、版本与权限上限。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-LANG-01 | 自定义 Policy CRUD，不可变版本、一个有效版本、版本查询/删除/切换 |
| IAM-LANG-02 | 文档严格校验，未知/重复字段、超限、非法 scope/action/resource 拒绝 |
| IAM-LANG-03 | 精确 Action、受限通配、精确资源/集合选择、默认拒绝和显式 Deny |
| IAM-LANG-04 | 有界的字符串等值、时间、IP 条件；每键来源/类型/缺失/集合语义确定 |
| IAM-LANG-05 | User/Role boundary set/get/remove，仅限制最大权限 |
| IAM-LANG-06 | 版本切换/修改附件/边界下次请求生效，决定记录实际版本 |
| IAM-LANG-07 | 可视化/JSON 同一语言；分析器提供字段位置和稳定错误/警告 |
| IAM-LANG-08 | 委派管理不允许通过创建/改版/附件或去除边界扩大自身许可 |

## 详细设计

JSON languageVersion 初版定义一次，PolicyVersion 以独立 versionId/digest 记录内容。对象最多五个保留版本作为初始产品容量，可在真实容量门禁后调大；当前有效/被边界与历史证明引用版本不能直接删除。默认指针以 resourceVersion 原子切换，不就地改 JSON。

评估器处理类型化 Statement。条件缺失对匹配为 false；显式 Null 存在检查单独定义；否定条件也不能因属性缺失自动放行。多个条件同时满足，多值规则明确为 any/all；禁止隐式字符串类型转换。资源列表中每个必要资源都要通过，不以某个资源成功代替全部。

变更在 account → principal → policy → default pointer/attachment 锁顺序内检查管理者当前委派上限。首版可把高风险自定义授权限定为 root/明确 PolicyAdministrator 系统策略，不能用通用子集推理的假实现宣称安全委派。非 root 不得去除自身强制边界或为自己授予不可委派系统策略。

## 验收

Allow/Deny/边界交集表、条件缺失/类型/大小攻击、跨账号资源与 namespace、未知版本/Action、显式 Deny 全来源优先；真实数据库改版/附件/边界并发，旧 session 下次请求立即反映；旧事实仍可验证投递；UI 与 API 使用同一文档。fuzz 只证明当前 grammar 不崩溃且失败关闭，不快照实现细节。
