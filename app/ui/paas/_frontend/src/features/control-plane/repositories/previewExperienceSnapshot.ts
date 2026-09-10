import type { ExperienceSnapshot } from "../domain/experience";

export const previewExperienceSnapshot: ExperienceSnapshot = {
  organization: { id: "org-xiak", name: "Xiak 科技" },
  projects: [
    { id: "all", name: "全部项目" },
    { id: "commerce-prod", name: "电商中台 · 生产" },
    { id: "platform-dev", name: "平台研发 · 测试" }
  ],
  regions: [
    { id: "all", name: "全部区域" },
    { id: "shanghai-a", name: "上海私有云 A 区" },
    { id: "shanghai-b", name: "上海私有云 B 区" }
  ],
  resources: [
    {
      id: "pg-order-prod",
      name: "订单主库",
      kind: "POSTGRESQL",
      productId: "paas",
      productName: "托管数据库",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "HEALTHY",
      updatedAt: "2026-09-08T09:13:00Z",
      href: "/console/installations/"
    },
    {
      id: "app-checkout-api",
      name: "结算 API",
      kind: "APPLICATION",
      productId: "paas",
      productName: "应用托管",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "RUNNING",
      updatedAt: "2026-09-08T09:10:00Z",
      href: "/console/applications/"
    },
    {
      id: "pipeline-storefront",
      name: "storefront-release",
      kind: "PIPELINE",
      productId: "devops",
      productName: "研发效能",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "all",
      regionName: "全局",
      state: "HEALTHY",
      updatedAt: "2026-09-08T09:03:00Z",
      href: "/console/devops/"
    },
    {
      id: "service-payment",
      name: "支付服务",
      kind: "SERVICE_MONITOR",
      productId: "observability",
      productName: "可观测平台",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "DEGRADED",
      updatedAt: "2026-09-08T09:15:00Z",
      href: "/console/observability/"
    },
    {
      id: "node-edge-01",
      name: "edge-worker-01",
      kind: "COMPUTE_NODE",
      productId: "foundation",
      productName: "云基础平台",
      projectId: "platform-dev",
      projectName: "平台研发 · 测试",
      regionId: "shanghai-b",
      regionName: "上海私有云 B 区",
      state: "HEALTHY",
      updatedAt: "2026-09-08T09:14:00Z",
      href: "/console/regions/"
    },
    {
      id: "pg-matrix-dev",
      name: "Matrix 开发库",
      kind: "POSTGRESQL",
      productId: "paas",
      productName: "托管数据库",
      projectId: "platform-dev",
      projectName: "平台研发 · 测试",
      regionId: "shanghai-b",
      regionName: "上海私有云 B 区",
      state: "RUNNING",
      updatedAt: "2026-09-08T08:57:00Z",
      href: "/console/installations/"
    }
  ],
  operations: [
    { id: "op-1042", action: "发布应用", target: "结算 API · v2.8.0", productName: "应用托管", actor: "lin@org-xiak", state: "RUNNING", progress: 68, startedAt: "2026-09-08T09:12:00Z" },
    { id: "op-1041", action: "运行流水线", target: "storefront-release #286", productName: "研发效能", actor: "chen@org-xiak", state: "SUCCEEDED", progress: 100, startedAt: "2026-09-08T09:03:00Z", finishedAt: "2026-09-08T09:09:18Z" },
    { id: "op-1040", action: "扩容服务配额", target: "订单主库 · 生产型", productName: "托管数据库", actor: "admin", state: "SUCCEEDED", progress: 100, startedAt: "2026-09-08T08:37:00Z", finishedAt: "2026-09-08T08:38:24Z" },
    { id: "op-1039", action: "部署基础设施", target: "上海私有云 B 区", productName: "云基础平台", actor: "platform-bot", state: "FAILED", progress: 41, startedAt: "2026-09-08T08:15:00Z", finishedAt: "2026-09-08T08:17:51Z" }
  ],
  pipelines: [
    { id: "pipe-storefront", name: "storefront-release", repository: "commerce/storefront", branch: "main", commit: "4c7e2a1", environment: "生产", state: "SUCCEEDED", durationSeconds: 378, triggeredAt: "2026-09-08T09:03:00Z" },
    { id: "pipe-checkout", name: "checkout-api", repository: "commerce/checkout", branch: "release/2.8", commit: "a32fd09", environment: "生产", state: "RUNNING", durationSeconds: 222, triggeredAt: "2026-09-08T09:11:00Z" },
    { id: "pipe-matrix", name: "matrix-main", repository: "platform/matrix", branch: "main", commit: "d90b1f7", environment: "测试", state: "SUCCEEDED", durationSeconds: 484, triggeredAt: "2026-09-08T08:49:00Z" },
    { id: "pipe-infra", name: "region-rollout", repository: "platform/infrastructure", branch: "feat/shanghai-b", commit: "b831c2e", environment: "测试", state: "FAILED", durationSeconds: 171, triggeredAt: "2026-09-08T08:15:00Z" }
  ],
  serviceHealth: [
    { id: "checkout", name: "结算 API", productName: "电商中台", availability: 0.9998, latencyMs: 128, errorRate: 0.0018, state: "HEALTHY", trend: [42, 48, 46, 52, 58, 54, 62, 60, 66, 64, 72, 70] },
    { id: "payment", name: "支付服务", productName: "电商中台", availability: 0.9972, latencyMs: 386, errorRate: 0.0184, state: "DEGRADED", trend: [62, 58, 66, 54, 72, 68, 52, 44, 48, 38, 34, 41] },
    { id: "postgres", name: "订单主库", productName: "托管数据库", availability: 1, latencyMs: 12, errorRate: 0, state: "HEALTHY", trend: [36, 38, 40, 44, 42, 48, 46, 50, 52, 49, 54, 56] }
  ],
  alerts: [
    { id: "alert-payment-errors", title: "支付服务 5xx 错误率持续升高", serviceName: "支付服务", severity: "CRITICAL", state: "FIRING", startedAt: "2026-09-08T09:07:00Z", owner: "SRE 值班组" },
    { id: "alert-node-disk", title: "计算节点磁盘使用率超过 80%", serviceName: "edge-worker-02", severity: "WARNING", state: "ACKNOWLEDGED", startedAt: "2026-09-08T08:53:00Z", owner: "平台运维组" },
    { id: "alert-pipeline-duration", title: "生产流水线耗时偏离近期基线", serviceName: "storefront-release", severity: "INFO", state: "FIRING", startedAt: "2026-09-08T08:41:00Z", owner: "研发效能组" },
  ],
  announcements: [
    { id: "maintenance-shanghai-b", title: "上海私有云 B 区计划维护通知", body: "MOCK 通知：计划于 2026-09-10 02:00–03:00 UTC 进行基础设施维护。请提前检查关键工作负载的冗余配置；此样例不会触发实际维护。", publishedAt: "2026-09-08T09:10:00Z" },
    { id: "preview-ready", title: "Matrix Cloud 体验环境已就绪", body: "欢迎体验统一云控制台。当前服务、告警和任务均为 MOCK 数据，不会写入真实平台。消息已读状态只在当前体验会话保留。", publishedAt: "2026-09-08T08:00:00Z" }
  ],
  logs: {
    topics: [
      { id: "application", name: "application-production", regionId: "shanghai-a", retentionDays: 30, storageGiB: 12.6, source: "KUBERNETES", path: "/var/log/containers/*.log", nodeCount: 4, state: "ACTIVE" },
      { id: "gateway", name: "gateway-access", regionId: "shanghai-a", retentionDays: 7, storageGiB: 3.2, source: "KUBERNETES", path: "/var/log/gateway/access.log", nodeCount: 2, state: "ACTIVE" },
      { id: "system", name: "host-system", regionId: "shanghai-b", retentionDays: 14, storageGiB: 1.4, source: "HOST", path: "/var/log/syslog", nodeCount: 1, state: "PAUSED" }
    ],
    events: [
      { id: "log-1006", timestamp: "2026-09-08T09:14:28Z", topicId: "application", level: "ERROR", service: "payment-api", message: "Upstream payment provider timed out after 3000 ms", traceId: "trace-pay-8f42" },
      { id: "log-1005", timestamp: "2026-09-08T09:14:21Z", topicId: "gateway", level: "INFO", service: "gateway", message: "GET /api/catalog 200 18ms", traceId: "trace-gw-a421" },
      { id: "log-1004", timestamp: "2026-09-08T09:13:45Z", topicId: "application", level: "WARN", service: "checkout-api", message: "Connection pool utilization reached 82%", traceId: "trace-check-19c2" },
      { id: "log-1003", timestamp: "2026-09-08T09:12:36Z", topicId: "application", level: "INFO", service: "checkout-api", message: "Order created successfully: order-2026-1042", traceId: "trace-check-19b1" },
      { id: "log-1002", timestamp: "2026-09-08T09:11:08Z", topicId: "gateway", level: "ERROR", service: "gateway", message: "POST /api/payments 504 3012ms", traceId: "trace-pay-8f42" },
      { id: "log-1001", timestamp: "2026-09-08T09:02:18Z", topicId: "system", level: "INFO", service: "edge-worker-01", message: "Node heartbeat received; memory pressure normal", traceId: "trace-node-3310" }
    ]
  }
};
