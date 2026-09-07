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
  products: [
    {
      id: "foundation",
      name: "云基础平台",
      eyebrow: "Cloud foundation",
      description: "统一管理区域、计算节点、网络与存储能力。",
      href: "/console/regions/",
      availability: "AVAILABLE",
      resourceCount: 18,
      capabilities: ["区域与节点", "网络与存储", "容量治理"]
    },
    {
      id: "paas",
      name: "应用与数据服务",
      eyebrow: "PaaS",
      description: "交付应用运行环境与平台托管的数据服务。",
      href: "/console/catalog/",
      availability: "AVAILABLE",
      resourceCount: 12,
      capabilities: ["应用托管", "托管数据库", "服务配额"]
    },
    {
      id: "devops",
      name: "研发效能",
      eyebrow: "DevOps",
      description: "从代码提交到多环境发布，持续掌握交付质量。",
      href: "/console/devops/",
      availability: "PREVIEW",
      resourceCount: 7,
      capabilities: ["流水线", "制品", "环境发布"]
    },
    {
      id: "observability",
      name: "可观测平台",
      eyebrow: "Observability",
      description: "关联指标、日志、告警与服务健康状态。",
      href: "/console/observability/",
      availability: "PREVIEW",
      resourceCount: 26,
      capabilities: ["服务健康", "告警中心", "日志检索"]
    },
    {
      id: "security",
      name: "安全与访问",
      eyebrow: "Security & IAM",
      description: "管理组织、账号、角色与审计访问边界。",
      href: "/console/access/",
      availability: "AVAILABLE",
      resourceCount: 9,
      capabilities: ["账号与角色", "最小权限", "审计记录"]
    }
  ],
  resources: [
    {
      id: "pg-order-prod",
      name: "订单主库",
      kind: "PostgreSQL 18",
      productId: "paas",
      productName: "托管数据库",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "HEALTHY",
      updatedAt: "2 分钟前",
      href: "/console/installations/"
    },
    {
      id: "app-checkout-api",
      name: "结算 API",
      kind: "应用服务",
      productId: "paas",
      productName: "应用托管",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "RUNNING",
      updatedAt: "5 分钟前",
      href: "/console/resources/"
    },
    {
      id: "pipeline-storefront",
      name: "storefront-release",
      kind: "交付流水线",
      productId: "devops",
      productName: "研发效能",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "all",
      regionName: "全局",
      state: "HEALTHY",
      updatedAt: "12 分钟前",
      href: "/console/devops/"
    },
    {
      id: "service-payment",
      name: "支付服务",
      kind: "服务监控",
      productId: "observability",
      productName: "可观测平台",
      projectId: "commerce-prod",
      projectName: "电商中台 · 生产",
      regionId: "shanghai-a",
      regionName: "上海私有云 A 区",
      state: "DEGRADED",
      updatedAt: "刚刚",
      href: "/console/observability/"
    },
    {
      id: "node-edge-01",
      name: "edge-worker-01",
      kind: "计算节点",
      productId: "foundation",
      productName: "云基础平台",
      projectId: "platform-dev",
      projectName: "平台研发 · 测试",
      regionId: "shanghai-b",
      regionName: "上海私有云 B 区",
      state: "HEALTHY",
      updatedAt: "1 分钟前",
      href: "/console/regions/"
    },
    {
      id: "pg-matrix-dev",
      name: "Matrix 开发库",
      kind: "PostgreSQL 18",
      productId: "paas",
      productName: "托管数据库",
      projectId: "platform-dev",
      projectName: "平台研发 · 测试",
      regionId: "shanghai-b",
      regionName: "上海私有云 B 区",
      state: "RUNNING",
      updatedAt: "18 分钟前",
      href: "/console/installations/"
    }
  ],
  operations: [
    { id: "op-1042", action: "发布应用", target: "结算 API · v2.8.0", productName: "应用托管", actor: "lin@org-xiak", state: "RUNNING", progress: 68, startedAt: "3 分钟前" },
    { id: "op-1041", action: "运行流水线", target: "storefront-release #286", productName: "研发效能", actor: "chen@org-xiak", state: "SUCCEEDED", progress: 100, startedAt: "12 分钟前" },
    { id: "op-1040", action: "扩容服务配额", target: "订单主库 · 生产型", productName: "托管数据库", actor: "admin", state: "SUCCEEDED", progress: 100, startedAt: "38 分钟前" },
    { id: "op-1039", action: "部署基础设施", target: "上海私有云 B 区", productName: "云基础平台", actor: "platform-bot", state: "FAILED", progress: 41, startedAt: "1 小时前" }
  ],
  pipelines: [
    { id: "pipe-storefront", name: "storefront-release", repository: "commerce/storefront", branch: "main", commit: "4c7e2a1", environment: "生产", state: "SUCCEEDED", duration: "6m 18s", triggeredAt: "12 分钟前" },
    { id: "pipe-checkout", name: "checkout-api", repository: "commerce/checkout", branch: "release/2.8", commit: "a32fd09", environment: "生产", state: "RUNNING", duration: "3m 42s", triggeredAt: "4 分钟前" },
    { id: "pipe-matrix", name: "matrix-main", repository: "platform/matrix", branch: "main", commit: "d90b1f7", environment: "测试", state: "SUCCEEDED", duration: "8m 04s", triggeredAt: "26 分钟前" },
    { id: "pipe-infra", name: "region-rollout", repository: "platform/infrastructure", branch: "feat/shanghai-b", commit: "b831c2e", environment: "测试", state: "FAILED", duration: "2m 51s", triggeredAt: "1 小时前" }
  ],
  serviceHealth: [
    { id: "checkout", name: "结算 API", productName: "电商中台", availability: "99.98%", latency: "128 ms", errorRate: "0.18%", state: "HEALTHY", trend: [42, 48, 46, 52, 58, 54, 62, 60, 66, 64, 72, 70] },
    { id: "payment", name: "支付服务", productName: "电商中台", availability: "99.72%", latency: "386 ms", errorRate: "1.84%", state: "DEGRADED", trend: [62, 58, 66, 54, 72, 68, 52, 44, 48, 38, 34, 41] },
    { id: "postgres", name: "订单主库", productName: "托管数据库", availability: "100%", latency: "12 ms", errorRate: "0.00%", state: "HEALTHY", trend: [36, 38, 40, 44, 42, 48, 46, 50, 52, 49, 54, 56] }
  ],
  alerts: [
    { id: "alert-payment-errors", title: "支付服务 5xx 错误率持续升高", serviceName: "支付服务", severity: "CRITICAL", state: "FIRING", startedAt: "8 分钟前", owner: "SRE 值班组" },
    { id: "alert-node-disk", title: "计算节点磁盘使用率超过 80%", serviceName: "edge-worker-02", severity: "WARNING", state: "ACKNOWLEDGED", startedAt: "22 分钟前", owner: "平台运维组" },
    { id: "alert-pipeline-duration", title: "生产流水线耗时偏离近期基线", serviceName: "storefront-release", severity: "INFO", state: "FIRING", startedAt: "34 分钟前", owner: "研发效能组" }
  ]
};
