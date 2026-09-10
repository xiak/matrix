(() => {
  'use strict';

  const installationAPIVersion = 'installation.matrix.xiak.com/v1';
  const devopsAPIVersion = 'devops.matrix.xiak.com/v1';
  const sourceFreshnessMilliseconds = 2 * 60 * 1000;
  const productCatalog = Object.freeze({
    APPLICATION_PAAS: Object.freeze({
      route: 'paas', defaultPath: '/paas/configuration', label: 'Application PaaS', short: 'AP', view: 'paas-view'
    }),
    DEVOPS: Object.freeze({
      route: 'devops', defaultPath: '/devops/code', label: 'DevOps', short: 'DO', view: 'devops-view'
    })
  });
  const productStates = new Set(['READY', 'DEGRADED', 'UNAVAILABLE']);
  const productReasons = new Set(['', 'DEPENDENCY_UNAVAILABLE', 'OBSERVATION_STALE']);
  const productViews = [
    'login-view', 'loading-view', 'empty-view', 'paas-view', 'devops-view',
    'unsupported-view', 'route-not-found-view'
  ];
  const devopsRoutes = new Set(['code', 'pipelines', 'runs']);
  const terminalRunStates = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION']);
  const sourceHealthLabels = Object.freeze({
    PENDING: '等待观测',
    READY: '最近观测正常',
    UNAVAILABLE: '当前不可用',
    STALE: '观测已过期'
  });
  const sourceReasonLabels = Object.freeze({
    CONFIGURATION_CHANGED: '配置已变化，等待重新观测',
    OBSERVED: '固定检查已全部通过',
    SECRET_UNAVAILABLE: '凭据引用当前不可用',
    PROVIDER_UNAVAILABLE: '代码服务当前不可达',
    PROVIDER_UNSUPPORTED: '代码服务版本不受支持',
    CREDENTIAL_REJECTED: '代码服务拒绝凭据',
    CONNECTION_NOT_READY: '上游连接尚未就绪',
    REPOSITORY_UNAVAILABLE: '仓库当前不可观测',
    IDENTITY_MISMATCH: '仓库身份与绑定不一致',
    FETCH_PERMISSION_DENIED: '读取仓库权限不足',
    REPORT_PERMISSION_DENIED: '回报检查权限不足'
  });
  const runStateLabels = Object.freeze({
    QUEUED: '排队中',
    FETCHING: '正在获取',
    VERIFYING: '正在验证',
    REPORTING: '正在回报',
    SUCCEEDED: '验证通过',
    FAILED: '验证失败',
    CANCELLED: '已取消',
    RECONCILING: '正在核对外部结果',
    MANUAL_INTERVENTION: '需要人工介入'
  });
  const runReasonLabels = Object.freeze({
    EVENT_ADMITTED: '可信事件已接受',
    COMPLETED: '全部阶段已完成',
    SOURCE_UNAVAILABLE: '源代码当前不可用',
    COMMIT_MISMATCH: '提交身份与可信输入不一致',
    EXECUTOR_UNAVAILABLE: '隔离执行器当前不可用',
    VERIFICATION_FAILED: '固定验证步骤失败',
    DEADLINE_EXCEEDED: '运行超过固定时限',
    REPORT_UNAVAILABLE: '检查结果当前无法回报',
    REPORT_CONFLICT: '代码服务已有冲突结果',
    CANCELLED: '取消请求已生效',
    EXTERNAL_EFFECT_UNCERTAIN: '正在核对可能发生的外部效果',
    RECONCILIATION_EXHAUSTED: '自动核对已达上限'
  });

  let credential = '';
  let organization = '';
  let inventory = null;
  let activeProduct = null;
  let devopsBusy = false;
  let platformClockEpoch = NaN;
  let platformClockMonotonic = 0;
  const devopsState = {
    project: null,
    connection: null,
    binding: null,
    pipeline: null,
    revision: null,
    run: null,
    logs: [],
    nextLogSequence: 0,
    lastLogPage: null
  };

  const element = id => document.getElementById(id);
  const status = element('status');
  const statusBox = element('global-status');

  function token(prefix) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return prefix + Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
  }

  function setStatus(message, state = '') {
    status.textContent = String(message).slice(0, 240);
    statusBox.className = 'global-status' + (state ? ' ' + state : '');
  }

  function setText(id, value, fallback = '—') {
    const normalized = value === undefined || value === null || value === '' ? fallback : String(value);
    element(id).textContent = normalized.slice(0, 1024);
  }

  function showView(id, focus = true) {
    for (const view of productViews) element(view).hidden = view !== id;
    if (focus) element('workspace').focus({preventScroll: true});
  }

  function safeErrorMessage(response, body) {
    if (response.status === 400) return '输入不符合公开契约，请检查字段';
    if (response.status === 401) return '会话已失效，请重新登录';
    if (response.status === 403) return '当前身份没有执行此操作的权限';
    if (response.status === 404) return '当前组织中找不到该资源';
    if (response.status === 409) return '资源状态已变化或请求与既有意图冲突';
    if (response.status === 412) return '资源版本已变化，请先刷新状态';
    if (response.status === 413) return '请求超过平台固定上限';
    if (response.status === 415) return '请求格式不受支持';
    if (response.status === 428) return '操作缺少当前资源版本，请先刷新状态';
    if (response.status === 429) return '当前组织的运行队列已满';
    if (response.status === 503) return '平台依赖当前不可用，请稍后重试';
    if (body && body.code === 'INVALID_CONFIGURATION') return '配置内容不符合平台约束';
    return '请求未被平台接受';
  }

  async function responseBody(response, authenticated) {
    const contentType = response.headers.get('Content-Type') || '';
    let body = {};
    if (contentType.startsWith('application/json') || contentType.startsWith('application/problem+json')) {
      try { body = await response.json(); } catch (_) { body = {}; }
    }
    if (!response.ok) {
      const message = safeErrorMessage(response, body);
      if (authenticated && response.status === 401) clearSession(message);
      throw new Error(message);
    }
    if (!contentType.startsWith('application/json')) throw new Error('平台响应格式无效');
    return body;
  }

  async function apiRequest(path, options = {}, authenticated = true) {
    if (authenticated && !credential) throw new Error('请先登录');
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (authenticated) headers.set('Authorization', 'Bearer ' + credential);
    const response = await fetch(path, {
      ...options,
      headers,
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error'
    });
    return responseBody(response, authenticated);
  }

  async function platformPost(path, body, keyPrefix) {
    return apiRequest(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': token(keyPrefix)
      },
      body: JSON.stringify(body)
    });
  }

  async function guardedCommand(path, resourceVersion, keyPrefix) {
    if (!Number.isSafeInteger(resourceVersion) || resourceVersion < 1) {
      throw new Error('缺少可验证的当前资源版本，请先刷新状态');
    }
    return apiRequest(path, {
      method: 'POST',
      headers: {
        'If-Match': '"' + resourceVersion + '"',
        'Idempotency-Key': token(keyPrefix)
      }
    });
  }

  function requireDevOpsKind(value, kind) {
    if (!value || value.apiVersion !== devopsAPIVersion || value.kind !== kind) {
      throw new Error('DevOps 响应不符合当前 UI 契约');
    }
    return value;
  }

  function validInventory(value) {
    if (!value || value.apiVersion !== installationAPIVersion || value.kind !== 'InstalledProductList' ||
      typeof value.releaseId !== 'string' || typeof value.releaseVersion !== 'string' ||
      typeof value.observedAt !== 'string' || !Array.isArray(value.products) || value.products.length > 16) {
      return false;
    }
    const seen = new Set();
    return value.products.every(product => {
      const declared = product && productCatalog[product.id];
      if (!declared || seen.has(product.id) || product.routeKey !== declared.route ||
        typeof product.version !== 'string' || product.version.length > 96 ||
        !productStates.has(product.state) || !productReasons.has(product.reason || '') ||
        typeof product.observedAt !== 'string') {
        return false;
      }
      if ((product.state === 'READY') !== !(product.reason || '')) return false;
      seen.add(product.id);
      return true;
    });
  }

  function resetDevOpsState(resetForms = false) {
    devopsState.project = null;
    devopsState.connection = null;
    devopsState.binding = null;
    devopsState.pipeline = null;
    devopsState.revision = null;
    devopsState.run = null;
    devopsState.logs = [];
    devopsState.nextLogSequence = 0;
    devopsState.lastLogPage = null;
    devopsBusy = false;
    if (resetForms) {
      for (const id of ['devops-project-form', 'source-connection-form', 'repository-binding-form', 'pipeline-form', 'run-lookup-form']) {
        element(id).reset();
      }
    }
    renderDevOpsState();
  }

  function clearSession(message = '会话已从页面内存清除') {
    credential = '';
    organization = '';
    inventory = null;
    activeProduct = null;
    platformClockEpoch = NaN;
    platformClockMonotonic = 0;
    element('identity').hidden = true;
    element('product-navigation').hidden = true;
    element('product-list').replaceChildren();
    element('password').value = '';
    resetDevOpsState(true);
    showView('login-view', false);
    setStatus(message, message.includes('失效') ? 'error' : '');
    element('login-name').focus();
  }

  function stateClass(state) {
    if (state === 'READY') return 'ready';
    if (state === 'DEGRADED') return 'degraded';
    return 'unavailable';
  }

  function renderProductNavigation() {
    const list = element('product-list');
    list.replaceChildren();
    for (const product of inventory.products) {
      const declared = productCatalog[product.id];
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'product-button';
      button.dataset.productId = product.id;
      button.setAttribute('aria-label', declared.label + '，状态 ' + product.state);

      const glyph = document.createElement('span');
      glyph.className = 'product-glyph';
      glyph.setAttribute('aria-hidden', 'true');
      glyph.textContent = declared.short;
      const copy = document.createElement('span');
      const name = document.createElement('strong');
      name.textContent = declared.label;
      const version = document.createElement('small');
      version.textContent = product.version;
      copy.append(name, version);
      const dot = document.createElement('span');
      dot.className = 'product-status-dot ' + stateClass(product.state);
      dot.setAttribute('aria-hidden', 'true');
      button.append(glyph, copy, dot);
      button.addEventListener('click', () => navigateToProduct(product));
      list.append(button);
    }
  }

  function requestedRoute() {
    return location.pathname.split('/').filter(Boolean)[0] || '';
  }

  function requestedDevOpsRoute() {
    const segments = location.pathname.split('/').filter(Boolean);
    return segments[1] || 'code';
  }

  function navigateToProduct(product, replace = false) {
    const declared = productCatalog[product.id];
    history[replace ? 'replaceState' : 'pushState']({}, '', declared.defaultPath);
    renderRoute();
  }

  function renderRoute(focus = true) {
    if (!credential || !inventory) return;
    const route = requestedRoute();
    if (!route) {
      if (inventory.products.length) navigateToProduct(inventory.products[0], true);
      else showView('empty-view');
      return;
    }
    const product = inventory.products.find(item => productCatalog[item.id].route === route);
    const normalizedPath = location.pathname.replace(/\/+$/, '') || '/';
    if (product && product.id === 'DEVOPS' && normalizedPath === '/devops') {
      history.replaceState({}, '', '/devops/code');
      renderRoute(focus);
      return;
    }
    const devopsPath = product && product.id === 'DEVOPS' ? requestedDevOpsRoute() : '';
    const knownPath = product && (
      (product.id === 'APPLICATION_PAAS' && (normalizedPath === '/paas' || normalizedPath === '/paas/configuration')) ||
      (product.id === 'DEVOPS' && normalizedPath === '/devops/' + devopsPath && devopsRoutes.has(devopsPath))
    );
    if (!knownPath) {
      activeProduct = null;
      updateActiveButton('');
      showView('route-not-found-view', focus);
      return;
    }
    activeProduct = product;
    updateActiveButton(product.id);
    if (product.id === 'APPLICATION_PAAS') renderPaaS(product, focus);
    else if (product.id === 'DEVOPS') renderDevOps(product, devopsPath, focus);
    else showView(productCatalog[product.id].view, focus);
  }

  function updateActiveButton(productID) {
    for (const button of element('product-list').querySelectorAll('button')) {
      const active = button.dataset.productId === productID;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
  }

  function formatObservedAt(value) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return '无有效观测';
    return new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).format(parsed);
  }

  function renderPaaS(product, focus = true) {
    const state = element('product-state');
    state.className = 'product-state ' + stateClass(product.state);
    const labels = {READY: '运行正常', DEGRADED: '状态降级', UNAVAILABLE: '当前不可用'};
    element('product-state-label').textContent = labels[product.state];
    element('product-version').textContent = product.version;
    element('release-id').textContent = inventory.releaseId;
    element('release-version').textContent = inventory.releaseVersion;
    element('observed-at').textContent = formatObservedAt(product.observedAt);

    const notice = element('product-notice');
    notice.className = 'notice' + (product.state === 'UNAVAILABLE' ? ' unavailable' : '');
    notice.hidden = product.state === 'READY';
    if (product.state === 'DEGRADED') {
      element('product-notice-title').textContent = product.reason === 'OBSERVATION_STALE' ? '产品状态观测已过期' : '产品依赖状态降级';
      element('product-notice-detail').textContent = '页面保持可诊断，变更操作暂时关闭。';
    } else if (product.state === 'UNAVAILABLE') {
      element('product-notice-title').textContent = '产品当前不可用';
      element('product-notice-detail').textContent = '页面保持可诊断，平台已关闭所有变更操作。';
    }
    for (const control of document.querySelectorAll('.paas-mutation-control')) {
      control.disabled = product.state !== 'READY';
    }
    showView('paas-view', focus);
  }

  function renderDevOps(product, route, focus = true) {
    const state = element('devops-product-state');
    state.className = 'product-state ' + stateClass(product.state);
    const labels = {READY: '运行正常', DEGRADED: '状态降级', UNAVAILABLE: '当前不可用'};
    setText('devops-product-state-label', labels[product.state]);
    setText('devops-product-version', product.version);
    setText('devops-release-id', inventory.releaseId);
    setText('devops-release-version', inventory.releaseVersion);
    setText('devops-observed-at', formatObservedAt(product.observedAt));

    const notice = element('devops-product-notice');
    notice.className = 'notice' + (product.state === 'UNAVAILABLE' ? ' unavailable' : '');
    notice.hidden = product.state === 'READY';
    if (product.state === 'DEGRADED') {
      setText('devops-product-notice-title', product.reason === 'OBSERVATION_STALE' ? '产品状态观测已过期' : 'DevOps 依赖状态降级');
      setText('devops-product-notice-detail', '现有资源和运行证据仍可读取；创建、激活、Recheck 与运行控制已关闭。');
    } else if (product.state === 'UNAVAILABLE') {
      setText('devops-product-notice-title', 'DevOps 当前不可用');
      setText('devops-product-notice-detail', '页面保持可诊断，平台已关闭所有变更操作。');
    }

    for (const button of element('devops-local-nav').querySelectorAll('button')) {
      const current = button.dataset.devopsRoute === route;
      button.classList.toggle('active', current);
      if (current) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    element('devops-code-panel').hidden = route !== 'code';
    element('devops-pipelines-panel').hidden = route !== 'pipelines';
    element('devops-runs-panel').hidden = route !== 'runs';
    renderDevOpsState();
    showView('devops-view', focus);
  }

  function devopsCanMutate() {
    return Boolean(activeProduct && activeProduct.id === 'DEVOPS' && activeProduct.state === 'READY');
  }

  function resourceVersionOf(resource) {
    if (resource && resource.metadata && Number.isSafeInteger(resource.metadata.resourceVersion)) {
      return resource.metadata.resourceVersion;
    }
    if (resource && resource.status && Number.isSafeInteger(resource.status.resourceVersion)) {
      return resource.status.resourceVersion;
    }
    return 0;
  }

  function staleSourceStatus(statusValue) {
    if (!statusValue || statusValue.health !== 'READY') return false;
    const observed = new Date(statusValue.observedAt).getTime();
    const elapsed = Math.max(0, performance.now() - platformClockMonotonic);
    const reference = Number.isNaN(platformClockEpoch) ? Date.now() : platformClockEpoch + elapsed;
    return Number.isNaN(observed) || reference - observed >= sourceFreshnessMilliseconds ||
      Boolean(activeProduct && activeProduct.reason === 'OBSERVATION_STALE');
  }

  function appendSummary(containerID, glyph, emptyMessage, title, badge, tone, rows) {
    const container = element(containerID);
    container.replaceChildren();
    if (!title) {
      const mark = document.createElement('span');
      mark.className = 'empty-mark';
      mark.setAttribute('aria-hidden', 'true');
      mark.textContent = glyph;
      const copy = document.createElement('p');
      copy.textContent = emptyMessage;
      container.append(mark, copy);
      container.className = 'resource-summary';
      return;
    }

    container.className = 'resource-summary populated ' + tone;
    const heading = document.createElement('div');
    heading.className = 'summary-heading';
    const strong = document.createElement('strong');
    strong.textContent = String(title).slice(0, 256);
    const tag = document.createElement('span');
    tag.className = 'status-tag ' + tone;
    tag.textContent = badge;
    heading.append(strong, tag);
    const list = document.createElement('dl');
    list.className = 'summary-list';
    for (const row of rows) {
      const item = document.createElement('div');
      const term = document.createElement('dt');
      const description = document.createElement('dd');
      term.textContent = row[0];
      description.textContent = String(row[1] || '—').slice(0, 1024);
      item.append(term, description);
      list.append(item);
    }
    container.append(heading, list);
  }

  function renderProjectSummary() {
    const project = devopsState.project;
    appendSummary(
      'devops-project-summary', '＋', '尚未选择项目',
      project && project.metadata ? project.metadata.name : '',
      'SELECTED', 'ready',
      project && project.metadata ? [
        ['ID', project.metadata.id],
        ['Tenant', project.metadata.scope && project.metadata.scope.tenantId],
        ['Version', project.metadata.resourceVersion]
      ] : []
    );
  }

  function sourcePresentation(resource) {
    if (!resource || !resource.status) return {health: 'UNKNOWN', label: '状态未知', tone: 'unknown'};
    if (staleSourceStatus(resource.status)) return {health: 'STALE', label: sourceHealthLabels.STALE, tone: 'stale'};
    const health = sourceHealthLabels[resource.status.health] ? resource.status.health : 'UNKNOWN';
    const tones = {READY: 'ready', PENDING: 'pending', UNAVAILABLE: 'unavailable', UNKNOWN: 'unknown'};
    return {health, label: sourceHealthLabels[health] || '状态未知', tone: tones[health]};
  }

  function renderConnectionSummary() {
    const connection = devopsState.connection;
    const presentation = sourcePresentation(connection);
    appendSummary(
      'source-connection-summary', '◎', '尚未读取连接状态',
      connection && connection.metadata ? connection.metadata.name : '',
      presentation.label, presentation.tone,
      connection && connection.metadata && connection.spec && connection.status ? [
        ['ID', connection.metadata.id],
        ['Origin', connection.spec.endpointOrigin],
        ['原因', sourceReasonLabels[connection.status.reason] || '未识别的安全原因'],
        ['观测时间', formatObservedAt(connection.status.observedAt)]
      ] : []
    );
  }

  function renderBindingSummary() {
    const binding = devopsState.binding;
    const presentation = sourcePresentation(binding);
    appendSummary(
      'repository-binding-summary', '◇', '尚未读取仓库绑定',
      binding && binding.metadata ? binding.metadata.name : '',
      presentation.label, presentation.tone,
      binding && binding.metadata && binding.spec && binding.status ? [
        ['ID', binding.metadata.id],
        ['Repository', binding.spec.repositoryPath],
        ['Trusted branch', binding.spec.trustedDefaultBranch],
        ['原因', sourceReasonLabels[binding.status.reason] || '未识别的安全原因'],
        ['观测时间', formatObservedAt(binding.status.observedAt)]
      ] : []
    );
  }

  function safeCLIIdentity(value, fallback) {
    const normalized = String(value || '').trim();
    return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(normalized) ? normalized : fallback;
  }

  function renderOperatorCommands() {
    const spec = devopsState.connection && devopsState.connection.spec ? devopsState.connection.spec : {
      webhookSecretRef: element('webhook-secret-ref').value,
      fetchCredentialRef: element('fetch-credential-ref').value,
      reportCredentialRef: element('report-credential-ref').value
    };
    const tenant = safeCLIIdentity(organization, '<organization>');
    const commands = [
      ['WEBHOOK', safeCLIIdentity(spec.webhookSecretRef, '<reference>')],
      ['FETCH', safeCLIIdentity(spec.fetchCredentialRef, '<reference>')],
      ['REPORT', safeCLIIdentity(spec.reportCredentialRef, '<reference>')]
    ];
    const list = element('source-credential-commands');
    list.replaceChildren();
    for (const command of commands) {
      const row = document.createElement('div');
      const label = document.createElement('span');
      label.textContent = command[0];
      const code = document.createElement('code');
      code.textContent = 'mx devops source-credential apply --root <installation> --tenant ' + tenant +
        ' --purpose ' + command[0] + ' --reference ' + command[1] + ' --from-file <private-file>';
      row.append(label, code);
      list.append(row);
    }
  }

  function closedValue(value, accepted, fallback) {
    return accepted.has(value) ? value : fallback;
  }

  function formatBytes(value) {
    if (!Number.isFinite(value) || value < 0) return '—';
    if (value >= 1073741824) return (value / 1073741824).toFixed(value % 1073741824 === 0 ? 0 : 1) + ' GiB';
    if (value >= 1048576) return (value / 1048576).toFixed(value % 1048576 === 0 ? 0 : 1) + ' MiB';
    return value + ' B';
  }

  function renderPipelineSummary() {
    const pipeline = devopsState.pipeline;
    appendSummary(
      'pipeline-summary', '↗', '尚未创建或读取流水线',
      pipeline && pipeline.metadata ? pipeline.metadata.name : '',
      pipeline && pipeline.activeRevision ? 'ACTIVE' : 'DRAFT',
      pipeline && pipeline.activeRevision ? 'ready' : 'pending',
      pipeline && pipeline.metadata && pipeline.draft && pipeline.draft.spec ? [
        ['ID', pipeline.metadata.id],
        ['Binding', pipeline.draft.spec.repositoryBindingId],
        ['Trigger', closedValue(pipeline.draft.spec.triggerPolicy, new Set(['CHANGE']), '未知策略')],
        ['Profile', closedValue(pipeline.draft.spec.verificationProfile, new Set(['GO_1_26_OFFLINE_V1']), '未知档案')],
        ['Revision', pipeline.activeRevision ? pipeline.activeRevision.id : '尚未激活']
      ] : []
    );

    const revision = devopsState.revision;
    element('revision-contract').hidden = !revision;
    if (revision && revision.spec) {
      const limits = revision.spec.limits || {};
      const steps = Array.isArray(revision.spec.steps) ? revision.spec.steps.map(step => {
        return closedValue(step.kind, new Set(['GO_TEST', 'GO_VET']), 'UNKNOWN');
      }).join(' → ') : '—';
      setText('revision-number', '#' + revision.revision);
      setText('revision-id-display', revision.id);
      setText('revision-executor', closedValue(revision.spec.executorProfile, new Set(['MATRIX_NATIVE_ISOLATED_V1']), '未知执行器'));
      setText('revision-steps', steps);
      setText('revision-timeouts', limits.stepTimeoutSeconds + 's / run ' + limits.runTimeoutSeconds + 's');
      setText('revision-compute', limits.cpuMillis + 'm CPU / ' + formatBytes(limits.memoryBytes) + ' / ' + limits.processLimit + ' processes');
      setText('revision-log-limit', formatBytes(limits.maxLogBytes));
    }

    const binding = devopsState.binding;
    const connection = devopsState.connection;
    setText('pipeline-bound-source', binding && binding.spec ? binding.spec.repositoryPath + ' @ ' + binding.spec.trustedDefaultBranch : '未读取仓库绑定');
    const connectionPresentation = sourcePresentation(connection);
    setText('pipeline-source-health', connection ? '连接：' + connectionPresentation.label : '连接健康未知');
    setText(
      'pipeline-latest-run',
      devopsState.run && pipeline && devopsState.run.pipelineId === pipeline.metadata.id
        ? devopsState.run.id + ' · ' + (runStateLabels[devopsState.run.status.state] || '状态未知')
        : '当前页面尚未读取运行'
    );
  }

  function renderDeliveryContext() {
    setText('context-project', devopsState.project && devopsState.project.metadata && devopsState.project.metadata.id, '未选择');
    setText('context-repository', devopsState.binding && devopsState.binding.spec && devopsState.binding.spec.repositoryPath, '未绑定');
    setText(
      'context-pipeline',
      devopsState.pipeline && devopsState.pipeline.activeRevision && devopsState.pipeline.activeRevision.id,
      devopsState.pipeline ? '草稿未激活' : '未激活'
    );
    setText('context-run', devopsState.run && devopsState.run.id, '等待触发');
  }

  function renderRunStages(run) {
    const stages = ['RECEIVE', 'FETCH', 'VERIFY', 'REPORT'];
    const currentIndex = run && run.status ? stages.indexOf(run.status.stage) : -1;
    const stateValue = run && run.status ? run.status.state : '';
    for (const item of element('run-stage-rail').querySelectorAll('li')) {
      const index = stages.indexOf(item.dataset.stage);
      item.className = '';
      item.removeAttribute('aria-current');
      if (stateValue === 'SUCCEEDED' || index < currentIndex) {
        item.className = 'done';
      } else if (index === currentIndex) {
        if (stateValue === 'FAILED') item.className = 'failed';
        else if (stateValue === 'CANCELLED') item.className = 'cancelled';
        else if (stateValue === 'MANUAL_INTERVENTION') item.className = 'manual';
        else if (stateValue === 'RECONCILING') item.className = 'reconciling';
        else item.className = 'active';
        item.setAttribute('aria-current', 'step');
      }
    }
  }

  function renderRunEvidence() {
    const run = devopsState.run;
    element('run-empty-state').hidden = Boolean(run);
    element('run-evidence').hidden = !run;
    if (!run || !run.status || !run.input || !run.input.change) {
      renderRunStages(null);
      return;
    }

    const stateValue = runStateLabels[run.status.state] ? run.status.state : 'UNKNOWN';
    setText('run-id-display', run.id);
    setText('run-context-display', 'SourceEvent ' + run.input.sourceEventId + ' · revision ' + run.input.pipelineRevisionId);
    const stateTag = element('run-state');
    stateTag.textContent = runStateLabels[stateValue] || '状态未知';
    stateTag.className = 'run-state ' + stateValue.toLowerCase();
    setText('run-project-pipeline', run.projectId + ' / ' + run.pipelineId);
    setText('run-change', '#' + run.input.change.number + ' · ' + closedValue(run.input.change.action, new Set(['OPENED', 'REOPENED', 'UPDATED']), 'UNKNOWN'));
    setText('run-head-commit', run.input.change.headCommit);
    setText('run-base-commit', run.input.change.trustedBaseCommit);
    setText('run-revision', run.input.pipelineRevisionId);
    setText('run-input-digest', run.inputDigest);
    setText('run-observed-at', formatObservedAt(run.status.observedAt));
    setText('run-reason', runReasonLabels[run.status.reason] || '平台未返回已知原因');
    renderRunStages(run);
  }

  function renderLogs() {
    setText('log-cursor', 'afterSequence ' + devopsState.nextLogSequence);
    const output = element('run-logs');
    if (!devopsState.logs.length) {
      output.textContent = '等待日志证据…';
    } else {
      output.textContent = devopsState.logs.map(chunk => {
        const kind = chunk.step && ['GO_TEST', 'GO_VET'].includes(chunk.step.kind) ? chunk.step.kind : 'UNKNOWN';
        const ordinal = chunk.step && Number.isSafeInteger(chunk.step.ordinal) ? chunk.step.ordinal : '?';
        return '[' + chunk.sequence + '] step ' + ordinal + ' · ' + kind + '\n' + String(chunk.content || '');
      }).join('\n');
    }

    const page = devopsState.lastLogPage;
    if (!page) {
      setText('log-notice', '尚未读取日志。');
    } else if (page.truncated) {
      setText('log-notice', '较早日志已按保留策略过期；当前显示从可用 cursor 开始的证据。');
    } else if (!page.chunks.length) {
      setText('log-notice', '当前 cursor 之后暂无日志；这不等同于日志被截断。');
    } else if (page.hasMore) {
      setText('log-notice', '已读取一页，仍有更多规范化日志。');
    } else {
      setText('log-notice', '已读取当前可用的规范化日志。');
    }
  }

  function renderDevOpsControls() {
    const view = element('devops-view');
    const mutationsDisabled = devopsBusy || !devopsCanMutate();
    for (const control of view.querySelectorAll('.devops-mutation-control')) control.disabled = mutationsDisabled;
    for (const control of view.querySelectorAll('.devops-read-control')) control.disabled = devopsBusy;
    element('recheck-source-connection').disabled = mutationsDisabled || !devopsState.connection;
    element('recheck-repository-binding').disabled = mutationsDisabled || !devopsState.binding;
    element('activate-pipeline').disabled = mutationsDisabled || !devopsState.pipeline;

    const run = devopsState.run;
    const terminal = Boolean(run && run.status && terminalRunStates.has(run.status.state));
    element('cancel-run').disabled = mutationsDisabled || !run || terminal ||
      Boolean(run && run.status && run.status.cancellationRequestedAt);
    element('replay-run').disabled = mutationsDisabled || !run || !terminal;
    element('refresh-run').disabled = devopsBusy || !run;
    element('load-run-logs').disabled = devopsBusy || !run;
    element('clear-run-logs').disabled = devopsBusy || devopsState.logs.length === 0;
    view.setAttribute('aria-busy', devopsBusy ? 'true' : 'false');
  }

  function renderDevOpsState() {
    renderProjectSummary();
    renderConnectionSummary();
    renderBindingSummary();
    renderOperatorCommands();
    renderPipelineSummary();
    renderDeliveryContext();
    renderRunEvidence();
    renderLogs();
    renderDevOpsControls();
  }

  function resourcePathID(inputID) {
    const value = element(inputID).value.trim();
    if (!/^[a-z0-9][a-z0-9._-]{1,127}$/.test(value)) {
      throw new Error('资源 ID 不符合公开契约');
    }
    return encodeURIComponent(value);
  }

  function setInput(id, value) {
    if (value !== undefined && value !== null) element(id).value = String(value).slice(0, 512);
  }

  function setProject(project) {
    devopsState.project = project;
    if (project && project.metadata) {
      setInput('devops-project-id', project.metadata.id);
      setInput('devops-project-name', project.metadata.name);
      setInput('binding-project-id', project.metadata.id);
      setInput('pipeline-project-id', project.metadata.id);
    }
  }

  function setConnection(connection) {
    devopsState.connection = connection;
    if (connection && connection.metadata && connection.spec) {
      setInput('source-connection-id', connection.metadata.id);
      setInput('source-connection-name', connection.metadata.name);
      setInput('source-endpoint-origin', connection.spec.endpointOrigin);
      setInput('webhook-secret-ref', connection.spec.webhookSecretRef);
      setInput('fetch-credential-ref', connection.spec.fetchCredentialRef);
      setInput('report-credential-ref', connection.spec.reportCredentialRef);
      setInput('binding-connection-id', connection.metadata.id);
    }
  }

  function setBinding(binding) {
    devopsState.binding = binding;
    if (binding && binding.metadata && binding.spec) {
      setInput('binding-id', binding.metadata.id);
      setInput('binding-name', binding.metadata.name);
      setInput('binding-project-id', binding.projectId);
      setInput('binding-connection-id', binding.spec.sourceConnectionId);
      setInput('external-repository-id', binding.spec.externalRepositoryId);
      setInput('repository-path', binding.spec.repositoryPath);
      setInput('trusted-default-branch', binding.spec.trustedDefaultBranch);
      setInput('pipeline-binding-id', binding.metadata.id);
    }
  }

  function setPipeline(pipeline, revision = null) {
    devopsState.pipeline = pipeline;
    devopsState.revision = revision;
    if (pipeline && pipeline.metadata && pipeline.draft && pipeline.draft.spec) {
      setInput('pipeline-id', pipeline.metadata.id);
      setInput('pipeline-name', pipeline.metadata.name);
      setInput('pipeline-project-id', pipeline.projectId);
      setInput('pipeline-binding-id', pipeline.draft.spec.repositoryBindingId);
    }
  }

  function resetLogState() {
    devopsState.logs = [];
    devopsState.nextLogSequence = 0;
    devopsState.lastLogPage = null;
  }

  function setRun(run) {
    if (!devopsState.run || devopsState.run.id !== run.id) resetLogState();
    devopsState.run = run;
    setInput('run-id', run.id);
  }

  async function runDevOpsAction(progress, success, operation, requiresReady = false) {
    if (devopsBusy) return;
    if (requiresReady && !devopsCanMutate()) {
      setStatus('DevOps 未就绪，变更操作已关闭', 'error');
      return;
    }
    devopsBusy = true;
    renderDevOpsControls();
    setStatus(progress);
    try {
      await operation();
      renderDevOpsState();
      setStatus(typeof success === 'function' ? success() : success, 'ok');
    } catch (error) {
      setStatus(error.message || 'DevOps 操作失败', 'error');
    } finally {
      devopsBusy = false;
      renderDevOpsControls();
    }
  }

  async function loadPipelineRevision(pipeline) {
    if (!pipeline.activeRevision) return null;
    const pipelineID = encodeURIComponent(String(pipeline.metadata.id));
    const revisionID = encodeURIComponent(String(pipeline.activeRevision.id));
    return requireDevOpsKind(
      await apiRequest('/api/devops/v1/pipelines/' + pipelineID + '/revisions/' + revisionID),
      'PipelineRevision'
    );
  }

  async function loadProducts() {
    showView('loading-view');
    setStatus('正在核对签名产品清单…');
    try {
      const result = await apiRequest('/api/platform/v1/installed-products');
      if (!validInventory(result)) throw new Error('产品发现响应不符合已知契约');
      inventory = result;
      platformClockEpoch = new Date(result.observedAt).getTime();
      platformClockMonotonic = performance.now();
      element('release-label').textContent = result.releaseId;
      renderProductNavigation();
      element('product-navigation').hidden = result.products.length === 0;
      if (result.products.length === 0) showView('empty-view');
      else renderRoute();
      setStatus('已核对当前签名发布与产品状态', 'ok');
    } catch (error) {
      if (!credential) return;
      inventory = null;
      element('product-navigation').hidden = true;
      element('empty-detail').textContent = '产品发现服务当前不可用；未显示任何缓存产品。';
      showView('empty-view');
      setStatus(error.message || '无法读取已安装产品', 'error');
    }
  }

  element('login-form').addEventListener('submit', async event => {
    event.preventDefault();
    setStatus('正在建立 IAM 会话…');
    try {
      const body = await apiRequest('/api/iam/v1/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          loginName: element('login-name').value,
          password: element('password').value,
          requestId: token('ui-login-')
        })
      }, false);
      if (typeof body.credential !== 'string' || !body.credential ||
        !body.session || typeof body.session.organizationId !== 'string' || !body.session.organizationId) {
        throw new Error('IAM 会话响应无效');
      }
      credential = body.credential;
      organization = body.session.organizationId;
      element('password').value = '';
      element('organization-name').textContent = organization;
      element('identity').hidden = false;
      renderOperatorCommands();
      await loadProducts();
    } catch (error) {
      if (credential) clearSession(error.message || '登录失败');
      else setStatus(error.message || '登录失败', 'error');
    }
  });

  element('forget-session').addEventListener('click', async () => {
    const currentCredential = credential;
    if (currentCredential) {
      try {
        await apiRequest('/api/iam/v1/auth/logout', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({requestId: token('ui-logout-')})
        });
      } catch (_) { /* local credential removal remains authoritative for the browser */ }
    }
    clearSession();
  });

  element('retry-products').addEventListener('click', loadProducts);
  element('go-home').addEventListener('click', () => {
    if (inventory && inventory.products.length) navigateToProduct(inventory.products[0]);
    else history.pushState({}, '', '/');
  });

  element('workspace-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!activeProduct || activeProduct.state !== 'READY') {
      setStatus('产品未就绪，变更操作已关闭', 'error');
      return;
    }
    setStatus('正在创建应用与配置…');
    try {
      const applicationId = element('application-id').value;
      await platformPost('/api/paas/v1/applications', {
        id: applicationId,
        name: element('application-name').value
      }, 'ui-application-');
      await platformPost('/api/paas/v1/configurations', {
        id: element('configuration-id').value,
        name: element('configuration-name').value,
        applicationId
      }, 'ui-configuration-');
      setStatus('应用与配置已创建', 'ok');
    } catch (error) {
      setStatus(error.message || '创建失败', 'error');
    }
  });

  function parseValues(text) {
    const values = {};
    for (const raw of text.split(/\r?\n/)) {
      if (!raw.trim()) continue;
      const separator = raw.indexOf('=');
      if (separator < 1) throw new Error('每一行都必须使用 KEY=value');
      const key = raw.slice(0, separator).trim();
      if (Object.prototype.hasOwnProperty.call(values, key)) throw new Error('配置键不能重复');
      values[key] = raw.slice(separator + 1);
    }
    return values;
  }

  element('configuration-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!activeProduct || activeProduct.state !== 'READY') {
      setStatus('产品未就绪，变更操作已关闭', 'error');
      return;
    }
    setStatus('正在发布不可变配置修订…');
    try {
      const values = parseValues(element('configuration-values').value);
      const digest = await apiRequest('/ui/v1/configuration-digest', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({values})
      }, false);
      await platformPost('/api/paas/v1/configuration-revisions', {
        id: element('revision-id').value,
        name: element('revision-name').value,
        spec: {
          configurationId: element('configuration-id').value,
          values,
          contentDigest: digest.contentDigest
        }
      }, 'ui-configuration-revision-');
      setStatus('配置修订已发布；部署可显式绑定该修订', 'ok');
    } catch (error) {
      setStatus(error.message || '发布失败', 'error');
    }
  });

  for (const button of element('devops-local-nav').querySelectorAll('button')) {
    button.addEventListener('click', () => {
      history.pushState({}, '', '/devops/' + button.dataset.devopsRoute);
      renderRoute(false);
    });
  }

  for (const id of ['webhook-secret-ref', 'fetch-credential-ref', 'report-credential-ref']) {
    element(id).addEventListener('input', renderOperatorCommands);
  }

  element('devops-project-form').addEventListener('submit', event => {
    event.preventDefault();
    runDevOpsAction('正在创建 DevOps 项目…', 'DevOps 项目已创建', async () => {
      const project = requireDevOpsKind(await platformPost('/api/devops/v1/projects', {
        id: element('devops-project-id').value.trim(),
        name: element('devops-project-name').value.trim()
      }, 'ui-devops-project-'), 'DevOpsProject');
      setProject(project);
    }, true);
  });

  element('load-devops-project').addEventListener('click', () => {
    runDevOpsAction('正在读取 DevOps 项目…', '已读取 DevOps 项目', async () => {
      const project = requireDevOpsKind(
        await apiRequest('/api/devops/v1/projects/' + resourcePathID('devops-project-id')),
        'DevOpsProject'
      );
      setProject(project);
    });
  });

  element('source-connection-form').addEventListener('submit', event => {
    event.preventDefault();
    runDevOpsAction('正在创建 Gitea 连接…', '连接已创建，等待安装运维配置引用并完成观测', async () => {
      const connection = requireDevOpsKind(await platformPost('/api/devops/v1/source-connections', {
        id: element('source-connection-id').value.trim(),
        name: element('source-connection-name').value.trim(),
        spec: {
          adapterId: 'source-adapter-gitea-v1',
          endpointOrigin: element('source-endpoint-origin').value.trim(),
          webhookSecretRef: element('webhook-secret-ref').value.trim(),
          fetchCredentialRef: element('fetch-credential-ref').value.trim(),
          reportCredentialRef: element('report-credential-ref').value.trim()
        }
      }, 'ui-source-connection-'), 'SourceConnection');
      setConnection(connection);
    }, true);
  });

  element('load-source-connection').addEventListener('click', () => {
    runDevOpsAction('正在读取连接状态…', '已读取最新连接观测', async () => {
      setConnection(requireDevOpsKind(
        await apiRequest('/api/devops/v1/source-connections/' + resourcePathID('source-connection-id')),
        'SourceConnection'
      ));
    });
  });

  element('recheck-source-connection').addEventListener('click', () => {
    runDevOpsAction('正在安排连接 Recheck…', 'Recheck 已安排；当前健康状态仍由 observer 独立证明', async () => {
      const connection = devopsState.connection;
      setConnection(requireDevOpsKind(await guardedCommand(
        '/api/devops/v1/source-connections/' + encodeURIComponent(String(connection.metadata.id)) + '/recheck',
        resourceVersionOf(connection),
        'ui-source-connection-recheck-'
      ), 'SourceConnection'));
    }, true);
  });

  element('repository-binding-form').addEventListener('submit', event => {
    event.preventDefault();
    runDevOpsAction('正在创建仓库绑定…', '仓库绑定已创建，等待可信身份观测', async () => {
      const binding = requireDevOpsKind(await platformPost('/api/devops/v1/repository-bindings', {
        id: element('binding-id').value.trim(),
        name: element('binding-name').value.trim(),
        projectId: element('binding-project-id').value.trim(),
        spec: {
          sourceConnectionId: element('binding-connection-id').value.trim(),
          externalRepositoryId: element('external-repository-id').value.trim(),
          repositoryPath: element('repository-path').value.trim(),
          trustedDefaultBranch: element('trusted-default-branch').value.trim()
        }
      }, 'ui-repository-binding-'), 'RepositoryBinding');
      setBinding(binding);
    }, true);
  });

  element('load-repository-binding').addEventListener('click', () => {
    runDevOpsAction('正在读取仓库绑定…', '已读取最新仓库观测', async () => {
      setBinding(requireDevOpsKind(
        await apiRequest('/api/devops/v1/repository-bindings/' + resourcePathID('binding-id')),
        'RepositoryBinding'
      ));
    });
  });

  element('recheck-repository-binding').addEventListener('click', () => {
    runDevOpsAction('正在安排仓库 Recheck…', 'Recheck 已安排；浏览器未修改任何健康字段', async () => {
      const binding = devopsState.binding;
      setBinding(requireDevOpsKind(await guardedCommand(
        '/api/devops/v1/repository-bindings/' + encodeURIComponent(String(binding.metadata.id)) + '/recheck',
        resourceVersionOf(binding),
        'ui-repository-binding-recheck-'
      ), 'RepositoryBinding'));
    }, true);
  });

  element('pipeline-form').addEventListener('submit', event => {
    event.preventDefault();
    runDevOpsAction('正在创建流水线草稿…', '流水线草稿已创建；激活后才可接受变更事件', async () => {
      const pipeline = requireDevOpsKind(await platformPost('/api/devops/v1/pipelines', {
        id: element('pipeline-id').value.trim(),
        name: element('pipeline-name').value.trim(),
        projectId: element('pipeline-project-id').value.trim(),
        draft: {
          repositoryBindingId: element('pipeline-binding-id').value.trim(),
          triggerPolicy: 'CHANGE',
          verificationProfile: 'GO_1_26_OFFLINE_V1',
          dependencyEgress: 'NONE',
          reporterPolicy: 'CHANGE_CHECK_V1'
        }
      }, 'ui-pipeline-'), 'Pipeline');
      setPipeline(pipeline);
    }, true);
  });

  element('load-pipeline').addEventListener('click', () => {
    runDevOpsAction('正在读取流水线…', '已读取流水线及当前不可变修订', async () => {
      const pipeline = requireDevOpsKind(
        await apiRequest('/api/devops/v1/pipelines/' + resourcePathID('pipeline-id')),
        'Pipeline'
      );
      const revision = await loadPipelineRevision(pipeline);
      setPipeline(pipeline, revision);
    });
  });

  element('activate-pipeline').addEventListener('click', () => {
    runDevOpsAction('正在激活不可变修订…', '流水线修订已激活，可以接受可信变更事件', async () => {
      const pipeline = devopsState.pipeline;
      const activation = requireDevOpsKind(await guardedCommand(
        '/api/devops/v1/pipelines/' + encodeURIComponent(String(pipeline.metadata.id)) + '/activate',
        resourceVersionOf(pipeline),
        'ui-pipeline-activate-'
      ), 'PipelineActivation');
      setPipeline(activation.pipeline, activation.revision);
    }, true);
  });

  element('run-lookup-form').addEventListener('submit', event => {
    event.preventDefault();
    runDevOpsAction('正在读取 PipelineRun…', '已读取当前运行证据', async () => {
      setRun(requireDevOpsKind(
        await apiRequest('/api/devops/v1/runs/' + resourcePathID('run-id')),
        'PipelineRun'
      ));
    });
  });

  element('refresh-run').addEventListener('click', () => {
    runDevOpsAction('正在刷新 PipelineRun…', '运行状态已刷新', async () => {
      const run = devopsState.run;
      setRun(requireDevOpsKind(
        await apiRequest('/api/devops/v1/runs/' + encodeURIComponent(String(run.id))),
        'PipelineRun'
      ));
    });
  });

  element('cancel-run').addEventListener('click', () => {
    runDevOpsAction('正在请求取消运行…', '取消意图已持久化；存在外部效果时平台会先完成核对', async () => {
      const run = devopsState.run;
      setRun(requireDevOpsKind(await guardedCommand(
        '/api/devops/v1/runs/' + encodeURIComponent(String(run.id)) + '/cancel',
        resourceVersionOf(run),
        'ui-run-cancel-'
      ), 'PipelineRun'));
    }, true);
  });

  element('replay-run').addEventListener('click', () => {
    runDevOpsAction('正在创建手动重跑…', () => '已创建新运行 ' + devopsState.run.id, async () => {
      const run = devopsState.run;
      setRun(requireDevOpsKind(await guardedCommand(
        '/api/devops/v1/runs/' + encodeURIComponent(String(run.id)) + '/replay',
        resourceVersionOf(run),
        'ui-run-replay-'
      ), 'PipelineRun'));
    }, true);
  });

  element('load-run-logs').addEventListener('click', () => {
    runDevOpsAction('正在读取规范化日志…', '日志证据已更新', async () => {
      const run = devopsState.run;
      const page = requireDevOpsKind(await apiRequest(
        '/api/devops/v1/runs/' + encodeURIComponent(String(run.id)) +
        '/logs?afterSequence=' + devopsState.nextLogSequence
      ), 'PipelineRunLogPage');
      if (!Array.isArray(page.chunks) || !Number.isSafeInteger(page.nextSequence)) {
        throw new Error('日志响应不符合当前 UI 契约');
      }
      const seen = new Set(devopsState.logs.map(chunk => chunk.sequence));
      for (const chunk of page.chunks) {
        if (Number.isSafeInteger(chunk.sequence) && !seen.has(chunk.sequence)) {
          devopsState.logs.push(chunk);
          seen.add(chunk.sequence);
        }
      }
      devopsState.logs.sort((left, right) => left.sequence - right.sequence);
      devopsState.nextLogSequence = page.nextSequence;
      devopsState.lastLogPage = page;
    });
  });

  element('clear-run-logs').addEventListener('click', () => {
    resetLogState();
    renderLogs();
    renderDevOpsControls();
    setStatus('页面内日志已清空；服务端保留策略未改变', 'ok');
  });

  window.addEventListener('popstate', () => renderRoute());
  window.setInterval(() => {
    if (activeProduct && activeProduct.id === 'DEVOPS') {
      renderConnectionSummary();
      renderBindingSummary();
      renderPipelineSummary();
    }
  }, 30000);

  renderDevOpsState();
  if (requestedRoute() && !['paas', 'devops'].includes(requestedRoute())) {
    element('login-title').textContent = '登录后验证这个产品地址。';
  }
})();
