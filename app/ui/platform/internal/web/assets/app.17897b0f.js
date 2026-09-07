(() => {
  'use strict';

  const installationAPIVersion = 'installation.matrix.xiak.com/v1';
  const productCatalog = Object.freeze({
    APPLICATION_PAAS: Object.freeze({route: 'paas', label: 'Application PaaS', short: 'AP', view: 'paas-view'}),
    DEVOPS: Object.freeze({route: 'devops', label: 'DevOps', short: 'DO', view: 'unsupported-view'})
  });
  const productStates = new Set(['READY', 'DEGRADED', 'UNAVAILABLE']);
  const productReasons = new Set(['', 'DEPENDENCY_UNAVAILABLE', 'OBSERVATION_STALE']);
  const productViews = ['login-view', 'loading-view', 'empty-view', 'paas-view', 'unsupported-view', 'route-not-found-view'];

  let credential = '';
  let organization = '';
  let inventory = null;
  let activeProduct = null;

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

  function showView(id, focus = true) {
    for (const view of productViews) element(view).hidden = view !== id;
    if (focus) element('workspace').focus({preventScroll: true});
  }

  function safeErrorMessage(response, body) {
    if (response.status === 401) return '会话已失效，请重新登录';
    if (response.status === 403) return '当前身份没有执行此操作的权限';
    if (response.status === 409) return '资源状态已变化，请刷新后重试';
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

  function clearSession(message = '会话已从页面内存清除') {
    credential = '';
    organization = '';
    inventory = null;
    activeProduct = null;
    element('identity').hidden = true;
    element('product-navigation').hidden = true;
    element('product-list').replaceChildren();
    element('password').value = '';
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

  function navigateToProduct(product, replace = false) {
    const declared = productCatalog[product.id];
    const target = '/' + declared.route + (declared.route === 'paas' ? '/configuration' : '');
    history[replace ? 'replaceState' : 'pushState']({}, '', target);
    renderRoute();
  }

  function renderRoute() {
    if (!credential || !inventory) return;
    const route = requestedRoute();
    if (!route) {
      if (inventory.products.length) navigateToProduct(inventory.products[0], true);
      else showView('empty-view');
      return;
    }
    const product = inventory.products.find(item => productCatalog[item.id].route === route);
    const normalizedPath = location.pathname.replace(/\/+$/, '') || '/';
    const knownPath = product && (
      (product.id === 'APPLICATION_PAAS' && (normalizedPath === '/paas' || normalizedPath === '/paas/configuration')) ||
      (product.id === 'DEVOPS' && normalizedPath === '/devops')
    );
    if (!knownPath) {
      activeProduct = null;
      updateActiveButton('');
      showView('route-not-found-view');
      return;
    }
    activeProduct = product;
    updateActiveButton(product.id);
    if (product.id === 'APPLICATION_PAAS') renderPaaS(product);
    else showView(productCatalog[product.id].view);
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

  function renderPaaS(product) {
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
    for (const control of document.querySelectorAll('.mutation-control')) {
      control.disabled = product.state !== 'READY';
    }
    showView('paas-view');
  }

  async function loadProducts() {
    showView('loading-view');
    setStatus('正在核对签名产品清单…');
    try {
      const result = await apiRequest('/api/platform/v1/installed-products');
      if (!validInventory(result)) throw new Error('产品发现响应不符合已知契约');
      inventory = result;
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

  window.addEventListener('popstate', renderRoute);
  if (requestedRoute() && !['paas', 'devops'].includes(requestedRoute())) {
    element('login-title').textContent = '登录后验证这个产品地址。';
  }
})();
