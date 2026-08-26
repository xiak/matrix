(() => {
  'use strict';
  let credential = '';
  const element = id => document.getElementById(id);
  const status = element('status');
  const statusBox = status.parentElement;

  function token(prefix) {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return prefix + Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
  }

  function setStatus(message, state = '') {
    status.textContent = message.slice(0, 240);
    statusBox.className = 'status' + (state ? ' ' + state : '');
  }

  async function responseBody(response) {
    let body = {};
    try { body = await response.json(); } catch (_) { /* normalized below */ }
    if (!response.ok) {
      const message = typeof body.detail === 'string' ? body.detail :
        (typeof body.title === 'string' ? body.title : '请求未被平台接受');
      throw new Error(message);
    }
    return body;
  }

  async function platformPost(path, body, keyPrefix) {
    if (!credential) throw new Error('请先登录');
    const response = await fetch(path, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + credential,
        'Content-Type': 'application/json',
        'Idempotency-Key': token(keyPrefix)
      },
      body: JSON.stringify(body)
    });
    return responseBody(response);
  }

  element('login-form').addEventListener('submit', async event => {
    event.preventDefault();
    setStatus('正在建立 IAM 会话…');
    try {
      const response = await fetch('/api/iam/v1/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          loginName: element('login-name').value,
          password: element('password').value,
          requestId: token('ui-login-')
        })
      });
      const body = await responseBody(response);
      if (typeof body.credential !== 'string' || !body.credential) throw new Error('IAM 会话响应无效');
      credential = body.credential;
      element('password').value = '';
      element('configuration-panel').classList.remove('locked');
      element('forget-session').disabled = false;
      setStatus('已登录；会话仅保留在当前页面内存中', 'ok');
    } catch (error) {
      credential = '';
      setStatus(error.message || '登录失败', 'error');
    }
  });

  element('forget-session').addEventListener('click', () => {
    credential = '';
    element('configuration-panel').classList.add('locked');
    element('forget-session').disabled = true;
    setStatus('会话已从页面内存清除');
  });

  element('create-workspace').addEventListener('click', async () => {
    setStatus('正在创建应用与配置…');
    try {
      const applicationId = element('application-id').value;
      await platformPost('/api/paas/v1/applications', {
        id: applicationId, name: element('application-name').value
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
    setStatus('正在发布不可变配置修订…');
    try {
      const values = parseValues(element('configuration-values').value);
      const digestResponse = await fetch('/ui/v1/configuration-digest', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({values})
      });
      const digest = await responseBody(digestResponse);
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
})();
