// Isolated browser profiles and intercepted APIs only. No real account operations.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const site = process.env.UI_BASE_URL || 'http://127.0.0.1:8790/';

async function mock(context, local = true) {
  let pool = [], version = '', revision = 0, release = false, maximum = 0, uploads = 0, testCalls = 0;
  let testHeld = true, completeTest;
  const calls = [], jobs = new Map(), errors = [], assignments = [];
  const snapshot = () => ({ version, count: pool.length, entries: pool.map(p => ({ id: p.id, endpoint: p.endpoint })) });
  context.on('page', page => page.on('pageerror', error => errors.push(error.message)));
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname, method = req.method();
    if (path === '/api/capabilities') return route.fulfill({ json: { enabled: true, mode: 'live', available: true, max_concurrent: 10, max_batch: 50,
      routing: { allow_direct: local, default_mode: local ? 'direct' : 'pool', max_proxies: 50 } } });
    if (path === '/api/session') return route.fulfill({ json: { csrf: 'test-csrf' } });
    if (path === '/api/job-slots') return route.fulfill({ json: { status: 'ready', token: 'fixture-slot' } });
    if (path.startsWith('/api/job-slots/')) return route.fulfill({ json: { ok: true } });
    if (path === '/api/proxy-pool/test') {
      testCalls++;
      assert.equal(method, 'POST');
      assert(req.postDataJSON().proxies.length > 0);
      if (testHeld) await new Promise(resolve => { completeTest = resolve; });
      const result = testCalls === 1
        ? { ok: true, country: 'SG', ip: '203.0.113.7', latency_ms: 1234, selected: 2 }
        : { ok: false, code: 'proxy_test_timeout', message: '连接超时', selected: 1 };
      return route.fulfill({ json: result });
    }
    if (path === '/api/proxy-pool') {
      if (method === 'PUT') {
        uploads++; version = `pool-version-${++revision}`;
        pool = req.postDataJSON().proxies.map((_, i) => ({ id: String(i + 1), endpoint: 'socks5://gateway.example:3010', active: 0 }));
      }
      if (method === 'DELETE') { pool = []; version = ''; }
      return route.fulfill({ json: snapshot() });
    }
    if (path === '/api/jobs' && method === 'POST') {
      const body = req.postDataJSON();
      let selected;
      if (body.network_mode === 'pool') {
        assert.equal(body.proxy_pool_version, version);
        const unused = pool.filter(p => p.active === 0), choices = unused.length ? unused : pool;
        selected = choices[Math.floor(Math.random() * choices.length)];
        selected.active++;
        assignments.push(selected.id);
      } else assert(local && body.network_mode === 'direct');
      const id = `proxy-fixture-${jobs.size + 1}`;
      jobs.set(id, { id, body, proxy: selected, received: false, secret: false, done: false, events: [{ type: 'stage', stage: 'authenticating', state: 'unchanged', seq: 1 }] });
      maximum = Math.max(maximum, [...jobs.values()].filter(j => !j.done && j.proxy).length);
      calls.push(body);
      return route.fulfill({ json: { id } });
    }
    if (path === '/api/job-events') {
      const result = {};
      for (const [id, cursor] of Object.entries(req.postDataJSON().cursors)) {
        const job = jobs.get(id);
        if (release && !job.done) {
          if (!job.secret) {
            job.secret = true;
            job.events.push({ seq: job.events.length + 1, type: 'secret', stage: 'awaiting_receipt', state: 'enrollment_pending', new_secret: 'JBSWY3DPEHPK3PXP', factor_id: `factor-${id}`, receipt: 'fixture-receipt-1234567890123456' });
          } else if (job.received) {
            job.done = true;
            if (job.proxy) job.proxy.active--;
            job.events.push({ seq: job.events.length + 1, type: 'done', stage: 'complete', state: 'verified', code: 'verified', outcome: 'success' });
          }
        }
        result[id] = { events: job.events.slice(cursor), done: job.done };
      }
      return route.fulfill({ json: { jobs: result } });
    }
    const receipt = path.match(/^\/api\/jobs\/([^/]+)\/receipt$/);
    if (receipt) { jobs.get(receipt[1]).received = true; return route.fulfill({ json: { ok: true } }); }
    if (method === 'DELETE' && path.startsWith('/api/jobs/')) return route.fulfill({ json: { ok: true } });
    errors.push(`Unexpected mock API ${method} ${path}`);
    return route.fulfill({ status: 418, json: { code: 'unexpected' } });
  });
  return { calls, assignments, errors, release: () => { release = true; },
    releaseTest: () => { testHeld = false; completeTest?.(); }, get testCalls() { return testCalls; },
    get maximum() { return maximum; }, get uploads() { return uploads; } };
}

async function storage(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const request = indexedDB.open('keyshift-local-proxy-pool-v1', 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result, tx = db.transaction(['settings', 'keys'], 'readonly');
      const record = tx.objectStore('settings').get('pool'), key = tx.objectStore('keys').get('aes');
      tx.oncomplete = () => { db.close(); resolve({ exists: Boolean(record.result), cipher: record.result?.encrypted instanceof ArrayBuffer,
        iv: record.result?.iv instanceof Uint8Array, extractable: key.result?.extractable,
        raw: JSON.stringify(record.result), preferences: JSON.stringify(localStorage) }); };
    };
  }));
}

async function savedInput(page, value) {
  // Verify actual encrypted persistence without requiring product status text.
  await page.waitForFunction(expected => new Promise(resolve => {
    const request = indexedDB.open('keyshift-local-proxy-pool-v1', 1);
    request.onerror = () => resolve(false);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(['settings', 'keys'], 'readonly');
      const record = tx.objectStore('settings').get('pool'), key = tx.objectStore('keys').get('aes');
      tx.oncomplete = async () => {
        db.close();
        if (!record.result || !key.result) return resolve(false);
        try {
          const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.result.iv }, key.result, record.result.encrypted);
          resolve(JSON.parse(new TextDecoder().decode(plaintext)) === expected);
        } catch { resolve(false); }
      };
      tx.onerror = () => { db.close(); resolve(false); };
    };
  }), value);
}

async function main() {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_EXECUTABLE, headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const server = await mock(context), page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.goto(site);
    const poolCard = page.locator('.proxy-card');
    await page.getByRole('switch', { name: '本机直连', exact: true }).waitFor();
    const proxyPlaceholder = await page.getByLabel('代理地址', { exact: true }).getAttribute('placeholder');
    for (const prefix of ['socks5://', 'socks5h://', 'http://', 'https://']) assert(proxyPlaceholder.includes(prefix));
    assert(proxyPlaceholder.includes('默认 SOCKS5'));
    assert.equal(await poolCard.getByText(/自动保存|默认 SOCKS5/).count(), 0, 'Format hints belong inside the input only');
    await poolCard.screenshot({ path: 'output/playwright/proxy-placeholder-light.png', animations: 'disabled' });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await poolCard.screenshot({ path: 'output/playwright/proxy-placeholder-mobile-dark.png', animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    assert.equal(await page.getByRole('switch', { name: '本机直连', exact: true }).isChecked(), true);
    assert.equal(await page.locator('.snow-layer').count(), 0);
    await page.getByRole('switch', { name: '轻雪', exact: true }).focus();
    await page.keyboard.press('Space');
    await page.waitForFunction(() => document.querySelectorAll('.snow-flake').length === 36);
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(await page.locator('.snow-flake').evaluateAll(nodes => nodes.filter(n => getComputedStyle(n).display !== 'none').length), 16);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.waitForFunction(() => !document.querySelector('.snow-layer'));
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.waitForFunction(() => Boolean(document.querySelector('.snow-layer')));
    await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
    await page.waitForFunction(() => getComputedStyle(document.querySelector('.snow-flake')).animationPlayState === 'paused');
    await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); });
    await page.getByRole('switch', { name: '轻雪', exact: true }).click();
    await page.getByRole('switch', { name: '本机直连', exact: true }).click();
    assert.equal(await page.getByRole('button', { name: '开始更换', exact: true }).isDisabled(), true);
    await page.getByLabel('代理地址', { exact: true }).fill('gateway.example:3010:partial');
    await savedInput(page, 'gateway.example:3010:partial');
    await page.reload();
    await page.waitForFunction(() => document.querySelector('#proxy-lines')?.value === 'gateway.example:3010:partial');
    const fixtures = [1, 2, 3].map(i => `gateway.example:3010:session-${i}:CANARY_PROXY_${i}`).join('\n');
    await page.getByLabel('代理地址', { exact: true }).fill('gateway.example:3010:transient:CANARY_OLD');
    await page.getByLabel('代理地址', { exact: true }).fill(fixtures);
    await savedInput(page, fixtures);
    await poolCard.getByText('3 条有效', { exact: true }).waitFor();
    assert.equal(await poolCard.getByRole('button', { name: /保存|检测|编辑/ }).count(), 0);
    assert.equal(await page.getByLabel('代理地址', { exact: true }).inputValue(), fixtures);
    assert.equal(server.uploads, 0, 'Paste and automatic save must not contact proxy APIs');
    assert.equal(server.testCalls, 0, 'Paste must not start a connectivity test');
    // The explicit test always targets the pool, even when local direct mode is on.
    await page.getByRole('switch', { name: '本机直连', exact: true }).click();
    await page.getByRole('button', { name: '随机测试', exact: true }).evaluate(button => { button.click(); button.click(); });
    await page.getByRole('button', { name: '测试中…', exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: '测试中…', exact: true }).isDisabled(), true);
    assert.equal(await page.getByLabel('代理地址', { exact: true }).isDisabled(), true);
    assert.equal(server.testCalls, 1);
    server.releaseTest();
    await page.getByLabel('代理随机测试结果', { exact: true }).getByText('第 2 条代理 · SG · 203.0.113.7 · 1234 ms', { exact: true }).waitFor();
    await poolCard.screenshot({ path: 'output/playwright/proxy-test-success-mobile-light.png', animations: 'disabled' });
    assert.equal(server.calls.length, 0, 'A test must not create account jobs');
    assert.equal(server.uploads, 0, 'A test must not replace the account-task pool');
    await page.getByRole('switch', { name: '本机直连', exact: true }).click();
    await page.getByRole('button', { name: '随机测试', exact: true }).click();
    await page.getByLabel('代理随机测试结果', { exact: true }).getByText('第 1 条代理 · 测试失败 · 连接超时', { exact: true }).waitFor();
    assert.equal(server.testCalls, 2);
    const encrypted = await storage(page);
    assert(encrypted.cipher && encrypted.iv && encrypted.extractable === false);
    assert(!encrypted.raw.includes('CANARY_PROXY') && !encrypted.preferences.includes('CANARY_PROXY'));
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await poolCard.evaluate(el => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: 'output/playwright/proxy-pool-mobile-dark.png', animations: 'disabled' });
    await poolCard.screenshot({ path: 'output/playwright/proxy-test-mobile-dark.png', animations: 'disabled' });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await poolCard.screenshot({ path: 'output/playwright/proxy-test-light.png', animations: 'disabled' });
    await page.getByRole('tab', { name: '批量导入', exact: true }).click();
    await page.getByLabel('批量账号', { exact: true }).fill(Array.from({ length: 12 }, (_, i) => `proxy-task-${i}@example.com---fake-password---JBSWY3DPEHPK3PXP`).join('\n'));
    await page.getByRole('checkbox', { name: '我拥有这些账号或已获得操作授权', exact: true }).check();
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('button', { name: '确认并开始', exact: true }).click();
    await page.waitForFunction(() => [...document.querySelectorAll('[role="progressbar"]')].filter(n => n.getAttribute('aria-valuenow') === '10').length === 10);
    assert.equal(server.calls.length, 10);
    assert.equal(new Set(server.assignments.slice(0, 3)).size, 3, 'Use distinct entries before reusing');
    assert.equal(await page.getByRole('switch', { name: '本机直连', exact: true }).isDisabled(), true);
    assert.equal(await page.getByLabel('代理地址', { exact: true }).isDisabled(), true);
    assert.equal(await page.getByRole('button', { name: '随机测试', exact: true }).isDisabled(), true);
    await page.getByRole('switch', { name: '轻雪', exact: true }).click();
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: 'output/playwright/proxy-pool-desktop-light.png', animations: 'disabled' });
    await page.getByRole('navigation', { name: '任务分页', exact: true }).getByRole('button', { name: '下一页', exact: true }).click();
    await page.getByRole('button', { name: '取消 proxy-task-11@example.com', exact: true }).click();
    server.release();
    await page.getByText('11 成功 · 0 失败 · 1 取消', { exact: true }).waitFor();
    assert.equal(server.maximum, 10);
    assert.equal(server.calls.length, 11, 'Cancelled queued task must not submit a job');
    assert(server.calls.every(call => call.network_mode === 'pool' && call.proxy_pool_version && !JSON.stringify(call).includes('CANARY_PROXY')));
    await page.reload();
    await page.waitForFunction(value => document.querySelector('#proxy-lines')?.value === value, fixtures);
    assert.equal(await page.getByRole('switch', { name: '本机直连', exact: true }).isChecked(), false);
    assert.equal(await page.getByRole('switch', { name: '轻雪', exact: true }).isChecked(), true);
    assert.equal(server.uploads, 1, 'Reload restores input without uploading or detecting');
    assert.equal(server.testCalls, 2, 'Reload must not repeat the connectivity test');
    assert.equal(await page.getByLabel('代理随机测试结果', { exact: true }).count(), 0);
    const uploadsBeforeUnlock = server.uploads;
    await page.evaluate(() => window.dispatchEvent(new Event('mfa-session-expired')));
    await page.getByLabel('服务访问口令', { exact: true }).fill('fixture-access');
    await page.getByRole('button', { name: '解锁', exact: true }).click();
    await page.getByRole('button', { name: '开始更换', exact: true }).waitFor();
    assert.equal(server.uploads, uploadsBeforeUnlock, 'Unlock alone must not upload or detect');
    await page.getByLabel('账号凭证', { exact: true }).fill('next@example.com---fake-password---JBSWY3DPEHPK3PXP');
    await page.getByRole('checkbox', { name: '我拥有这些账号或已获得操作授权', exact: true }).check();
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('button', { name: '返回检查', exact: true }).click();
    assert.equal(server.uploads, uploadsBeforeUnlock + 1, 'The new session receives the pool only when a task is prepared');
    const other = await browser.newContext({ viewport: { width: 375, height: 812 } });
    const production = await mock(other, false), productionPage = await other.newPage();
    await productionPage.goto(site);
    await productionPage.getByLabel('代理地址', { exact: true }).waitFor();
    assert.equal(await productionPage.getByRole('switch', { name: '本机直连', exact: true }).count(), 0);
    assert.equal(await productionPage.getByRole('button', { name: '开始更换', exact: true }).isDisabled(), true);
    assert.equal(production.uploads, 0, 'Another profile must not restore the first profile pool');
    assert.equal(await productionPage.getByRole('switch', { name: '轻雪', exact: true }).isChecked(), false);
    assert.equal((await storage(page)).exists, true, 'Original profile still holds its encrypted pool');
    // Old versions stored an encrypted normalized list; restore it into the editable field.
    await productionPage.evaluate(async () => {
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
        new TextEncoder().encode(JSON.stringify(['socks5://legacy:CANARY_LEGACY@gateway.example:3010'])));
      await new Promise((resolve, reject) => {
        const request = indexedDB.open('keyshift-local-proxy-pool-v1', 1);
        request.onsuccess = () => {
          const db = request.result, tx = db.transaction(['settings', 'keys'], 'readwrite');
          tx.objectStore('settings').put({ iv, encrypted }, 'pool'); tx.objectStore('keys').put(key, 'aes');
          tx.oncomplete = () => { db.close(); resolve(); }; tx.onerror = () => reject(tx.error);
        };
      });
    });
    await productionPage.reload();
    await productionPage.waitForFunction(() => document.querySelector('#proxy-lines')?.value === 'socks5://legacy:CANARY_LEGACY@gateway.example:3010');
    assert.equal(production.uploads, 0, 'Restoring a legacy pool must not upload or probe it');
    await other.close();
    await page.getByRole('button', { name: '清空结果', exact: true }).click();
    await page.getByRole('button', { name: '确认清空', exact: true }).click();
    await page.locator('.saved-card').waitFor({ state: 'detached' });
    assert.equal((await storage(page)).exists, true, 'Clearing results preserves the separate proxy vault');
    await page.getByRole('button', { name: '清空代理池', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: '取消', exact: true }).click();
    assert.equal((await storage(page)).exists, true);
    await page.getByRole('button', { name: '清空代理池', exact: true }).click();
    await page.getByRole('button', { name: '确认清空', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('.proxy-card .count')?.textContent === '0');
    assert.equal((await storage(page)).exists, false);
    await page.reload();
    await page.getByLabel('代理地址', { exact: true }).waitFor();
    assert.equal((await page.getByLabel('代理地址', { exact: true }).inputValue()), '');
    assert.deepEqual(server.errors, []); assert.deepEqual(production.errors, []);
    await context.close();
    console.log(JSON.stringify({ passed: true, proxyMaximum: server.maximum, encryptedBrowserPool: true, reloadRestoresPool: true,
      independentProfileAndProductionPolicy: true, resultClearPreservesPool: true, confirmedProxyClear: true,
      manualRandomProxyTest: true, duplicateTestClickIgnored: true, countryIpAndLatencyShown: true,
      noAutomaticConnectivityChecks: true, pasteAutosavedWithoutUpload: true, incompleteDraftRestored: true, unusedProxiesBeforeReuse: true,
      legacyEncryptedPoolRestored: true,
      snow: { desktop: 36, mobile: 16, reducedMotion: true, hiddenPaused: true }, realAccountRequests: 0 }));
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
