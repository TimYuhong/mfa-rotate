// Run with PLAYWRIGHT_MODULE pointing to an existing Playwright package.
// All account APIs are intercepted; only static assets reach the local server.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');

async function main() {
  const site = process.env.UI_BASE_URL || 'http://127.0.0.1:8790/';
  const browser = await chromium.launch({ executablePath: process.env.CHROME_EXECUTABLE, headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(12000);
  const jobs = new Map(), attempts = new Map(), calls = [], pollWidths = [], errors = [];
  let release = false, maximum = 0, cancelCalls = 0, loseRetryResponse = true, releaseBulk = false;
  const operationLookups = [];
  const secret = 'KRUGS4ZANFZSAYJAORSXG5BAONSWG4TF';
  const dismissNotice = async () => {
    await page.locator('[data-feedback-dialog]').waitFor();
    await page.getByRole('button', { name: '关闭提示', exact: true }).click();
    await page.locator('[data-feedback-dialog]').waitFor({ state: 'detached' });
  };
  const choosePageSize = async (label, value) => {
    await page.getByRole('button', { name: label, exact: true }).click();
    await page.getByRole('menuitemradio', { name: `${value} 条`, exact: true }).click();
    await page.getByRole('menu').waitFor({ state: 'detached' });
  };
  const assertCounts = async expected => {
    await page.waitForFunction(values => Object.entries(values).every(([category, value]) =>
      document.querySelector(`[data-task-filter="${category}"] .filter-count`)?.textContent === String(value)), expected);
    assert.equal(expected.all, Object.entries(expected).filter(([category]) => category !== 'all').reduce((sum, [, value]) => sum + value, 0));
    const labels = { all: '全部', running: '进行中', queued: '队列中', success: '成功', failed: '失败', cancelled: '取消' };
    for (const [category, value] of Object.entries(expected)) {
      assert.equal(await page.locator(`[data-task-filter="${category}"]`).getAttribute('aria-label'), `${labels[category]}，${value} 个任务`);
    }
  };
  const emit = (job, event) => {
    job.events.push({ ...event, seq: job.events.length + 1 });
    if (event.type === 'done') job.done = true;
  };
  const finish = (job, state, code, outcome) => emit(job, {
    type: 'done', stage: state === 'verified' ? 'complete' : 'stopped', state, code, outcome,
    message: code === 'login_failed' ? '测试登录失败' : '',
  });
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method();
    if (path === '/api/capabilities') return route.fulfill({ json: { enabled: true, mode: 'live', available: true, max_concurrent: 10, max_batch: 50,
      routing: { allow_direct: true, default_mode: 'direct', max_proxies: 50 } } });
    if (path === '/api/session') return route.fulfill({ json: { csrf: 'test-csrf' } });
    if (path === '/api/job-slots') return route.fulfill({ json: { status: 'ready', token: 'fixture-slot' } });
    if (path.startsWith('/api/job-slots/')) return route.fulfill({ json: { ok: true } });
    if ((path === '/api/jobs' || path.endsWith('/retry')) && method === 'POST') {
      const payload = request.postDataJSON();
      if ([...jobs.values()].filter(job => !job.done).length >= 10) return route.fulfill({ status: 409, json: { code: 'busy', message: 'busy' } });
      const attempt = (attempts.get(payload.email) || 0) + 1;
      attempts.set(payload.email, attempt);
      const id = `test-job-${jobs.size + 1}`;
      const job = { id, payload, attempt, events: [], done: false, received: false };
      jobs.set(id, job);
      calls.push({ path, email: payload.email, action: payload.action });
      maximum = Math.max(maximum, [...jobs.values()].filter(job => !job.done).length);
      emit(job, { type: 'stage', stage: 'authenticating', state: payload.action === 'verify' ? 'activation_unknown' : 'unchanged' });
      if (payload.email === 'fixture-0@example.com' && attempt === 2 && loseRetryResponse) {
        loseRetryResponse = false;
        return route.abort('failed');
      }
      return route.fulfill({ json: { id } });
    }
    if (path.startsWith('/api/operations/')) {
      const operation = path.split('/').at(-1);
      operationLookups.push(operation);
      const job = [...jobs.values()].find(job => job.payload.operation_id === operation);
      return route.fulfill({ status: job ? 200 : 404, json: job ? { id: job.id } : { code: 'job_not_found' } });
    }
    if (path === '/api/job-events') {
      const { cursors } = request.postDataJSON(), result = {};
      pollWidths.push(Object.keys(cursors).length);
      for (const [id, cursor] of Object.entries(cursors)) {
        const job = jobs.get(id);
        if (!job) { result[id] = { error: 'job_not_found' }; continue; }
        if (!job.done && release) {
          const index = Number(job.payload.email.match(/fixture-(\d+)/)?.[1]);
          const isBulk = job.payload.email.startsWith('bulk-fixture-');
          if (isBulk && index === 2 && job.attempt === 1) {
            emit(job, { type: 'stage', stage: 'removing', state: 'removal_unknown' });
            finish(job, 'removal_unknown', 'network_error', 'failed');
          }
          else if (isBulk && index > 2 && !releaseBulk) { /* Hold capacity for queue/retry assertions. */ }
          else if (job.payload.action === 'verify') finish(job, 'verified', 'verified', 'success');
          else if (index === 0 && job.attempt === 1) finish(job, 'unchanged', 'login_failed', 'failed');
          else if (!job.events.some(event => event.type === 'secret')) emit(job, {
            type: 'secret', stage: 'awaiting_receipt', state: 'enrollment_pending', new_secret: secret,
            factor_id: `factor-${id}`, receipt: 'fixture-receipt-1234567890123456',
          });
          else if (job.received) {
            emit(job, { type: 'stage', stage: 'verifying', state: 'enabled_unverified' });
            if (index === 1 && job.attempt === 1) finish(job, 'enabled_unverified', 'login_failed', 'failed');
            else finish(job, 'verified', 'verified', 'success');
          }
        }
        result[id] = { events: job.events.slice(cursor), done: job.done };
      }
      return route.fulfill({ json: { jobs: result } });
    }
    const match = path.match(/^\/api\/jobs\/([^/]+)(?:\/(receipt|cancel))?$/);
    if (match) {
      const job = jobs.get(match[1]);
      if (match[2] === 'receipt') { job.received = true; return route.fulfill({ json: { ok: true } }); }
      if (match[2] === 'cancel') {
        cancelCalls++; finish(job, 'unchanged', 'cancelled', 'cancelled');
        return route.fulfill({ json: { deferred: false, done: false } });
      }
      if (method === 'DELETE') return route.fulfill({ json: { ok: true } });
    }
    errors.push(`Unexpected API: ${method} ${path}`);
    return route.fulfill({ status: 418, json: { code: 'unexpected', message: 'unexpected test call' } });
  });
  try {
    await page.goto(site);
    await assertCounts({ all: 0, running: 0, queued: 0, success: 0, failed: 0, cancelled: 0 });
    const sizeTrigger = page.getByRole('button', { name: '任务每页条数', exact: true });
    await sizeTrigger.focus();
    await page.keyboard.press('ArrowDown');
    await page.getByRole('menu').waitFor();
    await page.waitForFunction(() => document.querySelector('.glass-menu')?.dataset.glassMode === 'lens');
    assert.equal(await page.getByRole('menuitemradio').count(), 3);
    assert.equal(await page.getByRole('menuitemradio', { name: '10 条', exact: true }).getAttribute('aria-checked'), 'true');
    assert.equal(await page.evaluate(() => document.body.getAttribute('data-scroll-locked')), null);
    await page.getByRole('menu').screenshot({ path: 'output/playwright/glass-page-menu-light.png', animations: 'disabled' });
    await page.waitForFunction(() => document.activeElement?.getAttribute('role') === 'menuitemradio' && document.activeElement.textContent.trim() === '10 条');
    await page.keyboard.press('ArrowDown');
    await page.waitForFunction(() => document.activeElement?.getAttribute('role') === 'menuitemradio' && document.activeElement.textContent.trim() === '20 条');
    await page.keyboard.press('Enter');
    await page.getByRole('menu').waitFor({ state: 'detached' });
    assert.equal(await sizeTrigger.innerText(), '20 条');
    await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === '任务每页条数');
    await choosePageSize('任务每页条数', 10);
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await page.setViewportSize({ width: 375, height: 812 });
    await sizeTrigger.click();
    await page.waitForFunction(() => {
      const panel = document.querySelector('.glass-menu'), box = panel?.getBoundingClientRect();
      return box && box.left >= 11 && box.right <= innerWidth - 11 && box.top >= 11 && box.bottom <= innerHeight - 11 && panel.dataset.glassMode === 'lens';
    });
    await page.getByRole('menu').evaluate(panel => Promise.all(panel.getAnimations().map(animation => animation.finished)));
    assert((await page.getByRole('menuitemradio').evaluateAll(items => items.map(item => item.getBoundingClientRect().height))).every(height => height >= 44));
    await page.getByRole('menu').screenshot({ path: 'output/playwright/glass-page-menu-dark.png', animations: 'disabled' });
    const menuScroll = await page.evaluate(() => scrollY);
    await page.mouse.move(8, 200);
    await page.mouse.wheel(0, -180);
    await page.waitForFunction(previous => scrollY < previous - 50, menuScroll);
    await page.keyboard.press('Escape');
    await page.getByRole('menu').waitFor({ state: 'detached' });
    assert.equal(await sizeTrigger.innerText(), '10 条');
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await page.getByRole('tab', { name: '批量导入', exact: true }).click();
    await page.getByLabel('批量账号', { exact: true }).fill(Array.from({ length: 25 }, (_, i) => `fixture-${i}@example.com---fake-password---JBSWY3DPEHPK3PXP`).join('\n'));
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('alertdialog').waitFor();
    const glass = await page.locator('.glass-dialog-overlay').evaluate(overlay => ({
      background: getComputedStyle(overlay).backgroundColor,
      blur: getComputedStyle(overlay).backdropFilter,
    }));
    assert(!glass.background.includes('0, 0, 0'), JSON.stringify(glass));
    assert.equal(glass.blur, 'none', 'The overlay must not pre-blur the entire page');
    await page.waitForFunction(() => document.querySelector('.glass-dialog')?.dataset.glassMode === 'lens');
    const lens = await page.locator('.glass-dialog').evaluate(panel => ({
      filter: getComputedStyle(panel.querySelector('.glass-warp')).filter,
      source: panel.dataset.glassSource,
      radius: getComputedStyle(panel).borderRadius,
      displacement: panel.querySelector('feImage')?.getAttribute('href'),
      mapMode: panel.dataset.glassMap,
      canvasCount: panel.querySelectorAll('canvas').length,
      background: getComputedStyle(panel.querySelector('.glass-tint')).backgroundImage,
    }));
    assert(lens.filter.includes('url(') && lens.radius === '28px' && lens.displacement?.startsWith('data:image/png') && lens.mapMode === 'shader', 'Pinned upstream shader SVG lens is active');
    assert.equal(lens.source, 'rdev/liquid-glass-react');
    assert.equal(lens.canvasCount, 0, 'No continuous or attached Canvas renderer');
    const mapChannels = await page.locator('.glass-dialog').evaluate(async panel => {
      const image = new Image();
      image.src = panel.querySelector('feImage').getAttribute('href');
      await image.decode();
      const canvas = document.createElement('canvas'); canvas.width = image.width; canvas.height = image.height;
      const context = canvas.getContext('2d'); context.drawImage(image, 0, 0);
      const data = context.getImageData(0, 0, image.width, image.height).data;
      let redMin = 255, redMax = 0, blueMin = 255, blueMax = 0, compatible = true;
      for (let i = 0; i < data.length; i += 4) {
        redMin = Math.min(redMin, data[i]); redMax = Math.max(redMax, data[i]);
        blueMin = Math.min(blueMin, data[i + 2]); blueMax = Math.max(blueMax, data[i + 2]);
        compatible &&= data[i + 1] === data[i + 2];
      }
      return { width: image.width, height: image.height, redRange: redMax - redMin, blueRange: blueMax - blueMin, compatible };
    });
    assert(mapChannels.width <= 512 && mapChannels.height <= 320 && mapChannels.redRange > 80 && mapChannels.blueRange > 80 && mapChannels.compatible, JSON.stringify(mapChannels));
    assert.notEqual(lens.background, 'none', 'Optical material must not be replaced by an opaque OS fallback');
    await page.getByRole('alertdialog').evaluate(panel => Promise.all(panel.getAnimations().map(animation => animation.finished)));
    const overflow = await page.getByRole('alertdialog').evaluate(panel => ({
      extraHeight: panel.scrollHeight - panel.clientHeight, extraWidth: panel.scrollWidth - panel.clientWidth,
      scrollbar: getComputedStyle(panel).scrollbarWidth,
    }));
    assert(overflow.extraHeight <= 1 && overflow.extraWidth <= 1 && overflow.scrollbar === 'none', JSON.stringify(overflow));
    await page.evaluate(() => scrollTo(0, 0));
    await page.mouse.move(1200, 800);
    await page.mouse.wheel(0, 220);
    await page.waitForFunction(() => scrollY > 100);
    assert.equal(await page.getByRole('alertdialog').isVisible(), true, 'Background scrolling keeps the dialog open');
    assert.equal(await page.evaluate(() => document.body.getAttribute('data-scroll-locked')), null);
    const rimTransform = await page.locator('.glass-rim-flow').evaluate(rim => {
      const style = getComputedStyle(rim, '::before');
      if (style.animationName !== 'glass-rim-orbit' || style.animationPlayState !== 'running') throw new Error('Rim shimmer is not running');
      return style.transform;
    });
    await page.waitForFunction(previous => getComputedStyle(document.querySelector('.glass-rim-flow'), '::before').transform !== previous, rimTransform);
    const panelBox = await page.getByRole('alertdialog').boundingBox();
    const opticalScale = await page.locator('.glass-dialog feDisplacementMap').first().getAttribute('scale');
    await page.mouse.move(panelBox.x + panelBox.width * 0.7, panelBox.y + panelBox.height * 0.3);
    await page.waitForFunction(() => parseFloat(document.querySelector('.glass-dialog').style.getPropertyValue('--glass-light-x')) > 60);
    assert(Number(await page.locator('.glass-dialog feDisplacementMap').first().getAttribute('scale')) > Number(opticalScale), 'The optical layer responds to pointer position');
    const stablePanel = await page.getByRole('alertdialog').boundingBox();
    assert(Math.abs(stablePanel.x - panelBox.x) < 1 && Math.abs(stablePanel.y - panelBox.y) < 1, 'Optics must not move controls');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.waitForFunction(() => document.querySelector('.glass-dialog').style.getPropertyValue('--glass-light-x') === '25%');
    assert.equal(await page.locator('.glass-rim-flow').evaluate(rim => getComputedStyle(rim, '::before').animationName), 'none');
    assert.equal(await page.locator('.glass-dialog').evaluate(panel => panel.style.getPropertyValue('--glass-flow-x')), '0px');
    await page.mouse.move(panelBox.x + panelBox.width * 0.9, panelBox.y + panelBox.height * 0.5);
    assert.equal(await page.locator('.glass-dialog').evaluate(panel => panel.style.getPropertyValue('--glass-light-x')), '25%');
    const refracted = await page.getByRole('alertdialog').screenshot({ animations: 'disabled' });
    const activeLens = await page.locator('.glass-dialog').evaluate(panel => {
      const value = panel.style.getPropertyValue('--glass-lens');
      panel.style.setProperty('--glass-lens', 'none');
      return value;
    });
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const plainBackdrop = await page.getByRole('alertdialog').screenshot({ animations: 'disabled' });
    assert(!refracted.equals(plainBackdrop), 'The upstream filter must change rendered pixels');
    await page.locator('.glass-dialog').evaluate((panel, value) => panel.style.setProperty('--glass-lens', value), activeLens);
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.screenshot({ path: 'output/playwright/dialog-glass-light.png', animations: 'disabled' });
    await page.getByRole('button', { name: '返回检查', exact: true }).click();
    await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    assert.equal(await page.locator('.glass-filter-defs').count(), 0, 'Filter unmounts with the dialog');
    await page.waitForFunction(() => document.activeElement?.textContent === '开始更换');
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('alertdialog').waitFor();
    await page.screenshot({ path: 'output/playwright/dialog-glass-dark.png', animations: 'disabled' });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.waitForFunction(() => {
      const box = document.querySelector('[role="alertdialog"]')?.getBoundingClientRect();
      return box && box.left >= 15 && box.right <= innerWidth - 15;
    });
    const dialogBox = await page.getByRole('alertdialog').boundingBox();
    assert(dialogBox.x >= 15 && dialogBox.width <= 345, JSON.stringify({ mobileDialogBox: dialogBox }));
    await page.getByRole('button', { name: '确认并开始', exact: true }).focus();
    await page.keyboard.press('Tab');
    await page.waitForFunction(() => document.activeElement?.textContent === '返回检查');
    await page.screenshot({ path: 'output/playwright/dialog-glass-mobile.png', animations: 'disabled' });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: '确认并开始', exact: true }).click();
    await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    const taskPager = page.getByRole('navigation', { name: '任务分页', exact: true });
    const savedPager = page.getByRole('navigation', { name: '结果分页', exact: true });
    const taskBar = email => page.getByRole('progressbar', { name: `${email} 的任务进度`, exact: true });
    const assertTaskControlsSeparated = async () => {
      const boxes = await page.locator('.result-row').evaluateAll(rows => rows.flatMap(row => {
        const stage = row.querySelector('.task-stage'), action = row.querySelector('.row-actions button');
        if (!stage || !action) return [];
        const s = stage.getBoundingClientRect(), a = action.getBoundingClientRect();
        const heading = row.querySelector('.row-heading').getBoundingClientRect();
        return [{ horizontalGap: a.left - s.right, verticalGap: a.top - s.bottom,
          metaGap: row.querySelector('.task-row-meta').getBoundingClientRect().top - heading.bottom,
          targetHeight: a.height }];
      }));
      assert(boxes.length > 0);
      assert(boxes.every(box => (box.horizontalGap >= 15 || box.verticalGap >= 8) && box.metaGap >= 7 && box.targetHeight >= 44), JSON.stringify(boxes));
      const typography = await page.locator('[data-task-filter]').evaluateAll(buttons => buttons.map(button => {
        const label = button.querySelector('.filter-label'), count = button.querySelector('.filter-count');
        const markers = [label, count].map(parent => {
          const marker = document.createElement('i');
          marker.style.cssText = 'display:inline-block;width:0;height:0;padding:0;border:0;vertical-align:baseline';
          parent.append(marker); return marker;
        });
        const result = { delta: Math.abs(markers[0].getBoundingClientRect().y - markers[1].getBoundingClientRect().y),
          sameFontSize: getComputedStyle(label).fontSize === getComputedStyle(count).fontSize,
          sameLineHeight: getComputedStyle(label).lineHeight === getComputedStyle(count).lineHeight };
        markers.forEach(marker => marker.remove());
        return result;
      }));
      assert(typography.length === 6 && typography.every(item => item.delta < 0.25 && item.sameFontSize && item.sameLineHeight), JSON.stringify(typography));
    };
    await page.waitForFunction(() => document.querySelector('[role="progressbar"][aria-label="fixture-2@example.com 的任务进度"]')?.getAttribute('aria-valuenow') === '10');
    for (const theme of ['纯白', '深色']) {
      await page.getByRole('button', { name: theme, exact: true }).click();
      for (const width of [320, 375, 812, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        await assertTaskControlsSeparated();
        await page.getByRole('button', { name: '取消 fixture-2@example.com', exact: true }).hover();
        await assertTaskControlsSeparated();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        if (width === 375 || width === 1440) {
          await page.locator('.results-card').screenshot({ path: `output/playwright/task-controls-${theme === '纯白' ? 'light' : 'dark'}-${width}.png`, animations: 'disabled' });
        }
      }
    }
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    assert.equal(await page.locator('.result-row').count(), 10);
    assert.equal(await taskPager.locator('.page-number').innerText(), '第 1 / 3 页');
    await assertCounts({ all: 25, running: 10, queued: 15, success: 0, failed: 0, cancelled: 0 });
    await page.locator('[data-task-filter="running"]').click();
    await page.waitForFunction(() => document.querySelector('.results-card .pagination-total')?.textContent === '共 10 条');
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '导出成功 TXT', exact: true }).count(), 0);
    await page.locator('[data-task-filter="queued"]').click();
    await page.waitForFunction(() => document.querySelector('.results-card .pagination-total')?.textContent === '共 15 条');
    assert.equal(await taskBar('fixture-11@example.com').getAttribute('aria-valuenow'), '0');
    await assertCounts({ all: 25, running: 10, queued: 15, success: 0, failed: 0, cancelled: 0 });
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '导出成功 TXT', exact: true }).count(), 0);
    await page.locator('[data-task-filter="all"]').click();
    await taskPager.getByRole('button', { name: '下一页', exact: true }).click();
    await taskBar('fixture-11@example.com').waitFor();
    assert.equal(await taskBar('fixture-11@example.com').getAttribute('aria-valuenow'), '0');
    await taskPager.getByRole('button', { name: '上一页', exact: true }).click();
    await taskBar('fixture-2@example.com').waitFor();
    assert.equal(await taskBar('fixture-2@example.com').getAttribute('aria-valuenow'), '10');
    const accent = page.locator('.processing-accent');
    await page.locator('.results-card > .card-title').scrollIntoViewIfNeeded();
    await page.waitForFunction(() => document.querySelector('.processing-accent')?.dataset.paused === 'false');
    assert.equal(await accent.getAttribute('aria-hidden'), 'true');
    assert.equal(await accent.evaluate(el => getComputedStyle(el).animationName), 'processing-shine');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await accent.evaluate(el => getComputedStyle(el).animationName), 'none');
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); });
    await page.waitForFunction(() => document.querySelector('.processing-accent')?.dataset.paused === 'true');
    await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); scrollTo(0, 0); });
    await page.waitForFunction(() => document.querySelector('.processing-accent')?.dataset.paused === 'false');
    await page.screenshot({ path: 'output/playwright/task-progress-running-light.png', fullPage: false, animations: 'disabled' });
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await page.setViewportSize({ width: 375, height: 812 });
    await page.locator('.results-card').evaluate(el => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: 'output/playwright/task-progress-running-mobile.png', fullPage: false, animations: 'disabled' });
    await page.locator('.result-filter > div').screenshot({ path: 'output/playwright/task-counts-mobile.png', animations: 'disabled' });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await taskPager.getByRole('button', { name: '下一页', exact: true }).click();
    await page.getByRole('button', { name: '取消 fixture-11@example.com', exact: true }).click();
    await taskPager.getByRole('button', { name: '上一页', exact: true }).click();
    await page.getByRole('button', { name: '取消 fixture-2@example.com', exact: true }).click();
    console.log('STEP: cancelled one queued and one running task');
    release = true;
    await page.getByText('21 成功 · 2 失败 · 2 取消', { exact: true }).waitFor();
    await assertCounts({ all: 25, running: 0, queued: 0, success: 21, failed: 2, cancelled: 2 });
    assert.equal(await taskBar('fixture-0@example.com').getAttribute('aria-valuenow'), '10');
    assert.equal(await taskBar('fixture-1@example.com').getAttribute('aria-valuenow'), '95');
    assert.equal(await taskBar('fixture-3@example.com').getAttribute('aria-valuenow'), '100');
    await page.locator('.results-card').evaluate(el => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: 'output/playwright/task-progress-mixed-light.png', fullPage: false, animations: 'disabled' });
    await page.locator('.result-filter > div').screenshot({ path: 'output/playwright/task-counts-light.png', animations: 'disabled' });
    console.log('STEP: batch settled');
    assert.equal(maximum, 10);
    assert.equal(cancelCalls, 1);
    assert.equal(calls.some(call => call.email === 'fixture-11@example.com'), false);
    await page.locator('[data-task-filter="failed"]').click();
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 2);
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '重试失败', exact: true }).isEnabled(), true);
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '导出成功 TXT', exact: true }).count(), 0);
    await page.getByText('更换前失败 · 旧密钥未变更', { exact: true }).waitFor();
    await page.getByText('更换后验证失败 · 仅重试验证', { exact: true }).waitFor();
    const savedCard = page.locator('.saved-card');
    await choosePageSize('结果每页条数', 50);
    await page.getByRole('checkbox', { name: '选择已保存结果 fixture-1@example.com', exact: true }).check();
    assert.equal(await savedCard.getByRole('button', { name: '导出选中 TXT（0）', exact: true }).isDisabled(), true);
    await savedCard.getByRole('button', { name: '取消选择（1）', exact: true }).click();
    await choosePageSize('结果每页条数', 10);
    await page.getByRole('button', { name: '失败重试 fixture-0@example.com', exact: true }).click();
    await page.getByRole('button', { name: '确认并开始', exact: true }).click();
    await page.getByRole('button', { name: '核对状态 fixture-0@example.com', exact: true }).click();
    // Two synchronous clicks must still create only one verification attempt.
    await page.getByRole('button', { name: '重试验证 fixture-1@example.com', exact: true }).evaluate(button => { button.click(); button.click(); });
    await page.getByText('23 成功 · 0 失败 · 2 取消', { exact: true }).waitFor();
    assert.deepEqual(calls.filter(call => call.email === 'fixture-1@example.com').map(call => call.action), ['rotate', 'verify']);
    assert.equal(calls.filter(call => call.email === 'fixture-0@example.com').length, 2);
    assert.equal(operationLookups.length, 1);
    console.log('STEP: safe retries settled');
    await page.locator('[data-task-filter="cancelled"]').click();
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 2);
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '导出成功 TXT', exact: true }).count(), 0);
    assert.equal(await page.locator('.result-filter').getByRole('button', { name: '重试失败', exact: true }).count(), 0);
    await page.locator('[data-task-filter="success"]').click();
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 10);
    assert.equal((await page.getByRole('progressbar').evaluateAll(bars => bars.every(bar => bar.getAttribute('aria-valuenow') === '100'))), true);
    await choosePageSize('任务每页条数', 20);
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 20);
    await taskPager.getByRole('button', { name: '下一页', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 3);
    await choosePageSize('任务每页条数', 50);
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 23);
    await choosePageSize('任务每页条数', 10);
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 10);
    const downloadPromise = page.waitForEvent('download');
    await page.locator('.result-filter').getByRole('button', { name: '导出成功 TXT', exact: true }).click();
    const download = await downloadPromise, stream = await download.createReadStream(), chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const rows = Buffer.concat(chunks).toString('utf8').trim().split('\r\n');
    assert.equal(rows.length, 23);
    assert(rows.every(line => line.includes(`---fake-password---${secret}`)));
    await dismissNotice();
    assert.equal(await page.locator('.saved-entry').count(), 10);
    const selectedEmails = await page.locator('.saved-account > span:last-child').allTextContents();
    await savedCard.getByRole('checkbox').nth(0).check();
    await savedCard.getByRole('checkbox').nth(1).focus();
    await page.keyboard.press('Space');
    assert.equal(await savedCard.getByRole('checkbox').nth(1).isChecked(), true);
    await savedPager.getByRole('button', { name: '下一页', exact: true }).click();
    assert.equal(await savedPager.locator('.page-number').innerText(), '第 2 / 3 页');
    assert.equal(await taskPager.locator('.page-number').innerText(), '第 1 / 3 页');
    selectedEmails.splice(2);
    selectedEmails.push(await page.locator('.saved-account > span:last-child').first().innerText());
    // The email label and 44px target also toggle the existing Radix checkbox.
    await page.locator('.saved-account > span:last-child').first().click();
    assert.equal(await savedCard.getByRole('checkbox').first().isChecked(), true);
    const selectedDownloadPromise = page.waitForEvent('download');
    await savedCard.getByRole('button', { name: '导出选中 TXT（3）', exact: true }).click();
    const selectedDownload = await selectedDownloadPromise;
    const selectedStream = await selectedDownload.createReadStream(), selectedChunks = [];
    for await (const chunk of selectedStream) selectedChunks.push(chunk);
    const selectedLines = Buffer.concat(selectedChunks).toString('utf8').trim().split('\r\n');
    assert.deepEqual(selectedLines.map(line => line.split('---')[0]).sort(), selectedEmails.sort());
    assert(selectedLines.every(line => line.endsWith(`---fake-password---${secret}`)));
    await dismissNotice();
    await savedPager.getByRole('button', { name: '上一页', exact: true }).click();
    assert.equal(await savedCard.getByRole('checkbox').nth(0).isChecked(), true);
    assert.equal(await savedCard.getByRole('checkbox').nth(1).isChecked(), true);
    await savedCard.getByRole('button', { name: '取消选择（3）', exact: true }).click();
    assert.equal(await savedCard.locator('[role="checkbox"][data-state="checked"]').count(), 0);
    await savedCard.getByRole('button', { name: '全选', exact: true }).click();
    await savedCard.getByRole('button', { name: '取消选择（23）', exact: true }).waitFor();
    assert.equal(await savedCard.getByRole('button', { name: '全选', exact: true }).isDisabled(), true);
    assert.equal(await savedCard.locator('[role="checkbox"][data-state="checked"]').count(), 10);
    await savedPager.getByRole('button', { name: '下一页', exact: true }).click();
    assert.equal(await savedCard.locator('[role="checkbox"][data-state="checked"]').count(), 10);
    await savedPager.getByRole('button', { name: '下一页', exact: true }).click();
    assert.equal(await savedCard.locator('[role="checkbox"][data-state="checked"]').count(), 3);
    const selectAllDownloadPromise = page.waitForEvent('download');
    await savedCard.getByRole('button', { name: '导出选中 TXT（23）', exact: true }).click();
    const selectAllDownload = await selectAllDownloadPromise;
    const selectAllStream = await selectAllDownload.createReadStream(), selectAllChunks = [];
    for await (const chunk of selectAllStream) selectAllChunks.push(chunk);
    assert.equal(Buffer.concat(selectAllChunks).toString('utf8').trim().split('\r\n').length, 23);
    await dismissNotice();
    await savedCard.getByRole('button', { name: '取消选择（23）', exact: true }).click();
    assert.equal(await savedCard.getByRole('button', { name: '全选', exact: true }).isEnabled(), true);
    await savedPager.getByRole('button', { name: '上一页', exact: true }).click();
    await savedPager.getByRole('button', { name: '上一页', exact: true }).click();
    const allSavedDownloadPromise = page.waitForEvent('download');
    await savedCard.getByRole('button', { name: '导出成功 TXT', exact: true }).click();
    const allSavedDownload = await allSavedDownloadPromise;
    const allSavedStream = await allSavedDownload.createReadStream(), allSavedChunks = [];
    for await (const chunk of allSavedStream) allSavedChunks.push(chunk);
    assert.equal(Buffer.concat(allSavedChunks).toString('utf8').trim().split('\r\n').length, 23);
    await dismissNotice();
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await savedCard.getByRole('checkbox').first().check();
    await savedCard.evaluate(el => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: 'output/playwright/saved-selection-light.png', animations: 'disabled' });
    await page.getByRole('button', { name: '深色', exact: true }).click();
    await page.setViewportSize({ width: 375, height: 812 });
    await savedCard.evaluate(el => el.scrollIntoView({ block: 'start' }));
    for (const width of [320, 375]) {
      await page.setViewportSize({ width, height: 812 });
      await page.waitForFunction(() => {
        const toolbar = document.querySelector('.saved-toolbar');
        const box = toolbar.getBoundingClientRect();
        return box.width < innerWidth && box.height <= 100 && [...toolbar.querySelectorAll('button')].every(button => button.scrollWidth <= button.clientWidth + 1);
      });
      assert.equal(await savedCard.getByRole('checkbox').first().evaluate(el => getComputedStyle(el).borderRadius), '4px');
    }
    await page.screenshot({ path: 'output/playwright/saved-selection-mobile-dark.png', animations: 'disabled' });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await savedCard.getByRole('button', { name: '取消选择（1）', exact: true }).click();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await choosePageSize('结果每页条数', 20);
    await page.waitForFunction(() => document.querySelectorAll('.saved-entry').length === 20);
    await choosePageSize('结果每页条数', 50);
    await page.waitForFunction(() => document.querySelectorAll('.saved-entry').length === 23);
    await choosePageSize('结果每页条数', 10);
    await savedPager.getByRole('button', { name: '下一页', exact: true }).click();
    await savedPager.getByRole('button', { name: '下一页', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('.saved-entry').length === 3);
    const callsBeforePaging = calls.length;
    await savedCard.getByRole('checkbox').first().check();
    for (let removed = 0; removed < 3; removed++) {
      await page.locator('.saved-entry').first().getByRole('button', { name: /^清除 / }).click();
      await page.getByRole('button', { name: '确认清除', exact: true }).click();
      await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    }
    await page.waitForFunction(() => document.querySelector('.saved-card .page-number')?.textContent === '第 2 / 2 页');
    assert.equal(await page.locator('.saved-entry').count(), 10);
    assert.equal(await savedCard.getByRole('button', { name: /^取消选择/ }).count(), 0);
    assert.equal(calls.length, callsBeforePaging, 'Paging must not submit or retry a task');
    await page.getByRole('tab', { name: '单个账号', exact: true }).click();
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('button', { name: '关闭错误提示', exact: true }).waitFor();
    assert.equal(await page.locator('.status-dismissible').count(), 0, 'Global feedback must not render a page banner');
    const feedback = page.locator('[data-feedback-dialog]');
    await feedback.waitFor();
    for (const theme of ['纯白', '深色']) {
      await page.evaluate(value => {
        document.documentElement.dataset.appearance = value;
        document.documentElement.classList.toggle('dark', value === 'dark');
      }, theme === '纯白' ? 'light' : 'dark');
      for (const width of [320, 375, 812, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await page.waitForFunction(() => {
          const b = document.querySelector('[data-feedback-dialog]')?.getBoundingClientRect();
          return b && b.left >= 15 && b.right <= innerWidth - 15;
        });
        const box = await feedback.boundingBox();
        assert(box.x >= 15 && box.x + box.width <= width - 15, JSON.stringify({ width, box }));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      }
    }
    await feedback.screenshot({ path: 'output/playwright/feedback-glass-dark.png', animations: 'disabled' });
    await page.getByRole('button', { name: '关闭错误提示', exact: true }).click();
    await feedback.waitFor({ state: 'detached' });
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await page.locator('[data-progress-indicator]').first().evaluate(el => parseFloat(getComputedStyle(el).transitionDuration) < 0.01), true);
    await page.locator('[data-task-filter="all"]').click();
    await page.screenshot({ path: 'output/playwright/concurrency-desktop.png', fullPage: true });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.screenshot({ path: 'output/playwright/concurrency-mobile.png', fullPage: true });

    // Bulk retry while ten tasks are active: retries must join the same FIFO.
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.getByRole('tab', { name: '批量导入', exact: true }).click();
    await page.getByLabel('批量账号', { exact: true }).fill(Array.from({ length: 25 }, (_, i) => `bulk-fixture-${i}@example.com---fake-password---JBSWY3DPEHPK3PXP`).join('\n'));
    await page.getByRole('button', { name: '开始更换', exact: true }).click();
    await page.getByRole('button', { name: '确认并开始', exact: true }).click();
    await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    await page.getByText('0 成功 · 3 失败 · 0 取消', { exact: true }).waitFor();
    await assertCounts({ all: 25, running: 10, queued: 12, success: 0, failed: 3, cancelled: 0 });
    assert.equal(await savedCard.getByRole('button', { name: '清空结果', exact: true }).isDisabled(), true, 'Running tasks protect saved keys');
    await page.locator('[data-task-filter="running"]').click();
    await page.waitForFunction(() => document.querySelector('.results-card .pagination-total')?.textContent === '共 10 条');
    await page.locator('[data-task-filter="failed"]').click();
    await page.getByRole('button', { name: '重试失败', exact: true }).evaluate(button => { button.click(); button.click(); });
    await page.getByText('已将 2 个失败任务加入队列', { exact: true }).waitFor();
    await dismissNotice();
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 1);
    assert.equal(await page.getByRole('button', { name: '重试失败', exact: true }).isDisabled(), true);
    await page.locator('[data-task-filter="queued"]').click();
    await choosePageSize('任务每页条数', 50);
    await page.waitForFunction(() => document.querySelectorAll('.result-row').length === 14);
    await assertCounts({ all: 25, running: 10, queued: 14, success: 0, failed: 1, cancelled: 0 });
    assert.equal(calls.filter(call => call.email === 'bulk-fixture-0@example.com').length, 1);
    assert.equal(calls.filter(call => call.email === 'bulk-fixture-1@example.com').length, 1);
    await page.locator('.results-card').evaluate(el => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: 'output/playwright/retry-waiting-queue.png', animations: 'disabled' });
    releaseBulk = true;
    await page.getByText('24 成功 · 1 失败 · 0 取消', { exact: true }).waitFor();
    await assertCounts({ all: 25, running: 0, queued: 0, success: 24, failed: 1, cancelled: 0 });
    assert.deepEqual(calls.filter(call => call.email === 'bulk-fixture-0@example.com').map(call => call.action), ['rotate', 'rotate']);
    assert.deepEqual(calls.filter(call => call.email === 'bulk-fixture-1@example.com').map(call => call.action), ['rotate', 'verify']);
    assert.equal(calls.filter(call => call.email === 'bulk-fixture-2@example.com').length, 1);
    const lastOriginal = calls.findIndex(call => call.email === 'bulk-fixture-24@example.com');
    const firstRetry = calls.findIndex(call => call.email === 'bulk-fixture-0@example.com' && call.path.endsWith('/retry'));
    assert(firstRetry > lastOriginal, 'Retries must wait behind the original queue');
    assert.equal(maximum, 10);
    // Exercise the unsupported-engine branch without changing browser dependencies.
    const fallbackPage = await context.newPage();
    fallbackPage.on('pageerror', error => errors.push(error.message));
    await fallbackPage.addInitScript(() => Object.defineProperty(navigator, 'userAgent', {
      get: () => 'Mozilla/5.0 Version/18.0 Safari/605.1.15',
    }));
    await fallbackPage.goto(site);
    await fallbackPage.getByLabel('账号凭证', { exact: true }).fill('fallback@example.com---fake-password---JBSWY3DPEHPK3PXP');
    await fallbackPage.getByRole('checkbox', { name: '我拥有这些账号或已获得操作授权', exact: true }).check();
    await fallbackPage.getByRole('button', { name: '开始更换', exact: true }).click();
    await fallbackPage.getByRole('alertdialog').waitFor();
    const fallback = await fallbackPage.getByRole('alertdialog').evaluate(panel => ({
      mode: panel.dataset.glassMode,
      filter: getComputedStyle(panel.querySelector('.glass-warp')).backdropFilter,
    }));
    assert.equal(fallback.mode, undefined);
    assert(fallback.filter.includes('blur(') && !fallback.filter.includes('url('));
    await fallbackPage.emulateMedia({ forcedColors: 'active' });
    await fallbackPage.waitForFunction(() => getComputedStyle(document.querySelector('.glass-warp')).display === 'none');
    await fallbackPage.getByRole('button', { name: '返回检查', exact: true }).click();
    await fallbackPage.close();
    const inspectStorage = target => target.evaluate(() => new Promise((resolve, reject) => {
      const request = indexedDB.open('keyshift-local-results-v1', 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result, tx = db.transaction(['results', 'keys'], 'readonly');
        const results = tx.objectStore('results').getAllKeys(), keys = tx.objectStore('keys').getAllKeys();
        tx.oncomplete = () => { db.close(); resolve({ results: results.result, keys: keys.result, appearance: localStorage.getItem('mfa-rotate-appearance') }); };
      };
    }));
    const storedBeforeReload = await inspectStorage(page), callsBeforeClear = calls.length;
    assert(storedBeforeReload.results.length > 10);
    await page.reload();
    await page.waitForFunction(count => document.querySelector('.saved-card .count')?.textContent === String(count), storedBeforeReload.results.length);
    assert.deepEqual((await inspectStorage(page)).results, storedBeforeReload.results, 'Reload must retain saved results');
    const readDecrypted = () => page.evaluate(async () => {
      const db = await new Promise((resolve, reject) => { const request = indexedDB.open('keyshift-local-results-v1', 1); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
      const raw = await new Promise((resolve, reject) => {
        const tx = db.transaction(['results', 'keys'], 'readonly');
        const records = tx.objectStore('results').getAll(), key = tx.objectStore('keys').get('aes');
        tx.oncomplete = () => resolve({ records: records.result, key: key.result }); tx.onerror = () => reject(tx.error);
      }); db.close();
      const decoded = await Promise.all(raw.records.map(async record => JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.iv }, raw.key, record.encrypted)))));
      return { decoded, encryptedOnly: raw.records.every(record => Object.keys(record).sort().join(',') === 'encrypted,iv' && record.encrypted instanceof ArrayBuffer) };
    });
    const decrypted = await readDecrypted();
    assert(decrypted.encryptedOnly, 'Passwords and keys must never appear as plaintext IDB fields');
    assert(decrypted.decoded.every(record => record.password === 'fake-password'), 'All new records retain the password within encryption');
    assert.equal(await page.getByLabel('账号凭证', { exact: true }).inputValue(), '');
    assert.equal(await page.locator('.saved-card').innerText().then(text => text.includes('fake-password')), false, 'Do not render saved passwords');
    const exportRestored = async () => {
      const pending = page.waitForEvent('download');
      await savedCard.getByRole('button', { name: '导出成功 TXT', exact: true }).click();
      const file = await pending, stream = await file.createReadStream(), chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      const lines = Buffer.concat(chunks).toString('utf8').trim().split('\r\n');
      assert.equal(lines.length, storedBeforeReload.results.length);
      assert(lines.every(line => line.includes('---fake-password---')));
      await file.delete(); await dismissNotice();
    };
    await exportRestored();
    // Simulate one pre-upgrade ciphertext that contained no password.
    const legacyEmail = decrypted.decoded[0].email;
    await page.evaluate(async id => {
      const db = await new Promise(resolve => { const request = indexedDB.open('keyshift-local-results-v1', 1); request.onsuccess = () => resolve(request.result); });
      const old = await new Promise(resolve => { const tx = db.transaction(['results', 'keys'], 'readonly'); const record = tx.objectStore('results').get(id), key = tx.objectStore('keys').get('aes'); tx.oncomplete = () => resolve({ record: record.result, key: key.result }); });
      const value = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: old.record.iv }, old.key, old.record.encrypted))); delete value.password;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, old.key, new TextEncoder().encode(JSON.stringify(value)));
      await new Promise((resolve, reject) => { const tx = db.transaction('results', 'readwrite'); tx.objectStore('results').put({ iv, encrypted }, id); tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); }); db.close();
    }, decrypted.decoded[0].id);
    await page.reload();
    await page.waitForFunction(count => document.querySelector('.saved-card .count')?.textContent === String(count), storedBeforeReload.results.length);
    await savedCard.getByRole('button', { name: '导出成功 TXT', exact: true }).click();
    await page.locator('[data-feedback-dialog]').getByText('旧结果缺少密码。', { exact: false }).waitFor();
    await page.getByRole('button', { name: '关闭错误提示', exact: true }).click();
    await page.getByLabel('账号凭证', { exact: true }).fill(`${legacyEmail}---fake-password---JBSWY3DPEHPK3PXP`);
    await exportRestored();
    assert((await readDecrypted()).decoded.every(record => record.password === 'fake-password'));
    await page.reload();
    await page.waitForFunction(count => document.querySelector('.saved-card .count')?.textContent === String(count), storedBeforeReload.results.length);
    await exportRestored();
    assert.equal(calls.length, callsBeforeClear, 'Restored export and legacy backfill must not call account APIs');
    await savedCard.getByRole('button', { name: '清空结果', exact: true }).click();
    await page.getByRole('alertdialog').getByText('清空后无法恢复', { exact: false }).waitFor();
    await page.setViewportSize({ width: 375, height: 812 });
    await page.getByRole('alertdialog').evaluate(el => Promise.all(el.getAnimations().map(animation => animation.finished)));
    await page.screenshot({ path: 'output/playwright/clear-all-mobile-dark.png', animations: 'disabled' });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.getByRole('button', { name: '取消', exact: true }).click();
    assert.deepEqual((await inspectStorage(page)).results, storedBeforeReload.results);
    await page.setViewportSize({ width: 1440, height: 1000 });
    // A failed IDB clear must abort atomically and leave visible results available.
    await page.evaluate(() => {
      window.originalClear = IDBObjectStore.prototype.clear;
      IDBObjectStore.prototype.clear = function () { throw new DOMException('fixture clear failure', 'UnknownError'); };
    });
    await savedCard.getByRole('button', { name: '清空结果', exact: true }).click();
    await page.getByRole('button', { name: '确认清空', exact: true }).click();
    await page.getByText('清空失败，结果未清除，请重试', { exact: true }).waitFor();
    assert.deepEqual((await inspectStorage(page)).results, storedBeforeReload.results);
    await page.evaluate(() => {
      window.clearCalls = 0;
      IDBObjectStore.prototype.clear = function () { window.clearCalls++; return window.originalClear.call(this); };
    });
    await page.getByRole('button', { name: '关闭错误提示', exact: true }).click();
    await page.getByRole('button', { name: '纯白', exact: true }).click();
    await savedCard.getByRole('button', { name: '清空结果', exact: true }).click();
    await page.getByRole('alertdialog').evaluate(el => Promise.all(el.getAnimations().map(animation => animation.finished)));
    await page.screenshot({ path: 'output/playwright/clear-all-light.png', animations: 'disabled' });
    await page.getByRole('button', { name: '确认清空', exact: true }).evaluate(button => { button.click(); button.click(); });
    await savedCard.waitFor({ state: 'detached' });
    await page.getByText('已清空本浏览器保存的结果', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.clearCalls), 1, 'Duplicate confirmation must not clear twice');
    const afterClear = await inspectStorage(page);
    assert.deepEqual(afterClear.results, []);
    assert.deepEqual(afterClear.keys, storedBeforeReload.keys, 'Retain the encryption key');
    assert.equal(afterClear.appearance, 'light', 'Retain appearance preferences');
    await page.reload();
    await page.getByRole('button', { name: '开始更换', exact: true }).waitFor();
    assert.equal(await savedCard.count(), 0);
    assert.deepEqual((await inspectStorage(page)).results, [], 'Cleared results must not return after reload');
    await assertCounts({ all: 0, running: 0, queued: 0, success: 0, failed: 0, cancelled: 0 });
    assert.equal(calls.length, callsBeforeClear, 'Clear/reload must never submit account jobs');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, maximum, pollBatch: Math.max(...pollWidths), cancelCalls,
      lostRetryResponseRecoveredWithoutReplay: true, duplicateRetryClickIgnored: true,
      successfulTxtRows: rows.length, stageProgressVerified: true, independentPagination: true,
      taskControlsSeparatedAcrossThemesAndWidths: true, taskCountsAcrossPaginationAndRetries: true,
      pageSizes: [10, 20, 50], glassPageSizeMenu: true, menuKeyboardAndFocus: true, menuBackgroundScroll: true, clampedAfterDeletion: true, closeIconCentered: true,
      savedSelectionAcrossPages: true, selectedExportRows: selectedLines.length, glassFeedbackInsteadOfBanner: true,
      selectAllAcrossPages: true, compactSavedToolbar: true, processingAccentReducedAndHidden: true, svgRefractionMaterial: true, actualRefractionPixelsChanged: true, reducedMotionGlintDisabled: true,
      unsupportedEngineFallback: true, forcedColorsFallback: true,
      refreshRetainsResults: true, refreshExportsCompleteCredentials: true, encryptedPasswordBackfill: true, backgroundWheelScrollWithDialog: true,
      confirmedClearAll: true, failedClearAtomic: true, encryptionKeyAndAppearanceRetained: true,
      transparentGlassDialog: true, runningAndWaitingFilters: true, bulkRetryJoinedSharedQueue: true,
      unsafeMutationNotRetried: true, realAccountRequests: 0 }));
  } catch (error) {
    console.error(JSON.stringify({ failure: error.message, errors, summary: await page.locator('.result-summary').allTextContents(), rows: await page.locator('.result-row').allTextContents(), calls, pollWidths: pollWidths.slice(-8) }));
    process.exitCode = 1;
  } finally {
    await context.close();
    await browser.close();
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
