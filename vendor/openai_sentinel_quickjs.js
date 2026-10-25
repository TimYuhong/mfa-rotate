'use strict';

// sentinel-server-v1 (2026-09-19): 支持 `--server` 常驻模式（按行 JSON 协议）。
// 单次模式与旧行为一致：stdin 读一个 JSON、stdout 写一个 JSON。

const fs = require('node:fs');
const vm = require('node:vm');
const cryptoMod = require('node:crypto');

// ─── SDK load & patches (once per process) ─────────────────────────────────────

const EXPOSE_PATCH = "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t}({});";
const EXPOSE_REPLACEMENT =
  "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t.__debug_n=_n,t.__debug_bindProof=D,t}({});";
const INSTANCE_PATCH = "var P=new _;";
const INSTANCE_REPLACEMENT = "var P=new _;globalThis.__debugP=P;";
const SDK_GLOBAL_PATCH = "var SentinelSDK=";
const SDK_GLOBAL_REPLACEMENT = "globalThis.SentinelSDK=";

const sdkRaw = fs.readFileSync(process.env.OPENAI_SENTINEL_SDK_FILE, 'utf8');
let sdk = sdkRaw;
sdk = sdk.replace(SDK_GLOBAL_PATCH, SDK_GLOBAL_REPLACEMENT);
sdk = sdk.replace(INSTANCE_PATCH, INSTANCE_REPLACEMENT);
sdk = sdk.replace(EXPOSE_PATCH, EXPOSE_REPLACEMENT);
// 编译一次；每个请求在新建的 VM 上下文里执行同一份已编译脚本。
const sdkScript = new vm.Script(sdk, { filename: 'openai-sentinel-sdk.js' });

// VM 内的 console 只写 stderr，stdout 留给 JSON 协议帧。
const vmConsole = (() => {
  const write = (level) => (...args) => {
    try {
      const parts = args.map((value) => {
        if (typeof value === 'string') return value;
        try { return JSON.stringify(value); } catch (_) { return String(value); }
      });
      process.stderr.write(`[${level}] ${parts.join(' ')}\n`);
    } catch (_) {}
  };
  const noop = () => {};
  return {
    log: write('log'), info: write('info'), warn: write('warn'), error: write('error'),
    debug: write('debug'), trace: write('trace'), dir: write('dir'), table: write('table'),
    time: noop, timeEnd: noop, timeLog: noop, group: noop, groupCollapsed: noop,
    groupEnd: noop, assert: noop, count: noop, countReset: noop, clear: noop,
  };
})();

// ─── Helpers ───────────────────────────────────────────────────────────────────

function createStorage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    clear() { map.clear(); },
    getItem(key) { return map.has(String(key)) ? map.get(String(key)) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); },
    key(index) { return [...map.keys()][index] || null; },
  };
}

function genericElement(tagName) {
  const tag = String(tagName || 'div').toLowerCase();
  return {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    nodeName: tag.toUpperCase(),
    style: {},
    children: [],
    childNodes: [],
    src: '',
    id: '',
    className: '',
    innerHTML: '',
    textContent: '',
    parentNode: null,
    appendChild(child) { this.children.push(child); child.parentNode = this; return child; },
    removeChild(child) { this.children = this.children.filter(x => x !== child); return child; },
    insertBefore(n) { this.children.push(n); return n; },
    setAttribute() {},
    getAttribute() { return null; },
    hasAttribute() { return false; },
    removeAttribute() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    cloneNode() { return genericElement(tagName); },
    contains() { return false; },
    getBoundingClientRect() {
      return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 };
    },
    focus() {},
    blur() {},
    click() {},
  };
}

function canvasElement(input = {}) {
  const el = genericElement('canvas');
  el.width = 300;
  el.height = 150;
  el.toDataURL = () => 'data:image/png;base64,';
  el.toBlob = (cb) => { if (cb) cb(new Uint8Array(0)); };
  el.getContext = (kind) => {
    if (kind === '2d') {
      return {
        fillRect() {}, clearRect() {}, strokeRect() {},
        getImageData() { return { data: new Uint8Array(0) }; },
        putImageData() {}, createImageData() { return { data: new Uint8Array(0) }; },
        setTransform() {}, resetTransform() {}, drawImage() {},
        save() {}, restore() {}, beginPath() {}, closePath() {},
        moveTo() {}, lineTo() {}, clip() {}, quadraticCurveTo() {},
        bezierCurveTo() {}, arc() {}, arcTo() {}, rect() {},
        fill() {}, stroke() {}, measureText() { return { width: 0 }; },
        fillText() {}, strokeText() {},
        scale() {}, rotate() {}, translate() {},
        createLinearGradient() { return { addColorStop() {} }; },
        createRadialGradient() { return { addColorStop() {} }; },
        canvas: el,
        fillStyle: '', strokeStyle: '', lineWidth: 1, font: '10px sans-serif',
        textAlign: 'start', textBaseline: 'alphabetic',
        globalAlpha: 1, globalCompositeOperation: 'source-over',
      };
    }
    if (!['webgl', 'experimental-webgl', 'webgl2'].includes(kind)) return null;
    const dbg = { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
    const ua = String(input.user_agent || '').toLowerCase();
    const platform = String(input.platform || '').toLowerCase();
    const webglVendor = ua.includes('firefox') ? 'Mozilla' : (
      ua.includes('safari') && !ua.includes('chrome') ? 'Apple Inc.' : 'Google Inc. (Intel)'
    );
    const webglRenderer = (
      platform.includes('mac') || ua.includes('mac') || ua.includes('iphone')
        ? 'Apple GPU'
        : ua.includes('firefox')
          ? 'Intel Open Source Technology Center -- Mesa Intel(R) Graphics'
          : 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'
    );
    return {
      VENDOR: 0x1F00, RENDERER: 0x1F01,
      getExtension(name) { return name === 'WEBGL_debug_renderer_info' ? dbg : null; },
      getParameter(p) {
        if (p === dbg.UNMASKED_VENDOR_WEBGL || p === 0x1F00) return webglVendor;
        if (p === dbg.UNMASKED_RENDERER_WEBGL || p === 0x1F01) return webglRenderer;
        return 0;
      },
      getSupportedExtensions() { return ['WEBGL_debug_renderer_info']; },
      createBuffer() { return {}; }, createTexture() { return {}; },
      createShader() { return {}; }, createProgram() { return {}; },
      bindBuffer() {}, bufferData() {}, bindTexture() {},
      viewport() {}, clear() {}, enable() {}, disable() {},
      drawArrays() {}, drawElements() {},
      canvas: el,
    };
  };
  return el;
}

function _rng(min, max) {
  return min + Math.floor(Math.random() * Math.max(1, max - min + 1));
}

// ─── 按请求构建 VM 环境（每个请求一套干净的 mock/window/SDK 实例） ─────────────

function buildEnv(input) {
  const _listeners = new Map();

  function addListener(type, callback) {
    if (typeof callback !== 'function') return;
    const bucket = _listeners.get(type) || [];
    bucket.push(callback);
    _listeners.set(type, bucket);
  }

  function removeListener(type, callback) {
    const bucket = _listeners.get(type) || [];
    _listeners.set(type, bucket.filter(fn => fn !== callback));
  }

  async function dispatch(type, init) {
    const event = {
      type,
      bubbles: true,
      cancelable: true,
      defaultPrevented: false,
      timeStamp: performance.now(),
      target: null,
      currentTarget: null,
      preventDefault() { this.defaultPrevented = true; },
      stopPropagation() {},
      stopImmediatePropagation() {},
      ...(init || {}),
    };
    for (const cb of [...(_listeners.get(type) || [])]) {
      try { await cb(event); } catch (_) {}
    }
  }

  let iframeObject = null;
  let capturedProof = null;

  // ─── iframe mock / event listener infrastructure ───────────────────────────

  const screenW = Number(input.screen_width || 1920);
  const screenH = Number(input.screen_height || 1080);
  const screenAvailW = Number(input.screen_avail_width || screenW);
  const screenAvailH = Number(input.screen_avail_height || Math.max(0, screenH - 40));
  const innerW = Number(input.inner_width || Math.max(320, screenW - 17));
  const innerH = Number(input.inner_height || Math.max(240, screenH - 111));
  const outerW = Number(input.outer_width || screenW);
  const outerH = Number(input.outer_height || screenH);
  const colorDepth = Number(input.color_depth || 24);
  const jsHeapSizeLimit = Number(input.js_heap_size_limit || 4294967296);
  const scripts = [];
  const pageUrl = new URL(String(input.page_url || 'https://auth.openai.com/'));
  const pageOrigin = String(input.page_origin || pageUrl.origin);
  const sdkUrl = String(input.sdk_url || 'https://sentinel.openai.com/sentinel/sdk.js');

  const documentElement = genericElement('html');
  documentElement.clientWidth = innerW;
  documentElement.clientHeight = innerH;

  const bodyEl = genericElement('body');
  bodyEl.appendChild = function (child) {
    this.children.push(child);
    child.parentNode = this;
    if (child === iframeObject) {
      setTimeout(() => {
        for (const cb of (iframeObject._load || [])) {
          try { cb(); } catch (_) {}
        }
      }, 1);
    }
    return child;
  };

  const navPlatform = input.platform != null ? String(input.platform) : 'Win32';
  const navVendor = input.vendor != null ? String(input.vendor) : 'Google Inc.';

  const targetTz = String(input.timezone || 'UTC');
  const OrigDTF = Intl.DateTimeFormat;
  const PatchedDTF = function (locales, options) {
    const inst = new OrigDTF(locales, options);
    const orig = inst.resolvedOptions.bind(inst);
    inst.resolvedOptions = function () { const r = orig(); r.timeZone = targetTz; return r; };
    return inst;
  };
  Object.setPrototypeOf(PatchedDTF, OrigDTF);
  PatchedDTF.prototype = OrigDTF.prototype;
  PatchedDTF.supportedLocalesOf = OrigDTF.supportedLocalesOf;

  const navigatorObj = {
    userAgent: String(input.user_agent || 'Mozilla/5.0'),
    language: String(input.language || 'en-US'),
    languages: Array.isArray(input.languages) ? input.languages : ['en-US', 'en'],
    hardwareConcurrency: Number(input.hardware_concurrency || 8),
    platform: navPlatform,
    vendor: navVendor,
    maxTouchPoints: Number(input.max_touch_points || 0),
    webdriver: false,
    onLine: true,
    cookieEnabled: true,
    doNotTrack: null,
    appCodeName: 'Mozilla',
    appName: 'Netscape',
    appVersion: '5.0',
    product: 'Gecko',
    productSub: '20030107',
    vendorSub: '',
    connection: { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false },
    plugins: { length: 0 },
    mimeTypes: { length: 0 },
    mediaDevices: { enumerateDevices: async () => [] },
    getBattery: async () => ({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 }),
    sendBeacon: () => true,
    permissions: { query: async () => ({ state: 'prompt' }) },
  };
  if (input.device_memory != null && !Number.isNaN(Number(input.device_memory))) {
    navigatorObj.deviceMemory = Number(input.device_memory);
  }
  if (String(input.sec_ch_ua || '').trim()) {
    const brands = [...String(input.sec_ch_ua).matchAll(/"([^"]+)";v="([^"]+)"/g)]
      .map((match) => ({ brand: match[1], version: match[2] }));
    navigatorObj.userAgentData = {
      brands,
      mobile: String(input.sec_ch_ua_mobile || '?0') === '?1',
      platform: String(input.sec_ch_ua_platform || '').replace(/^"|"$/g, ''),
      getHighEntropyValues: async () => ({
        brands,
        mobile: String(input.sec_ch_ua_mobile || '?0') === '?1',
        platform: String(input.sec_ch_ua_platform || '').replace(/^"|"$/g, ''),
      }),
    };
  }

  const cryptoObj = {
    getRandomValues: (arr) => { cryptoMod.randomFillSync(arr); return arr; },
  };
  if (typeof cryptoMod.randomUUID === 'function') {
    const forcedSentinelSid = String(input.sentinel_sid || '').trim();
    let randomUUIDCalls = 0;
    cryptoObj.randomUUID = () => {
      randomUUIDCalls += 1;
      // The SDK's first UUID is the Sentinel context SID. Keep that SID
      // stable per top-level/password context; later UUIDs stay random.
      if (forcedSentinelSid && randomUUIDCalls === 1) return forcedSentinelSid;
      return cryptoMod.randomUUID();
    };
  }
  if (cryptoMod.webcrypto && cryptoMod.webcrypto.subtle) {
    cryptoObj.subtle = cryptoMod.webcrypto.subtle;
  }

  const context = {
    console: vmConsole,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    queueMicrotask,
    Promise,
    URL,
    URLSearchParams,
    Math,
    Date,
    JSON,
    Array,
    Object,
    String,
    Number,
    Boolean,
    RegExp,
    Function,
    Symbol,
    Reflect,
    Proxy,
    Error,
    TypeError,
    RangeError,
    ReferenceError,
    SyntaxError,
    Map,
    Set,
    WeakMap,
    WeakSet,
    Int8Array,
    Uint8Array,
    Uint8ClampedArray,
    Int16Array,
    Uint16Array,
    Int32Array,
    Uint32Array,
    Float32Array,
    Float64Array,
    ArrayBuffer,
    DataView,
    TextEncoder,
    TextDecoder,

    btoa: (s) => Buffer.from(String(s || ''), 'binary').toString('base64'),
    atob: (s) => Buffer.from(String(s || ''), 'base64').toString('binary'),
    unescape,
    encodeURIComponent,
    decodeURIComponent,
    encodeURI,
    decodeURI,
    parseInt,
    parseFloat,
    isFinite,
    isNaN,
    NaN,
    Infinity,
    undefined,
    Intl: { ...Intl, DateTimeFormat: PatchedDTF },

    crypto: cryptoObj,

    performance: {
      now: () => performance.now(),
      timeOrigin: performance.timeOrigin,
        memory: { jsHeapSizeLimit },
      getEntriesByType: () => [],
      getEntriesByName: () => [],
      mark: () => {},
      measure: () => {},
    },

    screen: {
      width: screenW,
      height: screenH,
      availWidth: screenAvailW,
      availHeight: screenAvailH,
      availLeft: 0,
      availTop: 0,
      colorDepth,
      pixelDepth: colorDepth,
      orientation: { type: 'landscape-primary', angle: 0 },
    },

    navigator: navigatorObj,

    history: {
      length: 1, state: null,
      back() {}, forward() {}, go() {},
      pushState() {}, replaceState() {},
    },

    localStorage: createStorage(),
    sessionStorage: createStorage(),

    innerWidth: innerW,
    innerHeight: innerH,
    outerWidth: outerW,
    outerHeight: outerH,
    devicePixelRatio: Number(input.device_pixel_ratio || 1),
    scrollX: 0,
    scrollY: 0,
    pageXOffset: 0,
    pageYOffset: 0,

    requestAnimationFrame: (cb) => { setTimeout(cb, 16); return 1; },
    cancelAnimationFrame: () => {},
    requestIdleCallback: (cb) => {
      if (typeof cb === 'function') cb({ didTimeout: false, timeRemaining: () => 50 });
      return 1;
    },
    cancelIdleCallback: () => {},

    getComputedStyle: () => ({ getPropertyValue() { return ''; } }),
    matchMedia: (query) => ({
      media: String(query || ''),
      matches: false,
      onchange: null,
      addListener() {}, removeListener() {},
      addEventListener() {}, removeEventListener() {},
      dispatchEvent() { return false; },
    }),

    Event: class Event {
      constructor(type, init) {
        this.type = type;
        this.bubbles = (init && init.bubbles) || false;
        this.cancelable = (init && init.cancelable) || false;
      }
    },
    CustomEvent: class CustomEvent {
      constructor(type, init) {
        this.type = type;
        this.detail = init && Object.prototype.hasOwnProperty.call(init, 'detail') ? init.detail : null;
      }
    },
    AbortController: globalThis.AbortController,
    AbortSignal: globalThis.AbortSignal,
    MessageChannel: class MessageChannel {
      constructor() {
        this.port1 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
        this.port2 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
      }
    },

    chrome: { runtime: {}, app: {} },
    CSS: { supports() { return true; } },
    indexedDB: {
      open() { return { onerror: null, onsuccess: null, onupgradeneeded: null, result: {}, error: null }; },
      deleteDatabase() { return {}; },
    },

    fetch: async () => { throw new Error('fetch should not be called'); },
    postMessage: () => {},

    addEventListener: addListener,
    removeEventListener: removeListener,
    dispatchEvent: (event) => { dispatch(event.type, event); return true; },

    origin: pageOrigin,

    location: {
      href: pageUrl.href,
      origin: pageUrl.origin,
      protocol: pageUrl.protocol,
      host: pageUrl.host,
      hostname: pageUrl.hostname,
      pathname: pageUrl.pathname,
      search: pageUrl.search,
      hash: pageUrl.hash,
      assign() {},
      replace() {},
      reload() {},
    },

    document: {
      readyState: 'complete',
      hidden: false,
      visibilityState: 'visible',
      referrer: pageUrl.href,
      URL: pageUrl.href,
      documentURI: pageUrl.href,
      location: {
        href: pageUrl.href,
        origin: pageUrl.origin,
        pathname: pageUrl.pathname,
        search: pageUrl.search,
      },
      cookie: 'oai-did=' + encodeURIComponent(input.device_id || ''),
      title: '',
      characterSet: 'UTF-8',
      contentType: 'text/html',
      scripts,
      currentScript: {
        src: sdkUrl,
        getAttribute() { return null; },
      },
      documentElement,
      body: bodyEl,
      head: genericElement('head'),
      createElement(tag) {
        const t = String(tag || '').toLowerCase();
      if (t === 'canvas') return canvasElement(input);
        if (t === 'iframe') {
          iframeObject = genericElement('iframe');
          iframeObject._load = [];
          iframeObject.addEventListener = (type, cb) => {
            if (type === 'load') iframeObject._load.push(cb);
          };
          iframeObject.removeEventListener = () => {};
          iframeObject.contentWindow = {
            postMessage(message, origin) {
              capturedProof = message.p;
              const result = input.action === 'solve'
                ? { cachedChatReq: input.challenge, cachedProof: input.request_p || message.p }
                : null;
              const ev = {
                source: iframeObject.contentWindow,
                data: { type: 'response', requestId: message.requestId, result },
                origin,
              };
              setTimeout(() => {
                for (const cb of [...(_listeners.get('message') || [])]) {
                  try { cb(ev); } catch (_) {}
                }
              }, 0);
            },
          };
          return iframeObject;
        }
        const el = genericElement(tag);
        if (t === 'script') scripts.push(el);
        return el;
      },
      createElementNS(_ns, tag) { return this.createElement(tag); },
      createDocumentFragment() { return genericElement('fragment'); },
      createTextNode(text) { return { nodeType: 3, textContent: text }; },
      createComment(text) { return { nodeType: 8, textContent: text }; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      getElementById() { return null; },
      getElementsByTagName(tag) { return tag === 'script' ? scripts : []; },
      getElementsByClassName() { return []; },
      addEventListener: addListener,
      removeEventListener: removeListener,
      dispatchEvent(event) { dispatch(event.type, event); return true; },
    },
  };

  context.window = context;
  context.globalThis = context;
  context.self = context;
  context.top = context;
  context.parent = context;

  // ─── Create VM sandbox & load SDK ────────────────────────────────────────────

  vm.createContext(context);
  sdkScript.runInContext(context, { timeout: 10000 });

  return {
    context,
    dispatch,
    getCapturedProof: () => capturedProof,
  };
}

// ─── Action dispatch ──────────────────────────────────────────────────────────

async function runAction(input, env) {
  const context = env.context;
  const action = input.action;
  const flow = String(input.flow || 'authorize_continue');

  if (action === 'requirements') {
    try {
      // init() keeps waiting for a browser lifecycle signal in this VM, while
      // the iframe bridge normally captures the proof almost immediately.
      Promise.resolve(context.SentinelSDK.init(flow)).catch(() => {});
      const proofDeadline = Date.now() + 500;
      while (!env.getCapturedProof() && Date.now() < proofDeadline) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      if (env.getCapturedProof()) {
        return { request_p: env.getCapturedProof() };
      }
    } catch (_) {}
    const requestP = await context.__debugP.getRequirementsToken();
    return { request_p: requestP };
  }

  if (action === 'solve') {
    let primaryError = '';

    try {
      // Execute only the SDK call.  A protocol VM has no user, DOM, or real
      // pointer/keyboard stream and must not fabricate those observations.
      const mainTokenPromise = context.SentinelSDK.token(flow);
      const mainToken = await Promise.race([
        mainTokenPromise,
        new Promise((_, rej) => setTimeout(() => rej(new Error('SDK token timeout')), 8000)),
      ]);
      if (mainToken) {
        let soToken = '';
        try {
          soToken = await Promise.race([
            context.SentinelSDK.sessionObserverToken(flow),
            new Promise((_, rej) => setTimeout(() => rej(new Error('SO timeout')), 5000)),
          ]);
        } catch (_) {
          soToken = '';
        }
        return { token: mainToken, so_token: soToken || '' };
      }
    } catch (error) {
      primaryError = String((error && error.stack) || error || 'unknown');
    }

    const challenge = input.challenge || {};
    const requestP = String(input.request_p || '').trim();
    if (!requestP) throw new Error('missing request_p');
    if (!context.__debugP || typeof context.__debugP.getEnforcementToken !== 'function') {
      throw new Error('SDK token failed and debug enforcement API is unavailable: ' + primaryError);
    }
    const finalP = await context.__debugP.getEnforcementToken(challenge);
    context.SentinelSDK.__debug_bindProof(challenge, requestP);
    const dx = challenge && challenge.turnstile ? challenge.turnstile.dx : null;
    const tValue = dx ? await context.SentinelSDK.__debug_n(challenge, dx) : null;
    return { final_p: finalP, t: tValue, so_token: '' };
  }

  throw new Error('unsupported action: ' + action);
}

// ─── Entry points ─────────────────────────────────────────────────────────────

async function runOneShot() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const env = buildEnv(input);
  const result = await runAction(input, env);
  // 输出刷出后立刻退出：solve 会留下 5s 兜底 timer（Promise.race 的输家），
  // 等事件循环自然结束会白白多等约 5s，一次性回退路径也因此变慢。
  process.stdout.write(JSON.stringify(result), () => process.exit(0));
}

function runServer() {
  const readline = require('node:readline');
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const emit = (obj) => { process.stdout.write(JSON.stringify(obj) + '\n'); };
  emit({ ready: true, pid: process.pid, node: process.version, sdk_bytes: sdkRaw.length });

  let chain = Promise.resolve();
  const handleLine = (line) => {
    const trimmed = String(line || '').trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      let stage = 'parse';
      const startedAt = Date.now();
      try {
        const req = JSON.parse(trimmed);
        stage = 'build';
        const buildStarted = Date.now();
        const env = buildEnv(req);
        const buildMs = Date.now() - buildStarted;
        stage = String(req.action || 'action');
        const result = await runAction(req, env);
        emit({ ok: true, result, ms: Date.now() - startedAt, build_ms: buildMs });
      } catch (error) {
        emit({
          ok: false,
          error: String((error && error.stack) || error || 'unknown'),
          stage,
          ms: Date.now() - startedAt,
        });
      }
    });
  };

  rl.on('line', handleLine);
  rl.on('close', () => {
    // stdin 关闭（父进程退出或测试用管道输入结束）：等队列处理完再退出。
    chain.then(() => process.exit(0), () => process.exit(0));
  });
}

process.on('uncaughtException', (err) => {
  process.stderr.write('[uncaught] ' + String((err && err.stack) || err) + '\n');
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  process.stderr.write('[unhandled] ' + String((err && err.stack) || err) + '\n');
  process.exit(1);
});

if (process.argv.includes('--server')) {
  runServer();
} else {
  runOneShot().catch((err) => {
    process.stderr.write(String((err && err.stack) || err));
    process.exit(1);
  });
}
