/*
 * Loads each browser's background script against a stubbed extension API.
 *
 * These scripts only ever run inside a browser, so a typo in one of them would otherwise not
 * surface until it was loaded by hand. This suite evaluates them in a VM with the WebExtension
 * surface faked out, then drives a policy push through the same path the native host uses and
 * checks the observable results: that a restricted navigation is redirected to the block page,
 * that an allowed one is untouched, and that log-only mode reports without blocking.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');

function read(...parts) {
  return readFileSync(path.join(root, ...parts), 'utf8');
}

/** A minimal stand-in for the parts of the WebExtension API the background scripts touch. */
function createBrowserStub() {
  const listeners = {};
  const calls = { tabUpdates: [], dynamicRules: [], sent: [] };
  let storage = {};
  let portMessageHandler = null;

  const event = (name) => ({
    addListener: (fn) => { listeners[name] = fn; }
  });

  const port = {
    onMessage: { addListener: (fn) => { portMessageHandler = fn; } },
    onDisconnect: { addListener: () => {} },
    postMessage: (message) => calls.sent.push(message)
  };

  const api = {
    runtime: {
      lastError: null,
      getManifest: () => ({ version: '1.0.0' }),
      getURL: (file) => 'chrome-extension://stubextensionid/' + file,
      connectNative: () => port,
      onMessage: event('runtime.onMessage'),
      onStartup: event('runtime.onStartup'),
      onInstalled: event('runtime.onInstalled')
    },
    storage: {
      local: {
        get: (_key, callback) => callback(storage),
        set: (items) => { storage = { ...storage, ...items }; }
      }
    },
    tabs: {
      update: (tabId, options) => {
        calls.tabUpdates.push({ tabId, url: options.url });
        return Promise.resolve();
      }
    },
    webNavigation: {
      onBeforeNavigate: event('onBeforeNavigate'),
      onHistoryStateUpdated: event('onHistoryStateUpdated'),
      onReferenceFragmentUpdated: event('onReferenceFragmentUpdated')
    },
    webRequest: {
      onBeforeRequest: {
        addListener: (fn) => { listeners['onBeforeRequest'] = fn; }
      }
    },
    alarms: {
      create: () => {},
      onAlarm: event('onAlarm')
    },
    declarativeNetRequest: {
      getDynamicRules: () => Promise.resolve([]),
      updateDynamicRules: (update) => {
        calls.dynamicRules.push(update);
        return Promise.resolve();
      }
    }
  };

  return { api, listeners, calls, pushPolicy: (message) => portMessageHandler(message) };
}

function load(backgroundPath, { chromiumStyle }) {
  const stub = createBrowserStub();

  // The background scripts schedule reconnect and keepalive timers that never stop. Inside the
  // sandbox they are unref'd so a test run is not held open by them.
  const unrefed = (schedule) => (...args) => {
    const timer = schedule(...args);
    if (timer && typeof timer.unref === 'function') timer.unref();
    return timer;
  };

  const sandbox = {
    console: { log: () => {}, error: () => {}, warn: () => {} },
    setTimeout: unrefed(setTimeout),
    setInterval: unrefed(setInterval),
    clearTimeout,
    clearInterval,
    URL, URLSearchParams, Date, JSON, Math, Object, Array, String, Number,
    navigator: { userAgent: 'Mozilla/5.0 Chrome/120.0.0.0' },
    importScripts: () => {} // the shared files are evaluated directly below
  };

  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  if (chromiumStyle) {
    sandbox.chrome = stub.api;
  } else {
    sandbox.browser = stub.api;
  }

  const context = vm.createContext(sandbox);
  vm.runInContext(read('src/extension-shared/guard-detect.js'), context);
  vm.runInContext(read('src/extension-shared/guard-link.js'), context);
  vm.runInContext(read(backgroundPath), context);

  return stub;
}

const POLICY = {
  type: 'config',
  revision: 7,
  paused: false,
  keywords: ['gambling'],
  blockedHosts: ['example-casino.com'],
  allowedHosts: ['docs.example.com'],
  matching: null,
  action: 'Block'
};

test('chromium: blocks a restricted navigation and reports it', () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy(POLICY);

  stub.listeners['onBeforeNavigate']({ frameId: 0, tabId: 42, url: 'https://www.google.com/search?q=online+gambling' });

  assert.equal(stub.calls.tabUpdates.length, 1);
  assert.match(stub.calls.tabUpdates[0].url, /blocked\.html\?k=gambling/);

  const report = stub.calls.sent.find((m) => m.type === 'detection');
  assert.equal(report.keyword, 'gambling');
  assert.equal(report.browser, 'chrome');
});

test('chromium: leaves an unrelated navigation alone', () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy(POLICY);

  stub.listeners['onBeforeNavigate']({ frameId: 0, tabId: 1, url: 'https://www.google.com/search?q=weather' });
  assert.equal(stub.calls.tabUpdates.length, 0);
});

test('chromium: ignores sub-frames', () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy(POLICY);

  stub.listeners['onBeforeNavigate']({ frameId: 3, tabId: 1, url: 'https://x.com/?q=gambling' });
  assert.equal(stub.calls.tabUpdates.length, 0);
});

test('chromium: log-only mode reports without blocking', () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy({ ...POLICY, action: 'LogOnly' });

  stub.listeners['onBeforeNavigate']({ frameId: 0, tabId: 5, url: 'https://x.com/?q=gambling' });

  assert.equal(stub.calls.tabUpdates.length, 0);
  assert.ok(stub.calls.sent.some((m) => m.type === 'detection'));
});

test('chromium: a pause suspends blocking', () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy({ ...POLICY, paused: true, pausedSeconds: 600 });

  stub.listeners['onBeforeNavigate']({ frameId: 0, tabId: 5, url: 'https://x.com/?q=gambling' });
  assert.equal(stub.calls.tabUpdates.length, 0);
});

test('chromium: generates declarativeNetRequest rules from the policy', async () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy(POLICY);
  await new Promise((resolve) => setTimeout(resolve, 10));

  const update = stub.calls.dynamicRules.at(-1);
  const kinds = update.addRules.map((rule) => rule.action.type);

  assert.ok(kinds.includes('allow'), 'the allowlisted host should produce an allow rule');
  assert.ok(kinds.includes('redirect'), 'keywords and blocked hosts should produce redirect rules');

  const allow = update.addRules.find((rule) => rule.action.type === 'allow');
  const redirect = update.addRules.find((rule) => rule.condition.urlFilter === 'gambling');

  assert.ok(allow.priority > redirect.priority, 'allow rules must outrank block rules');
});

test('chromium: keywords that cannot be expressed as a url filter are left to the detector', async () => {
  const stub = load('src/Guard.Chromium/background.js', { chromiumStyle: true });
  stub.pushPolicy({ ...POLICY, keywords: ['two words', 'ok-keyword', 'wild*card'] });
  await new Promise((resolve) => setTimeout(resolve, 10));

  const filters = stub.calls.dynamicRules.at(-1).addRules
    .map((rule) => rule.condition.urlFilter)
    .filter(Boolean);

  // Joined rather than compared structurally: the array crosses the VM realm boundary.
  assert.equal(filters.join(','), 'ok-keyword');
});

test('firefox: redirects a restricted request through blocking webRequest', () => {
  const stub = load('src/Guard.Firefox/background.js', { chromiumStyle: false });
  stub.pushPolicy(POLICY);

  const result = stub.listeners['onBeforeRequest']({
    url: 'https://www.example-casino.com/play', tabId: 9, type: 'main_frame'
  });

  assert.match(result.redirectUrl, /blocked\.html\?k=example-casino\.com&r=blockedHost/);
});

test('firefox: allows an allowlisted host even when it contains a keyword', () => {
  const stub = load('src/Guard.Firefox/background.js', { chromiumStyle: false });
  stub.pushPolicy(POLICY);

  const result = stub.listeners['onBeforeRequest']({
    url: 'https://docs.example.com/page?q=gambling', tabId: 9, type: 'main_frame'
  });

  assert.equal(Object.keys(result).length, 0);
});

test('firefox: log-only mode lets the request through', () => {
  const stub = load('src/Guard.Firefox/background.js', { chromiumStyle: false });
  stub.pushPolicy({ ...POLICY, action: 'LogOnly' });

  const result = stub.listeners['onBeforeRequest']({
    url: 'https://x.com/?q=gambling', tabId: 9, type: 'main_frame'
  });

  // An empty object means "do not interfere with this request". It is compared by key count
  // because the object comes from the VM realm and so is not reference-equal to a host literal.
  assert.equal(Object.keys(result).length, 0);
  assert.ok(stub.calls.sent.some((m) => m.type === 'detection'));
});
