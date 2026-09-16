/*
 * Guard — Chromium background service worker (Chrome, Edge, Avast Secure Browser).
 *
 * Two independent layers stop a restricted navigation:
 *
 *   1. declarativeNetRequest rules, generated from the keyword list. These are evaluated by the
 *      browser itself, so they work even while this service worker is asleep and there is no
 *      window in which a request can slip through.
 *   2. This worker's webNavigation handler, which runs the full detector. It catches what DNR
 *      cannot express — keywords containing spaces, percent-encoded and double-encoded forms,
 *      full-width look-alikes — and it is what reports detections to the Windows service.
 *
 * Neither layer asks the service for permission at navigation time: the policy is cached
 * locally, so the block happens instantly and still happens if the service is stopped.
 */
'use strict';

importScripts('guard-detect.js', 'guard-link.js');

const BROWSER_ID = detectBrowser();
const KEEPALIVE_ALARM = 'guard-keepalive';
const REPORT_DEDUP_MS = 5000;

/* DNR rule ids are regenerated wholesale on every policy change; this is the range we own. */
const RULE_ID_BASE = 1000;

let matcher = GuardDetect.createMatcher({ keywords: [] });
let policy = null;
const recentReports = new Map();

const link = new GuardLink({
  browserId: BROWSER_ID,
  extensionVersion: chrome.runtime.getManifest().version,
  log: (message) => console.log('[guard]', message),
  onPolicy: (next) => {
    policy = next;
    matcher = GuardDetect.createMatcher(next);
    syncDynamicRules(next).catch((error) => console.error('[guard] rule sync failed', error));
  }
});

link.start();

function detectBrowser() {
  // Edge and Avast are both Chromium; the user agent is the only thing that separates them and
  // it is only used for logging, never for a policy decision.
  const agent = (navigator.userAgent || '').toLowerCase();
  if (agent.includes('edg/')) return 'edge';
  if (agent.includes('avast')) return 'avast';
  return 'chrome';
}

function blockedPageUrl(result, originalUrl) {
  const params = new URLSearchParams({
    k: result.keyword,
    r: result.ruleType,
    u: originalUrl || ''
  });
  return chrome.runtime.getURL('blocked.html') + '?' + params.toString();
}

/** Suppresses duplicate reports when several listeners see the same navigation. */
function shouldReport(url, keyword) {
  const key = url + '|' + keyword;
  const now = Date.now();

  for (const [seen, at] of recentReports) {
    if (now - at > REPORT_DEDUP_MS) recentReports.delete(seen);
  }

  if (recentReports.has(key)) return false;
  recentReports.set(key, now);
  return true;
}

function evaluate(tabId, url) {
  if (!url || link.isPaused()) return;

  const result = matcher.match(url);
  if (!result) return;

  if (shouldReport(url, result.keyword)) {
    link.report({ url, keyword: result.keyword, part: result.part, tabId });
  }

  // In log-only mode the detection is still reported, but the page is left alone.
  if (!link.isBlocking()) return;

  chrome.tabs.update(tabId, { url: blockedPageUrl(result, url) }).catch(() => {
    /* The tab may already have been closed or redirected by the DNR layer. */
  });
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluate(details.tabId, details.url);
});

/* Single-page apps change the URL without a navigation event. */
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluate(details.tabId, details.url);
});

chrome.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluate(details.tabId, details.url);
});

/* A page stopped by declarativeNetRequest never reached the detector above, so the block page
   itself tells us about it and we forward the detection for logging. */
chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== 'blocked-page-shown') return;
  if (!shouldReport(message.url || 'dnr:' + message.keyword, message.keyword)) return;

  link.report({
    url: message.url || '',
    keyword: message.keyword,
    part: message.ruleType === 'blockedHost' ? 'host' : 'url',
    tabId: sender.tab ? sender.tab.id : undefined
  });
});

/*
 * declarativeNetRequest rule generation.
 *
 * urlFilter is a literal substring match, but '*', '^' and '|' are wildcards inside it and the
 * filter is matched against the raw URL. Keywords that contain those characters, or spaces, or
 * non-ASCII text, therefore cannot be expressed faithfully as a rule; they are skipped here and
 * handled by the detector above instead of being turned into a rule that over-blocks.
 */
function isDnrSafeKeyword(keyword) {
  if (!keyword || keyword.length < 2) return false;
  if (/[\s*^|]/.test(keyword)) return false;
  return /^[\x21-\x7e]+$/.test(keyword);
}

function buildRules(current) {
  const rules = [];
  let id = RULE_ID_BASE;

  // Allow rules carry the higher priority so an allowlisted host survives every block rule.
  (current.allowedHosts || []).forEach((host) => {
    rules.push({
      id: id++,
      priority: 3,
      action: { type: 'allow' },
      condition: { requestDomains: [host], resourceTypes: ['main_frame'] }
    });
  });

  (current.blockedHosts || []).forEach((host) => {
    rules.push({
      id: id++,
      priority: 2,
      action: {
        type: 'redirect',
        redirect: { extensionPath: '/blocked.html?k=' + encodeURIComponent(host) + '&r=blockedHost' }
      },
      condition: { requestDomains: [host], resourceTypes: ['main_frame'] }
    });
  });

  (current.keywords || []).filter(isDnrSafeKeyword).forEach((keyword) => {
    rules.push({
      id: id++,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: { extensionPath: '/blocked.html?k=' + encodeURIComponent(keyword) + '&r=keyword' }
      },
      condition: {
        urlFilter: keyword,
        isUrlFilterCaseSensitive: false,
        resourceTypes: ['main_frame']
      }
    });
  });

  return rules;
}

async function syncDynamicRules(current) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((rule) => rule.id);

  // While protection is paused, or the policy is log-only, the browser-level rules come down
  // entirely; a pause has an absolute expiry, after which the next policy push or keepalive
  // puts them back.
  const addRules = (link.isPaused() || !link.isBlocking()) ? [] : buildRules(current);

  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  console.log('[guard]', addRules.length, 'dynamic rules active');
}

/*
 * MV3 service workers are evicted when idle. The alarm wakes this one regularly so the native
 * port is re-established, a lapsed pause is undone, and the rule set is proven to still match
 * the cached policy.
 */
chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== KEEPALIVE_ALARM) return;
  if (!link.connected) link.connect();
  if (policy) syncDynamicRules(policy).catch(() => {});
});

chrome.runtime.onStartup.addListener(() => link.start());
chrome.runtime.onInstalled.addListener(() => link.start());
