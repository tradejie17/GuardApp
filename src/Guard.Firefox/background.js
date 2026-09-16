/*
 * Guard — Firefox background script.
 *
 * Firefox keeps blocking webRequest, which is a better fit than the Chromium design: the
 * detector runs inside onBeforeRequest and returns a redirect synchronously, so a restricted
 * request is stopped before it is sent and there is no race with a sleeping worker. The page is
 * a persistent background page for the same reason, so no declarativeNetRequest layer is needed
 * here.
 *
 * The policy comes from the same native-messaging link and the same cached-policy rules as the
 * Chromium build: if the Windows service is stopped, the last known policy keeps applying.
 */
'use strict';

const BROWSER_ID = 'firefox';
const REPORT_DEDUP_MS = 5000;
const RECONNECT_CHECK_MS = 60000;

let matcher = GuardDetect.createMatcher({ keywords: [] });
const recentReports = new Map();

const link = new GuardLink({
  browserId: BROWSER_ID,
  extensionVersion: browser.runtime.getManifest().version,
  log: (message) => console.log('[guard]', message),
  onPolicy: (next) => {
    matcher = GuardDetect.createMatcher(next);
    console.log('[guard] policy revision', next.revision, 'from', next.source);
  }
});

link.start();

function blockedPageUrl(result, originalUrl) {
  const params = new URLSearchParams({
    k: result.keyword,
    r: result.ruleType,
    u: originalUrl || ''
  });
  return browser.runtime.getURL('blocked.html') + '?' + params.toString();
}

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

function inspect(url, tabId) {
  if (!url || link.isPaused()) return null;

  const result = matcher.match(url);
  if (!result) return null;

  if (shouldReport(url, result.keyword)) {
    link.report({ url, keyword: result.keyword, part: result.part, tabId });
  }

  // In log-only mode the detection is recorded but the request is allowed through.
  if (!link.isBlocking()) return null;

  return blockedPageUrl(result, url);
}

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const redirectUrl = inspect(details.url, details.tabId);
    return redirectUrl ? { redirectUrl } : {};
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['blocking']
);

/* History API navigations inside a single-page app never issue a main_frame request. */
browser.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  const redirectUrl = inspect(details.url, details.tabId);
  if (redirectUrl) browser.tabs.update(details.tabId, { url: redirectUrl });
});

browser.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  const redirectUrl = inspect(details.url, details.tabId);
  if (redirectUrl) browser.tabs.update(details.tabId, { url: redirectUrl });
});

/* Kept for parity with the Chromium build, where the block page can be reached without passing
   through the detector. On Firefox it is a no-op in practice. */
browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== 'blocked-page-shown') return;
  if (!shouldReport(message.url || 'dnr:' + message.keyword, message.keyword)) return;

  link.report({
    url: message.url || '',
    keyword: message.keyword,
    part: message.ruleType === 'blockedHost' ? 'host' : 'url',
    tabId: sender.tab ? sender.tab.id : undefined
  });
});

setInterval(() => {
  if (!link.connected) link.connect();
}, RECONNECT_CHECK_MS);
