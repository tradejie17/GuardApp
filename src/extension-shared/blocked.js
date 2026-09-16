/*
 * blocked.js — renders the block page.
 *
 * Values come from the query string of an extension-internal URL, but they are still written
 * with textContent only: the matched text originates from a URL the user typed.
 */
(function () {
  'use strict';

  var api = globalThis.browser || globalThis.chrome;
  var params = new URLSearchParams(location.search);

  var keyword = params.get('k') || 'restricted rule';
  var ruleType = params.get('r') === 'blockedHost' ? 'Blocked site' : 'Restricted keyword';

  document.getElementById('keyword').textContent = keyword;
  document.getElementById('ruleType').textContent = ruleType;
  document.getElementById('time').textContent = new Date().toLocaleString();

  // A page reached through a declarativeNetRequest redirect never passed through the background
  // detector, so tell it here to make sure the detection still reaches the service log.
  try {
    api.runtime.sendMessage({
      type: 'blocked-page-shown',
      keyword: keyword,
      ruleType: params.get('r') || 'keyword',
      url: params.get('u') || ''
    });
  } catch (e) {
    /* The background worker may be starting up; the DNR rule still did its job. */
  }
})();
