/*
 * guard-detect.js — URL normalization and literal keyword matching.
 *
 * This is a deliberate mirror of Guard.Core.Detection (UrlNormalizer / KeywordMatcher) in the
 * Windows service. The extension needs to decide locally and synchronously so a navigation can
 * be stopped before the request leaves the machine; the service re-runs the same rules when it
 * receives the report. Any change here must be made in the C# engine too, and both test suites
 * (tests/Guard.Core.Tests and src/extension-shared/guard-detect.test.mjs) cover the same cases.
 */
(function (root) {
  'use strict';

  var MAX_URL_LENGTH = 8192;
  var MAX_DECODE_PASSES = 3;

  var INTERNAL_SCHEMES = [
    'chrome:', 'chrome-extension:', 'edge:', 'about:', 'moz-extension:',
    'devtools:', 'view-source:', 'data:', 'blob:'
  ];

  var DEFAULT_MATCHING = {
    caseSensitive: false,
    decodeUrl: true,
    normalizeUnicode: true,
    checkHost: true,
    checkPath: true,
    checkQuery: true,
    checkFragment: true
  };

  function withDefaults(options) {
    var merged = {};
    for (var key in DEFAULT_MATCHING) {
      merged[key] = options && options[key] !== undefined ? !!options[key] : DEFAULT_MATCHING[key];
    }
    return merged;
  }

  function decodeRepeatedly(text) {
    var current = text;
    for (var pass = 0; pass < MAX_DECODE_PASSES; pass++) {
      var decoded;
      try {
        decoded = decodeURIComponent(current);
      } catch (e) {
        // A stray '%' that is not a valid escape; keep what we already have.
        return current;
      }
      if (decoded === current) {
        return decoded;
      }
      current = decoded;
    }
    return current;
  }

  function canonicalize(value, options) {
    if (!value) {
      return '';
    }
    var text = String(value);
    var opts = withDefaults(options);

    if (opts.decodeUrl) {
      // '+' is a space in form encoding; decode it before unescaping, as browsers do.
      text = text.split('+').join(' ');
      text = decodeRepeatedly(text);
    }

    if (opts.normalizeUnicode && typeof text.normalize === 'function') {
      try {
        text = text.normalize('NFKC');
      } catch (e) {
        // Lone surrogates cannot be normalized; matching the raw text is better than skipping.
      }
    }

    if (!opts.caseSensitive) {
      text = text.toLowerCase();
    }

    return text;
  }

  function normalizeUrl(rawUrl, options) {
    var opts = withDefaults(options);
    var raw = rawUrl == null ? '' : String(rawUrl);
    if (raw.length > MAX_URL_LENGTH) {
      raw = raw.substring(0, MAX_URL_LENGTH);
    }

    var full = canonicalize(raw, opts);
    var parsed = null;
    try {
      parsed = new URL(raw);
    } catch (e) {
      parsed = null;
    }

    if (!parsed) {
      return {
        original: raw, scheme: '', host: '', path: '', query: '', fragment: '',
        full: full, isWellFormed: false
      };
    }

    var query = parsed.search.charAt(0) === '?' ? parsed.search.substring(1) : parsed.search;
    var fragment = parsed.hash.charAt(0) === '#' ? parsed.hash.substring(1) : parsed.hash;

    return {
      original: raw,
      scheme: parsed.protocol.toLowerCase(),
      host: canonicalize(parsed.hostname, opts),
      path: canonicalize(parsed.pathname, opts),
      query: canonicalize(query, opts),
      fragment: canonicalize(fragment, opts),
      full: full,
      isWellFormed: true
    };
  }

  function normalizeHosts(hosts) {
    var seen = Object.create(null);
    var out = [];
    (hosts || []).forEach(function (host) {
      if (typeof host !== 'string') return;
      var value = host.trim().replace(/^\.+/, '').toLowerCase();
      if (value && !seen[value]) {
        seen[value] = true;
        out.push(value);
      }
    });
    return out;
  }

  function matchHostList(host, list) {
    if (!host) return null;
    for (var i = 0; i < list.length; i++) {
      if (host === list[i] || host.endsWith('.' + list[i])) {
        return list[i];
      }
    }
    return null;
  }

  /**
   * Builds a matcher over a policy snapshot.
   * policy: { keywords, blockedHosts, allowedHosts, matching }
   */
  function createMatcher(policy) {
    var settings = policy || {};
    var options = withDefaults(settings.matching);

    var seen = Object.create(null);
    var keywords = [];
    (settings.keywords || []).forEach(function (keyword) {
      if (typeof keyword !== 'string') return;
      var value = canonicalize(keyword.trim(), options);
      if (value && !seen[value]) {
        seen[value] = true;
        keywords.push(value);
      }
    });

    var blockedHosts = normalizeHosts(settings.blockedHosts);
    var allowedHosts = normalizeHosts(settings.allowedHosts);

    function findIn(haystack, part) {
      if (!haystack) return null;
      for (var i = 0; i < keywords.length; i++) {
        if (haystack.indexOf(keywords[i]) !== -1) {
          return { isMatch: true, keyword: keywords[i], part: part, ruleType: 'keyword' };
        }
      }
      return null;
    }

    function match(rawUrl) {
      var url = typeof rawUrl === 'string' ? normalizeUrl(rawUrl, options) : rawUrl;

      if (url.isWellFormed && INTERNAL_SCHEMES.indexOf(url.scheme) !== -1) {
        return null;
      }

      // The allowlist wins over every rule.
      if (url.isWellFormed && matchHostList(url.host, allowedHosts)) {
        return null;
      }

      var blocked = url.isWellFormed ? matchHostList(url.host, blockedHosts) : null;
      if (blocked) {
        return { isMatch: true, keyword: blocked, part: 'host', ruleType: 'blockedHost' };
      }

      if (keywords.length === 0) {
        return null;
      }

      if (!url.isWellFormed) {
        return findIn(url.full, 'full');
      }

      return (options.checkHost && findIn(url.host, 'host')) ||
             (options.checkPath && findIn(url.path, 'path')) ||
             (options.checkQuery && findIn(url.query, 'query')) ||
             (options.checkFragment && findIn(url.fragment, 'fragment')) ||
             null;
    }

    return {
      match: match,
      keywordCount: keywords.length,
      hasRules: keywords.length > 0 || blockedHosts.length > 0
    };
  }

  var api = {
    MAX_URL_LENGTH: MAX_URL_LENGTH,
    DEFAULT_MATCHING: DEFAULT_MATCHING,
    canonicalize: canonicalize,
    normalizeUrl: normalizeUrl,
    createMatcher: createMatcher
  };

  root.GuardDetect = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : self);
