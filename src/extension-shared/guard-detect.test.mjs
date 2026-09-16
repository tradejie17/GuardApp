/*
 * Parity suite for the extension detector. Every case here has a twin in
 * tests/Guard.Core.Tests so the JavaScript and C# engines cannot drift apart.
 * Run with: node --test src/extension-shared/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const GuardDetect = require('./guard-detect.js');

const matcher = (...keywords) => GuardDetect.createMatcher({ keywords });

test('splits url components', () => {
  const url = GuardDetect.normalizeUrl('https://WWW.Example.COM/Articles/Test?q=Hello#Section');
  assert.equal(url.isWellFormed, true);
  assert.equal(url.host, 'www.example.com');
  assert.equal(url.path, '/articles/test');
  assert.equal(url.query, 'q=hello');
  assert.equal(url.fragment, 'section');
});

test('decodes percent encoding, plus signs and double encoding', () => {
  assert.equal(GuardDetect.normalizeUrl('https://g.com/?q=hello%20keyword').query, 'q=hello keyword');
  assert.equal(GuardDetect.normalizeUrl('https://g.com/?q=hello+keyword').query, 'q=hello keyword');
  assert.equal(GuardDetect.normalizeUrl('https://g.com/?q=hello%2520keyword').query, 'q=hello keyword');
});

test('folds full-width characters to ascii', () => {
  assert.equal(GuardDetect.normalizeUrl('https://example.com/ｋｅｙｗｏｒｄ').path, '/keyword');
});

test('handles unparseable and empty input without throwing', () => {
  assert.equal(GuardDetect.normalizeUrl('not a url at all').isWellFormed, false);
  assert.equal(GuardDetect.normalizeUrl(null).full, '');
  assert.equal(GuardDetect.normalizeUrl('https://example.com/?q=100%+of+%zz').isWellFormed, true);
});

test('truncates absurdly long urls', () => {
  const url = GuardDetect.normalizeUrl('https://example.com/' + 'a'.repeat(20000));
  assert.ok(url.full.length <= GuardDetect.MAX_URL_LENGTH);
});

for (const url of [
  'https://google.com/search?q=keyword',
  'https://google.com/search?q=hello+keyword',
  'https://google.com/search?q=hello%20keyword',
  'https://example.com/article/keyword/test',
  'https://example.com/search?q=KEYWORD',
  'https://example.com/page#keyword',
  'https://keyword.example.com/'
]) {
  test(`matches keyword in ${url}`, () => {
    const result = matcher('keyword').match(url);
    assert.ok(result && result.isMatch);
    assert.equal(result.keyword, 'keyword');
  });
}

for (const url of [
  'https://www.google.com/search?q=normal+topic',
  'https://example.com/',
  'https://example.com/keywo/rd'
]) {
  test(`allows ${url}`, () => {
    assert.equal(matcher('keyword').match(url), null);
  });
}

test('matches substrings inside larger words', () => {
  assert.ok(matcher('keyword').match('https://example.com/keyword123'));
  assert.ok(matcher('keyword').match('https://example.com/123keyword'));
  assert.ok(matcher('keyword').match('https://example.com/hello-keyword'));
});

test('matches multi-word keywords across encodings', () => {
  const m = matcher('restricted word');
  assert.ok(m.match('https://google.com/search?q=a+restricted+word+here'));
  assert.ok(m.match('https://google.com/search?q=restricted%20word'));
});

test('reports which part matched', () => {
  assert.equal(matcher('bad').match('https://bad.example.com/').part, 'host');
  assert.equal(matcher('bad').match('https://example.com/bad').part, 'path');
  assert.equal(matcher('bad').match('https://example.com/?q=bad').part, 'query');
  assert.equal(matcher('bad').match('https://example.com/#bad').part, 'fragment');
});

test('respects disabled component checks', () => {
  const m = GuardDetect.createMatcher({ keywords: ['keyword'], matching: { checkQuery: false } });
  assert.equal(m.match('https://example.com/?q=keyword'), null);
  assert.ok(m.match('https://example.com/keyword'));
});

test('respects case sensitive matching', () => {
  const m = GuardDetect.createMatcher({ keywords: ['KeyWord'], matching: { caseSensitive: true } });
  assert.ok(m.match('https://example.com/KeyWord'));
  assert.equal(m.match('https://example.com/keyword'), null);
});

test('blocks hosts and their subdomains', () => {
  const m = GuardDetect.createMatcher({ keywords: [], blockedHosts: ['example.com'] });
  assert.ok(m.match('https://example.com/anything'));
  assert.ok(m.match('https://www.example.com/'));
  assert.equal(m.match('https://example.com/').ruleType, 'blockedHost');
  assert.equal(m.match('https://notexample.com/'), null);
});

test('allowlist overrides every rule', () => {
  const m = GuardDetect.createMatcher({
    keywords: ['keyword'], blockedHosts: ['example.com'], allowedHosts: ['example.com']
  });
  assert.equal(m.match('https://example.com/keyword'), null);
  assert.ok(m.match('https://other.com/keyword'));
});

test('ignores internal browser pages', () => {
  const m = matcher('keyword', 'extensions', 'config');
  assert.equal(m.match('chrome://extensions'), null);
  assert.equal(m.match('about:config'), null);
  assert.equal(m.match('chrome-extension://abcdef/blocked.html?keyword=keyword'), null);
});

test('ignores blank and duplicate keywords', () => {
  const m = matcher('  keyword  ', 'keyword', '', '   ');
  assert.equal(m.keywordCount, 1);
  assert.ok(m.match('https://example.com/keyword'));
});

test('empty keyword list never matches', () => {
  assert.equal(GuardDetect.createMatcher({ keywords: [] }).match('https://example.com/keyword'), null);
});

test('matches inside unparseable input', () => {
  assert.ok(matcher('keyword').match('keyword'));
});
