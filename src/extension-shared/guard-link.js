/*
 * guard-link.js — the extension's connection to the Windows Guard service.
 *
 * Responsibilities:
 *   - keep a native-messaging port open to com.guard.windows and reconnect with backoff
 *   - cache the last policy the service sent, in extension storage
 *   - report detections, queuing them while the service is unreachable
 *
 * Fail-closed by design: if the native host or the service is gone, the extension keeps
 * enforcing the last policy it received rather than falling open. Killing the service is
 * therefore not a way to unblock browsing.
 */
(function (root) {
  'use strict';

  var api = root.browser || root.chrome;

  var NATIVE_HOST = 'com.guard.windows';
  var STORAGE_KEY = 'guard.policy';
  var MIN_RECONNECT_MS = 3000;
  var MAX_RECONNECT_MS = 60000;
  var MAX_QUEUED_REPORTS = 50;

  function GuardLink(settings) {
    this.browserId = settings.browserId;
    this.extensionVersion = settings.extensionVersion || '1.0.0';
    this.onPolicy = settings.onPolicy || function () {};
    this.log = settings.log || function () {};

    this.port = null;
    this.connected = false;
    this.reconnectMs = MIN_RECONNECT_MS;
    this.reconnectTimer = null;
    this.queue = [];

    /* The last policy we know about. pausedUntil is an absolute timestamp so that a pause
       expires on its own even if the service never gets to tell us it ended. */
    this.policy = {
      revision: 0,
      keywords: [],
      blockedHosts: [],
      allowedHosts: [],
      matching: null,
      action: 'Block',
      pausedUntil: 0,
      source: 'empty'
    };
  }

  GuardLink.prototype.start = function () {
    var self = this;
    this.loadCachedPolicy(function () {
      self.connect();
    });
  };

  GuardLink.prototype.loadCachedPolicy = function (done) {
    var self = this;
    try {
      var result = api.storage.local.get(STORAGE_KEY, function (items) {
        self.applyCached(items && items[STORAGE_KEY]);
        done();
      });
      // Firefox returns a promise instead of using the callback.
      if (result && typeof result.then === 'function') {
        result.then(function (items) {
          self.applyCached(items && items[STORAGE_KEY]);
          done();
        }, function () { done(); });
      }
    } catch (e) {
      this.log('failed to read cached policy: ' + e);
      done();
    }
  };

  GuardLink.prototype.applyCached = function (cached) {
    if (!cached || typeof cached !== 'object') {
      return;
    }
    cached.source = 'cache';
    this.policy = cached;
    this.onPolicy(this.policy);
    this.log('loaded cached policy revision ' + cached.revision);
  };

  GuardLink.prototype.savePolicy = function () {
    try {
      var payload = {};
      payload[STORAGE_KEY] = this.policy;
      api.storage.local.set(payload);
    } catch (e) {
      this.log('failed to cache policy: ' + e);
    }
  };

  GuardLink.prototype.connect = function () {
    var self = this;
    this.clearReconnect();

    try {
      this.port = api.runtime.connectNative(NATIVE_HOST);
    } catch (e) {
      this.log('connectNative failed: ' + e);
      this.scheduleReconnect();
      return;
    }

    this.port.onMessage.addListener(function (message) {
      self.handleMessage(message);
    });

    this.port.onDisconnect.addListener(function () {
      var error = api.runtime.lastError;
      self.connected = false;
      self.port = null;
      self.log('native host disconnected' + (error ? ': ' + error.message : ''));
      self.scheduleReconnect();
    });

    this.connected = true;
    this.reconnectMs = MIN_RECONNECT_MS;
    this.send({
      type: 'hello',
      browser: this.browserId,
      extensionVersion: this.extensionVersion
    });
    this.flushQueue();
  };

  GuardLink.prototype.scheduleReconnect = function () {
    var self = this;
    this.clearReconnect();
    var delay = this.reconnectMs;
    this.reconnectMs = Math.min(this.reconnectMs * 2, MAX_RECONNECT_MS);
    this.reconnectTimer = setTimeout(function () { self.connect(); }, delay);
  };

  GuardLink.prototype.clearReconnect = function () {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  };

  GuardLink.prototype.send = function (message) {
    if (!this.port) {
      return false;
    }
    try {
      this.port.postMessage(message);
      return true;
    } catch (e) {
      this.log('postMessage failed: ' + e);
      this.connected = false;
      this.port = null;
      this.scheduleReconnect();
      return false;
    }
  };

  GuardLink.prototype.handleMessage = function (message) {
    if (!message || typeof message !== 'object') {
      return;
    }

    if (message.type === 'config' || message.type === 'configChanged') {
      this.policy = {
        revision: message.revision || 0,
        keywords: message.keywords || [],
        blockedHosts: message.blockedHosts || [],
        allowedHosts: message.allowedHosts || [],
        matching: message.matching || null,
        action: message.action || 'Block',
        pausedUntil: message.paused ? Date.now() + (message.pausedSeconds || 0) * 1000 : 0,
        source: 'service'
      };
      this.savePolicy();
      this.onPolicy(this.policy);
      this.log('policy revision ' + this.policy.revision + ' applied');
    }
  };

  GuardLink.prototype.isPaused = function () {
    return this.policy.pausedUntil > Date.now();
  };

  /*
   * Whether a match should stop the navigation or only be recorded.
   *
   * 'LogOnly' and 'None' observe without interfering, which is the setting to run during
   * rollout. Every other action stops the navigation: actions this version does not implement
   * yet (closing the browser, locking, shutting down) are treated as at least a block, so a
   * policy written for a later version is never silently downgraded to doing nothing.
   */
  GuardLink.prototype.isBlocking = function () {
    var action = this.policy.action || 'Block';
    return action !== 'LogOnly' && action !== 'None';
  };

  /** Reports a detection, queuing it if the service is currently unreachable. */
  GuardLink.prototype.report = function (detection) {
    var message = {
      type: 'detection',
      browser: this.browserId,
      url: detection.url,
      keyword: detection.keyword,
      part: detection.part,
      tabId: detection.tabId,
      timestamp: new Date().toISOString()
    };

    if (!this.send(message)) {
      this.queue.push(message);
      if (this.queue.length > MAX_QUEUED_REPORTS) {
        this.queue.shift();
      }
    }
  };

  GuardLink.prototype.flushQueue = function () {
    var pending = this.queue;
    this.queue = [];
    for (var i = 0; i < pending.length; i++) {
      if (!this.send(pending[i])) {
        this.queue = pending.slice(i);
        return;
      }
    }
  };

  root.GuardLink = GuardLink;
})(typeof globalThis !== 'undefined' ? globalThis : self);
