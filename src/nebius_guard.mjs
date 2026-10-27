import crypto from 'node:crypto';
import { isIP } from 'node:net';

function isPrivateIpv4(host) {
  const [a, b] = host.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

function isBlockedNetworkHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal') return true;
  if (isIP(host) === 4) return isPrivateIpv4(host);
  if (isIP(host) !== 6) return false;

  // WHATWG URL parsing canonicalizes embedded dotted IPv4 to hexadecimal words.
  const halves = host.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = (halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left).map(word => Number.parseInt(word, 16));
  const zeroPrefix = words.slice(0, 7).every(word => word === 0);
  if (zeroPrefix && words[7] <= 1) return true; // Unspecified and loopback.
  if ((words[0] & 0xfe00) === 0xfc00 || (words[0] & 0xffc0) === 0xfe80) return true;
  if ((words[0] & 0xff00) === 0xff00) return true; // Multicast is not a public tool destination.
  const mappedIpv4 = words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff;
  const compatibleIpv4 = words.slice(0, 6).every(word => word === 0);
  if (mappedIpv4 || compatibleIpv4) {
    return isPrivateIpv4(`${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`);
  }
  return false;
}

export class NebiusGuard {
  constructor(options = {}) {
    const endpoint = new URL(options.nebiusEndpoint || 'https://api.tokenfactory.nebius.com/v1');
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) {
      throw new Error('ERR_NEBIUS_ENDPOINT_MUST_BE_HTTPS');
    }
    this.nebiusEndpoint = endpoint.toString().replace(/\/$/, '');
    this.defaultModel = options.defaultModel || 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B';
    this.apiKey = options.apiKey || '';
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    this.requestTimeoutMs = options.requestTimeoutMs || 60000;
    this.maxResponseBytes = options.maxResponseBytes || 1024 * 1024;
    this.allowedTools = new Set(options.allowedTools || ['search_web', 'fetch_metric', 'calculate_risk', 'query_db']);
    this.rateLimit = options.rateLimit || { maxPerMinute: 60 };
    this.requestTimestamps = [];
    this.cache = new Map();
    this.cacheTtlMs = options.cacheTtlMs || 300000;
    this.auditLog = [];
    this.lastLogHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.activeStreams = new Map();
    this.circuitBreakerTripped = false;
  }

  _inferenceCacheKey(prompt, model, temperature, maxTokens, apiKey) {
    const credentialHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    return crypto.createHash('sha256')
      .update(JSON.stringify({ prompt, model, temperature, maxTokens, credentialHash }))
      .digest('hex');
  }

  _requireApiKey(apiKey) {
    const resolved = apiKey || this.apiKey;
    if (typeof resolved !== 'string' || resolved.trim().length === 0) {
      throw new Error('ERR_NEBIUS_API_KEY_REQUIRED');
    }
    return resolved;
  }

  _requestContext(externalSignal) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new Error('ERR_NEBIUS_TIMEOUT')), this.requestTimeoutMs);
    let abortListener;

    if (externalSignal) {
      abortListener = () => controller.abort(externalSignal.reason);
      if (externalSignal.aborted) abortListener();
      else externalSignal.addEventListener('abort', abortListener, { once: true });
    }

    return {
      controller,
      cleanup: () => {
        clearTimeout(timeout);
        if (externalSignal && abortListener) {
          externalSignal.removeEventListener('abort', abortListener);
        }
      }
    };
  }

  async _readJson(response) {
    const declaredLength = Number(response.headers.get('content-length') || 0);
    if (declaredLength > this.maxResponseBytes) {
      try { await response.body?.cancel(); } catch {}
      throw new Error('ERR_NEBIUS_RESPONSE_TOO_LARGE');
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('ERR_NEBIUS_INVALID_JSON');
    const chunks = [];
    let receivedBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        receivedBytes += value.byteLength;
        if (receivedBytes > this.maxResponseBytes) throw new Error('ERR_NEBIUS_RESPONSE_TOO_LARGE');
        chunks.push(value);
      }
    } finally {
      try { await reader.cancel(); } catch {}
      reader.releaseLock();
    }
    const text = Buffer.concat(chunks, receivedBytes).toString('utf8');

    try {
      return JSON.parse(text);
    } catch {
      throw new Error('ERR_NEBIUS_INVALID_JSON');
    }
  }

  async _request(path, { apiKey, method = 'GET', body, signal } = {}) {
    const key = this._requireApiKey(apiKey);
    const { controller, cleanup } = this._requestContext(signal);

    try {
      const response = await this.fetchImpl(`${this.nebiusEndpoint}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${key}`,
          ...(body ? { 'Content-Type': 'application/json' } : {})
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal
      });

      if (!response.ok) {
        this._appendAudit('UPSTREAM_REQUEST_FAILED', { path, status: response.status });
        throw new Error(`ERR_NEBIUS_HTTP_${response.status}`);
      }

      return { response, controller, cleanup };
    } catch (error) {
      cleanup();
      if (controller.signal.aborted) throw new Error('ERR_NEBIUS_REQUEST_ABORTED');
      throw error;
    }
  }

  async listModels({ apiKey, signal } = {}) {
    const request = await this._request('/models', { apiKey, signal });
    try {
      const payload = await this._readJson(request.response);
      if (!Array.isArray(payload?.data)) throw new Error('ERR_NEBIUS_INVALID_MODELS_RESPONSE');
      return payload.data
        .filter(model => typeof model?.id === 'string')
        .map(model => ({ id: model.id, ownedBy: model.owned_by || null }));
    } finally {
      request.cleanup();
    }
  }

  async complete({ prompt, model = this.defaultModel, apiKey, temperature = 0.2, maxTokens = 512, signal } = {}) {
    const key = this._requireApiKey(apiKey);
    if (signal?.aborted) throw new Error('ERR_NEBIUS_REQUEST_ABORTED');
    const inspection = this.inspectPrompt(prompt, {
      cacheKey: this._inferenceCacheKey(prompt, model, temperature, maxTokens, key)
    });
    if (!inspection.passed) throw new Error(inspection.reason);
    if (inspection.cached) {
      return { source: 'cache', model, content: inspection.response, usage: null, responseId: null };
    }

    const request = await this._request('/chat/completions', {
      apiKey: key,
      method: 'POST',
      signal,
      body: {
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature,
        max_tokens: maxTokens,
        stream: false
      }
    });

    try {
      const payload = await this._readJson(request.response);
      const content = payload?.choices?.[0]?.message?.content;
      if (typeof content !== 'string' || content.length === 0) {
        throw new Error('ERR_NEBIUS_INVALID_COMPLETION_RESPONSE');
      }

      const sanitizer = this.createStreamSanitizer(`nebius-completion-${crypto.randomUUID()}`);
      let safeContent;
      try {
        const checked = sanitizer.processChunk(content);
        if (checked.drop) throw new Error(checked.reason);
        const tail = sanitizer.flush();
        if (tail.drop) throw new Error(tail.reason);
        safeContent = checked.chunk + tail.chunk;
      } finally {
        sanitizer.close();
      }

      this.saveCache(inspection.cacheKey, safeContent);
      this._appendAudit('LIVE_INFERENCE_COMPLETED', {
        model,
        responseId: typeof payload.id === 'string' ? payload.id : null,
        totalTokens: Number.isFinite(payload?.usage?.total_tokens) ? payload.usage.total_tokens : null
      });

      return {
        source: 'nebius-token-factory',
        model,
        content: safeContent,
        usage: payload.usage || null,
        responseId: typeof payload.id === 'string' ? payload.id : null
      };
    } finally {
      request.cleanup();
    }
  }

  async streamCompletion({
    prompt,
    model = this.defaultModel,
    apiKey,
    temperature = 0.2,
    maxTokens = 512,
    signal,
    onChunk = () => {}
  } = {}) {
    const key = this._requireApiKey(apiKey);
    if (signal?.aborted) throw new Error('ERR_NEBIUS_REQUEST_ABORTED');
    const inspection = this.inspectPrompt(prompt, {
      cacheKey: this._inferenceCacheKey(prompt, model, temperature, maxTokens, key)
    });
    if (!inspection.passed) throw new Error(inspection.reason);
    if (inspection.cached) {
      await onChunk(inspection.response);
      return { source: 'cache', model, content: inspection.response };
    }

    const request = await this._request('/chat/completions', {
      apiKey: key,
      method: 'POST',
      signal,
      body: {
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature,
        max_tokens: maxTokens,
        stream: true
      }
    });

    const reader = request.response.body?.getReader();
    if (!reader) {
      request.cleanup();
      throw new Error('ERR_NEBIUS_STREAM_UNAVAILABLE');
    }

    const decoder = new TextDecoder();
    const sanitizer = this.createStreamSanitizer(`nebius-${crypto.randomUUID()}`);
    let buffer = '';
    let content = '';
    let receivedBytes = 0;

    const handleEvent = async (line) => {
      if (!line.startsWith('data:')) return false;
      const data = line.slice(5).trim();
      if (data === '[DONE]') return true;
      if (!data) return false;

      let payload;
      try {
        payload = JSON.parse(data);
      } catch {
        throw new Error('ERR_NEBIUS_INVALID_STREAM_EVENT');
      }
      if (payload && Object.hasOwn(payload, 'error')) {
        throw new Error('ERR_NEBIUS_STREAM_PROVIDER_ERROR');
      }

      const delta = payload?.choices?.[0]?.delta?.content;
      if (typeof delta !== 'string' || delta.length === 0) return false;
      const checked = sanitizer.processChunk(delta);
      if (checked.drop) {
        request.controller.abort(new Error(checked.reason));
        throw new Error(checked.reason);
      }

      if (checked.chunk) {
        content += checked.chunk;
        await onChunk(checked.chunk);
      }
      return false;
    };

    try {
      let done = false;
      while (!done) {
        const result = await reader.read();
        if (result.done) break;
        receivedBytes += result.value.byteLength;
        if (receivedBytes > this.maxResponseBytes) throw new Error('ERR_NEBIUS_RESPONSE_TOO_LARGE');
        buffer += decoder.decode(result.value, { stream: true });

        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (await handleEvent(line)) {
            done = true;
            break;
          }
        }
      }

      buffer += decoder.decode();
      if (!done && buffer.trim()) done = await handleEvent(buffer.trim());
      if (!done) throw new Error('ERR_NEBIUS_INCOMPLETE_STREAM');
      const tail = sanitizer.flush();
      if (tail.drop) throw new Error(tail.reason);
      if (tail.chunk) {
        content += tail.chunk;
        await onChunk(tail.chunk);
      }
      if (!content) throw new Error('ERR_NEBIUS_EMPTY_STREAM');

      this.saveCache(inspection.cacheKey, content);
      this._appendAudit('LIVE_STREAM_COMPLETED', { model, outputCharacters: content.length });
      return { source: 'nebius-token-factory', model, content };
    } catch (error) {
      request.controller.abort(error);
      throw error;
    } finally {
      sanitizer.close();
      try { await reader.cancel(); } catch {}
      request.cleanup();
    }
  }

  tripCircuitBreaker(reason) {
    this.circuitBreakerTripped = true;
    this._appendAudit('CIRCUIT_BREAKER_TRIPPED', { reason });
  }

  resetCircuitBreaker() {
    this.circuitBreakerTripped = false;
    this._appendAudit('CIRCUIT_BREAKER_RESET', {});
  }

  _appendAudit(action, details) {
    const timestamp = Date.now();
    const payload = JSON.stringify({ action, details, timestamp, prevHash: this.lastLogHash });
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const entry = { action, details, timestamp, prevHash: this.lastLogHash, hash };
    this.auditLog.push(entry);
    this.lastLogHash = hash;
    return entry;
  }

  verifyAuditChain() {
    let prev = '0000000000000000000000000000000000000000000000000000000000000000';
    for (const entry of this.auditLog) {
      if (entry.prevHash !== prev) return false;
      const expected = crypto.createHash('sha256')
        .update(JSON.stringify({ action: entry.action, details: entry.details, timestamp: entry.timestamp, prevHash: prev }))
        .digest('hex');
      if (entry.hash !== expected) return false;
      prev = entry.hash;
    }
    return true;
  }

  checkRateLimit() {
    const now = Date.now();
    const windowStart = now - 60000;
    this.requestTimestamps = this.requestTimestamps.filter(t => t > windowStart);
    if (this.requestTimestamps.length >= this.rateLimit.maxPerMinute) {
      this._appendAudit('RATE_LIMIT_EXCEEDED', { count: this.requestTimestamps.length });
      return { allowed: false, reason: 'ERR_RATE_LIMIT_EXCEEDED' };
    }
    this.requestTimestamps.push(now);
    return { allowed: true };
  }

  inspectPrompt(prompt, { cacheKey } = {}) {
    if (this.circuitBreakerTripped) {
      return { passed: false, reason: 'ERR_CIRCUIT_BREAKER_ACTIVE' };
    }

    const rate = this.checkRateLimit();
    if (!rate.allowed) {
      return { passed: false, reason: rate.reason };
    }

    if (typeof prompt !== 'string' || prompt.trim().length === 0) {
      return { passed: false, reason: 'ERR_INVALID_PROMPT' };
    }

    const lower = prompt.toLowerCase();
    const injectionPatterns = [
      'ignore previous instructions',
      'disregard all prior instructions',
      'system override: you are now',
      'dump your system prompt',
      'print your initial instructions',
      '<script>',
      '<![cdata['
    ];

    for (const pattern of injectionPatterns) {
      if (lower.includes(pattern)) {
        this._appendAudit('INJECTION_DETECTED', { pattern });
        return { passed: false, reason: 'ERR_PROMPT_INJECTION_DETECTED', pattern };
      }
    }

    const resolvedCacheKey = cacheKey || crypto.createHash('sha256').update(prompt).digest('hex');
    const cached = this.cache.get(resolvedCacheKey);
    if (cached && (Date.now() - cached.timestamp < this.cacheTtlMs)) {
      this._appendAudit('CACHE_HIT', { cacheKey: resolvedCacheKey });
      return { passed: true, cached: true, response: cached.response };
    }

    return { passed: true, cached: false, cacheKey: resolvedCacheKey };
  }

  saveCache(cacheKey, response) {
    this.cache.set(cacheKey, { response, timestamp: Date.now() });
    this._appendAudit('CACHE_STORED', { cacheKey });
  }

  validateToolCall(toolCall) {
    if (this.circuitBreakerTripped) {
      return { approved: false, violation: 'ERR_CIRCUIT_BREAKER_ACTIVE' };
    }

    if (!toolCall || typeof toolCall.name !== 'string') {
      return { approved: false, violation: 'ERR_MALFORMED_TOOL_CALL' };
    }

    if (!this.allowedTools.has(toolCall.name)) {
      this._appendAudit('UNAUTHORIZED_TOOL', { name: toolCall.name });
      return { approved: false, violation: 'ERR_UNAUTHORIZED_TOOL', toolName: toolCall.name };
    }

    let params = toolCall.arguments ?? {};
    let paramStr;
    try {
      if (typeof params === 'string') params = JSON.parse(params);
      if (!params || typeof params !== 'object' || Array.isArray(params)) {
        return { approved: false, violation: 'ERR_MALFORMED_TOOL_CALL' };
      }
      paramStr = JSON.stringify(params);
    } catch {
      return { approved: false, violation: 'ERR_MALFORMED_TOOL_CALL' };
    }

    const pending = Object.entries(params);
    while (pending.length > 0) {
      const [name, value] = pending.pop();
      if (value && typeof value === 'object') {
        pending.push(...Object.entries(value));
        continue;
      }
      if (typeof value !== 'string') continue;
      const urls = /(?:url|uri|endpoint)$/i.test(name)
        ? [value]
        : [...value.matchAll(/(?:[a-z][a-z0-9+.-]*:)?\/\/[^\s"'<>]+/gi)].map(match => match[0]);
      for (const target of urls) {
        let url;
        try {
          url = new URL(target.startsWith('//') ? `https:${target}` : target);
        } catch {
          return { approved: false, violation: 'ERR_INVALID_TOOL_URL' };
        }
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
          return { approved: false, violation: 'ERR_UNSAFE_TOOL_URL' };
        }
        if (isBlockedNetworkHost(url.hostname)) {
          this._appendAudit('SSRF_ATTEMPT_BLOCKED', { tool: toolCall.name, host: url.hostname });
          return { approved: false, violation: 'ERR_SSRF_DETECTED', blockedTarget: url.hostname };
        }
      }
    }

    if (paramStr.includes('../') || paramStr.includes('..\\')) {
      this._appendAudit('PATH_TRAVERSAL_BLOCKED', { tool: toolCall.name });
      return { approved: false, violation: 'ERR_PATH_TRAVERSAL_DETECTED' };
    }

    const shellPatterns = [';', '&&', '||', '|', '`', '$(', 'rm -rf', 'cat /etc/passwd', 'chmod '];
    for (const s of shellPatterns) {
      if (paramStr.includes(s)) {
        this._appendAudit('COMMAND_INJECTION_BLOCKED', { tool: toolCall.name, pattern: s });
        return { approved: false, violation: 'ERR_COMMAND_INJECTION_DETECTED', pattern: s };
      }
    }

    this._appendAudit('TOOL_CALL_APPROVED', { tool: toolCall.name });
    return { approved: true, toolCall };
  }

  createStreamSanitizer(streamId) {
    let pending = '';
    const secretPatterns = [
      { regex: /sk-[A-Za-z0-9]{32,}/, minimumLength: 35 },
      { regex: /AKIA[0-9A-Z]{16}/, minimumLength: 20 },
      { regex: /ghp_[A-Za-z0-9]{36}/, minimumLength: 40 },
      { regex: /nebius-[a-z0-9]{20,}/i, minimumLength: 27 },
      { regex: /v1\.[A-Za-z0-9_-]{20,}/, minimumLength: 23 }
    ];
    // Retaining this suffix ensures no supported credential's initial byte can
    // be emitted before enough following characters arrive to recognize it.
    const holdback = Math.max(...secretPatterns.map(pattern => pattern.minimumLength)) - 1;

    this.activeStreams.set(streamId, { startedAt: Date.now(), aborted: false });

    return {
      processChunk: (chunk) => {
        const stream = this.activeStreams.get(streamId);
        if (!stream || stream.aborted) {
          return { drop: true, reason: 'STREAM_ABORTED' };
        }

        pending += chunk;

        for (const { regex } of secretPatterns) {
          if (regex.test(pending)) {
            this.abortStream(streamId);
            this._appendAudit('SECRET_LEAK_PREVENTED', { streamId });
            return { drop: true, reason: 'ERR_CREDENTIAL_LEAK_PREVENTED' };
          }
        }

        let emitLength = Math.max(0, pending.length - holdback);
        // Do not split a UTF-16 surrogate pair between callback chunks.
        const last = pending.charCodeAt(emitLength - 1);
        const next = pending.charCodeAt(emitLength);
        if (last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) emitLength -= 1;
        const safe = pending.slice(0, emitLength);
        pending = pending.slice(emitLength);
        return { drop: false, chunk: safe };
      },
      flush: () => {
        const stream = this.activeStreams.get(streamId);
        if (!stream || stream.aborted) return { drop: true, reason: 'STREAM_ABORTED' };
        const chunk = pending;
        pending = '';
        return { drop: false, chunk };
      },
      close: () => {
        this.activeStreams.delete(streamId);
      }
    };
  }

  abortStream(streamId) {
    const stream = this.activeStreams.get(streamId);
    if (stream) {
      stream.aborted = true;
      this._appendAudit('STREAM_ABORTED', { streamId });
      return true;
    }
    return false;
  }
}
