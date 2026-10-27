import crypto from 'node:crypto';

export class NebiusGuard {
  constructor(options = {}) {
    const endpoint = new URL(options.nebiusEndpoint || 'https://api.tokenfactory.nebius.com/v1');
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password) {
      throw new Error('ERR_NEBIUS_ENDPOINT_MUST_BE_HTTPS');
    }
    this.nebiusEndpoint = endpoint.toString().replace(/\/$/, '');
    this.defaultModel = options.defaultModel || 'nvidia/Nemotron-3_5-Lightning';
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

  _inferenceCacheKey(prompt, model, temperature, maxTokens) {
    return crypto.createHash('sha256')
      .update(JSON.stringify({ prompt, model, temperature, maxTokens }))
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
      throw new Error('ERR_NEBIUS_RESPONSE_TOO_LARGE');
    }

    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > this.maxResponseBytes) {
      throw new Error('ERR_NEBIUS_RESPONSE_TOO_LARGE');
    }

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
    const inspection = this.inspectPrompt(prompt, {
      cacheKey: this._inferenceCacheKey(prompt, model, temperature, maxTokens)
    });
    if (!inspection.passed) throw new Error(inspection.reason);
    if (inspection.cached) {
      return { source: 'cache', model, content: inspection.response, usage: null, responseId: null };
    }

    const request = await this._request('/chat/completions', {
      apiKey,
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

      const sanitizer = this.createStreamSanitizer(`nebius-completion-${Date.now()}`);
      const checked = sanitizer.processChunk(content);
      sanitizer.close();
      if (checked.drop) throw new Error(checked.reason);

      this.saveCache(inspection.cacheKey, content);
      this._appendAudit('LIVE_INFERENCE_COMPLETED', {
        model,
        responseId: typeof payload.id === 'string' ? payload.id : null,
        totalTokens: Number.isFinite(payload?.usage?.total_tokens) ? payload.usage.total_tokens : null
      });

      return {
        source: 'nebius-token-factory',
        model,
        content,
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
    const inspection = this.inspectPrompt(prompt, {
      cacheKey: this._inferenceCacheKey(prompt, model, temperature, maxTokens)
    });
    if (!inspection.passed) throw new Error(inspection.reason);
    if (inspection.cached) {
      await onChunk(inspection.response);
      return { source: 'cache', model, content: inspection.response };
    }

    const request = await this._request('/chat/completions', {
      apiKey,
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
    const sanitizer = this.createStreamSanitizer(`nebius-${Date.now()}`);
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

      const delta = payload?.choices?.[0]?.delta?.content;
      if (typeof delta !== 'string' || delta.length === 0) return false;
      const checked = sanitizer.processChunk(delta);
      if (checked.drop) {
        request.controller.abort(new Error(checked.reason));
        throw new Error(checked.reason);
      }

      content += delta;
      await onChunk(delta);
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
      if (!done && buffer.trim()) await handleEvent(buffer.trim());
      if (!content) throw new Error('ERR_NEBIUS_EMPTY_STREAM');

      this.saveCache(inspection.cacheKey, content);
      this._appendAudit('LIVE_STREAM_COMPLETED', { model, outputCharacters: content.length });
      return { source: 'nebius-token-factory', model, content };
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

    const params = toolCall.arguments || {};
    const paramStr = JSON.stringify(params);

    const ssrfPatterns = [
      '169.254.169.254',
      'metadata.google.internal',
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '::1',
      '10.0.',
      '192.168.',
      '172.16.'
    ];

    for (const p of ssrfPatterns) {
      if (paramStr.includes(p)) {
        this._appendAudit('SSRF_ATTEMPT_BLOCKED', { tool: toolCall.name, pattern: p });
        return { approved: false, violation: 'ERR_SSRF_DETECTED', blockedTarget: p };
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
    let accumulated = '';
    const secretPatterns = [
      /sk-[A-Za-z0-9]{32,}/,
      /AKIA[0-9A-Z]{16}/,
      /ghp_[A-Za-z0-9]{36}/,
      /nebius-[a-z0-9]{20,}/i,
      /v1\.[A-Za-z0-9_-]{20,}/
    ];

    this.activeStreams.set(streamId, { startedAt: Date.now(), aborted: false });

    return {
      processChunk: (chunk) => {
        const stream = this.activeStreams.get(streamId);
        if (!stream || stream.aborted) {
          return { drop: true, reason: 'STREAM_ABORTED' };
        }

        accumulated += chunk;

        for (const regex of secretPatterns) {
          if (regex.test(accumulated)) {
            this.abortStream(streamId);
            this._appendAudit('SECRET_LEAK_PREVENTED', { streamId });
            return { drop: true, reason: 'ERR_CREDENTIAL_LEAK_PREVENTED' };
          }
        }

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
