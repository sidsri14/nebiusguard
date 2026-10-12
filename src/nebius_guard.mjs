import crypto from 'node:crypto';

export class NebiusGuard {
  constructor(options = {}) {
    this.nebiusEndpoint = options.nebiusEndpoint || 'https://api.studio.nebius.ai/v1';
    this.defaultModel = options.defaultModel || 'nvidia/nemotron-4-340b-instruct';
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

  inspectPrompt(prompt) {
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

    const cacheKey = crypto.createHash('sha256').update(prompt).digest('hex');
    const cached = this.cache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp < this.cacheTtlMs)) {
      this._appendAudit('CACHE_HIT', { cacheKey });
      return { passed: true, cached: true, response: cached.response };
    }

    return { passed: true, cached: false, cacheKey };
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
      /nebius-[a-z0-9]{20,}/i
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
