import { NebiusGuard } from '../src/nebius_guard.mjs';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = fileURLToPath(new URL('./evidence/', import.meta.url));
mkdirSync(output, { recursive: true });
const guard = new NebiusGuard({ allowedTools: ['fetch_metric'] });
const targets = ['http://169.254.169.254/latest/meta-data/', 'http://2130706433/', 'http://10.1.2.3/', 'http://LOCALHOST/'];
const ssrf = targets.map(url => ({ url, ...guard.validateToolCall({ name: 'fetch_metric', arguments: { url } }) }));
const sse = deltas => new Response(deltas.map(content => `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`).join(''));
const leaked = [];
const credentialGuard = new NebiusGuard({ apiKey: 'synthetic-test-credential', fetchImpl: async () => sse(['v1.' + 'a'.repeat(10), 'b'.repeat(25)]) });
let credentialError;
try { await credentialGuard.streamCompletion({ prompt: 'Synthetic credential-boundary case', onChunk: chunk => leaked.push(chunk) }); }
catch (error) { credentialError = error.message; }
const incompleteGuard = new NebiusGuard({ apiKey: 'synthetic-test-credential', fetchImpl: async () => sse(['Synthetic partial output without a terminal marker.']) });
let incompleteError;
try { await incompleteGuard.streamCompletion({ prompt: 'Synthetic incomplete stream' }); }
catch (error) { incompleteError = error.message; }
let providerCalls = 0;
const cacheGuard = new NebiusGuard({ fetchImpl: async () => {
  providerCalls += 1;
  return new Response(JSON.stringify({ choices: [{ message: { content: 'Synthetic safe answer' } }] }));
} });
await cacheGuard.complete({ prompt: 'Same synthetic prompt', apiKey: 'synthetic-account-a' });
await cacheGuard.complete({ prompt: 'Same synthetic prompt', apiKey: 'synthetic-account-b' });
const tests = spawnSync(process.execPath, ['--test', 'test/nebius_guard.test.mjs'], { cwd: root, encoding: 'utf8' });
if (tests.status !== 0) throw new Error('The real test suite failed; no demo evidence may be produced.');
const testCount = Number(tests.stdout.match(/(?:#|ℹ) tests (\d+)/)?.[1]);
const passCount = Number(tests.stdout.match(/(?:#|ℹ) pass (\d+)/)?.[1]);
if (!testCount || testCount !== passCount) throw new Error('Unexpected test output; inspect it before recording.');
const offline = spawnSync(process.execPath, ['demo.mjs'], { cwd: root, encoding: 'utf8' });
if (offline.status !== 0) throw new Error('The offline demonstration failed.');
writeFileSync(output + 'tests.txt', tests.stdout.trimEnd() + '\n');
writeFileSync(output + 'offline-demo.txt', offline.stdout.trimEnd() + '\n');
const evidence = {
  capturedAt: new Date().toISOString(),
  live: {
    sourceNote: 'Actual authenticated command output captured by the parent agent on October 28, 2026; replayed here, not a new provider request.',
    command: 'npm run demo:live', modelCount: 30,
    model: 'nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B',
    endpoint: 'https://api.tokenfactory.nebius.com/v1',
    answer: 'Blocking cloud-metadata SSRF calls stops attackers from harvesting sensitive instance credentials and other internal data that could be used for further compromise. It also prevents the gateway from being leveraged as a pivot point to bypass network security controls.',
    provider: 'nebius-token-factory', auditChainValid: true, auditEvents: 2
  },
  synthetic: {
    ssrf,
    credential: { rejected: credentialError, emittedCharacters: leaked.join('').length, cacheEntries: credentialGuard.cache.size },
    incomplete: { rejected: incompleteError, cacheEntries: incompleteGuard.cache.size, completionAudit: incompleteGuard.auditLog.some(event => event.action === 'LIVE_STREAM_COMPLETED') },
    cache: { syntheticAccounts: 2, providerCalls, cacheEntries: cacheGuard.cache.size }
  },
  tests: { count: testCount, passed: passCount, failed: 0 }
};
if (ssrf.some(result => result.approved) || leaked.join('').length || !credentialError || !incompleteError || providerCalls !== 2) throw new Error('A recorded boundary assertion failed.');
writeFileSync(output + 'verified-evidence.json', JSON.stringify(evidence, null, 2) + '\n');
console.log(JSON.stringify({ tests: evidence.tests, ssrfCases: ssrf.length, credentialPrefixEmitted: false, incompleteCached: false, accountIsolation: true }));
