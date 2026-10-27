import { NebiusGuard } from './src/nebius_guard.mjs';

const apiKey = process.env.NEBIUS_API_KEY || process.env.NEBIUS_TOKEN_FACTORY_KEY;
if (!apiKey) {
  console.error('NEBIUS_API_KEY is required. Create it in Token Factory and export it only in your local shell.');
  process.exit(1);
}

const guard = new NebiusGuard({
  apiKey,
  nebiusEndpoint: process.env.NEBIUS_BASE_URL || 'https://api.tokenfactory.nebius.com/v1',
  requestTimeoutMs: 60000
});

const models = await guard.listModels();
const requestedModel = process.env.NEBIUS_MODEL;
const model = requestedModel || models.find(candidate => candidate.id.toLowerCase().startsWith('nvidia/'))?.id;

if (!model) {
  console.error('No NVIDIA model is available to this key. Inspect the Token Factory catalog or set NEBIUS_MODEL exactly.');
  process.exit(1);
}
if (requestedModel && !models.some(candidate => candidate.id === requestedModel)) {
  console.error(`NEBIUS_MODEL is not present in this key's live catalog: ${requestedModel}`);
  process.exit(1);
}

console.log(`Authenticated model count: ${models.length}`);
console.log(`Selected NVIDIA model: ${model}`);
console.log('Streaming through NebiusGuard:\n');

const result = await guard.streamCompletion({
  model,
  prompt: 'In two short sentences, explain why an AI agent gateway should block cloud-metadata SSRF tool calls.',
  maxTokens: 180,
  onChunk: chunk => process.stdout.write(chunk)
});

console.log('\n');
console.log(`Provider: ${result.source}`);
console.log(`Audit chain valid: ${guard.verifyAuditChain()}`);
console.log(`Audit events: ${guard.auditLog.length}`);

