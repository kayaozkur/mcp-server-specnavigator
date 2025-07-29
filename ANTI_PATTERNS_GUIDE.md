# Anti-Patterns Guide

*A comprehensive guide to common architectural mistakes and how to avoid them*

## Table of Contents

1. [Architecture Anti-Patterns](#architecture-anti-patterns)
2. [Performance Anti-Patterns](#performance-anti-patterns)
3. [Caching Anti-Patterns](#caching-anti-patterns)
4. [Security Anti-Patterns](#security-anti-patterns)
5. [Code Quality Anti-Patterns](#code-quality-anti-patterns)

---

## Architecture Anti-Patterns

### 1. Disconnected Systems

**What It Looks Like:**
```typescript
// ❌ AVOID: Multiple systems that don't communicate
class ServerCache { }
class GitHubActionsCache { }
// These can get out of sync
```

**Why It's Bad:**
- Data inconsistency between systems
- No single source of truth
- Debugging becomes nightmare
- Race conditions

**The Right Way:**
```typescript
// ✅ PREFER: Unified system with sync mechanism
class UnifiedCache {
  async sync(source: CacheSource): Promise<void> {
    const data = await source.getData();
    await this.updateAllLayers(data);
    await this.notifySubscribers(data);
  }
}
```

### 2. Monolithic Request Handlers

**What It Looks Like:**
```typescript
// ❌ AVOID: Giant switch statement
switch (action) {
  case 'create': { /* 50 lines */ }
  case 'update': { /* 60 lines */ }
  case 'delete': { /* 40 lines */ }
}
```

**Why It's Bad:**
- Violates single responsibility principle
- Hard to test individual actions
- Difficult to add new actions
- Code duplication

**The Right Way:**
```typescript
// ✅ PREFER: Handler registry
const handlers = new Map<string, Handler>([
  ['create', new CreateHandler()],
  ['update', new UpdateHandler()],
  ['delete', new DeleteHandler()]
]);

const handler = handlers.get(action);
if (!handler) throw new Error(`Unknown action: ${action}`);
await handler.execute(request);
```

---

## Performance Anti-Patterns

### 3. Sequential Processing

**What It Looks Like:**
```typescript
// ❌ AVOID: Sequential fetching
for (const file of files) {
  const data = await fetch(file);
  results.push(data);
}
```

**Why It's Bad:**
- Wastes time waiting for each request
- Total time = sum of all request times
- Doesn't utilize available resources

**The Right Way:**
```typescript
// ✅ PREFER: Parallel processing with limits
const results = await pLimit(5)(
  files.map(file => () => fetch(file))
);
```

### 4. No Resource Pooling

**What It Looks Like:**
```typescript
// ❌ AVOID: Creating new connections every time
async function queryDatabase(sql: string) {
  const connection = await createConnection();
  const result = await connection.query(sql);
  await connection.close();
  return result;
}
```

**Why It's Bad:**
- Connection overhead on every request
- Resource exhaustion under load
- Slower response times

**The Right Way:**
```typescript
// ✅ PREFER: Connection pooling
const pool = createPool({
  min: 2,
  max: 10,
  idleTimeout: 30000
});

async function queryDatabase(sql: string) {
  const connection = await pool.acquire();
  try {
    return await connection.query(sql);
  } finally {
    pool.release(connection);
  }
}
```

---

## Caching Anti-Patterns

### 5. Inefficient Cache Timing Strategy

**What It Looks Like:**
```typescript
// ❌ AVOID: Metadata expiring before data
const cache = {
  metadata: { ttl: 5 * 60 },    // 5 minutes
  data: { ttl: 60 * 60 }        // 1 hour
};
// Problem: Checks for updates every 5 min but data cached for 1 hour
```

**Why It's Bad:**
- Unnecessary update checks
- Metadata and data out of sync
- Inefficient resource usage

**The Right Way:**
```typescript
// ✅ PREFER: Smart cache invalidation
const cache = {
  metadata: { ttl: 60 * 60 },   // Check less frequently
  data: { ttl: 'on-change' }    // Invalidate when metadata changes
};
```

### 6. No HTTP Caching Standards

**What It Looks Like:**
```typescript
// ❌ AVOID: Checking only basic headers
const changed = headers['last-modified'] !== cached.lastModified;
```

**Why It's Bad:**
- Misses cache validation opportunities
- Doesn't respect server caching directives
- May serve stale content

**The Right Way:**
```typescript
// ✅ PREFER: Comprehensive HTTP caching
const headers = {
  'If-None-Match': cached.etag,
  'If-Modified-Since': cached.lastModified,
  'Cache-Control': 'no-cache'
};

const response = await fetch(url, { headers });
if (response.status === 304) {
  return cached.data; // Not modified
}
```

---

## Security Anti-Patterns

### 7. Security Theater

**What It Looks Like:**
```typescript
// ❌ AVOID: Security checks that don't block
try {
  await securityScan();
} catch (error) {
  console.log('Security issue found');
  // Continues anyway!
}
```

**Why It's Bad:**
- Creates false sense of security
- Vulnerabilities go to production
- Compliance without protection

**The Right Way:**
```typescript
// ✅ PREFER: Enforced security
const vulnerabilities = await securityScan();
if (vulnerabilities.critical > 0) {
  throw new SecurityError('Critical vulnerabilities found');
}
```

### 8. Missing Request Validation

**What It Looks Like:**
```typescript
// ❌ AVOID: Type casting without validation
const limit = req.query.limit as number || 10;
```

**Why It's Bad:**
- Type casting doesn't validate
- Opens door to injection attacks
- Can cause runtime errors

**The Right Way:**
```typescript
// ✅ PREFER: Schema validation
const schema = z.object({
  limit: z.number().min(1).max(100).default(10),
  offset: z.number().min(0).default(0)
});

const { limit, offset } = schema.parse(req.query);
```

---

## Code Quality Anti-Patterns

### 9. Silent Failures

**What It Looks Like:**
```typescript
// ❌ AVOID: Swallowing errors
try {
  await fetchData();
} catch (error) {
  console.log(error); // Just logs, continues
}
```

**Why It's Bad:**
- Hides problems
- Makes debugging difficult
- Can cause data corruption
- No recovery strategy

**The Right Way:**
```typescript
// ✅ PREFER: Proper error handling
try {
  await fetchData();
} catch (error) {
  metrics.recordError(error);
  
  if (isRecoverable(error)) {
    return await fallbackStrategy();
  }
  
  throw new DataFetchError(error);
}
```

### 10. Dead Code

**What It Looks Like:**
```typescript
// ❌ AVOID: Implementing features that aren't used
class AdvancedFeature {
  // 200 lines of unused code
}
```

**Why It's Bad:**
- Increases maintenance burden
- Confuses developers
- May have security vulnerabilities
- Wastes build time

**The Right Way:**
```typescript
// ✅ PREFER: Test-driven development
describe('Feature', () => {
  it('should be used', () => {
    const usage = findUsages('AdvancedFeature');
    expect(usage.length).toBeGreaterThan(0);
  });
});
```

### 11. No Error Recovery Strategy

**What It Looks Like:**
```typescript
// ❌ AVOID: Single point of failure
try {
  const data = await fetch(url);
} catch (error) {
  throw new Error('Failed to fetch');
}
```

**Why It's Bad:**
- No resilience
- Single failure crashes system
- Poor user experience

**The Right Way:**
```typescript
// ✅ PREFER: Fallback chain
const fallbacks = [
  () => fetch(primaryUrl),
  () => fetch(cdnUrl),
  () => fetch(mirrorUrl),
  () => loadFromCache(),
  () => loadFromDisk()
];

for (const fallback of fallbacks) {
  try {
    return await fallback();
  } catch (error) {
    continue;
  }
}
```

### 12. All-or-Nothing Updates

**What It Looks Like:**
```typescript
// ❌ AVOID: No granular change tracking
if (newContent !== oldContent) {
  invalidateEverything();
}
```

**Why It's Bad:**
- Inefficient cache invalidation
- Unnecessary processing
- Poor performance

**The Right Way:**
```typescript
// ✅ PREFER: Incremental updates
const changes = diff(oldContent, newContent);
for (const change of changes) {
  invalidateSection(change.path);
  updateSection(change.path, change.value);
}
```

### 13. Hardcoded Values

**What It Looks Like:**
```typescript
// ❌ AVOID: Hardcoded configuration
const CACHE_TTL = 3600;
const API_URL = 'https://api.example.com';
```

**Why It's Bad:**
- Can't change without deployment
- Different values for different environments
- Security risk for sensitive data

**The Right Way:**
```typescript
// ✅ PREFER: Configuration management
const config = {
  cache: {
    ttl: env.CACHE_TTL || 3600,
    maxSize: env.CACHE_MAX_SIZE || 1000
  },
  api: {
    url: env.API_URL || 'https://api.example.com',
    timeout: env.API_TIMEOUT || 5000
  }
};
```

### 14. Premature Optimization

**What It Looks Like:**
```typescript
// ❌ AVOID: Complex optimization without metrics
class SuperOptimizedCache {
  // 500 lines of complex caching logic
}
```

**Why It's Bad:**
- Adds complexity without proven need
- Harder to maintain
- May not improve performance
- Could introduce bugs

**The Right Way:**
```typescript
// ✅ PREFER: Simple solution first, optimize based on metrics
class SimpleCache {
  private cache = new Map();
  
  get(key: string) {
    return this.cache.get(key);
  }
}
```

### 15. Missing Observability

**What It Looks Like:**
```typescript
// ❌ AVOID: Black box operations
async function processData(data: any) {
  const result = await transform(data);
  await save(result);
  return result;
}
```

**Why It's Bad:**
- Can't track performance
- No visibility into failures
- Difficult to debug
- No metrics for optimization

**The Right Way:**
```typescript
// ✅ PREFER: Observable operations
async function processData(data: any) {
  const span = tracer.startSpan('processData');
  const timer = metrics.timer('process_data_duration');
  
  try {
    logger.info('Processing data', { size: data.length });
    
    const result = await transform(data);
    metrics.counter('data_transformed', { type: data.type });
    
    await save(result);
    metrics.counter('data_saved');
    
    return result;
  } catch (error) {
    logger.error('Failed to process data', error);
    metrics.counter('process_data_error', { error: error.name });
    throw error;
  } finally {
    span.finish();
    timer.end();
  }
}
```

---

## Key Takeaways

1. **Avoid disconnected systems** - Always design with integration in mind
2. **Handle errors properly** - Silent failures are worse than loud ones
3. **Design for observability** - You can't fix what you can't see
4. **Validate everything** - Never trust input, always validate
5. **Keep it simple** - Complexity is the enemy of reliability

Remember: These anti-patterns often appear gradually as systems evolve. Regular code reviews and architectural assessments can help catch them early.