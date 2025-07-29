# Universal Project Architecture Template
*A comprehensive guideline for building robust, scalable, and maintainable systems*

## Table of Contents

1. [Project Overview Template](#project-overview-template)
2. [Core Architecture Principles](#core-architecture-principles)
3. [System Design Patterns](#system-design-patterns)
4. [Caching Strategy Framework](#caching-strategy-framework)
5. [Update Detection & Synchronization](#update-detection--synchronization)
6. [Error Handling & Recovery](#error-handling--recovery)
7. [Performance Optimization](#performance-optimization)
8. [Security & Validation](#security--validation)
9. [Monitoring & Observability](#monitoring--observability)
10. [Testing Strategy](#testing-strategy)
11. [CI/CD Pipeline Design](#cicd-pipeline-design)
12. [Documentation Standards](#documentation-standards)
13. [Implementation Checklist](#implementation-checklist)
14. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)

---

## Project Overview Template

### Initial Project Analysis Framework

When analyzing any project, repository, or system, use this structured approach:

```markdown
## Project: [NAME]
### Purpose
- Primary function:
- Target users:
- Key value proposition:

### Core Components
1. **Data Sources**
   - [ ] Identify all external data sources
   - [ ] Document update frequencies
   - [ ] Map data flow paths
   - [ ] Define data contracts

2. **Processing Pipeline**
   - [ ] Input validation
   - [ ] Transformation logic
   - [ ] Output generation
   - [ ] Side effects

3. **Storage Systems**
   - [ ] Cache layers
   - [ ] Persistent storage
   - [ ] Backup mechanisms
   - [ ] Data lifecycle

4. **External Interfaces**
   - [ ] API endpoints
   - [ ] Event streams
   - [ ] Webhooks
   - [ ] File systems
```

### Architecture Documentation Template

```yaml
# architecture.yaml
system:
  name: "Project Name"
  version: "1.0.0"
  description: "Concise system description"
  
components:
  - name: "Component A"
    type: "service|library|tool"
    responsibilities:
      - "Specific responsibility 1"
      - "Specific responsibility 2"
    dependencies:
      - "Component B"
      - "External Service X"
    interfaces:
      input: "Data format/protocol"
      output: "Data format/protocol"
    
data_flow:
  sources:
    - name: "Source 1"
      type: "api|file|stream|database"
      update_frequency: "realtime|hourly|daily"
      reliability: "high|medium|low"
  
  sinks:
    - name: "Output 1"
      type: "api|file|stream|database"
      delivery_guarantee: "at-least-once|exactly-once|best-effort"
```

---

## Core Architecture Principles

### 1. Single Responsibility Components

**Principle**: Each component should have ONE clear purpose.

```typescript
// ❌ BAD: Monolithic class doing everything
class SpecManager {
  fetchSpec() { }
  parseSpec() { }
  cacheSpec() { }
  validateSpec() { }
  searchSpec() { }
  exportSpec() { }
}

// ✅ GOOD: Separated concerns
class SpecFetcher {
  async fetch(url: string): Promise<RawSpec> { }
}

class SpecParser {
  async parse(raw: RawSpec): Promise<ParsedSpec> { }
}

class SpecCache {
  async get(key: string): Promise<ParsedSpec | null> { }
  async set(key: string, value: ParsedSpec): Promise<void> { }
}
```

### 2. Unified State Management

**Principle**: Avoid multiple sources of truth.

```typescript
// ❌ BAD: Multiple disconnected caches
class ServerCache { }
class ActionCache { }
class LocalCache { }

// ✅ GOOD: Unified cache with sync
interface CacheLayer {
  name: string;
  priority: number;
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
}

class UnifiedCache {
  private layers: CacheLayer[] = [
    new MemoryCache({ priority: 1 }),
    new RedisCache({ priority: 2 }),
    new DiskCache({ priority: 3 })
  ];
  
  async get(key: string): Promise<any> {
    for (const layer of this.layers) {
      const value = await layer.get(key);
      if (value) {
        // Propagate to higher priority caches
        await this.propagateUp(key, value, layer.priority);
        return value;
      }
    }
    return null;
  }
}
```

### 3. Observable Systems

**Principle**: Every action should be traceable.

```typescript
interface SystemEvent {
  id: string;
  timestamp: Date;
  type: string;
  component: string;
  data: any;
  metadata: {
    correlationId?: string;
    userId?: string;
    version?: string;
  };
}

class ObservableComponent {
  private eventBus: EventBus;
  
  async execute(operation: string, data: any) {
    const event = this.createEvent('start', operation, data);
    this.eventBus.emit(event);
    
    try {
      const result = await this.doWork(data);
      this.eventBus.emit(this.createEvent('success', operation, result));
      return result;
    } catch (error) {
      this.eventBus.emit(this.createEvent('error', operation, { error }));
      throw error;
    }
  }
}
```

---

## System Design Patterns

### 1. Resource Management Pattern

```typescript
interface Resource {
  id: string;
  acquire(): Promise<void>;
  release(): Promise<void>;
  healthCheck(): Promise<boolean>;
}

class ResourceManager<T extends Resource> {
  private pool: T[] = [];
  private inUse: Map<string, T> = new Map();
  private config: ResourceConfig;
  
  async acquire(): Promise<T> {
    // Try to get from pool
    let resource = this.pool.pop();
    
    if (!resource) {
      // Create new if under limit
      if (this.inUse.size < this.config.maxSize) {
        resource = await this.createResource();
      } else {
        // Wait for available resource
        resource = await this.waitForResource();
      }
    }
    
    // Health check before use
    if (!await resource.healthCheck()) {
      await resource.release();
      return this.acquire(); // Retry
    }
    
    this.inUse.set(resource.id, resource);
    return resource;
  }
  
  async release(resource: T): Promise<void> {
    this.inUse.delete(resource.id);
    
    if (this.pool.length < this.config.poolSize) {
      this.pool.push(resource);
    } else {
      await resource.release();
    }
  }
}
```

### 2. Circuit Breaker Pattern

```typescript
enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open'
}

class CircuitBreaker {
  private state = CircuitState.CLOSED;
  private failures = 0;
  private lastFailTime?: Date;
  private successCount = 0;
  
  constructor(
    private config: {
      failureThreshold: number;
      resetTimeout: number;
      halfOpenRequests: number;
    }
  ) {}
  
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (this.shouldAttemptReset()) {
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  private onSuccess() {
    this.failures = 0;
    
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.config.halfOpenRequests) {
        this.state = CircuitState.CLOSED;
      }
    }
  }
  
  private onFailure() {
    this.failures++;
    this.lastFailTime = new Date();
    
    if (this.failures >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }
}
```

### 3. Event Sourcing Pattern

```typescript
interface Event {
  id: string;
  type: string;
  timestamp: Date;
  data: any;
  version: number;
}

interface Aggregate {
  id: string;
  version: number;
  apply(event: Event): void;
}

class EventStore {
  private events: Map<string, Event[]> = new Map();
  
  async append(aggregateId: string, event: Event): Promise<void> {
    const events = this.events.get(aggregateId) || [];
    events.push(event);
    this.events.set(aggregateId, events);
    
    // Publish to event bus
    await this.eventBus.publish(event);
  }
  
  async getEvents(aggregateId: string, fromVersion?: number): Promise<Event[]> {
    const events = this.events.get(aggregateId) || [];
    return fromVersion 
      ? events.filter(e => e.version > fromVersion)
      : events;
  }
  
  async replay(aggregate: Aggregate): Promise<void> {
    const events = await this.getEvents(aggregate.id);
    for (const event of events) {
      aggregate.apply(event);
    }
  }
}
```

### 4. Version Control Pattern

```typescript
interface Version {
  id: string;
  hash: string;
  timestamp: Date;
  parent?: string;
  author?: string;
  message?: string;
}

class VersionManager {
  private versions: Map<string, Version> = new Map();
  private head: string | null = null;
  
  async trackChange(content: string, message?: string): Promise<Version> {
    const hash = this.calculateHash(content);
    const version: Version = {
      id: this.generateId(),
      hash,
      timestamp: new Date(),
      parent: this.head || undefined,
      message
    };
    
    // Store version
    this.versions.set(version.id, version);
    await this.storage.saveVersion(version, content);
    
    // Update head
    this.head = version.id;
    
    return version;
  }
  
  async getVersion(versionId: string): Promise<string> {
    const version = this.versions.get(versionId);
    if (!version) {
      throw new Error(`Version not found: ${versionId}`);
    }
    
    return await this.storage.loadContent(version.hash);
  }
  
  async diff(fromVersion: string, toVersion: string): Promise<ChangeSet> {
    const fromContent = await this.getVersion(fromVersion);
    const toContent = await this.getVersion(toVersion);
    
    return this.computeDiff(fromContent, toContent);
  }
  
  private calculateHash(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }
}
```

### 5. Streaming Pattern

```typescript
interface StreamProcessor<T, R> {
  process(chunk: T): Promise<R>;
  flush?(): Promise<R[]>;
}

class StreamingPipeline<T, R> {
  constructor(
    private processor: StreamProcessor<T, R>,
    private options: {
      highWaterMark?: number;
      parallel?: number;
      encoding?: BufferEncoding;
    } = {}
  ) {}
  
  async *processLargeFile(path: string): AsyncIterableIterator<R> {
    const stream = createReadStream(path, {
      highWaterMark: this.options.highWaterMark || 16384,
      encoding: this.options.encoding
    });
    
    const queue: Promise<R>[] = [];
    const maxParallel = this.options.parallel || 1;
    
    for await (const chunk of stream) {
      // Process chunks in parallel up to limit
      if (queue.length >= maxParallel) {
        yield await queue.shift()!;
      }
      
      queue.push(this.processor.process(chunk));
    }
    
    // Process remaining items
    while (queue.length > 0) {
      yield await queue.shift()!;
    }
    
    // Flush any buffered data
    if (this.processor.flush) {
      const flushed = await this.processor.flush();
      for (const item of flushed) {
        yield item;
      }
    }
  }
  
  // Transform stream for real-time processing
  createTransformStream(): Transform {
    return new Transform({
      objectMode: true,
      async transform(chunk, encoding, callback) {
        try {
          const result = await this.processor.process(chunk);
          callback(null, result);
        } catch (error) {
          callback(error);
        }
      },
      async flush(callback) {
        try {
          if (this.processor.flush) {
            const results = await this.processor.flush();
            for (const result of results) {
              this.push(result);
            }
          }
          callback();
        } catch (error) {
          callback(error);
        }
      }
    });
  }
}
```

### 6. Rollback Pattern

```typescript
interface Snapshot {
  id: string;
  timestamp: Date;
  state: any;
  metadata?: Record<string, any>;
}

class RollbackManager {
  private snapshots: Snapshot[] = [];
  private maxSnapshots = 10;
  
  async executeWithRollback<T>(
    operation: () => Promise<T>,
    options: {
      snapshotFn: () => Promise<any>;
      restoreFn: (snapshot: any) => Promise<void>;
      validateFn?: (result: T) => Promise<boolean>;
    }
  ): Promise<T> {
    // Create snapshot before operation
    const snapshot: Snapshot = {
      id: this.generateId(),
      timestamp: new Date(),
      state: await options.snapshotFn()
    };
    
    this.addSnapshot(snapshot);
    
    try {
      // Execute operation
      const result = await operation();
      
      // Validate result if validator provided
      if (options.validateFn) {
        const isValid = await options.validateFn(result);
        if (!isValid) {
          throw new ValidationError('Operation result validation failed');
        }
      }
      
      return result;
    } catch (error) {
      // Rollback on error
      logger.warn('Operation failed, rolling back', { error });
      
      try {
        await options.restoreFn(snapshot.state);
        logger.info('Rollback successful', { snapshotId: snapshot.id });
      } catch (rollbackError) {
        logger.error('Rollback failed', { 
          originalError: error,
          rollbackError 
        });
        throw new RollbackError('Failed to rollback after error', {
          originalError: error,
          rollbackError
        });
      }
      
      throw error;
    }
  }
  
  private addSnapshot(snapshot: Snapshot): void {
    this.snapshots.push(snapshot);
    
    // Maintain snapshot limit
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots.shift();
    }
  }
  
  async getSnapshots(): Promise<Snapshot[]> {
    return [...this.snapshots].reverse();
  }
  
  async restoreSnapshot(snapshotId: string): Promise<void> {
    const snapshot = this.snapshots.find(s => s.id === snapshotId);
    if (!snapshot) {
      throw new Error(`Snapshot not found: ${snapshotId}`);
    }
    
    // Implementation depends on what's being rolled back
    await this.restoreState(snapshot.state);
  }
}
```

---

## Caching Strategy Framework

### Multi-Layer Cache Architecture

```typescript
interface CacheConfig {
  ttl: number;
  maxSize: number;
  evictionPolicy: 'LRU' | 'LFU' | 'FIFO';
  warmupOnStart: boolean;
  compressionEnabled: boolean;
}

class CacheStrategy {
  private layers: CacheLayer[] = [];
  
  constructor(private config: {
    memory: CacheConfig;
    redis: CacheConfig;
    disk: CacheConfig;
  }) {
    this.initializeLayers();
  }
  
  async get<T>(key: string): Promise<CacheResult<T>> {
    const startTime = Date.now();
    
    for (const layer of this.layers) {
      const result = await layer.get(key);
      
      if (result) {
        // Record metrics
        this.metrics.recordHit(layer.name, Date.now() - startTime);
        
        // Propagate to faster layers
        await this.propagateToFasterLayers(key, result, layer);
        
        return {
          value: result,
          source: layer.name,
          age: result.metadata.age,
          ttl: result.metadata.ttl
        };
      }
    }
    
    this.metrics.recordMiss(Date.now() - startTime);
    return null;
  }
  
  async set<T>(key: string, value: T, options?: CacheOptions): Promise<void> {
    const metadata = {
      timestamp: Date.now(),
      ttl: options?.ttl || this.config.memory.ttl,
      compressed: false,
      checksum: this.calculateChecksum(value)
    };
    
    // Write to all layers based on size and importance
    const promises = this.layers.map(layer => {
      if (this.shouldWriteToLayer(layer, value, options)) {
        return layer.set(key, value, metadata);
      }
    });
    
    await Promise.allSettled(promises);
  }
}
```

### Cache Invalidation Strategy

```typescript
class CacheInvalidator {
  private strategies: InvalidationStrategy[] = [
    new TTLInvalidation(),
    new VersionInvalidation(),
    new EventBasedInvalidation(),
    new DependencyInvalidation()
  ];
  
  async invalidate(pattern: string, options?: InvalidationOptions): Promise<void> {
    const plan = this.createInvalidationPlan(pattern, options);
    
    // Execute invalidation in correct order
    for (const step of plan.steps) {
      await this.executeStep(step);
    }
    
    // Verify invalidation
    if (options?.verify) {
      await this.verifyInvalidation(pattern);
    }
  }
  
  private createInvalidationPlan(pattern: string, options?: InvalidationOptions) {
    return {
      steps: [
        { layer: 'memory', pattern, immediate: true },
        { layer: 'redis', pattern, immediate: true },
        { layer: 'disk', pattern, immediate: false },
        { layer: 'cdn', pattern, immediate: false }
      ],
      dependencies: this.findDependencies(pattern),
      notifications: this.getSubscribers(pattern)
    };
  }
}

// Smart cache warming
class CacheWarmer {
  async warmup(strategy: WarmupStrategy): Promise<void> {
    const items = await strategy.getItemsToWarm();
    
    // Parallel warming with rate limiting
    const limiter = new RateLimiter(10); // 10 concurrent
    
    await Promise.allSettled(
      items.map(item => 
        limiter.execute(() => this.warmItem(item))
      )
    );
  }
  
  private async warmItem(item: WarmupItem): Promise<void> {
    try {
      const data = await this.fetcher.fetch(item.source);
      await this.cache.set(item.key, data, {
        ttl: item.ttl,
        priority: item.priority
      });
    } catch (error) {
      this.logger.error(`Failed to warm ${item.key}`, error);
    }
  }
}
```

---

## Update Detection & Synchronization

### Intelligent Change Detection

```typescript
interface ChangeDetector {
  detect(source: DataSource): Promise<ChangeSet>;
}

class CompositeChangeDetector implements ChangeDetector {
  private detectors: ChangeDetector[] = [
    new HeaderChangeDetector(),    // HTTP headers
    new ContentHashDetector(),      // Content hashing
    new StructuralChangeDetector(), // AST comparison
    new SemanticChangeDetector()    // Meaning changes
  ];
  
  async detect(source: DataSource): Promise<ChangeSet> {
    const changes = await Promise.all(
      this.detectors.map(d => d.detect(source))
    );
    
    return this.mergeChangeSets(changes);
  }
}

class HeaderChangeDetector implements ChangeDetector {
  async detect(source: DataSource): Promise<ChangeSet> {
    const headers = await source.getHeaders();
    const cached = await this.cache.getHeaders(source.id);
    
    const changes: Change[] = [];
    
    // Check all relevant headers
    const relevantHeaders = [
      'last-modified',
      'etag',
      'content-length',
      'content-type',
      'x-content-version',
      'x-checksum'
    ];
    
    for (const header of relevantHeaders) {
      if (headers[header] !== cached?.[header]) {
        changes.push({
          type: 'header',
          field: header,
          oldValue: cached?.[header],
          newValue: headers[header],
          severity: this.getSeverity(header)
        });
      }
    }
    
    return { changes, timestamp: new Date() };
  }
}
```

### Synchronization Framework

```typescript
class SyncManager {
  private syncStrategies: Map<string, SyncStrategy> = new Map([
    ['realtime', new RealtimeSync()],
    ['batch', new BatchSync()],
    ['eventual', new EventualSync()],
    ['manual', new ManualSync()]
  ]);
  
  async sync(source: string, target: string, options: SyncOptions): Promise<SyncResult> {
    const strategy = this.syncStrategies.get(options.strategy) || new EventualSync();
    
    // Pre-sync validation
    await this.validateSync(source, target);
    
    // Create sync plan
    const plan = await this.createSyncPlan(source, target, options);
    
    // Execute sync with monitoring
    const monitor = new SyncMonitor(plan);
    
    try {
      const result = await strategy.execute(plan, monitor);
      
      // Post-sync validation
      await this.validateSyncResult(result);
      
      return result;
    } catch (error) {
      await this.handleSyncError(error, plan);
      throw error;
    }
  }
  
  private async createSyncPlan(source: string, target: string, options: SyncOptions) {
    const changes = await this.changeDetector.detect(source);
    
    return {
      id: generateId(),
      source,
      target,
      changes,
      strategy: options.strategy,
      priority: this.calculatePriority(changes),
      estimatedDuration: this.estimateDuration(changes),
      rollbackPlan: this.createRollbackPlan(changes)
    };
  }
}

// Conflict resolution
class ConflictResolver {
  async resolve(conflicts: Conflict[]): Promise<Resolution[]> {
    const resolutions: Resolution[] = [];
    
    for (const conflict of conflicts) {
      const resolution = await this.resolveConflict(conflict);
      resolutions.push(resolution);
    }
    
    return resolutions;
  }
  
  private async resolveConflict(conflict: Conflict): Promise<Resolution> {
    // Try automatic resolution strategies
    const strategies = [
      new TimestampResolution(),    // Newest wins
      new VersionResolution(),       // Higher version wins
      new MergeResolution(),         // Try to merge
      new CustomRuleResolution()     // Apply custom rules
    ];
    
    for (const strategy of strategies) {
      if (strategy.canResolve(conflict)) {
        return await strategy.resolve(conflict);
      }
    }
    
    // Fall back to manual resolution
    return {
      type: 'manual',
      conflict,
      requiresIntervention: true
    };
  }
}
```

---

## Error Handling & Recovery

### Comprehensive Error Framework

```typescript
// Error taxonomy
abstract class BaseError extends Error {
  constructor(
    message: string,
    public code: string,
    public severity: 'low' | 'medium' | 'high' | 'critical',
    public recoverable: boolean,
    public context?: any
  ) {
    super(message);
    this.name = this.constructor.name;
  }
  
  abstract getRecoveryStrategy(): RecoveryStrategy;
}

class NetworkError extends BaseError {
  constructor(message: string, context?: any) {
    super(message, 'NETWORK_ERROR', 'high', true, context);
  }
  
  getRecoveryStrategy(): RecoveryStrategy {
    return new RetryWithBackoffStrategy({
      maxRetries: 3,
      initialDelay: 1000,
      maxDelay: 30000,
      backoffFactor: 2
    });
  }
}

// Recovery strategies
interface RecoveryStrategy {
  attempt<T>(operation: () => Promise<T>): Promise<T>;
}

class RetryWithBackoffStrategy implements RecoveryStrategy {
  constructor(private config: RetryConfig) {}
  
  async attempt<T>(operation: () => Promise<T>): Promise<T> {
    let lastError: Error;
    
    for (let i = 0; i < this.config.maxRetries; i++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        if (!this.isRetryable(error)) {
          throw error;
        }
        
        const delay = Math.min(
          this.config.initialDelay * Math.pow(this.config.backoffFactor, i),
          this.config.maxDelay
        );
        
        await this.delay(delay);
      }
    }
    
    throw new MaxRetriesExceededError(lastError);
  }
  
  private isRetryable(error: any): boolean {
    return error.name === 'NetworkError' || 
           error.name === 'TimeoutError' ||
           error.code === 'ECONNRESET' ||
           error.code === 'ETIMEDOUT';
  }
  
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Fallback chain
class FallbackChain {
  constructor(private fallbacks: FallbackOption[]) {}
  
  async execute<T>(): Promise<T> {
    const errors: Error[] = [];
    
    for (const fallback of this.fallbacks) {
      try {
        this.logger.info(`Attempting ${fallback.name}`);
        return await fallback.execute();
      } catch (error) {
        errors.push(error);
        this.logger.warn(`${fallback.name} failed:`, error);
        
        if (fallback.stopOnFailure) {
          throw new FallbackChainError(errors);
        }
      }
    }
    
    throw new AllFallbacksFailedError(errors);
  }
}

// Error aggregation and reporting
class ErrorReporter {
  private queue: ErrorReport[] = [];
  private batchSize = 100;
  private flushInterval = 5000;
  
  report(error: Error, context?: any): void {
    const report: ErrorReport = {
      id: generateId(),
      timestamp: new Date(),
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: (error as any).code
      },
      context: {
        ...context,
        environment: this.getEnvironment(),
        system: this.getSystemInfo()
      }
    };
    
    this.queue.push(report);
    
    if (this.queue.length >= this.batchSize) {
      this.flush();
    }
  }
  
  private async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    
    const reports = this.queue.splice(0, this.batchSize);
    
    try {
      await this.sendReports(reports);
    } catch (error) {
      // Put reports back if sending failed
      this.queue.unshift(...reports);
    }
  }
}
```

---

## Performance Optimization

### Performance Monitoring Framework

```typescript
class PerformanceMonitor {
  private metrics: Map<string, Metric[]> = new Map();
  
  measure<T>(name: string, operation: () => Promise<T>): Promise<T> {
    const start = performance.now();
    const startMemory = process.memoryUsage();
    
    return operation()
      .then(result => {
        this.recordSuccess(name, start, startMemory);
        return result;
      })
      .catch(error => {
        this.recordFailure(name, start, startMemory, error);
        throw error;
      });
  }
  
  private recordSuccess(name: string, start: number, startMemory: any) {
    const duration = performance.now() - start;
    const endMemory = process.memoryUsage();
    
    this.addMetric(name, {
      duration,
      memory: {
        heapUsed: endMemory.heapUsed - startMemory.heapUsed,
        external: endMemory.external - startMemory.external
      },
      success: true,
      timestamp: new Date()
    });
    
    // Check performance thresholds
    this.checkThresholds(name, duration);
  }
}

// Resource pooling
class ResourcePool<T> {
  private available: T[] = [];
  private inUse: Set<T> = new Set();
  private waiting: Array<(resource: T) => void> = [];
  
  constructor(
    private factory: () => Promise<T>,
    private config: {
      min: number;
      max: number;
      idleTimeout: number;
      acquireTimeout: number;
    }
  ) {
    this.initialize();
  }
  
  async acquire(): Promise<PooledResource<T>> {
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Acquire timeout')), this.config.acquireTimeout);
    });
    
    const resource = await Promise.race([
      this.getResource(),
      timeout
    ]);
    
    return new PooledResource(resource, () => this.release(resource));
  }
  
  private async getResource(): Promise<T> {
    // Try available pool
    const available = this.available.pop();
    if (available) {
      this.inUse.add(available);
      return available;
    }
    
    // Create new if under limit
    if (this.inUse.size < this.config.max) {
      const resource = await this.factory();
      this.inUse.add(resource);
      return resource;
    }
    
    // Wait for release
    return new Promise(resolve => {
      this.waiting.push(resolve);
    });
  }
}

// Lazy loading and pagination
class LazyLoader<T> {
  private cache: Map<number, T[]> = new Map();
  private pageSize: number;
  
  constructor(
    private loader: (offset: number, limit: number) => Promise<T[]>,
    options: { pageSize: number; preloadPages: number }
  ) {
    this.pageSize = options.pageSize;
  }
  
  async *iterate(): AsyncIterableIterator<T> {
    let page = 0;
    let hasMore = true;
    
    while (hasMore) {
      const items = await this.getPage(page);
      
      if (items.length === 0) {
        hasMore = false;
        break;
      }
      
      for (const item of items) {
        yield item;
      }
      
      page++;
      
      // Preload next page
      this.preloadPage(page + 1);
    }
  }
  
  private async getPage(page: number): Promise<T[]> {
    if (this.cache.has(page)) {
      return this.cache.get(page)!;
    }
    
    const offset = page * this.pageSize;
    const items = await this.loader(offset, this.pageSize);
    
    this.cache.set(page, items);
    return items;
  }
}
```

### Optimization Patterns

```typescript
// 1. Debouncing and throttling
class RateLimiter {
  private queues: Map<string, Array<() => Promise<any>>> = new Map();
  
  constructor(private config: {
    maxConcurrent: number;
    minTimeBetween: number;
    maxQueueSize: number;
  }) {}
  
  async execute<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const queue = this.queues.get(key) || [];
    
    if (queue.length >= this.config.maxQueueSize) {
      throw new Error('Rate limit queue full');
    }
    
    return new Promise((resolve, reject) => {
      queue.push(async () => {
        try {
          const result = await fn();
          resolve(result);
        } catch (error) {
          reject(error);
        }
      });
      
      this.queues.set(key, queue);
      this.processQueue(key);
    });
  }
}

// 2. Memoization with expiry
class Memoizer {
  private cache: Map<string, { value: any; expiry: number }> = new Map();
  
  memoize<T extends (...args: any[]) => any>(
    fn: T,
    options: { ttl: number; keyGenerator?: (...args: any[]) => string }
  ): T {
    return ((...args: any[]) => {
      const key = options.keyGenerator ? options.keyGenerator(...args) : JSON.stringify(args);
      
      const cached = this.cache.get(key);
      if (cached && cached.expiry > Date.now()) {
        return cached.value;
      }
      
      const result = fn(...args);
      
      this.cache.set(key, {
        value: result,
        expiry: Date.now() + options.ttl
      });
      
      return result;
    }) as T;
  }
}

// 3. Batch processing
class BatchProcessor<T, R> {
  private batch: T[] = [];
  private timer?: NodeJS.Timeout;
  
  constructor(
    private processor: (items: T[]) => Promise<R[]>,
    private config: {
      maxBatchSize: number;
      maxWaitTime: number;
    }
  ) {}
  
  async add(item: T): Promise<R> {
    return new Promise((resolve, reject) => {
      this.batch.push(item);
      
      if (this.batch.length >= this.config.maxBatchSize) {
        this.processBatch();
      } else if (!this.timer) {
        this.timer = setTimeout(() => this.processBatch(), this.config.maxWaitTime);
      }
    });
  }
}
```

---

## Security & Validation

### Input Validation Framework

```typescript
// Schema validation
import { z } from 'zod';

class ValidationPipeline {
  private validators: Validator[] = [];
  
  add(validator: Validator): this {
    this.validators.push(validator);
    return this;
  }
  
  async validate(input: any): Promise<ValidationResult> {
    const errors: ValidationError[] = [];
    
    for (const validator of this.validators) {
      const result = await validator.validate(input);
      
      if (!result.valid) {
        errors.push(...result.errors);
        
        if (validator.stopOnError) {
          break;
        }
      }
    }
    
    return {
      valid: errors.length === 0,
      errors,
      sanitized: this.sanitize(input)
    };
  }
}

// Request validation middleware
class RequestValidator {
  constructor(private schemas: Map<string, z.Schema>) {}
  
  validate(endpoint: string): Middleware {
    return async (req, res, next) => {
      const schema = this.schemas.get(endpoint);
      
      if (!schema) {
        return next();
      }
      
      try {
        const validated = await schema.parseAsync(req.body);
        req.body = validated;
        next();
      } catch (error) {
        if (error instanceof z.ZodError) {
          res.status(400).json({
            error: 'Validation failed',
            details: error.errors
          });
        } else {
          next(error);
        }
      }
    };
  }
}

// Security headers and sanitization
class SecurityMiddleware {
  apply(): Middleware {
    return (req, res, next) => {
      // Security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      
      // Input sanitization
      req.body = this.sanitizeInput(req.body);
      req.query = this.sanitizeInput(req.query);
      req.params = this.sanitizeInput(req.params);
      
      next();
    };
  }
  
  private sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      return this.sanitizeString(input);
    }
    
    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item));
    }
    
    if (typeof input === 'object' && input !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(input)) {
        sanitized[this.sanitizeString(key)] = this.sanitizeInput(value);
      }
      return sanitized;
    }
    
    return input;
  }
}
```

### Authentication & Authorization

```typescript
interface AuthStrategy {
  authenticate(credentials: any): Promise<User>;
  verify(token: string): Promise<User>;
}

class AuthManager {
  private strategies: Map<string, AuthStrategy> = new Map([
    ['jwt', new JWTAuthStrategy()],
    ['oauth', new OAuthStrategy()],
    ['apikey', new APIKeyStrategy()]
  ]);
  
  async authenticate(method: string, credentials: any): Promise<AuthResult> {
    const strategy = this.strategies.get(method);
    
    if (!strategy) {
      throw new Error(`Unknown auth method: ${method}`);
    }
    
    try {
      const user = await strategy.authenticate(credentials);
      const token = await this.generateToken(user);
      
      return {
        success: true,
        user,
        token,
        expiresIn: this.config.tokenExpiry
      };
    } catch (error) {
      this.auditLog.recordFailedAuth(method, credentials, error);
      throw error;
    }
  }
}

// Role-based access control
class AccessControl {
  private permissions: Map<string, Set<string>> = new Map();
  
  can(user: User, action: string, resource: string): boolean {
    const userPermissions = this.getUserPermissions(user);
    const requiredPermission = `${action}:${resource}`;
    
    return userPermissions.has(requiredPermission) || 
           userPermissions.has(`${action}:*`) ||
           userPermissions.has('*:*');
  }
  
  enforce(action: string, resource: string): Middleware {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      if (!this.can(req.user, action, resource)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      
      next();
    };
  }
}
```

---

## Monitoring & Observability

### Structured Logging

```typescript
enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  FATAL = 4
}

interface LogContext {
  correlationId: string;
  userId?: string;
  requestId?: string;
  service: string;
  environment: string;
  version: string;
}

class StructuredLogger {
  constructor(
    private context: LogContext,
    private transports: LogTransport[]
  ) {}
  
  log(level: LogLevel, message: string, data?: any): void {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: LogLevel[level],
      message,
      data,
      context: this.context,
      stack: level >= LogLevel.ERROR ? new Error().stack : undefined
    };
    
    this.transports.forEach(transport => {
      transport.write(entry);
    });
  }
  
  // Contextual logging
  child(additionalContext: Partial<LogContext>): StructuredLogger {
    return new StructuredLogger(
      { ...this.context, ...additionalContext },
      this.transports
    );
  }
}

// Log aggregation
class LogAggregator {
  private buffer: LogEntry[] = [];
  private flushInterval = 5000;
  
  aggregate(entry: LogEntry): void {
    this.buffer.push(entry);
    
    // Pattern detection
    this.detectPatterns(entry);
    
    // Anomaly detection
    if (this.isAnomaly(entry)) {
      this.alerting.sendAlert({
        type: 'log_anomaly',
        severity: 'high',
        entry
      });
    }
  }
  
  private detectPatterns(entry: LogEntry): void {
    // Error rate spike detection
    if (entry.level === 'ERROR') {
      const recentErrors = this.getRecentErrors(60000); // Last minute
      if (recentErrors.length > this.config.errorThreshold) {
        this.alerting.sendAlert({
          type: 'error_spike',
          count: recentErrors.length,
          threshold: this.config.errorThreshold
        });
      }
    }
  }
}
```

### Metrics Collection

```typescript
interface MetricCollector {
  counter(name: string, value?: number, tags?: Record<string, string>): void;
  gauge(name: string, value: number, tags?: Record<string, string>): void;
  histogram(name: string, value: number, tags?: Record<string, string>): void;
  timer(name: string): Timer;
}

class PrometheusCollector implements MetricCollector {
  private registry: Registry;
  
  counter(name: string, value: number = 1, tags?: Record<string, string>): void {
    const counter = this.getOrCreateCounter(name);
    counter.inc(tags, value);
  }
  
  gauge(name: string, value: number, tags?: Record<string, string>): void {
    const gauge = this.getOrCreateGauge(name);
    gauge.set(tags, value);
  }
  
  histogram(name: string, value: number, tags?: Record<string, string>): void {
    const histogram = this.getOrCreateHistogram(name);
    histogram.observe(tags, value);
  }
  
  timer(name: string): Timer {
    return new Timer((duration) => {
      this.histogram(`${name}_duration_ms`, duration);
    });
  }
}

// Business metrics
class BusinessMetrics {
  constructor(private collector: MetricCollector) {}
  
  recordRequest(endpoint: string, method: string, status: number, duration: number): void {
    this.collector.counter('http_requests_total', 1, {
      endpoint,
      method,
      status: status.toString()
    });
    
    this.collector.histogram('http_request_duration_ms', duration, {
      endpoint,
      method
    });
    
    if (status >= 500) {
      this.collector.counter('http_errors_total', 1, {
        endpoint,
        method,
        type: 'server_error'
      });
    }
  }
  
  recordBusinessEvent(event: string, value?: number, metadata?: any): void {
    this.collector.counter(`business_event_${event}`, value || 1, metadata);
  }
}
```

### Distributed Tracing

```typescript
interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  startTime: number;
  endTime?: number;
  tags: Record<string, any>;
  logs: Array<{ timestamp: number; fields: Record<string, any> }>;
}

class TracingManager {
  private activeSpans: Map<string, Span> = new Map();
  
  startSpan(operationName: string, parentSpan?: Span): Span {
    const span: Span = {
      traceId: parentSpan?.traceId || this.generateTraceId(),
      spanId: this.generateSpanId(),
      parentSpanId: parentSpan?.spanId,
      operationName,
      startTime: Date.now(),
      tags: {},
      logs: []
    };
    
    this.activeSpans.set(span.spanId, span);
    return span;
  }
  
  finishSpan(span: Span): void {
    span.endTime = Date.now();
    this.activeSpans.delete(span.spanId);
    
    // Send to tracing backend
    this.send(span);
  }
  
  // Context propagation
  inject(span: Span, carrier: any): void {
    carrier['x-trace-id'] = span.traceId;
    carrier['x-span-id'] = span.spanId;
  }
  
  extract(carrier: any): Span | null {
    const traceId = carrier['x-trace-id'];
    const parentSpanId = carrier['x-span-id'];
    
    if (!traceId) return null;
    
    return {
      traceId,
      spanId: this.generateSpanId(),
      parentSpanId,
      operationName: 'unknown',
      startTime: Date.now(),
      tags: {},
      logs: []
    };
  }
}
```

### Health Checks

```typescript
interface HealthCheck {
  name: string;
  check(): Promise<HealthStatus>;
}

class HealthMonitor {
  private checks: HealthCheck[] = [];
  
  register(check: HealthCheck): void {
    this.checks.push(check);
  }
  
  async checkHealth(): Promise<OverallHealth> {
    const results = await Promise.allSettled(
      this.checks.map(check => 
        this.executeCheck(check)
      )
    );
    
    const statuses = results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          name: this.checks[index].name,
          status: 'unhealthy',
          error: result.reason.message
        };
      }
    });
    
    return {
      status: this.calculateOverallStatus(statuses),
      checks: statuses,
      timestamp: new Date()
    };
  }
  
  private async executeCheck(check: HealthCheck): Promise<HealthStatus> {
    const timeout = new Promise<HealthStatus>((_, reject) => {
      setTimeout(() => reject(new Error('Health check timeout')), 5000);
    });
    
    return Promise.race([check.check(), timeout]);
  }
}

// Example health checks
class DatabaseHealthCheck implements HealthCheck {
  name = 'database';
  
  async check(): Promise<HealthStatus> {
    try {
      await this.db.query('SELECT 1');
      return { name: this.name, status: 'healthy' };
    } catch (error) {
      return { 
        name: this.name, 
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// MCP-specific monitoring
class MCPServerMonitor {
  private metrics: MetricCollector;
  private logger: StructuredLogger;
  
  constructor(metrics: MetricCollector, logger: StructuredLogger) {
    this.metrics = metrics;
    this.logger = logger;
  }
  
  // Monitor tool invocations
  async monitorToolCall(toolName: string, execute: () => Promise<any>): Promise<any> {
    const timer = this.metrics.timer(`mcp_tool_${toolName}_duration`);
    const startMemory = process.memoryUsage();
    
    try {
      this.metrics.counter('mcp_tool_calls_total', 1, { tool: toolName });
      
      const result = await execute();
      
      this.metrics.counter('mcp_tool_calls_success', 1, { tool: toolName });
      
      // Track response size
      const responseSize = JSON.stringify(result).length;
      this.metrics.histogram('mcp_tool_response_size_bytes', responseSize, { tool: toolName });
      
      return result;
    } catch (error) {
      this.metrics.counter('mcp_tool_calls_error', 1, { 
        tool: toolName,
        error: error.name 
      });
      
      this.logger.error('MCP tool call failed', {
        tool: toolName,
        error: error.message,
        stack: error.stack
      });
      
      throw error;
    } finally {
      timer.end();
      
      // Memory usage
      const endMemory = process.memoryUsage();
      this.metrics.gauge('mcp_memory_usage_bytes', endMemory.heapUsed, {
        measurement: 'heap_used'
      });
    }
  }
  
  // Monitor message processing
  monitorMessageProcessing(): void {
    this.metrics.counter('mcp_messages_received_total');
    
    // Message queue depth
    setInterval(() => {
      const queueDepth = this.getMessageQueueDepth();
      this.metrics.gauge('mcp_message_queue_depth', queueDepth);
    }, 5000);
  }
  
  // Monitor transport health
  async checkTransportHealth(): Promise<HealthStatus> {
    try {
      const isConnected = await this.transport.isConnected();
      const latency = await this.transport.measureLatency();
      
      this.metrics.gauge('mcp_transport_latency_ms', latency);
      
      return {
        name: 'mcp_transport',
        status: isConnected ? 'healthy' : 'unhealthy',
        metrics: { latency }
      };
    } catch (error) {
      return {
        name: 'mcp_transport',
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// Cache-specific monitoring
class CacheMonitor {
  private metrics: MetricCollector;
  
  monitorCacheOperation<T>(
    operation: 'get' | 'set' | 'delete',
    cacheLayer: string,
    key: string,
    execute: () => Promise<T>
  ): Promise<T> {
    const timer = this.metrics.timer(`cache_${operation}_duration_ms`);
    
    return execute()
      .then(result => {
        this.metrics.counter(`cache_${operation}_total`, 1, {
          layer: cacheLayer,
          status: 'success'
        });
        
        if (operation === 'get' && result) {
          this.metrics.counter('cache_hits_total', 1, { layer: cacheLayer });
        } else if (operation === 'get' && !result) {
          this.metrics.counter('cache_misses_total', 1, { layer: cacheLayer });
        }
        
        return result;
      })
      .catch(error => {
        this.metrics.counter(`cache_${operation}_total`, 1, {
          layer: cacheLayer,
          status: 'error'
        });
        throw error;
      })
      .finally(() => timer.end());
  }
  
  // Monitor cache efficiency
  calculateCacheMetrics(): void {
    setInterval(() => {
      // Hit rate calculation
      const hits = this.getMetric('cache_hits_total');
      const misses = this.getMetric('cache_misses_total');
      const hitRate = hits / (hits + misses) || 0;
      
      this.metrics.gauge('cache_hit_rate', hitRate);
      
      // Memory usage per layer
      const layers = ['memory', 'redis', 'disk'];
      for (const layer of layers) {
        const size = this.getCacheSize(layer);
        this.metrics.gauge('cache_size_bytes', size, { layer });
        
        const items = this.getCacheItemCount(layer);
        this.metrics.gauge('cache_items_count', items, { layer });
      }
      
      // TTL effectiveness
      const expiredItems = this.getExpiredItemCount();
      this.metrics.counter('cache_expired_items_total', expiredItems);
    }, 30000); // Every 30 seconds
  }
}

// Specification update monitoring
class SpecUpdateMonitor {
  private metrics: MetricCollector;
  private logger: StructuredLogger;
  
  async monitorSpecUpdate(source: string): Promise<void> {
    const timer = this.metrics.timer('spec_update_check_duration_ms');
    
    try {
      const hasUpdates = await this.checkForUpdates(source);
      
      this.metrics.counter('spec_update_checks_total', 1, {
        source,
        has_updates: hasUpdates.toString()
      });
      
      if (hasUpdates) {
        this.metrics.counter('spec_updates_detected_total', 1, { source });
        
        // Track update frequency
        const lastUpdate = this.getLastUpdateTime(source);
        const timeSinceLastUpdate = Date.now() - lastUpdate;
        this.metrics.histogram('spec_update_interval_ms', timeSinceLastUpdate, { source });
      }
      
      // Version tracking
      const currentVersion = await this.getCurrentVersion(source);
      this.metrics.gauge('spec_version', this.versionToNumber(currentVersion), {
        source,
        version: currentVersion
      });
      
    } catch (error) {
      this.metrics.counter('spec_update_errors_total', 1, {
        source,
        error: error.name
      });
      
      this.logger.error('Spec update check failed', {
        source,
        error: error.message
      });
    } finally {
      timer.end();
    }
  }
  
  // Monitor parsing performance
  async monitorParsing(content: string): Promise<any> {
    const timer = this.metrics.timer('spec_parse_duration_ms');
    const contentSize = content.length;
    
    this.metrics.histogram('spec_content_size_bytes', contentSize);
    
    try {
      const result = await this.parse(content);
      
      this.metrics.counter('spec_parse_success_total');
      
      // Track parsed structure metrics
      this.metrics.gauge('spec_sections_count', result.sections.length);
      this.metrics.gauge('spec_depth_max', result.maxDepth);
      
      return result;
    } catch (error) {
      this.metrics.counter('spec_parse_errors_total', 1, {
        error: error.name
      });
      throw error;
    } finally {
      timer.end();
    }
  }
}
```

---

## Testing Strategy

### Test Architecture

```typescript
// Test utilities
class TestFixture {
  private mocks: Map<string, any> = new Map();
  private spies: Map<string, jest.SpyInstance> = new Map();
  
  async setup(): Promise<void> {
    // Setup test database
    await this.setupDatabase();
    
    // Setup mocks
    this.setupMocks();
    
    // Setup spies
    this.setupSpies();
  }
  
  async teardown(): Promise<void> {
    // Restore all mocks and spies
    this.spies.forEach(spy => spy.mockRestore());
    
    // Clean database
    await this.cleanDatabase();
  }
  
  getMock<T>(name: string): T {
    return this.mocks.get(name);
  }
}

// Integration test helper
class IntegrationTestHelper {
  private app: Application;
  private server: Server;
  
  async start(): Promise<void> {
    this.app = await createApp({ env: 'test' });
    this.server = this.app.listen(0);
  }
  
  async stop(): Promise<void> {
    await new Promise(resolve => this.server.close(resolve));
  }
  
  request(): SuperTest {
    return supertest(this.app);
  }
}

// Test data builders
class TestDataBuilder {
  static user(overrides?: Partial<User>): User {
    return {
      id: faker.datatype.uuid(),
      email: faker.internet.email(),
      name: faker.name.fullName(),
      createdAt: faker.date.past(),
      ...overrides
    };
  }
  
  static async createUser(overrides?: Partial<User>): Promise<User> {
    const user = this.user(overrides);
    return await db.users.create(user);
  }
}
```

### Test Patterns

```typescript
// 1. Behavior-driven tests
describe('UserService', () => {
  describe('when creating a new user', () => {
    it('should validate email format', async () => {
      const service = new UserService();
      
      await expect(
        service.create({ email: 'invalid-email' })
      ).rejects.toThrow('Invalid email format');
    });
    
    it('should hash the password', async () => {
      const service = new UserService();
      const hashSpy = jest.spyOn(bcrypt, 'hash');
      
      await service.create({
        email: 'test@example.com',
        password: 'password123'
      });
      
      expect(hashSpy).toHaveBeenCalledWith('password123', 10);
    });
  });
});

// 2. Property-based testing
import fc from 'fast-check';

describe('Parser', () => {
  it('should parse and serialize to the same value', () => {
    fc.assert(
      fc.property(fc.json(), (data) => {
        const parsed = parser.parse(data);
        const serialized = parser.serialize(parsed);
        expect(serialized).toEqual(data);
      })
    );
  });
});

// 3. Snapshot testing for complex outputs
describe('MarkdownGenerator', () => {
  it('should generate correct markdown tree', () => {
    const generator = new MarkdownGenerator();
    const spec = loadTestSpec();
    
    const tree = generator.generateTree(spec);
    
    expect(tree).toMatchSnapshot();
  });
});

// 4. Contract testing
describe('API Contract', () => {
  it('should match the OpenAPI schema', async () => {
    const response = await request(app)
      .get('/api/users')
      .expect(200);
    
    expect(response.body).toMatchSchema(userListSchema);
  });
});
```

---

## CI/CD Pipeline Design

### Pipeline Configuration

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  NODE_VERSION: '20.x'
  CACHE_KEY: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}

jobs:
  # 1. Code Quality
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Lint
        run: npm run lint
      
      - name: Type check
        run: npm run type-check
      
      - name: Code complexity
        run: npx complexity-report --max-complexity 10

  # 2. Security Scanning
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security audit
        run: npm audit --audit-level moderate
      
      - name: SAST scan
        uses: github/super-linter@v4
        env:
          VALIDATE_ALL_CODEBASE: false
          DEFAULT_BRANCH: main
      
      - name: Secret scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}

  # 3. Testing
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18.x, 20.x]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js ${{ matrix.node }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Unit tests
        run: npm run test:unit -- --coverage
      
      - name: Integration tests
        run: npm run test:integration
      
      - name: E2E tests
        if: matrix.os == 'ubuntu-latest'
        run: npm run test:e2e
      
      - name: Upload coverage
        if: matrix.os == 'ubuntu-latest' && matrix.node == '20.x'
        uses: codecov/codecov-action@v3

  # 4. Performance Testing
  performance:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run benchmarks
        run: |
          npm run benchmark -- --output benchmark-results.json
      
      - name: Compare with base
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'customBiggerIsBetter'
          output-file-path: benchmark-results.json
          fail-on-alert: true
          alert-threshold: '110%'

  # 5. Build and Deploy
  deploy:
    needs: [quality, security, test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build
        run: |
          npm ci
          npm run build
      
      - name: Generate docs
        run: npm run docs:generate
      
      - name: Deploy to staging
        run: |
          npm run deploy:staging
      
      - name: Smoke tests
        run: |
          npm run test:smoke -- --url ${{ env.STAGING_URL }}
      
      - name: Deploy to production
        if: success()
        run: |
          npm run deploy:production
```

### Deployment Strategy

```typescript
// deployment/deploy.ts
interface DeploymentStrategy {
  deploy(version: string, environment: Environment): Promise<void>;
  rollback(environment: Environment): Promise<void>;
  verify(environment: Environment): Promise<boolean>;
}

class BlueGreenDeployment implements DeploymentStrategy {
  async deploy(version: string, environment: Environment): Promise<void> {
    // 1. Deploy to inactive environment
    const inactiveEnv = await this.getInactiveEnvironment(environment);
    await this.deployToEnvironment(version, inactiveEnv);
    
    // 2. Run health checks
    const healthy = await this.runHealthChecks(inactiveEnv);
    if (!healthy) {
      throw new Error('Health checks failed on new deployment');
    }
    
    // 3. Warm up cache
    await this.warmupCache(inactiveEnv);
    
    // 4. Switch traffic
    await this.switchTraffic(inactiveEnv);
    
    // 5. Monitor for issues
    await this.monitorDeployment(inactiveEnv, { duration: 300000 }); // 5 minutes
  }
  
  async rollback(environment: Environment): Promise<void> {
    const previousEnv = await this.getPreviousEnvironment(environment);
    await this.switchTraffic(previousEnv);
  }
}

class CanaryDeployment implements DeploymentStrategy {
  async deploy(version: string, environment: Environment): Promise<void> {
    const stages = [
      { percentage: 5, duration: 300000 },    // 5% for 5 minutes
      { percentage: 25, duration: 600000 },   // 25% for 10 minutes
      { percentage: 50, duration: 900000 },   // 50% for 15 minutes
      { percentage: 100, duration: 0 }        // 100%
    ];
    
    for (const stage of stages) {
      await this.deployCanary(version, environment, stage.percentage);
      
      if (stage.duration > 0) {
        const metrics = await this.collectMetrics(stage.duration);
        
        if (!this.meetsThresholds(metrics)) {
          await this.rollback(environment);
          throw new Error(`Canary failed at ${stage.percentage}%`);
        }
      }
    }
  }
}
```

---

## Documentation Standards

### API Documentation

```typescript
/**
 * @api {post} /api/users Create User
 * @apiName CreateUser
 * @apiGroup Users
 * @apiVersion 1.0.0
 * 
 * @apiDescription Creates a new user account with the provided details.
 * 
 * @apiParam {String} email User's email address (must be unique)
 * @apiParam {String} password User's password (min 8 characters)
 * @apiParam {String} [name] User's display name
 * 
 * @apiParamExample {json} Request-Example:
 *     {
 *       "email": "user@example.com",
 *       "password": "securepassword",
 *       "name": "John Doe"
 *     }
 * 
 * @apiSuccess {String} id User's unique identifier
 * @apiSuccess {String} email User's email address
 * @apiSuccess {String} name User's display name
 * @apiSuccess {Date} createdAt Account creation timestamp
 * 
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 201 Created
 *     {
 *       "id": "123e4567-e89b-12d3-a456-426614174000",
 *       "email": "user@example.com",
 *       "name": "John Doe",
 *       "createdAt": "2024-01-15T10:30:00Z"
 *     }
 * 
 * @apiError ValidationError Invalid input parameters
 * @apiError ConflictError Email already exists
 * 
 * @apiErrorExample {json} Validation-Error:
 *     HTTP/1.1 400 Bad Request
 *     {
 *       "error": "ValidationError",
 *       "message": "Invalid input",
 *       "details": [
 *         {
 *           "field": "email",
 *           "message": "Invalid email format"
 *         }
 *       ]
 *     }
 */
```

### Architecture Decision Records (ADR)

```markdown
# ADR-001: Caching Strategy

## Status
Accepted

## Context
We need to implement caching to reduce load on external APIs and improve response times.
Current options include:
- In-memory caching (Node cache)
- Redis
- Local file cache

## Decision
We will implement a multi-layer caching strategy:
1. L1: In-memory cache (5 minute TTL)
2. L2: Redis cache (1 hour TTL)  
3. L3: Local file backup (persistent)

## Consequences
**Positive:**
- Improved performance
- Resilience to external service failures
- Reduced API costs

**Negative:**
- Increased complexity
- Cache invalidation challenges
- Additional infrastructure (Redis)

## References
- [Caching Best Practices](https://example.com/caching)
- [Redis Documentation](https://redis.io/docs)
```

---

## Implementation Checklist

### Pre-Development

- [ ] **Requirements Analysis**
  - [ ] Identify all data sources
  - [ ] Map data flows
  - [ ] Define SLAs
  - [ ] List external dependencies

- [ ] **Architecture Design**
  - [ ] Create component diagram
  - [ ] Define interfaces
  - [ ] Plan error scenarios
  - [ ] Design monitoring strategy

- [ ] **Security Planning**
  - [ ] Threat modeling
  - [ ] Authentication strategy
  - [ ] Authorization matrix
  - [ ] Data encryption plan

### Development Phase

- [ ] **Code Structure**
  - [ ] Implement single responsibility
  - [ ] Use dependency injection
  - [ ] Add comprehensive error handling
  - [ ] Include input validation

- [ ] **Performance**
  - [ ] Implement caching layers
  - [ ] Add connection pooling
  - [ ] Use batch processing
  - [ ] Optimize queries

- [ ] **Observability**
  - [ ] Structured logging
  - [ ] Metrics collection
  - [ ] Distributed tracing
  - [ ] Health checks

### Testing Phase

- [ ] **Test Coverage**
  - [ ] Unit tests (>80%)
  - [ ] Integration tests
  - [ ] E2E tests
  - [ ] Performance tests

- [ ] **Security Testing**
  - [ ] SAST scanning
  - [ ] Dependency scanning
  - [ ] Penetration testing
  - [ ] Secret scanning

### Deployment Phase

- [ ] **CI/CD Pipeline**
  - [ ] Automated builds
  - [ ] Quality gates
  - [ ] Security scanning
  - [ ] Automated deployment

- [ ] **Monitoring Setup**
  - [ ] Alerts configured
  - [ ] Dashboards created
  - [ ] SLO tracking
  - [ ] Runbooks prepared

### Post-Deployment

- [ ] **Documentation**
  - [ ] API documentation
  - [ ] Architecture diagrams
  - [ ] Runbooks
  - [ ] ADRs

- [ ] **Maintenance**
  - [ ] Backup procedures
  - [ ] Update strategy
  - [ ] Incident response plan
  - [ ] Performance baseline

---

## Anti-Patterns to Avoid

### 1. **Disconnected Systems**
```typescript
// ❌ AVOID: Multiple systems that don't communicate
class ServerCache { }
class GitHubActionsCache { }
// These can get out of sync

// ✅ PREFER: Unified system with sync mechanism
class UnifiedCache {
  async sync(source: CacheSource): Promise<void> { }
}
```

### 2. **Silent Failures**
```typescript
// ❌ AVOID: Swallowing errors
try {
  await fetchData();
} catch (error) {
  console.log(error); // Just logs, continues
}

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

### 3. **Hardcoded Values**
```typescript
// ❌ AVOID: Hardcoded configuration
const CACHE_TTL = 3600;
const API_URL = 'https://api.example.com';

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

### 4. **Premature Optimization**
```typescript
// ❌ AVOID: Complex optimization without metrics
class SuperOptimizedCache {
  // 500 lines of complex caching logic
}

// ✅ PREFER: Simple solution first, optimize based on metrics
class SimpleCache {
  private cache = new Map();
  
  get(key: string) {
    return this.cache.get(key);
  }
}
```

### 5. **Missing Observability**
```typescript
// ❌ AVOID: Black box operations
async function processData(data: any) {
  const result = await transform(data);
  await save(result);
  return result;
}

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

### 6. **Inefficient Cache Timing Strategy**
```typescript
// ❌ AVOID: Metadata expiring before data
const cache = {
  metadata: { ttl: 5 * 60 },    // 5 minutes
  data: { ttl: 60 * 60 }        // 1 hour
};
// Problem: Checks for updates every 5 min but data cached for 1 hour

// ✅ PREFER: Smart cache invalidation
const cache = {
  metadata: { ttl: 60 * 60 },   // Check less frequently
  data: { ttl: 'on-change' }    // Invalidate when metadata changes
};
```

### 7. **No Error Recovery Strategy**
```typescript
// ❌ AVOID: Single point of failure
try {
  const data = await fetch(url);
} catch (error) {
  throw new Error('Failed to fetch');
}

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

### 8. **Sequential Processing**
```typescript
// ❌ AVOID: Sequential fetching
for (const file of files) {
  const data = await fetch(file);
  results.push(data);
}

// ✅ PREFER: Parallel processing with limits
const results = await pLimit(5)(
  files.map(file => () => fetch(file))
);
```

### 9. **Monolithic Request Handlers**
```typescript
// ❌ AVOID: Giant switch statement
switch (action) {
  case 'create': { /* 50 lines */ }
  case 'update': { /* 60 lines */ }
  case 'delete': { /* 40 lines */ }
}

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

### 10. **Missing Request Validation**
```typescript
// ❌ AVOID: Type casting without validation
const limit = req.query.limit as number || 10;

// ✅ PREFER: Schema validation
const schema = z.object({
  limit: z.number().min(1).max(100).default(10),
  offset: z.number().min(0).default(0)
});

const { limit, offset } = schema.parse(req.query);
```

### 11. **No HTTP Caching Standards**
```typescript
// ❌ AVOID: Checking only basic headers
const changed = headers['last-modified'] !== cached.lastModified;

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

### 12. **All-or-Nothing Updates**
```typescript
// ❌ AVOID: No granular change tracking
if (newContent !== oldContent) {
  invalidateEverything();
}

// ✅ PREFER: Incremental updates
const changes = diff(oldContent, newContent);
for (const change of changes) {
  invalidateSection(change.path);
  updateSection(change.path, change.value);
}
```

### 13. **Dead Code**
```typescript
// ❌ AVOID: Implementing features that aren't used
class AdvancedFeature {
  // 200 lines of unused code
}

// ✅ PREFER: Test-driven development
describe('Feature', () => {
  it('should be used', () => {
    const usage = findUsages('AdvancedFeature');
    expect(usage.length).toBeGreaterThan(0);
  });
});
```

### 14. **Security Theater**
```typescript
// ❌ AVOID: Security checks that don't block
try {
  await securityScan();
} catch (error) {
  console.log('Security issue found');
  // Continues anyway!
}

// ✅ PREFER: Enforced security
const vulnerabilities = await securityScan();
if (vulnerabilities.critical > 0) {
  throw new SecurityError('Critical vulnerabilities found');
}
```

### 15. **Multiple Sources of Truth**
```typescript
// ❌ AVOID: Disconnected cache systems
class ServerCache { }
class GitHubActionsCache { }
// These operate independently and get out of sync

// ✅ PREFER: Unified system with sync
class UnifiedCache {
  async sync(source: CacheSource): Promise<void> {
    const data = await source.getData();
    await this.updateAllLayers(data);
    await this.notifySubscribers(data);
  }
}
```

---

## Conclusion

This template provides a comprehensive framework for building robust, scalable, and maintainable systems. Key principles to remember:

1. **Start Simple**: Don't over-engineer. Build the simplest solution that works, then iterate.
2. **Measure Everything**: You can't improve what you don't measure.
3. **Fail Gracefully**: Always have a fallback plan.
4. **Automate Repetitive Tasks**: If you do it twice, automate it.
5. **Document Decisions**: Future you will thank present you.

Remember: Good architecture evolves. Start with these patterns and adapt them to your specific needs.