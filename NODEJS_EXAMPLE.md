# Node.js/TypeScript Implementation Example

This guide demonstrates how to implement the architecture patterns in a Node.js/TypeScript project with practical examples.

## Table of Contents

1. [Project Structure](#project-structure)
2. [Package Configuration](#package-configuration)
3. [TypeScript Configuration](#typescript-configuration)
4. [Core Implementation Patterns](#core-implementation-patterns)
5. [Testing Examples](#testing-examples)
6. [Integration Examples](#integration-examples)

---

## Project Structure

```
my-node-project/
├── src/
│   ├── core/
│   │   ├── cache/
│   │   │   ├── cache.interface.ts
│   │   │   ├── cache.service.ts
│   │   │   └── cache.service.test.ts
│   │   ├── errors/
│   │   │   ├── error.types.ts
│   │   │   ├── error.handler.ts
│   │   │   └── error.handler.test.ts
│   │   ├── monitoring/
│   │   │   ├── metrics.service.ts
│   │   │   ├── logger.service.ts
│   │   │   └── health.service.ts
│   │   └── utils/
│   │       ├── retry.util.ts
│   │       ├── validation.util.ts
│   │       └── circuit-breaker.util.ts
│   ├── modules/
│   │   ├── data-fetcher/
│   │   │   ├── data-fetcher.service.ts
│   │   │   ├── data-fetcher.interface.ts
│   │   │   └── data-fetcher.test.ts
│   │   └── processor/
│   │       ├── processor.service.ts
│   │       ├── processor.queue.ts
│   │       └── processor.test.ts
│   ├── config/
│   │   ├── app.config.ts
│   │   ├── cache.config.ts
│   │   └── database.config.ts
│   ├── types/
│   │   └── index.d.ts
│   └── index.ts
├── tests/
│   ├── integration/
│   │   └── api.integration.test.ts
│   ├── e2e/
│   │   └── workflow.e2e.test.ts
│   └── fixtures/
│       └── test-data.ts
├── .env.example
├── .gitignore
├── .eslintrc.json
├── .prettierrc
├── jest.config.ts
├── tsconfig.json
├── package.json
└── README.md
```

---

## Package Configuration

### package.json

```json
{
  "name": "my-node-project",
  "version": "1.0.0",
  "description": "Example Node.js/TypeScript project implementing architecture patterns",
  "main": "dist/index.js",
  "type": "module",
  "engines": {
    "node": ">=18.0.0"
  },
  "scripts": {
    "build": "tsc && tsc-alias",
    "dev": "tsx watch src/index.ts",
    "start": "node dist/index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:integration": "jest --config=jest.integration.config.ts",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write \"src/**/*.ts\"",
    "typecheck": "tsc --noEmit",
    "clean": "rimraf dist coverage",
    "prepare": "husky install"
  },
  "dependencies": {
    "axios": "^1.7.2",
    "bull": "^4.12.2",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "ioredis": "^5.3.2",
    "joi": "^17.11.0",
    "node-cache": "^5.1.2",
    "pino": "^8.16.2",
    "prom-client": "^15.1.0",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/bull": "^4.10.0",
    "@types/express": "^4.17.21",
    "@types/jest": "^29.5.11",
    "@types/node": "^20.10.5",
    "@typescript-eslint/eslint-plugin": "^6.15.0",
    "@typescript-eslint/parser": "^6.15.0",
    "eslint": "^8.56.0",
    "eslint-config-prettier": "^9.1.0",
    "eslint-plugin-jest": "^27.6.0",
    "husky": "^8.0.3",
    "jest": "^29.7.0",
    "lint-staged": "^15.2.0",
    "prettier": "^3.1.1",
    "rimraf": "^5.0.5",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.1",
    "ts-node": "^10.9.2",
    "tsc-alias": "^1.8.8",
    "tsx": "^4.7.0",
    "typescript": "^5.3.3"
  },
  "lint-staged": {
    "*.ts": [
      "eslint --fix",
      "prettier --write"
    ]
  }
}
```

---

## TypeScript Configuration

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "allowSyntheticDefaultImports": true,
    "baseUrl": "./src",
    "paths": {
      "@core/*": ["core/*"],
      "@modules/*": ["modules/*"],
      "@config/*": ["config/*"],
      "@types/*": ["types/*"],
      "@utils/*": ["core/utils/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "coverage", "**/*.test.ts", "**/*.spec.ts"],
  "ts-node": {
    "esm": true,
    "experimentalSpecifierResolution": "node"
  }
}
```

### jest.config.ts

```typescript
import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        moduleResolution: 'node',
      },
    }],
  },
  moduleNameMapper: {
    '^@core/(.*)$': '<rootDir>/src/core/$1',
    '^@modules/(.*)$': '<rootDir>/src/modules/$1',
    '^@config/(.*)$': '<rootDir>/src/config/$1',
    '^@utils/(.*)$': '<rootDir>/src/core/utils/$1',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/index.ts',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
```

---

## Core Implementation Patterns

### 1. Caching Implementation

#### src/core/cache/cache.interface.ts

```typescript
export interface CacheOptions {
  ttl?: number; // Time to live in seconds
  namespace?: string;
  checkPeriod?: number;
}

export interface CacheEntry<T> {
  value: T;
  createdAt: Date;
  expiresAt?: Date;
  hits: number;
}

export interface ICacheService {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
  getStats(): Promise<CacheStats>;
}

export interface CacheStats {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  size: number;
  hitRate: number;
}
```

#### src/core/cache/cache.service.ts

```typescript
import NodeCache from 'node-cache';
import { createHash } from 'crypto';
import { Logger } from '@core/monitoring/logger.service';
import { MetricsService } from '@core/monitoring/metrics.service';
import { ICacheService, CacheOptions, CacheStats } from './cache.interface';

export class CacheService implements ICacheService {
  private cache: NodeCache;
  private stats: CacheStats;
  private readonly logger: Logger;
  private readonly metrics: MetricsService;
  private readonly namespace: string;

  constructor(
    options: CacheOptions = {},
    logger: Logger,
    metrics: MetricsService
  ) {
    this.cache = new NodeCache({
      stdTTL: options.ttl || 3600,
      checkperiod: options.checkPeriod || 600,
      useClones: false,
    });
    
    this.namespace = options.namespace || 'default';
    this.logger = logger;
    this.metrics = metrics;
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      size: 0,
      hitRate: 0,
    };

    this.setupEventListeners();
  }

  async get<T>(key: string): Promise<T | undefined> {
    const hashedKey = this.hashKey(key);
    
    try {
      const value = this.cache.get<T>(hashedKey);
      
      if (value !== undefined) {
        this.stats.hits++;
        this.metrics.increment('cache.hits', { namespace: this.namespace });
        this.logger.debug('Cache hit', { key, namespace: this.namespace });
      } else {
        this.stats.misses++;
        this.metrics.increment('cache.misses', { namespace: this.namespace });
        this.logger.debug('Cache miss', { key, namespace: this.namespace });
      }
      
      this.updateHitRate();
      return value;
    } catch (error) {
      this.logger.error('Cache get error', { key, error });
      throw error;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const hashedKey = this.hashKey(key);
    
    try {
      const success = ttl 
        ? this.cache.set(hashedKey, value, ttl)
        : this.cache.set(hashedKey, value);
      
      if (success) {
        this.stats.sets++;
        this.metrics.increment('cache.sets', { namespace: this.namespace });
        this.logger.debug('Cache set', { key, ttl, namespace: this.namespace });
      }
    } catch (error) {
      this.logger.error('Cache set error', { key, error });
      throw error;
    }
  }

  async delete(key: string): Promise<boolean> {
    const hashedKey = this.hashKey(key);
    
    try {
      const deleted = this.cache.del(hashedKey);
      
      if (deleted > 0) {
        this.stats.deletes++;
        this.metrics.increment('cache.deletes', { namespace: this.namespace });
        this.logger.debug('Cache delete', { key, namespace: this.namespace });
        return true;
      }
      
      return false;
    } catch (error) {
      this.logger.error('Cache delete error', { key, error });
      throw error;
    }
  }

  async clear(): Promise<void> {
    try {
      this.cache.flushAll();
      this.logger.info('Cache cleared', { namespace: this.namespace });
      this.metrics.increment('cache.clears', { namespace: this.namespace });
    } catch (error) {
      this.logger.error('Cache clear error', { error });
      throw error;
    }
  }

  async has(key: string): Promise<boolean> {
    const hashedKey = this.hashKey(key);
    return this.cache.has(hashedKey);
  }

  async getStats(): Promise<CacheStats> {
    this.stats.size = this.cache.keys().length;
    return { ...this.stats };
  }

  private hashKey(key: string): string {
    return createHash('sha256')
      .update(`${this.namespace}:${key}`)
      .digest('hex');
  }

  private updateHitRate(): void {
    const total = this.stats.hits + this.stats.misses;
    this.stats.hitRate = total > 0 ? this.stats.hits / total : 0;
    
    this.metrics.gauge('cache.hit_rate', this.stats.hitRate, {
      namespace: this.namespace,
    });
  }

  private setupEventListeners(): void {
    this.cache.on('expired', (key, value) => {
      this.logger.debug('Cache key expired', { key });
      this.metrics.increment('cache.expirations', { namespace: this.namespace });
    });

    this.cache.on('flush', () => {
      this.logger.info('Cache flushed', { namespace: this.namespace });
    });
  }
}
```

### 2. Error Handling Implementation

#### src/core/errors/error.types.ts

```typescript
export enum ErrorCode {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  TIMEOUT = 'TIMEOUT',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  CIRCUIT_BREAKER_OPEN = 'CIRCUIT_BREAKER_OPEN',
}

export interface ErrorContext {
  service?: string;
  operation?: string;
  userId?: string;
  requestId?: string;
  metadata?: Record<string, any>;
}

export class ApplicationError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly context: ErrorContext;
  public readonly timestamp: Date;
  public readonly isOperational: boolean;

  constructor(
    message: string,
    code: ErrorCode = ErrorCode.INTERNAL_ERROR,
    statusCode: number = 500,
    isOperational: boolean = true,
    context: ErrorContext = {}
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.context = context;
    this.timestamp = new Date();

    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

export class ValidationError extends ApplicationError {
  constructor(message: string, context?: ErrorContext) {
    super(message, ErrorCode.VALIDATION_ERROR, 400, true, context);
  }
}

export class NotFoundError extends ApplicationError {
  constructor(resource: string, context?: ErrorContext) {
    super(`${resource} not found`, ErrorCode.NOT_FOUND, 404, true, context);
  }
}

export class UnauthorizedError extends ApplicationError {
  constructor(message: string = 'Unauthorized', context?: ErrorContext) {
    super(message, ErrorCode.UNAUTHORIZED, 401, true, context);
  }
}

export class ServiceUnavailableError extends ApplicationError {
  constructor(service: string, context?: ErrorContext) {
    super(
      `Service ${service} is unavailable`,
      ErrorCode.SERVICE_UNAVAILABLE,
      503,
      true,
      context
    );
  }
}
```

#### src/core/errors/error.handler.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import { Logger } from '@core/monitoring/logger.service';
import { MetricsService } from '@core/monitoring/metrics.service';
import { ApplicationError, ErrorCode } from './error.types';

export class ErrorHandler {
  constructor(
    private readonly logger: Logger,
    private readonly metrics: MetricsService
  ) {}

  public handleError(error: Error | ApplicationError): void {
    if (this.isOperationalError(error)) {
      this.handleOperationalError(error as ApplicationError);
    } else {
      this.handleCriticalError(error);
    }
  }

  public errorMiddleware() {
    return (
      error: Error | ApplicationError,
      req: Request,
      res: Response,
      next: NextFunction
    ): void => {
      const requestContext = {
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        requestId: req.get('x-request-id'),
      };

      this.logger.error('Request error', {
        error: error.message,
        stack: error.stack,
        context: requestContext,
      });

      this.metrics.increment('http.errors', {
        code: (error as ApplicationError).code || ErrorCode.INTERNAL_ERROR,
        method: req.method,
        path: req.route?.path || 'unknown',
      });

      if (this.isOperationalError(error)) {
        const appError = error as ApplicationError;
        res.status(appError.statusCode).json({
          error: {
            message: appError.message,
            code: appError.code,
            timestamp: appError.timestamp,
            requestId: requestContext.requestId,
          },
        });
      } else {
        res.status(500).json({
          error: {
            message: 'Internal server error',
            code: ErrorCode.INTERNAL_ERROR,
            timestamp: new Date(),
            requestId: requestContext.requestId,
          },
        });
      }
    };
  }

  private isOperationalError(error: Error): boolean {
    return error instanceof ApplicationError && error.isOperational;
  }

  private handleOperationalError(error: ApplicationError): void {
    this.logger.warn('Operational error', {
      error: error.toJSON(),
    });

    this.metrics.increment('errors.operational', {
      code: error.code,
      service: error.context.service,
    });
  }

  private handleCriticalError(error: Error): void {
    this.logger.error('Critical error', {
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name,
      },
    });

    this.metrics.increment('errors.critical');

    // In production, you might want to:
    // 1. Send alerts
    // 2. Restart the process gracefully
    // 3. Report to error tracking service
  }

  public async shutdown(): Promise<void> {
    this.logger.info('Error handler shutting down...');
    // Cleanup resources if needed
  }
}
```

### 3. Monitoring Implementation

#### src/core/monitoring/logger.service.ts

```typescript
import pino, { Logger as PinoLogger } from 'pino';

export interface LogContext {
  [key: string]: any;
}

export class Logger {
  private logger: PinoLogger;

  constructor(name: string, level: string = 'info') {
    this.logger = pino({
      name,
      level,
      timestamp: pino.stdTimeFunctions.isoTime,
      formatters: {
        level: (label) => {
          return { level: label };
        },
      },
      redact: {
        paths: ['password', 'token', 'apiKey', 'secret'],
        remove: true,
      },
    });
  }

  info(message: string, context?: LogContext): void {
    this.logger.info(context, message);
  }

  warn(message: string, context?: LogContext): void {
    this.logger.warn(context, message);
  }

  error(message: string, context?: LogContext): void {
    this.logger.error(context, message);
  }

  debug(message: string, context?: LogContext): void {
    this.logger.debug(context, message);
  }

  fatal(message: string, context?: LogContext): void {
    this.logger.fatal(context, message);
  }

  child(bindings: LogContext): Logger {
    const childLogger = new Logger('child', this.logger.level);
    childLogger.logger = this.logger.child(bindings);
    return childLogger;
  }
}
```

#### src/core/monitoring/metrics.service.ts

```typescript
import { Registry, Counter, Gauge, Histogram, Summary } from 'prom-client';

export interface MetricLabels {
  [key: string]: string;
}

export class MetricsService {
  private registry: Registry;
  private counters: Map<string, Counter<string>>;
  private gauges: Map<string, Gauge<string>>;
  private histograms: Map<string, Histogram<string>>;
  private summaries: Map<string, Summary<string>>;

  constructor() {
    this.registry = new Registry();
    this.counters = new Map();
    this.gauges = new Map();
    this.histograms = new Map();
    this.summaries = new Map();

    this.initializeDefaultMetrics();
  }

  increment(name: string, labels?: MetricLabels): void {
    const counter = this.getOrCreateCounter(name);
    if (labels) {
      counter.inc(labels);
    } else {
      counter.inc();
    }
  }

  decrement(name: string, labels?: MetricLabels): void {
    const counter = this.getOrCreateCounter(name);
    if (labels) {
      counter.inc(labels, -1);
    } else {
      counter.inc(-1);
    }
  }

  gauge(name: string, value: number, labels?: MetricLabels): void {
    const gauge = this.getOrCreateGauge(name);
    if (labels) {
      gauge.set(labels, value);
    } else {
      gauge.set(value);
    }
  }

  histogram(name: string, value: number, labels?: MetricLabels): void {
    const histogram = this.getOrCreateHistogram(name);
    if (labels) {
      histogram.observe(labels, value);
    } else {
      histogram.observe(value);
    }
  }

  summary(name: string, value: number, labels?: MetricLabels): void {
    const summary = this.getOrCreateSummary(name);
    if (labels) {
      summary.observe(labels, value);
    } else {
      summary.observe(value);
    }
  }

  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  getContentType(): string {
    return this.registry.contentType;
  }

  private getOrCreateCounter(name: string): Counter<string> {
    if (!this.counters.has(name)) {
      const counter = new Counter({
        name,
        help: `Counter for ${name}`,
        registers: [this.registry],
      });
      this.counters.set(name, counter);
    }
    return this.counters.get(name)!;
  }

  private getOrCreateGauge(name: string): Gauge<string> {
    if (!this.gauges.has(name)) {
      const gauge = new Gauge({
        name,
        help: `Gauge for ${name}`,
        registers: [this.registry],
      });
      this.gauges.set(name, gauge);
    }
    return this.gauges.get(name)!;
  }

  private getOrCreateHistogram(name: string): Histogram<string> {
    if (!this.histograms.has(name)) {
      const histogram = new Histogram({
        name,
        help: `Histogram for ${name}`,
        registers: [this.registry],
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      });
      this.histograms.set(name, histogram);
    }
    return this.histograms.get(name)!;
  }

  private getOrCreateSummary(name: string): Summary<string> {
    if (!this.summaries.has(name)) {
      const summary = new Summary({
        name,
        help: `Summary for ${name}`,
        registers: [this.registry],
        percentiles: [0.5, 0.9, 0.95, 0.99],
      });
      this.summaries.set(name, summary);
    }
    return this.summaries.get(name)!;
  }

  private initializeDefaultMetrics(): void {
    // HTTP metrics
    this.getOrCreateCounter('http_requests_total');
    this.getOrCreateHistogram('http_request_duration_seconds');
    this.getOrCreateGauge('http_requests_in_flight');

    // Business metrics
    this.getOrCreateCounter('business_operations_total');
    this.getOrCreateHistogram('business_operation_duration_seconds');

    // System metrics
    this.getOrCreateGauge('system_cpu_usage_percent');
    this.getOrCreateGauge('system_memory_usage_bytes');
  }
}
```

### 4. Utility Functions

#### src/core/utils/retry.util.ts

```typescript
export interface RetryOptions {
  maxAttempts?: number;
  initialDelay?: number;
  maxDelay?: number;
  factor?: number;
  onRetry?: (error: Error, attempt: number) => void;
}

export async function retry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    initialDelay = 100,
    maxDelay = 5000,
    factor = 2,
    onRetry,
  } = options;

  let lastError: Error;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (attempt === maxAttempts) {
        throw lastError;
      }

      if (onRetry) {
        onRetry(lastError, attempt);
      }

      const delay = Math.min(
        initialDelay * Math.pow(factor, attempt - 1),
        maxDelay
      );

      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  throw lastError!;
}

export function retryable<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options?: RetryOptions
): T {
  return (async (...args: Parameters<T>) => {
    return retry(() => fn(...args), options);
  }) as T;
}
```

#### src/core/utils/circuit-breaker.util.ts

```typescript
export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  resetTimeout?: number;
  monitoringPeriod?: number;
  minimumRequests?: number;
  onStateChange?: (oldState: CircuitState, newState: CircuitState) => void;
}

export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failures: number = 0;
  private successes: number = 0;
  private lastFailureTime?: Date;
  private requests: number = 0;
  private readonly options: Required<CircuitBreakerOptions>;

  constructor(options: CircuitBreakerOptions = {}) {
    this.options = {
      failureThreshold: options.failureThreshold || 50,
      resetTimeout: options.resetTimeout || 60000,
      monitoringPeriod: options.monitoringPeriod || 10000,
      minimumRequests: options.minimumRequests || 10,
      onStateChange: options.onStateChange || (() => {}),
    };
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (this.shouldAttemptReset()) {
        this.transitionTo(CircuitState.HALF_OPEN);
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

  private onSuccess(): void {
    this.requests++;
    this.failures = 0;

    if (this.state === CircuitState.HALF_OPEN) {
      this.successes++;
      if (this.successes >= this.options.minimumRequests) {
        this.transitionTo(CircuitState.CLOSED);
      }
    }
  }

  private onFailure(): void {
    this.requests++;
    this.failures++;
    this.lastFailureTime = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.transitionTo(CircuitState.OPEN);
    } else if (this.state === CircuitState.CLOSED) {
      const failureRate = (this.failures / this.requests) * 100;
      if (
        this.requests >= this.options.minimumRequests &&
        failureRate >= this.options.failureThreshold
      ) {
        this.transitionTo(CircuitState.OPEN);
      }
    }
  }

  private shouldAttemptReset(): boolean {
    return (
      this.lastFailureTime &&
      Date.now() - this.lastFailureTime.getTime() >= this.options.resetTimeout
    );
  }

  private transitionTo(newState: CircuitState): void {
    const oldState = this.state;
    this.state = newState;

    if (newState === CircuitState.CLOSED) {
      this.failures = 0;
      this.successes = 0;
      this.requests = 0;
    } else if (newState === CircuitState.HALF_OPEN) {
      this.successes = 0;
    }

    this.options.onStateChange(oldState, newState);
  }

  getState(): CircuitState {
    return this.state;
  }

  getStats() {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      requests: this.requests,
      lastFailureTime: this.lastFailureTime,
    };
  }
}
```

---

## Testing Examples

### 1. Unit Test Example

#### src/core/cache/cache.service.test.ts

```typescript
import { CacheService } from './cache.service';
import { Logger } from '@core/monitoring/logger.service';
import { MetricsService } from '@core/monitoring/metrics.service';

describe('CacheService', () => {
  let cacheService: CacheService;
  let mockLogger: jest.Mocked<Logger>;
  let mockMetrics: jest.Mocked<MetricsService>;

  beforeEach(() => {
    mockLogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    mockMetrics = {
      increment: jest.fn(),
      gauge: jest.fn(),
    } as any;

    cacheService = new CacheService(
      { ttl: 60, namespace: 'test' },
      mockLogger,
      mockMetrics
    );
  });

  describe('get', () => {
    it('should return cached value on hit', async () => {
      const key = 'test-key';
      const value = { data: 'test-data' };

      await cacheService.set(key, value);
      const result = await cacheService.get(key);

      expect(result).toEqual(value);
      expect(mockMetrics.increment).toHaveBeenCalledWith('cache.hits', {
        namespace: 'test',
      });
    });

    it('should return undefined on miss', async () => {
      const result = await cacheService.get('non-existent');

      expect(result).toBeUndefined();
      expect(mockMetrics.increment).toHaveBeenCalledWith('cache.misses', {
        namespace: 'test',
      });
    });
  });

  describe('set', () => {
    it('should store value with default TTL', async () => {
      const key = 'test-key';
      const value = { data: 'test-data' };

      await cacheService.set(key, value);
      const result = await cacheService.get(key);

      expect(result).toEqual(value);
      expect(mockMetrics.increment).toHaveBeenCalledWith('cache.sets', {
        namespace: 'test',
      });
    });

    it('should store value with custom TTL', async () => {
      const key = 'test-key';
      const value = { data: 'test-data' };
      const ttl = 30;

      await cacheService.set(key, value, ttl);
      const result = await cacheService.get(key);

      expect(result).toEqual(value);
    });
  });

  describe('delete', () => {
    it('should delete existing key', async () => {
      const key = 'test-key';
      await cacheService.set(key, 'value');

      const deleted = await cacheService.delete(key);

      expect(deleted).toBe(true);
      expect(await cacheService.get(key)).toBeUndefined();
      expect(mockMetrics.increment).toHaveBeenCalledWith('cache.deletes', {
        namespace: 'test',
      });
    });

    it('should return false for non-existent key', async () => {
      const deleted = await cacheService.delete('non-existent');

      expect(deleted).toBe(false);
    });
  });

  describe('getStats', () => {
    it('should return cache statistics', async () => {
      await cacheService.set('key1', 'value1');
      await cacheService.get('key1'); // hit
      await cacheService.get('key2'); // miss

      const stats = await cacheService.getStats();

      expect(stats).toMatchObject({
        hits: 1,
        misses: 1,
        sets: 1,
        deletes: 0,
        size: 1,
        hitRate: 0.5,
      });
    });
  });
});
```

### 2. Integration Test Example

#### tests/integration/api.integration.test.ts

```typescript
import request from 'supertest';
import { Application } from 'express';
import { createApp } from '../../src/app';
import { Database } from '../../src/infrastructure/database';
import { CacheService } from '@core/cache/cache.service';

describe('API Integration Tests', () => {
  let app: Application;
  let database: Database;
  let cache: CacheService;

  beforeAll(async () => {
    // Setup test environment
    process.env.NODE_ENV = 'test';
    
    // Initialize services
    database = new Database({ url: 'mongodb://localhost:27017/test' });
    await database.connect();
    
    // Create app instance
    app = createApp({ database });
  });

  afterAll(async () => {
    await database.disconnect();
  });

  beforeEach(async () => {
    // Clear test data
    await database.clear();
    await cache.clear();
  });

  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'healthy',
        timestamp: expect.any(String),
        services: {
          database: 'connected',
          cache: 'healthy',
        },
      });
    });
  });

  describe('POST /api/data', () => {
    it('should create new data entry', async () => {
      const payload = {
        name: 'Test Item',
        value: 42,
        metadata: {
          source: 'test',
          priority: 'high',
        },
      };

      const response = await request(app)
        .post('/api/data')
        .send(payload)
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        ...payload,
        createdAt: expect.any(String),
        updatedAt: expect.any(String),
      });
    });

    it('should validate input data', async () => {
      const invalidPayload = {
        name: '', // Invalid: empty name
        value: 'not-a-number', // Invalid: should be number
      };

      const response = await request(app)
        .post('/api/data')
        .send(invalidPayload)
        .expect(400);

      expect(response.body).toMatchObject({
        error: {
          code: 'VALIDATION_ERROR',
          message: expect.any(String),
          details: expect.arrayContaining([
            expect.objectContaining({
              field: 'name',
              message: expect.any(String),
            }),
            expect.objectContaining({
              field: 'value',
              message: expect.any(String),
            }),
          ]),
        },
      });
    });
  });

  describe('GET /api/data/:id', () => {
    it('should return cached data on second request', async () => {
      // Create test data
      const createResponse = await request(app)
        .post('/api/data')
        .send({ name: 'Test', value: 42 })
        .expect(201);

      const id = createResponse.body.id;

      // First request - should hit database
      const firstRequest = await request(app)
        .get(`/api/data/${id}`)
        .expect(200);

      // Second request - should hit cache
      const secondRequest = await request(app)
        .get(`/api/data/${id}`)
        .set('x-cache-control', 'max-age=3600')
        .expect(200);

      expect(secondRequest.headers['x-cache-hit']).toBe('true');
      expect(firstRequest.body).toEqual(secondRequest.body);
    });
  });
});
```

### 3. End-to-End Test Example

#### tests/e2e/workflow.e2e.test.ts

```typescript
import { TestEnvironment } from '../utils/test-environment';
import { DataProcessor } from '@modules/processor/processor.service';
import { NotificationService } from '@modules/notification/notification.service';

describe('Data Processing Workflow E2E', () => {
  let env: TestEnvironment;

  beforeAll(async () => {
    env = await TestEnvironment.setup();
  });

  afterAll(async () => {
    await env.teardown();
  });

  it('should process data through complete pipeline', async () => {
    // 1. Submit data for processing
    const inputData = {
      source: 'test-source',
      type: 'batch',
      items: [
        { id: '1', value: 100 },
        { id: '2', value: 200 },
        { id: '3', value: 300 },
      ],
    };

    const submitResponse = await env.api
      .post('/api/process')
      .send(inputData)
      .expect(202);

    const jobId = submitResponse.body.jobId;
    expect(jobId).toBeDefined();

    // 2. Wait for processing to complete
    await env.waitForJobCompletion(jobId, 30000);

    // 3. Verify results
    const resultResponse = await env.api
      .get(`/api/jobs/${jobId}/result`)
      .expect(200);

    expect(resultResponse.body).toMatchObject({
      status: 'completed',
      summary: {
        total: 3,
        processed: 3,
        failed: 0,
      },
      results: expect.arrayContaining([
        expect.objectContaining({
          id: '1',
          originalValue: 100,
          processedValue: expect.any(Number),
        }),
      ]),
    });

    // 4. Verify notifications were sent
    const notifications = await env.getNotifications();
    expect(notifications).toContainEqual(
      expect.objectContaining({
        type: 'job.completed',
        jobId,
        recipient: 'test@example.com',
      })
    );

    // 5. Verify metrics were recorded
    const metrics = await env.getMetrics();
    expect(metrics).toContain('job_processing_duration_seconds');
    expect(metrics).toContain('job_items_processed_total{status="success"}');
  });

  it('should handle partial failures gracefully', async () => {
    // Submit data with some invalid items
    const inputData = {
      source: 'test-source',
      type: 'batch',
      items: [
        { id: '1', value: 100 },
        { id: '2', value: -1 }, // Invalid: negative value
        { id: '3', value: 300 },
      ],
    };

    const submitResponse = await env.api
      .post('/api/process')
      .send(inputData)
      .expect(202);

    const jobId = submitResponse.body.jobId;

    // Wait for completion
    await env.waitForJobCompletion(jobId, 30000);

    // Verify partial success
    const resultResponse = await env.api
      .get(`/api/jobs/${jobId}/result`)
      .expect(200);

    expect(resultResponse.body).toMatchObject({
      status: 'completed_with_errors',
      summary: {
        total: 3,
        processed: 2,
        failed: 1,
      },
      errors: expect.arrayContaining([
        expect.objectContaining({
          itemId: '2',
          error: expect.stringContaining('negative value'),
        }),
      ]),
    });
  });
});
```

---

## Integration Examples

### 1. Express Application Setup

#### src/app.ts

```typescript
import express, { Application } from 'express';
import { errorMiddleware } from '@core/errors/error.middleware';
import { metricsMiddleware } from '@core/monitoring/metrics.middleware';
import { loggingMiddleware } from '@core/monitoring/logging.middleware';
import { rateLimitMiddleware } from '@core/security/rate-limit.middleware';
import { healthRouter } from './routes/health.routes';
import { apiRouter } from './routes/api.routes';

export function createApp(dependencies: AppDependencies): Application {
  const app = express();

  // Basic middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Custom middleware
  app.use(loggingMiddleware(dependencies.logger));
  app.use(metricsMiddleware(dependencies.metrics));
  app.use(rateLimitMiddleware(dependencies.cache));

  // Routes
  app.use('/health', healthRouter(dependencies));
  app.use('/api', apiRouter(dependencies));

  // Error handling
  app.use(errorMiddleware(dependencies.errorHandler));

  return app;
}
```

### 2. Dependency Injection Setup

#### src/container.ts

```typescript
import { CacheService } from '@core/cache/cache.service';
import { Logger } from '@core/monitoring/logger.service';
import { MetricsService } from '@core/monitoring/metrics.service';
import { ErrorHandler } from '@core/errors/error.handler';
import { DataFetcher } from '@modules/data-fetcher/data-fetcher.service';
import { Processor } from '@modules/processor/processor.service';
import { config } from '@config/app.config';

export class Container {
  private services: Map<string, any> = new Map();

  constructor() {
    this.registerServices();
  }

  private registerServices(): void {
    // Core services
    this.register('logger', () => new Logger('app', config.log.level));
    this.register('metrics', () => new MetricsService());
    
    this.register('cache', () => 
      new CacheService(
        config.cache,
        this.get('logger'),
        this.get('metrics')
      )
    );

    this.register('errorHandler', () =>
      new ErrorHandler(
        this.get('logger'),
        this.get('metrics')
      )
    );

    // Business services
    this.register('dataFetcher', () =>
      new DataFetcher(
        this.get('cache'),
        this.get('logger'),
        this.get('metrics')
      )
    );

    this.register('processor', () =>
      new Processor(
        this.get('dataFetcher'),
        this.get('cache'),
        this.get('logger')
      )
    );
  }

  register<T>(name: string, factory: () => T): void {
    this.services.set(name, {
      factory,
      instance: null,
    });
  }

  get<T>(name: string): T {
    const service = this.services.get(name);
    
    if (!service) {
      throw new Error(`Service ${name} not found`);
    }

    if (!service.instance) {
      service.instance = service.factory();
    }

    return service.instance;
  }

  async shutdown(): Promise<void> {
    // Shutdown services in reverse order
    const shutdownOrder = [
      'processor',
      'dataFetcher',
      'errorHandler',
      'cache',
      'metrics',
      'logger',
    ];

    for (const serviceName of shutdownOrder) {
      const service = this.get(serviceName);
      if (service && typeof service.shutdown === 'function') {
        await service.shutdown();
      }
    }
  }
}
```

### 3. Main Application Entry Point

#### src/index.ts

```typescript
import { createApp } from './app';
import { Container } from './container';
import { config } from '@config/app.config';
import { gracefulShutdown } from '@core/utils/shutdown.util';

async function main() {
  const container = new Container();
  const logger = container.get<Logger>('logger');

  try {
    // Create and start the application
    const app = createApp({
      logger: container.get('logger'),
      metrics: container.get('metrics'),
      cache: container.get('cache'),
      errorHandler: container.get('errorHandler'),
      dataFetcher: container.get('dataFetcher'),
      processor: container.get('processor'),
    });

    const server = app.listen(config.port, () => {
      logger.info(`Server started on port ${config.port}`);
    });

    // Setup graceful shutdown
    gracefulShutdown(server, async () => {
      logger.info('Shutting down gracefully...');
      await container.shutdown();
      logger.info('Shutdown complete');
    });

  } catch (error) {
    logger.fatal('Failed to start application', { error });
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

main();
```

---

## Configuration Examples

### 1. Environment Configuration

#### .env.example

```bash
# Application
NODE_ENV=development
PORT=3000
LOG_LEVEL=debug

# Cache
CACHE_TTL=3600
CACHE_CHECK_PERIOD=600

# Database
DATABASE_URL=mongodb://localhost:27017/myapp
DATABASE_POOL_SIZE=10

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# External Services
API_BASE_URL=https://api.example.com
API_KEY=your-api-key
API_TIMEOUT=5000

# Monitoring
METRICS_PORT=9090
SENTRY_DSN=

# Security
JWT_SECRET=your-jwt-secret
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### 2. Application Configuration

#### src/config/app.config.ts

```typescript
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const configSchema = z.object({
  env: z.enum(['development', 'test', 'production']),
  port: z.number().min(1).max(65535),
  log: z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']),
  }),
  cache: z.object({
    ttl: z.number().positive(),
    checkPeriod: z.number().positive(),
  }),
  database: z.object({
    url: z.string().url(),
    poolSize: z.number().positive(),
  }),
  redis: z.object({
    url: z.string().url(),
    password: z.string().optional(),
  }),
  api: z.object({
    baseUrl: z.string().url(),
    key: z.string(),
    timeout: z.number().positive(),
  }),
  monitoring: z.object({
    metricsPort: z.number().min(1).max(65535),
    sentryDsn: z.string().optional(),
  }),
  security: z.object({
    jwtSecret: z.string().min(32),
    rateLimit: z.object({
      windowMs: z.number().positive(),
      maxRequests: z.number().positive(),
    }),
  }),
});

const rawConfig = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  log: {
    level: process.env.LOG_LEVEL || 'info',
  },
  cache: {
    ttl: parseInt(process.env.CACHE_TTL || '3600', 10),
    checkPeriod: parseInt(process.env.CACHE_CHECK_PERIOD || '600', 10),
  },
  database: {
    url: process.env.DATABASE_URL || 'mongodb://localhost:27017/myapp',
    poolSize: parseInt(process.env.DATABASE_POOL_SIZE || '10', 10),
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD,
  },
  api: {
    baseUrl: process.env.API_BASE_URL || 'https://api.example.com',
    key: process.env.API_KEY || '',
    timeout: parseInt(process.env.API_TIMEOUT || '5000', 10),
  },
  monitoring: {
    metricsPort: parseInt(process.env.METRICS_PORT || '9090', 10),
    sentryDsn: process.env.SENTRY_DSN,
  },
  security: {
    jwtSecret: process.env.JWT_SECRET || 'default-secret-change-me',
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10),
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    },
  },
};

export const config = configSchema.parse(rawConfig);
export type Config = z.infer<typeof configSchema>;
```

---

## Summary

This implementation example demonstrates:

1. **Clean Architecture**: Separation of concerns with clearly defined layers
2. **Dependency Injection**: Centralized service management with container pattern
3. **Error Handling**: Comprehensive error types and global error handling
4. **Caching Strategy**: Multi-layer caching with metrics and monitoring
5. **Monitoring**: Integrated logging and metrics collection
6. **Testing**: Unit, integration, and E2E test examples
7. **Configuration**: Environment-based configuration with validation
8. **Resilience Patterns**: Circuit breaker, retry logic, and graceful degradation
9. **TypeScript Best Practices**: Strong typing, interfaces, and modern ES features
10. **Production Readiness**: Health checks, graceful shutdown, and observability

Each component is designed to be:
- **Testable**: With dependency injection and clear interfaces
- **Maintainable**: Following SOLID principles and clean code practices
- **Scalable**: Ready for horizontal scaling and high load
- **Observable**: With comprehensive logging and metrics
- **Resilient**: With proper error handling and recovery mechanisms