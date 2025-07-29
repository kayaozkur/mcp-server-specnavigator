# Monitoring & Observability Setup Guide

A comprehensive guide for implementing monitoring and observability in your applications, extracted from the PROJECT_ARCHITECTURE_TEMPLATE.md.

## Table of Contents

1. [Structured Logging Setup](#structured-logging-setup)
2. [Metrics Collection Configuration](#metrics-collection-configuration)
3. [Distributed Tracing Implementation](#distributed-tracing-implementation)
4. [Health Checks Setup](#health-checks-setup)
5. [Example Dashboard Configurations](#example-dashboard-configurations)
6. [Alert Rules](#alert-rules)
7. [MCP-Specific Monitoring](#mcp-specific-monitoring)
8. [Cache Monitoring](#cache-monitoring)
9. [Specification Update Monitoring](#specification-update-monitoring)

## Structured Logging Setup

### Basic Logger Implementation

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

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  data?: any;
  context: LogContext;
  stack?: string;
}

interface LogTransport {
  write(entry: LogEntry): void;
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
  
  // Convenience methods
  debug(message: string, data?: any) {
    this.log(LogLevel.DEBUG, message, data);
  }
  
  info(message: string, data?: any) {
    this.log(LogLevel.INFO, message, data);
  }
  
  warn(message: string, data?: any) {
    this.log(LogLevel.WARN, message, data);
  }
  
  error(message: string, data?: any) {
    this.log(LogLevel.ERROR, message, data);
  }
  
  fatal(message: string, data?: any) {
    this.log(LogLevel.FATAL, message, data);
  }
  
  // Contextual logging
  child(additionalContext: Partial<LogContext>): StructuredLogger {
    return new StructuredLogger(
      { ...this.context, ...additionalContext },
      this.transports
    );
  }
}
```

### Log Transports Implementation

```typescript
// Console Transport
class ConsoleTransport implements LogTransport {
  write(entry: LogEntry): void {
    const { timestamp, level, message, data, context } = entry;
    const output = {
      timestamp,
      level,
      message,
      ...context,
      ...(data && { data })
    };
    
    if (level === 'ERROR' || level === 'FATAL') {
      console.error(JSON.stringify(output));
    } else {
      console.log(JSON.stringify(output));
    }
  }
}

// File Transport
import { createWriteStream, WriteStream } from 'fs';
import { join } from 'path';

class FileTransport implements LogTransport {
  private stream: WriteStream;
  
  constructor(private config: { logDir: string; filename: string }) {
    const logPath = join(config.logDir, config.filename);
    this.stream = createWriteStream(logPath, { flags: 'a' });
  }
  
  write(entry: LogEntry): void {
    this.stream.write(JSON.stringify(entry) + '\n');
  }
  
  close(): void {
    this.stream.end();
  }
}

// HTTP Transport for centralized logging
class HttpTransport implements LogTransport {
  constructor(
    private config: {
      endpoint: string;
      apiKey: string;
      batchSize?: number;
      flushInterval?: number;
    }
  ) {
    this.buffer = [];
    this.startBatchTimer();
  }
  
  private buffer: LogEntry[] = [];
  
  write(entry: LogEntry): void {
    this.buffer.push(entry);
    
    if (this.buffer.length >= (this.config.batchSize || 100)) {
      this.flush();
    }
  }
  
  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    
    const entries = this.buffer.splice(0, this.buffer.length);
    
    try {
      await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify({ logs: entries })
      });
    } catch (error) {
      // Put logs back if sending failed
      this.buffer.unshift(...entries);
      console.error('Failed to send logs:', error);
    }
  }
  
  private startBatchTimer(): void {
    setInterval(() => {
      this.flush();
    }, this.config.flushInterval || 5000);
  }
}
```

### Log Aggregation and Pattern Detection

```typescript
class LogAggregator {
  private buffer: LogEntry[] = [];
  private flushInterval = 5000;
  private config = {
    errorThreshold: 10,
    windowSize: 60000 // 1 minute
  };
  
  constructor(private alerting: AlertingService) {}
  
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
      const recentErrors = this.getRecentErrors(this.config.windowSize);
      if (recentErrors.length > this.config.errorThreshold) {
        this.alerting.sendAlert({
          type: 'error_spike',
          count: recentErrors.length,
          threshold: this.config.errorThreshold,
          window: `${this.config.windowSize / 1000}s`
        });
      }
    }
    
    // Detect repeated error patterns
    const errorPattern = this.findErrorPattern(entry);
    if (errorPattern) {
      this.alerting.sendAlert({
        type: 'repeated_error',
        pattern: errorPattern,
        count: errorPattern.count
      });
    }
  }
  
  private getRecentErrors(windowMs: number): LogEntry[] {
    const cutoff = Date.now() - windowMs;
    return this.buffer.filter(
      entry => 
        entry.level === 'ERROR' && 
        new Date(entry.timestamp).getTime() > cutoff
    );
  }
  
  private findErrorPattern(entry: LogEntry): any {
    if (entry.level !== 'ERROR') return null;
    
    // Group errors by message pattern
    const recentErrors = this.getRecentErrors(300000); // 5 minutes
    const patterns = new Map<string, number>();
    
    recentErrors.forEach(error => {
      const pattern = this.normalizeErrorMessage(error.message);
      patterns.set(pattern, (patterns.get(pattern) || 0) + 1);
    });
    
    // Find patterns that occur more than 5 times
    for (const [pattern, count] of patterns.entries()) {
      if (count > 5) {
        return { pattern, count };
      }
    }
    
    return null;
  }
  
  private normalizeErrorMessage(message: string): string {
    // Remove dynamic values like IDs, timestamps, etc.
    return message
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<UUID>')
      .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\b/g, '<TIMESTAMP>')
      .replace(/\b\d+\b/g, '<NUMBER>');
  }
  
  private isAnomaly(entry: LogEntry): boolean {
    // Implement anomaly detection logic
    // For example, check for unusual log levels, unexpected services, etc.
    return false;
  }
}
```

### Practical Logger Setup

```typescript
// Initialize logger with multiple transports
function createLogger(config: {
  service: string;
  environment: string;
  version: string;
}): StructuredLogger {
  const context: LogContext = {
    correlationId: generateCorrelationId(),
    service: config.service,
    environment: config.environment,
    version: config.version
  };
  
  const transports: LogTransport[] = [
    new ConsoleTransport(),
    new FileTransport({
      logDir: './logs',
      filename: `${config.service}-${new Date().toISOString().split('T')[0]}.log`
    })
  ];
  
  // Add HTTP transport for production
  if (config.environment === 'production') {
    transports.push(new HttpTransport({
      endpoint: process.env.LOG_ENDPOINT!,
      apiKey: process.env.LOG_API_KEY!,
      batchSize: 100,
      flushInterval: 5000
    }));
  }
  
  return new StructuredLogger(context, transports);
}

// Usage example
const logger = createLogger({
  service: 'mcp-server',
  environment: process.env.NODE_ENV || 'development',
  version: process.env.APP_VERSION || '1.0.0'
});

// Create child logger for specific request
app.use((req, res, next) => {
  req.logger = logger.child({
    requestId: generateRequestId(),
    userId: req.user?.id
  });
  next();
});
```

## Metrics Collection Configuration

### Metric Collector Interface and Implementation

```typescript
interface MetricCollector {
  counter(name: string, value?: number, tags?: Record<string, string>): void;
  gauge(name: string, value: number, tags?: Record<string, string>): void;
  histogram(name: string, value: number, tags?: Record<string, string>): void;
  timer(name: string): Timer;
}

interface Timer {
  end(): void;
}

class Timer {
  private startTime: number;
  
  constructor(private callback: (duration: number) => void) {
    this.startTime = Date.now();
  }
  
  end(): void {
    const duration = Date.now() - this.startTime;
    this.callback(duration);
  }
}
```

### Prometheus Collector Implementation

```typescript
import { Registry, Counter, Gauge, Histogram } from 'prom-client';

class PrometheusCollector implements MetricCollector {
  private registry: Registry;
  private counters: Map<string, Counter> = new Map();
  private gauges: Map<string, Gauge> = new Map();
  private histograms: Map<string, Histogram> = new Map();
  
  constructor() {
    this.registry = new Registry();
  }
  
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
  
  private getOrCreateCounter(name: string): Counter {
    if (!this.counters.has(name)) {
      const counter = new Counter({
        name,
        help: `Counter for ${name}`,
        labelNames: this.extractLabelNames(name),
        registers: [this.registry]
      });
      this.counters.set(name, counter);
    }
    return this.counters.get(name)!;
  }
  
  private getOrCreateGauge(name: string): Gauge {
    if (!this.gauges.has(name)) {
      const gauge = new Gauge({
        name,
        help: `Gauge for ${name}`,
        labelNames: this.extractLabelNames(name),
        registers: [this.registry]
      });
      this.gauges.set(name, gauge);
    }
    return this.gauges.get(name)!;
  }
  
  private getOrCreateHistogram(name: string): Histogram {
    if (!this.histograms.has(name)) {
      const histogram = new Histogram({
        name,
        help: `Histogram for ${name}`,
        labelNames: this.extractLabelNames(name),
        buckets: [0.1, 5, 15, 50, 100, 500, 1000, 2500, 5000],
        registers: [this.registry]
      });
      this.histograms.set(name, histogram);
    }
    return this.histograms.get(name)!;
  }
  
  private extractLabelNames(metricName: string): string[] {
    // Extract common label names based on metric patterns
    const labels = ['status', 'method', 'endpoint', 'error', 'type'];
    return labels;
  }
  
  // Expose metrics endpoint
  getMetrics(): Promise<string> {
    return this.registry.metrics();
  }
}
```

### Business Metrics Implementation

```typescript
class BusinessMetrics {
  constructor(private collector: MetricCollector) {}
  
  recordRequest(endpoint: string, method: string, status: number, duration: number): void {
    // Total requests counter
    this.collector.counter('http_requests_total', 1, {
      endpoint,
      method,
      status: status.toString()
    });
    
    // Request duration histogram
    this.collector.histogram('http_request_duration_ms', duration, {
      endpoint,
      method
    });
    
    // Error counters
    if (status >= 500) {
      this.collector.counter('http_errors_total', 1, {
        endpoint,
        method,
        type: 'server_error'
      });
    } else if (status >= 400) {
      this.collector.counter('http_errors_total', 1, {
        endpoint,
        method,
        type: 'client_error'
      });
    }
    
    // Track slow requests
    if (duration > 1000) {
      this.collector.counter('slow_requests_total', 1, {
        endpoint,
        method,
        threshold: '1000ms'
      });
    }
  }
  
  recordBusinessEvent(event: string, value?: number, metadata?: any): void {
    this.collector.counter(`business_event_${event}`, value || 1, metadata);
  }
  
  recordUserAction(action: string, userId: string, metadata?: any): void {
    this.collector.counter('user_actions_total', 1, {
      action,
      ...metadata
    });
  }
  
  recordPayment(amount: number, currency: string, status: string): void {
    this.collector.counter('payments_total', 1, { currency, status });
    
    if (status === 'success') {
      this.collector.histogram('payment_amount', amount, { currency });
      this.collector.counter('revenue_total', amount, { currency });
    }
  }
  
  recordQueueDepth(queueName: string, depth: number): void {
    this.collector.gauge('queue_depth', depth, { queue: queueName });
  }
  
  recordTaskExecution(taskName: string, duration: number, success: boolean): void {
    this.collector.histogram('task_duration_ms', duration, {
      task: taskName,
      status: success ? 'success' : 'failure'
    });
    
    this.collector.counter('tasks_total', 1, {
      task: taskName,
      status: success ? 'success' : 'failure'
    });
  }
}
```

### Express Middleware for Metrics

```typescript
import express from 'express';

function metricsMiddleware(
  metrics: BusinessMetrics
): express.RequestHandler {
  return (req, res, next) => {
    const start = Date.now();
    
    // Capture response finish
    res.on('finish', () => {
      const duration = Date.now() - start;
      const endpoint = req.route?.path || req.path;
      
      metrics.recordRequest(
        endpoint,
        req.method,
        res.statusCode,
        duration
      );
    });
    
    next();
  };
}

// Setup metrics endpoint
function setupMetricsEndpoint(
  app: express.Application,
  collector: PrometheusCollector
): void {
  app.get('/metrics', async (req, res) => {
    try {
      const metrics = await collector.getMetrics();
      res.set('Content-Type', 'text/plain');
      res.send(metrics);
    } catch (error) {
      res.status(500).send('Error collecting metrics');
    }
  });
}
```

## Distributed Tracing Implementation

### Tracing Core Components

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
  private backend: TracingBackend;
  
  constructor(backend: TracingBackend) {
    this.backend = backend;
  }
  
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
    this.backend.send(span);
  }
  
  // Context propagation for HTTP requests
  inject(span: Span, carrier: any): void {
    carrier['x-trace-id'] = span.traceId;
    carrier['x-span-id'] = span.spanId;
    carrier['x-parent-span-id'] = span.parentSpanId;
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
  
  private generateTraceId(): string {
    return crypto.randomBytes(16).toString('hex');
  }
  
  private generateSpanId(): string {
    return crypto.randomBytes(8).toString('hex');
  }
}

// Span builder for easier usage
class SpanBuilder {
  constructor(private span: Span, private tracer: TracingManager) {}
  
  setTag(key: string, value: any): SpanBuilder {
    this.span.tags[key] = value;
    return this;
  }
  
  log(fields: Record<string, any>): SpanBuilder {
    this.span.logs.push({
      timestamp: Date.now(),
      fields
    });
    return this;
  }
  
  setOperationName(name: string): SpanBuilder {
    this.span.operationName = name;
    return this;
  }
  
  finish(): void {
    this.tracer.finishSpan(this.span);
  }
}
```

### Express Tracing Middleware

```typescript
function tracingMiddleware(tracer: TracingManager): express.RequestHandler {
  return (req, res, next) => {
    // Extract parent span from headers
    const parentSpan = tracer.extract(req.headers);
    
    // Start new span
    const span = tracer.startSpan(
      `${req.method} ${req.path}`,
      parentSpan || undefined
    );
    
    // Add tags
    span.tags = {
      'http.method': req.method,
      'http.url': req.url,
      'http.remote_addr': req.ip,
      'user.id': req.user?.id
    };
    
    // Store span in request
    (req as any).span = span;
    
    // Intercept response
    const originalSend = res.send;
    res.send = function(data: any) {
      span.tags['http.status_code'] = res.statusCode;
      
      if (res.statusCode >= 400) {
        span.tags['error'] = true;
        span.logs.push({
          timestamp: Date.now(),
          fields: {
            event: 'error',
            message: data?.message || 'HTTP error'
          }
        });
      }
      
      tracer.finishSpan(span);
      return originalSend.call(this, data);
    };
    
    next();
  };
}
```

### Database Tracing

```typescript
class TracedDatabase {
  constructor(
    private db: Database,
    private tracer: TracingManager
  ) {}
  
  async query(sql: string, params?: any[], parentSpan?: Span): Promise<any> {
    const span = this.tracer.startSpan('db.query', parentSpan);
    
    span.tags = {
      'db.type': 'postgresql',
      'db.statement': sql.substring(0, 100), // Truncate for safety
      'db.operation': this.extractOperation(sql)
    };
    
    try {
      const result = await this.db.query(sql, params);
      
      span.tags['db.rows_affected'] = result.rowCount;
      
      return result;
    } catch (error) {
      span.tags['error'] = true;
      span.logs.push({
        timestamp: Date.now(),
        fields: {
          event: 'error',
          message: error.message,
          stack: error.stack
        }
      });
      
      throw error;
    } finally {
      this.tracer.finishSpan(span);
    }
  }
  
  private extractOperation(sql: string): string {
    const operation = sql.trim().split(' ')[0].toUpperCase();
    return operation;
  }
}
```

### HTTP Client Tracing

```typescript
class TracedHttpClient {
  constructor(private tracer: TracingManager) {}
  
  async fetch(url: string, options: RequestInit = {}, parentSpan?: Span): Promise<Response> {
    const span = this.tracer.startSpan('http.request', parentSpan);
    
    span.tags = {
      'http.method': options.method || 'GET',
      'http.url': url,
      'span.kind': 'client'
    };
    
    // Inject tracing headers
    const headers = new Headers(options.headers);
    this.tracer.inject(span, headers);
    
    try {
      const response = await fetch(url, {
        ...options,
        headers
      });
      
      span.tags['http.status_code'] = response.status;
      
      if (!response.ok) {
        span.tags['error'] = true;
      }
      
      return response;
    } catch (error) {
      span.tags['error'] = true;
      span.logs.push({
        timestamp: Date.now(),
        fields: {
          event: 'error',
          message: error.message
        }
      });
      
      throw error;
    } finally {
      this.tracer.finishSpan(span);
    }
  }
}
```

## Health Checks Setup

### Health Check Framework

```typescript
interface HealthStatus {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  message?: string;
  error?: string;
  metrics?: Record<string, any>;
  lastCheck?: Date;
}

interface HealthCheck {
  name: string;
  check(): Promise<HealthStatus>;
}

interface OverallHealth {
  status: 'healthy' | 'unhealthy' | 'degraded';
  checks: HealthStatus[];
  timestamp: Date;
  version?: string;
  uptime?: number;
}

class HealthMonitor {
  private checks: HealthCheck[] = [];
  private cache: Map<string, HealthStatus> = new Map();
  private checkInterval: number = 30000; // 30 seconds
  private startTime: number = Date.now();
  
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
          status: 'unhealthy' as const,
          error: result.reason.message
        };
      }
    });
    
    // Update cache
    statuses.forEach(status => {
      this.cache.set(status.name, status);
    });
    
    return {
      status: this.calculateOverallStatus(statuses),
      checks: statuses,
      timestamp: new Date(),
      version: process.env.APP_VERSION,
      uptime: Date.now() - this.startTime
    };
  }
  
  private async executeCheck(check: HealthCheck): Promise<HealthStatus> {
    const timeout = new Promise<HealthStatus>((_, reject) => {
      setTimeout(() => reject(new Error('Health check timeout')), 5000);
    });
    
    try {
      const result = await Promise.race([check.check(), timeout]);
      return {
        ...result,
        lastCheck: new Date()
      };
    } catch (error) {
      return {
        name: check.name,
        status: 'unhealthy',
        error: error.message,
        lastCheck: new Date()
      };
    }
  }
  
  private calculateOverallStatus(statuses: HealthStatus[]): 'healthy' | 'unhealthy' | 'degraded' {
    const unhealthyCount = statuses.filter(s => s.status === 'unhealthy').length;
    const degradedCount = statuses.filter(s => s.status === 'degraded').length;
    
    if (unhealthyCount > 0) {
      return 'unhealthy';
    } else if (degradedCount > 0) {
      return 'degraded';
    }
    return 'healthy';
  }
  
  // Start periodic health checks
  startPeriodicChecks(): void {
    setInterval(async () => {
      try {
        await this.checkHealth();
      } catch (error) {
        console.error('Periodic health check failed:', error);
      }
    }, this.checkInterval);
  }
  
  // Get cached status
  getCachedStatus(): OverallHealth {
    const statuses = Array.from(this.cache.values());
    return {
      status: this.calculateOverallStatus(statuses),
      checks: statuses,
      timestamp: new Date(),
      version: process.env.APP_VERSION,
      uptime: Date.now() - this.startTime
    };
  }
}
```

### Common Health Check Implementations

```typescript
// Database Health Check
class DatabaseHealthCheck implements HealthCheck {
  name = 'database';
  
  constructor(private db: Database) {}
  
  async check(): Promise<HealthStatus> {
    const start = Date.now();
    
    try {
      await this.db.query('SELECT 1');
      const latency = Date.now() - start;
      
      return { 
        name: this.name, 
        status: latency < 100 ? 'healthy' : 'degraded',
        metrics: { latency_ms: latency }
      };
    } catch (error) {
      return { 
        name: this.name, 
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// Redis Health Check
class RedisHealthCheck implements HealthCheck {
  name = 'redis';
  
  constructor(private redis: RedisClient) {}
  
  async check(): Promise<HealthStatus> {
    try {
      const start = Date.now();
      await this.redis.ping();
      const latency = Date.now() - start;
      
      // Check memory usage
      const info = await this.redis.info('memory');
      const memoryUsage = this.parseMemoryUsage(info);
      
      return {
        name: this.name,
        status: this.evaluateRedisHealth(latency, memoryUsage),
        metrics: {
          latency_ms: latency,
          memory_used_mb: memoryUsage
        }
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'unhealthy',
        error: error.message
      };
    }
  }
  
  private evaluateRedisHealth(latency: number, memoryUsage: number): 'healthy' | 'degraded' {
    if (latency > 50 || memoryUsage > 1024) {
      return 'degraded';
    }
    return 'healthy';
  }
  
  private parseMemoryUsage(info: string): number {
    const match = info.match(/used_memory:(\d+)/);
    return match ? parseInt(match[1]) / 1024 / 1024 : 0;
  }
}

// Disk Space Health Check
import { statfs } from 'fs/promises';

class DiskSpaceHealthCheck implements HealthCheck {
  name = 'disk_space';
  
  constructor(private path: string = '/') {}
  
  async check(): Promise<HealthStatus> {
    try {
      const stats = await statfs(this.path);
      const totalGB = stats.blocks * stats.bsize / 1024 / 1024 / 1024;
      const freeGB = stats.bfree * stats.bsize / 1024 / 1024 / 1024;
      const usedPercent = ((totalGB - freeGB) / totalGB) * 100;
      
      return {
        name: this.name,
        status: usedPercent > 90 ? 'unhealthy' : usedPercent > 80 ? 'degraded' : 'healthy',
        metrics: {
          total_gb: totalGB.toFixed(2),
          free_gb: freeGB.toFixed(2),
          used_percent: usedPercent.toFixed(2)
        }
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// External Service Health Check
class ExternalServiceHealthCheck implements HealthCheck {
  constructor(
    public name: string,
    private url: string,
    private timeout: number = 5000
  ) {}
  
  async check(): Promise<HealthStatus> {
    try {
      const start = Date.now();
      const response = await fetch(this.url, {
        signal: AbortSignal.timeout(this.timeout)
      });
      const latency = Date.now() - start;
      
      return {
        name: this.name,
        status: response.ok ? 'healthy' : 'degraded',
        metrics: {
          latency_ms: latency,
          status_code: response.status
        }
      };
    } catch (error) {
      return {
        name: this.name,
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}

// Memory Health Check
class MemoryHealthCheck implements HealthCheck {
  name = 'memory';
  
  async check(): Promise<HealthStatus> {
    const usage = process.memoryUsage();
    const heapUsedMB = usage.heapUsed / 1024 / 1024;
    const heapTotalMB = usage.heapTotal / 1024 / 1024;
    const rssMB = usage.rss / 1024 / 1024;
    const heapPercent = (usage.heapUsed / usage.heapTotal) * 100;
    
    return {
      name: this.name,
      status: heapPercent > 90 ? 'unhealthy' : heapPercent > 75 ? 'degraded' : 'healthy',
      metrics: {
        heap_used_mb: heapUsedMB.toFixed(2),
        heap_total_mb: heapTotalMB.toFixed(2),
        rss_mb: rssMB.toFixed(2),
        heap_percent: heapPercent.toFixed(2)
      }
    };
  }
}
```

### Health Check Express Endpoint

```typescript
function setupHealthEndpoints(
  app: express.Application,
  healthMonitor: HealthMonitor
): void {
  // Liveness probe - simple check that the app is running
  app.get('/health/live', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });
  
  // Readiness probe - check if app is ready to serve traffic
  app.get('/health/ready', async (req, res) => {
    const health = await healthMonitor.checkHealth();
    const statusCode = health.status === 'healthy' ? 200 : 503;
    
    res.status(statusCode).json(health);
  });
  
  // Detailed health check
  app.get('/health', async (req, res) => {
    const verbose = req.query.verbose === 'true';
    
    if (verbose) {
      const health = await healthMonitor.checkHealth();
      res.json(health);
    } else {
      // Return cached status for performance
      const health = healthMonitor.getCachedStatus();
      res.json({
        status: health.status,
        timestamp: health.timestamp
      });
    }
  });
}
```

## Example Dashboard Configurations

### Grafana Dashboard JSON

```json
{
  "dashboard": {
    "title": "Application Monitoring Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_errors_total[5m])",
            "legendFormat": "{{type}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Response Time (p95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_ms_bucket[5m]))",
            "legendFormat": "{{endpoint}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Memory Usage",
        "targets": [
          {
            "expr": "mcp_memory_usage_bytes{measurement=\"heap_used\"}",
            "legendFormat": "Heap Used"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {
            "expr": "cache_hit_rate",
            "legendFormat": "{{layer}}"
          }
        ],
        "type": "gauge"
      },
      {
        "title": "Active Connections",
        "targets": [
          {
            "expr": "mcp_transport_connections_active",
            "legendFormat": "Active"
          }
        ],
        "type": "stat"
      }
    ]
  }
}
```

### CloudWatch Dashboard

```typescript
const dashboardBody = {
  widgets: [
    {
      type: "metric",
      properties: {
        metrics: [
          ["MyApp", "http_requests_total", { stat: "Sum" }],
          [".", "http_errors_total", { stat: "Sum" }]
        ],
        period: 300,
        stat: "Average",
        region: "us-east-1",
        title: "Request and Error Rates"
      }
    },
    {
      type: "metric",
      properties: {
        metrics: [
          ["MyApp", "http_request_duration_ms", { stat: "p95" }],
          [".", ".", { stat: "p99" }]
        ],
        period: 300,
        stat: "Average",
        region: "us-east-1",
        title: "Response Time Percentiles"
      }
    }
  ]
};
```

## Alert Rules

### Prometheus Alert Rules

```yaml
groups:
  - name: application_alerts
    interval: 30s
    rules:
      # High Error Rate
      - alert: HighErrorRate
        expr: rate(http_errors_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"
      
      # High Response Time
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_ms_bucket[5m])) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value }}ms"
      
      # Memory Usage
      - alert: HighMemoryUsage
        expr: (mcp_memory_usage_bytes{measurement="heap_used"} / mcp_memory_usage_bytes{measurement="heap_total"}) > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Heap usage is at {{ $value | humanizePercentage }}"
      
      # Cache Miss Rate
      - alert: HighCacheMissRate
        expr: (1 - cache_hit_rate) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High cache miss rate"
          description: "Cache miss rate is {{ $value | humanizePercentage }}"
      
      # Service Down
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "{{ $labels.instance }} has been down for more than 1 minute"
```

### Alert Manager Configuration

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'team-notifications'
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
    - match:
        severity: warning
      receiver: 'slack'

receivers:
  - name: 'team-notifications'
    email_configs:
      - to: 'team@example.com'
        from: 'alerts@example.com'
        headers:
          Subject: 'Alert: {{ .GroupLabels.alertname }}'
  
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'
        description: '{{ .CommonAnnotations.summary }}'
  
  - name: 'slack'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK'
        channel: '#alerts'
        title: 'Alert: {{ .GroupLabels.alertname }}'
        text: '{{ .CommonAnnotations.description }}'
```

## MCP-Specific Monitoring

### MCP Server Monitor Implementation

```typescript
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
  
  private getMessageQueueDepth(): number {
    // Implementation specific to your message queue
    return 0;
  }
}
```

## Cache Monitoring

### Cache Monitor Implementation

```typescript
class CacheMonitor {
  private metrics: MetricCollector;
  
  constructor(metrics: MetricCollector) {
    this.metrics = metrics;
  }
  
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
  
  private getMetric(name: string): number {
    // Implementation to retrieve metric value
    return 0;
  }
  
  private getCacheSize(layer: string): number {
    // Implementation specific to each cache layer
    return 0;
  }
  
  private getCacheItemCount(layer: string): number {
    // Implementation specific to each cache layer
    return 0;
  }
  
  private getExpiredItemCount(): number {
    // Implementation to count expired items
    return 0;
  }
}
```

## Specification Update Monitoring

### Spec Update Monitor Implementation

```typescript
class SpecUpdateMonitor {
  private metrics: MetricCollector;
  private logger: StructuredLogger;
  
  constructor(metrics: MetricCollector, logger: StructuredLogger) {
    this.metrics = metrics;
    this.logger = logger;
  }
  
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
  
  private async checkForUpdates(source: string): Promise<boolean> {
    // Implementation specific to your update check logic
    return false;
  }
  
  private getLastUpdateTime(source: string): number {
    // Implementation to get last update timestamp
    return Date.now();
  }
  
  private async getCurrentVersion(source: string): Promise<string> {
    // Implementation to get current version
    return '1.0.0';
  }
  
  private versionToNumber(version: string): number {
    // Convert semantic version to number for gauges
    const [major, minor, patch] = version.split('.').map(Number);
    return major * 10000 + minor * 100 + patch;
  }
  
  private async parse(content: string): Promise<any> {
    // Implementation of parsing logic
    return {};
  }
}
```

## Complete Setup Example

```typescript
// monitoring-setup.ts
import express from 'express';

export function setupMonitoring(app: express.Application) {
  // Initialize collectors
  const prometheusCollector = new PrometheusCollector();
  const metrics = new BusinessMetrics(prometheusCollector);
  
  // Initialize logger
  const logger = createLogger({
    service: 'mcp-server',
    environment: process.env.NODE_ENV || 'development',
    version: process.env.APP_VERSION || '1.0.0'
  });
  
  // Initialize tracing
  const tracingBackend = new JaegerBackend({
    serviceName: 'mcp-server',
    endpoint: process.env.JAEGER_ENDPOINT
  });
  const tracer = new TracingManager(tracingBackend);
  
  // Setup health checks
  const healthMonitor = new HealthMonitor();
  healthMonitor.register(new DatabaseHealthCheck(db));
  healthMonitor.register(new RedisHealthCheck(redis));
  healthMonitor.register(new DiskSpaceHealthCheck());
  healthMonitor.register(new MemoryHealthCheck());
  healthMonitor.register(new ExternalServiceHealthCheck('github', 'https://api.github.com/health'));
  
  // Start periodic health checks
  healthMonitor.startPeriodicChecks();
  
  // Apply middleware
  app.use(metricsMiddleware(metrics));
  app.use(tracingMiddleware(tracer));
  
  // Setup endpoints
  setupMetricsEndpoint(app, prometheusCollector);
  setupHealthEndpoints(app, healthMonitor);
  
  // MCP-specific monitoring
  const mcpMonitor = new MCPServerMonitor(prometheusCollector, logger);
  const cacheMonitor = new CacheMonitor(prometheusCollector);
  const specMonitor = new SpecUpdateMonitor(prometheusCollector, logger);
  
  // Start cache metrics collection
  cacheMonitor.calculateCacheMetrics();
  
  return {
    logger,
    metrics,
    tracer,
    healthMonitor,
    mcpMonitor,
    cacheMonitor,
    specMonitor
  };
}

// Usage in your application
const monitoring = setupMonitoring(app);

// Use in your code
monitoring.logger.info('Application started');
monitoring.metrics.recordBusinessEvent('server_start');

// Monitor specific operations
await monitoring.mcpMonitor.monitorToolCall('search', async () => {
  // Your tool implementation
});
```

## Best Practices

1. **Log Levels**: Use appropriate log levels (DEBUG for development, INFO for general operations, WARN for recoverable issues, ERROR for failures)

2. **Metric Naming**: Follow consistent naming conventions (e.g., `service_component_measurement_unit`)

3. **Tag Cardinality**: Keep tag cardinality low to avoid metric explosion

4. **Sampling**: For high-volume operations, consider sampling traces and logs

5. **Retention**: Set appropriate retention policies for logs and metrics

6. **Security**: Never log sensitive information (passwords, tokens, PII)

7. **Performance**: Monitor the overhead of monitoring itself

8. **Alerting**: Start with simple alerts and refine based on actual incidents

This guide provides a comprehensive foundation for implementing monitoring and observability in your applications. Customize and extend these patterns based on your specific needs and infrastructure.