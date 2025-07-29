# CI/CD Setup Guide for MCP Server SpecNavigator

This comprehensive guide covers the complete CI/CD pipeline setup for the MCP Server SpecNavigator project, including GitHub Actions workflows, deployment strategies, security scanning, and performance testing.

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions Workflows](#github-actions-workflows)
3. [Deployment Strategies](#deployment-strategies)
4. [Pipeline Configuration](#pipeline-configuration)
5. [Security Scanning Integration](#security-scanning-integration)
6. [Performance Testing Setup](#performance-testing-setup)
7. [Best Practices](#best-practices)
8. [Monitoring and Alerts](#monitoring-and-alerts)
9. [Troubleshooting](#troubleshooting)

---

## Overview

Our CI/CD pipeline is designed to ensure code quality, security, and reliability through automated testing, scanning, and deployment processes. The pipeline uses GitHub Actions as the primary CI/CD platform and supports multiple deployment strategies.

### Key Features

- **Multi-stage pipeline** with parallel job execution
- **Cross-platform testing** (Ubuntu, Windows, macOS)
- **Automated security scanning** at multiple levels
- **Performance benchmarking** with regression detection
- **Blue-Green and Canary deployment** strategies
- **Comprehensive monitoring** and alerting

---

## GitHub Actions Workflows

### Main CI/CD Workflow

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *' # Daily security scan at 2 AM

env:
  NODE_VERSION: '20.x'
  CACHE_KEY: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}

jobs:
  # 1. Code Quality and Linting
  quality:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history for better analysis
      
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
      
      - name: Check formatting
        run: npm run format:check
      
      - name: License check
        run: npx license-checker --production --summary

  # 2. Security Scanning
  security:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Security audit
        run: npm audit --audit-level moderate
      
      - name: SAST scan with CodeQL
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript, typescript
      
      - name: Dependency check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'mcp-server-specnavigator'
          path: '.'
          format: 'HTML'
      
      - name: Secret scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
      
      - name: Container scanning (if applicable)
        if: hashFiles('Dockerfile') != ''
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'

  # 3. Testing
  test:
    runs-on: ${{ matrix.os }}
    timeout-minutes: 20
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18.x, 20.x]
      fail-fast: false
    
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
        run: npm run test:unit -- --coverage --reporters=default --reporters=jest-junit
        env:
          JEST_JUNIT_OUTPUT_DIR: ./test-results
      
      - name: Integration tests
        run: npm run test:integration
      
      - name: E2E tests
        if: matrix.os == 'ubuntu-latest'
        run: npm run test:e2e
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.os }}-${{ matrix.node }}
          path: test-results
      
      - name: Upload coverage
        if: matrix.os == 'ubuntu-latest' && matrix.node == '20.x'
        uses: codecov/codecov-action@v3
        with:
          fail_ci_if_error: true

  # 4. Performance Testing
  performance:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    if: github.event_name == 'pull_request'
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run benchmarks
        run: |
          npm run benchmark -- --output benchmark-results.json
      
      - name: Compare with base branch
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'customBiggerIsBetter'
          output-file-path: benchmark-results.json
          github-token: ${{ secrets.GITHUB_TOKEN }}
          auto-push: false
          comment-on-alert: true
          fail-on-alert: true
          alert-threshold: '110%'
          alert-comment-cc-users: '@maintainers'
      
      - name: Memory profiling
        run: |
          npm run profile:memory
          
      - name: CPU profiling
        run: |
          npm run profile:cpu

  # 5. Build and Publish
  build:
    needs: [quality, security, test]
    runs-on: ubuntu-latest
    timeout-minutes: 15
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
          registry-url: 'https://registry.npmjs.org'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build
        run: npm run build
      
      - name: Generate documentation
        run: npm run docs:generate
      
      - name: Package
        run: npm pack
      
      - name: Upload build artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-artifacts
          path: |
            dist/
            *.tgz
      
      - name: Publish to npm (if release)
        if: startsWith(github.ref, 'refs/tags/v')
        run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

  # 6. Deploy to Staging
  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    if: github.ref == 'refs/heads/develop'
    environment:
      name: staging
      url: ${{ steps.deploy.outputs.url }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: build-artifacts
      
      - name: Deploy to staging
        id: deploy
        run: |
          # Your deployment script here
          echo "::set-output name=url::https://staging.example.com"
      
      - name: Run smoke tests
        run: |
          npm run test:smoke -- --url ${{ steps.deploy.outputs.url }}
      
      - name: Notify team
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Staging deployment completed'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}

  # 7. Deploy to Production
  deploy-production:
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 15
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: ${{ steps.deploy.outputs.url }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: build-artifacts
      
      - name: Deploy using Blue-Green strategy
        id: deploy
        run: |
          # Implementation below in deployment strategies section
          ./scripts/deploy-blue-green.sh production
      
      - name: Health check
        run: |
          ./scripts/health-check.sh ${{ steps.deploy.outputs.url }}
      
      - name: Run smoke tests
        run: |
          npm run test:smoke -- --url ${{ steps.deploy.outputs.url }}
      
      - name: Performance validation
        run: |
          npm run test:performance -- --url ${{ steps.deploy.outputs.url }}
```

### Security Workflow

```yaml
# .github/workflows/security.yml
name: Security Scanning

on:
  schedule:
    - cron: '0 2 * * *' # Daily at 2 AM
  workflow_dispatch: # Manual trigger

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'mcp-server-specnavigator'
          path: '.'
          format: 'ALL'
          args: >
            --enableRetired
            --enableExperimental
      
      - name: License compliance check
        run: |
          npx license-checker --production --onlyAllow "MIT;Apache-2.0;BSD-3-Clause;BSD-2-Clause;ISC"
      
      - name: Create security report
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            dependency-check-report.*
            snyk-report.json
```

### Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20.x'
          registry-url: 'https://registry.npmjs.org'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build
        run: npm run build
      
      - name: Generate changelog
        run: |
          npx conventional-changelog-cli -p angular -i CHANGELOG.md -s
      
      - name: Create GitHub Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          body_path: CHANGELOG.md
          draft: false
          prerelease: false
      
      - name: Publish to NPM
        run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

---

## Deployment Strategies

### Blue-Green Deployment

```typescript
// deployment/strategies/blue-green.ts
interface Environment {
  name: 'blue' | 'green';
  url: string;
  healthEndpoint: string;
  version?: string;
}

interface BlueGreenConfig {
  environments: {
    blue: Environment;
    green: Environment;
  };
  loadBalancer: {
    url: string;
    switchEndpoint: string;
  };
  healthCheck: {
    retries: number;
    interval: number;
    timeout: number;
  };
  rollback: {
    automatic: boolean;
    monitoringDuration: number;
  };
}

class BlueGreenDeployment {
  constructor(private config: BlueGreenConfig) {}

  async deploy(version: string): Promise<void> {
    // 1. Identify inactive environment
    const activeEnv = await this.getActiveEnvironment();
    const inactiveEnv = activeEnv.name === 'blue' ? 'green' : 'blue';
    
    console.log(`Deploying version ${version} to ${inactiveEnv} environment`);
    
    // 2. Deploy to inactive environment
    await this.deployToEnvironment(inactiveEnv, version);
    
    // 3. Run health checks
    const healthy = await this.runHealthChecks(inactiveEnv);
    if (!healthy) {
      throw new Error(`Health checks failed on ${inactiveEnv} environment`);
    }
    
    // 4. Warm up the new environment
    await this.warmupEnvironment(inactiveEnv);
    
    // 5. Run smoke tests
    await this.runSmokeTests(inactiveEnv);
    
    // 6. Switch traffic
    await this.switchTraffic(inactiveEnv);
    
    // 7. Monitor for issues
    if (this.config.rollback.automatic) {
      this.startMonitoring(inactiveEnv);
    }
    
    console.log(`Successfully deployed version ${version} to ${inactiveEnv}`);
  }

  private async runHealthChecks(env: string): Promise<boolean> {
    const environment = this.config.environments[env];
    const { retries, interval, timeout } = this.config.healthCheck;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await fetch(environment.healthEndpoint, { 
          signal: AbortSignal.timeout(timeout) 
        });
        
        if (response.ok) {
          const health = await response.json();
          if (health.status === 'healthy') {
            return true;
          }
        }
      } catch (error) {
        console.log(`Health check attempt ${i + 1} failed:`, error);
      }
      
      if (i < retries - 1) {
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    }
    
    return false;
  }

  private async switchTraffic(targetEnv: string): Promise<void> {
    const { url, switchEndpoint } = this.config.loadBalancer;
    
    const response = await fetch(`${url}${switchEndpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: targetEnv })
    });
    
    if (!response.ok) {
      throw new Error('Failed to switch traffic');
    }
    
    // Verify the switch
    await new Promise(resolve => setTimeout(resolve, 5000));
    const activeEnv = await this.getActiveEnvironment();
    
    if (activeEnv.name !== targetEnv) {
      throw new Error('Traffic switch verification failed');
    }
  }

  private async startMonitoring(env: string): Promise<void> {
    const startTime = Date.now();
    const duration = this.config.rollback.monitoringDuration;
    
    const monitoringInterval = setInterval(async () => {
      try {
        const metrics = await this.collectMetrics(env);
        
        if (this.detectAnomalies(metrics)) {
          console.error('Anomalies detected, initiating rollback');
          await this.rollback();
          clearInterval(monitoringInterval);
        }
        
        if (Date.now() - startTime > duration) {
          console.log('Monitoring period completed successfully');
          clearInterval(monitoringInterval);
        }
      } catch (error) {
        console.error('Monitoring error:', error);
      }
    }, 30000); // Check every 30 seconds
  }

  async rollback(): Promise<void> {
    const activeEnv = await this.getActiveEnvironment();
    const previousEnv = activeEnv.name === 'blue' ? 'green' : 'blue';
    
    console.log(`Rolling back to ${previousEnv} environment`);
    await this.switchTraffic(previousEnv);
  }
}
```

### Canary Deployment

```typescript
// deployment/strategies/canary.ts
interface CanaryStage {
  percentage: number;
  duration: number;
  validation: {
    errorRateThreshold: number;
    latencyThreshold: number;
    customMetrics?: Array<{
      name: string;
      threshold: number;
      comparison: 'gt' | 'lt' | 'eq';
    }>;
  };
}

interface CanaryConfig {
  stages: CanaryStage[];
  metrics: {
    endpoint: string;
    interval: number;
  };
  rollback: {
    automatic: boolean;
    notificationWebhook?: string;
  };
}

class CanaryDeployment {
  constructor(private config: CanaryConfig) {}

  async deploy(version: string): Promise<void> {
    console.log(`Starting canary deployment of version ${version}`);
    
    for (const [index, stage] of this.config.stages.entries()) {
      console.log(`Stage ${index + 1}: Routing ${stage.percentage}% of traffic`);
      
      // Deploy canary with specified traffic percentage
      await this.deployCanary(version, stage.percentage);
      
      // Monitor for the specified duration
      if (stage.duration > 0) {
        const success = await this.monitorStage(stage);
        
        if (!success) {
          console.error(`Canary stage ${index + 1} failed validation`);
          
          if (this.config.rollback.automatic) {
            await this.rollback();
            throw new Error(`Canary deployment failed at ${stage.percentage}%`);
          }
          
          // Wait for manual intervention
          throw new Error('Canary validation failed, manual intervention required');
        }
      }
      
      console.log(`Stage ${index + 1} completed successfully`);
    }
    
    console.log('Canary deployment completed successfully');
  }

  private async monitorStage(stage: CanaryStage): Promise<boolean> {
    const startTime = Date.now();
    const { duration, validation } = stage;
    
    while (Date.now() - startTime < duration) {
      const metrics = await this.collectMetrics();
      
      // Check error rate
      if (metrics.errorRate > validation.errorRateThreshold) {
        console.error(`Error rate ${metrics.errorRate}% exceeds threshold ${validation.errorRateThreshold}%`);
        return false;
      }
      
      // Check latency
      if (metrics.p99Latency > validation.latencyThreshold) {
        console.error(`P99 latency ${metrics.p99Latency}ms exceeds threshold ${validation.latencyThreshold}ms`);
        return false;
      }
      
      // Check custom metrics
      if (validation.customMetrics) {
        for (const customMetric of validation.customMetrics) {
          const value = metrics[customMetric.name];
          const threshold = customMetric.threshold;
          
          let failed = false;
          switch (customMetric.comparison) {
            case 'gt':
              failed = value > threshold;
              break;
            case 'lt':
              failed = value < threshold;
              break;
            case 'eq':
              failed = value !== threshold;
              break;
          }
          
          if (failed) {
            console.error(`Custom metric ${customMetric.name} = ${value} failed validation`);
            return false;
          }
        }
      }
      
      // Wait before next check
      await new Promise(resolve => setTimeout(resolve, this.config.metrics.interval));
    }
    
    return true;
  }

  private async collectMetrics(): Promise<any> {
    const response = await fetch(this.config.metrics.endpoint);
    if (!response.ok) {
      throw new Error('Failed to collect metrics');
    }
    return response.json();
  }

  private async deployCanary(version: string, percentage: number): Promise<void> {
    // Implementation depends on your infrastructure
    // This could involve updating load balancer rules, K8s deployments, etc.
    console.log(`Deploying canary version ${version} with ${percentage}% traffic`);
  }

  private async rollback(): Promise<void> {
    console.log('Initiating canary rollback');
    await this.deployCanary('stable', 100);
    
    if (this.config.rollback.notificationWebhook) {
      await this.notifyRollback();
    }
  }

  private async notifyRollback(): Promise<void> {
    await fetch(this.config.rollback.notificationWebhook!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event: 'canary_rollback',
        timestamp: new Date().toISOString(),
        message: 'Canary deployment was automatically rolled back due to validation failures'
      })
    });
  }
}
```

### Deployment Scripts

```bash
#!/bin/bash
# scripts/deploy-blue-green.sh

set -euo pipefail

ENVIRONMENT=$1
VERSION=${2:-$(git describe --tags --always)}

echo "Deploying version $VERSION to $ENVIRONMENT using Blue-Green strategy"

# Load environment configuration
source "./config/${ENVIRONMENT}.env"

# Run pre-deployment checks
./scripts/pre-deploy-checks.sh

# Execute blue-green deployment
node ./deployment/cli.js blue-green \
  --version "$VERSION" \
  --environment "$ENVIRONMENT" \
  --config "./deployment/config/${ENVIRONMENT}.json"

# Run post-deployment validation
./scripts/post-deploy-validation.sh "$ENVIRONMENT"

echo "Deployment completed successfully"
```

---

## Pipeline Configuration

### Complete Pipeline Jobs Configuration

```yaml
# .github/workflows/complete-pipeline.yml
name: Complete CI/CD Pipeline

on:
  push:
    branches: [main, develop, 'release/*']
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deployment environment'
        required: true
        default: 'staging'
        type: choice
        options:
          - staging
          - production
      strategy:
        description: 'Deployment strategy'
        required: true
        default: 'blue-green'
        type: choice
        options:
          - blue-green
          - canary
          - rolling

jobs:
  # Setup job to prepare the pipeline
  setup:
    runs-on: ubuntu-latest
    outputs:
      should-deploy: ${{ steps.check.outputs.should-deploy }}
      version: ${{ steps.version.outputs.version }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Check deployment conditions
        id: check
        run: |
          if [[ "${{ github.event_name }}" == "workflow_dispatch" ]] || 
             [[ "${{ github.ref }}" == "refs/heads/main" ]] || 
             [[ "${{ github.ref }}" == "refs/heads/develop" ]]; then
            echo "should-deploy=true" >> $GITHUB_OUTPUT
          else
            echo "should-deploy=false" >> $GITHUB_OUTPUT
          fi
      
      - name: Determine version
        id: version
        run: |
          if [[ "${{ github.ref }}" == refs/tags/* ]]; then
            VERSION=${GITHUB_REF#refs/tags/}
          else
            VERSION=$(git describe --tags --always --dirty)
          fi
          echo "version=$VERSION" >> $GITHUB_OUTPUT

  # Parallel quality checks
  quality-checks:
    needs: setup
    runs-on: ubuntu-latest
    strategy:
      matrix:
        check: [lint, format, complexity, dependencies]
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup environment
        uses: ./.github/actions/setup-env
      
      - name: Run ${{ matrix.check }} check
        run: npm run check:${{ matrix.check }}

  # Security scanning with multiple tools
  security-scan:
    needs: setup
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Run security scans
        uses: ./.github/actions/security-scan
        with:
          snyk-token: ${{ secrets.SNYK_TOKEN }}
          sonarcloud-token: ${{ secrets.SONAR_TOKEN }}

  # Comprehensive testing matrix
  test-suite:
    needs: [quality-checks, security-scan]
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18.x, 20.x]
        test-type: [unit, integration, e2e]
        exclude:
          - os: windows-latest
            test-type: e2e
          - os: macos-latest
            test-type: e2e
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup test environment
        uses: ./.github/actions/setup-test-env
        with:
          os: ${{ matrix.os }}
          node-version: ${{ matrix.node }}
      
      - name: Run ${{ matrix.test-type }} tests
        run: npm run test:${{ matrix.test-type }}
        env:
          TEST_TIMEOUT: 300000

  # Performance benchmarking
  performance-test:
    needs: test-suite
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run performance benchmarks
        uses: ./.github/actions/performance-benchmark
        with:
          comparison-branch: ${{ github.base_ref }}

  # Build and package
  build-package:
    needs: test-suite
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build application
        run: |
          npm ci
          npm run build
          npm run package
      
      - name: Create release artifacts
        run: |
          tar -czf release-${{ needs.setup.outputs.version }}.tar.gz dist/
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: release-artifacts
          path: release-*.tar.gz
          retention-days: 30

  # Deployment job
  deploy:
    needs: [setup, build-package]
    if: needs.setup.outputs.should-deploy == 'true'
    runs-on: ubuntu-latest
    environment:
      name: ${{ github.event.inputs.environment || 'staging' }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: release-artifacts
      
      - name: Deploy application
        run: |
          ./scripts/deploy.sh \
            --environment "${{ github.event.inputs.environment || 'staging' }}" \
            --strategy "${{ github.event.inputs.strategy || 'blue-green' }}" \
            --version "${{ needs.setup.outputs.version }}"
      
      - name: Verify deployment
        run: |
          ./scripts/verify-deployment.sh \
            --environment "${{ github.event.inputs.environment || 'staging' }}"

  # Post-deployment validation
  post-deploy:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run smoke tests
        run: |
          npm run test:smoke -- \
            --environment "${{ github.event.inputs.environment || 'staging' }}"
      
      - name: Check deployment health
        run: |
          ./scripts/health-check.sh \
            --environment "${{ github.event.inputs.environment || 'staging' }}"
      
      - name: Notify success
        if: success()
        uses: ./.github/actions/notify
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK }}
          message: "Deployment successful"
```

### Reusable Actions

```yaml
# .github/actions/setup-env/action.yml
name: 'Setup Environment'
description: 'Sets up the development environment'

runs:
  using: 'composite'
  steps:
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20.x'
        cache: 'npm'
    
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          node_modules
          ~/.npm
        key: deps-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
        restore-keys: |
          deps-${{ runner.os }}-
    
    - name: Install dependencies
      shell: bash
      run: npm ci --prefer-offline --no-audit
```

---

## Security Scanning Integration

### Comprehensive Security Configuration

```typescript
// security/scanner.ts
interface SecurityScanConfig {
  scanners: {
    sast: boolean;
    dast: boolean;
    dependencies: boolean;
    containers: boolean;
    secrets: boolean;
    licenses: boolean;
  };
  thresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  ignorePaths: string[];
  customRules: SecurityRule[];
}

class SecurityScanner {
  constructor(private config: SecurityScanConfig) {}

  async runFullScan(): Promise<SecurityReport> {
    const results: ScanResult[] = [];

    if (this.config.scanners.sast) {
      results.push(await this.runSASTScan());
    }

    if (this.config.scanners.dependencies) {
      results.push(await this.runDependencyScan());
    }

    if (this.config.scanners.secrets) {
      results.push(await this.runSecretScan());
    }

    if (this.config.scanners.licenses) {
      results.push(await this.runLicenseScan());
    }

    const report = this.generateReport(results);
    await this.checkThresholds(report);

    return report;
  }

  private async runSASTScan(): Promise<ScanResult> {
    // Run CodeQL
    const codeqlResults = await this.runCodeQL();
    
    // Run Semgrep
    const semgrepResults = await this.runSemgrep();
    
    // Run custom security rules
    const customResults = await this.runCustomRules();

    return this.mergeScanResults([codeqlResults, semgrepResults, customResults]);
  }

  private async runDependencyScan(): Promise<ScanResult> {
    const scanners = [
      () => this.runNpmAudit(),
      () => this.runSnyk(),
      () => this.runOWASPDependencyCheck(),
      () => this.runRetireJS()
    ];

    const results = await Promise.all(scanners.map(scanner => scanner()));
    return this.mergeScanResults(results);
  }

  private async checkThresholds(report: SecurityReport): Promise<void> {
    const violations = [];

    if (report.summary.critical > this.config.thresholds.critical) {
      violations.push(`Critical vulnerabilities: ${report.summary.critical} (threshold: ${this.config.thresholds.critical})`);
    }

    if (report.summary.high > this.config.thresholds.high) {
      violations.push(`High vulnerabilities: ${report.summary.high} (threshold: ${this.config.thresholds.high})`);
    }

    if (violations.length > 0) {
      throw new SecurityThresholdError(violations);
    }
  }
}
```

### Security Workflow Integration

```yaml
# .github/workflows/security-advanced.yml
name: Advanced Security Scanning

on:
  schedule:
    - cron: '0 */6 * * *' # Every 6 hours
  pull_request:
    paths:
      - 'package*.json'
      - '**/*.ts'
      - '**/*.js'
  workflow_dispatch:

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: NPM Audit
        run: |
          npm audit --json > npm-audit-report.json || true
          
      - name: Snyk Test
        uses: snyk/actions/node@master
        with:
          args: --all-projects --json-file-output=snyk-report.json
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      
      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'mcp-server-specnavigator'
          path: '.'
          format: 'JSON'
          args: >
            --enableRetired
            --enableExperimental
            --nvdApiKey ${{ secrets.NVD_API_KEY }}
      
      - name: Process results
        run: |
          node ./scripts/process-security-results.js

  sast-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: javascript, typescript
          queries: security-and-quality
      
      - name: Autobuild
        uses: github/codeql-action/autobuild@v2
      
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/javascript
            p/typescript
            p/security-audit
            p/owasp-top-ten
      
      - name: Custom security rules
        run: |
          npx eslint . --ext .ts,.js \
            --config .eslintrc.security.js \
            --format json \
            --output-file eslint-security-report.json

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: TruffleHog OSS
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified
      
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: detect-secrets
        run: |
          pip install detect-secrets
          detect-secrets scan --baseline .secrets.baseline

  license-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: License Finder
        run: |
          npm install -g license-checker
          license-checker --json > licenses.json
          
      - name: FOSSA
        uses: fossas/fossa-action@main
        with:
          api-key: ${{ secrets.FOSSA_API_KEY }}
      
      - name: Check compliance
        run: |
          node ./scripts/check-license-compliance.js

  create-report:
    needs: [dependency-scan, sast-scan, secret-scan, license-compliance]
    runs-on: ubuntu-latest
    if: always()
    steps:
      - uses: actions/checkout@v4
      
      - name: Download all artifacts
        uses: actions/download-artifact@v3
      
      - name: Generate security report
        run: |
          node ./scripts/generate-security-report.js
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const report = require('./security-summary.json');
            const comment = `## Security Scan Results\n${report.summary}`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

## Performance Testing Setup

### Performance Test Framework

```typescript
// performance/benchmark.ts
import { performance } from 'perf_hooks';

interface BenchmarkConfig {
  name: string;
  iterations: number;
  warmup: number;
  timeout: number;
  baseline?: BenchmarkResult;
}

interface BenchmarkResult {
  name: string;
  metrics: {
    mean: number;
    median: number;
    p95: number;
    p99: number;
    min: number;
    max: number;
    stdDev: number;
  };
  memory: {
    heapUsed: number;
    external: number;
    rss: number;
  };
}

class PerformanceBenchmark {
  async run(config: BenchmarkConfig, fn: () => Promise<void>): Promise<BenchmarkResult> {
    // Warmup phase
    for (let i = 0; i < config.warmup; i++) {
      await fn();
    }

    // Collect samples
    const samples: number[] = [];
    const memorySnapshots: any[] = [];

    for (let i = 0; i < config.iterations; i++) {
      const startMemory = process.memoryUsage();
      const start = performance.now();
      
      await fn();
      
      const duration = performance.now() - start;
      const endMemory = process.memoryUsage();
      
      samples.push(duration);
      memorySnapshots.push({
        heapUsed: endMemory.heapUsed - startMemory.heapUsed,
        external: endMemory.external - startMemory.external,
        rss: endMemory.rss - startMemory.rss
      });
    }

    const result = this.calculateMetrics(config.name, samples, memorySnapshots);
    
    if (config.baseline) {
      this.compareWithBaseline(result, config.baseline);
    }

    return result;
  }

  private calculateMetrics(
    name: string, 
    samples: number[], 
    memorySnapshots: any[]
  ): BenchmarkResult {
    samples.sort((a, b) => a - b);
    
    return {
      name,
      metrics: {
        mean: this.mean(samples),
        median: this.percentile(samples, 50),
        p95: this.percentile(samples, 95),
        p99: this.percentile(samples, 99),
        min: samples[0],
        max: samples[samples.length - 1],
        stdDev: this.standardDeviation(samples)
      },
      memory: {
        heapUsed: this.mean(memorySnapshots.map(m => m.heapUsed)),
        external: this.mean(memorySnapshots.map(m => m.external)),
        rss: this.mean(memorySnapshots.map(m => m.rss))
      }
    };
  }

  private compareWithBaseline(current: BenchmarkResult, baseline: BenchmarkResult): void {
    const regression = current.metrics.p95 > baseline.metrics.p95 * 1.1;
    
    if (regression) {
      console.warn(`Performance regression detected in ${current.name}:`);
      console.warn(`  P95: ${current.metrics.p95.toFixed(2)}ms (baseline: ${baseline.metrics.p95.toFixed(2)}ms)`);
      console.warn(`  Memory: ${(current.memory.heapUsed / 1024 / 1024).toFixed(2)}MB (baseline: ${(baseline.memory.heapUsed / 1024 / 1024).toFixed(2)}MB)`);
    }
  }

  private mean(values: number[]): number {
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  private percentile(values: number[], p: number): number {
    const index = Math.ceil((p / 100) * values.length) - 1;
    return values[index];
  }

  private standardDeviation(values: number[]): number {
    const avg = this.mean(values);
    const squareDiffs = values.map(value => Math.pow(value - avg, 2));
    return Math.sqrt(this.mean(squareDiffs));
  }
}
```

### Performance Test Suite

```typescript
// performance/tests/api-performance.test.ts
import { PerformanceBenchmark } from '../benchmark';

describe('API Performance Tests', () => {
  const benchmark = new PerformanceBenchmark();

  test('Specification parsing performance', async () => {
    const result = await benchmark.run({
      name: 'spec-parsing',
      iterations: 100,
      warmup: 10,
      timeout: 5000
    }, async () => {
      await parseSpecification(largeSpecContent);
    });

    expect(result.metrics.p95).toBeLessThan(100); // 100ms
    expect(result.memory.heapUsed).toBeLessThan(50 * 1024 * 1024); // 50MB
  });

  test('Search performance', async () => {
    const result = await benchmark.run({
      name: 'search-operation',
      iterations: 1000,
      warmup: 50,
      timeout: 1000
    }, async () => {
      await searchSpecifications('test query');
    });

    expect(result.metrics.p99).toBeLessThan(50); // 50ms
  });

  test('Concurrent request handling', async () => {
    const result = await benchmark.run({
      name: 'concurrent-requests',
      iterations: 10,
      warmup: 2,
      timeout: 30000
    }, async () => {
      const promises = Array(100).fill(null).map(() => 
        fetch('/api/specifications')
      );
      await Promise.all(promises);
    });

    expect(result.metrics.mean).toBeLessThan(5000); // 5s for 100 requests
  });
});
```

### Load Testing Configuration

```yaml
# k6/load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Ramp up to 10 users
    { duration: '5m', target: 10 },   // Stay at 10 users
    { duration: '2m', target: 50 },   // Ramp up to 50 users
    { duration: '5m', target: 50 },   // Stay at 50 users
    { duration: '2m', target: 100 },  // Ramp up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '5m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% of requests under 500ms
    errors: ['rate<0.1'], // Error rate under 10%
  },
};

export default function () {
  // Test specification retrieval
  const specResponse = http.get(`${__ENV.API_URL}/api/specifications`);
  check(specResponse, {
    'spec list status is 200': (r) => r.status === 200,
    'spec list response time < 500ms': (r) => r.timings.duration < 500,
  });
  errorRate.add(specResponse.status !== 200);

  sleep(1);

  // Test search functionality
  const searchResponse = http.get(`${__ENV.API_URL}/api/search?q=test`);
  check(searchResponse, {
    'search status is 200': (r) => r.status === 200,
    'search response time < 300ms': (r) => r.timings.duration < 300,
  });
  errorRate.add(searchResponse.status !== 200);

  sleep(1);
}
```

---

## Best Practices

### 1. Pipeline Design Principles

- **Fail Fast**: Run quick checks (linting, type checking) before expensive operations
- **Parallel Execution**: Run independent jobs in parallel to reduce total pipeline time
- **Caching**: Cache dependencies, build artifacts, and test results
- **Incremental Builds**: Only rebuild what has changed
- **Resource Optimization**: Use appropriate runner sizes for different jobs

### 2. Security Best Practices

- **Least Privilege**: Give minimal permissions to CI/CD service accounts
- **Secret Management**: Use GitHub Secrets or external secret managers
- **Dependency Scanning**: Scan for vulnerabilities in every build
- **Code Signing**: Sign releases and verify signatures
- **Audit Logging**: Log all deployment activities

### 3. Testing Strategy

- **Test Pyramid**: More unit tests, fewer integration tests, minimal E2E tests
- **Test Isolation**: Tests should not depend on external services
- **Test Data Management**: Use fixtures and factories for consistent test data
- **Flaky Test Management**: Identify and fix flaky tests immediately
- **Performance Baselines**: Establish and monitor performance baselines

### 4. Deployment Best Practices

- **Environment Parity**: Keep all environments as similar as possible
- **Database Migrations**: Automate and version control database changes
- **Feature Flags**: Use feature flags for gradual rollouts
- **Rollback Plan**: Always have a tested rollback procedure
- **Health Checks**: Implement comprehensive health check endpoints

### 5. Monitoring and Observability

```typescript
// monitoring/pipeline-metrics.ts
class PipelineMetrics {
  private metrics = {
    buildDuration: new Histogram({
      name: 'ci_build_duration_seconds',
      help: 'Build duration in seconds',
      labelNames: ['job', 'status']
    }),
    deploymentSuccess: new Counter({
      name: 'cd_deployment_total',
      help: 'Total deployments',
      labelNames: ['environment', 'strategy', 'status']
    }),
    testResults: new Gauge({
      name: 'ci_test_results',
      help: 'Test results',
      labelNames: ['type', 'status']
    }),
    securityVulnerabilities: new Gauge({
      name: 'security_vulnerabilities_total',
      help: 'Total security vulnerabilities',
      labelNames: ['severity']
    })
  };

  recordBuildDuration(job: string, duration: number, status: string): void {
    this.metrics.buildDuration.labels(job, status).observe(duration);
  }

  recordDeployment(environment: string, strategy: string, success: boolean): void {
    this.metrics.deploymentSuccess
      .labels(environment, strategy, success ? 'success' : 'failure')
      .inc();
  }

  recordTestResults(type: string, passed: number, failed: number): void {
    this.metrics.testResults.labels(type, 'passed').set(passed);
    this.metrics.testResults.labels(type, 'failed').set(failed);
  }

  recordSecurityScan(critical: number, high: number, medium: number, low: number): void {
    this.metrics.securityVulnerabilities.labels('critical').set(critical);
    this.metrics.securityVulnerabilities.labels('high').set(high);
    this.metrics.securityVulnerabilities.labels('medium').set(medium);
    this.metrics.securityVulnerabilities.labels('low').set(low);
  }
}
```

---

## Monitoring and Alerts

### Pipeline Monitoring Dashboard

```typescript
// monitoring/dashboard-config.ts
export const pipelineDashboard = {
  title: 'CI/CD Pipeline Dashboard',
  panels: [
    {
      title: 'Build Success Rate',
      query: 'rate(ci_build_total{status="success"}[5m]) / rate(ci_build_total[5m])',
      visualization: 'gauge',
      thresholds: [
        { value: 0.95, color: 'green' },
        { value: 0.80, color: 'yellow' },
        { value: 0, color: 'red' }
      ]
    },
    {
      title: 'Average Build Duration',
      query: 'avg(ci_build_duration_seconds) by (job)',
      visualization: 'graph'
    },
    {
      title: 'Deployment Frequency',
      query: 'sum(increase(cd_deployment_total[1d])) by (environment)',
      visualization: 'bar'
    },
    {
      title: 'Security Vulnerabilities',
      query: 'security_vulnerabilities_total',
      visualization: 'table',
      groupBy: ['severity']
    },
    {
      title: 'Test Coverage',
      query: 'test_coverage_percentage',
      visualization: 'gauge',
      unit: 'percent'
    }
  ]
};
```

### Alert Configuration

```yaml
# monitoring/alerts.yml
groups:
  - name: pipeline_alerts
    interval: 30s
    rules:
      - alert: HighBuildFailureRate
        expr: rate(ci_build_total{status="failure"}[15m]) > 0.25
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High build failure rate detected"
          description: "Build failure rate is {{ $value }} (threshold: 0.25)"

      - alert: SecurityCriticalVulnerability
        expr: security_vulnerabilities_total{severity="critical"} > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Critical security vulnerability detected"
          description: "{{ $value }} critical vulnerabilities found"

      - alert: DeploymentFailed
        expr: increase(cd_deployment_total{status="failure"}[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Deployment failure detected"
          description: "Deployment to {{ $labels.environment }} failed"

      - alert: LongRunningPipeline
        expr: ci_build_duration_seconds > 1800
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Pipeline taking too long"
          description: "Pipeline {{ $labels.job }} running for {{ $value }} seconds"

      - alert: TestCoverageDropped
        expr: delta(test_coverage_percentage[1h]) < -5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Test coverage dropped significantly"
          description: "Coverage dropped by {{ $value }}%"
```

---

## Troubleshooting

### Common Pipeline Issues

#### 1. Flaky Tests

**Problem**: Tests pass sometimes and fail other times without code changes.

**Solution**:
```typescript
// test-utils/retry-helper.ts
export async function retryTest(
  fn: () => Promise<void>,
  options = { retries: 3, delay: 1000 }
): Promise<void> {
  let lastError: Error;
  
  for (let i = 0; i < options.retries; i++) {
    try {
      await fn();
      return;
    } catch (error) {
      lastError = error;
      if (i < options.retries - 1) {
        await new Promise(resolve => setTimeout(resolve, options.delay));
      }
    }
  }
  
  throw lastError;
}

// Usage in tests
test('potentially flaky test', async () => {
  await retryTest(async () => {
    const result = await fetchExternalResource();
    expect(result).toBeDefined();
  });
});
```

#### 2. Slow Pipeline Performance

**Problem**: Pipeline takes too long to complete.

**Solution**:
- Enable dependency caching
- Run jobs in parallel
- Use matrix builds wisely
- Optimize test suite performance
- Use incremental builds

#### 3. Security Scan False Positives

**Problem**: Security scans report vulnerabilities that are false positives.

**Solution**:
```json
// .snyk
{
  "ignore": {
    "SNYK-JS-LODASH-567746": {
      "paths": ["*"],
      "reason": "This vulnerability doesn't affect our usage",
      "expires": "2024-12-31"
    }
  }
}
```

#### 4. Deployment Failures

**Problem**: Deployments fail intermittently.

**Solution**:
- Implement proper health checks
- Add retry logic to deployment scripts
- Use deployment windows
- Implement proper rollback procedures

### Debugging Pipeline Failures

```yaml
# Add debug steps to your workflow
- name: Debug Environment
  if: failure()
  run: |
    echo "Node version: $(node --version)"
    echo "NPM version: $(npm --version)"
    echo "Current directory: $(pwd)"
    echo "Directory contents:"
    ls -la
    echo "Environment variables:"
    env | sort
    echo "Network connectivity:"
    curl -I https://registry.npmjs.org
```

### Pipeline Optimization Tips

1. **Use Job Dependencies Wisely**
   ```yaml
   jobs:
     quick-checks:
       runs-on: ubuntu-latest
       # Run first, fail fast
     
     expensive-tests:
       needs: quick-checks
       # Only run if quick checks pass
   ```

2. **Cache Everything Possible**
   ```yaml
   - uses: actions/cache@v3
     with:
       path: |
         ~/.npm
         ~/.cache
         node_modules
       key: ${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
   ```

3. **Use Artifacts Efficiently**
   ```yaml
   - uses: actions/upload-artifact@v3
     with:
       name: build-output
       path: dist/
       retention-days: 1  # Don't keep artifacts forever
   ```

---

## Conclusion

This comprehensive CI/CD setup guide provides a robust foundation for automating your software delivery pipeline. The key to success is:

1. **Start Simple**: Implement basic CI/CD first, then add complexity
2. **Monitor Everything**: You can't improve what you don't measure
3. **Automate Security**: Make security checks part of every build
4. **Test Thoroughly**: Comprehensive testing prevents production issues
5. **Deploy Safely**: Use proven deployment strategies
6. **Document Processes**: Keep runbooks and documentation up to date

Remember to regularly review and update your CI/CD pipeline as your project evolves. Happy deploying!