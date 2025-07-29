# Security Guide

*Comprehensive security practices and implementation patterns for robust application development*

## Table of Contents

1. [Input Validation Framework](#input-validation-framework)
2. [Authentication & Authorization](#authentication--authorization)
3. [Security Middleware](#security-middleware)
4. [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
5. [Security Headers & Best Practices](#security-headers--best-practices)
6. [Common Vulnerabilities & Prevention](#common-vulnerabilities--prevention)
7. [Additional Security Patterns](#additional-security-patterns)
8. [Security Monitoring & Auditing](#security-monitoring--auditing)

---

## Input Validation Framework

### Schema Validation with Zod

```typescript
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
  
  private sanitize(input: any): any {
    // Implement sanitization logic
    return input;
  }
}
```

### Request Validation Middleware

```typescript
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
```

### Common Validation Schemas

```typescript
// User input validation
const userSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  username: z.string()
    .min(3)
    .max(20)
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  age: z.number().min(0).max(150).optional(),
  roles: z.array(z.enum(['user', 'admin', 'moderator'])).default(['user'])
});

// API request validation
const apiRequestSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
  endpoint: z.string().url(),
  headers: z.record(z.string()),
  body: z.any().optional(),
  query: z.record(z.string()).optional(),
  timeout: z.number().min(0).max(300000).default(30000)
});

// File upload validation
const fileUploadSchema = z.object({
  filename: z.string().regex(/^[a-zA-Z0-9_\-\.]+$/),
  mimetype: z.enum(['image/jpeg', 'image/png', 'image/gif', 'application/pdf']),
  size: z.number().max(10 * 1024 * 1024), // 10MB max
  content: z.instanceof(Buffer)
});
```

### Input Sanitization

```typescript
class InputSanitizer {
  static sanitizeString(input: string): string {
    return input
      .trim()
      .replace(/[<>]/g, '') // Remove basic HTML tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+\s*=/gi, ''); // Remove event handlers
  }
  
  static sanitizeSQL(input: string): string {
    // Use parameterized queries instead, but for legacy code:
    return input.replace(/['";\\]/g, '\\$&');
  }
  
  static sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .replace(/\.{2,}/g, '_')
      .substring(0, 255);
  }
  
  static sanitizeJSON(input: any): any {
    if (typeof input === 'string') {
      return this.sanitizeString(input);
    }
    
    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeJSON(item));
    }
    
    if (typeof input === 'object' && input !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(input)) {
        sanitized[this.sanitizeString(key)] = this.sanitizeJSON(value);
      }
      return sanitized;
    }
    
    return input;
  }
}
```

---

## Authentication & Authorization

### Authentication Strategies

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
```

### JWT Authentication Implementation

```typescript
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

class JWTAuthStrategy implements AuthStrategy {
  private readonly secret = process.env.JWT_SECRET!;
  private readonly expiresIn = '24h';
  
  async authenticate(credentials: { email: string; password: string }): Promise<User> {
    const user = await this.userRepository.findByEmail(credentials.email);
    
    if (!user) {
      throw new AuthenticationError('Invalid credentials');
    }
    
    const isValidPassword = await bcrypt.compare(credentials.password, user.passwordHash);
    
    if (!isValidPassword) {
      throw new AuthenticationError('Invalid credentials');
    }
    
    return user;
  }
  
  async verify(token: string): Promise<User> {
    try {
      const payload = jwt.verify(token, this.secret) as JWTPayload;
      
      // Check if token is blacklisted
      if (await this.tokenBlacklist.isBlacklisted(token)) {
        throw new AuthenticationError('Token has been revoked');
      }
      
      const user = await this.userRepository.findById(payload.userId);
      
      if (!user) {
        throw new AuthenticationError('User not found');
      }
      
      return user;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError('Invalid token');
      }
      throw error;
    }
  }
  
  generateToken(user: User): string {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions
    };
    
    return jwt.sign(payload, this.secret, {
      expiresIn: this.expiresIn,
      issuer: 'your-app-name',
      audience: 'your-app-users',
      subject: user.id
    });
  }
}
```

### OAuth2 Strategy

```typescript
class OAuthStrategy implements AuthStrategy {
  private providers: Map<string, OAuthProvider> = new Map([
    ['google', new GoogleOAuthProvider()],
    ['github', new GitHubOAuthProvider()],
    ['microsoft', new MicrosoftOAuthProvider()]
  ]);
  
  async authenticate(credentials: { provider: string; code: string }): Promise<User> {
    const provider = this.providers.get(credentials.provider);
    
    if (!provider) {
      throw new Error(`Unknown OAuth provider: ${credentials.provider}`);
    }
    
    // Exchange code for token
    const accessToken = await provider.exchangeCodeForToken(credentials.code);
    
    // Get user info from provider
    const profile = await provider.getUserProfile(accessToken);
    
    // Find or create user
    let user = await this.userRepository.findByOAuthId(
      credentials.provider,
      profile.id
    );
    
    if (!user) {
      user = await this.userRepository.create({
        email: profile.email,
        name: profile.name,
        oauthProviders: [{
          provider: credentials.provider,
          providerId: profile.id
        }]
      });
    }
    
    return user;
  }
}
```

---

## Security Middleware

### Comprehensive Security Middleware

```typescript
class SecurityMiddleware {
  apply(): Middleware {
    return (req, res, next) => {
      // Security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.setHeader('Content-Security-Policy', this.getCSPHeader());
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
      
      // Remove sensitive headers
      res.removeHeader('X-Powered-By');
      res.removeHeader('Server');
      
      // Input sanitization
      req.body = this.sanitizeInput(req.body);
      req.query = this.sanitizeInput(req.query);
      req.params = this.sanitizeInput(req.params);
      
      next();
    };
  }
  
  private getCSPHeader(): string {
    return [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self' https://api.example.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ');
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
  
  private sanitizeString(str: string): string {
    return str
      .replace(/[<>]/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '');
  }
}
```

### Rate Limiting Middleware

```typescript
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';

class RateLimitingMiddleware {
  createLimiter(options: RateLimitOptions): Middleware {
    return rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
      max: options.max || 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'rate-limit:'
      }),
      skip: (req) => {
        // Skip rate limiting for whitelisted IPs
        return this.isWhitelisted(req.ip);
      },
      handler: (req, res) => {
        this.logger.warn('Rate limit exceeded', {
          ip: req.ip,
          path: req.path,
          method: req.method
        });
        
        res.status(429).json({
          error: 'Too many requests',
          retryAfter: res.getHeader('Retry-After')
        });
      }
    });
  }
  
  // Different limiters for different endpoints
  getApiLimiter() {
    return this.createLimiter({
      windowMs: 15 * 60 * 1000,
      max: 100
    });
  }
  
  getAuthLimiter() {
    return this.createLimiter({
      windowMs: 15 * 60 * 1000,
      max: 5 // Strict limit for auth endpoints
    });
  }
  
  getUploadLimiter() {
    return this.createLimiter({
      windowMs: 60 * 60 * 1000,
      max: 10 // 10 uploads per hour
    });
  }
}
```

### CORS Middleware

```typescript
import cors from 'cors';

class CORSMiddleware {
  configure(): Middleware {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    
    return cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or Postman)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
      maxAge: 86400 // 24 hours
    });
  }
}
```

---

## Role-Based Access Control (RBAC)

### RBAC Implementation

```typescript
interface Permission {
  resource: string;
  action: string;
  conditions?: Record<string, any>;
}

interface Role {
  id: string;
  name: string;
  permissions: Permission[];
  inherits?: string[]; // Role inheritance
}

class AccessControl {
  private roles: Map<string, Role> = new Map();
  private userRoles: Map<string, string[]> = new Map();
  
  // Define roles and permissions
  constructor() {
    this.defineRoles();
  }
  
  private defineRoles() {
    // Basic user role
    this.addRole({
      id: 'user',
      name: 'User',
      permissions: [
        { resource: 'profile', action: 'read' },
        { resource: 'profile', action: 'update', conditions: { own: true } }
      ]
    });
    
    // Moderator role (inherits from user)
    this.addRole({
      id: 'moderator',
      name: 'Moderator',
      inherits: ['user'],
      permissions: [
        { resource: 'content', action: 'read' },
        { resource: 'content', action: 'update' },
        { resource: 'content', action: 'delete', conditions: { flagged: true } }
      ]
    });
    
    // Admin role (inherits from moderator)
    this.addRole({
      id: 'admin',
      name: 'Administrator',
      inherits: ['moderator'],
      permissions: [
        { resource: '*', action: '*' } // Full access
      ]
    });
  }
  
  can(user: User, action: string, resource: string, context?: any): boolean {
    const userPermissions = this.getUserPermissions(user);
    
    for (const permission of userPermissions) {
      if (this.matchesPermission(permission, action, resource, context)) {
        return true;
      }
    }
    
    return false;
  }
  
  private matchesPermission(
    permission: Permission,
    action: string,
    resource: string,
    context?: any
  ): boolean {
    // Check resource match
    if (permission.resource !== '*' && permission.resource !== resource) {
      return false;
    }
    
    // Check action match
    if (permission.action !== '*' && permission.action !== action) {
      return false;
    }
    
    // Check conditions
    if (permission.conditions) {
      for (const [key, value] of Object.entries(permission.conditions)) {
        if (context?.[key] !== value) {
          return false;
        }
      }
    }
    
    return true;
  }
  
  private getUserPermissions(user: User): Permission[] {
    const permissions: Permission[] = [];
    const processedRoles = new Set<string>();
    
    const processRole = (roleId: string) => {
      if (processedRoles.has(roleId)) return;
      processedRoles.add(roleId);
      
      const role = this.roles.get(roleId);
      if (!role) return;
      
      // Add role permissions
      permissions.push(...role.permissions);
      
      // Process inherited roles
      if (role.inherits) {
        role.inherits.forEach(processRole);
      }
    };
    
    // Process all user roles
    user.roles.forEach(processRole);
    
    return permissions;
  }
  
  // Middleware for route protection
  enforce(action: string, resource: string): Middleware {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      
      const context = {
        own: req.params.userId === req.user.id,
        ...req.body
      };
      
      if (!this.can(req.user, action, resource, context)) {
        this.auditLog.recordAccessDenied(req.user, action, resource);
        return res.status(403).json({ error: 'Forbidden' });
      }
      
      next();
    };
  }
}
```

### Dynamic Permission Checking

```typescript
class DynamicAccessControl {
  async checkAccess(
    user: User,
    resource: any,
    action: string
  ): Promise<boolean> {
    // Get resource-specific rules
    const rules = await this.getRulesForResource(resource);
    
    for (const rule of rules) {
      if (await this.evaluateRule(rule, user, resource, action)) {
        return true;
      }
    }
    
    return false;
  }
  
  private async evaluateRule(
    rule: AccessRule,
    user: User,
    resource: any,
    action: string
  ): Promise<boolean> {
    // Check action
    if (!rule.actions.includes(action) && !rule.actions.includes('*')) {
      return false;
    }
    
    // Evaluate conditions
    for (const condition of rule.conditions) {
      const result = await this.evaluateCondition(condition, user, resource);
      if (!result) return false;
    }
    
    return true;
  }
  
  private async evaluateCondition(
    condition: Condition,
    user: User,
    resource: any
  ): Promise<boolean> {
    switch (condition.type) {
      case 'ownership':
        return resource.ownerId === user.id;
        
      case 'department':
        return user.department === condition.value;
        
      case 'time':
        return this.evaluateTimeCondition(condition);
        
      case 'custom':
        return await condition.evaluate(user, resource);
        
      default:
        return false;
    }
  }
}
```

---

## Security Headers & Best Practices

### Comprehensive Security Headers

```typescript
class SecurityHeaders {
  static apply(app: Express): void {
    // Helmet for basic security headers
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          workerSrc: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          manifestSrc: ["'self'"]
        }
      },
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: true,
      crossOriginResourcePolicy: { policy: "cross-origin" },
      dnsPrefetchControl: true,
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      ieNoOpen: true,
      noSniff: true,
      originAgentCluster: true,
      permittedCrossDomainPolicies: false,
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
      xssFilter: true
    }));
    
    // Additional custom headers
    app.use((req, res, next) => {
      // Feature Policy / Permissions Policy
      res.setHeader('Permissions-Policy', 
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
      );
      
      // Expect-CT
      res.setHeader('Expect-CT', 'max-age=86400, enforce');
      
      // Clear Site Data on logout
      if (req.path === '/logout') {
        res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
      }
      
      next();
    });
  }
}
```

### Security Best Practices Implementation

```typescript
class SecurityBestPractices {
  // Secure session configuration
  static configureSession(app: Express): void {
    app.use(session({
      secret: process.env.SESSION_SECRET!,
      name: 'sessionId', // Don't use default name
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only
        httpOnly: true, // No JS access
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        sameSite: 'strict' // CSRF protection
      },
      store: new RedisStore({
        client: redisClient,
        prefix: 'sess:',
        ttl: 86400 // 24 hours
      })
    }));
  }
  
  // Password hashing
  static async hashPassword(password: string): Promise<string> {
    const saltRounds = 12; // Increase for more security
    return bcrypt.hash(password, saltRounds);
  }
  
  // Secure random token generation
  static generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }
  
  // Time-constant string comparison (prevent timing attacks)
  static secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
  
  // Encrypt sensitive data
  static encrypt(text: string, key: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }
  
  static decrypt(encryptedText: string, key: string): string {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

---

## Common Vulnerabilities & Prevention

### 1. SQL Injection Prevention

```typescript
class SQLInjectionPrevention {
  // Use parameterized queries
  async getUserById(userId: string): Promise<User> {
    // ❌ BAD: String concatenation
    // const query = `SELECT * FROM users WHERE id = '${userId}'`;
    
    // ✅ GOOD: Parameterized query
    const query = 'SELECT * FROM users WHERE id = ?';
    const [rows] = await this.db.execute(query, [userId]);
    return rows[0];
  }
  
  // Use query builders
  async searchUsers(searchTerm: string): Promise<User[]> {
    return this.db('users')
      .where('name', 'like', `%${searchTerm}%`)
      .orWhere('email', 'like', `%${searchTerm}%`)
      .limit(50);
  }
  
  // Validate and sanitize input
  validateUserId(userId: string): boolean {
    // UUID format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(userId);
  }
}
```

### 2. Cross-Site Scripting (XSS) Prevention

```typescript
class XSSPrevention {
  // Output encoding
  static encodeHTML(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  
  // React/JSX automatically escapes, but for dynamic HTML:
  static sanitizeHTML(html: string): string {
    const clean = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href', 'target']
    });
    return clean;
  }
  
  // URL parameter encoding
  static encodeURL(str: string): string {
    return encodeURIComponent(str);
  }
  
  // JSON encoding for inline scripts
  static encodeJSON(obj: any): string {
    return JSON.stringify(obj)
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e')
      .replace(/&/g, '\\u0026')
      .replace(/'/g, '\\u0027');
  }
}
```

### 3. Cross-Site Request Forgery (CSRF) Prevention

```typescript
import csrf from 'csurf';

class CSRFProtection {
  static configure(app: Express): void {
    const csrfProtection = csrf({
      cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      }
    });
    
    // Apply to state-changing routes
    app.use('/api', csrfProtection);
    
    // Provide token to client
    app.get('/api/csrf-token', (req, res) => {
      res.json({ csrfToken: req.csrfToken() });
    });
  }
  
  // Double Submit Cookie Pattern (alternative)
  static doubleSubmitCookie(): Middleware {
    return (req, res, next) => {
      const token = req.headers['x-csrf-token'];
      const cookie = req.cookies['csrf-token'];
      
      if (!token || !cookie || token !== cookie) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
      }
      
      next();
    };
  }
}
```

### 4. Insecure Direct Object References (IDOR) Prevention

```typescript
class IDORPrevention {
  // Always check ownership
  async getDocument(userId: string, documentId: string): Promise<Document> {
    const document = await this.db.findById(documentId);
    
    if (!document) {
      throw new NotFoundError('Document not found');
    }
    
    if (document.ownerId !== userId) {
      throw new ForbiddenError('Access denied');
    }
    
    return document;
  }
  
  // Use UUIDs instead of sequential IDs
  generateId(): string {
    return crypto.randomUUID();
  }
  
  // Implement proper access controls
  async updateResource(
    userId: string,
    resourceId: string,
    updates: any
  ): Promise<Resource> {
    // Check permissions
    const hasAccess = await this.accessControl.can(
      userId,
      'update',
      'resource',
      { resourceId }
    );
    
    if (!hasAccess) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    return this.db.update(resourceId, updates);
  }
}
```

### 5. Security Misconfiguration Prevention

```typescript
class SecurityConfiguration {
  static validateEnvironment(): void {
    const requiredEnvVars = [
      'JWT_SECRET',
      'SESSION_SECRET',
      'DATABASE_ENCRYPTION_KEY',
      'API_KEY'
    ];
    
    const missing = requiredEnvVars.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
    
    // Validate secret strength
    if (process.env.JWT_SECRET!.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters');
    }
  }
  
  static configureErrorHandling(app: Express): void {
    // Don't expose stack traces in production
    app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
      logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
      });
      
      if (process.env.NODE_ENV === 'production') {
        res.status(500).json({
          error: 'Internal server error',
          message: 'An unexpected error occurred'
        });
      } else {
        res.status(500).json({
          error: err.name,
          message: err.message,
          stack: err.stack
        });
      }
    });
  }
}
```

### 6. XML External Entity (XXE) Prevention

```typescript
class XXEPrevention {
  static parseXMLSafely(xml: string): any {
    const parser = new DOMParser();
    
    // Disable external entities
    const doc = parser.parseFromString(xml, 'text/xml', {
      resolveExternals: false,
      validateOnParse: false,
      loaddtd: false
    });
    
    return doc;
  }
  
  // For Node.js xml2js
  static configureXMLParser(): any {
    return {
      explicitArray: false,
      ignoreAttrs: true,
      parseTagValue: false,
      parseBooleans: false,
      parseNumbers: false,
      xmlns: false,
      allowBooleanAttributes: false,
      attrkey: '@',
      charkey: '#',
      strict: true,
      attrNameProcessors: [sanitizeXMLString],
      attrValueProcessors: [sanitizeXMLString],
      tagNameProcessors: [sanitizeXMLString],
      valueProcessors: [sanitizeXMLString]
    };
  }
}
```

---

## Additional Security Patterns

### Secure File Upload

```typescript
class SecureFileUpload {
  private allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
  ];
  
  private maxFileSize = 10 * 1024 * 1024; // 10MB
  
  async handleUpload(file: Express.Multer.File, userId: string): Promise<UploadResult> {
    // Validate file type
    if (!this.allowedMimeTypes.includes(file.mimetype)) {
      throw new ValidationError('Invalid file type');
    }
    
    // Validate file size
    if (file.size > this.maxFileSize) {
      throw new ValidationError('File too large');
    }
    
    // Validate file content matches MIME type
    const fileType = await fileTypeFromBuffer(file.buffer);
    if (!fileType || fileType.mime !== file.mimetype) {
      throw new ValidationError('File content does not match declared type');
    }
    
    // Generate secure filename
    const extension = path.extname(file.originalname);
    const filename = `${userId}_${Date.now()}_${crypto.randomBytes(8).toString('hex')}${extension}`;
    
    // Scan for malware (example with ClamAV)
    const isSafe = await this.scanFile(file.buffer);
    if (!isSafe) {
      throw new SecurityError('File failed security scan');
    }
    
    // Store in secure location (outside web root)
    const filepath = path.join(this.uploadDir, filename);
    await fs.promises.writeFile(filepath, file.buffer);
    
    return {
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype,
      uploadedAt: new Date()
    };
  }
  
  private async scanFile(buffer: Buffer): Promise<boolean> {
    try {
      const result = await this.clamav.scanBuffer(buffer);
      return result.isInfected === false;
    } catch (error) {
      this.logger.error('File scan failed', error);
      return false; // Fail closed
    }
  }
}
```

### API Key Management

```typescript
class APIKeyManager {
  async generateAPIKey(userId: string, name: string): Promise<APIKey> {
    // Generate cryptographically secure key
    const key = crypto.randomBytes(32).toString('hex');
    const keyHash = await this.hashAPIKey(key);
    
    // Store hashed version
    const apiKey = await this.db.create({
      userId,
      name,
      keyHash,
      prefix: key.substring(0, 8), // For identification
      createdAt: new Date(),
      lastUsed: null,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
    });
    
    // Return key only once
    return {
      ...apiKey,
      key: `${apiKey.prefix}.${key}` // Include prefix for easy identification
    };
  }
  
  async validateAPIKey(key: string): Promise<APIKeyValidation> {
    const [prefix, actualKey] = key.split('.');
    
    // Find by prefix
    const apiKeys = await this.db.findByPrefix(prefix);
    
    for (const apiKey of apiKeys) {
      const isValid = await this.verifyAPIKey(actualKey, apiKey.keyHash);
      
      if (isValid) {
        // Check expiration
        if (apiKey.expiresAt < new Date()) {
          throw new AuthenticationError('API key expired');
        }
        
        // Update last used
        await this.db.updateLastUsed(apiKey.id);
        
        return {
          valid: true,
          userId: apiKey.userId,
          scopes: apiKey.scopes
        };
      }
    }
    
    throw new AuthenticationError('Invalid API key');
  }
  
  private async hashAPIKey(key: string): Promise<string> {
    return bcrypt.hash(key, 12);
  }
  
  private async verifyAPIKey(key: string, hash: string): Promise<boolean> {
    return bcrypt.compare(key, hash);
  }
}
```

---

## Security Monitoring & Auditing

### Security Event Monitoring

```typescript
class SecurityMonitor {
  private events: SecurityEvent[] = [];
  private thresholds = {
    failedLogins: { count: 5, window: 300000 }, // 5 failures in 5 minutes
    apiErrors: { count: 50, window: 60000 }, // 50 errors in 1 minute
    suspiciousPatterns: { count: 10, window: 600000 } // 10 in 10 minutes
  };
  
  async recordEvent(event: SecurityEvent): Promise<void> {
    this.events.push(event);
    
    // Check for patterns
    await this.detectPatterns(event);
    
    // Store in persistent storage
    await this.persistEvent(event);
    
    // Clean old events
    this.cleanOldEvents();
  }
  
  private async detectPatterns(event: SecurityEvent): Promise<void> {
    // Failed login attempts
    if (event.type === 'failed_login') {
      const recentFailures = this.getRecentEvents(
        'failed_login',
        this.thresholds.failedLogins.window,
        { ip: event.ip }
      );
      
      if (recentFailures.length >= this.thresholds.failedLogins.count) {
        await this.handleSecurityIncident({
          type: 'brute_force_attempt',
          severity: 'high',
          ip: event.ip,
          details: `${recentFailures.length} failed login attempts`
        });
      }
    }
    
    // SQL injection attempts
    if (event.type === 'suspicious_input') {
      const patterns = [
        /union.*select/i,
        /drop.*table/i,
        /insert.*into/i,
        /script.*>/i,
        /onclick.*=/i
      ];
      
      for (const pattern of patterns) {
        if (pattern.test(event.data)) {
          await this.handleSecurityIncident({
            type: 'injection_attempt',
            severity: 'critical',
            ip: event.ip,
            details: `Possible injection attempt: ${event.data}`
          });
          break;
        }
      }
    }
  }
  
  private async handleSecurityIncident(incident: SecurityIncident): Promise<void> {
    // Log incident
    this.logger.error('Security incident detected', incident);
    
    // Block IP if critical
    if (incident.severity === 'critical') {
      await this.ipBlocker.block(incident.ip, '24h');
    }
    
    // Send alerts
    await this.alerting.sendSecurityAlert(incident);
    
    // Store incident
    await this.db.storeIncident(incident);
  }
}
```

### Audit Logging

```typescript
class AuditLogger {
  async log(event: AuditEvent): Promise<void> {
    const auditEntry: AuditEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      userId: event.userId,
      action: event.action,
      resource: event.resource,
      resourceId: event.resourceId,
      result: event.result,
      ip: event.ip,
      userAgent: event.userAgent,
      metadata: event.metadata,
      changes: event.changes
    };
    
    // Store in multiple places for redundancy
    await Promise.all([
      this.db.storeAuditLog(auditEntry),
      this.fileLogger.writeAuditLog(auditEntry),
      this.siem.sendAuditLog(auditEntry)
    ]);
  }
  
  // Compliance reporting
  async generateComplianceReport(
    startDate: Date,
    endDate: Date,
    filters?: AuditFilters
  ): Promise<ComplianceReport> {
    const logs = await this.db.getAuditLogs(startDate, endDate, filters);
    
    return {
      period: { start: startDate, end: endDate },
      totalEvents: logs.length,
      userActivity: this.aggregateByUser(logs),
      resourceAccess: this.aggregateByResource(logs),
      securityEvents: this.filterSecurityEvents(logs),
      anomalies: await this.detectAnomalies(logs)
    };
  }
}
```

---

## Conclusion

This security guide provides comprehensive patterns and implementations for building secure applications. Key principles to remember:

1. **Defense in Depth**: Layer multiple security controls
2. **Fail Secure**: Default to denying access
3. **Least Privilege**: Grant minimum necessary permissions
4. **Input Validation**: Never trust user input
5. **Output Encoding**: Always encode output based on context
6. **Secure by Default**: Make security the default, not an option
7. **Regular Updates**: Keep dependencies and security patches current
8. **Monitor and Audit**: Log security events and review regularly

Remember: Security is not a feature, it's a continuous process. Regular security audits, penetration testing, and staying updated with the latest security best practices are essential for maintaining a secure application.