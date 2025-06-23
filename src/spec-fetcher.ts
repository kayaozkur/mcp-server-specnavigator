import axios from 'axios';
import NodeCache from 'node-cache';
import { promises as fs } from 'fs';
import path from 'path';

export interface SpecUpdate {
  hasUpdates: boolean;
  lastChecked: Date;
  currentVersion?: string;
  latestVersion?: string;
  changes?: string[];
}

export class SpecFetcher {
  private cache: NodeCache;
  private readonly cacheKey = 'mcp-spec';
  private readonly metaKey = 'mcp-spec-meta';
  private readonly specUrl = 'https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/index.md';
  private readonly cacheTTL = 3600; // 1 hour in seconds

  constructor() {
    this.cache = new NodeCache({
      stdTTL: this.cacheTTL,
      checkperiod: 600, // Check for expired keys every 10 minutes
    });
  }

  async checkForUpdates(forceRefresh: boolean = false): Promise<SpecUpdate> {
    const lastChecked = new Date();
    
    if (!forceRefresh) {
      const cachedMeta = this.cache.get<SpecUpdate>(this.metaKey);
      if (cachedMeta && (lastChecked.getTime() - cachedMeta.lastChecked.getTime()) < 300000) {
        // Return cached metadata if checked within last 5 minutes
        return cachedMeta;
      }
    }

    try {
      // Fetch the latest spec headers to check for updates
      const response = await axios.head(this.specUrl);
      const latestVersion = response.headers['last-modified'] || response.headers['etag'];
      
      const cachedSpec = this.cache.get<{ version: string; content: string }>(this.cacheKey);
      const currentVersion = cachedSpec?.version;

      const hasUpdates = !currentVersion || currentVersion !== latestVersion;

      const update: SpecUpdate = {
        hasUpdates,
        lastChecked,
        currentVersion,
        latestVersion,
        changes: hasUpdates ? ['Specification updated since last fetch'] : [],
      };

      // Cache the metadata
      this.cache.set(this.metaKey, update, 300); // Cache for 5 minutes

      if (hasUpdates || forceRefresh) {
        // Fetch and cache the new spec
        await this.fetchAndCacheSpec(latestVersion);
      }

      return update;
    } catch (error) {
      console.error('Error checking for updates:', error);
      return {
        hasUpdates: false,
        lastChecked,
        changes: ['Error checking for updates'],
      };
    }
  }

  async getSpec(): Promise<string> {
    // Check cache first
    const cachedSpec = this.cache.get<{ version: string; content: string }>(this.cacheKey);
    if (cachedSpec) {
      return cachedSpec.content;
    }

    // Fetch if not cached
    await this.checkForUpdates(true);
    const spec = this.cache.get<{ version: string; content: string }>(this.cacheKey);
    
    if (!spec) {
      throw new Error('Failed to fetch specification');
    }

    return spec.content;
  }

  private async fetchAndCacheSpec(version?: string): Promise<void> {
    try {
      const response = await axios.get(this.specUrl);
      const content = response.data;
      const specVersion = version || response.headers['last-modified'] || response.headers['etag'] || Date.now().toString();

      // Cache the spec
      this.cache.set(this.cacheKey, {
        version: specVersion,
        content,
      });

      // Also save to local file as backup
      await this.saveLocalBackup(content);
    } catch (error) {
      console.error('Error fetching specification:', error);
      
      // Try to load from local backup
      const backup = await this.loadLocalBackup();
      if (backup) {
        this.cache.set(this.cacheKey, {
          version: 'local-backup',
          content: backup,
        });
      } else {
        throw new Error('Failed to fetch specification and no local backup available');
      }
    }
  }

  private async saveLocalBackup(content: string): Promise<void> {
    try {
      const backupDir = path.join(process.cwd(), '.cache');
      await fs.mkdir(backupDir, { recursive: true });
      await fs.writeFile(path.join(backupDir, 'mcp-spec-backup.md'), content, 'utf-8');
    } catch (error) {
      console.error('Error saving local backup:', error);
    }
  }

  private async loadLocalBackup(): Promise<string | null> {
    try {
      const backupPath = path.join(process.cwd(), '.cache', 'mcp-spec-backup.md');
      return await fs.readFile(backupPath, 'utf-8');
    } catch (error) {
      return null;
    }
  }

  async fetchAdditionalSpecs(): Promise<Map<string, string>> {
    const additionalSpecs = new Map<string, string>();
    const specPaths = [
      'architecture.md',
      'protocol.md',
      'capabilities.md',
      'messages.md',
      'errors.md',
    ];

    const baseUrl = 'https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/';

    for (const specPath of specPaths) {
      try {
        const response = await axios.get(baseUrl + specPath);
        additionalSpecs.set(specPath.replace('.md', ''), response.data);
      } catch (error) {
        console.error(`Error fetching ${specPath}:`, error);
      }
    }

    return additionalSpecs;
  }
}