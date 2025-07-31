const { specNavigatorTools } = require('../src/tools');

describe('specNavigatorTools', () => {
  it('should export an array of tools', () => {
    expect(Array.isArray(specNavigatorTools)).toBe(true);
    expect(specNavigatorTools.length).toBeGreaterThan(0);
  });

  describe('fetch_spec_updates tool', () => {
    it('should have correct structure', () => {
      const fetchTool = specNavigatorTools.find(tool => tool.name === 'fetch_spec_updates');
      
      expect(fetchTool).toBeDefined();
      expect(fetchTool?.name).toBe('fetch_spec_updates');
      expect(fetchTool?.description).toBeDefined();
      expect(fetchTool?.inputSchema).toBeDefined();
      expect(fetchTool?.inputSchema.type).toBe('object');
      expect(fetchTool?.inputSchema.properties).toBeDefined();
    });

    it('should have force_refresh parameter', () => {
      const fetchTool = specNavigatorTools.find(tool => tool.name === 'fetch_spec_updates');
      
      expect(fetchTool?.inputSchema.properties?.force_refresh).toBeDefined();
      expect((fetchTool?.inputSchema.properties?.force_refresh as any)?.type).toBe('boolean');
    });
  });

  describe('generate_markdown_tree tool', () => {
    it('should have correct structure', () => {
      const treeTool = specNavigatorTools.find(tool => tool.name === 'generate_markdown_tree');
      
      expect(treeTool).toBeDefined();
      expect(treeTool?.name).toBe('generate_markdown_tree');
      expect(treeTool?.description).toBeDefined();
      expect(treeTool?.inputSchema).toBeDefined();
      expect(treeTool?.inputSchema.type).toBe('object');
      expect(treeTool?.inputSchema.properties).toBeDefined();
    });

    it('should have max_depth parameter with constraints', () => {
      const treeTool = specNavigatorTools.find(tool => tool.name === 'generate_markdown_tree');
      
      expect(treeTool?.inputSchema.properties?.max_depth).toBeDefined();
      expect((treeTool?.inputSchema.properties?.max_depth as any)?.type).toBe('number');
      expect((treeTool?.inputSchema.properties?.max_depth as any)?.minimum).toBe(1);
      expect((treeTool?.inputSchema.properties?.max_depth as any)?.maximum).toBe(6);
    });
  });

  describe('find_sections tool', () => {
    it('should have correct structure', () => {
      const findTool = specNavigatorTools.find(tool => tool.name === 'find_sections');
      
      expect(findTool).toBeDefined();
      expect(findTool?.name).toBe('find_sections');
      expect(findTool?.description).toBeDefined();
      expect(findTool?.inputSchema).toBeDefined();
      expect(findTool?.inputSchema.type).toBe('object');
      expect(findTool?.inputSchema.properties).toBeDefined();
    });

    it('should have required query parameter', () => {
      const findTool = specNavigatorTools.find(tool => tool.name === 'find_sections');
      
      expect(findTool?.inputSchema.properties?.query).toBeDefined();
      expect((findTool?.inputSchema.properties?.query as any)?.type).toBe('string');
      expect(findTool?.inputSchema.required).toContain('query');
    });

    it('should have fuzzy parameter', () => {
      const findTool = specNavigatorTools.find(tool => tool.name === 'find_sections');
      
      expect(findTool?.inputSchema.properties?.fuzzy).toBeDefined();
      expect((findTool?.inputSchema.properties?.fuzzy as any)?.type).toBe('boolean');
    });
  });

  it('should have all expected tools', () => {
    const toolNames = specNavigatorTools.map(tool => tool.name);
    
    expect(toolNames).toContain('fetch_spec_updates');
    expect(toolNames).toContain('generate_markdown_tree');
    expect(toolNames).toContain('find_sections');
  });
});