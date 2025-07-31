const { AnchorNavigator } = require('../src/anchor-navigator');

describe('AnchorNavigator', () => {
  let navigator: AnchorNavigator;

  beforeEach(() => {
    navigator = new AnchorNavigator();
  });

  const sampleMarkdown = `
# Introduction
This is the introduction section.

## Getting Started
How to get started with the protocol.

### Installation
Install the required packages.

## API Reference
Detailed API documentation.

### Methods
Available methods and their parameters.

## Examples
Code examples and use cases.
  `;

  describe('findSections', () => {
    it('should find sections with exact matching', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'API', false);

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThan(0);
      
      const apiSection = results.find(r => r.title.includes('API'));
      expect(apiSection).toBeDefined();
      expect(apiSection?.title).toContain('API Reference');
    });

    it('should find sections with fuzzy matching', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'start', true);

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
      
      // Should find "Getting Started" with fuzzy matching
      const startSection = results.find(r => r.title.toLowerCase().includes('start'));
      expect(startSection).toBeDefined();
    });

    it('should return empty array for non-matching query', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'nonexistent', false);

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(0);
    });

    it('should handle case-insensitive search', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'EXAMPLES', false);

      expect(results).toBeDefined();
      expect(results.length).toBeGreaterThan(0);
      
      const exampleSection = results.find(r => r.title.toLowerCase().includes('examples'));
      expect(exampleSection).toBeDefined();
    });

    it('should return sections with proper structure', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'Getting', false);

      expect(results.length).toBeGreaterThan(0);
      
      const section = results[0];
      expect(section).toHaveProperty('title');
      expect(section).toHaveProperty('path');
      expect(section).toHaveProperty('anchor');
      expect(section).toHaveProperty('preview');
      expect(section).toHaveProperty('depth');
      
      expect(typeof section.title).toBe('string');
      expect(typeof section.path).toBe('string');
      expect(typeof section.anchor).toBe('string');
      expect(typeof section.preview).toBe('string');
      expect(typeof section.depth).toBe('number');
    });
  });

  describe('generateSectionPath', () => {
    it('should generate valid section paths', async () => {
      const results = await navigator.findSections(sampleMarkdown, 'Installation', false);
      
      if (results.length > 0) {
        const section = results[0];
        expect(section.path).toBeDefined();
        expect(section.path.length).toBeGreaterThan(0);
      }
    });
  });
});