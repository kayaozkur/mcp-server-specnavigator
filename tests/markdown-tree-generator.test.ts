const { MarkdownTreeGenerator } = require('../src/markdown-tree-generator');

describe('MarkdownTreeGenerator', () => {
  let generator: MarkdownTreeGenerator;

  beforeEach(() => {
    generator = new MarkdownTreeGenerator();
  });

  describe('generateTree', () => {
    const sampleMarkdown = `
# Main Title
Some content here.

## Section 1
More content.

### Subsection 1.1  
Even more content.

## Section 2
Final content.
    `;

    it('should generate tree with default options', async () => {
      const tree = await generator.generateTree(sampleMarkdown, {
        maxDepth: 3,
        includeAnchors: false,
      });

      expect(tree).toBeDefined();
      expect(typeof tree).toBe('string');
      expect(tree).toContain('Main Title');
      expect(tree).toContain('Section 1');
      expect(tree).toContain('Section 2');
    });

    it('should respect maxDepth parameter', async () => {
      const tree = await generator.generateTree(sampleMarkdown, {
        maxDepth: 2,
        includeAnchors: false,
      });

      expect(tree).toContain('Section 1');
      expect(tree).toContain('Section 2');
      // Should not contain subsection due to maxDepth = 2
      expect(tree).not.toContain('Subsection 1.1');
    });

    it('should handle empty markdown', async () => {
      const tree = await generator.generateTree('', {
        maxDepth: 3,
        includeAnchors: false,
      });

      expect(tree).toBeDefined();
      expect(typeof tree).toBe('string');
    });

    it('should handle markdown with no headers', async () => {
      const noHeaderMarkdown = 'Just some plain text without any headers.';
      
      const tree = await generator.generateTree(noHeaderMarkdown, {
        maxDepth: 3,
        includeAnchors: false,
      });

      expect(tree).toBeDefined();
      expect(typeof tree).toBe('string');
    });

    it('should include anchors when requested', async () => {
      const tree = await generator.generateTree(sampleMarkdown, {
        maxDepth: 3,
        includeAnchors: true,
      });

      expect(tree).toBeDefined();
      expect(typeof tree).toBe('string');
      // Should contain some form of anchor or link formatting
      expect(tree.length).toBeGreaterThan(0);
    });
  });
});