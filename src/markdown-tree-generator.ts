import { unified } from 'unified';
import remarkParse from 'remark-parse';
import type { Root } from 'mdast';

export interface TreeOptions {
  maxDepth: number;
  includeAnchors: boolean;
}

export class MarkdownTreeGenerator {
  async generateTree(markdown: string, options: TreeOptions): Promise<string> {
    const { maxDepth } = options;

    // Parse the markdown
    const processor = unified().use(remarkParse);
    const tree = processor.parse(markdown) as Root;

    // Extract headings
    const headings = this.extractHeadings(tree, maxDepth);

    // Generate table of contents
    const tocTree = this.buildTocTree(headings);

    // Convert to markdown string
    return this.renderTree(tocTree, 0);
  }

  private extractHeadings(tree: Root, maxDepth: number): Array<{
    depth: number;
    text: string;
    anchor: string;
  }> {
    const headings: Array<{ depth: number; text: string; anchor: string }> = [];

    const visit = (node: any) => {
      if (node.type === 'heading' && node.depth <= maxDepth) {
        const text = this.getTextContent(node);
        const anchor = this.generateAnchor(text);
        headings.push({
          depth: node.depth,
          text,
          anchor,
        });
      }
      if (node.children) {
        node.children.forEach(visit);
      }
    };

    tree.children.forEach(visit);
    return headings;
  }

  private getTextContent(node: any): string {
    if (node.type === 'text') {
      return node.value;
    }
    if (node.children) {
      return node.children.map((child: any) => this.getTextContent(child)).join('');
    }
    return '';
  }

  private generateAnchor(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^\w\s-]/g, '') // Remove special characters
      .replace(/\s+/g, '-') // Replace spaces with hyphens
      .replace(/-+/g, '-') // Replace multiple hyphens with single hyphen
      .trim();
  }

  private buildTocTree(
    headings: Array<{ depth: number; text: string; anchor: string }>
  ): any {
    const root: any = {
      children: [],
    };

    const stack: any[] = [root];
    let lastDepth = 0;

    for (const heading of headings) {
      const item = {
        text: heading.text,
        anchor: heading.anchor,
        depth: heading.depth,
        children: [],
      };

      // Find the correct parent
      while (stack.length > 1 && heading.depth <= lastDepth) {
        stack.pop();
        lastDepth--;
      }

      // Add to current parent
      const parent = stack[stack.length - 1];
      parent.children.push(item);

      // Update stack for potential children
      if (heading.depth > lastDepth) {
        stack.push(item);
        lastDepth = heading.depth;
      }
    }

    return root;
  }

  private renderTree(node: any, indent: number): string {
    let result = '';

    if (node.text) {
      const prefix = '  '.repeat(indent) + '- ';
      if (node.anchor) {
        result += `${prefix}[${node.text}](#${node.anchor})\n`;
      } else {
        result += `${prefix}${node.text}\n`;
      }
    }

    for (const child of node.children || []) {
      result += this.renderTree(child, node.text ? indent + 1 : indent);
    }

    return result;
  }

  async generateEnhancedTree(
    markdown: string,
    additionalSpecs: Map<string, string>
  ): Promise<string> {
    let enhancedTree = '# Model Context Protocol Specification Navigation\n\n';

    // Generate main spec tree
    enhancedTree += '## Main Specification\n\n';
    const mainTree = await this.generateTree(markdown, {
      maxDepth: 3,
      includeAnchors: true,
    });
    enhancedTree += mainTree + '\n';

    // Generate trees for additional specs
    for (const [name, content] of additionalSpecs) {
      enhancedTree += `## ${this.formatSpecName(name)}\n\n`;
      const subTree = await this.generateTree(content, {
        maxDepth: 3,
        includeAnchors: true,
      });
      enhancedTree += subTree + '\n';
    }

    return enhancedTree;
  }

  private formatSpecName(name: string): string {
    return name
      .split(/[-_]/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  async generateCompactTree(markdown: string): Promise<string> {
    const headings = await this.extractAllHeadings(markdown);
    let tree = '';

    for (const heading of headings) {
      const indent = '  '.repeat(heading.depth - 1);
      tree += `${indent}- ${heading.text}\n`;
    }

    return tree;
  }

  private async extractAllHeadings(markdown: string): Promise<
    Array<{ depth: number; text: string }>
  > {
    const lines = markdown.split('\n');
    const headings: Array<{ depth: number; text: string }> = [];

    for (const line of lines) {
      const match = line.match(/^(#{1,6})\s+(.+)$/);
      if (match) {
        headings.push({
          depth: match[1].length,
          text: match[2].trim(),
        });
      }
    }

    return headings;
  }
}