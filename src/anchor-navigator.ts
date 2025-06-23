export interface SectionResult {
  title: string;
  path: string;
  anchor: string;
  preview: string;
  depth: number;
}

export class AnchorNavigator {
  async findSections(
    markdown: string,
    query: string,
    fuzzy: boolean = false
  ): Promise<SectionResult[]> {
    const sections = this.parseSections(markdown);
    const results: SectionResult[] = [];

    const searchQuery = query.toLowerCase();

    for (const section of sections) {
      const titleLower = section.title.toLowerCase();
      
      let matches = false;
      if (fuzzy) {
        // Fuzzy matching: check if all characters in query appear in order
        matches = this.fuzzyMatch(searchQuery, titleLower);
      } else {
        // Exact substring matching
        matches = titleLower.includes(searchQuery);
      }

      if (matches) {
        results.push({
          ...section,
          anchor: this.generateAnchor(section.title),
        });
      }
    }

    // Sort by relevance (exact matches first, then by position)
    return results.sort((a, b) => {
      const aExact = a.title.toLowerCase() === searchQuery;
      const bExact = b.title.toLowerCase() === searchQuery;
      
      if (aExact && !bExact) return -1;
      if (!aExact && bExact) return 1;
      
      // Then sort by depth (higher level sections first)
      if (a.depth !== b.depth) return a.depth - b.depth;
      
      // Finally by position in document
      return 0;
    });
  }

  async getSectionContent(
    markdown: string,
    sectionPath: string,
    includeSubsections: boolean = false
  ): Promise<string> {
    const lines = markdown.split('\n');
    const sections = this.parseSectionsWithContent(lines);

    // Find the section by path or anchor
    const targetSection = sections.find(
      section =>
        section.path === sectionPath ||
        this.generateAnchor(section.title) === sectionPath
    );

    if (!targetSection) {
      throw new Error(`Section not found: ${sectionPath}`);
    }

    if (!includeSubsections) {
      return targetSection.content;
    }

    // Include subsections
    let content = targetSection.content;
    const targetDepth = targetSection.depth;
    const startIndex = sections.indexOf(targetSection);

    for (let i = startIndex + 1; i < sections.length; i++) {
      const section = sections[i];
      if (section.depth <= targetDepth) {
        break; // We've reached a section at the same or higher level
      }
      content += `\n\n${section.heading}\n\n${section.content}`;
    }

    return content;
  }

  private parseSections(markdown: string): Omit<SectionResult, 'anchor'>[] {
    const lines = markdown.split('\n');
    const sections: Omit<SectionResult, 'anchor'>[] = [];
    let currentPath: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);

      if (headingMatch) {
        const depth = headingMatch[1].length;
        const title = headingMatch[2].trim();

        // Update path based on depth
        currentPath = currentPath.slice(0, depth - 1);
        currentPath.push(this.slugify(title));

        // Get preview (next few lines after heading)
        let preview = '';
        for (let j = i + 1; j < Math.min(i + 4, lines.length); j++) {
          const previewLine = lines[j].trim();
          if (previewLine && !previewLine.startsWith('#')) {
            preview += previewLine + ' ';
            if (preview.length > 150) break;
          }
        }
        preview = preview.trim().substring(0, 150);
        if (preview.length === 150) preview += '...';

        sections.push({
          title,
          path: currentPath.join('/'),
          preview,
          depth,
        });
      }
    }

    return sections;
  }

  private parseSectionsWithContent(lines: string[]): Array<{
    title: string;
    path: string;
    depth: number;
    content: string;
    heading: string;
  }> {
    const sections: Array<{
      title: string;
      path: string;
      depth: number;
      content: string;
      heading: string;
    }> = [];
    
    let currentSection: any = null;
    let currentPath: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);

      if (headingMatch) {
        // Save previous section if exists
        if (currentSection) {
          sections.push(currentSection);
        }

        const depth = headingMatch[1].length;
        const title = headingMatch[2].trim();

        // Update path
        currentPath = currentPath.slice(0, depth - 1);
        currentPath.push(this.slugify(title));

        currentSection = {
          title,
          path: currentPath.join('/'),
          depth,
          content: '',
          heading: line,
        };
      } else if (currentSection) {
        // Add content to current section
        if (currentSection.content || line.trim()) {
          currentSection.content += (currentSection.content ? '\n' : '') + line;
        }
      }
    }

    // Don't forget the last section
    if (currentSection) {
      sections.push(currentSection);
    }

    return sections;
  }

  private generateAnchor(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
  }

  private slugify(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
  }

  private fuzzyMatch(query: string, text: string): boolean {
    let queryIndex = 0;
    
    for (let i = 0; i < text.length && queryIndex < query.length; i++) {
      if (text[i] === query[queryIndex]) {
        queryIndex++;
      }
    }
    
    return queryIndex === query.length;
  }

  async generateAnchorIndex(markdown: string): Promise<string> {
    const sections = this.parseSections(markdown);
    let index = '# Section Index\n\n';

    const byDepth = new Map<number, typeof sections>();
    
    for (const section of sections) {
      if (!byDepth.has(section.depth)) {
        byDepth.set(section.depth, []);
      }
      byDepth.get(section.depth)!.push(section);
    }

    for (const [depth, depthSections] of Array.from(byDepth.entries()).sort(
      (a, b) => a[0] - b[0]
    )) {
      index += `## Level ${depth} Sections\n\n`;
      for (const section of depthSections) {
        const anchor = this.generateAnchor(section.title);
        index += `- [${section.title}](#${anchor}) - \`${section.path}\`\n`;
        if (section.preview) {
          index += `  > ${section.preview}\n`;
        }
      }
      index += '\n';
    }

    return index;
  }
}