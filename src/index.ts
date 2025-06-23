#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { specNavigatorTools } from './tools.js';
import { SpecFetcher } from './spec-fetcher.js';
import { MarkdownTreeGenerator } from './markdown-tree-generator.js';
import { AnchorNavigator } from './anchor-navigator.js';

// Initialize components
const specFetcher = new SpecFetcher();
const treeGenerator = new MarkdownTreeGenerator();
const anchorNavigator = new AnchorNavigator();

// Create MCP server
const server = new Server(
  {
    name: 'mcp-server-specnavigator',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: specNavigatorTools,
  };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'fetch_spec_updates': {
        const forceRefresh = args?.force_refresh || false;
        const result = await specFetcher.checkForUpdates(forceRefresh);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'generate_markdown_tree': {
        const maxDepth = args?.max_depth || 3;
        const includeAnchors = args?.include_anchors || true;
        const spec = await specFetcher.getSpec();
        const tree = await treeGenerator.generateTree(spec, {
          maxDepth,
          includeAnchors,
        });
        return {
          content: [
            {
              type: 'text',
              text: tree,
            },
          ],
        };
      }

      case 'find_section': {
        if (!args?.query) {
          throw new Error('Query parameter is required');
        }
        const spec = await specFetcher.getSpec();
        const results = await anchorNavigator.findSections(
          spec,
          args.query,
          args.fuzzy || false
        );
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      }

      case 'get_spec_content': {
        if (!args?.section_path) {
          throw new Error('Section path parameter is required');
        }
        const spec = await specFetcher.getSpec();
        const content = await anchorNavigator.getSectionContent(
          spec,
          args.section_path,
          args.include_subsections || false
        );
        return {
          content: [
            {
              type: 'text',
              text: content,
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP SpecNavigator server started');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});