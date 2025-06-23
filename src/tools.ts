import { Tool } from '@modelcontextprotocol/sdk/types.js';

export const specNavigatorTools: Tool[] = [
  {
    name: 'fetch_spec_updates',
    description: 'Check for upstream changes in the Model Context Protocol specification',
    inputSchema: {
      type: 'object',
      properties: {
        force_refresh: {
          type: 'boolean',
          description: 'Force refresh the specification even if cache is valid',
          default: false,
        },
      },
    },
  },
  {
    name: 'generate_markdown_tree',
    description: 'Generate a navigable tree structure of the MCP specification with optional anchor links',
    inputSchema: {
      type: 'object',
      properties: {
        max_depth: {
          type: 'number',
          description: 'Maximum heading depth to include in the tree (1-6)',
          default: 3,
          minimum: 1,
          maximum: 6,
        },
        include_anchors: {
          type: 'boolean',
          description: 'Include clickable anchor links in the tree',
          default: true,
        },
      },
    },
  },
  {
    name: 'find_section',
    description: 'Search for sections in the MCP specification by keyword and return anchor links',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query for section titles',
        },
        fuzzy: {
          type: 'boolean',
          description: 'Enable fuzzy matching for more flexible search results',
          default: false,
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'get_spec_content',
    description: 'Retrieve content from a specific section of the MCP specification',
    inputSchema: {
      type: 'object',
      properties: {
        section_path: {
          type: 'string',
          description: 'Path to the section (e.g., "protocol/messages") or anchor name',
        },
        include_subsections: {
          type: 'boolean',
          description: 'Include all subsections under the requested section',
          default: false,
        },
      },
      required: ['section_path'],
    },
  },
];