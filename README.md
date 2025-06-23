# @lepion/mcp-server-specnavigator

An MCP (Model Context Protocol) server for navigating and exploring Model Context Protocol specifications with dynamic markdown tree generation and intelligent section navigation.

## Attribution

This project is based on the Model Context Protocol specification from https://github.com/modelcontextprotocol/modelcontextprotocol

## Purpose

The MCP SpecNavigator server provides tools to:
- Navigate MCP specifications dynamically
- Generate markdown tree structures for easy exploration
- Search and find specific sections with anchor links
- Fetch and cache upstream specification updates
- Provide contextual access to MCP documentation

## Features

- **Dynamic Markdown Tree Generation**: Automatically generates navigable tree structures from MCP specifications
- **Intelligent Section Search**: Find sections by keywords and get direct anchor links
- **Specification Caching**: Efficiently caches specifications to reduce network requests
- **Upstream Synchronization**: Check for updates from the official MCP repository
- **Section Content Retrieval**: Get specific sections of the specification on demand

## Installation

```bash
# Clone the repository
git clone https://github.com/lepion/mcp-server-specnavigator.git
cd mcp-server-specnavigator

# Install dependencies
npm install

# Build the TypeScript code
npm run build

# Start the server
npm start
```

### Development Mode

```bash
# Run with hot reload
npm run dev
```

## Available Tools

### 1. `fetch_spec_updates`
Check for upstream changes in the MCP specification repository.

**Parameters:**
- `force_refresh` (boolean, optional): Force refresh even if cache is valid

**Returns:**
- Update status and any new changes detected

### 2. `generate_markdown_tree`
Create a navigable tree structure of the MCP specification.

**Parameters:**
- `max_depth` (number, optional): Maximum depth of the tree (default: 3)
- `include_anchors` (boolean, optional): Include anchor links in the tree

**Returns:**
- Markdown-formatted tree structure with navigation links

### 3. `find_section`
Search for sections by keyword and return anchor links.

**Parameters:**
- `query` (string, required): Search query for section titles
- `fuzzy` (boolean, optional): Enable fuzzy matching (default: false)

**Returns:**
- Array of matching sections with titles, paths, and anchor links

### 4. `get_spec_content`
Retrieve content from a specific section of the specification.

**Parameters:**
- `section_path` (string, required): Path to the section (e.g., "protocol/messages")
- `include_subsections` (boolean, optional): Include subsection content

**Returns:**
- Markdown content of the requested section

## MCP Configuration

To use this server with Claude Desktop or other MCP clients, add the following to your MCP configuration:

```json
{
  "mcpServers": {
    "specnavigator": {
      "command": "node",
      "args": ["/path/to/mcp-server-specnavigator/dist/index.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Architecture

```
src/
├── index.ts                    # Main MCP server entry point
├── spec-fetcher.ts            # Handles fetching and caching specs
├── markdown-tree-generator.ts  # Generates dynamic markdown trees
├── anchor-navigator.ts        # Finds sections and generates anchors
└── tools.ts                   # MCP tool definitions
```

## Development

### Running Tests

```bash
npm test
```

### Linting

```bash
npm run lint
```

### Formatting

```bash
npm run format
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Acknowledgments

Special thanks to the Model Context Protocol team for creating the specification and protocol that this server navigates.