# @lepion/mcp-server-specnavigator

[![npm version](https://badge.fury.io/js/@lepion%2Fmcp-server-specnavigator.svg)](https://www.npmjs.com/package/@lepion/mcp-server-specnavigator)

An intelligent MCP (Model Context Protocol) server for navigating, exploring, and understanding the Model Context Protocol specification with dynamic markdown tree generation, intelligent section navigation, and upstream synchronization.

## 🎯 Purpose

The MCP SpecNavigator server transforms the way you interact with MCP specifications by providing:
- 🌳 **Dynamic Markdown Trees** - Navigate specifications with auto-generated tree structures
- 🔍 **Intelligent Search** - Find sections instantly with keyword search and anchor links
- 🔄 **Upstream Sync** - Stay updated with the latest specification changes
- 📚 **Contextual Documentation** - Access specific sections on-demand
- ⚡ **Performance Optimized** - Efficient caching for fast responses

## 📋 Attribution

This project is based on and provides navigation for the [Model Context Protocol specification](https://github.com/modelcontextprotocol/modelcontextprotocol) created by the Model Context Protocol team. This is a wrapper/navigation tool that enhances access to the original specification.

## ✨ Features

- **Dynamic Markdown Tree Generation**: Automatically generates navigable tree structures from MCP specifications
- **Intelligent Section Search**: Find sections by keywords and get direct anchor links
- **Specification Caching**: Efficiently caches specifications to reduce network requests
- **Upstream Synchronization**: Check for updates from the official MCP repository
- **Section Content Retrieval**: Get specific sections of the specification on demand

## 📦 Installation

### Via npm (Recommended)
```bash
npm install -g @lepion/mcp-server-specnavigator
```

### From Source
```bash
# Clone the repository
git clone https://github.com/kayaozkur/mcp-server-specnavigator.git
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

## 🛠️ Available Tools

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

## ⚙️ MCP Configuration

### For Claude Desktop

Add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "specnavigator": {
      "command": "npx",
      "args": ["@lepion/mcp-server-specnavigator"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

### For Development
```json
{
  "mcpServers": {
    "specnavigator": {
      "command": "node",
      "args": ["/path/to/mcp-server-specnavigator/dist/index.js"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  }
}
```

## 🏗️ Architecture

```
src/
├── index.ts                    # Main MCP server entry point
├── spec-fetcher.ts            # Handles fetching and caching specs
├── markdown-tree-generator.ts  # Generates dynamic markdown trees
├── anchor-navigator.ts        # Finds sections and generates anchors
└── tools.ts                   # MCP tool definitions
```

## 🧪 Development

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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Model Context Protocol Team** - For creating the [MCP specification](https://github.com/modelcontextprotocol/modelcontextprotocol) that this server navigates
- **Anthropic** - For developing the Model Context Protocol standard
- **Contributors** - Everyone who has contributed to improving this navigation tool

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@lepion/mcp-server-specnavigator)
- [GitHub Repository](https://github.com/kayaozkur/mcp-server-specnavigator)
- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/modelcontextprotocol)
- [Report Issues](https://github.com/kayaozkur/mcp-server-specnavigator/issues)

---

Built with ❤️ by the Lepion Team