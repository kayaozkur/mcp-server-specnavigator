# 🚀 Quick Start Checklist for MCP SpecNavigator

Get up and running with MCP SpecNavigator in minutes by following this checklist.

## ✅ Essential First Steps

### 1. **Prerequisites Check**
- [ ] Node.js 18+ installed (`node --version`)
- [ ] npm 8+ installed (`npm --version`)
- [ ] Git installed (for development)
- [ ] Claude Desktop installed (for integration)

### 2. **Installation**
- [ ] **Option A: Global Install (Recommended)**
  ```bash
  npm install -g @lepion/mcp-server-specnavigator
  ```
- [ ] **Option B: From Source**
  ```bash
  git clone https://github.com/kayaozkur/mcp-server-specnavigator.git
  cd mcp-server-specnavigator
  npm install
  npm run build
  ```

### 3. **Configuration**
- [ ] Locate Claude Desktop config file:
  - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
  - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- [ ] Add SpecNavigator configuration:
  ```json
  {
    "mcpServers": {
      "specnavigator": {
        "command": "npx",
        "args": ["@lepion/mcp-server-specnavigator"]
      }
    }
  }
  ```
- [ ] Restart Claude Desktop

## ⚠️ Common Gotchas to Avoid

### Configuration Issues
- **❌ Wrong Path**: Don't use relative paths in config
- **✅ Correct**: Use `npx` for global installs or absolute paths
- **❌ Missing Restart**: Config changes require Claude Desktop restart
- **✅ Always**: Restart Claude Desktop after config changes

### Development Pitfalls
- **❌ Forgetting Build**: TypeScript must be compiled before running
- **✅ Always**: Run `npm run build` after changes
- **❌ Wrong Node Version**: Using Node < 18 will cause errors
- **✅ Check**: Run `node --version` to verify Node 18+

### Windows-Specific
- **❌ Path Separators**: Using forward slashes in Windows paths
- **✅ Use**: Backslashes or escaped forward slashes
- **❌ Permission Issues**: Running without proper permissions
- **✅ Try**: Run terminal as Administrator if needed

## 🛠️ Tool Setup Requirements

### For Users (Production)
```bash
# Install globally
npm install -g @lepion/mcp-server-specnavigator

# Verify installation
npx @lepion/mcp-server-specnavigator --version
```

### For Developers
```bash
# Clone and setup
git clone https://github.com/kayaozkur/mcp-server-specnavigator.git
cd mcp-server-specnavigator

# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev
```

### Environment Variables (Optional)
```bash
# Development mode
NODE_ENV=development

# Custom cache directory
SPEC_CACHE_DIR=/path/to/cache

# Cache TTL (in seconds)
CACHE_TTL=3600
```

## ✔️ Verification Steps

### 1. **Verify Installation**
- [ ] Run `npx @lepion/mcp-server-specnavigator --version`
- [ ] Should output version number without errors

### 2. **Test Server Startup**
- [ ] Run `npx @lepion/mcp-server-specnavigator`
- [ ] Should see "MCP SpecNavigator Server started" message
- [ ] No error messages should appear

### 3. **Claude Desktop Integration**
- [ ] Open Claude Desktop
- [ ] Check for SpecNavigator in available tools
- [ ] Try command: "Generate a markdown tree of MCP specs"
- [ ] Should return formatted tree structure

### 4. **Test Core Features**
```bash
# Test 1: Fetch updates
"Check for MCP specification updates"

# Test 2: Generate tree
"Create a markdown tree of the MCP specification"

# Test 3: Search sections
"Find sections about 'messages' in the MCP spec"

# Test 4: Get content
"Get the content of the protocol/messages section"
```

## 📚 Detailed Guides & Resources

### Essential Documentation
- 📖 [Full README](./README.md) - Complete project documentation
- 🏗️ [Implementation Guide](./IMPLEMENTATION_GUIDE.md) - Technical implementation details
- 📊 [Executive Summary](./EXECUTIVE_SUMMARY.md) - Project overview and rationale
- 🔍 [Repository Analysis](./REPOSITORY_ANALYSIS.md) - Code structure analysis

### External Resources
- 🌐 [NPM Package Page](https://www.npmjs.com/package/@lepion/mcp-server-specnavigator)
- 💻 [GitHub Repository](https://github.com/kayaozkur/mcp-server-specnavigator)
- 📋 [MCP Specification](https://github.com/modelcontextprotocol/modelcontextprotocol)
- 🐛 [Report Issues](https://github.com/kayaozkur/mcp-server-specnavigator/issues)

### Quick Commands Reference
```bash
# Development
npm run dev          # Start with hot reload
npm run build        # Compile TypeScript
npm run test         # Run tests
npm run lint         # Check code style
npm run format       # Auto-format code

# Production
npm start            # Start compiled server
npx @lepion/mcp-server-specnavigator  # Run global install
```

## 🆘 Troubleshooting Quick Fixes

### Server Won't Start
1. Check Node version: `node --version` (must be 18+)
2. Reinstall dependencies: `npm clean-install`
3. Rebuild: `npm run build`

### Claude Desktop Can't Find Server
1. Verify config path is correct
2. Check JSON syntax in config file
3. Restart Claude Desktop
4. Try absolute path instead of npx

### TypeScript Errors
1. Update TypeScript: `npm update typescript`
2. Clean build: `rm -rf dist && npm run build`
3. Check tsconfig.json exists

---

**Need Help?** 
- 🐛 [Open an Issue](https://github.com/kayaozkur/mcp-server-specnavigator/issues)
- 📧 Contact: See package.json for author info
- 💬 Check existing issues for solutions

**Ready to Go?** Start with the Essential First Steps checklist above! 🚀