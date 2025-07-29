#!/bin/bash

# Setup script for project-architecture-blueprint repository
# This script creates the necessary directory structure and initializes the repository

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Project Architecture Blueprint Setup ===${NC}"
echo ""

# Get the target directory from command line or use current directory
TARGET_DIR="${1:-.}"

# Create main directory if specified
if [ "$TARGET_DIR" != "." ]; then
    echo -e "${GREEN}Creating project directory: $TARGET_DIR${NC}"
    mkdir -p "$TARGET_DIR"
fi

cd "$TARGET_DIR"

# Create directory structure
echo -e "${GREEN}Creating directory structure...${NC}"

# Main directories
mkdir -p docs/{templates,guides,examples}
mkdir -p .github/{workflows,ISSUE_TEMPLATE,PULL_REQUEST_TEMPLATE}
mkdir -p examples/{microservices,monolithic,serverless,event-driven}
mkdir -p scripts
mkdir -p assets/diagrams

# Create subdirectories for guides
mkdir -p docs/guides/{implementation,security,monitoring,ci-cd,anti-patterns}

# Create subdirectories for examples
mkdir -p examples/microservices/{architecture,docker,kubernetes}
mkdir -p examples/monolithic/{architecture,deployment}
mkdir -p examples/serverless/{aws,azure,gcp}
mkdir -p examples/event-driven/{kafka,rabbitmq,redis}

echo -e "${GREEN}Directory structure created successfully!${NC}"

# Move/copy markdown files to appropriate locations
echo -e "${GREEN}Organizing documentation files...${NC}"

# Define source files and their destinations
declare -A FILE_MAPPINGS=(
    ["PROJECT_ARCHITECTURE_TEMPLATE.md"]="docs/templates/PROJECT_ARCHITECTURE_TEMPLATE.md"
    ["EXECUTIVE_SUMMARY.md"]="docs/templates/EXECUTIVE_SUMMARY.md"
    ["IMPLEMENTATION_GUIDE.md"]="docs/guides/implementation/IMPLEMENTATION_GUIDE.md"
    ["ANTI_PATTERNS_GUIDE.md"]="docs/guides/anti-patterns/ANTI_PATTERNS_GUIDE.md"
    ["MONITORING_SETUP_GUIDE.md"]="docs/guides/monitoring/MONITORING_SETUP_GUIDE.md"
    ["CI_CD_SETUP_GUIDE.md"]="docs/guides/ci-cd/CI_CD_SETUP_GUIDE.md"
    ["SECURITY_GUIDE.md"]="docs/guides/security/SECURITY_GUIDE.md"
    ["QUICK_START_CHECKLIST.md"]="docs/QUICK_START_CHECKLIST.md"
    ["README_NEW_REPO.md"]="README.md"
)

# Check if we're in the source directory
if [ -f "PROJECT_ARCHITECTURE_TEMPLATE.md" ]; then
    echo -e "${YELLOW}Found source markdown files. Moving to organized structure...${NC}"
    
    for source in "${!FILE_MAPPINGS[@]}"; do
        dest="${FILE_MAPPINGS[$source]}"
        if [ -f "$source" ]; then
            mv "$source" "$dest"
            echo "  Moved: $source -> $dest"
        fi
    done
    
    # Handle the original README separately
    if [ -f "README.md" ] && [ ! -f "docs/ORIGINAL_README.md" ]; then
        mv README.md docs/ORIGINAL_README.md
        echo "  Preserved original README.md -> docs/ORIGINAL_README.md"
    fi
fi

# Create placeholder files for examples
echo -e "${GREEN}Creating example placeholder files...${NC}"

# Microservices example
cat > examples/microservices/README.md << 'EOF'
# Microservices Architecture Example

This directory contains examples of microservices architecture patterns.

## Contents

- `architecture/` - Architecture diagrams and documentation
- `docker/` - Docker compose files and configurations
- `kubernetes/` - Kubernetes manifests and helm charts

## Getting Started

1. Review the architecture documentation
2. Choose the deployment method (Docker or Kubernetes)
3. Follow the setup instructions in the respective directories
EOF

# Monolithic example
cat > examples/monolithic/README.md << 'EOF'
# Monolithic Architecture Example

This directory contains examples of monolithic architecture patterns.

## Contents

- `architecture/` - Architecture diagrams and documentation
- `deployment/` - Deployment configurations and scripts

## Getting Started

1. Review the architecture documentation
2. Follow the deployment guide for your target environment
EOF

# Serverless example
cat > examples/serverless/README.md << 'EOF'
# Serverless Architecture Example

This directory contains examples of serverless architecture patterns.

## Contents

- `aws/` - AWS Lambda and serverless framework examples
- `azure/` - Azure Functions examples
- `gcp/` - Google Cloud Functions examples

## Getting Started

1. Choose your cloud provider
2. Review the provider-specific examples
3. Follow the deployment instructions
EOF

# Event-driven example
cat > examples/event-driven/README.md << 'EOF'
# Event-Driven Architecture Example

This directory contains examples of event-driven architecture patterns.

## Contents

- `kafka/` - Apache Kafka examples
- `rabbitmq/` - RabbitMQ examples
- `redis/` - Redis Pub/Sub examples

## Getting Started

1. Choose your messaging system
2. Review the implementation examples
3. Follow the setup instructions
EOF

# Create example architecture diagram placeholder
cat > examples/microservices/architecture/architecture.md << 'EOF'
# Microservices Architecture

## Overview

This document describes a sample microservices architecture.

## Services

1. **API Gateway** - Entry point for all client requests
2. **User Service** - Handles user authentication and profiles
3. **Product Service** - Manages product catalog
4. **Order Service** - Processes orders
5. **Notification Service** - Sends notifications

## Communication Patterns

- REST APIs for synchronous communication
- Message queues for asynchronous events
- Service mesh for inter-service communication

## Diagram

```mermaid
graph LR
    Client[Client] --> Gateway[API Gateway]
    Gateway --> UserSvc[User Service]
    Gateway --> ProductSvc[Product Service]
    Gateway --> OrderSvc[Order Service]
    OrderSvc --> Queue[Message Queue]
    Queue --> NotifSvc[Notification Service]
```
EOF

# Initialize git repository
if [ ! -d ".git" ]; then
    echo -e "${GREEN}Initializing git repository...${NC}"
    git init
    echo -e "${GREEN}Git repository initialized!${NC}"
else
    echo -e "${YELLOW}Git repository already exists${NC}"
fi

# Create .gitignore
echo -e "${GREEN}Creating .gitignore file...${NC}"
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
vendor/
*.lock
package-lock.json
yarn.lock

# Build outputs
dist/
build/
out/
target/
*.exe
*.dll
*.so
*.dylib

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# Environment files
.env
.env.local
.env.*.local
*.env

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Testing
coverage/
.coverage
*.cover
.hypothesis/
.pytest_cache/
junit.xml

# Temporary files
tmp/
temp/
*.tmp
*.temp
*.bak
*.backup
*.old

# OS files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Python
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
.Python
venv/
env/
pip-log.txt

# Java
*.class
*.jar
*.war
*.ear
*.iml
.gradle/
gradle-app.setting

# .NET
bin/
obj/
*.user
*.userosscache
*.sln.docstates

# Ruby
*.gem
*.rbc
.bundle/
.config
coverage/
spec/reports/
EOF

# Create basic GitHub Actions workflows
echo -e "${GREEN}Setting up GitHub Actions workflows...${NC}"

# Create documentation workflow
cat > .github/workflows/documentation.yml << 'EOF'
name: Documentation

on:
  push:
    branches: [ main ]
    paths:
      - 'docs/**'
      - 'README.md'
  pull_request:
    branches: [ main ]
    paths:
      - 'docs/**'
      - 'README.md'

jobs:
  validate-links:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Validate Markdown links
      uses: gaurav-nelson/github-action-markdown-link-check@v1
      with:
        folder-path: 'docs'
        
  check-spelling:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Check spelling
      uses: streetsidesoftware/cspell-action@v2
      with:
        files: |
          **/*.md
          **/*.txt
EOF

# Create example validation workflow
cat > .github/workflows/validate-examples.yml << 'EOF'
name: Validate Examples

on:
  push:
    branches: [ main ]
    paths:
      - 'examples/**'
  pull_request:
    branches: [ main ]
    paths:
      - 'examples/**'

jobs:
  validate-structure:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Validate example structure
      run: |
        echo "Checking example directories..."
        for dir in examples/*/; do
          if [ -d "$dir" ]; then
            echo "Validating $dir"
            if [ ! -f "$dir/README.md" ]; then
              echo "ERROR: Missing README.md in $dir"
              exit 1
            fi
          fi
        done
        echo "All examples have README files!"
EOF

# Create issue templates
echo -e "${GREEN}Creating issue templates...${NC}"

cat > .github/ISSUE_TEMPLATE/documentation-update.md << 'EOF'
---
name: Documentation Update
about: Suggest improvements or report issues with documentation
title: '[DOCS] '
labels: documentation
assignees: ''
---

## Documentation Section
<!-- Which document or section needs updating? -->

## Current Issue
<!-- Describe what's wrong or missing -->

## Suggested Improvement
<!-- How should it be improved? -->

## Additional Context
<!-- Any other relevant information -->
EOF

cat > .github/ISSUE_TEMPLATE/new-example-request.md << 'EOF'
---
name: New Example Request
about: Request a new architecture example
title: '[EXAMPLE] '
labels: enhancement, example
assignees: ''
---

## Architecture Type
<!-- What type of architecture example are you requesting? -->

## Use Case
<!-- Describe the use case for this example -->

## Technologies
<!-- What technologies should be included? -->

## Additional Requirements
<!-- Any specific requirements or constraints -->
EOF

# Create pull request template
cat > .github/PULL_REQUEST_TEMPLATE/pull_request_template.md << 'EOF'
## Description
<!-- Provide a brief description of your changes -->

## Type of Change
- [ ] Documentation update
- [ ] New example
- [ ] Bug fix
- [ ] Feature enhancement
- [ ] Other (please describe)

## Checklist
- [ ] I have read the contributing guidelines
- [ ] My changes follow the existing style and structure
- [ ] I have tested my changes
- [ ] I have updated relevant documentation
- [ ] All new examples include README files

## Related Issues
<!-- Link any related issues here -->

## Additional Notes
<!-- Any additional information reviewers should know -->
EOF

# Create a simple contributing guide
cat > CONTRIBUTING.md << 'EOF'
# Contributing to Project Architecture Blueprint

Thank you for your interest in contributing! This document provides guidelines for contributing to this repository.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Guidelines

### Documentation
- Keep documentation clear and concise
- Use proper markdown formatting
- Include examples where appropriate
- Check for spelling and grammar

### Examples
- Each example must have a README.md
- Include architecture diagrams when possible
- Provide clear setup instructions
- Test all code examples

### Commit Messages
- Use clear and descriptive commit messages
- Start with a verb (Add, Update, Fix, Remove)
- Keep the first line under 50 characters

## Code of Conduct

Please be respectful and constructive in all interactions.
EOF

# Create a simple script for updating documentation
cat > scripts/update-docs.sh << 'EOF'
#!/bin/bash

# Script to update documentation timestamps and check links

echo "Updating documentation..."

# Find all markdown files and update last modified date
find docs -name "*.md" -type f | while read file; do
    echo "Processing: $file"
    # Add your documentation update logic here
done

echo "Documentation update complete!"
EOF

chmod +x scripts/update-docs.sh

# Final summary
echo ""
echo -e "${BLUE}=== Setup Complete! ===${NC}"
echo ""
echo -e "${GREEN}Repository structure created successfully!${NC}"
echo ""
echo "Next steps:"
echo "1. Review the generated structure"
echo "2. Customize the templates for your organization"
echo "3. Add your specific examples"
echo "4. Commit and push to your repository"
echo ""
echo "Directory structure:"
echo "  docs/           - All documentation"
echo "  examples/       - Architecture examples"
echo "  .github/        - GitHub Actions and templates"
echo "  scripts/        - Utility scripts"
echo ""

# Create a summary file
cat > SETUP_SUMMARY.md << EOF
# Setup Summary

This repository was set up on $(date)

## Structure Created

- **docs/** - Documentation organized by type
  - templates/ - Architecture templates
  - guides/ - Implementation guides
  - examples/ - Example references
  
- **examples/** - Working examples
  - microservices/
  - monolithic/
  - serverless/
  - event-driven/
  
- **.github/** - GitHub configuration
  - workflows/ - CI/CD workflows
  - ISSUE_TEMPLATE/ - Issue templates
  - PULL_REQUEST_TEMPLATE/ - PR template

## Files Created

- .gitignore - Git ignore rules
- CONTRIBUTING.md - Contribution guidelines
- Example README files in each directory
- GitHub Actions workflows
- Issue and PR templates

## Next Steps

1. Customize the templates
2. Add your examples
3. Configure GitHub Actions
4. Start documenting!
EOF

echo -e "${GREEN}Setup summary saved to SETUP_SUMMARY.md${NC}"