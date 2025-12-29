#!/bin/bash
set -euo pipefail

# Only run in Claude Code remote/web environments
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# Install Node.js dependencies if package.json exists
if [ -f "package.json" ]; then
  echo "Installing Node.js dependencies..."
  npm install
fi

# Install Python dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
  echo "Installing Python dependencies..."
  pip install -r requirements.txt
fi

# Install Python dependencies if pyproject.toml exists (Poetry/pip)
if [ -f "pyproject.toml" ]; then
  if command -v poetry &> /dev/null && grep -q "\[tool.poetry\]" pyproject.toml; then
    echo "Installing Python dependencies with Poetry..."
    poetry install
  else
    echo "Installing Python dependencies with pip..."
    pip install -e .
  fi
fi

# Install Go dependencies if go.mod exists
if [ -f "go.mod" ]; then
  echo "Installing Go dependencies..."
  go mod download
fi

# Install Rust dependencies if Cargo.toml exists
if [ -f "Cargo.toml" ]; then
  echo "Installing Rust dependencies..."
  cargo fetch
fi

# Install Ruby dependencies if Gemfile exists
if [ -f "Gemfile" ]; then
  echo "Installing Ruby dependencies..."
  bundle install
fi

echo "Session start hook completed successfully"
