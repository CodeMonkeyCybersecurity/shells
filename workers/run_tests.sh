#!/usr/bin/env bash
#
# Run Python worker unit tests
#
# Usage:
#   ./workers/run_tests.sh              # Run all tests
#   ./workers/run_tests.sh --cov        # Run with coverage report
#   ./workers/run_tests.sh -k test_name # Run specific test

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Python Worker Unit Tests"
echo "=========================================="
echo ""

# Check if pytest is installed
if ! python3 -c "import pytest" 2>/dev/null; then
    echo "Installing test dependencies..."
    pip install -q pytest pytest-asyncio pytest-mock pytest-cov
fi

# Run tests
if [[ "$*" == *"--cov"* ]]; then
    echo "Running tests with coverage..."
    pytest tests/ \
        --cov=service \
        --cov-report=term-missing \
        --cov-report=html \
        "$@"

    echo ""
    echo "Coverage report generated: workers/htmlcov/index.html"
else
    pytest tests/ "$@"
fi

echo ""
echo "=========================================="
echo "Tests completed"
echo "=========================================="
