#!/bin/bash
# Test runner script

set -euo pipefail

echo "Blockchain Core Test Suite"
echo "========================="

# Check if blockchain_core is built
if ! python -c "import blockchain_core" 2>/dev/null; then
    echo "ERROR: blockchain_core not found. Please build first:"
    echo "  ./build_arch.sh --build"
    exit 1
fi

# Run basic tests
echo "Running basic tests..."
python tests/test_basic.py

# Run performance test if available
if [[ -f "tests/test_performance.py" ]]; then
    echo -e "\nRunning performance tests..."
    python tests/test_performance.py
fi

echo -e "\nTest suite completed!"
