#!/bin/bash
# smoke_test.sh - Run smoke tests against the greywall binary
#
# This script tests the compiled greywall binary to ensure basic functionality works.
# Unlike integration tests (which test internal APIs), smoke tests verify the
# final artifact behaves correctly.
#
# Usage:
#   ./scripts/smoke_test.sh [path-to-greywall-binary]
#
# If no path is provided, it will look for ./greywall or use 'go run'.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
SKIPPED=0

GREYWALL_BIN="${1:-}"
if [[ -z "$GREYWALL_BIN" ]]; then
    if [[ -x "./greywall" ]]; then
        GREYWALL_BIN="./greywall"
    elif [[ -x "./dist/greywall" ]]; then
        GREYWALL_BIN="./dist/greywall"
    else
        echo "Building greywall..."
        go build -o ./greywall ./cmd/greywall
        GREYWALL_BIN="./greywall"
    fi
fi

if [[ ! -x "$GREYWALL_BIN" ]]; then
    echo "Error: greywall binary not found at $GREYWALL_BIN"
    exit 1
fi

echo "Using greywall binary: $GREYWALL_BIN"
echo "=============================================="

# Create temp workspace in current directory (not /tmp, which gets overlaid by bwrap --tmpfs)
WORKSPACE=$(mktemp -d -p .)
trap "rm -rf $WORKSPACE" EXIT

run_test() {
    local name="$1"
    local expected_result="$2"  # "pass" or "fail"
    shift 2
    
    echo -n "Testing: $name... "
    
    # Run command and capture result (use "$@" to preserve argument quoting)
    set +e
    output=$("$@" 2>&1)
    exit_code=$?
    set -e
    
    if [[ "$expected_result" == "pass" ]]; then
        if [[ $exit_code -eq 0 ]]; then
            echo -e "${GREEN}PASS${NC}"
            PASSED=$((PASSED + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC} (expected success, got exit code $exit_code)"
            echo "  Output: ${output:0:200}"
            FAILED=$((FAILED + 1))
            return 1
        fi
    else
        if [[ $exit_code -ne 0 ]]; then
            echo -e "${GREEN}PASS${NC} (correctly failed)"
            PASSED=$((PASSED + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC} (expected failure, but command succeeded)"
            echo "  Output: ${output:0:200}"
            FAILED=$((FAILED + 1))
            return 1
        fi
    fi
}

command_exists() {
    command -v "$1" &> /dev/null
}

skip_test() {
    local name="$1"
    local reason="$2"
    echo -e "Testing: $name... ${YELLOW}SKIPPED${NC} ($reason)"
    SKIPPED=$((SKIPPED + 1))
}

echo ""
echo "=== Basic Functionality ==="
echo ""

# Test: Version flag works
run_test "version flag" "pass" "$GREYWALL_BIN" --version

# Test: Echo works
run_test "echo command" "pass" "$GREYWALL_BIN" -c "echo hello"

# Test: ls works
run_test "ls command" "pass" "$GREYWALL_BIN" -- ls

# Test: pwd works
run_test "pwd command" "pass" "$GREYWALL_BIN" -- pwd

echo ""
echo "=== Filesystem Restrictions ==="
echo ""

# Test: Read existing file works
echo "test content" > "$WORKSPACE/test.txt"
run_test "read file in workspace" "pass" "$GREYWALL_BIN" -c "cat $WORKSPACE/test.txt"

# Test: Write outside workspace blocked
# Create a settings file that only allows write to current workspace
SETTINGS_FILE="$WORKSPACE/greywall.json"
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

# Note: Use /var/tmp since /tmp is mounted as tmpfs (writable but ephemeral) inside the sandbox
OUTSIDE_FILE="/var/tmp/outside-greywall-test-$$.txt"
run_test "write outside workspace blocked" "fail" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "touch $OUTSIDE_FILE"

# Cleanup in case it wasn't blocked
rm -f "$OUTSIDE_FILE" 2>/dev/null || true

# Test: Write inside workspace allowed (using the workspace path in -c)
run_test "write inside workspace allowed" "pass" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "touch $WORKSPACE/new-file.txt"

# Check file was actually created
if [[ -f "$WORKSPACE/new-file.txt" ]]; then
    echo -e "Testing: file actually created... ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "Testing: file actually created... ${RED}FAIL${NC} (file does not exist)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Command Blocking ==="
echo ""

# Create settings with command deny list
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  },
  "command": {
    "deny": ["rm -rf", "dangerous-command"]
  }
}
EOF

# Test: Denied command is blocked
run_test "blocked command (rm -rf)" "fail" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "rm -rf /tmp/test"

# Test: Similar but not blocked command works (rm without -rf)
run_test "allowed command (echo)" "pass" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "echo safe command"

# Test: Chained command with blocked command
run_test "chained blocked command" "fail" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "ls && rm -rf /tmp/test"

# Test: Nested shell with blocked command
run_test "nested shell blocked command" "fail" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c 'bash -c "rm -rf /tmp/test"'

echo ""
echo "=== Network Restrictions ==="
echo ""

# Reset settings to default (network through proxy)
cat > "$SETTINGS_FILE" << EOF
{
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

if command_exists curl; then
    # Test: Network blocked by default - curl should fail or return blocked message
    # Use curl's own timeout (no need for external timeout command)
    output=$("$GREYWALL_BIN" -s "$SETTINGS_FILE" -c "curl -s --connect-timeout 2 --max-time 3 http://example.com" 2>&1) || true
    if echo "$output" | grep -qi "blocked\|refused\|denied\|timeout\|error"; then
        echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    elif [[ -z "$output" ]]; then
        # Empty output is also okay - network was blocked
        echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        # Check if it's actually blocked content vs real response
        if echo "$output" | grep -qi "doctype\|html\|example domain"; then
            echo -e "Testing: network blocked (curl)... ${RED}FAIL${NC} (got actual response)"
            FAILED=$((FAILED + 1))
        else
            echo -e "Testing: network blocked (curl)... ${GREEN}PASS${NC} (no real response)"
            PASSED=$((PASSED + 1))
        fi
    fi
else
    skip_test "network blocked (curl)" "curl not installed"
fi


echo ""
echo "=== Tool Compatibility ==="
echo ""

if command_exists python3; then
    run_test "python3 works" "pass" "$GREYWALL_BIN" -c "python3 -c 'print(1+1)'"
else
    skip_test "python3 works" "python3 not installed"
fi

if command_exists node; then
    run_test "node works" "pass" "$GREYWALL_BIN" -c "node -e 'console.log(1+1)'"
else
    skip_test "node works" "node not installed"
fi

if command_exists git; then
    run_test "git version works" "pass" "$GREYWALL_BIN" -- git --version
else
    skip_test "git version works" "git not installed"
fi

if command_exists rg; then
    run_test "ripgrep works" "pass" "$GREYWALL_BIN" -- rg --version
else
    skip_test "ripgrep works" "rg not installed"
fi

echo ""
echo "=== Environment ==="
echo ""

# Test: GREYWALL_SANDBOX env var is set
run_test "GREYWALL_SANDBOX set" "pass" "$GREYWALL_BIN" -c 'test "$GREYWALL_SANDBOX" = "1"'

# Test: Proxy env vars are set when network is configured
cat > "$SETTINGS_FILE" << EOF
{
  "network": {
    "proxyUrl": "socks5://localhost:43052"
  },
  "filesystem": {
    "allowWrite": ["$WORKSPACE"]
  }
}
EOF

run_test "HTTP_PROXY set" "pass" "$GREYWALL_BIN" -s "$SETTINGS_FILE" -c 'test -n "$HTTP_PROXY"'

echo ""
echo "=============================================="
echo ""
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
echo ""
