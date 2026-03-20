#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh [patch|minor|beta]
# Default: patch

BUMP_TYPE="${1:-patch}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

DRY_RUN="${DRY_RUN:-0}"

# shellcheck source=scripts/bump_version.sh
source "$(dirname "$0")/bump_version.sh"

info "Bump type: $BUMP_TYPE"

# =============================================================================
# Preflight checks
# =============================================================================

info "Running preflight checks..."

# Check we're in a git repository
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    error "Not in a git repository"
fi

# Check we're on the default branch (main)
DEFAULT_BRANCH="main"
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]]; then
    error "Not on default branch. Current: $CURRENT_BRANCH, Expected: $DEFAULT_BRANCH"
fi

# Check for uncommitted changes
if ! git diff --quiet || ! git diff --staged --quiet; then
    error "Working directory has uncommitted changes. Commit or stash them first."
fi

# Check for untracked files (warning only)
UNTRACKED=$(git ls-files --others --exclude-standard)
if [[ -n "$UNTRACKED" ]]; then
    warn "Untracked files present (continuing anyway):"
    echo "$UNTRACKED" | head -5
fi

# Fetch latest from remote
info "Fetching latest from origin..."
git fetch origin "$DEFAULT_BRANCH" --tags

# Check if local branch is up to date with remote
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse "origin/$DEFAULT_BRANCH")
if [[ "$LOCAL_COMMIT" != "$REMOTE_COMMIT" ]]; then
    error "Local branch is not up to date with origin/$DEFAULT_BRANCH. Run 'git pull' first."
fi

# Check if there are commits since last tag
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$LAST_TAG" ]]; then
    COMMITS_SINCE_TAG=$(git rev-list "$LAST_TAG"..HEAD --count)
    if [[ "$COMMITS_SINCE_TAG" -eq 0 ]]; then
        error "No commits since last tag ($LAST_TAG). Nothing to release."
    fi
    info "Commits since $LAST_TAG: $COMMITS_SINCE_TAG"
fi

# Check that tests pass
info "Running tests..."
if ! make test-ci; then
    error "Tests failed. Fix them before releasing."
fi

# Check that lint passes
info "Running linter..."
if ! make lint; then
    error "Lint failed. Fix issues before releasing."
fi

info "✓ All preflight checks passed"

# =============================================================================
# Calculate new version
# =============================================================================

NEW_VERSION=$(bump_version "$LAST_TAG" "$BUMP_TYPE")

if [[ "$DRY_RUN" == "1" ]]; then
    info "Dry run: would release $NEW_VERSION"
    exit 0
fi

# =============================================================================
# Confirm and create tag
# =============================================================================

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Ready to release: $NEW_VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Create and push tag $NEW_VERSION? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Aborted."
    exit 0
fi

# Create annotated tag
info "Creating tag $NEW_VERSION..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

# Push tag to origin
info "Pushing tag to origin..."
git push origin "$NEW_VERSION"

echo ""
info "✓ Released $NEW_VERSION"
info "GitHub Actions will now build and publish the release."
info "Watch progress at: https://github.com/GreyhavenHQ/greywall/actions"
