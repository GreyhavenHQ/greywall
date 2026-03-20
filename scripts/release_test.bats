#!/usr/bin/env bats
#
# Tests for scripts/bump_version.sh version-bumping logic.
#
# Requirements:
#   brew install bats-core
#
# Run:
#   bats scripts/release_test.bats

# shellcheck source=scripts/bump_version.sh
source "$BATS_TEST_DIRNAME/bump_version.sh"

setup() {
    TEST_DIR=$(mktemp -d)
    cd "$TEST_DIR"
    git -c init.defaultBranch=main init -q
    git config user.email "test@example.com"
    git config user.name "Test"
    git commit --allow-empty -m "initial commit" -q
}

teardown() {
    rm -rf "$TEST_DIR"
}

# =============================================================================
# Input validation
# =============================================================================

@test "rejects invalid bump type" {
    run bump_version "" "foobar"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Invalid bump type"* ]]
}

# =============================================================================
# No existing tags
# =============================================================================

@test "patch with no tags starts at v0.1.0" {
    result=$(bump_version "" "patch")
    [ "$result" = "v0.1.0" ]
}

@test "minor with no tags starts at v0.1.0" {
    result=$(bump_version "" "minor")
    [ "$result" = "v0.1.0" ]
}

@test "beta with no tags starts at v0.1.0-beta.1" {
    result=$(bump_version "" "beta")
    [ "$result" = "v0.1.0-beta.1" ]
}

# =============================================================================
# Patch bumps
# =============================================================================

@test "patch increments patch version" {
    git tag v0.3.0
    result=$(bump_version "v0.3.0" "patch")
    [ "$result" = "v0.3.1" ]
}

@test "patch increments from higher patch number" {
    git tag v0.3.9
    result=$(bump_version "v0.3.9" "patch")
    [ "$result" = "v0.3.10" ]
}

@test "patch strips pre-release suffix from last tag" {
    git tag v0.3.0
    git commit --allow-empty -m "beta work" -q
    git tag v0.3.1-beta.2
    result=$(bump_version "v0.3.1-beta.2" "patch")
    [ "$result" = "v0.3.2" ]
}

# =============================================================================
# Minor bumps
# =============================================================================

@test "minor increments minor and resets patch to zero" {
    result=$(bump_version "v0.3.2" "minor")
    [ "$result" = "v0.4.0" ]
}

@test "minor increments from v1.2.9" {
    result=$(bump_version "v1.2.9" "minor")
    [ "$result" = "v1.3.0" ]
}

# =============================================================================
# Beta bumps
# =============================================================================

@test "beta from stable tag produces beta.1 of next patch" {
    git tag v0.3.0
    result=$(bump_version "v0.3.0" "beta")
    [ "$result" = "v0.3.1-beta.1" ]
}

@test "beta auto-increments to beta.2 when beta.1 exists" {
    git tag v0.3.0
    git tag v0.3.1-beta.1
    result=$(bump_version "v0.3.0" "beta")
    [ "$result" = "v0.3.1-beta.2" ]
}

@test "beta auto-increments to beta.3 when beta.1 and beta.2 exist" {
    git tag v0.3.0
    git tag v0.3.1-beta.1
    git tag v0.3.1-beta.2
    result=$(bump_version "v0.3.0" "beta")
    [ "$result" = "v0.3.1-beta.3" ]
}

@test "beta uses stable tag as base, not the latest beta tag" {
    git tag v0.2.0
    git tag v0.3.1-beta.1
    # Base is v0.2.0 → next patch is v0.2.1, so beta is v0.2.1-beta.1
    result=$(bump_version "v0.2.0" "beta")
    [ "$result" = "v0.2.1-beta.1" ]
}
