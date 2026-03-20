#!/usr/bin/env bash
# bump_version <last_tag> <bump_type>
#
# Calculates and prints the next version string.
# Reads local git tags for beta numbering; requires no remote.
#
# Arguments:
#   last_tag   — current latest tag (e.g. "v0.3.0"), or "" if none
#   bump_type  — "patch", "minor", or "beta"
#
# Output: new version string on stdout (e.g. "v0.3.1")
# Info messages go to stderr so callers can capture stdout cleanly.

bump_version() {
    local last_tag="$1"
    local bump_type="$2"

    if [[ "$bump_type" != "patch" && "$bump_type" != "minor" && "$bump_type" != "beta" ]]; then
        echo "Invalid bump type: $bump_type. Use 'patch', 'minor', or 'beta'." >&2
        return 1
    fi

    if [[ -z "$last_tag" ]]; then
        local new_version
        if [[ "$bump_type" == "beta" ]]; then
            new_version="v0.1.0-beta.1"
        else
            new_version="v0.1.0"
        fi
        echo "$new_version"
        echo "No existing tags found. Starting at $new_version" >&2
        return
    fi

    if [[ "$bump_type" == "beta" ]]; then
        local last_stable_tag
        last_stable_tag=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -v '\-' | sort -V | tail -1 || true)
        if [[ -z "$last_stable_tag" ]]; then
            last_stable_tag="v0.0.0"
        fi
        local version="${last_stable_tag#v}"
        local major minor patch
        IFS='.' read -r major minor patch <<< "$version"
        patch=$((patch + 1))
        local base_version="${major}.${minor}.${patch}"
        local latest_beta
        latest_beta=$(git tag -l "v${base_version}-beta.*" | sort -V | tail -1 || true)
        local beta_num
        if [[ -z "$latest_beta" ]]; then
            beta_num=1
        else
            beta_num=$(echo "$latest_beta" | sed 's/.*-beta\.\([0-9]*\)$/\1/')
            beta_num=$((beta_num + 1))
        fi
        local new_version="v${base_version}-beta.${beta_num}"
        echo "$new_version"
        echo "Beta tag: $last_stable_tag → $new_version" >&2
    else
        local version="${last_tag#v}"
        version="${version%%-*}"  # strip pre-release suffix if present
        local major minor patch
        IFS='.' read -r major minor patch <<< "$version"

        if [[ -z "$major" || -z "$minor" || -z "$patch" ]]; then
            echo "Failed to parse version from tag: $last_tag" >&2
            return 1
        fi

        case "$bump_type" in
            patch) patch=$((patch + 1)) ;;
            minor) minor=$((minor + 1)); patch=0 ;;
        esac

        local new_version="v${major}.${minor}.${patch}"
        echo "$new_version"
        echo "Version bump: $last_tag → $new_version" >&2
    fi
}
