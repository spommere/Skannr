#!/usr/bin/env bash
#
# Prepare and publish a Skannr source release from the current Git checkout.
#
# The script intentionally stages through Git instead of copying files by hand:
# .gitignore remains the authority for excluding generated state, but the
# staging command also excludes the high-risk local paths directly so Git does
# not try to descend into root-owned runtime/log directories.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

usage() {
    cat <<'EOF'
Usage:
  scripts/release.sh [version|patch|minor|major] [--all|--files <paths...>]
                     [--no-push] [--archive-dir <dir>]

Examples:
  scripts/release.sh 0.1.1
  scripts/release.sh patch --all
  scripts/release.sh 0.2.1 --files README.md VERSION src/skannr/main.py

If no version is supplied, the script prompts for one.
If no file mode is supplied, the script prompts and defaults to --all.
EOF
}

die() {
    echo "release.sh: $*" >&2
    exit 1
}

current_version() {
    tr -d '[:space:]' < "$repo_dir/VERSION"
}

validate_version() {
    case "$1" in
        [0-9]*.[0-9]*.[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

increment_version() {
    local bump=$1
    local current major minor patch

    current=$(current_version)
    validate_version "$current" || die "VERSION is not semantic: $current"

    IFS=. read -r major minor patch <<EOF
$current
EOF

    case "$bump" in
        patch) patch=$((patch + 1)) ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        *) die "unknown bump type: $bump" ;;
    esac

    printf '%s.%s.%s\n' "$major" "$minor" "$patch"
}

version_arg=""
push_release=1
archive_dir="$repo_dir/.."
stage_mode=""
declare -a stage_files=()
declare -a local_only_paths=("config" "runtime" "logs" "pcaps" ".venv" "crtar.sh")

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --all)
            stage_mode="all"
            shift
            ;;
        --files)
            stage_mode="files"
            shift
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --*) break ;;
                    *) stage_files+=("$1"); shift ;;
                esac
            done
            ;;
        --no-push)
            push_release=0
            shift
            ;;
        --archive-dir)
            [ "$#" -ge 2 ] || die "--archive-dir requires a directory"
            archive_dir=$2
            shift 2
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [ -z "$version_arg" ] || die "version supplied more than once"
            version_arg=$1
            shift
            ;;
    esac
done

cd "$repo_dir"

git_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    die "$repo_dir is not an initialized Git repository"
}
[ "$git_root" = "$repo_dir" ] || die "run from repo root: $git_root"

tracked_local_paths=()
while IFS= read -r tracked_path; do
    tracked_local_paths+=("$tracked_path")
done < <(git ls-files -- "${local_only_paths[@]}")

if [ "${#tracked_local_paths[@]}" -gt 0 ]; then
    {
        echo "release.sh: local-only paths are tracked and must be removed from Git:"
        printf '  %s\n' "${tracked_local_paths[@]}"
        echo
        echo "Run this once in the real Git checkout, then commit the removal:"
        printf '  git rm -r --cached --'
        printf ' %q' "${local_only_paths[@]}"
        printf '\n'
    } >&2
    exit 1
fi

if [ -z "$version_arg" ]; then
    printf 'Version, or patch/minor/major [%s]: ' "$(current_version)"
    read -r version_arg
fi

if [ -z "$version_arg" ]; then
    version=$(current_version)
elif [ "$version_arg" = "patch" ] ||
     [ "$version_arg" = "minor" ] ||
     [ "$version_arg" = "major" ]; then
    version=$(increment_version "$version_arg")
else
    version=$version_arg
fi

validate_version "$version" || {
    die "version must look like MAJOR.MINOR.PATCH, got: $version"
}

printf '%s\n' "$version" > VERSION
echo "Set VERSION to $version"

if [ -z "$stage_mode" ]; then
    printf 'Files to stage [all]: '
    read -r answer
    if [ -z "$answer" ] || [ "$answer" = "all" ]; then
        stage_mode="all"
    else
        stage_mode="files"
        # shellcheck disable=SC2206
        stage_files=($answer)
    fi
fi

if [ "$stage_mode" = "all" ]; then
    git add -A -- .
    #git add -A -- . \
        #':!.venv' \
        #':!config' \
        #':!runtime' \
        #':!logs' \
        #':!pcaps' \
        #':!crtar.sh'
else
    [ "${#stage_files[@]}" -gt 0 ] || die "--files needs at least one path"
    for local_path in "${local_only_paths[@]}"; do
        for stage_file in "${stage_files[@]}"; do
            case "$stage_file" in
                "$local_path"|"./$local_path"|"$local_path"/*|"./$local_path"/*)
                    die "$local_path is local-only and must not be staged"
                    ;;
            esac
        done
    done
    git add -- VERSION "${stage_files[@]}"
fi

git diff --cached --quiet && die "nothing is staged for commit"

default_message="Release $version"
printf 'Commit message [%s]: ' "$default_message"
read -r commit_message
commit_message=${commit_message:-$default_message}

git commit -m "$commit_message"

branch=$(git branch --show-current)
[ -n "$branch" ] || die "current Git branch could not be determined"

if [ "$push_release" -eq 1 ]; then
    git push origin "$branch"
else
    echo "Skipping git push because --no-push was supplied"
fi

mkdir -p "$archive_dir"
archive_path="$archive_dir/skannr-$version.tar.gz"
git archive \
    --format=tar.gz \
    --prefix="skannr-$version/" \
    -o "$archive_path" \
    HEAD

echo "Created $archive_path"
