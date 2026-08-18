#!/usr/bin/env bash
#
# Rebase the fork's patch series onto an upstream Komodo release.
#
#   ./scripts/tdd/sync-upstream.sh            # newest upstream release tag
#   ./scripts/tdd/sync-upstream.sh v2.4.0     # a specific tag
#
# Produces a branch `tdd/rebase/<tag>` and stops. It does not force-move
# tdd/release/*, does not push, and does not deploy -- promoting a rebase is a
# human decision taken after the verification commands below pass.
set -euo pipefail

PATCHES_BRANCH="tdd/patches"
UPSTREAM_REMOTE="upstream"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '\033[1m==>\033[0m %s\n' "$*"; }

[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit or stash first"
git rev-parse --verify --quiet "$PATCHES_BRANCH" >/dev/null \
  || die "branch '$PATCHES_BRANCH' not found"
git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1 \
  || die "remote '$UPSTREAM_REMOTE' not configured (expected moghtech/komodo)"

note "Fetching $UPSTREAM_REMOTE"
git fetch --tags --quiet "$UPSTREAM_REMOTE"

if [ $# -ge 1 ]; then
  TARGET_TAG="$1"
  git rev-parse --verify --quiet "refs/tags/$TARGET_TAG" >/dev/null \
    || die "tag '$TARGET_TAG' does not exist"
else
  # Newest release tag, excluding upstream's -dev-N prereleases.
  TARGET_TAG="$(git tag -l 'v[0-9]*' --sort=-v:refname | grep -v -- '-dev-' | head -1)"
  [ -n "$TARGET_TAG" ] || die "could not determine the newest upstream release tag"
fi

# The tag the patch series currently sits on: the nearest tag that is an
# ancestor of the series, i.e. the base it was last rebased onto.
BASE_TAG="$(git describe --tags --abbrev=0 --exclude='*-dev-*' "$PATCHES_BRANCH^^^" 2>/dev/null || true)"
[ -n "$BASE_TAG" ] || die "could not determine the current base tag of $PATCHES_BRANCH"

if [ "$BASE_TAG" = "$TARGET_TAG" ]; then
  note "Already based on $TARGET_TAG -- nothing to do."
  exit 0
fi

REBASE_BRANCH="tdd/rebase/$TARGET_TAG"
note "Rebasing $PATCHES_BRANCH from $BASE_TAG onto $TARGET_TAG"
printf '    commits to replay:\n'
git log --oneline "$BASE_TAG..$PATCHES_BRANCH" | sed 's/^/      /'

git branch -f "$REBASE_BRANCH" "$PATCHES_BRANCH"
git checkout --quiet "$REBASE_BRANCH"

if ! git rebase --onto "$TARGET_TAG" "$BASE_TAG"; then
  cat >&2 <<MSG

The rebase stopped on a conflict. Only four upstream files are touched by this
patch series, so see docs/tdd/MAINTENANCE.md ("When a rebase conflicts") for
what each one means.

  resolve, then:  git add <files> && git rebase --continue
  or abandon:     git rebase --abort && git checkout $PATCHES_BRANCH
MSG
  exit 1
fi

note "Rebased cleanly onto $TARGET_TAG (branch: $REBASE_BRANCH)"
cat <<MSG

Verify before promoting -- a clean rebase is not a working build:

  cargo test  -p interpolate -p infisical
  cargo check -p komodo_core -p komodo_periphery

Then promote:

  git branch -f $PATCHES_BRANCH        $REBASE_BRANCH
  git branch -f tdd/release/$TARGET_TAG $REBASE_BRANCH
  git push origin $PATCHES_BRANCH tdd/release/$TARGET_TAG

And record the outcome in the rebase history table in docs/tdd/MAINTENANCE.md.
MSG
