#!/usr/bin/env bash
#
# Build the Komodo Core image for this fork -- and only that image.
#
#   ./scripts/tdd/build-core-image.sh                 # build + tag
#   ./scripts/tdd/build-core-image.sh --push          # also push to the registry
#
# Periphery is deliberately not built: secret interpolation happens entirely in
# Core, so every Periphery in the estate keeps running the stock upstream
# image. See docs/tdd/DEPLOYMENT.md.
set -euo pipefail

cd "$(dirname "$0")/../.."

REGISTRY="${REGISTRY:-repo.indexarr.net/indexarr}"
IMAGE_NAME="${IMAGE_NAME:-komodo-core-infisical}"
PATCH_LEVEL="${PATCH_LEVEL:-1}"
PUSH=0
[ "${1:-}" = "--push" ] && PUSH=1

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# Upstream version this fork is currently based on.
KOMODO_VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
[ -n "$KOMODO_VERSION" ] || die "could not read the workspace version from Cargo.toml"

TAG="${KOMODO_VERSION}-infisical.${PATCH_LEVEL}"
LOCAL_REF="${IMAGE_NAME}:${TAG}"
REMOTE_REF="${REGISTRY}/${IMAGE_NAME}:${TAG}"
GIT_SHA="$(git rev-parse --short HEAD)"

note "Building Komodo Core ${KOMODO_VERSION} + Infisical provider"
printf '    local  : %s\n    remote : %s\n    commit : %s\n    ui     : ghcr.io/moghtech/komodo-ui:%s (upstream, unmodified)\n\n' \
  "$LOCAL_REF" "$REMOTE_REF" "$GIT_SHA" "$KOMODO_VERSION"

# The daemon's disk is shared with every running stack on Node B, so refuse to
# start a multi-gigabyte build that could tip it over.
#
# The daemon is frequently remote from this shell -- inside MyDevEnv2 only the
# socket is mounted, not the data directory -- so the path may not be stat-able
# here. Treat "cannot determine" as a warning rather than a failure, and never
# let the probe itself abort the script under `set -e`/`pipefail`.
DOCKER_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
AVAIL_GB=""
if [ -n "$DOCKER_ROOT" ] && [ -d "$DOCKER_ROOT" ]; then
  AVAIL_GB="$(df -BG --output=avail "$DOCKER_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9' || true)"
fi

if [ -n "$AVAIL_GB" ]; then
  [ "$AVAIL_GB" -ge 40 ] \
    || die "only ${AVAIL_GB}G free on the docker root disk; refusing to build (need ~40G headroom)"
  note "Docker root disk: ${AVAIL_GB}G free"
else
  note "Could not measure free space on the docker root disk (${DOCKER_ROOT:-unknown});" \
       "check it has ~40G headroom before continuing."
fi

docker build \
  --file scripts/tdd/core-only.Dockerfile \
  --build-arg "KOMODO_VERSION=${KOMODO_VERSION}" \
  --label "org.opencontainers.image.revision=${GIT_SHA}" \
  --label "org.opencontainers.image.version=${TAG}" \
  --tag "$LOCAL_REF" \
  --tag "$REMOTE_REF" \
  .

note "Built $LOCAL_REF"
docker image inspect "$LOCAL_REF" --format '    size: {{.Size}} bytes / arch: {{.Architecture}} / created: {{.Created}}'

if [ "$PUSH" = "1" ]; then
  note "Pushing $REMOTE_REF"
  docker push "$REMOTE_REF"
fi

cat <<MSG

Reclaim the build cache when you are done -- this daemon is Node B's:

  docker builder prune -f

MSG
