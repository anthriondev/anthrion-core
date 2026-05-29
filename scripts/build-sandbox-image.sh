#!/usr/bin/env bash
#
# Build the scan-engine sandbox image (T3.2, Part A).
#
# The worker runs each scan in a throwaway container created from this image
# (ARCHITECTURE.md §5). Build it ONCE; the worker reuses it for every scan. Rebuild
# when scan-engine, sandbox-runtime, or the pinned Playwright version changes.
#
# Usage:
#   scripts/build-sandbox-image.sh            # tags anthrion-scan-runtime:latest + :1.60.0
#   SANDBOX_IMAGE=myrepo/scan:tag scripts/build-sandbox-image.sh
#
# Must be run from the repo root (the build context is the monorepo root).

set -euo pipefail

# Keep this in sync with packages/scan-engine "playwright" version + the Dockerfile base.
PLAYWRIGHT_VERSION="1.60.0"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${SANDBOX_IMAGE:-anthrion-scan-runtime:latest}"
VERSION_TAG="anthrion-scan-runtime:${PLAYWRIGHT_VERSION}"

echo "Building scan-runtime image:"
echo "  context : $REPO_ROOT"
echo "  tags    : $IMAGE , $VERSION_TAG"

docker build \
  -f packages/sandbox-runtime/Dockerfile \
  -t "$IMAGE" \
  -t "$VERSION_TAG" \
  "$REPO_ROOT"

echo "Done. Images:"
docker image ls --filter "reference=anthrion-scan-runtime"
