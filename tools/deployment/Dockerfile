# MeshCentral release image: the fork package installed from its own tarball, nothing else (Stage 4, D11).
#
# Build context root (Dockerfile.dockerignore sends only these):
#   MeshCentral/    a full clone of the fork at the release commit, with its .git and complete history
#                   (pack.js packs only tracked files and dates agent modules from git history)
#   MeshAgent/tools/deployment/release_image.js
#   agent-builds/   the pinned fork agent builds, as `agent_build_release.py fetch --output agent-builds` wrote them
#
# node:24.22.1-bookworm-slim, pinned by its multi-platform index digest (D1: production runs Node 24).
# Change it only through a reviewed change.
FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
# pack.js reads the tracked tree and its history with git.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /build /opt/meshcentral && chown node:node /build /opt/meshcentral
COPY --chown=node:node MeshCentral /build/MeshCentral
COPY --chown=node:node agent-builds /build/agent-builds
COPY --chown=node:node MeshAgent/tools/deployment/release_image.js /build/release_image.js
USER node
# D4: the release pack runs on Linux. pack.js stages the pinned agents from agent-builds/ only when each
# matches its size and SHA384 pin, packs, and checks the packed bytes; release_image.js then requires
# the tarball to be the one deploy/package-lock.json pins (T21).
RUN node /build/MeshCentral/deploy/scripts/pack.js --agents /build/agent-builds --json > /build/pack-record.txt \
    && node /build/release_image.js verify-pack --meshcentral /build/MeshCentral --pack-record /build/pack-record.txt
WORKDIR /opt/meshcentral
# npm ci installs exactly the lock: the fork tarball (its sha512 is pinned) and the production dependencies.
# The daemon marker keeps self-update off (D6, PRD-11). release_image.js checks the installed tree and
# writes the release manifest.
RUN mkdir dist \
    && cp /build/MeshCentral/deploy/package.json /build/MeshCentral/deploy/package-lock.json . \
    && cp /build/MeshCentral/deploy/dist/meshcentral-*.tgz dist/ \
    && npm ci --omit=dev --no-audit --no-fund \
    && rm -r dist \
    && touch node_modules/meshcentral/daemon \
    && node /build/release_image.js manifest --meshcentral /build/MeshCentral --pack-record /build/pack-record.txt \
        --install /opt/meshcentral --out /opt/meshcentral/release/manifest.json

FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
ENV NODE_ENV=production
WORKDIR /opt/meshcentral
# Root-owned: the service account reads the package but cannot change it.
COPY --from=build --chown=root:root /opt/meshcentral /opt/meshcentral
USER node
ENTRYPOINT ["node", "/opt/meshcentral/node_modules/meshcentral/meshcentral.js"]
CMD ["--datapath", "/opt/meshcentral/meshcentral-data", "--filespath", "/opt/meshcentral/meshcentral-files"]
