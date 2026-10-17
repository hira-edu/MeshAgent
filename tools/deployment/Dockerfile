# The image digest pins Node and the OS. Update it through a reviewed change.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pefile make g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/meshcentral
COPY MeshCentral/package.json MeshCentral/package-lock.json ./
RUN chown node:node .
USER node
RUN npm ci --omit=dev --no-audit --no-fund
USER root
COPY MeshCentral /inputs/MeshCentral
COPY MeshAgent/deploy.py /inputs/MeshAgent/deploy.py
COPY MeshAgent/tools/configure_agent_certificate_history.js /inputs/MeshAgent/tools/configure_agent_certificate_history.js
COPY MeshAgent/tools/prepare_release_image.py /inputs/MeshAgent/tools/prepare_release_image.py
COPY artifacts /inputs/artifacts
RUN python3 /inputs/MeshAgent/tools/prepare_release_image.py \
    && node --check node_modules/meshcentral/meshcentral.js \
    && node --check node_modules/meshcentral/meshagent.js \
    && node --check node_modules/meshcentral/meshrelay.js

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
ENV NODE_ENV=production
WORKDIR /opt/meshcentral
COPY --from=build /opt/meshcentral /opt/meshcentral
USER node
ENTRYPOINT ["node", "/opt/meshcentral/node_modules/meshcentral/meshcentral.js"]
CMD ["--datapath", "/opt/meshcentral/meshcentral-data", "--filespath", "/opt/meshcentral/meshcentral-files"]
