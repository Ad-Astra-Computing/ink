# TypeScript side of the INK interop lab: the reference receiver, the lab peer
# and the lab driver, all bundled against the TypeScript sources in this
# repository rather than a published package.
#
# Build context is the repository root:
#
#   docker build -f interop-lab/ts/Dockerfile -t ink-interop-lab-ts .
#
# The base image is pinned by digest so a rebuild resolves the same bytes.

FROM docker.io/library/node:24-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build
WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY examples/reference-receiver/src ./examples/reference-receiver/src
COPY examples/docker-receiver/server.mjs ./examples/docker-receiver/server.mjs
COPY interop-lab/ts ./interop-lab/ts

WORKDIR /build/interop-lab/ts
RUN npm ci --ignore-scripts && node build.mjs

FROM docker.io/library/node:24-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS runtime
WORKDIR /app

# The bundles inline the library and the example sources, so the runtime image
# carries no node_modules at all.
COPY --from=build /build/interop-lab/ts/dist ./dist
COPY --from=build /build/examples/docker-receiver/server.mjs ./server.mjs
COPY --from=build /build/interop-lab/ts/receiver-entrypoint.sh ./receiver-entrypoint.sh
RUN chmod +x /app/receiver-entrypoint.sh

ENV HOST=0.0.0.0
USER node
CMD ["node", "/app/dist/peer.mjs"]
