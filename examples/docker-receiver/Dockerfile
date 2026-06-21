# Dockerized INK reference receiver.
#
# Build context is the examples/ directory (the parent), because the build
# bundles the sibling reference-receiver. Build from the repo root with:
#
#   docker build -f examples/docker-receiver/Dockerfile -t ink-receiver examples
#
# or just use the compose file in this directory, which sets the context.

# ---- build stage: install deps and esbuild-bundle the receiver -------------
FROM node:24-slim AS build
WORKDIR /app/docker-receiver
COPY docker-receiver/package.json docker-receiver/package-lock.json* ./
RUN npm ci
WORKDIR /app
COPY reference-receiver ./reference-receiver
COPY docker-receiver ./docker-receiver
RUN cd docker-receiver && node build.mjs

# ---- runtime stage: just Node + the self-contained bundle ------------------
# The bundle inlines @adastracomputing/ink and the receiver, so the runtime
# image carries no node_modules at all.
FROM node:24-slim AS runtime
WORKDIR /app
COPY --from=build /app/docker-receiver/dist ./dist
COPY --from=build /app/docker-receiver/server.mjs ./server.mjs
ENV PORT=8787 HOST=0.0.0.0
EXPOSE 8787
USER node
CMD ["node", "server.mjs"]
