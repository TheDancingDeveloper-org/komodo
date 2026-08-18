## Builds ONLY the Komodo Core image for this fork.
##
## Scope is deliberately narrow (see docs/tdd/DEPLOYMENT.md):
##   - Secret interpolation happens entirely in Core, so Periphery is NOT
##     rebuilt. Every Periphery in the estate keeps running the stock upstream
##     image, which also keeps the blast radius of this fork to one container.
##   - The UI is pulled from the version-matched upstream image rather than
##     rebuilt from source. It is byte-identical to what upstream ships for
##     this release and this fork does not touch it.
##
## Compared with the upstream two-step path (bin/binaries.Dockerfile then
## bin/core/single-arch.Dockerfile) this skips the Periphery binary and the
## Node/yarn UI build, which matters because the Docker daemon this builds on
## is Node B's own and its root disk is the estate's tightest resource.

ARG KOMODO_VERSION=2.2.0
ARG UI_IMAGE=ghcr.io/moghtech/komodo-ui:${KOMODO_VERSION}

FROM rust:1.95.0-bookworm AS builder
RUN cargo install cargo-strip
WORKDIR /builder

# The whole workspace must be present for Cargo to resolve members, even
# though only komodo_core and komodo_cli are built below.
COPY Cargo.toml Cargo.lock ./
COPY ./lib ./lib
COPY ./client/core/rs ./client/core/rs
COPY ./client/periphery ./client/periphery
COPY ./bin/core ./bin/core
COPY ./bin/periphery ./bin/periphery
COPY ./bin/cli ./bin/cli
COPY ./xtask ./xtask

# `km` is shipped in the upstream Core image and referenced by the
# KOMODO_CLI_CONFIG_* environment below, so it is built to keep this image's
# contract identical to upstream's. komodo_periphery is deliberately absent.
RUN cargo build -p komodo_core -p komodo_cli --release && cargo strip

FROM ${UI_IMAGE} AS ui

FROM debian:trixie-slim

COPY ./bin/core/starship.toml /starship.toml
COPY ./bin/core/debian-deps.sh .
RUN sh ./debian-deps.sh && rm ./debian-deps.sh

COPY ./config/core.config.toml /config/.default.config.toml
COPY --from=ui /ui /app/ui
COPY --from=builder /builder/target/release/core /usr/local/bin/core
COPY --from=builder /builder/target/release/km /usr/local/bin/km
COPY --from=denoland/deno:bin /deno /usr/local/bin/deno

ENV DENO_DIR=/action-cache/deno
RUN mkdir /action-cache && \
	cd /action-cache && \
	deno install jsr:@std/yaml jsr:@std/toml

COPY ./bin/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9120

ENV KOMODO_CLI_CONFIG_PATHS="/config"
ENV KOMODO_CLI_CONFIG_KEYWORDS="*config.*,*komodo.cli*.*"

ENTRYPOINT [ "entrypoint.sh" ]
CMD [ "core" ]

# Label to prevent Komodo from stopping this container with StopAllContainers
LABEL komodo.skip="true"
LABEL org.opencontainers.image.description="Komodo Core with Infisical secret provider"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/TheDancingDeveloper-org/komodo"
