# SplitKey Sealer — simulation image (docs/09-platforms-builds-testing.md).
# Build context is the Sealer/ workspace root:
#   docker build -f sim/Dockerfile .

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p sealer-cli -p sealerd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sks /usr/local/bin/sks
COPY --from=build /src/target/release/sealerd /usr/local/bin/sealerd
COPY --from=build /src/target/release/sealer /usr/local/bin/sealer
ENTRYPOINT ["sealerd"]
