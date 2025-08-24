FROM rust:1.85-alpine AS chef
USER root
RUN apk add --no-cache musl-dev & cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin app-service

FROM debian:bookworm-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/app-service /usr/local/bin
# Copy from builder stage, not from local filesystem
COPY --from=builder /app/app-service/assets /app/assets
ENV AUTH_SERVICE_HOST_NAME=auth-service
ENTRYPOINT ["/usr/local/bin/app-service"]
