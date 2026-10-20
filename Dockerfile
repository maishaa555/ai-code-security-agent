# Build stage using latest stable Rust
FROM rust:latest as builder

WORKDIR /app
COPY . .

# Install essential build tools, pkg-config, and OpenSSL headers
RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev curl && rm -rf /var/lib/apt/lists/*

# Strict single-job memory limit to prevent OOM in Render Free Tier
ENV CARGO_BUILD_JOBS=1
ENV RUSTFLAGS="-C codegen-units=1"

# Build binary
RUN cargo build --release -j 1 --bin secscan-server

# Runtime stage
FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /app/target/release/secscan-server /usr/local/bin/secscan-server
COPY test-corpus /app/test-corpus

# Install test dependencies for vulnerable corpus
RUN pip install --no-cache-dir flask requests urllib3

EXPOSE 3000

ENV PORT=3000
ENV RUST_LOG=info
CMD ["secscan-server"]
