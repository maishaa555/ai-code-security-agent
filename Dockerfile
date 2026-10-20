# Build stage using Rust
FROM rust:1.80-slim as builder

WORKDIR /app
COPY . .

# Install build dependencies including pkg-config and libssl-dev
RUN apt-get update && apt-get install -y gcc g++ make curl pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Constrain parallel jobs to prevent OOM in low-memory container builds (e.g. Render Free Tier)
ENV CARGO_BUILD_JOBS=1
ENV RUSTFLAGS="-C codegen-units=1"

# Build binary
RUN cargo build --release --bin secscan-server

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
