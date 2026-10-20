# Build stage using Rust
FROM rust:1.80-slim as builder

WORKDIR /app
COPY . .

# Install build dependencies
RUN apt-get update && apt-get install -y gcc g++ make curl && rm -rf /var/lib/apt/lists/*

# Build binary
RUN cargo build --release --bin secscan-server

# Runtime stage
FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /app/target/release/secscan-server /usr/local/bin/secscan-server
COPY test-corpus /app/test-corpus

# Install test dependencies for vulnerable corpus
RUN pip install flask requests urllib3

EXPOSE 3000

ENV RUST_LOG=info
CMD ["secscan-server"]
