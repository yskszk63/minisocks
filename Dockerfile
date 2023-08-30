FROM rust:1.72-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock .
RUN cargo fetch --locked
COPY src/ src/
RUN cargo install --path .

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/minisocks /app
CMD ["/app"]
