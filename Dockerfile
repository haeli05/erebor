FROM rust:1.77-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin erebor

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/erebor /usr/local/bin/
EXPOSE 8080
CMD ["erebor"]
