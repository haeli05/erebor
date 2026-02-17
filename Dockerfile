FROM rust:1.77-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin erebor

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd -r erebor && useradd -r -g erebor erebor
COPY --from=builder /app/target/release/erebor /usr/local/bin/
USER erebor
EXPOSE 8080
CMD ["erebor"]
