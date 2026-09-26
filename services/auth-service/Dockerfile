FROM rust:1.91-bookworm as builder

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/auth-service /usr/local/bin/auth-service

ENV RUST_LOG=info
EXPOSE 8007

CMD ["auth-service"]
