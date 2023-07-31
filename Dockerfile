# FROM rust:1.71.0

# LABEL org.opencontainers.image.authors="developers@authress.io"
# RUN apt-get update && apt-get install -y openssl curl procps && rm -rf /var/lib/apt/lists/*

# WORKDIR /usr/src/authress-local
# COPY . .
# RUN cargo build --release --example server

# EXPOSE 8888
# CMD ["/usr/src/authress-local/target/release/examples/server"]

FROM rust:1.71.0 as builder

WORKDIR /usr/src/authress-local
COPY . .
RUN apt-get update & apt-get install -y openssl curl procps & rm -rf /var/lib/apt/lists/*
RUN cargo build --release --example server

FROM debian:bullseye-slim

LABEL org.opencontainers.image.authors="developers@authress.io"

RUN apt-get update & apt-get install -y openssl curl procps & rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/authress-local/target/release/examples/server /usr/local/bin/authress-local

EXPOSE 8888
CMD ["/usr/local/bin/authress-local"]