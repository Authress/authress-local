# FROM rust:1.71 as builder
# ENV APP authress-local
# WORKDIR /usr/src/$APP
# COPY . .
# RUN cargo install --path .
 
# FROM debian:bookworm
# RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
# COPY --from=builder /usr/local/cargo/bin/$APP /usr/local/bin/authress-local

#####

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssl curl procps && rm -rf /var/lib/apt/lists/*
COPY ./target/release/examples/server /usr/local/bin/authress-local

EXPOSE 8888/tcp
CMD ["/usr/local/bin/authress-local"]