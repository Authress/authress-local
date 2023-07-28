# Contribution and Development Guide

## Package Layout

* Follows [Rust Package Layout](https://doc.rust-lang.org/cargo/guide/project-layout.html)

## Running the Rust Service locally
```sh
cargo build --example server 
cargo run --example server
```

## Build the container locally
```sh
podman build -f Dockerfile -t authress-local
podman run -it -p 8888:8888 localhost/authress-local:latest
```

## Stop the container
```sh
podman container ls
podman container kill NAME
```

## Debug the container
```sh
# copy file out
podman cp <container_id>:/path/to/useful/file /local-path

# Jump into container
podman exec -it <container_id> /bin/bash
```