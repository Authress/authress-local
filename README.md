# Authress Local

Authress Local provides a local running version of an Authorization API in a container. Use Docker, Podman, Nomad or another container management solution to run authorization and authentication directly on your localhost.

Authress local stands up an API that offers parity with the [Authress Authorization API](https://authress.io/app/#/api). You can use Authress local to build authentication and authorization directly into your applications and services.

Additionally, Authress local is great way to develop with Authress without needing to have an Authress account.

<p align="center">
    <a href="https://crates.io/crates/authress-local" alt="Authress Local Container">
        <img src="https://img.shields.io/badge/Container-authress/authress-local.svg">
    </a>
    <a href="https://github.com/Authress/authress-local/actions" alt="GitHub action status">
        <img src="https://github.com/authress/authress-local/actions/workflows/build.yml/badge.svg">
    </a>
    <a href="./LICENSE" alt="agpl-3.0 license">
      <img src="https://img.shields.io/badge/license-AGPL-3.0-blue.svg">
    </a>
    <a href="https://authress.io/community" alt="authress community">
      <img src="https://img.shields.io/badge/Community-Authress-fbaf0b.svg">
    </a>
</p>

<hr>

## Usage
Run the container locally:

#### Docker
```sh
docker pull authress/authress-local
docker run -d -p 8888:8080 authress/authress-local
```

#### Podman
```sh
podman pull docker://authress/authress-local
podman run -d -p 8888:8080 authress/authress-local
```

This will run the container locally on port `8888`, if you want to run the container on a different port, change the `8888` to another port number.

The api for the running container matches the API at [Authress APi](https://authress.io/app/#/api).

An example API request to check a user's authorization is:

```bash
curl localhost:8888/v1/users/USER/resources/RESOURCE/permissions/PERMISSION
```

Where `USER` would be the user, `RESOURCE` is the resource uri,and the `PERMISSION` is the permission. Authress recommends using one of the many [SDKs](https://authress.io/knowledge-base/docs/SDKs) to connect instead. If you are interested in already working starter kits for various languages check out the [Authress starter kits](https://authress.io/knowledge-base/docs/SDKs), they are listed by language.

## Contributing to Authress Local
Want to contribute to Authress local, check out the [Contribution and Development Guide](./contributing.md)