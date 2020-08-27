# ConsenSource Common [![Build Status](https://travis-ci.org/target/consensource-common.svg?branch=master)](https://travis-ci.org/target/consensource-common)

A common library which provides state address hashing functions and a builder for generating ConsenSource-specific protobuff message objects.

The following components depend on this repo: 
- https://github.com/target/consensource-processor
- https://github.com/target/consensource-sds
- https://github.com/target/consensource-api
- https://github.com/target/consensource-cli

## Building Shared Docker Images

### Base Rust Images

These are shared images that we use to build various ConsenSource components.

* Rust stable image for the CLI

```sh
$ docker build -f docker/Dockerfile.cli-stable .
```

* General Rust stable image

```sh
$ docker build -f docker/Dockerfile.stable .
```

* Nightly Rust image for the API

```sh
$ docker build -f docker/Dockerfile.nightly .
```

### Tarpaulin Images

These images are for generating test coverage in our Travis CI builds.

* For the API

```sh
$ docker build -f docker/tarpaulin/api/Dockerfile .
```

* For the processor*

```sh
$ docker build -f docker/tarpaulin/processor/Dockerfile .
```

* For the SDS

```sh
$ docker build -f docker/tarpaulin/sds/Dockerfile .
```
