FROM rust:1.87-alpine AS build
WORKDIR /build

RUN apk update && apk add git alpine-sdk make libffi-dev openssl-dev pkgconfig bash

COPY Cargo.lock Cargo.toml .

RUN mkdir src
RUN echo "pub fn test() {}" > src/lib.rs
RUN cargo build
RUN rm -r src

COPY src src
COPY index.html .

EXPOSE 8000

ENV RUST_LOG=debug

CMD ["cargo", "run"]
