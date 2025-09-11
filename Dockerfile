FROM rust:1.89-alpine AS build
WORKDIR /build

RUN echo http://dl-cdn.alpinelinux.org/alpine/edge/main > /etc/apk/repositories
RUN echo http://dl-cdn.alpinelinux.org/alpine/edge/community >> /etc/apk/repositories

RUN apk update && apk upgrade
RUN apk add git alpine-sdk make libffi-dev openssl-dev pkgconfig bash openssl-libs-static

COPY Cargo.lock Cargo.toml .

RUN mkdir src
RUN echo "pub fn test() {}" > src/lib.rs
RUN cargo build -r
RUN rm -r src

COPY src src

RUN cargo build -r

FROM rust:1.89-alpine
WORKDIR /srv

COPY --from=build /build/target/release/rfinger rfinger
COPY index.html .

CMD ["./rfinger"]
