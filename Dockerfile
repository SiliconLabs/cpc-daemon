# v1.0
# oldstable
FROM debian:10-slim
ENV LC_CTYPE=C.UTF-8
ARG TZ=UTC
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -q update && apt-get -qy --no-install-recommends install \
  cmake ninja-build pkg-config gcc binutils linux-libc-dev libc6-dev libgpiod-dev libmbedtls-dev

RUN chmod 777 /opt
VOLUME /mnt
WORKDIR /build
ENV CFLAGS="-ffunction-sections -fno-omit-frame-pointer -fstack-protector-strong"
ENV LDFLAGS="-Wl,--gc-sections"
