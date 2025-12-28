# ========== GO BUILD STAGE ==========
FROM golang:1.22-alpine AS go-builder

WORKDIR /build/bridge

# Install build dependencies
RUN apk add --no-cache git

# Copy Go module file
COPY bridge/go.mod ./

# Download dependencies (this will auto-generate go.sum)
RUN go mod download

# Copy Go source code
COPY bridge/converter.go ./

# Build static library (enable CGO for Alpine)
ENV CGO_ENABLED=1
RUN go build \
    -buildmode=c-archive \
    -ldflags="-s -w" \
    -o libmihomo.a \
    .

# Verify build output
RUN ls -lh libmihomo.a libmihomo.h && \
    file libmihomo.a

# ========== C++ BUILD STAGE ==========
FROM alpine:3.16 AS builder
ARG THREADS="4"
ARG SHA=""

WORKDIR /

RUN set -xe && \
    apk add --no-cache --virtual .build-tools git g++ build-base linux-headers cmake python3 ccache ninja && \
    apk add --no-cache --virtual .build-deps curl-dev rapidjson-dev pcre2-dev yaml-cpp-dev

# quickjspp
RUN set -xe && \
    git clone --no-checkout https://github.com/ftk/quickjspp.git && \
    cd quickjspp && \
    git fetch origin 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git checkout 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make quickjs -j ${THREADS} && \
    install -d /usr/lib/quickjs/ && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -d /usr/include/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include

# libcron
RUN set -xe && \
    git clone https://github.com/PerMalmberg/libcron --depth=1 && \
    cd libcron && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make libcron -j ${THREADS} && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && \
    install -d /usr/include/libcron/ && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && \
    install -d /usr/include/date/ && \
    install -m644 libcron/externals/date/include/date/* /usr/include/date/

# toml11
RUN set -xe && \
    git clone https://github.com/ToruNiina/toml11 --branch="v4.3.0" --depth=1 && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j ${THREADS}

# Copy Go library from go-builder stage
COPY --from=go-builder /build/bridge/libmihomo.a /usr/lib/
COPY --from=go-builder /build/bridge/libmihomo.h /usr/include/

# build subconverter from THIS repository source (provided by build context)
WORKDIR /src
COPY . /src

RUN set -xe && \
    [ -n "${SHA}" ] && sed -i 's/#define BUILD_ID ""/#define BUILD_ID "'\"${SHA}\"'"/' src/version.h || true && \
    python3 -m ensurepip && \
    python3 -m pip install --no-cache-dir gitpython && \
    python3 scripts/update_rules.py -c scripts/rules_config.conf && \
    # Copy Go library to bridge directory for CMake detection
    mkdir -p bridge && \
    cp /usr/lib/libmihomo.a bridge/ && \
    cp /usr/include/libmihomo.h bridge/ && \
    # Configure ccache
    export PATH="/usr/lib/ccache/bin:$PATH" && \
    export CCACHE_DIR=/tmp/ccache && \
    export CCACHE_COMPILERCHECK=content && \
    # Use Ninja generator and enable ccache
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER_LAUNCHER=ccache . && \
    # Parallel build
    ninja -j ${THREADS}

# ========== FINAL STAGE ==========
FROM alpine:3.16
RUN apk add --no-cache --virtual subconverter-deps pcre2 libcurl yaml-cpp

COPY --from=builder /src/subconverter /usr/bin/
COPY --from=builder /src/base /base/

ENV TZ=Africa/Abidjan
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /base
CMD subconverter
EXPOSE 25500/tcp
