# ========== GO BUILD STAGE ==========
FROM golang:1.22-bookworm AS go-builder

WORKDIR /build/bridge

# Install build dependencies (gcc required for CGO)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy Go module file
COPY bridge/go.mod ./

# Download dependencies (this will auto-generate go.sum)
RUN go mod download

# Copy Go source code
COPY bridge/converter.go ./

# Update go.sum with actual dependencies from source files
RUN go mod tidy

# Copy scripts for scheme generation
COPY scripts/ ../scripts/
RUN go run ../scripts/generate_schemes.go mihomo_schemes.h
RUN go run ../scripts/generate_param_compat.go -o param_compat.h

# Build static library (enable CGO for glibc)
ENV CGO_ENABLED=1
RUN go build \
    -buildmode=c-archive \
    -ldflags="-s -w" \
    -o libmihomo.a \
    .

# Verify build output
RUN ls -lh libmihomo.a libmihomo.h

# ========== C++ BUILD STAGE ==========
FROM debian:bookworm-slim AS builder
ARG THREADS="4"
ARG SHA=""

WORKDIR /

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git g++ build-essential cmake python3 python3-pip \
    pkg-config \
    libcurl4-openssl-dev libpcre2-dev rapidjson-dev \
    libyaml-cpp-dev ca-certificates ninja-build ccache && \
    rm -rf /var/lib/apt/lists/*

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
COPY --from=go-builder /build/bridge/mihomo_schemes.h /src/src/parser/mihomo_schemes.h
COPY --from=go-builder /build/bridge/param_compat.h /src/src/parser/param_compat.h

RUN set -xe && \
    [ -n "${SHA}" ] && sed -i "s/#define BUILD_ID \"\"/#define BUILD_ID \"${SHA}\"/" src/version.h || true && \
    # Copy Go library to bridge directory for CMake detection
    mkdir -p bridge && \
    cp /usr/lib/libmihomo.a bridge/ && \
    cp /usr/include/libmihomo.h bridge/ && \
    # Configure ccache
    export PATH="/usr/lib/ccache:$PATH" && \
    export CCACHE_DIR=/tmp/ccache && \
    export CCACHE_COMPILERCHECK=content && \
    # Use Ninja generator and enable ccache
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER_LAUNCHER=ccache . && \
    # Parallel build (reduced from ${THREADS} to avoid OOM in Docker)
    ninja -j 4

# ========== FINAL STAGE ==========
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcre2-8-0 libcurl4 libyaml-cpp0.7 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/subconverter /usr/bin/
COPY --from=builder /src/base /base/

ENV TZ=Africa/Abidjan
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /base
CMD ["subconverter"]
EXPOSE 25500/tcp
