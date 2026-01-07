# ========== GO BUILD STAGE ==========
# 使用 glibc (Debian) 构建 Go 共享库，避免 musl 下 Go runtime 初始化崩溃
FROM golang:latest AS go-builder

ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /build/bridge

# Debian 使用 apt 包管理器
RUN apt-get update && \
    apt-get install -y --no-install-recommends git build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy Go source code FIRST (needed for dependency analysis)
COPY bridge/converter.go ./

# Initialize new go.mod dynamically
RUN go mod init github.com/aethersailor/subconverter-extended/bridge

# Get latest Mihomo and resolve all dependencies
RUN go get github.com/metacubex/mihomo@Meta

# Upgrade all dependencies to latest versions (security fix)
RUN go get -u all

# Tidy dependencies (auto-resolves transitive deps)
RUN go mod tidy

# Copy scripts for scheme generation
COPY scripts/ ../scripts/
RUN go run ../scripts/generate_schemes.go mihomo_schemes.h
RUN go run ../scripts/generate_param_compat.go -o param_compat.h

# Build shared library (c-shared mode for musl compatibility)
# 关键修改：
# 1. 使用 c-shared 模式避免 musl 环境下 Go runtime 初始化问题
# 2. musl libc 不向构造函数传递 argc/argv，c-archive 模式会导致 Segfault
# 3. c-shared 模式下 Go runtime 边界清晰，初始化更稳定
RUN echo "==> Building for $TARGETARCH with c-shared mode (musl compatible)" && \
    CGO_ENABLED=1 \
    go build \
    -trimpath \
    -buildmode=c-shared \
    -o libmihomo.so \
    .

# Verify build output
RUN ls -lh libmihomo.so libmihomo.h

# ========== C++ BUILD STAGE ==========
# 使用 Debian (glibc) 编译，运行时再搬运依赖到 Alpine
FROM debian:latest AS builder
ARG THREADS="4"
ARG SHA=""
ARG VERSION="dev"
ARG BUILD_DATE=""

WORKDIR /

# 安装 Debian 构建依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git g++ build-essential cmake python3 python3-pip \
    pkg-config curl \
    libcurl4-openssl-dev libpcre2-dev rapidjson-dev \
    libyaml-cpp-dev ca-certificates ninja-build ccache && \
    rm -rf /var/lib/apt/lists/*

# quickjspp
RUN set -xe && \
    git clone --depth=1 https://github.com/ftk/quickjspp.git && \
    cd quickjspp && \
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

# toml11 (跟随默认分支最新版本)
RUN set -xe && \
    git clone https://github.com/ToruNiina/toml11 --depth=1 && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j ${THREADS}

# Copy Go shared library and module files from go-builder stage
COPY --from=go-builder /build/bridge/libmihomo.so /usr/lib/
COPY --from=go-builder /build/bridge/libmihomo.h /usr/include/
COPY --from=go-builder /build/bridge/go.mod /src/bridge/go.mod
COPY --from=go-builder /build/bridge/go.sum /src/bridge/go.sum

# build subconverter from THIS repository source
WORKDIR /src
COPY . /src
COPY --from=go-builder /build/bridge/mihomo_schemes.h /src/src/parser/mihomo_schemes.h
COPY --from=go-builder /build/bridge/param_compat.h /src/src/parser/param_compat.h

# Download latest header-only libraries
RUN set -xe && \
    echo "Downloading latest cpp-httplib..." && \
    curl -fsSL https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h -o include/httplib.h && \
    echo "Downloading latest nlohmann/json..." && \
    curl -fsSL https://github.com/nlohmann/json/releases/latest/download/json.hpp -o include/nlohmann/json.hpp && \
    echo "Downloading latest inja..." && \
    curl -fsSL https://raw.githubusercontent.com/pantor/inja/master/single_include/inja/inja.hpp -o include/inja.hpp && \
    echo "Downloading latest jpcre2..." && \
    curl -fsSL https://raw.githubusercontent.com/jpcre2/jpcre2/master/src/jpcre2.hpp -o include/jpcre2.hpp && \
    echo "Copying latest quickjspp from compiled source..." && \
    cp /usr/include/quickjspp.hpp include/quickjspp.hpp && \
    echo "All header libraries updated to latest versions"

RUN set -xe && \
    [ -n "${SHA}" ] && sed -i "s/#define BUILD_ID \"\"/#define BUILD_ID \"${SHA}\"/ " src/version.h || true && \
    [ -n "${VERSION}" ] && sed -i "s/#define VERSION \"dev\"/#define VERSION \"${VERSION}\"/" src/version.h || true && \
    [ -n "${BUILD_DATE}" ] && sed -i "s/#define BUILD_DATE \"\"/#define BUILD_DATE \"${BUILD_DATE}\"/" src/version.h || true && \
    mkdir -p bridge && \
    cp /usr/lib/libmihomo.so bridge/ && \
    cp /usr/include/libmihomo.h bridge/ && \
    export PATH="/usr/lib/ccache:$PATH" && \
    export CCACHE_DIR=/tmp/ccache && \
    export CCACHE_COMPILERCHECK=content && \
    cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=OFF \
    . && \
    ninja -j ${THREADS}

# 收集 glibc 运行时依赖（动态探测，避免固定版本）
RUN set -xe && \
    mkdir -p /runtime-libs && \
    ldd /src/subconverter /usr/lib/libmihomo.so | \
      awk '{for (i=1; i<=NF; i++) if ($i ~ "^/") print $i}' | \
      sort -u | \
      while read -r lib; do \
        if [ -e "$lib" ]; then \
          mkdir -p "/runtime-libs$(dirname "$lib")" && \
          cp -aL "$lib" "/runtime-libs$lib"; \
        fi; \
      done && \
    for loader in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /lib/ld-linux-aarch64.so.1 /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1; do \
      if [ -e "$loader" ]; then \
        mkdir -p "/runtime-libs$(dirname "$loader")" && \
        cp -aL "$loader" "/runtime-libs$loader"; \
      fi; \
    done && \
    libc_path="$(ldd /src/subconverter | awk '$1 == "libc.so.6" {print $3; exit}')" && \
    libc_dir="$(dirname "${libc_path:-/lib/x86_64-linux-gnu/libc.so.6}")" && \
    for extra in libnss_dns.so.2 libnss_files.so.2 libnss_compat.so.2 libresolv.so.2; do \
      if [ -e "$libc_dir/$extra" ]; then \
        mkdir -p "/runtime-libs$libc_dir" && \
        cp -aL "$libc_dir/$extra" "/runtime-libs$libc_dir/$extra"; \
      fi; \
    done && \
    if [ -f /etc/nsswitch.conf ]; then \
      mkdir -p /runtime-libs/etc && \
      cp -aL /etc/nsswitch.conf /runtime-libs/etc/nsswitch.conf; \
    fi

# ========== FINAL STAGE ==========
# Alpine 运行时 + 搬运 glibc 依赖（不固定版本）
FROM alpine:latest

ARG VERSION="dev"
ARG SHA=""
ARG BUILD_DATE=""
LABEL \
  org.opencontainers.image.title="SubConverter-Extended" \
  org.opencontainers.image.description="A Modern Evolution of subconverter; an enhanced implementation aligned with Mihomo configuration" \
  org.opencontainers.image.url="https://github.com/Aethersailor/SubConverter-Extended" \
  org.opencontainers.image.source="https://github.com/Aethersailor/SubConverter-Extended" \
  org.opencontainers.image.licenses="GPL-3.0" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${SHA}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  maintainer="Aethersailor"

RUN apk add --no-cache ca-certificates

COPY --from=builder /src/subconverter /usr/bin/subconverter
COPY --from=builder /src/base /base/
COPY --from=builder /usr/lib/libmihomo.so /usr/lib/
COPY --from=builder /runtime-libs/ /
COPY --from=builder /etc/nsswitch.conf /etc/nsswitch.conf

# 确保二进制和库可执行
RUN chmod +x /usr/bin/subconverter && chmod +x /usr/lib/libmihomo.so

ENV TZ=Asia/Shanghai
ENV LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu:/lib64:/usr/lib"
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /base
RUN set -e && \
    printf '%s\n' \
      '#!/bin/sh' \
      'set -e' \
      'ARCH="$(uname -m)"' \
      'case "$ARCH" in' \
      '  x86_64) LIB_ARCH="x86_64-linux-gnu" ;;' \
      '  aarch64|arm64) LIB_ARCH="aarch64-linux-gnu" ;;' \
      '  *) LIB_ARCH="" ;;' \
      'esac' \
      'if [ -n "$LIB_ARCH" ]; then' \
      '  export LD_LIBRARY_PATH="/lib/${LIB_ARCH}:/usr/lib/${LIB_ARCH}:/lib64:/usr/lib"' \
      'fi' \
      'CONF="${PREF_PATH:-/base/pref.toml}"' \
      'CONF_DIR="$(dirname "$CONF")"' \
      'mkdir -p "$CONF_DIR"' \
      'if [ ! -f "$CONF" ] && [ -f /base/pref.example.toml ]; then' \
      '  cp /base/pref.example.toml "$CONF"' \
      'fi' \
      'exec /usr/bin/subconverter -f "$CONF"' \
      > /usr/local/bin/start-subconverter && \
    chmod +x /usr/local/bin/start-subconverter
CMD ["/usr/local/bin/start-subconverter"]
EXPOSE 25500/tcp
