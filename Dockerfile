# ========== GO BUILD STAGE ==========
# 使用 glibc (Debian) 构建 Go 共享库，避免 musl 下 Go runtime 初始化崩溃
ARG GO_IMAGE=mirror.gcr.io/library/golang:latest
ARG DEBIAN_IMAGE=mirror.gcr.io/library/debian:latest
ARG ALPINE_IMAGE=mirror.gcr.io/library/alpine:latest
ARG DEBIAN_TRIXIE_IMAGE=mirror.gcr.io/library/debian:trixie
ARG DEBIAN_TRIXIE_SLIM_IMAGE=mirror.gcr.io/library/debian:trixie-slim
FROM ${GO_IMAGE} AS go-builder

ARG TARGETARCH
ARG TARGETVARIANT
ARG MIHOMO_REF="Meta"
ARG MIHOMO_CACHE_BUST=1
ARG REFRESH_GO_DEPS=false
ARG ENABLE_SANITIZERS=false

WORKDIR /build/bridge

# Debian 使用 apt 包管理器
RUN apt-get update && \
    apt-get install -y --no-install-recommends git build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy committed Go module files and source.
COPY bridge/go.mod bridge/go.sum ./
COPY bridge/converter.go ./
COPY bridge/age.go ./
COPY bridge/parser.go ./
COPY bridge/preprocess.go ./
COPY bridge/mieru.go ./
COPY bridge/cmd/portable-updater/ ./cmd/portable-updater/

RUN set -xe && \
    if [ "${REFRESH_GO_DEPS}" = "true" ]; then \
      echo "MIHOMO_CACHE_BUST=$MIHOMO_CACHE_BUST" && \
      go get github.com/metacubex/mihomo@${MIHOMO_REF} && \
      mihomo_version="$(go list -m -f '{{.Version}}' github.com/metacubex/mihomo)" && \
      mieru_version="$(go list -m -f '{{.Version}}' github.com/enfein/mieru/v3)" && \
      protobuf_version="$(go list -m -f '{{.Version}}' google.golang.org/protobuf)" && \
      test -n "${mihomo_version}" && test -n "${mieru_version}" && test -n "${protobuf_version}" && \
      go get -u all && \
      go get \
        "github.com/enfein/mieru/v3@${mieru_version}" \
        "google.golang.org/protobuf@${protobuf_version}" && \
      go mod tidy && \
      test "$(go list -m -f '{{.Version}}' github.com/metacubex/mihomo)" = "${mihomo_version}" && \
      test "$(go list -m -f '{{.Version}}' github.com/enfein/mieru/v3)" = "${mieru_version}" && \
      test "$(go list -m -f '{{.Version}}' google.golang.org/protobuf)" = "${protobuf_version}"; \
    else \
      go mod download; \
    fi

# Copy scripts for scheme generation
COPY scripts/ ../scripts/
RUN go run ../scripts/generate_proxy_validation.go -o proxy_validation_generated.go -manifest mihomo_capabilities.json
RUN go run ../scripts/generate_schemes.go -manifest mihomo_capabilities.json -o mihomo_schemes.h
RUN go run ../scripts/generate_param_compat.go -manifest mihomo_capabilities.json -o param_compat.h

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags='-s -w' \
    -o subconverter-update \
    ./cmd/portable-updater

# Build the shared library used by the normal Alpine runtime and a glibc archive
# for build/test consumers.  The sanitizer build instruments the Go archive so
# its runtime cooperates with the outer C++ ASan process.  The c-shared form is
# retained for production, but is not used in this glibc sanitizer composition.
# 关键修改：
# 1. 使用 c-shared 模式避免 musl 环境下 Go runtime 初始化问题
# 2. musl libc 不向构造函数传递 argc/argv，c-archive 模式会导致 Segfault
# 3. c-shared 模式下 Go runtime 边界清晰，初始化更稳定
RUN set -xe && \
    CGO_ENABLED=1 go build \
    -trimpath \
    -ldflags='-s -w' \
    -buildmode=c-shared \
    -o libmihomo.so \
    . && \
    sanitizer_flags="" && \
    if [ "${ENABLE_SANITIZERS}" = "true" ]; then \
      sanitizer_flags="-asan"; \
      echo "==> Building glibc Go archive with ASan interoperability"; \
    fi && \
    echo "==> Building glibc archive for $TARGETARCH" && \
    CGO_ENABLED=1 \
    go build ${sanitizer_flags} \
    -trimpath \
    -ldflags='-s -w' \
    -buildmode=c-archive \
    -o libmihomo.a \
    .

# Verify build output
RUN ls -lh libmihomo.so libmihomo.a libmihomo.h subconverter-update

# Build the config validator from the exact Mihomo module selected by the
# bridge. It is test-only and never copied into the runtime or CI export image.
ARG BUILD_TESTS=false
RUN set -eux; \
    mkdir -p /build/test-tools; \
    if [ "${BUILD_TESTS}" = "true" ]; then \
      mihomo_dir="$(GOWORK=off go list -m -mod=readonly -f '{{.Dir}}' github.com/metacubex/mihomo)"; \
      mihomo_version="$(GOWORK=off go list -m -mod=readonly -f '{{.Version}}' github.com/metacubex/mihomo)"; \
      echo "Building Mihomo config validator ${mihomo_version}"; \
      (cd "${mihomo_dir}" && \
        GOWORK=off CGO_ENABLED=1 go build \
          -mod=readonly \
          -trimpath \
          -ldflags='-s -w' \
          -o /build/test-tools/mihomo \
          .); \
      test -x /build/test-tools/mihomo; \
    fi

# ========== C++ BUILD STAGE ==========
# 使用 Debian (glibc) 编译，运行时再搬运依赖到 Alpine
FROM ${DEBIAN_IMAGE} AS builder
ARG THREADS="4"
ARG SHA=""
ARG VERSION="dev"
ARG BUILD_DATE=""
ARG REFRESH_HEADERS=false
ARG SOURCE_DEPS_CACHE_BUST=stable
ARG QUICKJSPP_REF
ARG LIBCRON_REF
ARG TOML11_REF
ARG CPP_HTTPLIB_REF
ARG NLOHMANN_JSON_REF
ARG INJA_REF
ARG JPCRE2_REF
ARG ENABLE_SANITIZERS=false

WORKDIR /

# 安装 Debian 构建依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git g++ build-essential cmake python3 python3-pip \
    pkg-config curl \
    libcurl4-openssl-dev libpcre2-dev libboost-dev rapidjson-dev \
    libyaml-cpp-dev ca-certificates ninja-build ccache && \
    rm -rf /var/lib/apt/lists/*

# quickjspp
RUN set -xe && \
    echo "SOURCE_DEPS_CACHE_BUST=${SOURCE_DEPS_CACHE_BUST}" && \
    git init quickjspp && \
    git -C quickjspp remote add origin https://github.com/ftk/quickjspp.git && \
    git -C quickjspp fetch --depth=1 origin "${QUICKJSPP_REF}" && \
    git -C quickjspp checkout --detach FETCH_HEAD && \
    git -C quickjspp submodule update --init --recursive --depth=1 && \
    cd quickjspp && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make quickjs -j ${THREADS} && \
    install -d /usr/lib/quickjs/ && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -d /usr/include/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include

# libcron
RUN set -xe && \
    echo "SOURCE_DEPS_CACHE_BUST=${SOURCE_DEPS_CACHE_BUST}" && \
    git init libcron && \
    git -C libcron remote add origin https://github.com/PerMalmberg/libcron.git && \
    git -C libcron fetch --depth=1 origin "${LIBCRON_REF}" && \
    git -C libcron checkout --detach FETCH_HEAD && \
    git -C libcron submodule update --init --recursive --depth=1 && \
    cd libcron && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make libcron -j ${THREADS} && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && \
    install -d /usr/include/libcron/ && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && \
    install -d /usr/include/date/ && \
    install -m644 libcron/externals/date/include/date/* /usr/include/date/

RUN set -xe && \
    echo "SOURCE_DEPS_CACHE_BUST=${SOURCE_DEPS_CACHE_BUST}" && \
    git init toml11 && \
    git -C toml11 remote add origin https://github.com/ToruNiina/toml11.git && \
    git -C toml11 fetch --depth=1 origin "${TOML11_REF}" && \
    git -C toml11 checkout --detach FETCH_HEAD && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j ${THREADS}

# Copy Go shared library and module files from go-builder stage
COPY --from=go-builder /build/bridge/libmihomo.so /usr/lib/
COPY --from=go-builder /build/bridge/libmihomo.a /usr/lib/
COPY --from=go-builder /build/bridge/libmihomo.h /usr/include/
COPY --from=go-builder /build/test-tools/ /opt/subconverter-test-tools/

ARG BUILD_TESTS=false
ARG TARGETARCH
ARG SINGBOX_STABLE_VERSION=1.13.18
ARG SINGBOX_STABLE_SHA256=b5c973890cf171a42512baaec6f21939f1b75b87551f335344986fd6041916d9
ARG SINGBOX_NEXT_VERSION=1.14.0-beta.14
ARG SINGBOX_NEXT_SHA256=b526ec3f4ef231db82eee935715812115055cfad3e1116a9d31cc9aad8bbd3af
RUN set -eux; \
    if [ "${BUILD_TESTS}" = "true" ]; then \
      test "${TARGETARCH}" = "amd64"; \
      for channel in stable next; do \
        if [ "${channel}" = "stable" ]; then \
          version="${SINGBOX_STABLE_VERSION}"; \
          checksum="${SINGBOX_STABLE_SHA256}"; \
        else \
          version="${SINGBOX_NEXT_VERSION}"; \
          checksum="${SINGBOX_NEXT_SHA256}"; \
        fi; \
        archive="/tmp/sing-box-${version}-linux-amd64-glibc.tar.gz"; \
        curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL \
          "https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-amd64-glibc.tar.gz" \
          -o "${archive}"; \
        printf '%s  %s\n' "${checksum}" "${archive}" | sha256sum -c -; \
        tar -xzf "${archive}" -C /tmp; \
        install -m755 \
          "/tmp/sing-box-${version}-linux-amd64-glibc/sing-box" \
          "/opt/subconverter-test-tools/sing-box-${channel}"; \
        rm -rf "${archive}" \
          "/tmp/sing-box-${version}-linux-amd64-glibc"; \
      done; \
      /opt/subconverter-test-tools/sing-box-stable version; \
      /opt/subconverter-test-tools/sing-box-next version; \
    fi

# build SubConverter-Extended from THIS repository source
WORKDIR /src
COPY . /src
COPY --from=go-builder /build/bridge/go.mod /src/bridge/go.mod
COPY --from=go-builder /build/bridge/go.sum /src/bridge/go.sum
COPY --from=go-builder /build/bridge/mihomo_capabilities.json /src/bridge/mihomo_capabilities.json
COPY --from=go-builder /build/bridge/proxy_validation_generated.go /src/bridge/proxy_validation_generated.go
COPY --from=go-builder /build/bridge/mihomo_schemes.h /src/src/parser/mihomo_schemes.h
COPY --from=go-builder /build/bridge/param_compat.h /src/src/parser/param_compat.h

RUN set -xe && \
    if [ "${REFRESH_HEADERS}" = "true" ]; then \
      echo "Downloading pinned cpp-httplib..." && \
      curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL "https://raw.githubusercontent.com/yhirose/cpp-httplib/${CPP_HTTPLIB_REF}/httplib.h" -o include/httplib.h && \
      echo "Downloading pinned nlohmann/json..." && \
      curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL "https://raw.githubusercontent.com/nlohmann/json/${NLOHMANN_JSON_REF}/single_include/nlohmann/json.hpp" -o include/nlohmann/json.hpp && \
      echo "Downloading pinned inja..." && \
      curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL "https://raw.githubusercontent.com/pantor/inja/${INJA_REF}/single_include/inja/inja.hpp" -o include/inja.hpp && \
      echo "Downloading pinned jpcre2..." && \
      curl --retry 5 --retry-all-errors --retry-delay 5 -fsSL "https://raw.githubusercontent.com/jpcre2/jpcre2/${JPCRE2_REF}/src/jpcre2.hpp" -o include/jpcre2.hpp && \
      echo "Copying pinned quickjspp from compiled source..." && \
      cp /usr/include/quickjspp.hpp include/quickjspp.hpp && \
      echo "Copying pinned libcron headers from compiled source..." && \
      rm -rf include/libcron include/date && \
      cp -a /libcron/libcron/include/libcron include/libcron && \
      cp -a /libcron/libcron/externals/date/include/date include/date && \
      echo "Copying pinned toml11 headers from compiled source..." && \
      rm -rf include/toml11 && \
      cp /toml11/include/toml.hpp include/toml.hpp && \
      cp -a /toml11/include/toml11 include/toml11; \
    else \
      echo "Using committed header libraries"; \
    fi

RUN set -xe && \
    BUILD_ID="$(printf '%.7s' "${SHA}")" && \
    [ -n "${BUILD_ID}" ] && sed -i "s/#define BUILD_ID \"\"/#define BUILD_ID \"${BUILD_ID}\"/ " src/version.h || true && \
    [ -n "${VERSION}" ] && sed -i "s/#define VERSION \"dev\"/#define VERSION \"${VERSION}\"/" src/version.h || true && \
    [ -n "${BUILD_DATE}" ] && sed -i "s/#define BUILD_DATE \"\"/#define BUILD_DATE \"${BUILD_DATE}\"/" src/version.h || true && \
    mkdir -p bridge && \
    rm -f bridge/libmihomo.so bridge/libmihomo.a && \
    if [ "${ENABLE_SANITIZERS}" = "true" ]; then \
      cp /usr/lib/libmihomo.a bridge/; \
    else \
      cp /usr/lib/libmihomo.so bridge/; \
    fi && \
    cp /usr/include/libmihomo.h bridge/ && \
    if [ "${BUILD_TESTS}" = "true" ]; then \
      test -x /opt/subconverter-test-tools/mihomo; \
      test -x /opt/subconverter-test-tools/sing-box-stable; \
      test -x /opt/subconverter-test-tools/sing-box-next; \
    fi && \
    export PATH="/usr/lib/ccache:$PATH" && \
    export CCACHE_DIR=/tmp/ccache && \
    export CCACHE_COMPILERCHECK=content && \
    cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=${BUILD_TESTS} \
    -DREQUIRE_MIHOMO_TEST_BINARY=${BUILD_TESTS} \
    -DMIHOMO_TEST_BINARY=/opt/subconverter-test-tools/mihomo \
    -DREQUIRE_SINGBOX_TEST_BINARIES=${BUILD_TESTS} \
    -DSINGBOX_STABLE_TEST_BINARY=/opt/subconverter-test-tools/sing-box-stable \
    -DSINGBOX_NEXT_TEST_BINARY=/opt/subconverter-test-tools/sing-box-next \
    -DENABLE_SANITIZERS=${ENABLE_SANITIZERS} \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=OFF \
    . && \
    ninja -j ${THREADS}

RUN if [ "${BUILD_TESTS}" = "true" ]; then \
      if [ "${ENABLE_SANITIZERS}" = "true" ]; then \
        export ASAN_OPTIONS="detect_leaks=1:strict_string_checks=1:halt_on_error=1:abort_on_error=1"; \
        export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"; \
        echo "Sanitizers enabled; production runtime and full correctness suite instrumented"; \
      fi; \
      ctest --test-dir . --output-on-failure --timeout 120; \
    fi

# 收集 glibc 运行时依赖（动态探测，避免固定版本）
RUN set -xe && \
    mkdir -p /runtime-libs && \
    ELF_LIBRARY_PATH="/usr/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu:/lib64" \
      bash /src/scripts/ci/copy-elf-runtime-deps.sh /runtime-libs \
        /src/subconverter \
        /usr/lib/libmihomo.so \
        libnss_dns.so.2 \
        libnss_files.so.2 \
        libnss_compat.so.2 \
        libresolv.so.2 && \
    chmod 0755 /runtime-libs/usr/lib/libmihomo.so && \
    if [ -f /etc/nsswitch.conf ]; then \
      mkdir -p /runtime-libs/etc && \
      cp -aL /etc/nsswitch.conf /runtime-libs/etc/nsswitch.conf; \
    fi

# Small CI-only export image. It reuses the completed builder cache without
# loading the full compiler toolchain into the runner's Docker daemon.
FROM scratch AS ci-export
COPY --from=builder /src/subconverter /src/subconverter
COPY --from=go-builder /build/bridge/subconverter-update /src/subconverter-update
COPY --from=builder /runtime-libs /runtime-libs
COPY --from=builder /src/bridge /src/bridge
COPY --from=builder /src/src/parser/mihomo_schemes.h /src/src/parser/mihomo_schemes.h
COPY --from=builder /src/src/parser/param_compat.h /src/src/parser/param_compat.h
COPY --from=builder /src/include /src/include
CMD ["/src/subconverter"]

# ========== FINAL STAGE ==========
# Alpine 运行时 + 搬运 glibc 依赖（不固定版本）
FROM ${ALPINE_IMAGE}

ARG VERSION="dev"
ARG SHA=""
ARG BUILD_DATE=""
ARG DEPENDENCY_SNAPSHOT_SHA=""
LABEL \
  org.opencontainers.image.title="SubConverter-Extended" \
  org.opencontainers.image.description="A Modern Evolution of subconverter; an enhanced implementation aligned with Mihomo configuration" \
  org.opencontainers.image.url="https://github.com/Aethersailor/SubConverter-Extended" \
  org.opencontainers.image.source="https://github.com/Aethersailor/SubConverter-Extended" \
  org.opencontainers.image.licenses="GPL-3.0" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${SHA}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  com.aethersailor.dependency-snapshot.sha256="${DEPENDENCY_SNAPSHOT_SHA}" \
  maintainer="Aethersailor"

ENV TZ=Asia/Shanghai
RUN apk add --no-cache ca-certificates tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

COPY --from=builder --chmod=0755 /src/subconverter /usr/bin/subconverter
COPY --from=builder /src/base /base/
COPY --from=builder /runtime-libs/ /

ENV LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu:/lib64:/usr/lib"

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
