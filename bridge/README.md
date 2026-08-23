# Mihomo Parser Bridge

`bridge/` provides the CGO wrapper that lets SubConverter-Extended reuse
Mihomo's native subscription parser.

## Current status

The bridge is integrated into the C++ build:

- `bridge/converter.go` exports `ConvertSubscription` and `FreeString`.
- `bridge/parser.go` mirrors Mihomo proxy-provider parsing for native YAML and
  URI/base64 subscriptions, including per-proxy validation.
- `src/parser/mihomo_bridge.cpp` calls the exported Go functions and converts
  Mihomo JSON output into C++ proxy nodes.
- `src/generator/config/nodemanip.cpp` selects the parser after the request
  target has been resolved. `clash` and `clashr` use the Mihomo bridge and fail
  closed on parser errors; every other target uses the legacy parser without
  invoking the bridge. Consequently, `target=auto` uses Mihomo only when its
  User-Agent resolves to `clash` or `clashr`.
- `CMakeLists.txt` enables `USE_MIHOMO_PARSER` automatically when either
  `bridge/libmihomo.so` or `bridge/libmihomo.a` is present.

## Build modes

### Alpine Docker image

The default `Dockerfile` builds `libmihomo.so` with `go build
-buildmode=c-shared`.

This is the preferred Alpine path because the Go runtime boundary stays inside
the shared object, avoiding the musl initialization crash seen with static
`c-archive` linking.

### Debian Docker image

`docker/Dockerfile.debian` builds `libmihomo.a` with `go build
-buildmode=c-archive`.

This path is kept for glibc-based binary builds where static archive linking is
stable and easier to package.

## Local development

Install Go and a working C compiler for the target platform before building the
CGO archive. If your IDE reports that `libmihomo.h` is missing, build the
bridge locally:

```bash
cd bridge
bash build.sh
```

`build.sh` first regenerates the capability manifest and all derived parser
metadata, then builds the static `c-archive`. The generated artifacts are:

- `bridge/libmihomo.h`
- `bridge/libmihomo.a`
- `bridge/mihomo_capabilities.json`
- `bridge/proxy_validation_generated.go`
- `src/parser/mihomo_schemes.h`
- `src/parser/param_compat.h`

The Alpine Docker build follows the same generation sequence but produces
`bridge/libmihomo.so`. Review changes to generated, checked-in metadata before
committing them.

`mihomo_capabilities.json` is the single generated description of the pinned
Mihomo module. The validation source and both C++ headers are derived from that
manifest. Generation stops if the manifest is missing or incompatible; the
build does not fall back to a hard-coded protocol or parameter list.

## Updating Mihomo

The current checked-in Go module pins the Mihomo module version in `go.mod`.
When intentionally updating Mihomo, update and verify the bridge from
`bridge/`:

```bash
go get github.com/metacubex/mihomo@<version-or-ref>
go mod tidy
```

Then run `bash build.sh`, or execute the equivalent generation sequence below
before rebuilding the Docker image:

```bash
go run ../scripts/generate_proxy_validation.go \
  -o proxy_validation_generated.go \
  -manifest mihomo_capabilities.json
go run ../scripts/generate_schemes.go \
  -manifest mihomo_capabilities.json \
  -o ../src/parser/mihomo_schemes.h
go run ../scripts/generate_param_compat.go \
  -manifest mihomo_capabilities.json \
  -o ../src/parser/param_compat.h
```

Run the commands in this order. The first command reads the pinned Mihomo
source and writes the capability manifest. The remaining commands consume the
same manifest, so parser validation, URI detection, and global parameter
overlays cannot silently use different protocol snapshots.

## Testing notes

Run `go test ./...` in `bridge/` for preprocessing, native provider YAML,
validation, and duplicate-name coverage. The Docker smoke action also verifies
remote-only, URI-only, and mixed Clash inputs with both `list=false` and
`list=true`, plus scalar and nested YAML type preservation.

## License

The Mihomo parser dependency comes from
[metacubex/mihomo](https://github.com/metacubex/mihomo). Its `Meta` kernel
branch and the release version pinned by this bridge are licensed under
[GPL-3.0](https://github.com/MetaCubeX/mihomo/blob/Meta/LICENSE).

SubConverter-Extended is also licensed under GPL-3.0, and the combined project
remains GPL-3.0 licensed.
