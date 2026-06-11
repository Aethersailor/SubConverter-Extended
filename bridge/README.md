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
- `src/generator/config/nodemanip.cpp` uses the Mihomo parser when
  `USE_MIHOMO_PARSER` is defined. Clash-compatible output fails closed on
  Mihomo parser errors; other targets retain the legacy compatibility fallback.
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

If your IDE reports that `libmihomo.h` is missing, build the bridge locally:

```bash
cd bridge
bash build.sh
```

The generated artifacts are:

- `bridge/libmihomo.h`
- `bridge/libmihomo.a` or `bridge/libmihomo.so`, depending on the build path

The Docker build also regenerates:

- `src/parser/mihomo_schemes.h`
- `src/parser/param_compat.h`

## Updating Mihomo

The current checked-in Go module pins the Mihomo module version in `go.mod`.
When intentionally updating Mihomo, update and verify the bridge from
`bridge/`:

```bash
go get github.com/metacubex/mihomo@<version-or-ref>
go mod tidy
```

Then regenerate the parser compatibility headers and rebuild the Docker image.

## Testing notes

Run `go test ./...` in `bridge/` for preprocessing, native provider YAML,
validation, and duplicate-name coverage. The Docker smoke action also verifies
remote-only, URI-only, and mixed Clash inputs with both `list=false` and
`list=true`, plus scalar and nested YAML type preservation.

## License

The Mihomo parser dependency comes from
[metacubex/mihomo](https://github.com/metacubex/mihomo), which is licensed
under the MIT License.

SubConverter-Extended is licensed under GPL-3.0. MIT-licensed code can be used
in this GPL-3.0 project, while the combined project remains GPL-3.0 licensed.
