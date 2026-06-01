#!/usr/bin/env bash
set -euo pipefail

DEST_ROOT="${1:?destination root is required}"
shift

READELF="${READELF:-readelf}"
ELF_LIBRARY_PATH="${ELF_LIBRARY_PATH:-}"

declare -a SEARCH_DIRS=()
if [ -n "${ELF_LIBRARY_PATH}" ]; then
  IFS=':' read -r -a SEARCH_DIRS <<< "${ELF_LIBRARY_PATH}"
fi

SEARCH_DIRS+=(
  /lib
  /usr/lib
  /lib64
  /usr/lib64
  /lib/x86_64-linux-gnu
  /usr/lib/x86_64-linux-gnu
  /lib/aarch64-linux-gnu
  /usr/lib/aarch64-linux-gnu
  /lib/arm-linux-gnueabihf
  /usr/lib/arm-linux-gnueabihf
  /usr/arm-linux-gnueabihf/lib
)

declare -A COPIED=()
declare -A SCANNED=()
declare -a QUEUE=()

canonical_path() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path"
  else
    readlink -f "$path"
  fi
}

copy_runtime_file() {
  local source="$1"
  local logical="$source"
  local resolved
  resolved="$(canonical_path "$source")"

  if [ -n "${COPIED[$logical]:-}" ]; then
    return
  fi

  local dest="${DEST_ROOT}${logical}"
  mkdir -p "$(dirname "$dest")"
  cp -aL "$source" "$dest"
  COPIED["$logical"]=1
  QUEUE+=("$resolved")
}

resolve_soname() {
  local soname="$1"

  if [[ "$soname" == */* ]] && [ -e "$soname" ]; then
    printf '%s\n' "$soname"
    return 0
  fi

  local dir candidate
  for dir in "${SEARCH_DIRS[@]}"; do
    [ -n "$dir" ] || continue
    candidate="${dir}/${soname}"
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

copy_needed_by() {
  local elf="$1"

  if [ -n "${SCANNED[$elf]:-}" ]; then
    return
  fi
  SCANNED["$elf"]=1

  if ! "$READELF" -h "$elf" >/dev/null 2>&1; then
    return
  fi

  local interp
  interp="$("$READELF" -l "$elf" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p' | head -n 1)"
  if [ -n "$interp" ] && [ -e "$interp" ]; then
    copy_runtime_file "$interp"
  fi

  local needed resolved
  while IFS= read -r needed; do
    [ -n "$needed" ] || continue
    if resolved="$(resolve_soname "$needed")"; then
      copy_runtime_file "$resolved"
    else
      echo "warning: could not resolve ELF dependency '$needed' required by $elf" >&2
    fi
  done < <("$READELF" -d "$elf" 2>/dev/null | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')
}

for input in "$@"; do
  if [ -e "$input" ]; then
    case "$(basename "$input")" in
      *.so|*.so.*|ld-*.so*|ld-linux*.so*) copy_runtime_file "$input" ;;
    esac
    copy_needed_by "$(canonical_path "$input")"
  elif resolved="$(resolve_soname "$input")"; then
    copy_runtime_file "$resolved"
  else
    echo "warning: could not resolve requested runtime file '$input'" >&2
  fi
done

while [ "${#QUEUE[@]}" -gt 0 ]; do
  current="${QUEUE[0]}"
  QUEUE=("${QUEUE[@]:1}")
  copy_needed_by "$current"
done
