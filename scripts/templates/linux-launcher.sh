#!/bin/sh
set -e

CONFIG_MODE="__CONFIG_MODE__"
ROOT="__ROOT__"
CONFIG_DIR="__CONFIG_DIR__"

if [ "$ROOT" = "__PORTABLE_ROOT__" ]; then
  ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
fi

if [ "$CONFIG_DIR" = "__ROOT_BASE__" ]; then
  CONFIG_DIR="$ROOT/base"
fi

if [ "$CONFIG_MODE" = "portable" ]; then
  UPDATE_STATE_DIR="${ROOT}.update"
  umask 077
  mkdir -p "$UPDATE_STATE_DIR"
  if [ -z "${SUBCONVERTER_RUNTIME_STATE_FILE:-}" ]; then
    SUBCONVERTER_RUNTIME_STATE_FILE="$UPDATE_STATE_DIR/runtime.json"
    export SUBCONVERTER_RUNTIME_STATE_FILE
  fi

  if [ "${SUBCONVERTER_UPDATE_VALIDATION:-0}" != "1" ] && \
     [ -x "$ROOT/subconverter-update" ]; then
    if "$ROOT/subconverter-update" recover; then
      recovery_result=0
    else
      recovery_result=$?
    fi
    case "$recovery_result" in
      0) ;;
      10) exec "$ROOT/start.sh" "$@" ;;
      *)
        echo "Portable update recovery failed; refusing to start from an uncertain root." >&2
        exit "$recovery_result"
        ;;
    esac

    if [ "${SUBCONVERTER_SKIP_AUTO_UPDATE:-0}" != "1" ]; then
      if "$ROOT/subconverter-update" auto; then
        automatic_result=0
      else
        automatic_result=$?
      fi
      case "$automatic_result" in
        0) ;;
        10) exec "$ROOT/start.sh" "$@" ;;
        *)
          echo "Automatic update failed; starting the currently validated portable version." >&2
          ;;
      esac
    fi
  fi
fi

join_config_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)
      if [ "$CONFIG_MODE" = "openwrt" ]; then
        printf '%s\n' "$CONFIG_DIR/$1"
      else
        printf '%s\n' "$ROOT/$1"
      fi
      ;;
  esac
}

create_config() {
  target="$(join_config_path "$1")"
  target_dir="$(dirname "$target")"
  mkdir -p "$target_dir"

  case "$target" in
    *.yml|*.yaml) example="$ROOT/base/pref.example.yml" ;;
    *.ini) example="$ROOT/base/pref.example.ini" ;;
    *) example="$ROOT/base/pref.example.toml" ;;
  esac

  if [ ! -f "$example" ]; then
    echo "Cannot create configuration file: $target" >&2
    echo "Missing example file: $example" >&2
    exit 1
  fi

  cp "$example" "$target"
  if [ "$CONFIG_MODE" = "openwrt" ]; then
    chmod 0600 "$target"
  fi
  printf '%s\n' "$target"
}

ensure_openwrt_resource_links() {
  mkdir -p "$CONFIG_DIR" /tmp/subconverter-extended/cache

  # Older OpenWrt packages copied pref.example.* to /etc unchanged.  These
  # compatibility links repair the resulting relative base/ and snippets/
  # paths without rewriting a possibly user-edited preference file.
  if [ ! -e "$CONFIG_DIR/base" ] && [ ! -L "$CONFIG_DIR/base" ]; then
    ln -s "$ROOT/base/base" "$CONFIG_DIR/base"
  fi
  if [ ! -e "$CONFIG_DIR/snippets" ] && [ ! -L "$CONFIG_DIR/snippets" ]; then
    ln -s "$ROOT/base/snippets" "$CONFIG_DIR/snippets"
  fi
  if [ ! -e "$CONFIG_DIR/cache" ] && [ ! -L "$CONFIG_DIR/cache" ]; then
    ln -s /tmp/subconverter-extended/cache "$CONFIG_DIR/cache"
  fi
}

resolve_portable_config() {
  if [ -n "${PREF_PATH:-}" ]; then
    conf="$(join_config_path "$PREF_PATH")"
    if [ ! -f "$conf" ]; then
      create_config "$conf"
      return
    fi
    printf '%s\n' "$conf"
    return
  fi

  conf="$ROOT/base/pref.toml"
  if [ ! -f "$conf" ]; then
    create_config "$conf"
    return
  fi
  printf '%s\n' "$conf"
}

resolve_openwrt_config() {
  if [ -n "${PREF_PATH:-}" ]; then
    conf="$(join_config_path "$PREF_PATH")"
    if [ ! -f "$conf" ]; then
      create_config "$conf"
      return
    fi
    printf '%s\n' "$conf"
    return
  fi

  for conf in "$CONFIG_DIR/pref.toml" "$CONFIG_DIR/pref.yml" "$CONFIG_DIR/pref.ini"; do
    if [ -f "$conf" ]; then
      printf '%s\n' "$conf"
      return
    fi
  done

  for conf in "$ROOT/base/pref.toml" "$ROOT/base/pref.yml" "$ROOT/base/pref.ini"; do
    if [ -f "$conf" ]; then
      printf '%s\n' "$conf"
      return
    fi
  done

  for pair in \
    "pref.example.toml:pref.toml" \
    "pref.example.yml:pref.yml" \
    "pref.example.ini:pref.ini"; do
    example="${pair%%:*}"
    target="${pair#*:}"
    if [ -f "$ROOT/base/$example" ]; then
      create_config "$target"
      return
    fi
  done

  echo "No configuration file found. Expected $CONFIG_DIR/pref.toml, pref.yml, or pref.ini." >&2
  exit 1
}

if [ -x "$ROOT/lib64/ld-linux-x86-64.so.2" ]; then
  LOADER="$ROOT/lib64/ld-linux-x86-64.so.2"
  LIB_PATH="$ROOT/lib/x86_64-linux-gnu:$ROOT/usr/lib/x86_64-linux-gnu:$ROOT/lib64:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ]; then
  LOADER="$ROOT/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
  LIB_PATH="$ROOT/lib/x86_64-linux-gnu:$ROOT/usr/lib/x86_64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/ld-linux-aarch64.so.1" ]; then
  LOADER="$ROOT/lib/ld-linux-aarch64.so.1"
  LIB_PATH="$ROOT/lib/aarch64-linux-gnu:$ROOT/usr/lib/aarch64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ]; then
  LOADER="$ROOT/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
  LIB_PATH="$ROOT/lib/aarch64-linux-gnu:$ROOT/usr/lib/aarch64-linux-gnu:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/lib/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
elif [ -x "$ROOT/usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3" ]; then
  LOADER="$ROOT/usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3"
  LIB_PATH="$ROOT/lib/arm-linux-gnueabihf:$ROOT/usr/lib/arm-linux-gnueabihf:$ROOT/usr/arm-linux-gnueabihf/lib:$ROOT/lib:$ROOT/usr/lib"
else
  echo "glibc loader not found in package." >&2
  exit 1
fi

if [ "$CONFIG_MODE" = "openwrt" ]; then
  ensure_openwrt_resource_links
  CONF="$(resolve_openwrt_config)"
else
  CONF="$(resolve_portable_config)"
fi

exec "$LOADER" --library-path "$LIB_PATH" "$ROOT/subconverter" -f "$CONF"
