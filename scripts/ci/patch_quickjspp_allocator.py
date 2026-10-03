#!/usr/bin/env python3
"""Preserve SCE's optional QuickJS allocator when refreshing pinned headers."""
from pathlib import Path
import sys


def patch(content: str) -> str:
    before = "    Runtime()\n    {\n        rt = JS_NewRuntime();"
    after = ("    Runtime(const JSMallocFunctions *allocator = nullptr, void *opaque = nullptr)\n"
             "    {\n        rt = allocator ? JS_NewRuntime2(allocator, opaque) : JS_NewRuntime();")
    if after in content:
        return content
    if content.count(before) != 1:
        raise RuntimeError("quickjspp Runtime constructor changed; review allocator integration")
    return content.replace(before, after, 1)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_text(patch(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
