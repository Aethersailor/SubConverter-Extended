#!/usr/bin/env python3
"""Preserve SCE's QuickJS allocator and C++ value compatibility patches."""
from pathlib import Path
import sys


def patch(content: str) -> str:
    before = "    Runtime()\n    {\n        rt = JS_NewRuntime();"
    after = ("    Runtime(const JSMallocFunctions *allocator = nullptr, void *opaque = nullptr)\n"
             "    {\n        rt = allocator ? JS_NewRuntime2(allocator, opaque) : JS_NewRuntime();")
    if after not in content:
        if content.count(before) != 1:
            raise RuntimeError("quickjspp Runtime constructor changed; review allocator integration")
        content = content.replace(before, after, 1)

    # QuickJS uses C compound literals. Explicit C++ copies preserve the same
    # values while avoiding frontend differences when binding JSValue&&.
    for before, after in (
        ("toJSON(const Value& replacer = JS_UNDEFINED, const Value& space = JS_UNDEFINED)",
         "toJSON(const Value& replacer = JSValue(JS_UNDEFINED), const Value& space = JSValue(JS_UNDEFINED))"),
        ("                    ctor(JS_NULL)", "                    ctor(JSValue(JS_NULL))"),
    ):
        if after in content:
            continue
        if content.count(before) != 1:
            raise RuntimeError("quickjspp value initialization changed; review C++ compatibility")
        content = content.replace(before, after, 1)
    return content


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_text(patch(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
