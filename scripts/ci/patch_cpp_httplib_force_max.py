#!/usr/bin/env python3
"""Apply the small force_max integration patch to a pinned cpp-httplib.

The dependency refresh path downloads the upstream single header before the
project is built.  Keep the embedding-specific completion and waitable-queue
hooks reproducible, and fail closed when an upstream update changes an anchor.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PATCH_MARKERS = (
    "set_write_completion_handler(std::function<void(bool)> handler)",
    "std::function<void(bool)> write_completion_handler_;",
    "bool wait_when_full = false);",
    "bool wait_when_full_;",
    "return complete_write(ret);",
)


def replace_once(content: str, old: str, new: str, label: str) -> str:
    count = content.count(old)
    if count != 1:
        raise RuntimeError(
            f"cpp-httplib patch anchor {label!r} matched {count} times"
        )
    return content.replace(old, new, 1)


def patch_response_completion_storage(content: str) -> str:
    anchors = (
        "  std::string file_content_content_type_;\n};",
        "  detail::EncodingType file_content_encoding_ = detail::EncodingType::None;\n};",
    )
    counts = tuple(content.count(anchor) for anchor in anchors)
    if sum(counts) != 1:
        raise RuntimeError(
            "cpp-httplib patch anchor 'response completion storage' "
            f"matched {sum(counts)} times"
        )
    anchor = anchors[counts.index(1)]
    replacement = (
        anchor[:-3]
        + "\n  std::function<void(bool)> write_completion_handler_;\n};"
    )
    return content.replace(anchor, replacement, 1)


def apply_patch(content: str) -> str:
    present = tuple(marker in content for marker in PATCH_MARKERS)
    if all(present):
        return content
    if any(present):
        raise RuntimeError("cpp-httplib force_max patch is only partially present")

    content = patch_response_completion_storage(content)
    replacements = (
        (
            "response public hooks",
            "  void set_file_content(const std::string &path);\n\n"
            "  Response() = default;",
            "  void set_file_content(const std::string &path);\n\n"
            "  // Called exactly once after the server has attempted to write the complete\n"
            "  // response. This lets embedding applications attribute request completion\n"
            "  // from the actual write result instead of racing a later socket-liveness\n"
            "  // probe against a client that normally closes the connection.\n"
            "  void set_write_completion_handler(std::function<void(bool)> handler) {\n"
            "    write_completion_handler_ = std::move(handler);\n"
            "  }\n"
            "  void notify_write_completion(bool success) {\n"
            "    auto handler = std::move(write_completion_handler_);\n"
            "    if (handler) { handler(success); }\n"
            "  }\n\n"
            "  Response() = default;",
        ),
        (
            "thread pool declaration",
            "      time_t idle_timeout_sec = CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT);",
            "      time_t idle_timeout_sec = CPPHTTPLIB_THREAD_POOL_IDLE_TIMEOUT,\n"
            "      bool wait_when_full = false);",
        ),
        (
            "thread pool storage",
            "  size_t idle_thread_count_;\n\n  bool shutdown_;",
            "  size_t idle_thread_count_;\n"
            "  bool wait_when_full_;\n\n  bool shutdown_;",
        ),
        (
            "thread pool constructor",
            "inline ThreadPool::ThreadPool(size_t n, size_t max_n, size_t mqr,\n"
            "                              time_t idle_timeout_sec)\n"
            "    : base_thread_count_(n), max_queued_requests_(mqr),\n"
            "      idle_timeout_sec_(idle_timeout_sec), idle_thread_count_(0),\n"
            "      shutdown_(false) {",
            "inline ThreadPool::ThreadPool(size_t n, size_t max_n, size_t mqr,\n"
            "                              time_t idle_timeout_sec,\n"
            "                              bool wait_when_full)\n"
            "    : base_thread_count_(n), max_queued_requests_(mqr),\n"
            "      idle_timeout_sec_(idle_timeout_sec), idle_thread_count_(0),\n"
            "      wait_when_full_(wait_when_full), shutdown_(false) {",
        ),
        (
            "thread pool producer wait",
            "    std::unique_lock<std::mutex> lock(mutex_);\n"
            "    if (shutdown_) { return false; }",
            "    std::unique_lock<std::mutex> lock(mutex_);\n"
            "    if (wait_when_full_ && max_queued_requests_ > 0) {\n"
            "      cond_.wait(lock, [&] {\n"
            "        return shutdown_ || jobs_.size() < max_queued_requests_;\n"
            "      });\n"
            "    }\n"
            "    if (shutdown_) { return false; }",
        ),
        (
            "thread pool producer notification",
            "  cond_.notify_one();\n  return true;\n}",
            "  if (wait_when_full_) {\n"
            "    cond_.notify_all();\n"
            "  } else {\n"
            "    cond_.notify_one();\n"
            "  }\n"
            "  return true;\n}",
        ),
        (
            "thread pool consumer notification",
            "      fn = std::move(jobs_.front());\n"
            "      jobs_.pop_front();\n"
            "    }\n\n"
            "    assert(true == static_cast<bool>(fn));",
            "      fn = std::move(jobs_.front());\n"
            "      jobs_.pop_front();\n"
            "    }\n"
            "    if (wait_when_full_) { cond_.notify_all(); }\n\n"
            "    assert(true == static_cast<bool>(fn));",
        ),
        (
            "write completion scope",
            "  assert(res.status != -1);\n\n"
            "  if (400 <= res.status && error_handler_ &&",
            "  assert(res.status != -1);\n"
            "  auto complete_write = [&res](bool success) {\n"
            "    res.notify_write_completion(success);\n"
            "    return success;\n"
            "  };\n\n"
            "  if (400 <= res.status && error_handler_ &&",
        ),
        (
            "write response headers",
            "  if (!detail::write_response_line(bstrm, res.status)) { return false; }\n"
            "  if (header_writer_(bstrm, res.headers) <= 0) { return false; }",
            "  if (!detail::write_response_line(bstrm, res.status)) {\n"
            "    return complete_write(false);\n"
            "  }\n"
            "  if (header_writer_(bstrm, res.headers) <= 0) {\n"
            "    return complete_write(false);\n"
            "  }",
        ),
        (
            "write response buffer",
            "  if (!detail::write_data(strm, data.data(), data.size())) { return false; }",
            "  if (!detail::write_data(strm, data.data(), data.size())) {\n"
            "    return complete_write(false);\n"
            "  }",
        ),
        (
            "write response result",
            "  return ret;\n}\n\ninline bool\nServer::write_content_with_provider",
            "  return complete_write(ret);\n}\n\ninline bool\n"
            "Server::write_content_with_provider",
        ),
    )
    for label, old, new in replacements:
        content = replace_once(content, old, new, label)
    if not all(marker in content for marker in PATCH_MARKERS):
        raise RuntimeError("cpp-httplib force_max patch validation failed")
    return content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("header", help="header path, or - for stdin/stdout")
    args = parser.parse_args()
    if args.header == "-":
        original = sys.stdin.read()
        sys.stdout.write(apply_patch(original))
        return 0
    header = Path(args.header)
    original = header.read_text(encoding="utf-8")
    patched = apply_patch(original)
    if patched != original:
        header.write_text(patched, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
