#include "handler/inspect_page.h"

#include <string>

#include "version.h"

namespace inspect_page {

std::string page(Request &, Response &response) {
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";

  return R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
    <meta name="color-scheme" content="light dark">
    <title>SubConverter-Extended Inspector</title>
    <script>
        (function () {
            function detectPreferredLanguage() {
                var languages = navigator.languages && navigator.languages.length
                    ? navigator.languages
                    : [navigator.language || ""];
                var isChinese = languages.some(function (language) {
                    return /^zh\b/i.test(language);
                });
                return isChinese ? "zh-CN" : "en";
            }

            document.documentElement.lang = detectPreferredLanguage();
        })();
    </script>
    <link rel="icon" type="image/svg+xml" href="/version/favicon-dark.svg">
    <link rel="icon" type="image/svg+xml" href="/version/favicon-light.svg" media="(prefers-color-scheme: light)">
    <link rel="icon" type="image/svg+xml" href="/version/favicon-dark.svg" media="(prefers-color-scheme: dark)">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #f8fafc 0%, #eef2f7 48%, #e2e8f0 100%);
            --bg-grid: rgba(15, 23, 42, 0.055);
            --bg-sheen: linear-gradient(115deg, transparent 0%, transparent 33%, rgba(14, 165, 233, 0.11) 48%, rgba(132, 204, 22, 0.09) 58%, transparent 73%, transparent 100%);
            --container-bg: rgba(255, 255, 255, 0.82);
            --container-border: rgba(255, 255, 255, 0.68);
            --container-highlight: rgba(255, 255, 255, 0.72);
            --shadow: 0 28px 70px rgba(15, 23, 42, 0.13);
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --text-muted: #64748b;
            --divider-bg: linear-gradient(90deg, transparent, rgba(15, 23, 42, 0.12), transparent);
            --info-block-bg: rgba(255, 255, 255, 0.52);
            --info-block-border: rgba(15, 23, 42, 0.08);
            --info-block-hover: rgba(255, 255, 255, 0.72);
            --input-bg: rgba(255, 255, 255, 0.7);
            --input-border: rgba(26, 32, 44, 0.14);
            --link-color: #3182ce;
            --link-hover: #2b6cb0;
            --header-gradient: linear-gradient(135deg, #1a202c 0%, #4a5568 100%);
            --accent-gradient: linear-gradient(135deg, #0284c7 0%, #0891b2 45%, #65a30d 100%);
            --accent-soft: rgba(2, 132, 199, 0.1);
            --status-bg: rgba(2, 132, 199, 0.08);
            --status-border: rgba(2, 132, 199, 0.18);
            --status-dot: #10b981;
            --warn-dot: #f59e0b;
            --error-dot: #ef4444;
            --brand-mark-filter:
                drop-shadow(0 16px 28px rgba(2, 132, 199, 0.16))
                drop-shadow(0 8px 14px rgba(5, 150, 105, 0.12));
            --control-bg: rgba(255, 255, 255, 0.72);
            --control-hover: rgba(255, 255, 255, 0.92);
            --control-border: rgba(26, 32, 44, 0.12);
            --control-shadow: 0 12px 28px rgba(31, 38, 135, 0.12);
            --code-bg: rgba(15, 23, 42, 0.06);
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-gradient: linear-gradient(135deg, #05070b 0%, #0d111a 46%, #111827 100%);
                --bg-grid: rgba(148, 163, 184, 0.075);
                --bg-sheen: linear-gradient(115deg, transparent 0%, transparent 31%, rgba(34, 211, 238, 0.12) 47%, rgba(132, 204, 22, 0.08) 58%, transparent 74%, transparent 100%);
                --container-bg: rgba(15, 23, 42, 0.72);
                --container-border: rgba(148, 163, 184, 0.18);
                --container-highlight: rgba(255, 255, 255, 0.11);
                --shadow: 0 32px 80px rgba(0, 0, 0, 0.62);
                --text-primary: #f8f9fa;
                --text-secondary: #a0aec0;
                --text-muted: #7f8ea3;
                --divider-bg: linear-gradient(90deg, transparent, rgba(148, 163, 184, 0.18), transparent);
                --info-block-bg: rgba(255, 255, 255, 0.045);
                --info-block-border: rgba(255, 255, 255, 0.08);
                --info-block-hover: rgba(255, 255, 255, 0.065);
                --input-bg: rgba(15, 23, 42, 0.48);
                --input-border: rgba(255, 255, 255, 0.16);
                --link-color: #63b3ed;
                --link-hover: #90cdf4;
                --header-gradient: linear-gradient(135deg, #ffffff 0%, #90cdf4 100%);
                --accent-gradient: linear-gradient(135deg, #38bdf8 0%, #22d3ee 42%, #84cc16 100%);
                --accent-soft: rgba(56, 189, 248, 0.12);
                --status-bg: rgba(34, 211, 238, 0.1);
                --status-border: rgba(34, 211, 238, 0.22);
                --status-dot: #34d399;
                --brand-mark-filter:
                    drop-shadow(0 18px 32px rgba(34, 211, 238, 0.2))
                    drop-shadow(0 10px 18px rgba(132, 204, 22, 0.12));
                --control-bg: rgba(20, 24, 33, 0.7);
                --control-hover: rgba(35, 42, 56, 0.86);
                --control-border: rgba(255, 255, 255, 0.16);
                --control-shadow: 0 16px 34px rgba(0, 0, 0, 0.36);
                --code-bg: rgba(0, 0, 0, 0.24);
            }
        }

        html[lang^="zh"] [data-lang="en"],
        html:not([lang^="zh"]) [data-lang="zh"] {
            display: none;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Outfit', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif;
            min-height: 100vh;
            min-height: 100svh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-gradient);
            background-attachment: fixed;
            padding: 24px;
            color: var(--text-primary);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            overflow-x: hidden;
            position: relative;
        }

        body::before,
        body::after {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
        }

        body::before {
            background-image:
                linear-gradient(var(--bg-grid) 1px, transparent 1px),
                linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px);
            background-size: 36px 36px;
            mask-image: linear-gradient(to bottom, transparent 0%, #000 18%, #000 82%, transparent 100%);
            -webkit-mask-image: linear-gradient(to bottom, transparent 0%, #000 18%, #000 82%, transparent 100%);
            opacity: 0.58;
        }

        body::after {
            background: var(--bg-sheen);
            opacity: 0.82;
        }

        .lang-toggle {
            position: fixed;
            top: calc(18px + env(safe-area-inset-top, 0px));
            right: calc(18px + env(safe-area-inset-right, 0px));
            z-index: 10;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid var(--control-border);
            border-radius: 999px;
            background: var(--control-bg);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            box-shadow: var(--control-shadow);
            color: var(--text-primary);
            cursor: pointer;
            font: inherit;
            font-size: 0.86rem;
            font-weight: 700;
            line-height: 1;
            min-height: 40px;
            min-width: 76px;
            padding: 9px 13px;
            transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
        }

        .lang-toggle:hover {
            background: var(--control-hover);
            transform: translateY(-1px);
        }

        .lang-toggle:focus-visible,
        button:focus-visible,
        textarea:focus-visible,
        input:focus-visible {
            outline: 3px solid rgba(99, 179, 237, 0.35);
            outline-offset: 2px;
        }

        .lang-toggle svg {
            width: 17px;
            height: 17px;
            flex: 0 0 auto;
        }

        .lang-toggle-text {
            min-width: 20px;
            text-align: center;
        }

        .container {
            background: var(--container-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-radius: 32px;
            padding: 44px 52px 38px;
            max-width: 980px;
            width: 100%;
            min-width: 0;
            box-shadow: var(--shadow);
            border: 1px solid var(--container-border);
            position: relative;
            z-index: 1;
            overflow: hidden;
            animation: fadeIn 1s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .container::before {
            content: "";
            position: absolute;
            inset: 0;
            background:
                linear-gradient(180deg, var(--container-highlight), transparent 34%),
                linear-gradient(90deg, transparent, var(--accent-soft), transparent);
            opacity: 0.62;
            pointer-events: none;
        }

        .container::after {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: 32px;
            padding: 1px;
            background: linear-gradient(135deg, var(--container-highlight), transparent 42%, rgba(255,255,255,0.05));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
        }

        .container > * {
            position: relative;
            z-index: 1;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        header {
            text-align: center;
            margin-bottom: 28px;
        }

        .brand-mark {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 88px;
            height: 88px;
            margin: 0 auto 16px;
            filter: var(--brand-mark-filter);
            transition: transform 0.28s ease, filter 0.28s ease;
        }

        .brand-mark img {
            display: block;
            width: 100%;
            height: 100%;
        }

        .brand-mark:hover {
            transform: translateY(-2px) scale(1.02);
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-bottom: 14px;
            padding: 7px 12px;
            border-radius: 999px;
            border: 1px solid var(--status-border);
            background: var(--status-bg);
            color: var(--text-primary);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--status-dot);
            box-shadow: 0 0 0 5px color-mix(in srgb, var(--status-dot) 16%, transparent);
        }

        h1 {
            background: var(--header-gradient);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: 0;
            line-height: 1.05;
            overflow-wrap: anywhere;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1.02em;
            font-weight: 500;
            letter-spacing: 0;
            text-transform: uppercase;
            opacity: 0.72;
        }

        .section {
            margin: 18px 0;
            padding: 22px 24px;
            background: var(--info-block-bg);
            border-radius: 22px;
            border: 1px solid var(--info-block-border);
            transition: background 0.22s ease, border-color 0.22s ease, transform 0.22s ease;
        }

        .section:hover {
            background: var(--info-block-hover);
            transform: translateY(-1px);
        }

        .section-title {
            font-size: 0.9em;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: 0;
        }

        .section-title::before {
            content: "";
            display: block;
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-gradient);
        }

        label {
            display: block;
            margin-bottom: 10px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 700;
            letter-spacing: 0;
        }

        textarea,
        input {
            display: block;
            width: 100%;
            min-width: 0;
            max-width: 100%;
            border: 1px solid var(--input-border);
            border-radius: 18px;
            background: var(--input-bg);
            color: var(--text-primary);
            font: inherit;
            font-size: 0.95rem;
            line-height: 1.45;
            padding: 14px 16px;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08);
        }

        textarea {
            min-height: 116px;
            max-height: 260px;
            overflow: auto;
            resize: vertical;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", "Microsoft YaHei", monospace;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        textarea::placeholder,
        input::placeholder {
            color: var(--text-muted);
            opacity: 0.72;
        }

        .toolbar {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 14px;
            flex-wrap: wrap;
        }

        .request-preview {
            margin-top: 12px;
            padding: 12px 14px;
            border: 1px solid var(--info-block-border);
            border-radius: 16px;
            background: var(--code-bg);
            max-height: 132px;
            overflow: auto;
            min-width: 0;
        }

        .preview-label {
            color: var(--text-muted);
            font-size: 0.74rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
            margin-bottom: 7px;
        }

        .request-preview code {
            display: block;
            max-width: 100%;
            color: var(--text-secondary);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
            font-size: 0.78rem;
            line-height: 1.48;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        .button-row {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        button {
            border: 1px solid var(--control-border);
            border-radius: 999px;
            background: var(--control-bg);
            color: var(--text-primary);
            cursor: pointer;
            font: inherit;
            font-size: 0.9rem;
            font-weight: 700;
            line-height: 1;
            min-height: 42px;
            padding: 11px 16px;
            box-shadow: var(--control-shadow);
            transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
        }

        button:hover:not(:disabled) {
            background: var(--control-hover);
            transform: translateY(-1px);
        }

        button:disabled {
            cursor: progress;
            opacity: 0.7;
        }

        .primary {
            color: #f8fafc;
            border-color: transparent;
            background: var(--accent-gradient);
        }

        .primary:hover:not(:disabled) {
            background: var(--accent-gradient);
        }

        .hint {
            color: var(--text-muted);
            font-size: 0.86rem;
            line-height: 1.45;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
            gap: 12px;
        }

        .metric {
            min-width: 0;
            padding: 15px;
            border-radius: 18px;
            border: 1px solid var(--info-block-border);
            background: rgba(255, 255, 255, 0.18);
        }

        .metric-label {
            color: var(--text-muted);
            font-size: 0.76rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
            margin-bottom: 7px;
        }

        .metric-value {
            color: var(--text-primary);
            font-size: 1.42rem;
            font-weight: 700;
            line-height: 1.15;
            overflow-wrap: anywhere;
        }

        .state-line {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }

        .tag {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            max-width: 100%;
            min-height: 30px;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--status-border);
            background: var(--status-bg);
            color: var(--text-primary);
            font-size: 0.82rem;
            font-weight: 700;
            overflow-wrap: anywhere;
        }

        .tag::before {
            content: "";
            width: 7px;
            height: 7px;
            border-radius: 999px;
            background: var(--status-dot);
        }

        .tag.warn::before { background: var(--warn-dot); }
        .tag.error::before { background: var(--error-dot); }

        .table-wrap {
            overflow-x: auto;
            border: 1px solid var(--info-block-border);
            border-radius: 18px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 620px;
        }

        th,
        td {
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--info-block-border);
            color: var(--text-secondary);
            font-size: 0.9rem;
            vertical-align: top;
        }

        th {
            color: var(--text-primary);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
            background: rgba(255, 255, 255, 0.08);
        }

        tr:last-child td {
            border-bottom: 0;
        }

        td {
            overflow-wrap: anywhere;
        }

        .param-table {
            min-width: 820px;
        }

        .config-table {
            min-width: 680px;
        }

        .status-text {
            color: var(--text-primary);
            font-weight: 700;
        }

        .value-cell {
            max-width: 320px;
        }

        pre {
            max-height: 360px;
            overflow: auto;
            border: 1px solid var(--info-block-border);
            border-radius: 18px;
            background: var(--code-bg);
            color: var(--text-secondary);
            padding: 16px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
            font-size: 0.82rem;
            line-height: 1.48;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .divider {
            height: 1px;
            background: var(--divider-bg);
            margin: 24px 0 18px;
        }

        footer {
            color: var(--text-muted);
            font-size: 0.84em;
            line-height: 1.55;
            text-align: center;
        }

        a {
            color: var(--link-color);
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s ease;
        }

        a:hover { color: var(--link-hover); }

        .empty {
            color: var(--text-muted);
            padding: 14px 0 2px;
            font-size: 0.92rem;
        }

        [hidden] { display: none !important; }

        @media (max-width: 780px) {
            body {
                align-items: stretch;
                padding: 76px 14px 18px;
            }

            .container {
                border-radius: 24px;
                padding: 30px 20px 24px;
            }

            .container::after {
                border-radius: 24px;
            }

            .brand-mark {
                width: 76px;
                height: 76px;
            }

            h1 {
                font-size: 2.1em;
            }

            .section {
                border-radius: 18px;
                padding: 18px;
            }

            .summary-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .toolbar {
                align-items: stretch;
            }

            .button-row,
            .toolbar button {
                width: 100%;
            }

            .button-row {
                display: grid;
                grid-template-columns: 1fr;
            }

            .request-preview {
                max-height: 150px;
            }
        }

        @media (max-width: 440px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>
<body>
    <button class="lang-toggle" type="button" aria-label="Switch language">
        <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M4 5h9M9 3v2m1.7 0c-.6 3.5-2.4 6.1-5.2 7.7m2.8-3.1c1.1 1.3 2.3 2.3 3.7 3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M14 20l4-9 4 9m-6.7-3h5.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span class="lang-toggle-text" data-lang="en">中</span>
        <span class="lang-toggle-text" data-lang="zh">EN</span>
    </button>

    <main class="container">
        <header>
            <picture class="brand-mark">
                <source media="(prefers-color-scheme: dark)" srcset="/version/favicon-dark.svg">
                <img src="/version/favicon-light.svg" alt="SubConverter-Extended icon" width="88" height="88" decoding="async">
            </picture>
            <div class="status-pill">
                <span class="status-dot"></span>
                <span data-lang="en">Inspector</span>
                <span data-lang="zh">诊断台</span>
            </div>
            <h1>
                <span data-lang="en">Request Inspector</span>
                <span data-lang="zh">请求诊断台</span>
            </h1>
            <p class="subtitle">
                <span data-lang="en">Explain conversion without writing managed output</span>
                <span data-lang="zh">以只读方式解释转换结果</span>
            </p>
        </header>

        <section class="section">
            <div class="section-title">
                <span data-lang="en">Request</span>
                <span data-lang="zh">请求</span>
            </div>
            <label for="request-input">
                <span data-lang="en">/sub URL or query string</span>
                <span data-lang="zh">/sub 链接或查询参数</span>
            </label>
            <textarea id="request-input" spellcheck="false" placeholder="target=clash&url=https%3A%2F%2Fexample.com%2Fsub"></textarea>
            <div class="request-preview" aria-live="polite">
                <div class="preview-label">
                    <span data-lang="en">Normalized request</span>
                    <span data-lang="zh">规范化请求</span>
                </div>
                <code id="resolved-url">/sub?explain=true</code>
            </div>
            <div class="toolbar">
                <div class="button-row">
                    <button type="button" id="sample-button">
                        <span data-lang="en">Sample</span>
                        <span data-lang="zh">示例</span>
                    </button>
                    <button type="button" id="clear-button">
                        <span data-lang="en">Clear</span>
                        <span data-lang="zh">清空</span>
                    </button>
                    <button class="primary" type="button" id="run-button">
                        <span data-lang="en">Inspect</span>
                        <span data-lang="zh">开始诊断</span>
                    </button>
                </div>
            </div>
        </section>

        <section class="section" id="summary-section" hidden>
            <div class="section-title">
                <span data-lang="en">Summary</span>
                <span data-lang="zh">摘要</span>
            </div>
            <div class="summary-grid">
                <div class="metric">
                    <div class="metric-label" data-lang="en">Target</div>
                    <div class="metric-label" data-lang="zh">目标</div>
                    <div class="metric-value" id="metric-target">-</div>
                </div>
                <div class="metric">
                    <div class="metric-label" data-lang="en">Providers</div>
                    <div class="metric-label" data-lang="zh">Provider</div>
                    <div class="metric-value" id="metric-providers">-</div>
                </div>
                <div class="metric">
                    <div class="metric-label" data-lang="en">Nodes</div>
                    <div class="metric-label" data-lang="zh">节点</div>
                    <div class="metric-value" id="metric-nodes">-</div>
                </div>
                <div class="metric">
                    <div class="metric-label" data-lang="en">Output</div>
                    <div class="metric-label" data-lang="zh">输出</div>
                    <div class="metric-value" id="metric-output">-</div>
                </div>
                <div class="metric">
                    <div class="metric-label" data-lang="en">Params</div>
                    <div class="metric-label" data-lang="zh">参数</div>
                    <div class="metric-value" id="metric-parameters">-</div>
                </div>
                <div class="metric">
                    <div class="metric-label" data-lang="en">Config</div>
                    <div class="metric-label" data-lang="zh">配置</div>
                    <div class="metric-value" id="metric-config">-</div>
                </div>
            </div>
            <div class="state-line" id="state-line"></div>
        </section>

        <section class="section" id="parameter-section" hidden>
            <div class="section-title">
                <span data-lang="en">Parameters</span>
                <span data-lang="zh">参数</span>
            </div>
            <div class="table-wrap">
                <table class="param-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Source</th>
                            <th>Request value</th>
                            <th>Effective</th>
                            <th>Note</th>
                        </tr>
                    </thead>
                    <tbody id="parameters-body"></tbody>
                </table>
            </div>
        </section>

        <section class="section" id="config-section" hidden>
            <div class="section-title">
                <span data-lang="en">Effective Config</span>
                <span data-lang="zh">生效配置</span>
            </div>
            <div class="table-wrap">
                <table class="config-table">
                    <thead>
                        <tr>
                            <th>Section</th>
                            <th>Status</th>
                            <th>Source</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody id="config-body"></tbody>
                </table>
            </div>
        </section>

        <section class="section" id="provider-section" hidden>
            <div class="section-title">
                <span data-lang="en">Providers</span>
                <span data-lang="zh">Providers</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Source</th>
                            <th>Path</th>
                            <th>Filter</th>
                            <th>Interval</th>
                        </tr>
                    </thead>
                    <tbody id="providers-body"></tbody>
                </table>
            </div>
        </section>

        <section class="section" id="json-section" hidden>
            <div class="section-title">
                <span data-lang="en">JSON</span>
                <span data-lang="zh">JSON</span>
            </div>
            <pre id="json-output"></pre>
        </section>

        <section class="section" id="empty-section">
            <div class="section-title">
                <span data-lang="en">Ready</span>
                <span data-lang="zh">就绪</span>
            </div>
            <p class="empty">
                <span data-lang="en">Paste a conversion request and run inspection.</span>
                <span data-lang="zh">粘贴转换请求后开始诊断。</span>
            </p>
        </section>

        <div class="divider"></div>
        <footer>
            <span data-lang="en">SubConverter-Extended )html" +
         std::string(VERSION) +
         R"html( · <a href="/version">Version</a></span>
            <span data-lang="zh">SubConverter-Extended )html" +
         std::string(VERSION) +
         R"html( · <a href="/version">版本信息</a></span>
        </footer>
    </main>

    <script>
        (function () {
            var input = document.getElementById("request-input");
            var resolvedUrl = document.getElementById("resolved-url");
            var runButton = document.getElementById("run-button");
            var sampleButton = document.getElementById("sample-button");
            var clearButton = document.getElementById("clear-button");
            var summarySection = document.getElementById("summary-section");
            var parameterSection = document.getElementById("parameter-section");
            var configSection = document.getElementById("config-section");
            var providerSection = document.getElementById("provider-section");
            var jsonSection = document.getElementById("json-section");
            var emptySection = document.getElementById("empty-section");
            var parametersBody = document.getElementById("parameters-body");
            var configBody = document.getElementById("config-body");
            var providersBody = document.getElementById("providers-body");
            var jsonOutput = document.getElementById("json-output");
            var stateLine = document.getElementById("state-line");

            var sampleQuery = "target=clash&url=provider%3AHK%2Chttps%3A%2F%2Fexample.com%2Fsub&config=data%3A%2Cenable_rule_generator%3Dfalse";

            function isZh() {
                return /^zh\b/i.test(document.documentElement.lang || "");
            }

            function text(en, zh) {
                return isZh() ? zh : en;
            }

            function setText(id, value) {
                document.getElementById(id).textContent = value;
            }

            function formatBytes(value) {
                if (!Number.isFinite(value)) {
                    return "-";
                }
                if (value < 1024) {
                    return String(value) + " B";
                }
                if (value < 1024 * 1024) {
                    return (value / 1024).toFixed(1) + " KB";
                }
                return (value / 1024 / 1024).toFixed(1) + " MB";
            }

            function normalizeRequest(raw) {
                var value = (raw || "").trim();
                var url;
                if (!value) {
                    url = new URL("/sub", window.location.origin);
                } else if (value.charAt(0) === "?") {
                    url = new URL("/sub" + value, window.location.origin);
                } else if (value.charAt(0) === "/") {
                    url = new URL(value, window.location.origin);
                } else if (/^https?:\/\//i.test(value)) {
                    url = new URL(value);
                } else {
                    url = new URL("/sub?" + value, window.location.origin);
                }

                if (url.pathname !== "/sub") {
                    url.pathname = "/sub";
                }
                url.searchParams.set("explain", "true");
                return url;
            }

            function updateResolvedUrl() {
                try {
                    var url = normalizeRequest(input.value);
                    resolvedUrl.textContent = url.origin === window.location.origin
                        ? url.pathname + url.search
                        : url.toString();
                } catch (error) {
                    resolvedUrl.textContent = text("Invalid request", "请求无效");
                }
            }

            function tag(label, level) {
                var el = document.createElement("span");
                el.className = "tag" + (level ? " " + level : "");
                el.textContent = label;
                return el;
            }

            function showError(message, detail) {
                summarySection.hidden = true;
                parameterSection.hidden = true;
                configSection.hidden = true;
                providerSection.hidden = true;
                jsonSection.hidden = false;
                emptySection.hidden = true;
                jsonOutput.textContent = detail ? message + "\n\n" + detail : message;
            }

            function valueSummary(item) {
                var parts = [];
                if (item.value_preview) {
                    parts.push(item.value_preview);
                }
                if (item.value_hash) {
                    parts.push("#" + item.value_hash);
                }
                if (Number.isFinite(item.value_length)) {
                    parts.push(String(item.value_length) + " B");
                }
                return parts.length ? parts.join(" · ") : "-";
            }

            function appendCell(row, value, className) {
                var cell = document.createElement("td");
                if (className) {
                    cell.className = className;
                }
                cell.textContent = value === undefined || value === null || value === "" ? "-" : String(value);
                row.appendChild(cell);
            }

            function renderParameters(parameters) {
                var recognized = Array.isArray(parameters.recognized) ? parameters.recognized : [];
                var unrecognized = Array.isArray(parameters.unrecognized) ? parameters.unrecognized : [];
                var rows = recognized.concat(unrecognized);
                parametersBody.textContent = "";
                if (!rows.length) {
                    parameterSection.hidden = true;
                    return;
                }
                rows.forEach(function (item) {
                    var row = document.createElement("tr");
                    appendCell(row, item.name);
                    appendCell(row, item.status, "status-text");
                    appendCell(row, item.source);
                    appendCell(row, valueSummary(item), "value-cell");
                    appendCell(row, item.effective_value, "value-cell");
                    appendCell(row, item.note, "value-cell");
                    parametersBody.appendChild(row);
                });
                parameterSection.hidden = false;
            }

            function renderEffectiveConfig(effectiveConfig) {
                var sections = Array.isArray(effectiveConfig.sections) ? effectiveConfig.sections : [];
                configBody.textContent = "";
                if (!sections.length) {
                    configSection.hidden = true;
                    return;
                }
                sections.forEach(function (section) {
                    var row = document.createElement("tr");
                    appendCell(row, section.name);
                    appendCell(row, section.status, "status-text");
                    appendCell(row, section.source);
                    appendCell(row, section.detail, "value-cell");
                    configBody.appendChild(row);
                });
                configSection.hidden = false;
            }

            function renderProviders(providers) {
                providersBody.textContent = "";
                if (!providers.length) {
                    providerSection.hidden = true;
                    return;
                }
                providers.forEach(function (provider) {
                    var row = document.createElement("tr");
                    [provider.name || "-", provider.source_hash || "-", provider.path || "-", provider.filter || provider.exclude_filter || "-", String(provider.interval || "-")].forEach(function (value) {
                        var cell = document.createElement("td");
                        cell.textContent = value;
                        row.appendChild(cell);
                    });
                    providersBody.appendChild(row);
                });
                providerSection.hidden = false;
            }

            function renderReport(report) {
                var mode = report.mode || {};
                var inputs = report.inputs || {};
                var nodes = report.nodes || {};
                var external = report.external_config || {};
                var parameters = report.parameters || {};
                var effectiveConfig = report.effective_config || {};
                var output = report.output || {};
                var resources = report.resources || {};
                var providers = Array.isArray(report.providers) ? report.providers : [];
                var recognized = Array.isArray(parameters.recognized) ? parameters.recognized : [];
                var unrecognized = Array.isArray(parameters.unrecognized) ? parameters.unrecognized : [];
                var sections = Array.isArray(effectiveConfig.sections) ? effectiveConfig.sections : [];
                var changedParameters = recognized.filter(function (item) {
                    return item.status === "overridden" || item.status === "suppressed" || item.status === "ignored" || item.status === "invalid";
                }).length;

                setText("metric-target", report.target || "-");
                setText("metric-providers", String(output.provider_count || providers.length || 0));
                setText("metric-nodes", String(nodes.total || 0));
                setText("metric-output", formatBytes(output.bytes));
                setText("metric-parameters", String(recognized.length) + (unrecognized.length ? "+" + String(unrecognized.length) : ""));
                setText("metric-config", String(sections.length));

                stateLine.textContent = "";
                stateLine.appendChild(tag((report.ok ? "HTTP " : "HTTP ") + (report.status_code || "-"), report.ok ? "" : "error"));
                stateLine.appendChild(tag(mode.proxy_provider ? "proxy-provider" : "direct nodes", mode.proxy_provider ? "" : "warn"));
                stateLine.appendChild(tag(external.loaded ? text("config loaded", "配置已加载") : text("config not loaded", "配置未加载"), external.loaded ? "" : "warn"));
                stateLine.appendChild(tag(text("rulesets ", "规则集 ") + (resources.ruleset_count || 0)));
                stateLine.appendChild(tag(text("subscriptions ", "订阅 ") + (inputs.subscription_url_count || 0)));
                stateLine.appendChild(tag(text("params ", "参数 ") + recognized.length));
                if (changedParameters) {
                    stateLine.appendChild(tag(text("changed ", "变更 ") + changedParameters, "warn"));
                }
                if (unrecognized.length) {
                    stateLine.appendChild(tag(text("unknown ", "未知 ") + unrecognized.length, "warn"));
                }
                if (mode.upload_suppressed) {
                    stateLine.appendChild(tag(text("upload suppressed", "上传已抑制"), "warn"));
                }

                renderParameters(parameters);
                renderEffectiveConfig(effectiveConfig);
                renderProviders(providers);
                jsonOutput.textContent = JSON.stringify(report, null, 2);
                summarySection.hidden = false;
                jsonSection.hidden = false;
                emptySection.hidden = true;
            }

            async function inspectRequest() {
                var url;
                try {
                    url = normalizeRequest(input.value);
                } catch (error) {
                    showError(text("Invalid request URL", "请求链接无效"), String(error && error.message || error));
                    return;
                }

                runButton.disabled = true;
                try {
                    var response = await fetch(url.toString(), {
                        headers: { "Accept": "application/json" },
                        cache: "no-store"
                    });
                    var textBody = await response.text();
                    var report;
                    try {
                        report = JSON.parse(textBody);
                    } catch (error) {
                        showError(text("Response is not JSON", "响应不是 JSON"), textBody);
                        return;
                    }
                    renderReport(report);
                } catch (error) {
                    showError(text("Request failed", "请求失败"), String(error && error.message || error));
                } finally {
                    runButton.disabled = false;
                    updateResolvedUrl();
                }
            }

            document.querySelector(".lang-toggle").addEventListener("click", function () {
                document.documentElement.lang = isZh() ? "en" : "zh-CN";
                updateResolvedUrl();
            });

            input.addEventListener("input", updateResolvedUrl);
            runButton.addEventListener("click", inspectRequest);
            sampleButton.addEventListener("click", function () {
                input.value = sampleQuery;
                updateResolvedUrl();
            });
            clearButton.addEventListener("click", function () {
                input.value = "";
                updateResolvedUrl();
                summarySection.hidden = true;
                parameterSection.hidden = true;
                configSection.hidden = true;
                providerSection.hidden = true;
                jsonSection.hidden = true;
                emptySection.hidden = false;
                input.focus();
            });

            input.value = sampleQuery;
            updateResolvedUrl();
        })();
    </script>
</body>
</html>)html";
}

} // namespace inspect_page
