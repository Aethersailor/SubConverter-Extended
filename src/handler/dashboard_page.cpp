#include "handler/dashboard_page.h"

namespace dashboard_page {

std::string page(Request &, Response &response) {
  response.headers["Cache-Control"] =
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, "
      "s-maxage=0";
  response.headers["Pragma"] = "no-cache";
  response.headers["Expires"] = "0";
  response.headers["Surrogate-Control"] = "no-store";
  response.headers["X-Accel-Expires"] = "0";
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";

  return R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
    <meta name="color-scheme" content="light dark">
    <title>SubConverter-Extended Dashboard</title>
    <script>
        (function () {
            var saved = localStorage.getItem("sce-dashboard-lang");
            if (saved) {
                document.documentElement.lang = saved;
                return;
            }
            var languages = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ""];
            document.documentElement.lang = languages.some(function (language) { return /^zh\b/i.test(language); }) ? "zh-CN" : "en";
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
            --surface: rgba(255, 255, 255, 0.82);
            --surface-strong: rgba(255, 255, 255, 0.92);
            --surface-border: rgba(15, 23, 42, 0.1);
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --text-muted: #64748b;
            --accent: #0284c7;
            --accent-2: #65a30d;
            --accent-gradient: linear-gradient(135deg, #0284c7 0%, #0891b2 45%, #65a30d 100%);
            --shadow: 0 28px 70px rgba(15, 23, 42, 0.13);
            --control-bg: rgba(255, 255, 255, 0.72);
            --control-hover: rgba(255, 255, 255, 0.92);
            --control-border: rgba(26, 32, 44, 0.12);
            --map-stroke: rgba(255, 255, 255, 0.85);
            --map-empty: #d7e1ec;
            --map-data-min: #38bdf8;
            --map-data-mid: #0ea5e9;
            --map-data-max: #166534;
            --chart-requests: linear-gradient(180deg, #0284c7 0%, #0891b2 52%, #65a30d 100%);
            --chart-rules: linear-gradient(180deg, #7c3aed 0%, #2563eb 48%, #0891b2 100%);
            --rank-track: rgba(15, 23, 42, 0.08);
            --rank-request: linear-gradient(90deg, #0ea5e9 0%, #65a30d 100%);
            --rank-rule: linear-gradient(90deg, #7c3aed 0%, #0891b2 100%);
            --danger: #dc2626;
            --warn: #b45309;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-gradient: linear-gradient(135deg, #05070b 0%, #0d111a 46%, #111827 100%);
                --bg-grid: rgba(148, 163, 184, 0.075);
                --bg-sheen: linear-gradient(115deg, transparent 0%, transparent 31%, rgba(34, 211, 238, 0.12) 47%, rgba(132, 204, 22, 0.08) 58%, transparent 74%, transparent 100%);
                --surface: rgba(15, 23, 42, 0.72);
                --surface-strong: rgba(21, 29, 43, 0.9);
                --surface-border: rgba(148, 163, 184, 0.18);
                --text-primary: #f8f9fa;
                --text-secondary: #a0aec0;
                --text-muted: #7f8ea3;
                --accent: #38bdf8;
                --accent-2: #84cc16;
                --accent-gradient: linear-gradient(135deg, #38bdf8 0%, #22d3ee 42%, #84cc16 100%);
                --shadow: 0 32px 80px rgba(0, 0, 0, 0.62);
                --control-bg: rgba(20, 24, 33, 0.7);
                --control-hover: rgba(35, 42, 56, 0.86);
                --control-border: rgba(255, 255, 255, 0.16);
                --map-stroke: rgba(2, 6, 23, 0.9);
                --map-empty: #273449;
                --map-data-min: #22d3ee;
                --map-data-mid: #38bdf8;
                --map-data-max: #84cc16;
                --chart-requests: linear-gradient(180deg, #38bdf8 0%, #22d3ee 45%, #84cc16 100%);
                --chart-rules: linear-gradient(180deg, #a78bfa 0%, #60a5fa 48%, #22d3ee 100%);
                --rank-track: rgba(148, 163, 184, 0.16);
                --rank-request: linear-gradient(90deg, #22d3ee 0%, #84cc16 100%);
                --rank-rule: linear-gradient(90deg, #a78bfa 0%, #22d3ee 100%);
                --danger: #f87171;
                --warn: #fbbf24;
            }
        }

        html[lang^="zh"] [data-lang="en"],
        html:not([lang^="zh"]) [data-lang="zh"] { display: none; }

        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Outfit', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", sans-serif;
            color: var(--text-primary);
            background: var(--bg-gradient);
            background-attachment: fixed;
            -webkit-font-smoothing: antialiased;
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
            background-image: linear-gradient(var(--bg-grid) 1px, transparent 1px), linear-gradient(90deg, var(--bg-grid) 1px, transparent 1px);
            background-size: 36px 36px;
            mask-image: linear-gradient(to bottom, transparent 0%, #000 18%, #000 82%, transparent 100%);
            -webkit-mask-image: linear-gradient(to bottom, transparent 0%, #000 18%, #000 82%, transparent 100%);
            opacity: 0.58;
        }
        body::after { background: var(--bg-sheen); opacity: 0.82; }

        .shell {
            position: relative;
            z-index: 1;
            width: min(1180px, calc(100% - 32px));
            margin: 0 auto;
            padding: 28px 0 42px;
        }
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
            min-width: 0;
        }
        .brand img {
            width: 48px;
            height: 48px;
            flex: 0 0 auto;
            filter: drop-shadow(0 12px 24px rgba(2, 132, 199, 0.16));
        }
        h1 {
            margin: 0;
            font-size: 1.8rem;
            line-height: 1.08;
            letter-spacing: 0;
            overflow-wrap: anywhere;
        }
        .subtitle {
            margin-top: 5px;
            color: var(--text-secondary);
            font-size: 0.94rem;
            font-weight: 600;
        }
        .actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        button {
            border: 1px solid var(--control-border);
            background: var(--control-bg);
            color: var(--text-primary);
            border-radius: 999px;
            min-height: 40px;
            padding: 9px 13px;
            font: inherit;
            font-size: 0.88rem;
            font-weight: 700;
            cursor: pointer;
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            transition: background 0.2s ease, transform 0.2s ease;
        }
        button:hover { background: var(--control-hover); transform: translateY(-1px); }
        button:focus-visible { outline: 3px solid rgba(99, 179, 237, 0.35); outline-offset: 2px; }

        .panel {
            background: var(--surface);
            border: 1px solid var(--surface-border);
            box-shadow: var(--shadow);
            border-radius: 28px;
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            overflow: hidden;
        }
        .overview {
            padding: 24px;
            display: grid;
            gap: 18px;
        }
        .stat-block {
            min-width: 0;
            padding: 0 0 18px;
            border-bottom: 1px solid var(--surface-border);
        }
        .stat-block:last-child { border-bottom: 0; padding-bottom: 0; }
        .block-head {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 14px;
            margin-bottom: 14px;
        }
        .block-copy {
            margin-top: 5px;
            color: var(--text-muted);
            font-size: 0.86rem;
            font-weight: 650;
            line-height: 1.45;
        }
        .runtime-grid,
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
        }
        .metric-grid.two-up { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .window-grid {
            display: grid;
            grid-template-columns: minmax(280px, 0.9fr) minmax(0, 1.1fr);
            gap: 14px;
            align-items: stretch;
        }
        .metric {
            min-height: 116px;
            padding: 17px;
            border: 1px solid var(--surface-border);
            border-radius: 18px;
            background: rgba(255, 255, 255, 0.32);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        @media (prefers-color-scheme: dark) {
            .metric { background: rgba(255, 255, 255, 0.045); }
        }
        .metric-label {
            color: var(--text-muted);
            font-weight: 700;
            font-size: 0.78rem;
            text-transform: uppercase;
        }
        .metric-label.no-caps { text-transform: none; }
        .metric-value {
            margin-top: 12px;
            font-size: 1.8rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: 0;
        }
        .metric-sub {
            margin-top: 10px;
            color: var(--text-secondary);
            font-size: 0.86rem;
            font-weight: 650;
        }
        .metric-help {
            margin-top: 10px;
            color: var(--text-muted);
            font-size: 0.78rem;
            line-height: 1.42;
        }
        .metric-pair {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-top: 10px;
        }
        .metric-pair strong {
            display: block;
            font-size: 1.55rem;
            line-height: 1;
        }
        .metric-pair span {
            display: block;
            margin-top: 7px;
            color: var(--text-secondary);
            font-size: 0.82rem;
            font-weight: 700;
        }
        .range-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: flex-end;
        }
        .range-tab {
            min-height: 34px;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 0.78rem;
        }
        .range-tab[aria-pressed="true"] {
            color: #ffffff;
            border-color: transparent;
            background: var(--accent-gradient);
            box-shadow: 0 10px 24px rgba(2, 132, 199, 0.22);
        }
        .window-strip {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
        }
        .mini-window {
            min-height: 84px;
            padding: 13px;
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            background: rgba(255, 255, 255, 0.24);
        }
        @media (prefers-color-scheme: dark) {
            .mini-window { background: rgba(255, 255, 255, 0.035); }
        }
        .mini-window .metric-value { font-size: 1.25rem; margin-top: 9px; }
        .mini-window .metric-sub { font-size: 0.78rem; margin-top: 8px; }
        .content {
            display: grid;
            grid-template-columns: 1fr;
            gap: 22px;
            padding: 0 24px 24px;
        }
        .section {
            border-top: 1px solid var(--surface-border);
            padding-top: 22px;
            min-width: 0;
        }
        .section-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 14px;
        }
        h2 {
            margin: 0;
            font-size: 1.05rem;
            letter-spacing: 0;
        }
        .state-line {
            color: var(--text-muted);
            font-size: 0.86rem;
            font-weight: 650;
        }
        .hourly-grid,
        .ranking-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 16px;
        }
        .chart-card,
        .ranking-card {
            border: 1px solid var(--surface-border);
            border-radius: 20px;
            background: var(--surface-strong);
            overflow: hidden;
            min-width: 0;
        }
        .chart-card-head,
        .ranking-card-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 16px 0;
        }
        .chart-card h3,
        .ranking-card h3 {
            margin: 0;
            font-size: 0.94rem;
            letter-spacing: 0;
        }
        .map-wrap {
            position: relative;
            min-height: 500px;
            border: 1px solid var(--surface-border);
            border-radius: 20px;
            background: var(--surface-strong);
            overflow: hidden;
        }
        #world-map {
            width: 100%;
            height: 500px;
            display: block;
        }
        .country {
            fill: var(--country-fill, var(--map-empty));
            stroke: var(--map-stroke);
            stroke-width: 0.34;
            transition: fill 0.35s ease, opacity 0.16s ease;
        }
        .country.has-data { cursor: pointer; }
        .country.has-data {
            stroke-width: 0.42;
        }
        .country:hover { opacity: 0.82; }
        .map-legend {
            position: absolute;
            left: 16px;
            bottom: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            border-radius: 999px;
            border: 1px solid var(--surface-border);
            background: color-mix(in srgb, var(--surface-strong) 88%, transparent);
            color: var(--text-muted);
            font-size: 0.78rem;
            font-weight: 750;
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
        }
        .legend-swatch {
            width: 34px;
            height: 9px;
            border-radius: 999px;
            background: linear-gradient(90deg, var(--map-empty) 0 28%, var(--map-data-min) 38%, var(--map-data-mid) 65%, var(--map-data-max) 100%);
        }
        .tooltip {
            position: absolute;
            pointer-events: none;
            min-width: 170px;
            padding: 10px 12px;
            border-radius: 14px;
            border: 1px solid var(--surface-border);
            background: var(--surface-strong);
            color: var(--text-primary);
            box-shadow: 0 18px 36px rgba(15, 23, 42, 0.22);
            transform: translate(-50%, calc(-100% - 12px));
            opacity: 0;
            transition: opacity 0.12s ease;
            font-size: 0.86rem;
            z-index: 3;
        }
        .tooltip.show { opacity: 1; }
        .tooltip-title { font-weight: 800; margin-bottom: 4px; }
        .tooltip-row { color: var(--text-secondary); display: flex; justify-content: space-between; gap: 14px; }
        .chart {
            height: 170px;
            display: flex;
            align-items: end;
            gap: 5px;
            padding: 18px 14px 12px;
            border: 1px solid var(--surface-border);
            border-width: 0;
            border-radius: 0;
            background: transparent;
        }
        .bar {
            flex: 1 1 0;
            min-width: 4px;
            border-radius: 5px 5px 2px 2px;
            background: var(--chart-requests);
            opacity: 0.88;
            transition: height 0.38s ease, opacity 0.18s ease;
        }
        .bar.rule-bar { background: var(--chart-rules); }
        .ranking-list {
            display: grid;
            gap: 10px;
            padding: 14px 16px 16px;
        }
        .ranking-row {
            display: grid;
            grid-template-columns: minmax(160px, 1fr) minmax(120px, 0.65fr);
            align-items: center;
            gap: 12px;
            min-height: 52px;
        }
        .rank-country {
            display: flex;
            align-items: center;
            min-width: 0;
            font-weight: 750;
        }
        .rank-country-name {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .rank-metric {
            display: grid;
            gap: 6px;
            min-width: 0;
        }
        .rank-values {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            color: var(--text-secondary);
            font-size: 0.84rem;
            font-weight: 750;
        }
        .rank-bar-track {
            width: 100%;
            height: 8px;
            border-radius: 999px;
            background: var(--rank-track);
            overflow: hidden;
        }
        .rank-bar-fill {
            width: var(--rank-width, 0%);
            height: 100%;
            border-radius: inherit;
            background: var(--rank-request);
            transition: width 0.42s ease;
        }
        .rank-bar-fill.rule { background: var(--rank-rule); }
        .country-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 26px;
            margin-right: 8px;
            font-size: 1.08rem;
            line-height: 1;
            vertical-align: -0.08em;
        }
        .code-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 34px;
            height: 24px;
            border-radius: 999px;
            background: color-mix(in srgb, var(--accent) 16%, transparent);
            color: var(--text-primary);
            font-size: 0.75rem;
            font-weight: 800;
            margin-right: 8px;
        }
        .status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 7px 10px;
            border-radius: 999px;
            background: color-mix(in srgb, var(--accent) 12%, transparent);
            color: var(--text-primary);
            font-size: 0.82rem;
            font-weight: 750;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--accent-2);
        }
        .empty {
            padding: 30px;
            color: var(--text-muted);
            text-align: center;
            font-weight: 650;
        }
        .empty.compact {
            padding: 14px;
            text-align: left;
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
                transition-duration: 0.01ms !important;
            }
        }
        @media (max-width: 980px) {
            .runtime-grid, .metric-grid, .window-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .window-grid { grid-template-columns: 1fr; }
            .hourly-grid, .ranking-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
            .shell { width: min(100% - 20px, 1180px); padding-top: 16px; }
            .topbar { align-items: flex-start; flex-direction: column; }
            .overview { padding: 14px; }
            .runtime-grid, .metric-grid, .window-strip { grid-template-columns: 1fr; }
            .metric-grid.two-up, .metric-pair { grid-template-columns: 1fr; }
            .block-head { align-items: flex-start; flex-direction: column; }
            .range-tabs { justify-content: flex-start; }
            .metric { min-height: 112px; padding: 14px; }
            .metric-value { font-size: 1.42rem; }
            .content { padding: 0 14px 14px; }
            #world-map, .map-wrap { min-height: 320px; height: 320px; }
            .ranking-row { grid-template-columns: 1fr; gap: 8px; }
            .map-legend { left: 10px; right: 10px; justify-content: center; }
            h1 { font-size: 1.45rem; }
        }
    </style>
</head>
<body>
    <main class="shell">
        <div class="topbar">
            <div class="brand">
                <picture>
                    <source media="(prefers-color-scheme: dark)" srcset="/version/favicon-dark.svg">
                    <img src="/version/favicon-light.svg" alt="SubConverter-Extended" width="48" height="48" decoding="async">
                </picture>
                <div>
                    <h1><span data-lang="en">SubConverter-Extended Dashboard</span><span data-lang="zh">SubConverter-Extended 仪表盘</span></h1>
                    <div class="subtitle">
                        <span data-lang="en">Runtime conversion statistics</span>
                        <span data-lang="zh">运行期转换统计</span>
                    </div>
                </div>
            </div>
            <div class="actions">
                <button type="button" id="refresh-button">
                    <span data-lang="en">Refresh</span><span data-lang="zh">刷新</span>
                </button>
                <button type="button" id="lang-toggle">EN</button>
            </div>
        </div>

        <section class="panel">
            <div class="overview" id="metrics"></div>
            <div class="content">
                <section class="section">
                    <div class="section-head">
                        <h2><span data-lang="en">Last 24 Hours</span><span data-lang="zh">最近 24 小时</span></h2>
                        <span class="state-line" id="updated-at">-</span>
                    </div>
                    <div class="hourly-grid">
                        <article class="chart-card">
                            <div class="chart-card-head">
                                <h3><span data-lang="en">Requests</span><span data-lang="zh">请求</span></h3>
                                <span class="state-line" id="request-total">-</span>
                            </div>
                            <div class="chart" id="request-chart"></div>
                        </article>
                        <article class="chart-card">
                            <div class="chart-card-head">
                                <h3><span data-lang="en">Rules</span><span data-lang="zh">规则</span></h3>
                                <span class="state-line" id="rule-total">-</span>
                            </div>
                            <div class="chart" id="rule-chart"></div>
                        </article>
                    </div>
                </section>
                <section class="section">
                    <div class="section-head">
                        <div>
                            <h2><span data-lang="en">Country Distribution</span><span data-lang="zh">国家分布</span></h2>
                            <div class="state-line" id="country-range-label">-</div>
                        </div>
                        <div class="range-tabs" id="country-tabs"></div>
                        <span class="status"><span class="status-dot"></span><span id="country-status">-</span></span>
                    </div>
                    <div class="map-wrap">
                        <svg id="world-map" role="img" aria-label="World map"></svg>
                        <div class="map-legend">
                            <span>0</span>
                            <span class="legend-swatch"></span>
                            <span><span data-lang="en">High</span><span data-lang="zh">高</span></span>
                        </div>
                        <div class="tooltip" id="tooltip"></div>
                    </div>
                </section>
                <section class="section">
                    <div class="section-head">
                        <div>
                            <h2><span data-lang="en">Country Ranking</span><span data-lang="zh">国家排行</span></h2>
                            <div class="state-line" id="country-ranking-range">-</div>
                        </div>
                    </div>
                    <div class="ranking-grid">
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">Requests by Country</span><span data-lang="zh">国家请求排行</span></h3>
                                <span class="state-line" id="request-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="request-ranking"></div>
                        </article>
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">Rules by Country</span><span data-lang="zh">国家规则排行</span></h3>
                                <span class="state-line" id="rule-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="rule-ranking"></div>
                        </article>
                    </div>
                </section>
            </div>
        </section>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js"></script>
    <script>
        (function () {
            var ISO_N3 = {
                "004":"AF","008":"AL","010":"AQ","012":"DZ","016":"AS","020":"AD","024":"AO","028":"AG","031":"AZ","032":"AR","036":"AU","040":"AT","044":"BS","048":"BH","050":"BD","051":"AM","052":"BB","056":"BE","060":"BM","064":"BT","068":"BO","070":"BA","072":"BW","074":"BV","076":"BR","084":"BZ","086":"IO","090":"SB","092":"VG","096":"BN","100":"BG","104":"MM","108":"BI","112":"BY","116":"KH","120":"CM","124":"CA","132":"CV","136":"KY","140":"CF","144":"LK","148":"TD","152":"CL","156":"CN","158":"TW","162":"CX","166":"CC","170":"CO","174":"KM","175":"YT","178":"CG","180":"CD","184":"CK","188":"CR","191":"HR","192":"CU","196":"CY","203":"CZ","204":"BJ","208":"DK","212":"DM","214":"DO","218":"EC","222":"SV","226":"GQ","231":"ET","232":"ER","233":"EE","234":"FO","238":"FK","239":"GS","242":"FJ","246":"FI","248":"AX","250":"FR","254":"GF","258":"PF","260":"TF","262":"DJ","266":"GA","268":"GE","270":"GM","275":"PS","276":"DE","288":"GH","292":"GI","296":"KI","300":"GR","304":"GL","308":"GD","312":"GP","316":"GU","320":"GT","324":"GN","328":"GY","332":"HT","334":"HM","336":"VA","340":"HN","344":"HK","348":"HU","352":"IS","356":"IN","360":"ID","364":"IR","368":"IQ","372":"IE","376":"IL","380":"IT","384":"CI","388":"JM","392":"JP","398":"KZ","400":"JO","404":"KE","408":"KP","410":"KR","414":"KW","417":"KG","418":"LA","422":"LB","426":"LS","428":"LV","430":"LR","434":"LY","438":"LI","440":"LT","442":"LU","446":"MO","450":"MG","454":"MW","458":"MY","462":"MV","466":"ML","470":"MT","474":"MQ","478":"MR","480":"MU","484":"MX","492":"MC","496":"MN","498":"MD","499":"ME","500":"MS","504":"MA","508":"MZ","512":"OM","516":"NA","520":"NR","524":"NP","528":"NL","531":"CW","533":"AW","534":"SX","535":"BQ","540":"NC","548":"VU","554":"NZ","558":"NI","562":"NE","566":"NG","570":"NU","574":"NF","578":"NO","580":"MP","581":"UM","583":"FM","584":"MH","585":"PW","586":"PK","591":"PA","598":"PG","600":"PY","604":"PE","608":"PH","612":"PN","616":"PL","620":"PT","624":"GW","626":"TL","630":"PR","634":"QA","638":"RE","642":"RO","643":"RU","646":"RW","652":"BL","654":"SH","659":"KN","660":"AI","662":"LC","663":"MF","666":"PM","670":"VC","674":"SM","678":"ST","682":"SA","686":"SN","688":"RS","690":"SC","694":"SL","702":"SG","703":"SK","704":"VN","705":"SI","706":"SO","710":"ZA","716":"ZW","724":"ES","728":"SS","729":"SD","732":"EH","740":"SR","744":"SJ","748":"SZ","752":"SE","756":"CH","760":"SY","762":"TJ","764":"TH","768":"TG","772":"TK","776":"TO","780":"TT","784":"AE","788":"TN","792":"TR","795":"TM","796":"TC","798":"TV","800":"UG","804":"UA","807":"MK","818":"EG","826":"GB","831":"GG","832":"JE","833":"IM","834":"TZ","840":"US","850":"VI","854":"BF","858":"UY","860":"UZ","862":"VE","876":"WF","882":"WS","887":"YE","894":"ZM"
            };
            var metricsEl = document.getElementById("metrics");
            var countryStatus = document.getElementById("country-status");
            var countryTabs = document.getElementById("country-tabs");
            var countryRangeLabel = document.getElementById("country-range-label");
            var countryRankingRange = document.getElementById("country-ranking-range");
            var updatedAt = document.getElementById("updated-at");
            var requestChart = document.getElementById("request-chart");
            var ruleChart = document.getElementById("rule-chart");
            var requestTotal = document.getElementById("request-total");
            var ruleTotal = document.getElementById("rule-total");
            var requestRanking = document.getElementById("request-ranking");
            var ruleRanking = document.getElementById("rule-ranking");
            var requestRankingTotal = document.getElementById("request-ranking-total");
            var ruleRankingTotal = document.getElementById("rule-ranking-total");
            var tooltip = document.getElementById("tooltip");
            var mapData = null;
            var latest = null;
            var countryMap = new Map();
            var animatedValues = new Map();
            var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            var WINDOWS = [
                { key: "hour", en: "1 Hour", zh: "1 小时" },
                { key: "day", en: "1 Day", zh: "1 天" },
                { key: "seven_days", en: "7 Days", zh: "7 天" },
                { key: "thirty_days", en: "30 Days", zh: "30 天" }
            ];
            var COUNTRY_WINDOWS = [
                { key: "startup", en: "Since Start", zh: "本次启动" },
                { key: "hour", en: "1 Hour", zh: "1 小时" },
                { key: "day", en: "1 Day", zh: "1 天" },
                { key: "seven_days", en: "7 Days", zh: "7 天" },
                { key: "thirty_days", en: "30 Days", zh: "30 天" },
                { key: "lifetime", en: "Lifetime", zh: "历史总计" }
            ];
            var selectedWindow = localStorage.getItem("sce-dashboard-window") || "day";
            var selectedCountryWindow = localStorage.getItem("sce-dashboard-country-window") || "day";

            function isZh() { return /^zh\b/i.test(document.documentElement.lang); }
            function text(en, zh) { return isZh() ? zh : en; }
            function updateDocumentTitle() { document.title = text("SubConverter-Extended Dashboard", "SubConverter-Extended 仪表盘"); }
            function number(value) { return new Intl.NumberFormat(isZh() ? "zh-CN" : "en").format(value || 0); }
            function label(config) { return text(config.en, config.zh); }
            function windowConfig(key, source) {
                var list = source || COUNTRY_WINDOWS;
                return list.find(function (item) { return item.key === key; }) || list[0];
            }
            function countryName(code) {
                if (code === "ZZ" || code === "XX") return text("Unknown", "未知");
                if (code === "T1") return text("Tor network", "Tor 网络");
                try { return new Intl.DisplayNames([isZh() ? "zh-CN" : "en"], { type: "region" }).of(code) || code; }
                catch (error) { return code; }
            }
            function countryIcon(code) {
                if (!/^[A-Z]{2}$/.test(code) || code === "ZZ" || code === "XX") return String.fromCodePoint(0x25CC);
                return String.fromCodePoint(code.charCodeAt(0) + 127397, code.charCodeAt(1) + 127397);
            }
            function fmtTime(seconds) {
                if (!seconds) return "-";
                return new Intl.DateTimeFormat(isZh() ? "zh-CN" : "en", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(seconds * 1000));
            }
            function fmtDateTime(seconds) {
                if (!seconds) return "-";
                return new Intl.DateTimeFormat(isZh() ? "zh-CN" : "en", {
                    year: "numeric", month: "2-digit", day: "2-digit",
                    hour: "2-digit", minute: "2-digit", second: "2-digit"
                }).format(new Date(seconds * 1000));
            }
            function duration(seconds) {
                seconds = Math.max(0, Math.floor(Number(seconds) || 0));
                var days = Math.floor(seconds / 86400);
                var hours = Math.floor((seconds % 86400) / 3600);
                var minutes = Math.floor((seconds % 3600) / 60);
                var secs = seconds % 60;
                if (isZh()) {
                    if (days) return days + " 天 " + hours + " 小时";
                    if (hours) return hours + " 小时 " + minutes + " 分钟";
                    if (minutes) return minutes + " 分钟 " + secs + " 秒";
                    return secs + " 秒";
                }
                if (days) return days + "d " + hours + "h";
                if (hours) return hours + "h " + minutes + "m";
                if (minutes) return minutes + "m " + secs + "s";
                return secs + "s";
            }
            function percentage(value, total) {
                if (!total) return "0%";
                var pct = (value || 0) * 100 / total;
                if (pct > 0 && pct < 0.1) return "<0.1%";
                return pct.toFixed(1) + "%";
            }
            function countValue(key, value) {
                return '<span data-count-key="' + key + '" data-count-value="' + (Number(value) || 0) + '">' + number(value) + '</span>';
            }
            function animateCounters(root) {
                root.querySelectorAll("[data-count-key]").forEach(function (node) {
                    var key = node.getAttribute("data-count-key");
                    var target = Number(node.getAttribute("data-count-value")) || 0;
                    var start = animatedValues.has(key) ? animatedValues.get(key) : target;
                    animatedValues.set(key, target);
                    if (reduceMotion || start === target) {
                        node.textContent = number(target);
                        return;
                    }
                    var started = performance.now();
                    var durationMs = 420;
                    function step(now) {
                        var progress = Math.min(1, (now - started) / durationMs);
                        var eased = 1 - Math.pow(1 - progress, 3);
                        node.textContent = number(Math.round(start + (target - start) * eased));
                        if (progress < 1)
                            requestAnimationFrame(step);
                        else
                            node.textContent = number(target);
                    }
                    requestAnimationFrame(step);
                });
            }
            function rangeTabsHtml(source, selected, attr) {
                return source.map(function (item) {
                    return '<button type="button" class="range-tab" aria-pressed="' + (item.key === selected ? "true" : "false") + '" ' + attr + '="' + item.key + '">' + label(item) + '</button>';
                }).join("");
            }
            function updateRangeTabs(container, attr, selected) {
                container.querySelectorAll("[" + attr + "]").forEach(function (button) {
                    button.setAttribute("aria-pressed", button.getAttribute(attr) === selected ? "true" : "false");
                });
            }
            function countersPairHtml(titleEn, titleZh, counters, helpEn, helpZh) {
                counters = counters || {};
                var keyPrefix = "metric:" + titleEn.toLowerCase().replace(/[^a-z0-9]+/g, "-");
                return '<article class="metric">' +
                    '<div class="metric-label">' + text(titleEn, titleZh) + '</div>' +
                    '<div class="metric-pair">' +
                    '<div><strong>' + countValue(keyPrefix + ":requests", counters.subscription_requests) + '</strong><span>' + text("Requests", "请求") + '</span></div>' +
                    '<div><strong>' + countValue(keyPrefix + ":rules", counters.rule_conversions) + '</strong><span>' + text("Rules", "规则") + '</span></div>' +
                    '</div>' +
                    '<div class="metric-help">' + text(helpEn, helpZh) + '</div>' +
                    '</article>';
            }
            function runtimeCardHtml(titleEn, titleZh, value, helpEn, helpZh) {
                return '<article class="metric">' +
                    '<div class="metric-label no-caps">' + text(titleEn, titleZh) + '</div>' +
                    '<div class="metric-value">' + value + '</div>' +
                    '<div class="metric-help">' + text(helpEn, helpZh) + '</div>' +
                    '</article>';
            }
            function miniWindowHtml(config, counters) {
                counters = counters || {};
                return '<article class="mini-window">' +
                    '<div class="metric-label">' + label(config) + '</div>' +
                    '<div class="metric-value">' + countValue("window:" + config.key + ":requests", counters.subscription_requests) + '</div>' +
                    '<div class="metric-sub">' + text("Rules ", "规则 ") + countValue("window:" + config.key + ":rules", counters.rule_conversions) + '</div>' +
                    '</article>';
            }
            function renderMetrics(data) {
                var windows = data.windows || {};
                var runtime = data.runtime || {};
                var selected = windowConfig(selectedWindow, WINDOWS);
                selectedWindow = selected.key;
                metricsEl.innerHTML =
                    '<section class="stat-block">' +
                    '<div class="block-head"><div><h2>' + text("Runtime", "运行状态") + '</h2>' +
                    '<div class="block-copy">' + text("Service uptime and persisted runtime summary", "服务运行与累计运行概览") + '</div></div></div>' +
                    '<div class="runtime-grid">' +
                    runtimeCardHtml("Started", "本次启动时间", fmtDateTime(runtime.started_at || data.started_at), "Current process start time.", "当前进程启动时间。") +
                    runtimeCardHtml("Uptime", "本次运行时长", duration(runtime.uptime_seconds), "Time since this process started.", "从本次进程启动到现在的时长。") +
                    runtimeCardHtml("Total Runtime", "累计运行时长", duration(runtime.total_runtime_seconds), "Persisted across restarts.", "跨重启持久化累计。") +
                    runtimeCardHtml("Launches", "启动次数", number(runtime.launch_count), "Number of launches recorded in the statistics file.", "统计文件记录到的启动次数。") +
                    '</div></section>' +
                    '<section class="stat-block"><div class="block-head"><div><h2>' + text("Conversion Totals", "转换总览") + '</h2>' +
                    '<div class="block-copy">' + text("Requests and rule conversions by scope", "按统计范围查看请求与规则转换") + '</div></div></div>' +
                    '<div class="metric-grid two-up">' +
                    countersPairHtml("Since Start", "本次启动", windows.startup, "Only conversions after the current process started.", "仅统计当前进程启动后的转换。") +
                    countersPairHtml("Lifetime", "历史总计", windows.lifetime, "Persisted conversion totals since the statistics file was created.", "统计文件创建以来持久化累计的转换。") +
                    '</div></section>' +
                    '<section class="stat-block"><div class="block-head"><div><h2>' + text("Rolling Windows", "滚动时间窗") + '</h2>' +
                    '<div class="block-copy">' + text("Recent activity across selectable time ranges", "按时间范围查看近期活跃度") + '</div></div>' +
                    '<div class="range-tabs">' + rangeTabsHtml(WINDOWS, selectedWindow, "data-window-select") + '</div></div>' +
                    '<div class="window-grid">' +
                    countersPairHtml(selected.en, selected.zh, windows[selected.key], "Selected rolling window.", "当前选中的滚动时间窗。") +
                    '<div class="window-strip">' + WINDOWS.map(function (item) { return miniWindowHtml(item, windows[item.key]); }).join("") + '</div>' +
                    '</div></section>';
                animateCounters(metricsEl);

                metricsEl.querySelectorAll("[data-window-select]").forEach(function (button) {
                    button.addEventListener("click", function () {
                        selectedWindow = button.getAttribute("data-window-select");
                        localStorage.setItem("sce-dashboard-window", selectedWindow);
                        renderMetrics(latest || data);
                    });
                });
            }
            function renderHourlyChart(container, series, field, className, labelEn, labelZh) {
                container.textContent = "";
                if (!series.length) {
                    var empty = document.createElement("div");
                    empty.className = "empty compact";
                    empty.textContent = text("No hourly data", "暂无小时数据");
                    container.appendChild(empty);
                    return;
                }
                var max = Math.max(1, ...series.map(function (item) { return item[field] || 0; }));
                series.forEach(function (item) {
                    var value = item[field] || 0;
                    var bar = document.createElement("div");
                    bar.className = "bar " + className;
                    bar.style.height = "4px";
                    bar.title = fmtTime(item.time) + " / " + text(labelEn, labelZh) + " " + number(value);
                    container.appendChild(bar);
                    var targetHeight = Math.max(4, Math.round((value / max) * 132)) + "px";
                    requestAnimationFrame(function () { bar.style.height = targetHeight; });
                });
            }
            function renderHourlyCharts(series) {
                series = series || [];
                var requests = series.reduce(function (sum, item) { return sum + (item.subscription_requests || 0); }, 0);
                var rules = series.reduce(function (sum, item) { return sum + (item.rule_conversions || 0); }, 0);
                requestTotal.innerHTML = text("Total ", "合计 ") + countValue("hourly:requests", requests);
                ruleTotal.innerHTML = text("Total ", "合计 ") + countValue("hourly:rules", rules);
                animateCounters(requestTotal);
                animateCounters(ruleTotal);
                renderHourlyChart(requestChart, series, "subscription_requests", "request-bar", "Requests", "请求");
                renderHourlyChart(ruleChart, series, "rule_conversions", "rule-bar", "Rules", "规则");
            }
            function selectedCountries(data) {
                var windows = data.country_windows || {};
                return windows[selectedCountryWindow] || data.countries || [];
            }
            function renderCountryTabs() {
                selectedCountryWindow = windowConfig(selectedCountryWindow, COUNTRY_WINDOWS).key;
                countryTabs.innerHTML = rangeTabsHtml(COUNTRY_WINDOWS, selectedCountryWindow, "data-country-window");
                countryTabs.querySelectorAll("[data-country-window]").forEach(function (button) {
                    button.addEventListener("click", function () {
                        selectedCountryWindow = button.getAttribute("data-country-window");
                        localStorage.setItem("sce-dashboard-country-window", selectedCountryWindow);
                        updateRangeTabs(countryTabs, "data-country-window", selectedCountryWindow);
                        if (latest) {
                            renderCountries(selectedCountries(latest));
                            renderMap();
                        }
                    });
                });
            }
            function renderRankingPanel(container, countries, field, total, emptyMessageEn, emptyMessageZh) {
                container.textContent = "";
                var ranked = countries.filter(function (item) { return (item[field] || 0) > 0; })
                    .sort(function (a, b) { return (b[field] || 0) - (a[field] || 0); })
                    .slice(0, 12);
                if (!ranked.length) {
                    var empty = document.createElement("div");
                    empty.className = "empty compact";
                    empty.textContent = text(emptyMessageEn, emptyMessageZh);
                    container.appendChild(empty);
                    return;
                }
                var max = Math.max(1, ...ranked.map(function (item) { return item[field] || 0; }));
                ranked.forEach(function (item) {
                    var value = item[field] || 0;
                    var row = document.createElement("div");
                    row.className = "ranking-row";

                    var country = document.createElement("div");
                    country.className = "rank-country";
                    country.innerHTML = '<span class="country-icon">' + countryIcon(item.code) + '</span><span class="code-badge">' + item.code + '</span><span class="rank-country-name">' + countryName(item.code) + '</span>';

                    var metric = document.createElement("div");
                    metric.className = "rank-metric";
                    var values = document.createElement("div");
                    values.className = "rank-values";
                    values.innerHTML = '<span>' + countValue("rank:" + field + ":" + item.code, value) + '</span><span>' + percentage(value, total) + '</span>';
                    var track = document.createElement("div");
                    track.className = "rank-bar-track";
                    var fill = document.createElement("div");
                    fill.className = "rank-bar-fill" + (field === "rule_conversions" ? " rule" : "");
                    fill.style.setProperty("--rank-width", "0%");
                    track.appendChild(fill);
                    metric.appendChild(values);
                    metric.appendChild(track);
                    row.appendChild(country);
                    row.appendChild(metric);
                    container.appendChild(row);
                    requestAnimationFrame(function () {
                        fill.style.setProperty("--rank-width", Math.max(4, Math.round((value / max) * 100)) + "%");
                    });
                });
                animateCounters(container);
            }
            function renderCountries(countries) {
                countryMap = new Map();
                countries.forEach(function (item) { countryMap.set(item.code, item); });
                var countryConfig = windowConfig(selectedCountryWindow, COUNTRY_WINDOWS);
                selectedCountryWindow = countryConfig.key;
                updateRangeTabs(countryTabs, "data-country-window", selectedCountryWindow);
                var visibleCountries = countries.filter(function (item) { return item.code !== "ZZ" && item.code !== "XX"; });
                var totalRequests = countries.reduce(function (sum, item) { return sum + (item.subscription_requests || 0); }, 0);
                var totalRules = countries.reduce(function (sum, item) { return sum + (item.rule_conversions || 0); }, 0);
                countryRangeLabel.textContent = text("Showing ", "当前范围：") + label(countryConfig);
                countryRankingRange.textContent = text("Showing ", "当前范围：") + label(countryConfig);
                countryStatus.textContent = text("Countries ", "国家 ") + number(visibleCountries.length);
                requestRankingTotal.innerHTML = text("Total ", "合计 ") + countValue("country:" + selectedCountryWindow + ":requests", totalRequests);
                ruleRankingTotal.innerHTML = text("Total ", "合计 ") + countValue("country:" + selectedCountryWindow + ":rules", totalRules);
                animateCounters(requestRankingTotal);
                animateCounters(ruleRankingTotal);
                renderRankingPanel(requestRanking, countries, "subscription_requests", totalRequests, "No request data in this range", "当前范围暂无请求数据");
                renderRankingPanel(ruleRanking, countries, "rule_conversions", totalRules, "No rule data in this range", "当前范围暂无规则数据");
            }
            function renderMap() {
                if (!mapData || !window.d3 || !window.topojson) return;
                var svg = d3.select("#world-map");
                var node = svg.node();
                var width = node.clientWidth || 800;
                var height = node.clientHeight || 430;
                var styles = getComputedStyle(document.documentElement);
                var emptyColor = styles.getPropertyValue("--map-empty").trim() || "#cbd5e1";
                var dataMinColor = styles.getPropertyValue("--map-data-min").trim() || "#22c7d9";
                var dataMidColor = styles.getPropertyValue("--map-data-mid").trim() || "#0ea5e9";
                var dataMaxColor = styles.getPropertyValue("--map-data-max").trim() || "#15803d";
                svg.attr("viewBox", "0 0 " + width + " " + height);
                svg.selectAll("*").remove();
                var projection = d3.geoNaturalEarth1().rotate([-105, 0]).fitSize([width, height], { type: "Sphere" });
                var path = d3.geoPath(projection);
                var features = topojson.feature(mapData, mapData.objects.countries).features;
                var max = Math.max(1, ...Array.from(countryMap.values()).map(function (item) { return item.subscription_requests || 0; }));
                var color = d3.interpolateRgbBasis([dataMinColor, dataMidColor, dataMaxColor]);
                function countryRequests(code) {
                    var item = countryMap.get(code);
                    return item ? item.subscription_requests || 0 : 0;
                }
                function countryFill(code) {
                    var requests = countryRequests(code);
                    if (requests < 1) return emptyColor;
                    if (max <= 1) return color(0.35);
                    return color(Math.log10(requests) / Math.log10(max));
                }
                svg.append("path").datum({ type: "Sphere" }).attr("d", path).attr("fill", "transparent");
                svg.selectAll("path.country")
                    .data(features)
                    .enter()
                    .append("path")
                    .attr("class", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        return "country" + (countryRequests(code) > 0 ? " has-data" : "");
                    })
                    .attr("d", path)
                    .style("--country-fill", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        return countryFill(code);
                    })
                    .on("mousemove", function (event, d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")] || "ZZ";
                        var item = countryMap.get(code) || { subscription_requests: 0, rule_conversions: 0 };
                        var countryConfig = windowConfig(selectedCountryWindow, COUNTRY_WINDOWS);
                        tooltip.innerHTML = '<div class="tooltip-title"><span class="country-icon">' + countryIcon(code) + '</span>' + countryName(code) + ' · ' + code + '</div>' +
                            '<div class="tooltip-row"><span>' + text("Range", "范围") + '</span><strong>' + label(countryConfig) + '</strong></div>' +
                            '<div class="tooltip-row"><span>' + text("Requests", "请求") + '</span><strong>' + number(item.subscription_requests) + '</strong></div>' +
                            '<div class="tooltip-row"><span>' + text("Rules", "规则") + '</span><strong>' + number(item.rule_conversions) + '</strong></div>';
                        tooltip.style.left = event.offsetX + "px";
                        tooltip.style.top = event.offsetY + "px";
                        tooltip.classList.add("show");
                    })
                    .on("mouseleave", function () { tooltip.classList.remove("show"); });
            }
            function render(data) {
                latest = data;
                renderMetrics(data);
                renderHourlyCharts(data.series || []);
                renderCountryTabs();
                renderCountries(selectedCountries(data));
                updatedAt.textContent = text("Updated ", "更新 ") + fmtTime(data.generated_at);
                renderMap();
            }
            async function refresh() {
                var response = await fetch("/dashboard/data?_=" + Date.now(), { cache: "no-store", headers: { "Accept": "application/json" } });
                render(await response.json());
            }
            document.getElementById("lang-toggle").addEventListener("click", function () {
                document.documentElement.lang = isZh() ? "en" : "zh-CN";
                localStorage.setItem("sce-dashboard-lang", document.documentElement.lang);
                updateDocumentTitle();
                document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
                if (latest) render(latest);
            });
            document.getElementById("refresh-button").addEventListener("click", refresh);
            updateDocumentTitle();
            document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
            Promise.all([
                fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(function (response) { return response.json(); }).catch(function () { return null; }),
                refresh()
            ]).then(function (values) {
                mapData = values[0];
                renderMap();
            });
            window.addEventListener("resize", function () { renderMap(); });
            setInterval(function () {
                if (document.visibilityState !== "hidden")
                    refresh();
            }, 30000);
        })();
    </script>
</body>
</html>)html";
}

} // namespace dashboard_page
