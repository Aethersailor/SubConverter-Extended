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
            --bg-sheen: linear-gradient(115deg, transparent 0%, transparent 33%, rgba(14, 165, 233, 0.1) 48%, rgba(37, 99, 235, 0.075) 60%, transparent 73%, transparent 100%);
            --surface: rgba(255, 255, 255, 0.82);
            --surface-strong: rgba(255, 255, 255, 0.92);
            --surface-border: rgba(15, 23, 42, 0.1);
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --text-muted: #64748b;
            --accent: #2563eb;
            --accent-2: #0ea5e9;
            --accent-gradient: linear-gradient(135deg, #0ea5e9 0%, #2563eb 58%, #1d4ed8 100%);
            --shadow: 0 28px 70px rgba(15, 23, 42, 0.13);
            --control-bg: rgba(255, 255, 255, 0.72);
            --control-hover: rgba(255, 255, 255, 0.92);
            --control-border: rgba(26, 32, 44, 0.12);
            --map-stroke: rgba(255, 255, 255, 0.85);
            --map-empty: #d7e1ec;
            --china-inset-fill: #b9cce0;
            --china-inset-frame-stroke: rgba(71, 85, 105, 0.58);
            --china-inset-stroke: rgba(30, 64, 175, 0.58);
            --map-data-min: #93c5fd;
            --map-data-mid: #2563eb;
            --map-data-max: #1e3a8a;
            --chart-requests: linear-gradient(180deg, #93c5fd 0%, #2563eb 58%, #1e3a8a 100%);
            --chart-rules: linear-gradient(180deg, #93c5fd 0%, #2563eb 58%, #1e3a8a 100%);
            --rank-track: rgba(15, 23, 42, 0.08);
            --rank-request: linear-gradient(90deg, #93c5fd 0%, #2563eb 62%, #1e3a8a 100%);
            --rank-rule: linear-gradient(90deg, #93c5fd 0%, #2563eb 62%, #1e3a8a 100%);
            --danger: #dc2626;
            --warn: #b45309;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg-gradient: linear-gradient(135deg, #05070b 0%, #0d111a 46%, #111827 100%);
                --bg-grid: rgba(148, 163, 184, 0.075);
                --bg-sheen: linear-gradient(115deg, transparent 0%, transparent 31%, rgba(56, 189, 248, 0.12) 47%, rgba(59, 130, 246, 0.09) 60%, transparent 74%, transparent 100%);
                --surface: rgba(15, 23, 42, 0.72);
                --surface-strong: rgba(21, 29, 43, 0.9);
                --surface-border: rgba(148, 163, 184, 0.18);
                --text-primary: #f8f9fa;
                --text-secondary: #a0aec0;
                --text-muted: #7f8ea3;
                --accent: #38bdf8;
                --accent-2: #60a5fa;
                --accent-gradient: linear-gradient(135deg, #38bdf8 0%, #2563eb 58%, #1d4ed8 100%);
                --shadow: 0 32px 80px rgba(0, 0, 0, 0.62);
                --control-bg: rgba(20, 24, 33, 0.7);
                --control-hover: rgba(35, 42, 56, 0.86);
                --control-border: rgba(255, 255, 255, 0.16);
                --map-stroke: rgba(2, 6, 23, 0.9);
                --map-empty: #273449;
                --china-inset-fill: #445f7a;
                --china-inset-frame-stroke: rgba(148, 163, 184, 0.55);
                --china-inset-stroke: rgba(125, 211, 252, 0.72);
                --map-data-min: #7dd3fc;
                --map-data-mid: #38bdf8;
                --map-data-max: #2563eb;
                --chart-requests: linear-gradient(180deg, #7dd3fc 0%, #38bdf8 56%, #2563eb 100%);
                --chart-rules: linear-gradient(180deg, #7dd3fc 0%, #38bdf8 56%, #2563eb 100%);
                --rank-track: rgba(148, 163, 184, 0.16);
                --rank-request: linear-gradient(90deg, #7dd3fc 0%, #38bdf8 58%, #2563eb 100%);
                --rank-rule: linear-gradient(90deg, #7dd3fc 0%, #38bdf8 58%, #2563eb 100%);
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
            flex-wrap: wrap;
            justify-content: flex-end;
        }
        .page-link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            min-height: 40px;
            border: 1px solid var(--control-border);
            border-radius: 999px;
            background: var(--control-bg);
            color: var(--text-primary);
            cursor: pointer;
            font: inherit;
            font-size: 0.88rem;
            font-weight: 800;
            line-height: 1;
            padding: 9px 13px;
            text-decoration: none;
            transition: background 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
        }
        .page-link:hover {
            background: var(--control-hover);
            transform: translateY(-1px);
        }
        .page-link:focus-visible {
            outline: 3px solid rgba(99, 179, 237, 0.35);
            outline-offset: 2px;
        }
        .page-link svg {
            width: 17px;
            height: 17px;
            flex: 0 0 auto;
            fill: none;
            stroke: currentColor;
            stroke-width: 1.9;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        .menu-wrap {
            position: relative;
            display: inline-flex;
        }
        .refresh-menu {
            position: absolute;
            top: calc(100% + 8px);
            right: 0;
            display: grid;
            gap: 5px;
            min-width: 138px;
            padding: 8px;
            border: 1px solid var(--surface-border);
            border-radius: 16px;
            background: var(--surface-strong);
            box-shadow: 0 18px 38px rgba(15, 23, 42, 0.18);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            z-index: 8;
        }
        .refresh-menu[hidden] { display: none; }
        .refresh-option {
            display: flex;
            align-items: center;
            width: 100%;
            min-height: 34px;
            justify-content: flex-start;
            border-radius: 11px;
            padding: 7px 10px;
            text-align: left;
            backdrop-filter: none;
            -webkit-backdrop-filter: none;
        }
        .refresh-option[aria-pressed="true"] {
            color: #ffffff;
            border-color: transparent;
            background: var(--accent-gradient);
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
        .conversion-totals { margin-bottom: 12px; }
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
            color: var(--text-primary);
        }
        .metric-pair strong span {
            display: inline;
            margin-top: 0;
            color: inherit;
            font-size: inherit;
            font-weight: inherit;
        }
        .metric-pair > div > span {
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
            grid-template-columns: repeat(6, minmax(0, 1fr));
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
        .section-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            flex-wrap: wrap;
            gap: 10px;
            margin-left: auto;
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
        .geo-section {
            display: grid;
            gap: 16px;
        }
        .hourly-grid,
        .map-grid,
        .ranking-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 16px;
        }
        .chart-card,
        .map-card,
        .ranking-card {
            border: 1px solid var(--surface-border);
            border-radius: 20px;
            background: var(--surface-strong);
            overflow: hidden;
            min-width: 0;
        }
        .chart-card-head,
        .map-card-head,
        .ranking-card-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 16px 0;
        }
        .chart-card h3,
        .map-card h3,
        .ranking-card h3 {
            margin: 0;
            font-size: 0.94rem;
            letter-spacing: 0;
        }
        .map-frame {
            position: relative;
            min-height: 420px;
            overflow: hidden;
        }
        .world-map {
            width: 100%;
            height: 420px;
            display: block;
        }
        .country,
        .china-region {
            fill: var(--country-fill, var(--map-empty));
            stroke: var(--map-stroke);
            stroke-width: 0.34;
            transition: fill 0.35s ease, opacity 0.16s ease;
        }
        .country.has-data,
        .china-region.has-data { cursor: pointer; }
        .country.has-data,
        .china-region.has-data {
            stroke-width: 0.42;
        }
        .country:hover,
        .china-region:hover { opacity: 0.82; }
        .china-south-sea-inset {
            pointer-events: all;
        }
        .china-inset-frame {
            fill: color-mix(in srgb, var(--surface-strong) 76%, transparent);
            stroke: var(--china-inset-frame-stroke);
            stroke-width: 1;
            vector-effect: non-scaling-stroke;
        }
        .china-south-sea {
            fill: var(--china-inset-fill);
            stroke: var(--china-inset-stroke);
            stroke-width: 1.15;
            vector-effect: non-scaling-stroke;
        }
        .china-region-label {
            fill: var(--text-secondary);
            font-size: 0.68rem;
            font-weight: 800;
            pointer-events: none;
            text-anchor: middle;
        }
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
            position: fixed;
            pointer-events: none;
            min-width: 170px;
            padding: 10px 12px;
            border-radius: 14px;
            border: 1px solid var(--surface-border);
            background: var(--surface-strong);
            color: var(--text-primary);
            box-shadow: 0 18px 36px rgba(15, 23, 42, 0.22);
            max-width: min(280px, calc(100vw - 24px));
            opacity: 0;
            transition: opacity 0.12s ease;
            font-size: 0.86rem;
            z-index: 10000;
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
        .code-badge.region-badge { width: 46px; }
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
        .page-footer {
            margin-top: 22px;
            padding-top: 18px;
            border-top: 1px solid var(--surface-border);
            color: var(--text-muted);
            font-size: 0.84rem;
            line-height: 1.55;
            text-align: center;
        }
        .page-footer a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 700;
        }
        .page-footer a:hover { color: var(--accent-2); }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
                transition-duration: 0.01ms !important;
            }
        }
        @media (max-width: 980px) {
            .runtime-grid, .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .window-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            .window-grid { grid-template-columns: 1fr; }
            .hourly-grid, .map-grid, .ranking-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
            .shell { width: min(100% - 20px, 1180px); padding-top: 16px; }
            .topbar { align-items: flex-start; flex-direction: column; }
            .overview { padding: 14px; }
            .runtime-grid, .metric-grid, .window-strip { grid-template-columns: 1fr; }
            .metric-grid.two-up, .metric-pair { grid-template-columns: 1fr; }
            .block-head { align-items: flex-start; flex-direction: column; }
            .range-tabs { justify-content: flex-start; }
            .section-actions { justify-content: flex-start; margin-left: 0; width: 100%; }
            .actions { justify-content: flex-start; }
            .refresh-menu { left: 0; right: auto; }
            .metric { min-height: 112px; padding: 14px; }
            .metric-value { font-size: 1.42rem; }
            .content { padding: 0 14px 14px; }
            .world-map, .map-frame { min-height: 320px; height: 320px; }
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
                <a class="page-link" href="/version" aria-label="Open version page">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M20.6 13.2 13.2 20.6a2 2 0 0 1-2.8 0L3.4 13.6a2 2 0 0 1-.6-1.4V5a2 2 0 0 1 2-2h7.2a2 2 0 0 1 1.4.6l7.2 7.2a2 2 0 0 1 0 2.8Z"></path>
                        <circle cx="7.5" cy="7.5" r="1.2"></circle>
                    </svg>
                    <span data-lang="en">Version</span><span data-lang="zh">版本信息</span>
                </a>
                <a class="page-link" href="/inspect" aria-label="Open inspector">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <circle cx="11" cy="11" r="6"></circle>
                        <path d="m16 16 4 4"></path>
                        <path d="M8.5 11h5"></path>
                        <path d="M11 8.5v5"></path>
                    </svg>
                    <span data-lang="en">Inspector</span><span data-lang="zh">诊断台</span>
                </a>
                <button type="button" id="refresh-button">
                    <span data-lang="en">Refresh</span><span data-lang="zh">刷新</span>
                </button>
                <div class="menu-wrap">
                    <button type="button" id="refresh-interval-button" aria-haspopup="menu" aria-expanded="false">Auto: 3s</button>
                    <div class="refresh-menu" id="refresh-menu" role="menu" hidden></div>
                </div>
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
                <section class="section geo-section">
                    <div class="section-head">
                        <div>
                            <h2><span data-lang="en">Request Ranking</span><span data-lang="zh">请求排行</span></h2>
                            <div class="state-line" id="request-range-label">-</div>
                        </div>
                        <div class="section-actions">
                            <span class="status"><span class="status-dot"></span><span id="request-region-status">-</span></span>
                            <div class="range-tabs" id="request-tabs"></div>
                        </div>
                    </div>
                    <div class="map-grid">
                        <article class="map-card">
                            <div class="map-card-head">
                                <h3><span data-lang="en">World Requests</span><span data-lang="zh">世界请求</span></h3>
                                <span class="state-line" id="request-world-map-total">-</span>
                            </div>
                            <div class="map-frame">
                                <svg id="request-world-map" class="world-map" role="img" aria-label="World request map"></svg>
                                <div class="map-legend">
                                    <span>0</span>
                                    <span class="legend-swatch"></span>
                                    <span><span data-lang="en">High</span><span data-lang="zh">高</span></span>
                                </div>
                            </div>
                        </article>
                        <article class="map-card">
                            <div class="map-card-head">
                                <h3><span data-lang="en">China Region Requests</span><span data-lang="zh">中国地区请求</span></h3>
                                <span class="state-line" id="request-china-map-total">-</span>
                            </div>
                            <div class="map-frame">
                                <svg id="request-china-map" class="world-map" role="img" aria-label="China region request map"></svg>
                                <div class="map-legend">
                                    <span>0</span>
                                    <span class="legend-swatch"></span>
                                    <span><span data-lang="en">High</span><span data-lang="zh">高</span></span>
                                </div>
                            </div>
                        </article>
                    </div>
                    <div class="ranking-grid">
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">World Requests Top 5</span><span data-lang="zh">世界请求前五</span></h3>
                                <span class="state-line" id="request-world-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="request-world-ranking"></div>
                        </article>
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">China Region Requests Top 5</span><span data-lang="zh">中国地区请求前五</span></h3>
                                <span class="state-line" id="request-china-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="request-china-ranking"></div>
                        </article>
                    </div>
                </section>
                <section class="section geo-section">
                    <div class="section-head">
                        <div>
                            <h2><span data-lang="en">Rule Ranking</span><span data-lang="zh">规则排行</span></h2>
                            <div class="state-line" id="rule-range-label">-</div>
                        </div>
                        <div class="section-actions">
                            <span class="status"><span class="status-dot"></span><span id="rule-region-status">-</span></span>
                            <div class="range-tabs" id="rule-tabs"></div>
                        </div>
                    </div>
                    <div class="map-grid">
                        <article class="map-card">
                            <div class="map-card-head">
                                <h3><span data-lang="en">World Rules</span><span data-lang="zh">世界规则</span></h3>
                                <span class="state-line" id="rule-world-map-total">-</span>
                            </div>
                            <div class="map-frame">
                                <svg id="rule-world-map" class="world-map" role="img" aria-label="World rule map"></svg>
                                <div class="map-legend">
                                    <span>0</span>
                                    <span class="legend-swatch"></span>
                                    <span><span data-lang="en">High</span><span data-lang="zh">高</span></span>
                                </div>
                            </div>
                        </article>
                        <article class="map-card">
                            <div class="map-card-head">
                                <h3><span data-lang="en">China Region Rules</span><span data-lang="zh">中国地区规则</span></h3>
                                <span class="state-line" id="rule-china-map-total">-</span>
                            </div>
                            <div class="map-frame">
                                <svg id="rule-china-map" class="world-map" role="img" aria-label="China region rule map"></svg>
                                <div class="map-legend">
                                    <span>0</span>
                                    <span class="legend-swatch"></span>
                                    <span><span data-lang="en">High</span><span data-lang="zh">高</span></span>
                                </div>
                            </div>
                        </article>
                    </div>
                    <div class="ranking-grid">
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">World Rules Top 5</span><span data-lang="zh">世界规则前五</span></h3>
                                <span class="state-line" id="rule-world-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="rule-world-ranking"></div>
                        </article>
                        <article class="ranking-card">
                            <div class="ranking-card-head">
                                <h3><span data-lang="en">China Region Rules Top 5</span><span data-lang="zh">中国地区规则前五</span></h3>
                                <span class="state-line" id="rule-china-ranking-total">-</span>
                            </div>
                            <div class="ranking-list" id="rule-china-ranking"></div>
                        </article>
                    </div>
                </section>
            </div>
        </section>
        <footer class="page-footer">
            <span data-lang="en">Source Code: <a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank" rel="noopener noreferrer">GitHub</a> • License: <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a></span>
            <span data-lang="zh">源代码：<a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank" rel="noopener noreferrer">GitHub</a> • 许可证：<a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a></span>
        </footer>
    </main>
    <div class="tooltip" id="tooltip"></div>

    <script>
        (function () {
            var ISO_N3 = {
                "004":"AF","008":"AL","010":"AQ","012":"DZ","016":"AS","020":"AD","024":"AO","028":"AG","031":"AZ","032":"AR","036":"AU","040":"AT","044":"BS","048":"BH","050":"BD","051":"AM","052":"BB","056":"BE","060":"BM","064":"BT","068":"BO","070":"BA","072":"BW","074":"BV","076":"BR","084":"BZ","086":"IO","090":"SB","092":"VG","096":"BN","100":"BG","104":"MM","108":"BI","112":"BY","116":"KH","120":"CM","124":"CA","132":"CV","136":"KY","140":"CF","144":"LK","148":"TD","152":"CL","156":"CN","158":"TW","162":"CX","166":"CC","170":"CO","174":"KM","175":"YT","178":"CG","180":"CD","184":"CK","188":"CR","191":"HR","192":"CU","196":"CY","203":"CZ","204":"BJ","208":"DK","212":"DM","214":"DO","218":"EC","222":"SV","226":"GQ","231":"ET","232":"ER","233":"EE","234":"FO","238":"FK","239":"GS","242":"FJ","246":"FI","248":"AX","250":"FR","254":"GF","258":"PF","260":"TF","262":"DJ","266":"GA","268":"GE","270":"GM","275":"PS","276":"DE","288":"GH","292":"GI","296":"KI","300":"GR","304":"GL","308":"GD","312":"GP","316":"GU","320":"GT","324":"GN","328":"GY","332":"HT","334":"HM","336":"VA","340":"HN","344":"HK","348":"HU","352":"IS","356":"IN","360":"ID","364":"IR","368":"IQ","372":"IE","376":"IL","380":"IT","384":"CI","388":"JM","392":"JP","398":"KZ","400":"JO","404":"KE","408":"KP","410":"KR","414":"KW","417":"KG","418":"LA","422":"LB","426":"LS","428":"LV","430":"LR","434":"LY","438":"LI","440":"LT","442":"LU","446":"MO","450":"MG","454":"MW","458":"MY","462":"MV","466":"ML","470":"MT","474":"MQ","478":"MR","480":"MU","484":"MX","492":"MC","496":"MN","498":"MD","499":"ME","500":"MS","504":"MA","508":"MZ","512":"OM","516":"NA","520":"NR","524":"NP","528":"NL","531":"CW","533":"AW","534":"SX","535":"BQ","540":"NC","548":"VU","554":"NZ","558":"NI","562":"NE","566":"NG","570":"NU","574":"NF","578":"NO","580":"MP","581":"UM","583":"FM","584":"MH","585":"PW","586":"PK","591":"PA","598":"PG","600":"PY","604":"PE","608":"PH","612":"PN","616":"PL","620":"PT","624":"GW","626":"TL","630":"PR","634":"QA","638":"RE","642":"RO","643":"RU","646":"RW","652":"BL","654":"SH","659":"KN","660":"AI","662":"LC","663":"MF","666":"PM","670":"VC","674":"SM","678":"ST","682":"SA","686":"SN","688":"RS","690":"SC","694":"SL","702":"SG","703":"SK","704":"VN","705":"SI","706":"SO","710":"ZA","716":"ZW","724":"ES","728":"SS","729":"SD","732":"EH","740":"SR","744":"SJ","748":"SZ","752":"SE","756":"CH","760":"SY","762":"TJ","764":"TH","768":"TG","772":"TK","776":"TO","780":"TT","784":"AE","788":"TN","792":"TR","795":"TM","796":"TC","798":"TV","800":"UG","804":"UA","807":"MK","818":"EG","826":"GB","831":"GG","832":"JE","833":"IM","834":"TZ","840":"US","850":"VI","854":"BF","858":"UY","860":"UZ","862":"VE","876":"WF","882":"WS","887":"YE","894":"ZM"
            };
            var CHINA_ADCODE = {
                "110000":"CN-BJ","120000":"CN-TJ","130000":"CN-HE","140000":"CN-SX","150000":"CN-NM","210000":"CN-LN","220000":"CN-JL","230000":"CN-HL",
                "310000":"CN-SH","320000":"CN-JS","330000":"CN-ZJ","340000":"CN-AH","350000":"CN-FJ","360000":"CN-JX","370000":"CN-SD",
                "410000":"CN-HA","420000":"CN-HB","430000":"CN-HN","440000":"CN-GD","450000":"CN-GX","460000":"CN-HI",
                "500000":"CN-CQ","510000":"CN-SC","520000":"CN-GZ","530000":"CN-YN","540000":"CN-XZ","610000":"CN-SN","620000":"CN-GS",
                "630000":"CN-QH","640000":"CN-NX","650000":"CN-XJ","710000":"CN-TW","810000":"CN-HK","820000":"CN-MO"
            };
            var CHINA_REGION_NAMES = {
                "CN-AH": { en: "Anhui", zh: "安徽" }, "CN-BJ": { en: "Beijing", zh: "北京" }, "CN-CQ": { en: "Chongqing", zh: "重庆" },
                "CN-FJ": { en: "Fujian", zh: "福建" }, "CN-GD": { en: "Guangdong", zh: "广东" }, "CN-GS": { en: "Gansu", zh: "甘肃" },
                "CN-GX": { en: "Guangxi", zh: "广西" }, "CN-GZ": { en: "Guizhou", zh: "贵州" }, "CN-HA": { en: "Henan", zh: "河南" },
                "CN-HB": { en: "Hubei", zh: "湖北" }, "CN-HE": { en: "Hebei", zh: "河北" }, "CN-HI": { en: "Hainan", zh: "海南" },
                "CN-HK": { en: "Hong Kong", zh: "香港" }, "CN-HL": { en: "Heilongjiang", zh: "黑龙江" }, "CN-HN": { en: "Hunan", zh: "湖南" },
                "CN-JL": { en: "Jilin", zh: "吉林" }, "CN-JS": { en: "Jiangsu", zh: "江苏" }, "CN-JX": { en: "Jiangxi", zh: "江西" },
                "CN-LN": { en: "Liaoning", zh: "辽宁" }, "CN-MO": { en: "Macau", zh: "澳门" }, "CN-NM": { en: "Inner Mongolia", zh: "内蒙古" },
                "CN-NX": { en: "Ningxia", zh: "宁夏" }, "CN-QH": { en: "Qinghai", zh: "青海" }, "CN-SC": { en: "Sichuan", zh: "四川" },
                "CN-SD": { en: "Shandong", zh: "山东" }, "CN-SH": { en: "Shanghai", zh: "上海" }, "CN-SN": { en: "Shaanxi", zh: "陕西" },
                "CN-SX": { en: "Shanxi", zh: "山西" }, "CN-TJ": { en: "Tianjin", zh: "天津" }, "CN-TW": { en: "Taiwan", zh: "台湾" },
                "CN-XJ": { en: "Xinjiang", zh: "新疆" }, "CN-XZ": { en: "Tibet", zh: "西藏" }, "CN-YN": { en: "Yunnan", zh: "云南" },
                "CN-ZJ": { en: "Zhejiang", zh: "浙江" }, "CN-XX": { en: "Unknown mainland region", zh: "中国大陆未知地区" }
            };
            var CHINA_REGION_TILES = [
                ["CN-XJ","CN-GS","CN-NM","CN-HL","CN-JL","CN-LN"],
                ["CN-XZ","CN-QH","CN-NX","CN-SX","CN-BJ","CN-TJ"],
                ["CN-SC","CN-SN","CN-HE","CN-SD","CN-JS","CN-SH"],
                ["CN-YN","CN-GZ","CN-CQ","CN-HA","CN-AH","CN-ZJ"],
                ["CN-GX","CN-HN","CN-HB","CN-JX","CN-FJ","CN-TW"],
                ["CN-HI","CN-GD","CN-HK","CN-MO"]
            ];
            var metricsEl = document.getElementById("metrics");
            var requestTabs = document.getElementById("request-tabs");
            var ruleTabs = document.getElementById("rule-tabs");
            var requestRangeLabel = document.getElementById("request-range-label");
            var ruleRangeLabel = document.getElementById("rule-range-label");
            var requestRegionStatus = document.getElementById("request-region-status");
            var ruleRegionStatus = document.getElementById("rule-region-status");
            var updatedAt = document.getElementById("updated-at");
            var requestChart = document.getElementById("request-chart");
            var ruleChart = document.getElementById("rule-chart");
            var requestTotal = document.getElementById("request-total");
            var ruleTotal = document.getElementById("rule-total");
            var requestWorldMapTotal = document.getElementById("request-world-map-total");
            var requestChinaMapTotal = document.getElementById("request-china-map-total");
            var ruleWorldMapTotal = document.getElementById("rule-world-map-total");
            var ruleChinaMapTotal = document.getElementById("rule-china-map-total");
            var requestWorldRanking = document.getElementById("request-world-ranking");
            var requestChinaRanking = document.getElementById("request-china-ranking");
            var ruleWorldRanking = document.getElementById("rule-world-ranking");
            var ruleChinaRanking = document.getElementById("rule-china-ranking");
            var requestWorldRankingTotal = document.getElementById("request-world-ranking-total");
            var requestChinaRankingTotal = document.getElementById("request-china-ranking-total");
            var ruleWorldRankingTotal = document.getElementById("rule-world-ranking-total");
            var ruleChinaRankingTotal = document.getElementById("rule-china-ranking-total");
            var tooltip = document.getElementById("tooltip");
            var refreshIntervalButton = document.getElementById("refresh-interval-button");
            var refreshMenu = document.getElementById("refresh-menu");
            var worldMapData = null;
            var chinaMapData = null;
            var latest = null;
            var animatedValues = new Map();
            var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            var RANGE_WINDOWS = [
                { key: "startup", en: "Since Start", zh: "本次启动" },
                { key: "hour", en: "1 Hour", zh: "1 小时" },
                { key: "day", en: "1 Day", zh: "1 天" },
                { key: "seven_days", en: "7 Days", zh: "7 天" },
                { key: "thirty_days", en: "30 Days", zh: "30 天" },
                { key: "half_year", en: "Half Year", zh: "半年" },
                { key: "year", en: "1 Year", zh: "1 年" },
                { key: "lifetime", en: "Lifetime", zh: "历史总计" }
            ];
            var SUMMARY_WINDOWS = [
                { key: "hour", en: "1 Hour", zh: "1 小时" },
                { key: "day", en: "1 Day", zh: "1 天" },
                { key: "seven_days", en: "7 Days", zh: "7 天" },
                { key: "thirty_days", en: "30 Days", zh: "30 天" },
                { key: "half_year", en: "Half Year", zh: "半年" },
                { key: "year", en: "1 Year", zh: "1 年" }
            ];
            var REFRESH_OPTIONS = [
                { seconds: 0, en: "Pause", zh: "暂停" },
                { seconds: 1, en: "1s", zh: "1 秒" },
                { seconds: 3, en: "3s", zh: "3 秒" },
                { seconds: 5, en: "5s", zh: "5 秒" },
                { seconds: 10, en: "10s", zh: "10 秒" },
                { seconds: 30, en: "30s", zh: "30 秒" },
                { seconds: 60, en: "1m", zh: "1 分钟" },
                { seconds: 300, en: "5m", zh: "5 分钟" }
            ];
            var REQUEST_WINDOW_STORAGE_KEY = "sce-dashboard-request-window-v1";
            var RULE_WINDOW_STORAGE_KEY = "sce-dashboard-rule-window-v1";
            var REFRESH_INTERVAL_STORAGE_KEY = "sce-dashboard-refresh-interval-v2";
            var selectedRequestWindow = localStorage.getItem(REQUEST_WINDOW_STORAGE_KEY) || "lifetime";
            var selectedRuleWindow = localStorage.getItem(RULE_WINDOW_STORAGE_KEY) || "lifetime";
            var refreshIntervalSeconds = Number(localStorage.getItem(REFRESH_INTERVAL_STORAGE_KEY) || 3);
            var refreshTimer = null;
            var hourlyChartInitialized = new WeakMap();

            function isZh() { return /^zh\b/i.test(document.documentElement.lang); }
            function text(en, zh) { return isZh() ? zh : en; }
            function updateDocumentTitle() { document.title = text("SubConverter-Extended Dashboard", "SubConverter-Extended 仪表盘"); }
            function number(value) { return new Intl.NumberFormat(isZh() ? "zh-CN" : "en").format(value || 0); }
            function label(config) { return text(config.en, config.zh); }
            function windowConfig(key, source) {
                var list = source || RANGE_WINDOWS;
                return list.find(function (item) { return item.key === key; }) || list[list.length - 1];
            }
            function countryName(code) {
                if (code === "ZZ" || code === "XX") return text("Unknown", "未知");
                if (code === "T1") return text("Tor network", "Tor 网络");
                if (code === "CN") return text("Mainland China", "中国大陆");
                try { return new Intl.DisplayNames([isZh() ? "zh-CN" : "en"], { type: "region" }).of(code) || code; }
                catch (error) { return code; }
            }
            function countryIcon(code) {
                if (!/^[A-Z]{2}$/.test(code) || code === "ZZ" || code === "XX") return String.fromCodePoint(0x25CC);
                return String.fromCodePoint(code.charCodeAt(0) + 127397, code.charCodeAt(1) + 127397);
            }
            function chinaRegionName(code) {
                var item = CHINA_REGION_NAMES[code];
                if (item) return text(item.en, item.zh);
                return code || text("Unknown", "未知");
            }
            function chinaRegionBadge(code) {
                return code && code.indexOf("CN-") === 0 ? code.slice(3) : code;
            }
            function neutralRegionIcon() { return String.fromCodePoint(0x25C6); }
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
                    '<section class="stat-block"><div class="block-head"><div><h2>' + text("Conversion Overview", "转换总览") + '</h2>' +
                    '<div class="block-copy">' + text("Current-process and persisted totals with rolling comparison windows", "本次启动、历史总计与滚动时间范围对比") + '</div></div></div>' +
                    '<div class="metric-grid two-up conversion-totals">' +
                    countersPairHtml("Since Start", "本次启动", windows.startup, "Only conversions after the current process started.", "仅统计当前进程启动后的转换。") +
                    countersPairHtml("Lifetime", "历史总计", windows.lifetime, "Persisted conversion totals since the statistics file was created.", "统计文件创建以来持久化累计的转换。") +
                    '</div>' +
                    '<div class="window-strip">' + SUMMARY_WINDOWS.map(function (item) { return miniWindowHtml(item, windows[item.key]); }).join("") + '</div></section>';
                animateCounters(metricsEl);
            }
            function renderHourlyChart(container, series, field, className, labelEn, labelZh) {
                if (!series.length) {
                    container.textContent = "";
                    hourlyChartInitialized.delete(container);
                    var empty = document.createElement("div");
                    empty.className = "empty compact";
                    empty.textContent = text("No hourly data", "暂无小时数据");
                    container.appendChild(empty);
                    return;
                }
                container.querySelectorAll(".empty").forEach(function (node) { node.remove(); });
                var max = Math.max(1, ...series.map(function (item) { return item[field] || 0; }));
                var seen = new Set();
                var initialized = hourlyChartInitialized.get(container) === true;
                series.forEach(function (item, index) {
                    var value = item[field] || 0;
                    var key = String(item.time || index);
                    seen.add(key);
                    var bar = container.querySelector('[data-hour-key="' + key + '"]');
                    if (!bar) {
                        bar = document.createElement("div");
                        bar.className = "bar " + className;
                        bar.setAttribute("data-hour-key", key);
                        bar.style.height = initialized ? Math.max(4, Math.round((value / max) * 132)) + "px" : "4px";
                    } else {
                        bar.className = "bar " + className;
                    }
                    bar.title = fmtTime(item.time) + " / " + text(labelEn, labelZh) + " " + number(value);
                    container.appendChild(bar);
                    var targetHeight = Math.max(4, Math.round((value / max) * 132)) + "px";
                    if (bar.style.height !== targetHeight)
                        requestAnimationFrame(function () { bar.style.height = targetHeight; });
                });
                container.querySelectorAll("[data-hour-key]").forEach(function (bar) {
                    if (!seen.has(bar.getAttribute("data-hour-key")))
                        bar.remove();
                });
                hourlyChartInitialized.set(container, true);
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
            function countriesForWindow(data, key) {
                var windows = data.country_windows || {};
                return windows[key] || data.countries || [];
            }
            function chinaRegionsForWindow(data, key) {
                var windows = data.china_region_windows || {};
                return windows[key] || data.china_regions || [];
            }
            function renderTimeTabs() {
                selectedRequestWindow = windowConfig(selectedRequestWindow, RANGE_WINDOWS).key;
                selectedRuleWindow = windowConfig(selectedRuleWindow, RANGE_WINDOWS).key;
                requestTabs.innerHTML = rangeTabsHtml(RANGE_WINDOWS, selectedRequestWindow, "data-request-window");
                requestTabs.querySelectorAll("[data-request-window]").forEach(function (button) {
                    button.addEventListener("click", function () {
                        selectedRequestWindow = button.getAttribute("data-request-window");
                        localStorage.setItem(REQUEST_WINDOW_STORAGE_KEY, selectedRequestWindow);
                        updateRangeTabs(requestTabs, "data-request-window", selectedRequestWindow);
                        renderGeoSections();
                    });
                });
                ruleTabs.innerHTML = rangeTabsHtml(RANGE_WINDOWS, selectedRuleWindow, "data-rule-window");
                ruleTabs.querySelectorAll("[data-rule-window]").forEach(function (button) {
                    button.addEventListener("click", function () {
                        selectedRuleWindow = button.getAttribute("data-rule-window");
                        localStorage.setItem(RULE_WINDOW_STORAGE_KEY, selectedRuleWindow);
                        updateRangeTabs(ruleTabs, "data-rule-window", selectedRuleWindow);
                        renderGeoSections();
                    });
                });
            }
            function refreshOption(seconds) {
                return REFRESH_OPTIONS.find(function (item) { return item.seconds === seconds; }) || REFRESH_OPTIONS[2];
            }
            function refreshOptionText(option) {
                if (option.seconds === 0)
                    return text("Pause", "暂停");
                return label(option);
            }
            function refreshButtonText() {
                var option = refreshOption(refreshIntervalSeconds);
                if (option.seconds === 0)
                    return text("Auto: paused", "自动：暂停");
                return text("Auto: ", "自动：") + label(option);
            }
            function updateRefreshIntervalUi() {
                var normalized = refreshOption(refreshIntervalSeconds);
                refreshIntervalSeconds = normalized.seconds;
                refreshIntervalButton.textContent = refreshButtonText();
                refreshMenu.innerHTML = REFRESH_OPTIONS.map(function (item) {
                    return '<button type="button" class="refresh-option" role="menuitemradio" aria-pressed="' + (item.seconds === refreshIntervalSeconds ? "true" : "false") + '" data-refresh-seconds="' + item.seconds + '">' + refreshOptionText(item) + '</button>';
                }).join("");
                refreshMenu.querySelectorAll("[data-refresh-seconds]").forEach(function (button) {
                    button.addEventListener("click", function () {
                        refreshIntervalSeconds = Number(button.getAttribute("data-refresh-seconds")) || 0;
                        localStorage.setItem(REFRESH_INTERVAL_STORAGE_KEY, String(refreshIntervalSeconds));
                        refreshMenu.hidden = true;
                        refreshIntervalButton.setAttribute("aria-expanded", "false");
                        updateRefreshIntervalUi();
                        scheduleAutoRefresh();
                    });
                });
            }
            function scheduleAutoRefresh() {
                if (refreshTimer) {
                    clearInterval(refreshTimer);
                    refreshTimer = null;
                }
                if (refreshIntervalSeconds <= 0 || document.visibilityState === "hidden")
                    return;
                refreshTimer = setInterval(triggerRefresh, refreshIntervalSeconds * 1000);
            }
            function escapeHtml(value) {
                return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
                    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch];
                });
            }
            function renderRankingPanel(container, items, field, total, emptyMessageEn, emptyMessageZh, options) {
                options = options || {};
                var ranked = items.filter(function (item) { return (item[field] || 0) > 0; })
                    .sort(function (a, b) { return (b[field] || 0) - (a[field] || 0); })
                    .slice(0, 5);
                if (!ranked.length) {
                    container.textContent = "";
                    var empty = document.createElement("div");
                    empty.className = "empty compact";
                    empty.textContent = text(emptyMessageEn, emptyMessageZh);
                    container.appendChild(empty);
                    return;
                }
                container.querySelectorAll(".empty").forEach(function (node) { node.remove(); });
                var max = Math.max(1, ...ranked.map(function (item) { return item[field] || 0; }));
                var seen = new Set();
                ranked.forEach(function (item) {
                    var value = item[field] || 0;
                    var key = (options.keyPrefix || field) + ":" + item.code;
                    seen.add(key);
                    var row = container.querySelector('[data-rank-key="' + key + '"]');
                    var fill;
                    if (!row) {
                        row = document.createElement("div");
                        row.className = "ranking-row";
                        row.setAttribute("data-rank-key", key);

                        var country = document.createElement("div");
                        country.className = "rank-country";

                        var metric = document.createElement("div");
                        metric.className = "rank-metric";
                        var values = document.createElement("div");
                        values.className = "rank-values";
                        var track = document.createElement("div");
                        track.className = "rank-bar-track";
                        fill = document.createElement("div");
                        fill.className = "rank-bar-fill" + (field === "rule_conversions" ? " rule" : "");
                        fill.style.setProperty("--rank-width", "0%");
                        track.appendChild(fill);
                        metric.appendChild(values);
                        metric.appendChild(track);
                        row.appendChild(country);
                        row.appendChild(metric);
                    }
                    var name = options.name ? options.name(item) : countryName(item.code);
                    var badge = options.badge ? options.badge(item) : item.code;
                    var icon = options.icon ? options.icon(item) : countryIcon(item.code);
                    var badgeClass = options.region ? "code-badge region-badge" : "code-badge";
                    row.querySelector(".rank-country").innerHTML = '<span class="country-icon">' + icon + '</span><span class="' + badgeClass + '">' + escapeHtml(badge) + '</span><span class="rank-country-name">' + escapeHtml(name) + '</span>';
                    row.querySelector(".rank-values").innerHTML = '<span>' + countValue("rank:" + key, value) + '</span><span>' + percentage(value, total) + '</span>';
                    fill = row.querySelector(".rank-bar-fill");
                    container.appendChild(row);
                    var targetWidth = Math.max(4, Math.round((value / max) * 100)) + "%";
                    requestAnimationFrame(function () {
                        if (fill.style.getPropertyValue("--rank-width") !== targetWidth)
                            fill.style.setProperty("--rank-width", targetWidth);
                    });
                });
                container.querySelectorAll("[data-rank-key]").forEach(function (row) {
                    if (!seen.has(row.getAttribute("data-rank-key")))
                        row.remove();
                });
                animateCounters(container);
            }
            function itemMap(items) {
                var result = new Map();
                items.forEach(function (item) { result.set(item.code, item); });
                return result;
            }
            function totalFor(items, field) {
                return items.reduce(function (sum, item) { return sum + (item[field] || 0); }, 0);
            }
            function mapColors() {
                var styles = getComputedStyle(document.documentElement);
                return {
                    empty: styles.getPropertyValue("--map-empty").trim() || "#cbd5e1",
                    min: styles.getPropertyValue("--map-data-min").trim() || "#93c5fd",
                    mid: styles.getPropertyValue("--map-data-mid").trim() || "#2563eb",
                    max: styles.getPropertyValue("--map-data-max").trim() || "#1e3a8a"
                };
            }
            function colorForValue(value, max, colors) {
                if (value < 1) return colors.empty;
                var color = d3.interpolateRgbBasis([colors.min, colors.mid, colors.max]);
                if (max <= 1) return color(0.35);
                return color(Math.log10(value) / Math.log10(max));
            }
            function showTooltip(event, html) {
                tooltip.innerHTML = html;
                tooltip.classList.add("show");
                var gap = 14;
                var margin = 12;
                var width = tooltip.offsetWidth || 220;
                var height = tooltip.offsetHeight || 120;
                var x = event.clientX + gap;
                var y = event.clientY + gap;
                if (x + width + margin > window.innerWidth)
                    x = event.clientX - width - gap;
                if (y + height + margin > window.innerHeight)
                    y = event.clientY - height - gap;
                tooltip.style.left = Math.max(margin, Math.min(x, window.innerWidth - width - margin)) + "px";
                tooltip.style.top = Math.max(margin, Math.min(y, window.innerHeight - height - margin)) + "px";
            }
            function hideTooltip() { tooltip.classList.remove("show"); }
            function metricTooltipRow(item, field, metricEn, metricZh) {
                item = item || {};
                return '<div class="tooltip-row"><span>' + text(metricEn, metricZh) + '</span><strong>' + number(item[field]) + '</strong></div>';
            }
            function renderWorldMap(selector, countries, field, metricEn, metricZh, config) {
                if (!worldMapData || !window.d3 || !window.topojson) return;
                var svg = d3.select(selector);
                var node = svg.node();
                if (!node) return;
                var width = node.clientWidth || 800;
                var height = node.clientHeight || 430;
                var countriesMap = itemMap(countries);
                var colors = mapColors();
                svg.attr("viewBox", "0 0 " + width + " " + height);
                svg.selectAll("*").remove();
                var projection = d3.geoNaturalEarth1().rotate([-150, 0]).fitSize([width, height], { type: "Sphere" });
                var path = d3.geoPath(projection);
                var features = topojson.feature(worldMapData, worldMapData.objects.countries).features;
                var max = Math.max(1, ...countries.map(function (item) { return item[field] || 0; }));
                function countryValue(code) {
                    var item = countriesMap.get(code);
                    return item ? item[field] || 0 : 0;
                }
                svg.append("path").datum({ type: "Sphere" }).attr("d", path).attr("fill", "transparent");
                svg.selectAll("path.country")
                    .data(features)
                    .enter()
                    .append("path")
                    .attr("class", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        return "country" + (countryValue(code) > 0 ? " has-data" : "");
                    })
                    .attr("d", path)
                    .style("--country-fill", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        return colorForValue(countryValue(code), max, colors);
                    })
                    .on("mousemove", function (event, d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")] || "ZZ";
                        var item = countriesMap.get(code) || { subscription_requests: 0, rule_conversions: 0 };
                        showTooltip(event, '<div class="tooltip-title"><span class="country-icon">' + countryIcon(code) + '</span>' + escapeHtml(countryName(code)) + '</div>' +
                            '<div class="tooltip-row"><span>' + text("Range", "范围") + '</span><strong>' + label(config) + '</strong></div>' +
                            metricTooltipRow(item, field, metricEn, metricZh));
                    })
                    .on("mouseleave", hideTooltip);
            }
            function chinaFeatureCode(feature) {
                var props = feature.properties || {};
                var adcode = String(props.adcode || props.adcode_pro || props.code || "");
                return CHINA_ADCODE[adcode] || "";
            }
            function isSouthChinaSeaFeature(feature) {
                var props = feature.properties || {};
                var adcode = String(props.adcode || props.adcode_pro || props.code || "");
                var name = String(props.name || "");
                return adcode.indexOf("_JD") !== -1 || /南海|九段|South China Sea/i.test(name);
            }
            function rewindChinaGeometry(geometry) {
                if (!geometry || !Array.isArray(geometry.coordinates)) return geometry;
                if (geometry.type === "Polygon") {
                    return {
                        type: "Polygon",
                        coordinates: geometry.coordinates.map(function (ring) {
                            return Array.isArray(ring) ? ring.slice().reverse() : ring;
                        })
                    };
                }
                if (geometry.type === "MultiPolygon") {
                    return {
                        type: "MultiPolygon",
                        coordinates: geometry.coordinates.map(function (polygon) {
                            return polygon.map(function (ring) {
                                return Array.isArray(ring) ? ring.slice().reverse() : ring;
                            });
                        })
                    };
                }
                return geometry;
            }
            function rewindChinaFeature(feature) {
                return {
                    type: feature.type || "Feature",
                    properties: feature.properties || {},
                    geometry: rewindChinaGeometry(feature.geometry)
                };
            }
            function fitChinaMainProjection(collection, centerCollection, width, height) {
                var horizontalPad = Math.max(20, Math.min(34, width * 0.055));
                var verticalPad = Math.max(22, Math.min(38, height * 0.08));
                var projection = d3.geoMercator().fitExtent(
                    [[horizontalPad, verticalPad], [width - horizontalPad, height - verticalPad]],
                    collection);
                var reference = centerCollection && centerCollection.features && centerCollection.features.length
                    ? centerCollection : collection;
                var path = d3.geoPath(projection);
                var bounds = path.bounds(reference);
                if (isFinite(bounds[0][1]) && isFinite(bounds[1][1])) {
                    var currentCenterY = (bounds[0][1] + bounds[1][1]) / 2;
                    var shiftY = height * 0.55 - currentCenterY;
                    var maxShift = height * 0.12;
                    shiftY = Math.max(-maxShift, Math.min(maxShift, shiftY));
                    var translate = projection.translate();
                    projection.translate([translate[0], translate[1] + shiftY]);
                }
                return projection;
            }
            function renderSouthChinaSeaInset(svg, features, width, height, colors, config, field, metricEn, metricZh) {
                if (!features.length) return;
                var insetWidth = Math.max(54, Math.min(74, width * 0.14));
                var insetHeight = Math.max(72, Math.min(96, height * 0.23));
                var insetMargin = Math.max(18, Math.min(26, width * 0.045));
                var insetX = width - insetWidth - insetMargin;
                var insetY = height - insetHeight - insetMargin;
                var pad = 5;
                var collection = { type: "FeatureCollection", features: features };
                var projection = d3.geoMercator().fitSize(
                    [insetWidth - pad * 2, insetHeight - pad * 2], collection);
                var path = d3.geoPath(projection);
                function showInsetTooltip(event) {
                    var item = { subscription_requests: 0, rule_conversions: 0 };
                    showTooltip(event, '<div class="tooltip-title"><span class="country-icon">' + neutralRegionIcon() + '</span>' + text("South China Sea Islands", "南海诸岛") + '</div>' +
                        '<div class="tooltip-row"><span>' + text("Range", "范围") + '</span><strong>' + label(config) + '</strong></div>' +
                        metricTooltipRow(item, field, metricEn, metricZh));
                }
                var group = svg.append("g")
                    .attr("class", "china-south-sea-inset")
                    .attr("transform", "translate(" + insetX + "," + insetY + ")")
                    .on("mousemove", showInsetTooltip)
                    .on("mouseleave", hideTooltip);
                group.append("rect")
                    .attr("class", "china-inset-frame")
                    .attr("width", insetWidth)
                    .attr("height", insetHeight);
                group.append("g")
                    .attr("transform", "translate(" + pad + "," + pad + ")")
                    .selectAll("path.china-south-sea")
                    .data(features)
                    .enter()
                    .append("path")
                    .attr("class", "china-region china-south-sea")
                    .attr("d", path)
                    .style("--country-fill", colors.empty);
            }
            function renderChinaMap(selector, regions, field, metricEn, metricZh, config) {
                if (!window.d3) return;
                var svg = d3.select(selector);
                var node = svg.node();
                if (!node) return;
                var width = node.clientWidth || 800;
                var height = node.clientHeight || 430;
                var regionMap = itemMap(regions);
                var colors = mapColors();
                var max = Math.max(1, ...regions.map(function (item) { return item[field] || 0; }));
                svg.attr("viewBox", "0 0 " + width + " " + height);
                svg.selectAll("*").remove();
                function valueFor(code) {
                    var item = regionMap.get(code);
                    return item ? item[field] || 0 : 0;
                }
                function tooltipFor(event, code, item) {
                    item = item || { subscription_requests: 0, rule_conversions: 0 };
                    showTooltip(event, '<div class="tooltip-title"><span class="country-icon">' + neutralRegionIcon() + '</span>' + escapeHtml(chinaRegionName(code)) + '</div>' +
                        '<div class="tooltip-row"><span>' + text("Range", "范围") + '</span><strong>' + label(config) + '</strong></div>' +
                        metricTooltipRow(item, field, metricEn, metricZh));
                }
                if (chinaMapData && Array.isArray(chinaMapData.features) && chinaMapData.features.length) {
                    var features = chinaMapData.features.map(rewindChinaFeature);
                    var mainFeatures = features.filter(function (feature) { return !isSouthChinaSeaFeature(feature); });
                    var insetFeatures = features.filter(isSouthChinaSeaFeature);
                    var collection = { type: "FeatureCollection", features: mainFeatures.length ? mainFeatures : features };
                    var mainlandCenterFeatures = collection.features.filter(function (feature) {
                        return ["CN-TW", "CN-HK", "CN-MO", "CN-HI"].indexOf(chinaFeatureCode(feature)) === -1;
                    });
                    var mainlandCenterCollection = { type: "FeatureCollection", features: mainlandCenterFeatures };
                    var projection = fitChinaMainProjection(collection, mainlandCenterCollection, width, height);
                    var path = d3.geoPath(projection);
                    svg.selectAll("path.china-region")
                        .data(collection.features)
                        .enter()
                        .append("path")
                        .attr("class", function (d) {
                            var code = chinaFeatureCode(d);
                            return "china-region" + (valueFor(code) > 0 ? " has-data" : "");
                        })
                        .attr("d", path)
                        .style("--country-fill", function (d) {
                            return colorForValue(valueFor(chinaFeatureCode(d)), max, colors);
                        })
                        .on("mousemove", function (event, d) {
                            var code = chinaFeatureCode(d) || "CN-XX";
                            tooltipFor(event, code, regionMap.get(code));
                        })
                        .on("mouseleave", hideTooltip);
                    renderSouthChinaSeaInset(svg, insetFeatures, width, height, colors, config, field, metricEn, metricZh);
                    return;
                }
                var rows = CHINA_REGION_TILES;
                var columns = 6;
                var gap = 6;
                var pad = 18;
                var cellW = (width - pad * 2 - gap * (columns - 1)) / columns;
                var cellH = (height - pad * 2 - gap * (rows.length - 1)) / rows.length;
                rows.forEach(function (row, y) {
                    row.forEach(function (code, x) {
                        var item = regionMap.get(code) || { subscription_requests: 0, rule_conversions: 0 };
                        var group = svg.append("g")
                            .attr("transform", "translate(" + (pad + x * (cellW + gap)) + "," + (pad + y * (cellH + gap)) + ")");
                        group.append("rect")
                            .attr("class", "china-region" + (valueFor(code) > 0 ? " has-data" : ""))
                            .attr("rx", 7)
                            .attr("ry", 7)
                            .attr("width", cellW)
                            .attr("height", cellH)
                            .style("--country-fill", colorForValue(valueFor(code), max, colors))
                            .on("mousemove", function (event) { tooltipFor(event, code, item); })
                            .on("mouseleave", hideTooltip);
                        group.append("text")
                            .attr("class", "china-region-label")
                            .attr("x", cellW / 2)
                            .attr("y", cellH / 2 + 4)
                            .text(chinaRegionBadge(code));
                    });
                });
            }
            function renderGeoSection(kind) {
                if (!latest) return;
                var isRequest = kind === "request";
                var field = isRequest ? "subscription_requests" : "rule_conversions";
                var metricEn = isRequest ? "Requests" : "Rules";
                var metricZh = isRequest ? "请求" : "规则";
                var selected = isRequest ? selectedRequestWindow : selectedRuleWindow;
                var config = windowConfig(selected, RANGE_WINDOWS);
                if (isRequest) selectedRequestWindow = config.key;
                else selectedRuleWindow = config.key;
                var countries = countriesForWindow(latest, config.key);
                var regions = chinaRegionsForWindow(latest, config.key);
                var worldTotal = totalFor(countries, field);
                var chinaTotal = totalFor(regions, field);
                var visibleWorld = countries.filter(function (item) { return item.code !== "ZZ" && item.code !== "XX"; }).length;
                var visibleChina = regions.filter(function (item) { return item.code !== "CN-XX"; }).length;
                var prefix = isRequest ? "request" : "rule";
                var rangeLabel = isRequest ? requestRangeLabel : ruleRangeLabel;
                var status = isRequest ? requestRegionStatus : ruleRegionStatus;
                rangeLabel.textContent = text("Showing ", "当前范围：") + label(config);
                status.textContent = text("World ", "世界 ") + number(visibleWorld) + " · " + text("China regions ", "中国地区 ") + number(visibleChina);
                var worldMapTotal = isRequest ? requestWorldMapTotal : ruleWorldMapTotal;
                var chinaMapTotal = isRequest ? requestChinaMapTotal : ruleChinaMapTotal;
                var worldRankingTotal = isRequest ? requestWorldRankingTotal : ruleWorldRankingTotal;
                var chinaRankingTotal = isRequest ? requestChinaRankingTotal : ruleChinaRankingTotal;
                worldMapTotal.innerHTML = text("Total ", "合计 ") + countValue("map:" + prefix + ":world:" + config.key, worldTotal);
                chinaMapTotal.innerHTML = text("Total ", "合计 ") + countValue("map:" + prefix + ":china:" + config.key, chinaTotal);
                worldRankingTotal.innerHTML = text("Total ", "合计 ") + countValue("ranking:" + prefix + ":world:" + config.key, worldTotal);
                chinaRankingTotal.innerHTML = text("Total ", "合计 ") + countValue("ranking:" + prefix + ":china:" + config.key, chinaTotal);
                animateCounters(worldMapTotal);
                animateCounters(chinaMapTotal);
                animateCounters(worldRankingTotal);
                animateCounters(chinaRankingTotal);
                updateRangeTabs(isRequest ? requestTabs : ruleTabs, isRequest ? "data-request-window" : "data-rule-window", config.key);
                renderWorldMap("#" + prefix + "-world-map", countries, field, metricEn, metricZh, config);
                renderChinaMap("#" + prefix + "-china-map", regions, field, metricEn, metricZh, config);
                renderRankingPanel(isRequest ? requestWorldRanking : ruleWorldRanking, countries, field, worldTotal, "No world data in this range", "当前范围暂无世界数据", {
                    keyPrefix: prefix + ":world",
                    name: function (item) { return countryName(item.code); },
                    badge: function (item) { return item.code; },
                    icon: function (item) { return countryIcon(item.code); }
                });
                renderRankingPanel(isRequest ? requestChinaRanking : ruleChinaRanking, regions, field, chinaTotal, "No China region data in this range", "当前范围暂无中国地区数据", {
                    keyPrefix: prefix + ":china",
                    region: true,
                    name: function (item) { return chinaRegionName(item.code); },
                    badge: function (item) { return chinaRegionBadge(item.code); },
                    icon: function () { return neutralRegionIcon(); }
                });
            }
            function renderGeoSections() {
                renderGeoSection("request");
                renderGeoSection("rule");
            }
            function render(data) {
                latest = data;
                renderMetrics(data);
                renderHourlyCharts(data.series || []);
                renderTimeTabs();
                renderGeoSections();
                updatedAt.textContent = text("Updated ", "更新 ") + fmtTime(data.generated_at);
            }
            function loadScript(src, globalName) {
                if (globalName && window[globalName]) return Promise.resolve();
                return new Promise(function (resolve, reject) {
                    var script = document.createElement("script");
                    script.src = src;
                    script.async = true;
                    script.onload = function () { resolve(); };
                    script.onerror = function () { reject(new Error("Failed to load " + src)); };
                    document.head.appendChild(script);
                });
            }
            function loadJson(src) {
                return fetch(src, { cache: "force-cache" })
                    .then(function (response) { return response.ok ? response.json() : null; })
                    .catch(function () { return null; });
            }
            function loadMapResources() {
                return Promise.all([
                    loadScript("https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js", "d3"),
                    loadScript("https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js", "topojson")
                ]).then(function () {
                    return Promise.all([
                        loadJson("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"),
                        loadJson("https://geo.datav.aliyun.com/areas_v3/bound/100000_full.json")
                    ]);
                }).then(function (values) {
                    worldMapData = values[0];
                    chinaMapData = values[1];
                    renderGeoSections();
                }).catch(function () {
                    renderGeoSections();
                });
            }
            async function refresh() {
                try {
                    var response = await fetch("/dashboard/data?_=" + Date.now(), { cache: "no-store", headers: { "Accept": "application/json" } });
                    if (!response.ok) throw new Error("Dashboard data request failed: " + response.status);
                    render(await response.json());
                } catch (error) {
                    updatedAt.textContent = text("Update failed", "更新失败");
                    throw error;
                }
            }
            function triggerRefresh() {
                refresh().catch(function () {});
            }
            document.getElementById("lang-toggle").addEventListener("click", function () {
                document.documentElement.lang = isZh() ? "en" : "zh-CN";
                localStorage.setItem("sce-dashboard-lang", document.documentElement.lang);
                updateDocumentTitle();
                document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
                updateRefreshIntervalUi();
                if (latest) render(latest);
            });
            document.getElementById("refresh-button").addEventListener("click", triggerRefresh);
            refreshIntervalButton.addEventListener("click", function (event) {
                event.stopPropagation();
                refreshMenu.hidden = !refreshMenu.hidden;
                refreshIntervalButton.setAttribute("aria-expanded", refreshMenu.hidden ? "false" : "true");
            });
            document.addEventListener("click", function (event) {
                if (!refreshMenu.hidden && !refreshMenu.contains(event.target) && event.target !== refreshIntervalButton) {
                    refreshMenu.hidden = true;
                    refreshIntervalButton.setAttribute("aria-expanded", "false");
                }
            });
            document.addEventListener("visibilitychange", function () {
                scheduleAutoRefresh();
                if (document.visibilityState !== "hidden" && refreshIntervalSeconds > 0)
                    triggerRefresh();
            });
            updateDocumentTitle();
            document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
            updateRefreshIntervalUi();
            triggerRefresh();
            loadMapResources();
            window.addEventListener("resize", renderGeoSections);
            scheduleAutoRefresh();
        })();
    </script>
</body>
</html>)html";
}

} // namespace dashboard_page
