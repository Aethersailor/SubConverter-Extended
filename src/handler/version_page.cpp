#include "handler/version_page.h"

#include <string>

#include "version.h"

namespace {

const char *VERSION_FAVICON_DARK =
    R"svg(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="SubConverter-Extended icon">
  <defs>
    <linearGradient id="bg" x1="10" y1="8" x2="54" y2="56" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0f172a"/>
      <stop offset="1" stop-color="#1e293b"/>
    </linearGradient>
    <linearGradient id="cyan" x1="18" y1="20" x2="46" y2="20" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#38bdf8"/>
      <stop offset="1" stop-color="#22d3ee"/>
    </linearGradient>
    <linearGradient id="green" x1="46" y1="44" x2="18" y2="44" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#34d399"/>
      <stop offset="1" stop-color="#84cc16"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="14" fill="url(#bg)"/>
  <path d="M18 20h25" fill="none" stroke="url(#cyan)" stroke-width="6" stroke-linecap="round"/>
  <path d="M40 11l10 9-10 9" fill="none" stroke="#67e8f9" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M46 44H21" fill="none" stroke="url(#green)" stroke-width="6" stroke-linecap="round"/>
  <path d="M24 35l-10 9 10 9" fill="none" stroke="#bef264" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M24 31c0-6 4-10 9-10 3 0 6 1 8 3" fill="none" stroke="#f8fafc" stroke-width="5" stroke-linecap="round"/>
  <path d="M40 33c0 6-4 10-9 10-3 0-6-1-8-3" fill="none" stroke="#f8fafc" stroke-width="5" stroke-linecap="round"/>
</svg>)svg";

const char *VERSION_FAVICON_LIGHT =
    R"svg(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="SubConverter-Extended icon">
  <defs>
    <linearGradient id="bg" x1="10" y1="8" x2="54" y2="56" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#e8eef7"/>
    </linearGradient>
    <linearGradient id="cyan" x1="18" y1="20" x2="46" y2="20" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#0284c7"/>
      <stop offset="1" stop-color="#0891b2"/>
    </linearGradient>
    <linearGradient id="green" x1="46" y1="44" x2="18" y2="44" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#059669"/>
      <stop offset="1" stop-color="#65a30d"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="14" fill="url(#bg)"/>
  <rect x="1.5" y="1.5" width="61" height="61" rx="12.5" fill="none" stroke="#cbd5e1" stroke-width="3"/>
  <path d="M18 20h25" fill="none" stroke="url(#cyan)" stroke-width="6" stroke-linecap="round"/>
  <path d="M40 11l10 9-10 9" fill="none" stroke="#06b6d4" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M46 44H21" fill="none" stroke="url(#green)" stroke-width="6" stroke-linecap="round"/>
  <path d="M24 35l-10 9 10 9" fill="none" stroke="#84cc16" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M24 31c0-6 4-10 9-10 3 0 6 1 8 3" fill="none" stroke="#172033" stroke-width="5" stroke-linecap="round"/>
  <path d="M40 33c0 6-4 10-9 10-3 0-6-1-8-3" fill="none" stroke="#172033" stroke-width="5" stroke-linecap="round"/>
</svg>)svg";

std::string formatBuildDate(const std::string &value) {
  if (value.empty())
    return "unknown";
  size_t split_pos = value.find('T');
  if (split_pos == std::string::npos)
    split_pos = value.find(' ');
  std::string candidate =
      split_pos == std::string::npos ? value : value.substr(0, split_pos);
  if (candidate.size() >= 10 && candidate[4] == '-' && candidate[7] == '-' &&
      candidate[0] >= '0' && candidate[0] <= '9' && candidate[1] >= '0' &&
      candidate[1] <= '9' && candidate[2] >= '0' && candidate[2] <= '9' &&
      candidate[3] >= '0' && candidate[3] <= '9' && candidate[5] >= '0' &&
      candidate[5] <= '9' && candidate[6] >= '0' && candidate[6] <= '9' &&
      candidate[8] >= '0' && candidate[8] <= '9' && candidate[9] >= '0' &&
      candidate[9] <= '9') {
    return candidate.substr(0, 10);
  }
  return candidate;
}

std::string buildCommitLink(const std::string &build_id) {
  if (build_id.empty())
    return "";
  return "<a "
         "href=\"https://github.com/Aethersailor/"
         "SubConverter-Extended/commit/" +
         build_id + "\" target=\"_blank\" rel=\"noopener noreferrer\">" +
         build_id + "</a>";
}

} // namespace

namespace version_page {

std::string faviconDark(Request &, Response &response) {
  response.headers["Cache-Control"] = "public, max-age=86400";
  return VERSION_FAVICON_DARK;
}

std::string faviconLight(Request &, Response &response) {
  response.headers["Cache-Control"] = "public, max-age=86400";
  return VERSION_FAVICON_LIGHT;
}

std::string page(Request &, Response &response) {
  response.headers["X-Robots-Tag"] =
      "noindex, nofollow, noarchive, nosnippet, noimageindex";
  std::string build_id = BUILD_ID;
  std::string build_date = BUILD_DATE;
  std::string build_date_display = formatBuildDate(build_date);
  std::string build_date_value =
      build_date.empty()
          ? R"html(<span data-lang="en">unknown</span><span data-lang="zh">未知</span>)html"
          : build_date_display;
  std::string commit_link = buildCommitLink(build_id);

  return R"html(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
    <meta name="color-scheme" content="light dark">
    <title>SubConverter-Extended</title>
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
            /* Light Theme - 精准调优 */
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
            --link-color: #3182ce;
            --link-hover: #2b6cb0;
            --header-gradient: linear-gradient(135deg, #1a202c 0%, #4a5568 100%);
            --accent-gradient: linear-gradient(135deg, #0284c7 0%, #0891b2 45%, #65a30d 100%);
            --accent-soft: rgba(2, 132, 199, 0.1);
            --status-bg: rgba(2, 132, 199, 0.08);
            --status-border: rgba(2, 132, 199, 0.18);
            --status-dot: #10b981;
            --brand-mark-filter:
                drop-shadow(0 16px 28px rgba(2, 132, 199, 0.16))
                drop-shadow(0 8px 14px rgba(5, 150, 105, 0.12));
            --control-bg: rgba(255, 255, 255, 0.72);
            --control-hover: rgba(255, 255, 255, 0.92);
            --control-border: rgba(26, 32, 44, 0.12);
            --control-shadow: 0 12px 28px rgba(31, 38, 135, 0.12);
        }

        @media (prefers-color-scheme: dark) {
            :root {
                /* Dark Theme - 极黑质感 */
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

        .lang-toggle:focus-visible {
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
            max-width: 860px;
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
            margin-bottom: 30px;
        }

        .brand-mark {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 96px;
            height: 96px;
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
            font-size: 3em;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: 0;
            line-height: 1.05;
            overflow-wrap: anywhere;
        }

        .title-break {
            display: none;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1.05em;
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
            opacity: 0.88;
        }

        .section-title::before {
            content: "";
            width: 10px;
            height: 10px;
            border-radius: 999px;
            background: var(--accent-gradient);
            box-shadow: 0 0 0 5px var(--accent-soft);
        }

        .description {
            color: var(--text-secondary);
            font-size: 1em;
            line-height: 1.72;
            margin-bottom: 11px;
            padding-left: 1.65em;
            position: relative;
        }

        .description:last-child {
            margin-bottom: 0;
        }

        .description::before {
            content: "";
            position: absolute;
            left: 0.25em;
            top: 0.76em;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--accent-gradient);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin: 22px 0 24px;
        }

        .info-card {
            background: var(--info-block-bg);
            border: 1px solid var(--info-block-border);
            border-radius: 20px;
            padding: 18px;
            text-align: left;
            min-height: 132px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: transform 0.24s ease, box-shadow 0.24s ease, background 0.24s ease, border-color 0.24s ease;
        }

        .info-card:hover {
            transform: translateY(-4px);
            background: var(--info-block-hover);
            border-color: var(--status-border);
            box-shadow: 0 16px 32px rgba(15, 23, 42, 0.09);
        }

        .info-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 34px;
            height: 34px;
            border-radius: 12px;
            background: var(--accent-soft);
            color: var(--link-color);
            margin-bottom: 18px;
        }

        .info-icon svg {
            width: 18px;
            height: 18px;
        }

        .info-card .info-label {
            display: block;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 600;
        }

        .info-card .info-value {
            font-size: 1.12rem;
            font-weight: 700;
            color: var(--text-primary);
            word-break: break-all;
            line-height: 1.25;
        }

        .info-card .info-value a {
            font-family: 'Outfit', monospace;
            font-weight: 600;
        }

        a {
            color: var(--link-color);
            text-decoration: none;
            position: relative;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        a::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background: var(--link-color);
            transition: width 0.3s ease;
        }

        a:hover::after {
            width: 100%;
        }

        a:hover {
            color: var(--link-hover);
        }

        .footer {
            margin-top: 28px;
            padding-top: 22px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85em;
            opacity: 0.72;
            position: relative;
        }

        .footer::before {
            content: "";
            position: absolute;
            top: 0;
            left: 8%;
            right: 8%;
            height: 1px;
            background: var(--divider-bg);
        }

        .footer a {
            font-weight: 400;
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

        @media (max-width: 600px) {
            body { padding: 72px 16px 24px; }
            body::before {
                background-size: 28px 28px;
            }
            .container {
                border-radius: 26px;
                padding: 30px 20px 26px;
                width: calc(100vw - 32px);
                max-width: calc(100vw - 32px);
            }
            .container::after {
                border-radius: 26px;
            }
            .lang-toggle {
                top: calc(14px + env(safe-area-inset-top, 0px));
                right: calc(14px + env(safe-area-inset-right, 0px));
                min-height: 38px;
                min-width: 70px;
            }
            header { margin-bottom: 24px; }
            h1 {
                font-size: 2em;
                line-height: 1.12;
            }
            .title-break {
                display: block;
            }
            .subtitle {
                font-size: 0.92em;
                line-height: 1.45;
            }
            .brand-mark {
                width: 82px;
                height: 82px;
                margin-bottom: 14px;
            }
            .status-pill {
                font-size: 0.72rem;
                margin-bottom: 12px;
            }
            .info-grid { grid-template-columns: 1fr; gap: 12px; }
            .info-card {
                min-height: auto;
                padding: 16px;
            }
            .info-icon {
                margin-bottom: 14px;
            }
            .section {
                border-radius: 18px;
                padding: 17px;
            }
            .description {
                font-size: 0.96em;
                line-height: 1.68;
            }
        }
    </style>
</head>
<body>
    <button type="button" class="lang-toggle" id="lang-toggle">
        <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M2 12h20"></path>
            <path d="M12 2a15.3 15.3 0 0 1 0 20"></path>
            <path d="M12 2a15.3 15.3 0 0 0 0 20"></path>
        </svg>
        <span class="lang-toggle-text">中</span>
    </button>
    <div class="container">
        <header>
            <picture class="brand-mark">
                <source media="(prefers-color-scheme: dark)" srcset="/version/favicon-dark.svg">
                <img src="/version/favicon-light.svg" alt="SubConverter-Extended icon" width="96" height="96" decoding="async">
            </picture>
            <div class="status-pill" aria-live="polite">
                <span class="status-dot" aria-hidden="true"></span>
                <span data-lang="en">Service Online</span>
                <span data-lang="zh">服务在线</span>
            </div>
            <h1>SubConverter-<br class="title-break">Extended</h1>
            <p class="subtitle">
                <span data-lang="en">A Modern Evolution of Subconverter</span>
                <span data-lang="zh">Subconverter 的现代化演进版本</span>
            </p>
        </header>

        <div class="info-grid">
            <div class="info-card">
                <span class="info-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20.6 13.2 13.2 20.6a2 2 0 0 1-2.8 0L3.4 13.6a2 2 0 0 1-.6-1.4V5a2 2 0 0 1 2-2h7.2a2 2 0 0 1 1.4.6l7.2 7.2a2 2 0 0 1 0 2.8Z"></path>
                        <circle cx="7.5" cy="7.5" r="1.2"></circle>
                    </svg>
                </span>
                <span class="info-label">
                    <span data-lang="en">Version</span>
                    <span data-lang="zh">版本</span>
                </span>
                <div class="info-value">)html" VERSION R"html(</div>
            </div>
            <div class="info-card">
                <span class="info-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="18" cy="18" r="3"></circle>
                        <circle cx="6" cy="6" r="3"></circle>
                        <path d="M6 9v6a3 3 0 0 0 3 3h6"></path>
                        <path d="M12 6h6"></path>
                    </svg>
                </span>
                <span class="info-label">
                    <span data-lang="en">Build</span>
                    <span data-lang="zh">构建</span>
                </span>
                <div class="info-value">)html" +
         commit_link + R"html(</div>
            </div>
            <div class="info-card">
                <span class="info-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="4.5" width="18" height="16.5" rx="3"></rect>
                        <path d="M8 3v3"></path>
                        <path d="M16 3v3"></path>
                        <path d="M3 10h18"></path>
                    </svg>
                </span>
                <span class="info-label">
                    <span data-lang="en">Build Date</span>
                    <span data-lang="zh">构建日期</span>
                </span>
                <div class="info-value">)html" +
         build_date_value + R"html(</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">
                <span data-lang="en">Overview</span>
                <span data-lang="zh">项目概览</span>
            </div>
            <p class="description" data-lang="en">An enhanced implementation of subconverter, aligned with the <a href="https://github.com/MetaCubeX/mihomo/tree/Meta" target="_blank" rel="noopener noreferrer">Mihomo</a> <a href="https://wiki.metacubex.one/config/" target="_blank" rel="noopener noreferrer">configuration</a>.</p>
            <p class="description" data-lang="zh">subconverter 的增强实现，适配 <a href="https://github.com/MetaCubeX/mihomo/tree/Meta" target="_blank" rel="noopener noreferrer">Mihomo</a> <a href="https://wiki.metacubex.one/config/" target="_blank" rel="noopener noreferrer">配置规范</a>。</p>
            <p class="description" data-lang="en">Primarily for <a href="https://github.com/vernesong/OpenClash" target="_blank" rel="noopener noreferrer">OpenClash</a>, while compatible with other Clash clients.</p>
            <p class="description" data-lang="zh">主要面向 <a href="https://github.com/vernesong/OpenClash" target="_blank" rel="noopener noreferrer">OpenClash</a>，同时兼容其他 Clash 客户端。</p>
            <p class="description" data-lang="en">Dedicated companion backend for the <a href="https://github.com/Aethersailor/Custom_OpenClash_Rules" target="_blank" rel="noopener noreferrer">Custom_OpenClash_Rules</a> project.</p>
            <p class="description" data-lang="zh">作为 <a href="https://github.com/Aethersailor/Custom_OpenClash_Rules" target="_blank" rel="noopener noreferrer">Custom_OpenClash_Rules</a> 项目的专用配套后端。</p>
        </div>

        <div class="section">
            <div class="section-title">
                <span data-lang="en">Lineage</span>
                <span data-lang="zh">项目沿革</span>
            </div>
            <p class="description" data-lang="en">Originated and enhanced from: <a href="https://github.com/asdlokj1qpi233/subconverter" target="_blank" rel="noopener noreferrer">subconverter</a></p>
            <p class="description" data-lang="zh">源自并增强自：<a href="https://github.com/asdlokj1qpi233/subconverter" target="_blank" rel="noopener noreferrer">subconverter</a></p>
            <p class="description" data-lang="en">Modified and evolved by: <a href="https://github.com/Aethersailor" target="_blank" rel="noopener noreferrer">Aethersailor</a></p>
            <p class="description" data-lang="zh">由 <a href="https://github.com/Aethersailor" target="_blank" rel="noopener noreferrer">Aethersailor</a> 修改并持续演进</p>
        </div>

        <div class="footer">
            <span data-lang="en">Source Code: <a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank" rel="noopener noreferrer">GitHub</a> • License: <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a></span>
            <span data-lang="zh">源代码：<a href="https://github.com/Aethersailor/SubConverter-Extended" target="_blank" rel="noopener noreferrer">GitHub</a> • 许可证：<a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a></span>
        </div>
    </div>
    <script>
        (function () {
            var toggle = document.getElementById("lang-toggle");
            var label = toggle ? toggle.querySelector(".lang-toggle-text") : null;
            if (!toggle || !label) {
                return;
            }

            function isChinese() {
                return /^zh\b/i.test(document.documentElement.lang || "");
            }

            function setLanguage(language) {
                document.documentElement.lang = language;
                updateLanguageToggle();
            }

            function updateLanguageToggle() {
                if (isChinese()) {
                    label.textContent = "EN";
                    toggle.setAttribute("aria-label", "Switch to English");
                    toggle.setAttribute("title", "Switch to English");
                } else {
                    label.textContent = "中";
                    toggle.setAttribute("aria-label", "切换到中文");
                    toggle.setAttribute("title", "切换到中文");
                }
            }

            toggle.addEventListener("click", function () {
                setLanguage(isChinese() ? "en" : "zh-CN");
            });

            updateLanguageToggle();
        })();
    </script>
</body>
</html>)html";
}

} // namespace version_page
