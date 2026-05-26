#include "handler/dashboard_page.h"

namespace dashboard_page {

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
            --map-fill: #dbe6ef;
            --map-stroke: rgba(255, 255, 255, 0.85);
            --map-empty: #d4dde8;
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
                --map-fill: #243245;
                --map-stroke: rgba(2, 6, 23, 0.9);
                --map-empty: #253244;
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
        .hero {
            padding: 24px;
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 14px;
        }
        .metric {
            min-height: 126px;
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
        .content {
            display: grid;
            grid-template-columns: minmax(0, 1.4fr) minmax(320px, 0.8fr);
            gap: 18px;
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
        .map-wrap {
            position: relative;
            min-height: 430px;
            border: 1px solid var(--surface-border);
            border-radius: 20px;
            background: var(--surface-strong);
            overflow: hidden;
        }
        #world-map {
            width: 100%;
            height: 430px;
            display: block;
        }
        .country {
            fill: var(--map-empty);
            stroke: var(--map-stroke);
            stroke-width: 0.45;
            transition: fill 0.16s ease, opacity 0.16s ease;
        }
        .country.has-data { cursor: pointer; }
        .country:hover { opacity: 0.82; }
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
            border-radius: 20px;
            background: var(--surface-strong);
        }
        .bar {
            flex: 1 1 0;
            min-width: 4px;
            border-radius: 5px 5px 2px 2px;
            background: var(--accent-gradient);
            opacity: 0.88;
        }
        .country-table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid var(--surface-border);
            border-radius: 18px;
            overflow: hidden;
            background: var(--surface-strong);
        }
        .country-table th,
        .country-table td {
            padding: 11px 12px;
            text-align: left;
            border-bottom: 1px solid var(--surface-border);
            font-size: 0.9rem;
        }
        .country-table th {
            color: var(--text-muted);
            font-size: 0.76rem;
            text-transform: uppercase;
        }
        .country-table tr:last-child td { border-bottom: 0; }
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
        @media (max-width: 980px) {
            .hero { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            .content { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
            .shell { width: min(100% - 20px, 1180px); padding-top: 16px; }
            .topbar { align-items: flex-start; flex-direction: column; }
            .hero { grid-template-columns: 1fr 1fr; padding: 14px; }
            .metric { min-height: 112px; padding: 14px; }
            .metric-value { font-size: 1.42rem; }
            .content { padding: 0 14px 14px; }
            #world-map, .map-wrap { min-height: 310px; height: 310px; }
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
                    <h1>Dashboard</h1>
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
            <div class="hero" id="metrics"></div>
            <div class="content">
                <section class="section">
                    <div class="section-head">
                        <h2><span data-lang="en">Country Distribution</span><span data-lang="zh">国家分布</span></h2>
                        <span class="status"><span class="status-dot"></span><span id="country-status">-</span></span>
                    </div>
                    <div class="map-wrap">
                        <svg id="world-map" role="img" aria-label="World map"></svg>
                        <div class="tooltip" id="tooltip"></div>
                    </div>
                </section>
                <section class="section">
                    <div class="section-head">
                        <h2><span data-lang="en">Last 24 Hours</span><span data-lang="zh">最近 24 小时</span></h2>
                        <span class="state-line" id="updated-at">-</span>
                    </div>
                    <div class="chart" id="chart"></div>
                    <div style="height: 16px"></div>
                    <table class="country-table">
                        <thead>
                            <tr>
                                <th><span data-lang="en">Country</span><span data-lang="zh">国家</span></th>
                                <th><span data-lang="en">Requests</span><span data-lang="zh">请求</span></th>
                                <th><span data-lang="en">Rules</span><span data-lang="zh">规则</span></th>
                            </tr>
                        </thead>
                        <tbody id="country-body"></tbody>
                    </table>
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
            var countryBody = document.getElementById("country-body");
            var countryStatus = document.getElementById("country-status");
            var updatedAt = document.getElementById("updated-at");
            var chart = document.getElementById("chart");
            var tooltip = document.getElementById("tooltip");
            var mapData = null;
            var latest = null;
            var countryMap = new Map();

            function isZh() { return /^zh\b/i.test(document.documentElement.lang); }
            function text(en, zh) { return isZh() ? zh : en; }
            function number(value) { return new Intl.NumberFormat(isZh() ? "zh-CN" : "en").format(value || 0); }
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
            function metric(labelEn, labelZh, data) {
                var total = data || {};
                var el = document.createElement("article");
                el.className = "metric";
                el.innerHTML = '<div class="metric-label">' + text(labelEn, labelZh) + '</div>' +
                    '<div class="metric-value">' + number(total.subscription_requests) + '</div>' +
                    '<div class="metric-sub">' + text("Rules ", "规则 ") + number(total.rule_conversions) + '</div>';
                return el;
            }
            function renderMetrics(data) {
                var windows = data.windows || {};
                metricsEl.textContent = "";
                [
                    ["Since Start", "本次启动", windows.startup],
                    ["1 Hour", "1 小时", windows.hour],
                    ["1 Day", "1 天", windows.day],
                    ["7 Days", "7 天", windows.seven_days],
                    ["30 Days", "30 天", windows.thirty_days],
                    ["Lifetime", "历史总计", windows.lifetime]
                ].forEach(function (item) { metricsEl.appendChild(metric(item[0], item[1], item[2])); });
            }
            function renderChart(series) {
                chart.textContent = "";
                var max = Math.max(1, ...series.map(function (item) { return item.subscription_requests || 0; }));
                series.forEach(function (item) {
                    var bar = document.createElement("div");
                    bar.className = "bar";
                    bar.style.height = Math.max(4, Math.round(((item.subscription_requests || 0) / max) * 132)) + "px";
                    bar.title = fmtTime(item.time) + " / " + number(item.subscription_requests);
                    chart.appendChild(bar);
                });
            }
            function renderCountries(countries) {
                countryMap = new Map();
                countries.forEach(function (item) { countryMap.set(item.code, item); });
                countryStatus.textContent = text("Countries ", "国家 ") + number(countries.filter(function (item) { return item.code !== "ZZ" && item.code !== "XX"; }).length);
                countryBody.textContent = "";
                if (!countries.length) {
                    var row = document.createElement("tr");
                    var cell = document.createElement("td");
                    cell.colSpan = 3;
                    cell.className = "empty";
                    cell.textContent = text("No conversion data yet", "暂无转换数据");
                    row.appendChild(cell);
                    countryBody.appendChild(row);
                    return;
                }
                countries.slice(0, 12).forEach(function (item) {
                    var row = document.createElement("tr");
                    var name = document.createElement("td");
                    name.innerHTML = '<span class="country-icon">' + countryIcon(item.code) + '</span><span class="code-badge">' + item.code + '</span>' + countryName(item.code);
                    var req = document.createElement("td");
                    req.textContent = number(item.subscription_requests);
                    var rules = document.createElement("td");
                    rules.textContent = number(item.rule_conversions);
                    row.appendChild(name);
                    row.appendChild(req);
                    row.appendChild(rules);
                    countryBody.appendChild(row);
                });
            }
            function renderMap() {
                if (!mapData || !window.d3 || !window.topojson) return;
                var svg = d3.select("#world-map");
                var node = svg.node();
                var width = node.clientWidth || 800;
                var height = node.clientHeight || 430;
                svg.attr("viewBox", "0 0 " + width + " " + height);
                svg.selectAll("*").remove();
                var projection = d3.geoNaturalEarth1().fitSize([width, height], { type: "Sphere" });
                var path = d3.geoPath(projection);
                var features = topojson.feature(mapData, mapData.objects.countries).features;
                var max = Math.max(1, ...Array.from(countryMap.values()).map(function (item) { return item.subscription_requests || 0; }));
                var color = d3.scaleSequential([0, Math.log10(max + 1)], d3.interpolateYlGnBu);
                svg.append("path").datum({ type: "Sphere" }).attr("d", path).attr("fill", "transparent");
                svg.selectAll("path.country")
                    .data(features)
                    .enter()
                    .append("path")
                    .attr("class", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        return "country" + (countryMap.has(code) ? " has-data" : "");
                    })
                    .attr("d", path)
                    .attr("fill", function (d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")];
                        var item = countryMap.get(code);
                        if (!item) return "var(--map-empty)";
                        return color(Math.log10((item.subscription_requests || 0) + 1));
                    })
                    .on("mousemove", function (event, d) {
                        var code = ISO_N3[String(d.id).padStart(3, "0")] || "ZZ";
                        var item = countryMap.get(code) || { subscription_requests: 0, rule_conversions: 0 };
                        tooltip.innerHTML = '<div class="tooltip-title"><span class="country-icon">' + countryIcon(code) + '</span>' + countryName(code) + ' · ' + code + '</div>' +
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
                renderChart(data.series || []);
                renderCountries(data.countries || []);
                updatedAt.textContent = text("Updated ", "更新 ") + fmtTime(data.generated_at);
                renderMap();
            }
            async function refresh() {
                var response = await fetch("/dashboard/data", { cache: "no-store", headers: { "Accept": "application/json" } });
                render(await response.json());
            }
            document.getElementById("lang-toggle").addEventListener("click", function () {
                document.documentElement.lang = isZh() ? "en" : "zh-CN";
                localStorage.setItem("sce-dashboard-lang", document.documentElement.lang);
                document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
                if (latest) render(latest);
            });
            document.getElementById("refresh-button").addEventListener("click", refresh);
            document.getElementById("lang-toggle").textContent = isZh() ? "中" : "EN";
            Promise.all([
                fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(function (response) { return response.json(); }).catch(function () { return null; }),
                refresh()
            ]).then(function (values) {
                mapData = values[0];
                renderMap();
            });
            window.addEventListener("resize", function () { renderMap(); });
            setInterval(refresh, 30000);
        })();
    </script>
</body>
</html>)html";
}

} // namespace dashboard_page
