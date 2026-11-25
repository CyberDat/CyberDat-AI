# Global Cyber Threat Map — data sources

Checked on 2026-11-24 against the official pages linked below. A layer is enabled only when the source itself
gives the country; CyberDat does not use its own GeoIP database. The visitor's browser never contacts a source:
the server collects the data on a schedule (`wp cyberdat threatmap sync`) and keeps counters only.

| Layer | Source | Country from the source | Key | Enabled |
|---|---|---|---|---|
| `feodo` — botnet C2 servers | abuse.ch Feodo Tracker | yes, `country` (ISO 3166-1 alpha-2) | no | yes |
| `ransomware` — reported ransomware victims | Ransomware.live API PRO | yes, `country` (ISO 3166-1 alpha-2) | yes, free personal token | yes, when the key constant is set; otherwise "not configured" |
| — malware URLs | abuse.ch URLhaus | no | yes, Auth-Key | **no** |
| `radar` — DDoS targets (v1.1) | Cloudflare Radar API | yes, `targetCountryAlpha2`; values are percentages | yes, free API token | yes, when the token constant is set; otherwise "not configured" |

## abuse.ch Feodo Tracker

- **URL:** `https://feodotracker.abuse.ch/downloads/ipblocklist.json` (IOC dataset, JSON). The page with all
  formats: https://feodotracker.abuse.ch/blocklist/
- **Format:** a JSON array of objects with the fields `ip_address`, `port`, `status` (`online`/`offline`),
  `hostname`, `as_number`, `as_name`, `country`, `first_seen`, `last_online`, `malware`. Checked on the live file
  (2026-11-24). No history: the file is only the current list.
- **Key:** none.
- **Terms:** https://abuse.ch/terms-of-use/ section 3.4: Feodo Tracker data is "free to use without limitations
  according to Creative Commons principles (CC0) for both commercial and non-commercial purposes", served as is,
  best effort.
- **Frequency:** the blocklist is generated every 5 minutes (blocklist page). No query limit is published for
  Feodo Tracker. We fetch once an hour; `MIN_INTERVAL` = 300 s (the generation interval), so even `--force` cannot
  fetch more often than the file changes.
- **Conditional requests:** the server sends `ETag` and `Last-Modified`; `If-Modified-Since` returns `304`
  (checked 2026-11-24).
- **What we take:** the count of entries per `country` and per `malware` family. IP addresses, ports, host names
  and AS data are read only to validate the format and are never stored.
- **Note:** the Feodo Tracker FAQ (https://feodotracker.abuse.ch/faq/) says the datasets are nearly empty after
  the law-enforcement takedowns (Emotet 2021, Operation Endgame 2024). On 2026-11-24 the file had 5 entries in
  3 countries, last changed 2026-06-30. The layer is honest but sparse.
- **Records link:** https://feodotracker.abuse.ch/browse/ (the source has no per-country page).

## Ransomware.live (API PRO)

- **URL:** `https://api-pro.ransomware.live/victims/?year=YYYY&month=MM` (victims discovered in a month).
  API documentation: https://api-pro.ransomware.live/docs (Swagger at `/swagger.json`), overview
  https://www.ransomware.live/api
- **Format:** JSON list of victim objects. Documented fields include `victim`, `group`, `attackdate`,
  `discovered`, `country` (ISO 3166-1 alpha-2), `activity` (sector), `website`, `screenshot`, `infostealer`,
  `press`, `id`, `permalink`.
- **Key:** yes. API v2 (`api.ransomware.live`, no key) is "personal use only, not intended for corporate or
  business use", so we use API PRO: free personal token from https://my.ransomware.live sent in the header
  `X-API-KEY`. The key is read from the constant `CYBERDAT_RANSOMWARE_LIVE_API_KEY` in `wp-config.php`; it is never
  stored in the repository, the database, logs or error texts. Without the constant the layer is shown as
  "not configured".
- **Terms:** https://www.ransomware.live/t&c
  - Fair usage (section 4): no excessive polling; "our Data is cached for 30 minutes; polling more frequently than
    that interval brings no fresher results". No redistribution as an API, no raw data publishing, no cloning
    of the Ransomware.live site or dashboard look.
  - Non-commercial use (5.1) is free with attribution; **commercial use (5.2) needs prior written approval** of
    the owner of Ransomware.live. The site owner must confirm which case applies before the layer is switched on
    in production.
  - Attribution (section 6): "Ransomware.live must be clearly named as the source, linking back to
    ransomware.live, on any page … where this data is displayed". Recommended citation: "Source: Ransomware.live".
  - Section 7: inclusion in the data "does not constitute a determination or confirmation … that a claimed event
    occurred as described". The page says this.
- **Frequency:** quota 500,000 calls/month, fair use. `MIN_INTERVAL` = 1800 s (their 30-minute cache); we fetch
  once an hour: the current month every run, the previous months only to fill missing history and on the first
  two days of a month.
- **Conditional requests:** not documented; the collector sends `If-None-Match` / `If-Modified-Since` whenever the
  previous response had `ETag` / `Last-Modified` and accepts `304`.
- **What we take:** per victim only `country`, `activity` and the `discovered` date, turned into counts per
  country, per sector and per hour/day. Victim names, web sites, screenshots, infostealer data, press links, ids
  and permalinks are never stored. The page shows counts only; there is no public API or feed of the data.
- **Records link:** `https://www.ransomware.live/country/<CC>` (checked: a per-country page exists).

## Cloudflare Radar (v1.1, layer `radar` "DDoS targets")

Checked on 2026-11-25 against the official documentation.
- **URL:** `GET https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target`
  ([API reference](https://developers.cloudflare.com/api/resources/radar/subresources/attacks/subresources/layer7/subresources/top/subresources/locations/methods/target/)).
  Query: `dateRange=1d|7d|30d` plus the same value with `control` (`7dcontrol`) for the comparison window,
  `mitigationProduct=DDOS` (HTTP DDoS mitigation only, not WAF or bot rules), `limit=200`, `format=json`.
  One request per period: 3 requests per run.
- **Why layer 7, not layer 3/4:** the Radar glossary says that for layer 3/4 attacks "selected location is the
  location of the data center(s) where the attacks were mitigated", i.e. not the target. For layer 7 the target
  location is "determined by the attacked zone's billing country, when available".
- **Format:** `{"success": true, "result": {"meta": {"dateRange": [{startTime, endTime}, …], "lastUpdated",
  "normalization": "PERCENTAGE", …}, "top_0": [{"rank", "targetCountryAlpha2", "targetCountryName", "value"}],
  "top_1": [...]}}`. `value` is a string with a percentage "out of the total layer 7 attacks"; `top_1` is the control
  window. The collector rejects any answer whose `normalization` is not `PERCENTAGE`, so shares are never shown as
  counts. The page unit is "% of observed attacks"; the change is shown in percentage points.
- **Comparison:** given by the API (`<range>control`). The documentation says the control window is shifted back by
  the window's length rounded up to whole weeks, so for 24 h and 30 days it is not the immediately preceding period;
  the page labels it "vs comparison window" with its dates. CyberDat keeps no own history for this layer.
- **Key:** yes. A Custom API Token with "Account > Radar > Read"
  ([first request](https://developers.cloudflare.com/radar/get-started/first-request/)), sent as
  `Authorization: Bearer`. Read from the constant `CYBERDAT_CLOUDFLARE_RADAR_TOKEN` in `wp-config.php`; never stored.
  Without a token the API answers `9106 Missing X-Auth-Key, X-Auth-Email or Authorization headers` (checked).
- **Terms:** "Data available via Radar API endpoints is made available under the CC BY-NC 4.0 license"
  ([Radar docs](https://developers.cloudflare.com/radar/), [license](https://creativecommons.org/licenses/by-nc/4.0/)).
  CC BY-NC requires credit and a link to the license and forbids commercial use; the same owner decision as for
  Ransomware.live applies before the token is set in production. No exact citation text is published for API data;
  the page shows "Data: Cloudflare Radar (radar.cloudflare.com), licensed under CC BY-NC 4.0." with links to Radar
  and to the license.
- **Frequency:** the Cloudflare API limit is "1,200 requests per five minute period per user"
  ([limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/)); Radar publishes no update
  interval for this dataset. We fetch once an hour in the :47 slot; `MIN_INTERVAL` = 1800 s.
- **What we take:** per period the percentage per target country and the comparison percentage, the two windows and
  `lastUpdated`. Country names from the answer are not used (ours come from the ISO table).
- **Records link:** https://radar.cloudflare.com/ (a per-country page could not be verified: the site answers
  automated requests with a challenge).

## abuse.ch URLhaus — not enabled

- **URL:** https://urlhaus.abuse.ch/api/ (database dumps `/downloads/…`, bulk API `https://urlhaus-api.abuse.ch/`).
- **Key:** Auth-Key required (`https://urlhaus-api.abuse.ch/v2/files/exports/<Auth-Key>/recent.csv`).
- **Terms:** https://abuse.ch/terms-of-use/ section 3 and 4: free for not-for-profit use under fair-use volume
  limits; commercial or for-profit use may need a paid Spamhaus subscription.
- **Frequency:** dumps are generated every 5 minutes, "please do not fetch it more often than every 5 minutes".
- **Why not enabled:** the public documentation does not list a host-country field in the dumps or the bulk API
  (only a `geofenced` tag with NATO country codes that describes where a payload is served, not where the host
  is). A country would need our own GeoIP lookup of the hosts, which the brief forbids. The detailed export
  documentation is behind a login; if a future check shows a source-provided country field, the layer can be
  added with the same collector.

## Geometry

world-atlas 2.0.2, `countries-110m.json` (ISC license, data from Natural Earth, public domain), converted by
`tools/threat-map/build-geometry.cjs` into `wp-content/themes/cyberdat/assets/maps/threat-map-countries.json`
(equirectangular, Antarctica removed). See `wp-content/themes/cyberdat/assets/maps/NOTICE.md`.

Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m (v1.2).
Natural Earth draws de facto control, so the build script moves the Crimea polygon (found by its bounding box) from
Russia to Ukraine and merges it along the shared border, joins N. Cyprus to Cyprus and Somaliland to Somalia, and
keeps Kosovo separate (XK). Data are not re-attributed: if a source gives RU for something located in Crimea, the map
counts it for RU, because the source does not let us tell; the page says "Country attribution is taken from each
source as published."

## Flags (v1.1)

flag-icons 7.6.0 (npm, MIT), `flags/4x3` SVG, only the codes of `assets/maps/iso3166-1.json` (250). Built and
checked by `tools/threat-map/build-flags.cjs` with `tools/threat-map/svg-safety.cjs` (no scripts, event handlers,
foreignObject, external references, embedded images or styles); served from the theme, loaded lazily, decorative
(the country is always named in text). See `wp-content/themes/cyberdat/assets/flags/NOTICE.md`.

## Default layer (v1.1)

The tab order comes from the data: layers in status ok first, by the number of countries with data in 7 days, ties
in the order Ransomware.live, Cloudflare Radar, Feodo Tracker; if no layer is ok, Ransomware.live opens first with its
own status. A layer with fewer than 5 countries with data shows "Low activity in the source right now".
