# Global Cyber Threat Map — data sources

Checked on 2026-11-24 against the official pages linked below. A layer is enabled only when the source itself
gives the country; CyberDat does not use its own GeoIP database. The visitor's browser never contacts a source:
the server collects the data on a schedule (`wp cyberdat threatmap sync`) and keeps counters only.

| Layer | Source | Country from the source | Key | Enabled |
|---|---|---|---|---|
| `feodo` — botnet C2 servers | abuse.ch Feodo Tracker | yes, `country` (ISO 3166-1 alpha-2) | no | yes |
| `ransomware` — reported ransomware victims | Ransomware.live API PRO | yes, `country` (ISO 3166-1 alpha-2) | yes, free personal token | yes, when the key constant is set; otherwise "not configured" |
| — malware URLs | abuse.ch URLhaus | no | yes, Auth-Key | **no** |

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
