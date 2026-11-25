# Threat map fixtures (synthetic, de-identified)

- `feodo-ipblocklist.json` — the format of `https://feodotracker.abuse.ch/downloads/ipblocklist.json` (fields as in
  the live file on 2026-11-24). Every `ip_address` is from the RFC 5737 documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24), host names are null, AS data is a placeholder. Not real C2 servers.
- `ransomware-2026-11.json` — the documented fields of the Ransomware.live API PRO `/victims/` list. `victim` is always
  `VICTIM-PLACEHOLDER`; `website`, `screenshot`, `infostealer`, `press`, `id` and `permalink` are empty. Countries,
  sectors and dates are invented; edge cases: empty and null country, lower-case code, empty sector.

The tests add URLs, IP addresses and names at run time to prove that none of them reaches the history or the snapshot.
