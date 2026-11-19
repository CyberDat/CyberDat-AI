# Independent acceptance — Email Header Analyzer

For the owner (who prepares the set) and Codex (who runs it). All numbers published by the tool author are **not
independent**. Real headers stay **outside the repository**; only the summary line and the file hash are shared.

## 1. Collect 10–15 header sets

Mix ordinary wanted mail (newsletters, colleagues, a mailing list, a forwarded message) with spam and phishing, from
Gmail and Outlook.

* **Gmail (web):** open the message → ⋮ (More) → *Show original* → *Copy to clipboard* (or *Download original*, an .eml file).
* **Outlook (desktop):** open the message → *File* → *Properties* → copy *Internet headers*.
* **Outlook on the web / new Outlook:** open the message → ⋯ → *View* → *View message source* (or *View message details*).

Copy only the headers: delete everything after the first empty line (the body). The runner ignores the body anyway,
but it must not be stored in the set.

## 2. Replace before handing over

Replace consistently in every header of a message (the same value → the same replacement):

| What | Replace with |
|---|---|
| Your own and colleagues' addresses (To, Cc, Delivered-To, `for <…>` in Received, X-Original-To) | `user1@example.com`, `user2@example.com` … |
| Your organization's domain and internal server names | `example.com`, `mx.example.com`, `exch01.corp.example.com` |
| Internal IP addresses (10.x, 172.16–31.x, 192.168.x, fd00::/8) | other addresses in the same private range (keep them private) |
| Sender addresses of real people (not companies) | `sender1@example.org` … |
| Subjects and display names with personal or confidential content | a neutral text in the same language |
| Tokens in X- headers, tracking ids that look like secrets | `REMOVED` |

**Keep unchanged:** sender domains of companies and spammers, public IP addresses of external servers, the
Authentication-Results, ARC, Received-SPF and DKIM-Signature lines (except the replaced own domain consistently),
dates, Message-ID domains. Changing them changes what is measured. If you replace your domain, enter the replacement
as `own` for the case.

## 3. Label before the first run

Write the expected finding ids (see `rules.json`) **before** running the tool: either `expect` (exact list) or
`include`/`exclude` (ids that must or must not appear); `ignoreInfo: true` ignores info-level items. Mark ordinary
wanted mail with `benign: true` (the runner counts high findings on them). Optionally `dmarc` (the trusted DMARC result
you see in your own server's Authentication-Results) and `external` (the first external server).
Set `"provenance": "owner"` and `"authoredByToolAuthor": false`. Freeze the file.

## 4. Run locally

```
node tests/email-header-analyzer-independent.cjs /private/path/set.json --details
```

The output contains case ids, finding ids, counts and the file hash only — never header text. Nothing is sent anywhere.
Publish only the summary and the hash. Fixes after acceptance must be checked on new messages; the accepted set then
counts as used.

## Format

`template.json` (format example with two synthetic cases).
