# Вычитка текстов четырёх страниц (release 1)

Для владельца. Ниже собраны все английские тексты страниц `/tools/log-anonymizer/`, `/tools/prompt-injection-detector/`, `/tools/lotl-command-analyzer/` и `/tools/mcp-security-checker/`: шаблоны страниц (How it works, Privacy, Limitations, блок лицензии, подписи интерфейса) и редакционные поля из `editorial.json`, которые вставляются на staging. Состояние — ветка `integration/tools-release-1`. Файл собран скриптом из исходников, тексты не пересказаны.

У каждой строки шаблона есть метка вида `[LA-T4]`. Фразы, которые обещают больше, чем инструмент гарантирует, перечислены сразу ниже. Тексты я не менял: решение за вами. Для каждой пометки предложен вариант замены.

## Пометки: где текст обещает больше, чем делает инструмент

| # | Где | Фраза | В чём проблема | Предлагаемая замена | Важность |
|---|---|---|---|---|---|
| 1 | MCP: [MSC-T46], [MSC-T58], editorial how_it_works | “Recognized credentials are masked on a best-effort basis; unknown secrets can remain” / “never displayed or exported in full” | Маскируются только секреты, которые движок **распознал** (известный формат, секретное имя переменной, флаг или заголовок, пароль в URL). Нераспознанный секрет в аргументах может попасть в однострочную сводку сервера и в поле «Found:» (например, внутри `bash -c "…"`). | “Recognized secret values are masked: only their kind, the first characters and the length are shown. A secret in an unusual form can still appear in server summaries — remove credentials before pasting.” | **высокая**: обещание приватности |
| 2 | LotL: [LCA-T33] | “The data file and the script that builds it are published in the CyberDat repository.” | Верно, пока репозиторий публичный и код влит в публикуемую ветку. Если сделать репозиторий приватным, утверждение станет ложным, а вместе с ним нарушится условие GPL-3.0 о доступе к исходникам (см. LICENSES.md, вариант A). | Зависит от решения по лицензии и видимости репозитория. При варианте A: дать прямую ссылку на исходники или указать, как их получить. | **высокая**: лицензия |
| 3 | LA: [LA-T52] | “No third parties: the page loads no external scripts, fonts or analytics.” | Проверено только на локальном WordPress. На staging и production страница рендерится темой и плагинами сайта (Rank Math и т. д.); внешние шрифты или аналитика сайта эту фразу нарушат. | Оставить, если Codex на staging подтвердит отсутствие сторонних запросов (шаг HANDOFF «Network»). Иначе: “The tool itself loads no external scripts…” | средняя: проверить на staging |
| 4 | Все четыре: [LA-T2], [PID-T2], [LCA-T2], [MSC-T2] | “Try a current version of Edge, Chrome, Firefox or Safari.” | Настоящий Safari и iPhone не тестировались (только движок WebKit в Playwright на Windows). | Оставить после ручной проверки в Safari и на iPhone (шаг HANDOFF). | средняя |
| 5 | LA: editorial faq “Can I reverse the anonymization?” | “Only with the replacement map you download yourself.” | Стабильные метки и контекст (время, порядок событий, сохранённые поля) позволяют частично восстановить идентичность и без карты; это сказано в [LA-T59], но FAQ звучит абсолютно. | “Not directly: labels replace the values. Context that is kept (timestamps, order of events, unmasked fields) can still help someone identify people or hosts.” | средняя |
| 6 | LotL: editorial documentation “Data and license” | “updated at build time by a script” | Обновление делается вручную, запуском скрипта; автоматического обновления нет. Снимок от 26.09.2026. | “a fixed snapshot shown on the page; it is updated manually with a script in the CyberDat repository” | низкая |
| 7 | PI: editorial documentation “Hidden text” | “elements hidden with CSS” | Распознаются только встроенные стили и атрибуты; классы из внешних таблиц стилей не анализируются ([PID-T63]). | “elements hidden with inline CSS or the hidden attribute” | низкая |
| 8 | LA: [LA-T46] | “the tool refuses to produce output if the number of lines would change” | Это проверка в движке, покрытая тестами структуры; формулировка верная. Отмечаю, потому что это сильное обещание: менять код без этой проверки нельзя. | Без изменений. | инфо |
| 9 | LA: editorial summary | “Redact IP addresses, emails, usernames, hostnames …” | Имена людей и телефоны не распознаются (теперь первый пункт Limitations), однословные имена хостов пропускаются. Summary этого не говорит. | Можно добавить: “… Names of people and phone numbers are not detected.” | низкая |

Исторический обзор формулировок; текущие результаты и ограничения браузерных проверок см. CLAIMS-AUDIT.md. Проверяемые свойства: «This tool does not transmit the text you enter» (CSP `connect-src 'none'`, сетевые API в воркере отключены, ноль запросов при обработке), «the tool does not write input/results to persistent browser storage», вывод только текстом, перезапуск воркера при Cancel.

---

# Полный текст страниц


# Privacy Shield Log Anonymizer — /tools/log-anonymizer/

## Page template (template-parts/tools/log-anonymizer.php)
- [LA-T1] This tool needs JavaScript. Processing happens only in your browser, so nothing can run without it — and nothing is uploaded.
- [LA-T2] Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
- [LA-T3] Local only.
- [LA-T4] Your log is processed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics — and it is not stored.
- [LA-T5] Review before sharing.
- [LA-T6] Automated anonymization cannot guarantee that every secret or personal detail is removed. Check the result manually before you share it.

### Add your log
- [LA-T7] Log text
- [LA-T8] Paste log lines or load a plain-text file (UTF-8 or UTF-16 with BOM, up to 50 MB). Files larger than 1 MB are processed in the background without being shown here.
- [LA-T9] Load a text file
- [LA-T10] Load a text file
- [LA-T11] Load sample log
- [LA-T12] Clear everything

### Choose what to mask
- [LA-T13] Categories
- [LA-T14] Select all
- [LA-T15] Select none
- [LA-T16] Replacement labels
- [LA-T17] Stable labels — the same value always gets the same label, so you can still follow it through the log
- [LA-T18] Generic labels — every value of a category gets the same label
- [LA-T19] Keep private and loopback IPv4 addresses
- [LA-T20] Leaves 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 and 169.254.0.0/16 unchanged. Internal addresses can still reveal your network layout.
- [LA-T21] Custom rules
- [LA-T22] Add your own JavaScript regular expressions, for example internal ticket or employee IDs. Each match is replaced with your label. Custom rules run first. Matches that span several lines are skipped so the log structure is kept.
- [LA-T23] Add custom rule
- [LA-T24] Pattern (regular expression)
- [LA-T25] Label
- [LA-T26] Ignore case
- [LA-T27] Remove rule
- [LA-T28] Anonymize log
- [LA-T29] Cancel
- [LA-T30] Anonymization progress

### Review the result
- [LA-T31] Replacements by category
- [LA-T32] Category
- [LA-T33] Replaced
- [LA-T34] Unique values
- [LA-T35] Preview
- [LA-T36] Replaced values are highlighted. Everything that is not highlighted is unchanged — read it carefully.
- [LA-T37] Copy result
- [LA-T38] Download result
- [LA-T39] Replacement map
- [LA-T40] Contains the original values.
- [LA-T41] The map lists every label next to the secret or personal value it replaced. Keep it private and never send it together with the anonymized log.
- [LA-T42] I understand that the map contains sensitive original values
- [LA-T43] Download replacement map (JSON)

### How it works
- [LA-T44] Your text or file is read by a background worker inside this browser tab, so large logs do not freeze the page.
- [LA-T45] Versioned detection rules scan each line for the categories you selected. Payment card numbers must pass the Luhn checksum; IPv6 and IPv4 candidates are validated, not just pattern-matched.
- [LA-T46] Only the detected values are replaced. Line breaks, delimiters, field names and timestamps stay where they were, and the tool refuses to produce output if the number of lines would change.
- [LA-T47] With stable labels, the same value receives the same label everywhere in one run, so you can still correlate events without revealing the value.
- [LA-T48] Engine %1$s · rules %2$s

### Privacy
- [LA-T49] This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections.
- [LA-T50] If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its two static script files again from this site. Those requests contain no part of your input.
- [LA-T51] The tool does not write input or results to persistent browser storage. Browser session restore, extensions, clipboard and user exports are outside this control.
- [LA-T52] No third parties: the page loads no external scripts, fonts or analytics.
- [LA-T53] Browser extensions you have installed can read page content. Use a private window without extensions for highly sensitive logs.

### Limitations of automated analysis
- [LA-T54] Names of people and phone numbers are not detected. A name is masked only when it appears as a user name in a recognized field (for example user=…, an email address or a login line); everywhere else, check names and phone numbers yourself.
- [LA-T55] Detection is pattern-based. Secrets without a recognizable format or key name (for example a bare random string) and street addresses are not detected.
- [LA-T56] Hostnames are found from URLs, known key names, syslog headers and a list of top-level domains. Single-word hostnames outside those contexts are missed.
- [LA-T57] Four-part numbers such as 1.2.3.4 are treated as IPv4 addresses unless a version keyword precedes them. Some identifiers may be masked unnecessarily.
- [LA-T58] Values split across lines, encoded (Base64, URL-encoding inside other values) or in binary formats are not reliably detected. US SSNs are only detected in the 123-45-6789 format.
- [LA-T59] Stable labels are consistent within one run only. Labels and their order can reveal how many distinct users or hosts appear.

## Editorial fields (deploy/tools-log-anonymizer/editorial.json)

### summary

Redact IP addresses, emails, usernames, hostnames, tokens, API keys, passwords, card numbers and private keys from logs in your browser before you share them.

### how_it_works

Paste a log excerpt or load a text file. A background worker in your browser tab scans every line with versioned detection rules and replaces only the sensitive value, so timestamps, field names, delimiters and the number of lines stay exactly as they were.
With stable labels, the same value gets the same placeholder throughout one run (IPV4_1, USER_2), so you can still follow an attacker, a session or a host through the log. Generic labels (REDACTED_IPV4) hide even that relationship.

### documentation

### What is detected
IPv4 and IPv6 addresses (validated, with an option to keep private ranges), email and MAC addresses, JSON Web Tokens, Bearer/Basic and other Authorization header values, common cloud and service API keys (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic and others), passwords and secrets in key=value, JSON, YAML and XML form, cookies, credentials inside URLs, PEM and OpenSSH private key blocks, usernames from sshd, sudo, PAM, Windows events and home-directory paths, hostnames and domains from URLs, syslog headers and known key names, payment card numbers that pass the Luhn check, and US Social Security numbers in 123-45-6789 format.
### Custom rules
Add JavaScript regular expressions with your own label for internal identifiers such as employee or ticket numbers. Custom rules run first; matches that would span several lines are skipped.
### Exports
Copy or download the anonymized log. The separate replacement map lists every label with its original value so you can interpret answers you receive — keep it private and never share it with the log.
### Limits
Inputs up to 50 MB. Detection is heuristic: free-text names, bare random secrets and encoded values can be missed, and some identifiers may be masked unnecessarily. Always review the result before sharing.

### examples

### Share an incident log with a vendor
Mask customer IPs, emails and session cookies while keeping the attack sequence readable through stable labels.
### Ask an AI assistant or a forum about an error
Remove hostnames, internal URLs, API keys and tokens from a stack trace before pasting it into a third-party service.
### Attach logs to a bug report
Keep line numbers and structure intact so developers can still match timestamps and fields.
Accepted password for alice from 203.0.113.7 port 52211
→ Accepted password for USER_1 from IPV4_1 port 52211

### faq

### Is my log uploaded to CyberDat?
No. This tool does not transmit the text you enter: processing happens entirely in your browser, the page blocks network connections from its scripts with a Content Security Policy, and no input is stored in cookies, local storage or the URL.
### Why do I see requests in my browser's Network tab?
Loading the page downloads its own files from cyberdat.eu, including the two scripts of the background worker. If you select Cancel, or processing times out, the worker is restarted and those two static script files are requested again. None of these requests contains any part of your input.
### Is the output guaranteed to be safe to share?
No. Automated detection cannot recognize every secret or personal detail. Review the highlighted preview and the unhighlighted text before you share anything.
### Why is 1.2.3.4 replaced?
A bare four-part number is indistinguishable from an IPv4 address, so it is masked unless a version keyword such as version, build or v precedes it.
### Can I reverse the anonymization?
Only with the replacement map you download yourself. CyberDat never sees or keeps it.


# Indirect Prompt Injection Sanitizer & Detector — /tools/prompt-injection-detector/

## Page template (template-parts/tools/prompt-injection-detector.php)
- [PID-T1] This tool needs JavaScript. Analysis happens only in your browser, so nothing can run without it — and nothing is uploaded.
- [PID-T2] Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
- [PID-T3] Local only.
- [PID-T4] Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any AI service — and it is not stored.
- [PID-T5] No guarantee of safety.
- [PID-T6] Automated analysis cannot detect every prompt injection: a reworded attack can pass every rule. A result without findings does not make a text safe, and neither the original nor the sanitized copy should be treated as trusted instructions.

### Add the untrusted text
- [PID-T7] Text to analyze
- [PID-T8] Paste text that an AI assistant or agent would read: a web page (HTML source works best), an email, a document, search results or tool output. You can also load a plain-text file (UTF-8 or UTF-16 with BOM, up to 20 MB). Files larger than 1 MB are analyzed in the background without being shown here.
- [PID-T9] Load a text file
- [PID-T10] Load a text file
- [PID-T11] Load example
- [PID-T12] Clear everything

### Sanitized copy options
- [PID-T13] Detection always runs on a normalized copy of the text and is not affected by these options. They only control what the sanitized copy changes.
- [PID-T14] Normalization
- [PID-T15] Remove invisible and bidirectional control characters
- [PID-T16] zero-width, Unicode tags, bidi overrides; emoji joiners are kept
- [PID-T17] Apply Unicode NFKC normalization
- [PID-T18] ｆｕｌｌｗｉｄｔｈ → fullwidth, ﬁ → fi, ² → 2 (can change the meaning of some symbols)
- [PID-T19] Replace flagged passages
- [PID-T20] All findings, including low severity
- [PID-T21] Medium and high severity
- [PID-T22] High severity only
- [PID-T23] Do not replace anything (normalization only)
- [PID-T24] Analyze text
- [PID-T25] Cancel
- [PID-T26] Analysis progress

### Review the findings
- [PID-T27] Findings by rule group and severity
- [PID-T28] Rule group
- [PID-T29] High
- [PID-T30] Medium
- [PID-T31] Low
- [PID-T32] Findings
- [PID-T33] No rule matched. This only means that none of the known patterns was found; the text can still contain an injection.
- [PID-T34] Normalization and decoding
- [PID-T35] Before matching, the tool removed invisible characters, applied Unicode NFKC and decoded encoded fragments. This is what changed or was decoded:
- [PID-T36] Decoded fragments
- [PID-T37] Position
- [PID-T38] Encoding
- [PID-T39] Decoded text
- [PID-T40] Text with findings highlighted
- [PID-T41] Invisible characters inside findings are shown as ⟨U+…⟩. Text that is not highlighted was not flagged, which does not mean it was checked as safe.

### Sanitized copy (secondary)
- [PID-T42] Still untrusted.
- [PID-T43] The sanitized copy only removes what the rules recognized. Anything the rules missed is still in it, and normalization can change the meaning of some characters. Review every change below before you use it.
- [PID-T44] Changes: before and after
- [PID-T45] Removed text is struck through, inserted text is underlined. Each change starts with “−” (removed) and “+” (inserted) for screen readers and high-contrast modes.
- [PID-T46] Copy sanitized copy
- [PID-T47] Download sanitized copy
- [PID-T48] Download findings (JSON)
- [PID-T49] The findings report contains short excerpts of your text. It is created in your browser and saved only where you choose.

### How it works
- [PID-T50] Your text or file is read by a background worker inside this browser tab, so large inputs do not freeze the page.
- [PID-T51] A normalized copy is built first: zero-width, tag, variation-selector and bidirectional control characters are removed and Unicode NFKC is applied. Base64, hex, URL-encoded and escaped fragments are decoded up to three layers deep. Every position is mapped back to your original text.
- [PID-T52] Versioned rules look for known injection techniques in seven groups:
- [PID-T53] Every finding has a rule id, a severity, its line and column and an explanation. Phrases that are quoted or given as examples ("phrases like …") are still reported, with low severity.
- [PID-T54] The sanitized copy is secondary: it removes invisible characters, applies NFKC and replaces flagged passages with a visible marker, and every change is listed so you can check it.
- [PID-T55] Engine %1$s · rules %2$s

### Privacy
- [PID-T56] This tool does not transmit the text you enter. The page has no server endpoint for your data, it does not call any AI model or external service, and its Content Security Policy blocks scripts on this page from opening network connections.
- [PID-T57] If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its two static script files again from this site. Those requests contain no part of your input.
- [PID-T58] The tool does not write input or results to persistent browser storage. Browser session restore, extensions, clipboard and user exports are outside this control.
- [PID-T59] The text is treated as data only: it is never executed, and it is displayed as plain text, never as HTML, so markup or scripts in it cannot run.
- [PID-T60] Browser extensions you have installed can read page content. Use a private window without extensions for confidential documents.

### Limitations of automated analysis
- [PID-T61] Detection is rule-based. Attacks written in new words, spread across several sentences or in other languages are not detected. Rules cover English, German and Russian; French and Spanish only for the most common override phrase. No rule set can recognize every prompt injection.
- [PID-T62] Some legitimate texts are flagged, for example security articles that quote attack phrases, documentation of chat templates or hidden menus in HTML. Quoted phrases get low severity, but quoting does not make an instruction harmless to a model.
- [PID-T63] Hidden text is found only in the HTML source: CSS classes defined in style sheets, images, PDF layers and text extracted by OCR are not analyzed. Paste the text extracted from a PDF; the file itself is not read.
- [PID-T64] Decoding covers Base64, hex, URL encoding and HTML/Unicode escapes. ROT13, ciphers, compression and instructions split across several fragments are not decoded.
- [PID-T65] NFKC normalization and character removal can change the meaning of mathematical symbols, ligatures or right-to-left text in the sanitized copy. Check the list of changes.
- [PID-T66] Large inputs (above about 10 MB) can take a long time, especially in Safari and other WebKit browsers. The limit is 20 MB.

## Editorial fields (deploy/tools-prompt-injection-detector/editorial.json)

### summary

Check web pages, emails, documents and tool output for prompt injection before an AI assistant reads them: role spoofing, override directives, hidden text, encoded and obfuscated payloads, with a reviewable sanitized copy. Runs in your browser.

### how_it_works

Paste untrusted text — ideally the HTML source of a page, or the text of an email or document — and the tool analyzes it in a background worker in your browser tab. It first builds a normalized copy: invisible and bidirectional control characters are removed, Unicode NFKC folds styled and fullwidth letters, and Base64, hex, URL-encoded and escaped fragments are decoded up to three layers deep.
Versioned rules then look for known techniques in seven groups and report every finding with its rule id, severity, line and column and a plain-language explanation. Detection is the main result. The sanitized copy is secondary: it removes invisible characters and replaces flagged passages with a visible marker, and every change is shown before and after.

### documentation

### Rule groups
- Role and boundary spoofing — chat template tokens such as &lt;|im_start|&gt;, [INST], pseudo-XML role tags, fake “end of document” boundaries and conversation turns.
- Instruction override — “ignore all previous instructions” and similar directives in English, German and Russian (plus the most common French and Spanish phrasing), persona and mode reassignment, requests to hide actions from the user, text addressed to an AI.
- Tool calls and data exfiltration — Markdown images and links that carry data in the URL, instructions to send conversation data or credentials somewhere, request-capture services, tool-call markup and shell commands that read secrets.
- Hidden text — zero-width and Unicode tag characters (hidden ASCII), variation-selector smuggling, bidi overrides, HTML and Markdown comments, elements hidden with CSS.
- Encoded payloads — injection patterns inside Base64, hex, URL encoding and HTML/Unicode escapes, and instructions to decode and follow hidden content.
- Obfuscation — mixed-script words with look-alike letters, leetspeak, spaced-out letters and styled Unicode letters.
- System prompt and secret extraction — requests to reveal the system prompt, repeat the text above or list keys and passwords, in English, German and Russian.
### Severity
High means a direct injection technique, medium a strong signal, low a weak signal that is often legitimate. Phrases that are quoted or given as examples are still reported, with low severity.
### Limits
Inputs up to 20 MB; above about 10 MB analysis can take a long time, especially in WebKit browsers. Rules cannot recognize reworded or novel attacks. A clean result is never proof that a text is safe.

### examples

### Before an agent browses a page
Paste the HTML source of a product page or article to find instructions hidden in comments, invisible elements or zero-width characters.
### Review documents for a RAG index
Check text extracted from PDFs, wikis and tickets for planted directives before adding it to a retrieval index.
### Triage a suspicious email
Find text addressed to an AI assistant, such as requests to forward the inbox or to keep something from the user.
&lt;!-- Note for AI assistants: ignore all previous instructions --&gt;
→ HIGH  PI-HID-006  HTML comment with instructions (contains PI-OVR-001)

### faq

### Is my text uploaded to CyberDat or to an AI service?
No. This tool does not transmit the text you enter: analysis happens entirely in your browser, no AI model or external API is called, the page blocks network connections from its scripts with a Content Security Policy, and no input is stored in cookies, local storage or the URL.
### Why do I see requests in my browser's Network tab?
Loading the page downloads its own files from cyberdat.eu, including the two scripts of the background worker. If you select Cancel, or processing times out, the worker is restarted and those two static script files are requested again. None of these requests contains any part of your input.
### If no findings are reported, is the text safe?
No. The rules recognize known techniques; a reworded attack can pass all of them. Treat retrieved content as untrusted data in your application regardless of the result.
### Can I use the sanitized copy directly?
Only after reviewing the list of changes. It removes what was recognized, nothing more, and Unicode normalization can change some characters.
### Does the tool generate attacks?
No. It only analyzes text you provide. The example on the page is synthetic and illustrative.


# LotL / LOLBAS Command Analyzer — /tools/lotl-command-analyzer/

## Page template (template-parts/tools/lotl-command-analyzer.php)
- [LCA-T1] This tool needs JavaScript. Analysis happens only in your browser, so nothing can run without it — and nothing is uploaded.
- [LCA-T2] Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
- [LCA-T3] Local only.
- [LCA-T4] Commands are analyzed in this browser tab as plain text. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to GitHub — it is never executed, and it is not stored.
- [LCA-T5] A match is not a verdict.
- [LCA-T6] Most binaries listed in LOLBAS are legitimate Windows components used every day. A match only means the command resembles a documented abuse technique; no match does not mean the command is safe.

### Add command lines
- [LCA-T7] Command lines, one per line
- [LCA-T8] Paste process command lines from an alert, EDR or Sysmon event. Log records with a CommandLine field (JSON or key: value) are recognized and the field is extracted. You can also load a text, CSV or JSON export (UTF-8 or UTF-16 with BOM, up to 5 MB).
- [LCA-T9] Load a text file
- [LCA-T10] Load a text file
- [LCA-T11] Load examples
- [LCA-T12] Clear everything
- [LCA-T13] Analyze commands
- [LCA-T14] Cancel
- [LCA-T15] Analysis progress

### Review the analysis
- [LCA-T16] Documented LOLBAS functions matched
- [LCA-T17] LOLBAS function
- [LCA-T18] Matches
- [LCA-T19] Commands
- [LCA-T20] Sorted by severity. “From LOLBAS” marks information taken from the LOLBAS Project data; “CyberDat heuristic” marks checks written for this tool.
- [LCA-T21] Download analysis (JSON)
- [LCA-T22] The report contains your command lines. It is created in your browser and saved only where you choose.

### How it works
- [LCA-T23] Each line is analyzed as text in a background worker. If the line is a log record, its CommandLine field is used.
- [LCA-T24] Simple obfuscation is undone statically: cmd.exe ^ escapes, quotes inside words, PowerShell backticks, look-alike dashes and letter case. PowerShell -EncodedCommand values (Base64 of UTF-16LE) and FromBase64String literals are decoded and analyzed too. Nothing is executed or evaluated.
- [LCA-T25] Binaries, scripts and libraries are looked up in a bundled snapshot of the LOLBAS Project. The command is compared with every documented LOLBAS usage of that binary by its flags and arguments.
- [LCA-T26] For each match the tool shows the LOLBAS function (for example Download, Execute, AWL Bypass), the description, the MITRE ATT&CK® technique id exactly as given in LOLBAS, and the LOLBAS detection hints. No technique mapping is added by CyberDat.
- [LCA-T27] Separate CyberDat heuristics point out encoded PowerShell, download patterns, obfuscation, unusual binary locations and similar signals. They have no ATT&CK mapping and are not detection rules.
- [LCA-T28] Engine %1$s · heuristics %2$s · LOLBAS data %3$s (%4$s)

### Data source and license
- [LCA-T29] Windows binary data comes from the LOLBAS Project (Living Off The Land Binaries, Scripts and Libraries), maintained by its contributors:
- [LCA-T30] Snapshot of commit %1$s from %2$s.
- [LCA-T31] The LOLBAS data is licensed under the GNU General Public License v3.0. This page uses a modified version: converted from YAML to JSON with a subset of fields (author, acknowledgement and resource links omitted).
- [LCA-T32] License text (GPL-3.0)
- [LCA-T33] The data file and the script that builds it are published in the CyberDat repository.
- [LCA-T34] MITRE ATT&CK® technique ids are shown as provided by LOLBAS. ATT&CK® is a registered trademark of The MITRE Corporation. “© 2021 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.” (notice as reproduced in the LOLBAS NOTICE file)
- [LCA-T35] Links to LOLBAS pages and detection references are ordinary links; nothing is loaded from them automatically. Microsoft® Windows® is a registered trademark of Microsoft Corporation.

### Privacy
- [LCA-T36] This tool does not transmit the text you enter. The LOLBAS data is part of this page, so no request is made to GitHub or any other service, and the page’s Content Security Policy blocks scripts on this page from opening network connections.
- [LCA-T37] If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.
- [LCA-T38] The tool does not write input or results to persistent browser storage. Browser session restore, extensions, clipboard and user exports are outside this control.
- [LCA-T39] Commands are treated as data only: they are never executed, and they are displayed as plain text, never as HTML.
- [LCA-T40] Browser extensions you have installed can read page content. Use a private window without extensions for sensitive incident data.

### Limitations of automated analysis
- [LCA-T41] Only Windows binaries documented in LOLBAS are recognized. Linux and macOS commands are not covered, and abuse techniques that LOLBAS does not document are only caught by the generic heuristics, if at all.
- [LCA-T42] Renamed or copied binaries are recognized only by name; the command line alone cannot show what file actually ran. Check the process image, hash and parent process.
- [LCA-T43] Deobfuscation is static and limited: environment-variable substrings, string concatenation, compression, nested encodings beyond two levels and script files referenced by the command are not resolved.
- [LCA-T44] Matching is based on flags and arguments in the documented LOLBAS commands. Unusual argument orders or abbreviations may be missed, and ordinary administrative commands can partially match a documented usage.
- [LCA-T45] Detection hints and references are the ones listed in LOLBAS. LOLBAS states that they do not guarantee detection; they are starting points for an investigation, not rules.

## Editorial fields (deploy/tools-lotl-analyzer/editorial.json)

### summary

Paste a Windows command line from a log or alert and see which built-in binaries it uses, which documented LOLBAS abuse techniques it resembles, the ATT&CK ids LOLBAS lists for them and what to look for next. Runs in your browser; commands are never executed.

### how_it_works

Living-off-the-land attacks use binaries that ship with Windows, such as certutil, mshta, regsvr32 or rundll32, so the executable alone tells you little. What matters is how it is called. The analyzer reads each command line as text in a background worker, removes simple obfuscation (cmd.exe ^ escapes, quotes inside words, PowerShell backticks, look-alike dashes) and decodes PowerShell -EncodedCommand values.
Every binary, script and library is looked up in a bundled snapshot of the LOLBAS Project, and the arguments are compared with each documented LOLBAS usage. Matches show the LOLBAS function, its description, the MITRE ATT&CK id given by LOLBAS and the LOLBAS detection hints. Separate CyberDat heuristics flag encoded PowerShell, download patterns, obfuscation and binaries started from unusual locations.

### documentation

### Input
One command per line, up to 5 MB. Log records that contain a CommandLine field (Sysmon, EDR exports in JSON or key: value form) are recognized and the field is analyzed.
### Output
- From LOLBAS: recognized binary, its documented functions (Execute, Download, AWL Bypass, Dump …), the documented usages the command matches fully or partly, the ATT&CK id exactly as in LOLBAS, IOC hints and detection references listed by LOLBAS.
- CyberDat heuristics: encoded PowerShell (decoded and analyzed), download and Invoke-Expression patterns, options that hide windows or bypass policy, obfuscation, script protocols, alternate data streams, user-writable paths and binaries outside their documented locations. Heuristics have no ATT&CK mapping.
### Severity
High: a documented abuse capability such as download, application-control bypass or credential dumping, or a download combined with execution. Medium: a specific documented usage or a suspicious pattern. Low: weak signals typical of administration. Info: a LOLBAS binary without a documented abuse pattern.
### Data and license
Windows data: LOLBAS Project, GPL-3.0, snapshot of a fixed commit shown on the page, updated at build time by a script in the CyberDat repository. Linux (GTFOBins) is not included.

### examples

### Triage an EDR alert
Paste the process command line to see whether it matches a documented download or proxy-execution technique and which ATT&CK id LOLBAS assigns.
### Read an encoded PowerShell command
The Base64 UTF-16LE value of -EncodedCommand is decoded statically and the decoded script text is analyzed for download and execution patterns.
### Review a batch of Sysmon events
Paste exported process-creation events; the CommandLine field of each record is extracted and the most suspicious commands are listed first.
certutil.exe -urlcache -split -f http://example.com/a.txt a.txt
→ HIGH  Certutil.exe · Download (T1105, from LOLBAS)

### faq

### Is my command line sent to CyberDat or GitHub?
No. This tool does not transmit the text you enter. The LOLBAS data is bundled with the page, the page blocks network connections from its scripts with a Content Security Policy, and the tool does not use persistent browser storage. Browser session restore, extensions, clipboard and downloaded files are outside this control.
### Why do I see requests in my browser's Network tab?
Loading the page downloads its own files from cyberdat.eu, including the worker scripts and the LOLBAS data file. If you select Cancel, the worker is restarted and these static files may be requested again. None of these requests contains any part of your input.
### Does a match mean the command is malicious?
No. Most LOLBAS binaries are legitimate system tools used every day. A match means the command resembles a documented abuse technique and deserves a look in context.
### No match: is the command safe?
No. Only techniques documented in LOLBAS and a few generic patterns are recognized.
### Does the tool build or run attack commands?
No. It only explains command lines you paste. Nothing is executed and no commands are generated.


# MCP Security & Policy Checker — /tools/mcp-security-checker/

## Page template (template-parts/tools/mcp-security-checker.php)
- [MSC-T1] This tool needs JavaScript. The check happens only in your browser, so nothing can run without it — and nothing is uploaded.
- [MSC-T2] Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
- [MSC-T3] Local only.
- [MSC-T4] The configuration is checked in this browser tab as text. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any registry — servers are not started, and the tool does not use persistent browser storage. Browser session restore, extensions, clipboard and downloaded files are outside this control.
- [MSC-T5] A review aid, not a guarantee.
- [MSC-T6] Findings are based only on the text you paste. A finding is a reason to look closer, not proof of an attack, and no finding does not mean the configuration is safe.

### Add a configuration or tool list
- [MSC-T7] MCP configuration or tool list (JSON)
- [MSC-T8] Accepted: client configurations with "mcpServers", "servers" or "mcp.servers" (command, args, env, url, headers), "context_servers", a single server object, and tool lists ({"tools": [...]} or a tools/list response) with names, descriptions and input schemas. Comments and trailing commas are accepted. Several JSON documents can be pasted one after another. Up to 5 MB.
- [MSC-T9] Load a JSON file
- [MSC-T10] Load a JSON file
- [MSC-T11] Load example
- [MSC-T12] Clear everything
- [MSC-T13] What to check
- [MSC-T14] Security check
- [MSC-T15] look for risky settings, secrets and suspicious tool descriptions
- [MSC-T16] Policy check
- [MSC-T17] compare the configuration with your own rules
- [MSC-T18] Your policy (JSON)
- [MSC-T19] The policy is kept only in this tab. Use “Download policy” to save it as a file; it is not stored anywhere else.
- [MSC-T20] Load a policy file
- [MSC-T21] Load a policy file
- [MSC-T22] Load example policy
- [MSC-T23] Download policy
- [MSC-T24] Policy settings
- [MSC-T25] All settings are optional. Lists accept * and ? wildcards (not in paths). Denied entries always take precedence over allowed ones.
- [MSC-T26] Must be 1.
- [MSC-T27] Executables that start servers, by name (npx, uvx, docker, node …), including commands wrapped in sudo or a shell.
- [MSC-T28] npm and Python package names and container image names.
- [MSC-T29] true: every package and image needs an exact version or digest.
- [MSC-T30] Host names of remote servers and of http(s) URLs in arguments. *.example.com matches subdomains only.
- [MSC-T31] true: remote servers must use https:// (localhost is exempt).
- [MSC-T32] Directories. A path is allowed when it is inside an allowed directory; it violates a denied path when it is inside it or contains it. ~ also matches /home/<name>, /Users/<name> and C:\Users\<name>.
- [MSC-T33] Any of "stdio", "http", "sse".
- [MSC-T34] Names of environment variables servers may receive.
- [MSC-T35] true: no credentials written directly in the configuration.
- [MSC-T36] Tool names that must not be offered (needs a tool list in the input).
- [MSC-T37] false: no automatic approval (autoApprove, alwaysAllow, trust).
- [MSC-T38] Upper limits, whole numbers.
- [MSC-T39] Check configuration
- [MSC-T40] Cancel
- [MSC-T41] Check progress

### Review the results
- [MSC-T42] Findings by rule group
- [MSC-T43] Rule group
- [MSC-T44] Findings
- [MSC-T45] Servers and tool lists
- [MSC-T46] Sorted by the highest severity. Recognized credentials are masked on a best-effort basis; unknown secrets can remain: only their kind, the first characters and the length.
- [MSC-T47] Download results (JSON)
- [MSC-T48] The report contains the findings and a one-line summary of each server, with secret values masked. It does not contain the full configuration. It is created in your browser and saved only where you choose.

### How it works
- [MSC-T49] The text is parsed in a background worker by a JSON reader written for this tool. It records line numbers and duplicate keys and never evaluates anything.
- [MSC-T50] Servers are recognized in the common client formats; tool lists are matched to their server when they are part of the same configuration.
- [MSC-T51] Security check: CyberDat rules in eight groups look at secrets, launch commands, file access, remote addresses, tool capabilities, tool description poisoning, duplicate or look-alike names and general hygiene. High severity is reserved for very explicit risks or a combination of signals.
- [MSC-T52] Policy check: your JSON policy is validated first, with clear messages for unknown settings and wrong types, then every server is compared with it.
- [MSC-T53] Each finding shows the server, the location in the configuration with its line, the severity, an explanation and a suggested fix. No corrected configuration is generated: you decide what to change.
- [MSC-T54] Engine %1$s · rules %2$s

### Privacy
- [MSC-T55] This tool does not transmit the text you enter. The page’s Content Security Policy blocks scripts on this page from opening network connections, and URLs found in your configuration are never opened or checked online.
- [MSC-T56] If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.
- [MSC-T57] The tool does not write input or results to persistent browser storage. Browser session restore, extensions, clipboard and user exports are outside this control.
- [MSC-T58] Masking is best effort, not a guarantee of secret removal. The JSON report contains findings and one-line server summaries with secrets masked, not the full configuration.
- [MSC-T59] Browser extensions you have installed can read page content. Use a private window without extensions for configurations that contain real credentials — or remove the credentials first.

### Limitations
- [MSC-T60] TOML and YAML are not supported. Only JSON (with comments) is read, so configurations in TOML or YAML must be converted first. Client settings stored elsewhere and environment variables resolved at runtime are not visible to the tool.
- [MSC-T61] Conclusions are based only on the text of the configuration and tool lists. The tool does not start servers or run commands, does not check the reputation of packages, images or domains online, and does not audit server code. A server can behave differently from its description.
- [MSC-T62] Tool descriptions and annotations come from the server and may be untrusted. A tool list you paste shows what the server reported at that moment; servers can change their tools later.
- [MSC-T63] Look-alike package detection compares names with a short built-in list of well-known MCP packages. It does not contact npm, PyPI, container registries or MCP registries.
- [MSC-T64] Description poisoning is recognized by wording, markup and hidden characters. Reworded or novel injections can be missed, and legitimate descriptions can occasionally match.
- [MSC-T65] Secret detection relies on variable names and known credential formats. Unusual secrets can be missed, and an ordinary value in a variable called “password” is reported as a secret.

### Sources
- [MSC-T66] All rules, explanations and the example policy are written by CyberDat. No external rule set or database is bundled.
- [MSC-T67] Background reading: the Model Context Protocol specification by the MCP project (sections “Security and Trust & Safety” and “Tools”, which state that tool descriptions and annotations should be treated as untrusted). It is referenced here by name only; no text is copied.

## Editorial fields (deploy/tools-mcp-checker/editorial.json)

### summary

Paste an MCP client configuration or a server's tool list and get a list of risks — secrets in the file, risky launch commands, broad file access, insecure remote servers, dangerous tools and poisoned tool descriptions — with explanations and suggested fixes. Optionally check it against your own JSON policy. Runs in your browser; servers are never started.

### how_it_works

Model Context Protocol (MCP) servers give AI assistants and agents tools: file access, shell commands, browsers, databases, email. The configuration that connects them decides how much power they get, and the tool descriptions they report are read by the model as instructions. The checker reads the configuration as text in a background worker, recognizes the common client formats (mcpServers, servers, mcp.servers, context_servers) and tool lists, and applies CyberDat rules in eight groups.
Every finding names the server, the location in the configuration with its line number, the severity, why it matters and what to change. High severity is reserved for very explicit risks or a combination of signals, such as automatic approval of a tool that runs commands. Recognized credentials are masked on a best-effort basis; unknown secrets can remain.

### documentation

### Input
JSON or JSON with comments, up to 5 MB: client configurations (command, args, env, url, headers, autoApprove), single server objects, and tool lists ({"tools": [...]} or a tools/list response) with names, descriptions, input schemas and annotations. Several documents can be pasted one after another.
### Rule groups
- Secrets: credentials in env, arguments, URLs and headers (known formats and secret-like names).
- Launch commands: download piped to a shell, shell wrappers, unpinned npx/uvx, privileged containers, root or home mounts, sudo, temporary folders, inline code, installs from Git.
- File access: file system root, home directory, credential folders, wildcards.
- Remote servers: plain HTTP, metadata addresses, tunnels, unusual hosts and ports, disabled TLS checks.
- Tool capabilities: command execution, file writes, arbitrary URLs, browsers, email, SQL, and private data combined with an outbound channel.
- Description poisoning: hidden characters, instruction overrides, concealment, requests for credentials, hidden markup, rules for other servers' tools.
- Names: the same or similar tool names on different servers, duplicate JSON keys, package names that resemble well-known MCP packages (short built-in list).
- Hygiene: unpinned images, missing directory limits, timeouts, automatic approval, very large tool lists.
### Policy check
A JSON policy lists allowed and denied commands, packages, hosts, paths, transports, environment variables and tools, plus switches such as requireHttps, requirePinnedVersions, forbidLiteralSecrets and allowAutoApprove. The policy is validated with clear messages and kept only in the browser tab unless you download it.

### examples

### Review a configuration before sharing it
Find tokens written directly in env or headers before a .mcp.json or claude_desktop_config.json ends up in a repository.
### Check a new server's tool list
Paste the tools/list output to look for hidden characters, instruction overrides and requests to pass files through tool arguments.
### Enforce a team policy
Load the example policy, adapt the allowed packages, hosts and paths, and check each configuration against it.
"args": ["-y", "@modelcontextprotocol/server-filesystem", "~"]
→ MEDIUM  MCP-FS-002 File access to the entire home directory

### faq

### Is my configuration sent to CyberDat or anyone else?
No. This tool does not transmit the text you enter. The page blocks network connections from its scripts with a Content Security Policy, URLs in the configuration are never opened, and the tool does not use persistent browser storage. Browser session restore, extensions, clipboard and downloaded files are outside this control.
### Why do I see requests in my browser's Network tab?
Loading the page downloads its own files from cyberdat.eu, including the worker scripts. If you select Cancel, the worker is restarted and these static files may be requested again. None of these requests contains any part of your input.
### No findings: is the configuration safe?
No. The check is based only on the text. It does not start servers, check packages or domains online, or audit server code.
### Does it fix the configuration?
No. It explains each issue and suggests a change; you decide what to edit.
### Does it test servers or generate attacks?
No. Nothing is executed and no prompts or servers are generated.
