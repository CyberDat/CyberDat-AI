# Вычитка: Email Header Analyzer (integration/tools-utilities-1)

Для владельца. Все тексты на странице английские. Строки собраны автоматически из шаблона, app.js и движка (правила, список брендов), то есть это ровно то, что видит пользователь. Сначала — места, где нужно решение.

## Что проверить в первую очередь

| Место | Текст | Пометка |
|---|---|---|
| Плашка приватности | Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any mail, DNS or reputation service — and this tool does not write it to persistent browser storage. | Формулировка установленных страниц; перечень «mail, DNS or reputation service» — по смыслу инструмента. |
| Предупреждение | Headers only, no lookups. The tool reads what the mail servers recorded. It makes no DNS, WHOIS or reputation lookups and does not verify DKIM signatures. The message body and attachments are ignored. A message without findings is not shown to be safe or genuine. | Новое. |
| Limitations, 1-й пункт | No network lookups: the tool does not query DNS (SPF, DKIM, DMARC or MX records), WHOIS or the reputation of IP addresses and domains, and it does not verify DKIM signatures cryptographically. It shows the results the receiving servers already recorded. | Первым пунктом, как в задании. |
| Limitations, 2-й пункт | A message is never shown to be safe or genuine. A hijacked real account, or a message sent through a legitimate service, passes every check. | Вторым пунктом, как в задании. |
| Limitations, 3-й пункт | The trust boundary is an estimate from server names. … A forged result written just below your server’s own line can only be recognised when your server also wrote one above it. | Честная граница метода: поддельный Authentication-Results вплотную под строкой вашего сервера распознаётся только как дубликат. |
| Граница доверия у провайдера (2026-11-21) | Trust boundary: mx.google.com (mailbox provider for your domain). | Новая строка в блоке пояснений и в экспорте, по решению владельца; хост подставляется из Received. |
| Результат без находок | No known warning signs matched. This does not mean the message is safe. | Дословно из задания. |
| Sources | Public Suffix List by the Public Suffix List project (publicsuffix.org), Mozilla Public License 2.0, list of 2026-11-17 (SHA-256 809adae1a2cb…). It is published unmodified with this tool as public_suffix_list.dat together with the license text (LICENSE-MPL-2.0.txt). | Решение владельца 2026-11-19: MPL-2.0 принят; источник publicsuffix.org, закреплены SHA-256 и дата. |
| Список брендов | PayPal, Microsoft, Apple, Amazon, Google, DHL, DocuSign, Netflix, Sparkasse, Sberbank, Telekom, LinkedIn, Facebook, Dropbox, Adobe, FedEx, UPS, Booking.com | Мой короткий список: слова в отображаемом имени и домены брендов. Расширять ли его — решение владельца. Реальные домены брендов есть только в этом справочном списке; в корпусе и примерах — только зарезервированные домены. |
| Каталог и хаб | Email Header Analyzer · Quick Utilities · Quick utility · available | Решение владельца 2026-11-19: карточка остаётся, подпись «Quick utility» (одна строка в шаблоне хаба; карточки десяти без изменений). 2026-11-21: статус в каталоге available (итоговые статусы пакета); на хабе «Available» и «Open tool» только при опубликованной готовой странице, иначе «Coming soon» и «Quick utility». Адрес /tools/email-header-analyzer/ подтверждён. |

## Строки шаблона (55)

1. This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.
2. Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
3. Local only.
4. Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any mail, DNS or reputation service — and this tool does not write it to persistent browser storage.
5. Headers only, no lookups.
6. The tool reads what the mail servers recorded. It makes no DNS, WHOIS or reputation lookups and does not verify DKIM signatures. The message body and attachments are ignored. A message without findings is not shown to be safe or genuine.
7. Starting the local analyzer…
8. Add the message headers
9. Message headers or the whole message source
10. Gmail: open the message, More, Show original. Outlook: File, Properties, Internet headers (desktop) or View, View message source (web). Only the part before the first empty line is analysed; the body is ignored. Up to 5 MB.
11. Or open a saved message (.eml or .txt)
12. Your domain or mail server names (optional)
13. For example example.com, gateway.example.net. Servers of these domains are treated as yours, which sets the trust boundary more precisely. Lookalikes of these domains are reported.
14. Load phishing example
15. Load normal example
16. Clear
17. Analyze headers
18. Cancel
19. Progress
20. Review the analysis
21. Message
22. Findings
23. Delivery path, from sender to you
24. Authentication
25. Export
26. Mask recipient addresses
27. Mask internal IP addresses
28. Download report (Markdown)
29. Download report (JSON)
30. The report contains the findings, the parsed path and the authentication results; values that look like secrets are always masked. It never contains the message body. Choose the masking options before sharing it with colleagues.
31. How it works
32. Only the header block is read: long headers folded over several lines are joined, encoded names and subjects (such as =?UTF-8?B?…?=) are decoded with the browser’s built-in text decoder, and CRLF or LF line endings and extra spaces copied from webmail are handled.
33. Received lines are read from the bottom (sender) to the top (you): from, by, with, id, for, IP address and time, with the delay at each step. Formats from Gmail, Microsoft 365 and Exchange, Postfix, Exim, Sendmail and common gateways are recognised; a line that is not recognised is shown as written.
34. Trust boundary: the top lines are added by your own mail servers and can be believed. Everything below the first external server could have been written by the sender. The tool marks the assumed boundary; enter your domain or server names to set it more precisely.
35. Authentication-Results, ARC-Authentication-Results, Received-SPF and DKIM-Signature are read. SPF, DKIM, DMARC and ARC results are shown with the server that recorded them; results below the boundary or from an unknown server are marked as not trusted. Alignment compares the From domain with the SPF and DKIM domains using organizational domains from the Public Suffix List.
36. CyberDat rules then look for display names that name another address or a brand, Reply-To and Return-Path on other domains, lookalike domains (punycode, mixed alphabets, similar letters, digits for letters) compared with a short CyberDat brand list and with your own domain, missing or unusual Date and Message-ID, and mail software, originating IP and bulk-mail headers as information.
37. Engine %1$s · rules %2$s · Public Suffix List %3$s
38. Privacy
39. This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Internal IP addresses, addresses and server names in your headers stay in this tab.
40. Input fields and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.
41. If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.
42. This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.
43. Values that look like secrets are shown masked in results and reports; masking is best effort.
44. Limitations
45. No network lookups: the tool does not query DNS (SPF, DKIM, DMARC or MX records), WHOIS or the reputation of IP addresses and domains, and it does not verify DKIM signatures cryptographically. It shows the results the receiving servers already recorded.
46. A message is never shown to be safe or genuine. A hijacked real account, or a message sent through a legitimate service, passes every check.
47. The trust boundary is an estimate from server names. Gateways or forwarders run by another company are treated as external until you enter them as your own. A forged result written just below your server’s own line can only be recognised when your server also wrote one above it.
48. The body, links and attachments are not analysed. The brand list is short and written by CyberDat; lookalike detection compares spelling only and misses lookalikes of other names.
49. The formats of corporate Microsoft 365 and Exchange servers, mail gateways and most phishing variants were tested only on synthetic headers written by CyberDat, not on real mail. Real headers from these systems may contain variants the tool does not recognise.
50. Unusual Received formats may not be recognised. Organizational domains follow the bundled Public Suffix List snapshot; newer suffixes are unknown until the list is updated.
51. Input up to 5 MB, header part up to 1 MB. Processing stops after 30 seconds.
52. Sources
53. All rules, explanations, the brand list and the examples are written by CyberDat.
54. Public Suffix List by the Public Suffix List project (publicsuffix.org), Mozilla Public License 2.0, list of %1$s (SHA-256 %2$s…). It is published unmodified with this tool as public_suffix_list.dat together with the license text (LICENSE-MPL-2.0.txt).
55. Background reading: the IETF standards for message format, Received lines, Authentication-Results, SPF, DKIM, DMARC and ARC. They are referenced here by name only; no text is copied.

## Сообщения интерфейса из app.js (26)

1. No known warning signs matched. This does not mean the message is safe.
2. Browser not supported: this tool needs Web Workers, Unicode regular expressions and TextDecoder. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.
3. Starting the local analyzer…
4. The local analyzer could not start.
5. Ready. Headers are analyzed locally in this tab.
6. The local analyzer stopped. Reload the page.
7. The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.
8. Cancelled. Nothing was analyzed further.
9. Paste the message headers or open a saved message first.
10. The text is larger than 5 MB.
11. Analyzing the headers locally…
12. Processing took longer than 30 seconds and was stopped.
13. Trust boundary: your first server
14. Not verifiable (could be forged)
15. Not recognised, shown as written:
16. No message body was included; only headers were analyzed.
17. Minor and informational: 
18. No Received lines were found.
19. All steps are inside your organization (
20. It received the message from 
21. DKIM-Signature (not verified here): d=
22. No authentication headers were found.
23. The file is larger than 5 MB.
24. File opened in this tab (
25. The file could not be read.
26. Cleared. The headers and the results were removed from this page.

## Находки: заголовок, объяснение, что проверить дальше (29)

| Id | Уровень | Заголовок | Почему | Что проверить |
|---|---|---|---|---|
| EHA-PARSE-001 | info | Received line not recognised | The tool could not read the from/by parts of this Received line. It is shown as written and not used for the path. | Read the line yourself; unusual formats come from old or custom mail servers, but forged lines also look unusual. |
| EHA-PATH-001 | low | Times along the path go backwards | A server further along the path recorded an earlier time than the one before it, by more than 5 minutes. Clocks can be wrong, but forged Received lines below the trust boundary often have inconsistent times. | Compare the times above and below the trust boundary; only the lines above it were written by your servers. |
| EHA-PATH-002 | medium | Received date in the future | A server recorded a date more than 15 minutes after the time of this analysis. | Check whether the line is below the trust boundary (written by the sender) and whether the server clock was wrong. |
| EHA-PATH-003 | info | Long delivery time | More than an hour passed between the first and the last recorded hop. Queues, greylisting and retries are common causes. | Usually harmless. If the message claims urgency, the delay may simply mean it sat in a queue. |
| EHA-PATH-005 | low | No Received lines | Without Received lines the delivery path is unknown. The headers may be incomplete (for example copied from a mail client view) or the message was not delivered by SMTP. | Copy the complete original headers (Show original in Gmail, View message source or Message headers in Outlook). |
| EHA-PATH-006 | info | Received line without a date | A Received line has no date, so its place in time is unknown. | Usually a server quirk. Treat it with more caution if it is below the trust boundary. |
| EHA-AUTH-001 | high | DMARC failed | A receiving server you can trust recorded dmarc=fail: neither SPF nor DKIM confirmed the domain shown in From. Spoofed messages fail DMARC. | Treat the sender as unverified. Do not use links or attachments; confirm through a channel you already know. |
| EHA-AUTH-002 | medium | SPF did not pass | The sending server is not permitted by the SPF record of the envelope sender domain (fail, softfail or permerror), and DMARC did not pass. | Look at the sending IP in the trust-boundary hop and at the envelope sender (smtp.mailfrom or Return-Path). |
| EHA-AUTH-003 | medium | DKIM signature failed | A DKIM signature could not be verified (fail or permerror) and DMARC did not pass. The message may have been altered or the signature forged. | Check which domain (d=) signed and whether a forwarder or a mailing list changed the message. |
| EHA-AUTH-004 | low | No trusted authentication results | No SPF, DKIM or DMARC result written by a server inside the trust boundary was found. Either your server does not record them or the headers are incomplete. | Look for Authentication-Results added by your own mail server; enter your domain or server names to set the trust boundary. |
| EHA-AUTH-005 | medium | Untrusted authentication results claim a pass | Authentication-Results or Received-SPF that report a pass were written below the trust boundary or by a server that is not yours. Anyone can write such a header; senders add forged ones to look legitimate. | Ignore these results. Rely on the results written by your own servers, shown as trusted. |
| EHA-AUTH-006 | low | DMARC failed on a forwarded or list message | DMARC failed, but the message went through a forwarder or a mailing list (ARC pass recorded by your server, or a List-Id header). Forwarding and lists often break SPF and DKIM. A List-Id header can also be added by a sender. | Check the ARC results and the list or forwarding server. If you do not subscribe to such a list, treat it as a DMARC failure. |
| EHA-ALIGN-001 | medium | No sender identity matches From | Neither the SPF domain (envelope sender) nor a DKIM signing domain belongs to the same organizational domain as From, and no trusted DMARC result is recorded. | Ask whether the sending service is expected to send for this domain. Without alignment the From address is not confirmed. |
| EHA-RP-001 | info | Return-Path on another domain | Bounces go to a different organizational domain than From. Newsletter and ticket services do this routinely. | Usually harmless. It matters more together with failed authentication or a lookalike domain. |
| EHA-REPLY-001 | medium | Reply-To on another domain | Replies would go to a different organizational domain than the From address. Fraud messages use this to receive answers while showing a trusted sender. | Before replying, check the Reply-To address. Reply to a known address instead. |
| EHA-FROM-001 | medium | Another address or domain in the display name | The name shown in From contains an address or domain that is not the real sender address. Mail apps often show only the name. | Look at the actual address in angle brackets, not at the name. |
| EHA-FROM-002 | medium | Display name names a brand the address does not belong to | The name shown in From names a well-known company, but the sending domain is not one of its domains. | Do not trust the name. Go to the company website yourself instead of using links in the message. |
| EHA-FROM-003 | low | From missing or unusual | The From header is missing, empty or lists more than one address. | Treat the sender as unknown. |
| EHA-LOOK-001 | low | Internationalized domain | A sender domain is written in punycode (xn--), which mail apps may show with non-Latin or accented letters. Legitimate for many local names, but also used for lookalikes. | Compare the decoded form shown here with the domain you expect. |
| EHA-LOOK-002 | medium | Mixed alphabets in a domain | A domain label mixes letters from different alphabets, for example Latin and Cyrillic. This is a common way to imitate a domain. | Treat the domain as a lookalike unless you know it. |
| EHA-LOOK-003 | high | Lookalike domain | The From or Reply-To domain looks like a well-known brand or like your own domain (similar letters, digits for letters, rn for m, one changed letter, or the brand name inside another domain). | Compare letter by letter with the real domain. Do not use links, attachments or reply. |
| EHA-MSGID-001 | low | No Message-ID | Almost all mail software adds a Message-ID. Its absence suggests a hand-made or bulk-sending script. | Treat as a minor sign, stronger together with other findings. |
| EHA-MSGID-002 | info | Message-ID from another domain | The Message-ID was created under a different organizational domain than From. Many services (Outlook, newsletter tools) do this. | Usually harmless; it can show which system actually created the message. |
| EHA-DATE-001 | low | No Date | The Date header is required and normally set by the sending software. | Treat as a minor sign, stronger together with other findings. |
| EHA-DATE-002 | low | Unusual Date | The Date is in the future, far from the delivery time, cannot be read, or has a time zone that does not exist. | Compare it with the dates in the Received lines above the trust boundary. |
| EHA-INFO-001 | info | Mail software named | X-Mailer or User-Agent names the program that created the message. | Information only. Bulk-sending libraries in personal-looking mail can be a sign of a campaign. |
| EHA-INFO-002 | info | Originating IP recorded | X-Originating-IP shows the address of the device or webmail session that sent the message. | Information only. It can identify the sender's network; it is set by the sending service. |
| EHA-INFO-003 | info | Bulk or list mail | List-Unsubscribe, List-Id or Precedence marks a newsletter, notification or mailing list. | Information only. Lists explain some SPF and DMARC failures. |
| EHA-BRAND-001 | high | Claims a brand and fails authentication | The message presents itself as a well-known company (name or lookalike domain) and authentication failed or does not match From. | Treat as likely impersonation. Report it to your security team; do not use links, attachments or reply. |

## Список брендов (слова в имени → домены бренда)

- PayPal: paypal → paypal.com, paypal.de, paypal.me
- Microsoft: microsoft, office 365, microsoft 365, outlook, onedrive, sharepoint → microsoft.com, office.com, office365.com, outlook.com, live.com, hotmail.com, microsoftonline.com, sharepoint.com, onmicrosoft.com
- Apple: apple, icloud, itunes → apple.com, icloud.com, me.com, appleid.com (appleid.com добавлен 2026-11-21 по решению владельца: privaterelay.appleid.com)
- Amazon: amazon → amazon.com, amazon.de, amazon.co.uk, amazon.fr, amazonses.com, amazon.es, amazon.it
- Google: google, gmail → google.com, gmail.com, googlemail.com, youtube.com
- DHL: dhl → dhl.com, dhl.de
- DocuSign: docusign → docusign.com, docusign.net
- Netflix: netflix → netflix.com
- Sparkasse: sparkasse → sparkasse.de
- Sberbank: sberbank, сбербанк, сбер → sberbank.ru, sber.ru, sberbank.com
- Telekom: telekom → telekom.de, telekom.com, t-online.de
- LinkedIn: linkedin → linkedin.com
- Facebook: facebook, instagram → facebook.com, facebookmail.com, instagram.com, meta.com
- Dropbox: dropbox → dropbox.com, dropboxmail.com
- Adobe: adobe → adobe.com
- FedEx: fedex → fedex.com
- UPS: ups → ups.com
- Booking.com: booking.com → booking.com

## Editorial (editorial.json)

Предлагаемые поля страницы: title, summary, how_it_works, documentation, examples, faq, questions. Английский; «safe», «secure», «certified», «compliant» как обещание не используются.

