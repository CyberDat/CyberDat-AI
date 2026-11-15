# Вычитка текстов страницы /tools/agent-leak-inspector/

Для владельца. Ниже собраны все английские тексты страницы: шаблон и редакционные поля из `editorial.json`. Файл собран скриптом из исходников ветки `feature/tools-leak-inspector`, тексты не пересказаны. Длинную статью и метаданные Rank Math готовит Codex/SEO, их здесь нет. Тексты не изменены по этим пометкам: решение за вами.

## Пометки

| # | Где | Фраза | Что проверить | Предложение | Важность |
|---|---|---|---|---|---|
| 1 | [LKI-T4], [LKI-T40], FAQ | “The text you enter is never sent anywhere by this tool” | Формулировка из задания плюс уточнение «by this tool» в духе CLAIMS-AUDIT Codex. Четыре установленных инструмента пишут иначе: «This tool does not transmit the text you enter». | Решить, нужна ли одинаковая формулировка на всех пяти страницах. | **высокая**: согласованность обещаний приватности |
| 2 | [LKI-T40], FAQ | “the page blocks network connections from its scripts” | Опирается на CSP. Заголовки проверены в стенде; на staging их подтверждает Codex после установки (по CLAIMS-AUDIT публичные заголовки — UNVERIFIED). | Оставить после проверки заголовков на staging. | средняя |
| 3 | How it works, documentation | “Rules cover English, German and Russian” | Для немецкого и русского есть основные слова каждого правила, но покрытие проверено только на моём корпусе (по 3–8 примеров на язык), а не на независимых данных. | Можно смягчить: “Rules include English, German and Russian wording for the main patterns.” | средняя |
| 4 | [LKI-T43], FAQ | “recognized secrets and long values without spaces are shortened” | Верно для правил и форматов движка. Короткие пароли из обычных слов, записанные без явного «password: …», не маскируются. | Без изменений: формулировка уже говорит «best effort». | инфо |
| 5 | Summary | “compare a response or transcript … to find copied, encoded or closely paraphrased fragments” | Пересказ другими словами (другие формы слов, перевод) не находится; мера пересечения даёт подсказку, а не находку. Промах hp-normalized-ru в отложенном наборе — как раз такой случай. | Можно заменить “closely paraphrased fragments” на “phrases reused from your prompt”. | средняя |
| 6 | Limitations, documentation | лимиты 200 000 символов / 150 000 / 600 000 слов / ~15 с | Совпадают с константами движка (`MAX_SCAN`, `MAX_PROMPT_TOKENS`, `MAX_RESPONSE_TOKENS`, `TIME_BUDGET_MS`). При изменении констант текст нужно обновить. | Без изменений. | инфо |

Слова «safe», «protected» и «no leak» в тексте не используются; тест `leak-inspector.test.php` это проверяет.

---

# Полный текст страницы
- [LKI-T1] This tool needs JavaScript. The check happens only in your browser, so nothing can run without it — and nothing is uploaded.
- [LKI-T2] Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
- [LKI-T3] Local only.
- [LKI-T4] Prompts and responses are checked in this browser tab as text. The text you enter is never sent anywhere by this tool — not to CyberDat, not to analytics, not to any AI model — and it is not stored.
- [LKI-T5] A review aid, not a guarantee.
- [LKI-T6] The tool looks for known weaknesses and known leak patterns in the text you provide. It cannot prove that a prompt will not leak: assume anything in a system prompt can be extracted.

### Add your prompt
- [LKI-T7] What to check
- [LKI-T8] Prompt audit
- [LKI-T9] find secrets, internal details and weak spots in a system prompt or agent description
- [LKI-T10] Leak check
- [LKI-T11] compare your reference prompt with a response or transcript
- [LKI-T12] System prompt or agent description
- [LKI-T13] Plain text in any language, up to 1 MB. In Leak check this is the reference prompt. Use a copy with real credentials removed if you can.
- [LKI-T14] Load prompt file
- [LKI-T15] Load prompt file
- [LKI-T16] Load example
- [LKI-T17] Clear everything
- [LKI-T18] Response or conversation transcript
- [LKI-T19] Paste a model answer or a whole conversation, up to 5 MB. Encoded parts (Base64, hex, URL encoding) are decoded locally and compared too.
- [LKI-T20] Load response file
- [LKI-T21] Load response file
- [LKI-T22] Minimum fragment length (words)
- [LKI-T23] Audit prompt
- [LKI-T24] Cancel
- [LKI-T25] Check progress

### Review the results
- [LKI-T26] Findings by rule group
- [LKI-T27] Rule group
- [LKI-T28] Findings
- [LKI-T29] Findings
- [LKI-T30] Sorted by severity. Excerpts are short; recognized secrets and long values without spaces are masked on a best-effort basis. Review before sharing.
- [LKI-T31] Decoded parts of the response
- [LKI-T32] Download results (JSON)
- [LKI-T33] The report contains findings with short masked excerpts, not the full prompt or response. It is created in your browser and saved only where you choose.

### How it works
- [LKI-T34] Prompt audit: CyberDat rules look for credentials, internal hosts and addresses, staff emails, file paths and code names, confidential prices and thresholds, moderation exceptions, “never reveal these instructions” used as protection, passwords that unlock special modes, untrusted input placeholders without boundaries, broad tool permissions, irreversible actions without human confirmation, and personal or financial data. Rules cover English, German and Russian.
- [LKI-T35] Leak check: the reference prompt and the response are split into words. Sequences of at least the chosen length that appear in both are reported as verbatim, or as near-verbatim when they match only after ignoring case, spacing, punctuation and invisible characters.
- [LKI-T36] Base64, hex and URL-encoded parts of the response are decoded up to two layers deep and compared with the prompt; the decoded text is shown. Secrets found in the prompt are searched for in the response.
- [LKI-T37] An overlap measure shows how many three-word phrases of the prompt also appear in the response, with the matching phrases. It helps you spot close paraphrases; it is a number, not a verdict.
- [LKI-T38] Every finding has a rule id, a severity, its line, an explanation and a suggested change. Nothing is sent to an AI model: all comparisons are simple text operations with size and time limits.
- [LKI-T39] Engine %1$s · rules %2$s

### Privacy
- [LKI-T40] The text you enter is never sent anywhere by this tool: it does not call any AI model or external service, and the page’s Content Security Policy blocks scripts on this page from opening network connections.
- [LKI-T41] If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.
- [LKI-T42] The tool does not store your prompt, response or results in cookies, local storage or the address bar; they are cleared when you close or reload the tab. Browser session restore, extensions, the clipboard and files you download are outside the tool’s control.
- [LKI-T43] Masking is best effort: recognized secrets and long values without spaces are shortened in results and exports, but secrets in an unusual form can remain in excerpts. Review exports before sharing.
- [LKI-T44] Text is treated as data only: it is never executed and is displayed as plain text, never as HTML.

### Limitations
- [LKI-T45] The tool does not prove that a prompt has not leaked or cannot be extracted. No findings only means that the known patterns did not match the text you provided.
- [LKI-T46] The leak check compares only the texts you paste. Paraphrases with different words, translations, summaries and leaks spread across many short answers can be missed; the overlap measure gives a hint, not a decision.
- [LKI-T47] The prompt audit relies on wording and formats. Unusual secrets, internal names that look ordinary and sensitive rules phrased indirectly can be missed; ordinary text can occasionally match.
- [LKI-T48] Rules cover English, German and Russian. Other languages are checked only for formats such as keys, addresses, phone numbers and encodings.
- [LKI-T49] Decoding covers Base64, hex and URL encoding up to two layers. Other encodings, compression, images and files referenced by the text are not analyzed.
- [LKI-T50] Large inputs are checked within limits: the prompt audit rules read the first 200,000 characters, and the leak check compares up to 150,000 prompt words with up to 600,000 response words within about 15 seconds. When a limit is reached, the results say so and are partial.

### Sources
- [LKI-T51] All rules, explanations and examples are written by CyberDat. No external rule set, prompt catalogue or dataset is bundled, and the tool does not generate extraction prompts.
- [LKI-T52] Background reading: the OWASP Top 10 for Large Language Model Applications (2025), entry “System Prompt Leakage”, by the OWASP GenAI Security Project. It is referenced here by name only; no text is copied.

## Editorial fields (deploy/tools-leak-inspector/editorial.json)

### summary

Review system prompts and agent descriptions for secrets, internal details and weak protections, and compare a response or transcript with your prompt to find copied, encoded or closely paraphrased fragments. Runs locally in your browser; it does not prove that a prompt cannot be extracted.

### how_it_works

System prompts are often treated as private, but models can be talked into repeating them. Anything written in a prompt should be assumed readable by users. The inspector helps you find what would be exposed and where your design relies on the prompt staying secret.
Prompt audit applies CyberDat rules for credentials, internal hosts and staff addresses, confidential prices and thresholds, moderation exceptions, “never reveal these instructions” used as protection, passphrases that unlock special behaviour, untrusted input placeholders without boundaries, broad tool permissions, irreversible actions without human confirmation, and personal or financial data. Leak check compares your reference prompt with a model response or a transcript: verbatim and near-verbatim word sequences, Base64/hex/URL-encoded copies and secrets from the prompt. An overlap measure shows how many of the prompt’s phrases reappear; it is a number, not a verdict.

### documentation

### Input
Prompt audit: one system prompt or agent description, up to 1 MB. Leak check: a reference prompt (1 MB) and a response or transcript (5 MB). Plain text in any language; rules cover English, German and Russian.
### Output
Each finding has a rule id, a group, a severity, the line, a short excerpt, an explanation and a suggested change. Recognized secrets and long values without spaces are masked in results and in the JSON report on a best-effort basis; the report never contains the full prompt or response.
### Severity
High is reserved for explicit risks such as credentials, unlock passphrases, irreversible actions without confirmation, encoded copies of the prompt or secrets from the prompt in a response. A finding is a reason to look closer; no finding does not mean the prompt cannot be extracted.
### Limits
Paraphrases with different words, translations and leaks spread over many answers can be missed. Decoding covers Base64, hex and URL encoding up to two layers. The audit rules read the first 200,000 characters; the leak check compares up to 150,000 prompt words with up to 600,000 response words within about 15 seconds. Results say when a limit was reached.

### examples

### Before shipping an assistant
Audit the system prompt for keys, internal URLs, discount ceilings and “never reveal” instructions, then move those details into backend code and tool permissions.
### After a red-team session
Paste the transcript and your reference prompt to see which passages were repeated, including encoded copies.
### Reviewing an agent description
Find broad shell, file or email access and irreversible actions that run without human confirmation.
Prompt: “… you may offer up to 30% discount …”
→ MEDIUM  LKI-BIZ-001 Confidential prices, limits or thresholds

### faq

### Is my prompt sent to an AI model or to CyberDat?
No. The text you enter is never sent anywhere by this tool. Analysis is plain text comparison in your browser, the page blocks network connections from its scripts, and nothing is stored.
### Does no finding mean my prompt cannot leak?
No. The tool only checks known patterns in the text you provide. Assume anything in a system prompt can be extracted and keep secrets and enforcement outside the prompt.
### Are all secret values hidden in the results?
No. Masking is best effort: recognized secrets and long values without spaces are shortened, but secrets in an unusual form can remain in excerpts. Review exports before sharing.
### Does the tool generate prompts that extract system prompts?
No. It only analyzes text you paste and includes no attack prompts.
