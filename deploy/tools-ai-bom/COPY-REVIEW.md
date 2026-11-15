# Вычитка: тексты AI Model Bill of Materials (feature/tools-ai-bom)

Для владельца. Все тексты на странице английские. Ниже — строки, которые видит пользователь, собранные автоматически из шаблона, app.js и движка (правила). Сначала — места, где нужно решение.

## Что проверить в первую очередь

| Место | Текст | Пометка |
|---|---|---|
| Плашка приватности | “Your entries are processed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any model registry — and this tool does not write it to persistent browser storage.” | Формулировка с установленных страниц: «This tool does not transmit the text you enter — not to CyberDat, not to analytics … — and this tool does not write it to persistent browser storage». Перечень «not to any model registry» — по аналогии с MCP («not to any registry»). |
| Privacy, первый пункт | “This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Addresses in your entries are never opened or checked online.” | Первые два предложения дословно как у Log Anonymizer; третье — про адреса, как у MCP. |
| Privacy, пункт о переводчике | “Input fields, previews and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.” | Новый пункт: объясняет translate="no". |
| Limitations, первый пункт | “The document reflects only what you enter. The tool does not check whether entries are true, does not contact model registries and does not evaluate the model itself.” | Первым пунктом, как требует задание. |
| Limitations, второй пункт | “The tool helps document a model and its supply chain. It does not determine whether a system meets any law, regulation or standard.” | Вместо «compliant / соответствует EU AI Act, NIST, ISO». Названия законов и стандартов на странице не упоминаются. |
| Результат без находок | “No known gaps matched. This does not mean the model or its supply chain is safe.” | Дословно из задания. |
| Sources | “Format: the CycloneDX specification, version 1.7, by the OWASP CycloneDX project, published under the Apache License 2.0. It is referenced here by name only; no specification or schema text is copied, and the structure check is CyberDat’s own.” | Ссылок нет, только название. Лицензия Apache-2.0 проверена по файлу LICENSE и полю $comment схемы в теге 1.7.2. |
| Написание | license / licenses | Везде американское написание, как в CycloneDX и SPDX. |

## Все строки шаблона (130)

1. Weights files
2. Add weights file
3. Weights file
4. Data
5. Add dataset
6. Dataset
7. Dependencies
8. Add dependency
9. Dependency
10. External APIs
11. Add external API
12. External API
13. Quality metrics
14. Add metric
15. Metric
16. This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.
17. Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.
18. Local only.
19. Your entries are processed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any model registry — and this tool does not write it to persistent browser storage.
20. A documentation aid, not an assessment.
21. The document reflects only what you enter. The tool does not check whether entries are true, does not contact model registries and does not evaluate the model itself.
22. What do you want to do?
23. Build
24. fill in the form and get an AI BOM (CycloneDX JSON and Markdown)
25. Review
26. paste an existing AI BOM in CycloneDX JSON and get a list of gaps and risks
27. Describe the AI system
28. All fields are optional; empty fields are reported as gaps. Do not enter passwords, keys or tokens: refer to a secret by its name in your vault instead.
29. Load example
30. Clear everything
31. Model
32. Name
33. Version
34. Exact version, snapshot date or revision — not “latest” or a branch.
35. Vendor
36. License
37. SPDX identifier such as Apache-2.0, or the name of the terms.
38. Type
39. — not stated —
40. Own model
41. Fine-tuned model
42. External model used through an API
43. Base model (for a fine-tuned model)
44. Base model version
45. Deployment
46. Where it runs
47. For example: on-premises cluster, cloud region, user devices.
48. Purpose and limitations
49. Intended purpose
50. What the model is used for and by whom.
51. Limitations
52. Languages, inputs and situations where results are unreliable or the model must not be used.
53. Quality and safety evaluation
54. File name
55. Format
56. Hash algorithm
57. Hash (hex digest)
58. Source
59. Used for
60. Training
61. Fine-tuning
62. Evaluation
63. Contains personal data
64. Yes
65. No
66. Unknown
67. Kind
68. Framework
69. Library
70. Address
71. Value
72. Measured on
73. Remove
74. Safety evaluation
75. How the model was checked for harmful or unsafe output, data leakage or misuse, and when.
76. Responsible
77. Person or team
78. Organization
79. Contact (e-mail or URL)
80. Add an AI BOM
81. AI BOM in CycloneDX JSON
82. CycloneDX JSON, specVersion 1.5 to 1.7, with components of type machine-learning-model, data, file, framework or library. Strict JSON: comments and trailing commas are reported as errors. Up to 5 MB.
83. Load a JSON file
84. Load example BOM
85. Clear
86. Check and build
87. Cancel
88. Progress
89. Review the gaps
90. Findings by group
91. Group
92. Findings
93. Structure
94. Checked against the subset of CycloneDX fields that this tool reads and writes; other fields are not validated.
95. What the BOM contains
96. Open in the Build form
97. Download findings (JSON)
98. The findings file contains the findings with recognized secrets masked, not the BOM itself.
99. Export
100. I have checked these values and want to export the document anyway. The exported files contain them unmasked.
101. Download CycloneDX JSON
102. Download Markdown
103. Both files contain your entries as typed (secrets are masked only in the findings). They are created in your browser and saved only where you choose.
104. Preview: CycloneDX JSON
105. Preview: Markdown
106. How it works
107. Build: the form is read in this tab and checked by CyberDat rules in a background worker. The result is a CycloneDX 1.7 document with a component of type machine-learning-model and its model card, plus a Markdown version for people to read.
108. Review: the pasted JSON is read by a strict JSON reader written for this tool, which records line numbers and duplicate keys and never evaluates anything. Keys are matched regardless of case, underscores, hyphens and camelCase, and non-standard spellings are reported.
109. Rules in ten groups look for missing or unknown licenses, floating versions, weights without a hash or in pickle-based formats, fine-tuned models without a base model, datasets without a source or personal-data status, unpinned dependencies, http:// addresses, secrets, and missing purpose, limitations, evaluation or owner.
110. Each finding shows where it was found, its severity, why it matters and a suggested change. Secrets are shown only as their type and a masked fragment.
111. Fields that CycloneDX has no place for (model type, personal-data status, dataset use, deployment, safety evaluation) are stored as properties named cyberdat:aibom:…, so a document exported here can be reviewed here again with the same content.
112. Engine %1$s · rules %2$s · CycloneDX %3$s
113. Privacy
114. This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Addresses in your entries are never opened or checked online.
115. Input fields, previews and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.
116. If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.
117. This tool does not persist data: the form, the pasted BOM and the results are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.
118. Masking in the findings is best effort. Exported BOM files contain your entries unmasked; if values that look like secrets are found, the export asks for confirmation first.
119. The document reflects only what you entered. The tool does not check whether the entries are true, does not contact model registries, package indexes or dataset sources, and does not evaluate the model or its outputs.
120. The tool helps document a model and its supply chain. It does not determine whether a system meets any law, regulation or standard.
121. Only CycloneDX JSON is supported. SPDX, CycloneDX XML and other formats are not read or written in this version.
122. The structure check covers only the CycloneDX fields this tool uses. License identifiers are not checked against the full SPDX list, and other parts of a document are not validated.
123. “Unknown” is recognized in English, German and Russian and in common abbreviations such as n/a and TBD; other wordings are read as a stated value.
124. Pickle-based formats are recognized by file extension and the format you enter. A file can be pickle-based under another name.
125. Secret detection relies on known credential formats, secret-like names and a heuristic for long random-looking values. Unusual secrets can be missed, and an ordinary long value can be reported.
126. Text is stored in Unicode NFC: names typed with separate combining marks are exported in their composed form, which looks the same.
127. Review reads up to 5 MB. Processing stops after 120 seconds.
128. Sources
129. All rules, explanations and recommendations are written by CyberDat. No external rule set, model registry or database is bundled.
130. Format: the CycloneDX specification, version 1.7, by the OWASP CycloneDX project, published under the Apache License 2.0. It is referenced here by name only; no specification or schema text is copied, and the structure check is CyberDat’s own.

## Сообщения интерфейса (app.js)

- No known gaps matched. This does not mean the model or its supply chain is safe.
- Weights files
- Browser not supported: this tool needs Web Workers and Unicode regular expressions. Use a current version of Edge, Chrome, Firefox or Safari. Nothing was sent anywhere.
- Worker must be same-origin.
- The background worker stopped unexpectedly. Nothing was sent anywhere. Reload the page and try again.
- Checking the BOM locally…
- Checking and building locally…
- Processing took longer than 
-  seconds and was stopped.
- Cancelled. Nothing was processed further.
- The JSON could not be read: 
- The input could not be processed.
- Suggested change: 
- Secrets or high-risk gaps found.
- Remove secrets before you share this document.
- Gaps worth fixing found.
- Each one is listed with a suggested change.
- Only minor gaps found.
- This does not mean the model or its supply chain is safe.
- Checked the form
-  are not shown here; they are included in the downloads.
- Review the gaps
- Review the gaps and export
- Model components
- External APIs
-  that look like secrets or credentials 
-  found (see the findings). The preview below shows them masked. Remove them from the form, or confirm to export anyway.
- Input changed. Run the check again to update the result.
- Confirm the export first: the document contains values that look like secrets.
- CyberDat AI Model Bill of Materials
- Findings only; the BOM itself is not included. Recognized secrets are masked. The tool does not verify entries and does not assess the model. No finding does not mean the model or its supply chain is safe.
- Findings downloaded. The file contains findings with secrets masked, not the BOM.
- Check the BOM
- Check and build
- The BOM was copied into the Build form. Check it and select “Check and build”.

## Правила: заголовок, объяснение, рекомендация

| Id | Серьёзность | Заголовок | Объяснение | Рекомендация |
|---|---|---|---|---|
| AIBOM-LIC-001 | medium | Model license missing or unknown | Without a license nobody can tell whether the model may be used, changed or redistributed in this system. | Add the license of the model as an SPDX identifier (for example Apache-2.0) or the name of the license terms. |
| AIBOM-LIC-002 | medium | Dataset license missing or unknown | The terms of the data used for training or fine-tuning can restrict how the model may be used. | Add the license or the terms under which the dataset was obtained. |
| AIBOM-VER-001 | medium | Model version missing | Without a version the document cannot say which model was reviewed, and a later model can silently replace it. | Add the exact version, release date or revision of the model. |
| AIBOM-VER-002 | medium | Model version is floating | A branch name, “latest” or a range can point to a different model tomorrow, so the document no longer describes what runs. | Use an exact version, snapshot date or commit revision instead of a branch, tag such as “latest”, or range. |
| AIBOM-VER-003 | low | Base model version missing or floating | Fine-tuning results depend on the exact base model; a different base revision can behave differently. | Add the exact version or revision of the base model. |
| AIBOM-WGT-001 | medium | Weights file without a hash | Without a digest nobody can check that the deployed file is the one that was reviewed. | Add a SHA-256 (or stronger) digest of the weights file. |
| AIBOM-WGT-002 | medium | Pickle-based weights format | Formats based on Python pickle (.pkl, .pt, .pth, .bin, .ckpt, joblib) can run code when the file is loaded. | Prefer safetensors. If a pickle-based file is needed, load it only from a verified source with a checked digest, and in an isolated environment. |
| AIBOM-WGT-003 | low | Weak hash algorithm | MD5 and SHA-1 are not collision resistant, so a different file can have the same digest. | Record a SHA-256, SHA-384 or SHA-512 digest. |
| AIBOM-WGT-004 | low | Weights file without a source | Without a source it is unclear where the file was obtained and how to fetch the same file again. | Add the download location, registry entry or internal storage path. |
| AIBOM-WGT-005 | low | No weights files listed | For a model you run yourself, the weights are the core artefact of the supply chain. | List the weights files with format, digest and source. |
| AIBOM-PRV-001 | medium | Fine-tuned model without a base model | License terms, known weaknesses and behaviour of the base model carry over to the fine-tuned model. | Name the base model and its exact version. |
| AIBOM-DAT-001 | medium | Dataset without a source | Without a source the origin, consent and license of the data cannot be traced. | Add where the dataset comes from: a URL, a catalogue entry or an internal location. |
| AIBOM-DAT-002 | medium | Personal data status unknown | If it is not known whether a dataset contains personal data, data-protection duties cannot be assessed. | State whether the dataset contains personal data: yes or no. |
| AIBOM-DAT-003 | low | No datasets listed | A model you trained or fine-tuned depends on its training data; without it the document is incomplete. | List the training and fine-tuning datasets with source, license and personal-data status. |
| AIBOM-DEP-001 | medium | Dependency without a version | Without versions the framework and libraries that run the model cannot be checked for known vulnerabilities. | Add the exact version of each framework and library. |
| AIBOM-DEP-002 | low | Dependency version is floating | A range or “latest” can install a different release at the next build. | Pin the exact version that was tested. |
| AIBOM-NET-001 | medium | Address uses http:// | Unencrypted connections can be read or changed in transit, including model files and API calls. | Use https:// for this address. |
| AIBOM-SEC-001 | high | Credentials in an address | The address contains a password or a key. Anyone who receives the document can use it. | Remove the credential from the address, revoke it if it is real, and store it in a secrets manager. |
| AIBOM-SEC-002 | high | Secret in a field | The value has the format of a known credential. A bill of materials is meant to be shared, so it must not contain secrets. | Remove the value, revoke it if it is real, and refer to the secret by name only (for example “stored in the vault as OCR_API_KEY”). |
| AIBOM-SEC-003 | medium | Long random-looking value | The value is not a known credential format but looks like a key or token. | Check the value. If it is a secret, remove it and revoke it. |
| AIBOM-DOC-001 | medium | No intended purpose | Without a stated purpose, uses outside it cannot be recognized or limited. | Describe what the model is used for and by whom. |
| AIBOM-DOC-002 | medium | No limitations | Readers need to know where the model is unreliable or must not be used. | List known limitations: languages, input types, situations where results are unreliable. |
| AIBOM-DOC-003 | medium | No quality or safety evaluation | Without an evaluation there is no recorded basis for trusting the model in this use. | Add the metrics you measured and how the model was checked for safety problems. |
| AIBOM-DOC-004 | medium | No responsible person or contact | Questions, incidents and updates need an owner who can be reached. | Name the responsible person or team and add a contact (e-mail or URL). |
| AIBOM-DOC-005 | low | Model type not stated | Whether the model is your own, fine-tuned or used through an external API changes which risks apply. | Choose the model type: own, fine-tuned or external API. |
| AIBOM-DOC-006 | low | No vendor | For a fine-tuned or external model, the vendor is part of the supply chain. | Name the vendor or provider of the model. |
| AIBOM-FMT-001 | medium | No machine-learning model component | The document contains no component of type machine-learning-model, so model-level gaps cannot be checked. | Add the model as a component of type machine-learning-model. |
| AIBOM-FMT-002 | low | Structure problems | Some fields do not follow the CycloneDX structure that this tool checks. They were read where possible. | Correct the fields listed under “Structure”. |
