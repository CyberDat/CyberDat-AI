# Вычитка: новые английские тексты (feature/tools-la-unicode-fix)

Для владельца. Изменились только эти тексты на страницах; остальной текст четырёх страниц прежний.

| Где | Текст | Пометка |
|---|---|---|
| Log Anonymizer, Prompt Injection Detector, LotL Analyzer — блок «unsupported», показывается только в браузере без look-behind | “Browser not supported: this browser lacks a regular-expression feature (look-behind) that the tool needs. Use a current version of Edge, Chrome or Firefox, or Safari 16.4 or later. Nothing was sent anywhere.” | Версия Safari 16.4 — по документации о поддержке look-behind; на реальном Safari 16.3 не проверено (только симуляция). |
| MCP Security & Policy Checker — Limitations, новый пункт после пункта о description poisoning | “The description-poisoning wording rules are English only. Instructions written in German, Russian or other languages are not recognized by wording; hidden characters and markup are still detected in any language.” | “markup” — это теги вроде `<IMPORTANT>`/`<system>`, их имена английские; находятся независимо от языка окружающего текста. |
| Log Anonymizer — строка версии на странице | “Engine 1.0.3 · rules 2026-11-14.2” | Меняется автоматически из константы. |
