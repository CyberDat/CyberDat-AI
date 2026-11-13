# D14 — MCP Security Checker

**10 PASS / 0 FAIL** из 10 новых замороженных примеров.

Точные входы и машиночитаемые ожидания: приватный CASES.json (хеш в PROTOCOL.json). Для каждой строки ссылка ведёт к минимизированной сводке ожидаемого/фактического результата и хешу приватного подробного артефакта. Ожидания после запуска не менялись. Все входы синтетические. Полные входы, сырые результаты и проверочный код сохранены приватно; здесь публикуются только безопасные сводки после оценки, не изменяющие исходные результаты.

| Пример | Ожидаемый результат | Фактический результат | Статус | Ограничения и возможный риск |
|---|---|---|---|---|
| [MC01](cases/MC01.json) — Bounded local read-only inventory server | Не давать medium/high ограниченной локальной конфигурации. | level=none; findings=0 | PASS | None означает отсутствие найденных сигналов, а не аудит или доказательство безопасности server code. |
| [MC02](cases/MC02.json) — Unpinned runner with root access and automatic execution | Дать high unpinned runner + root access + automatic execution. | level=high; findings=5 | PASS | Опасные признаки отмечены; npx/server не запускались. |
| [MC03](cases/MC03.json) — Credential-bearing remote server over cleartext HTTP | Отметить credential-bearing HTTP и скрыть token в UI/JSON report. | level=high; findings=5 | PASS | Token скрыт; реальное соединение не выполнялось. |
| [MC04](cases/MC04.json) — Privileged container with writable host filesystem | Дать high privileged Docker с writable host-root mount. | level=high; findings=4 | PASS | Контейнер не запускался, проверен только текст конфигурации. |
| [MC05](cases/MC05.json) — Known provider credentials in env and option value | Найти известные provider credentials и не раскрыть их в UI/экспорте. | level=high; findings=3 | PASS | Оба синтетических значения скрыты; универсальная гарантия всех секретов не проверяется. |
| [MC06](cases/MC06.json) — Opaque custom tenant proof with an unfamiliar field name | Скрыть opaque env/option value и показать best-effort предупреждение. | level=info; findings=1 | PASS | Значение подавлено структурно; secret-finding не обязателен и не появился. Другие места/форматы могут быть пропущены. |
| [MC07](cases/MC07.json) — Percent-encoded nonstandard password in URL userinfo | Отметить URL userinfo и скрыть пароль в исходной и percent-encoded форме. | level=medium; findings=2 | PASS | Medium, пароль не найден в UI/report. Проверена одна кодировка и один URI. |
| [MC08](cases/MC08.json) — Truncated JSON containing a synthetic known token | Отвергнуть незавершённый JSON без token в сообщении об ошибке. | JSON отклонён; token в error/console отсутствует | PASS | Ожидаемая ошибка валидации — PASS; это не JS runtime error. |
| [MC09](cases/MC09.json) — Policy violation and distinct report/policy exports | Показать policy violations, скрыть opaque value в report, выгрузить policy дословно с предупреждением. | policy violations=2; report redaction / verbatim policy / warning — PASS | PASS | Две violations; report и policy экспортируются различно. Policy без редактирования по контракту; тестовая policy сама не содержала секретов. |
| [MC10](cases/MC10.json) — Poisoned tool description and inert HTML payload | Дать минимум medium poisoned description; HTML должен остаться текстом. | level=high; findings=3 | PASS | High, input HTML не исполнялся, внешнее изображение не загружалось; все poisoning-атаки этим не охвачены. |
