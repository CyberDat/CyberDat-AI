# Research Agent 0.8.3 — финальная приёмка

Снимок: **2026-11-13 15:13:44 UTC**. Среда: staging.cyberdat.eu. Итог **PARTIAL**.

| Компонент | Статус | Подтверждение / ограничение |
|---|---|---|
| Research Agent overall | PARTIAL | Исправления установлены; последние естественные повторы ещё не наступили |
| NVD | PARTIAL | Исходное окно завершено, 81 успешный batch; новая dense-правка не подтверждена штатным API-запуском |
| Crossref | PARTIAL | discovery_date устранена, 24 успешных batch; последующая capacity-правка ожидает штатного retry |
| Sophos | BLOCKED | На VPS HTTP/2 curl92, HTTP1.1 curl28; нет успешного получения/сохранения |
| CISA KEV | PASS | 1779 активных записей, последний scheduled HTTP304, каталог сохранён |
| Security Advisories | PASS | 118 записей, CISA/CERT-EU/MSRC без текущих ошибок |
| Scheduler | PASS | Все6 timers active; автоматические циклы и scheduled timestamps подтверждены |
| Scheduled telemetry | PASS | Реальные attempt/success/received/new-item/error/backoff; без исторического заполнения |
| Dashboard freshness | PASS | SQL/KPI/severity/91 feed dates совпадают; publication/receipt/sync разделены |
| Content Agent regression | PASS | 25 Content +24 Evidence TEMP-проверок, brief/2; все6 живых таблиц равны backup |
| Production unchanged | YES | Полное сравнение файлов и protected fingerprints; нет production SQL writes |

## Изменения и причины

**NVD.** Старый алгоритм сбрасывал offset ledger при изменении totalResults; равные totals тоже не доказывают неизменность состава API. Внедрено сохранение полного покрытия фиксированными временными диапазонами: каждый диапазон сертифицируется только одним полным валидированным ответом, границы перекрываются, CVE upsert идемпотентен. Старые cursor/rows/checkpoint сохранены; checkpoint меняется атомарно после полного покрытия окна. Обычные страницы200, запросы по31сек, максимум2/запуск, timeout12сек, body4MiB. После реального nvd_dense_slice 13ноября добавлен single-response запрос до2000 только для неделимого секундного диапазона; сверхлимитный ответ блокируется до SQL. Полная история NVD не импортировалась.

Локальный NVD cap5000 оставлял лишь781 свободную запись при4219 перед deploy и окне примерно3920 неизвестной степени пересечения. Предел NVD повышен до10000 при прежнем общем12000. Память fixture10000 строк:16MiB offline /75.3MiB внутри WordPress, feed20; cgroup256MiB и CPU25% прежние. Текущие10655 строк оставляют1345 до общего предела: это ограниченный staging index, бессрочное хранение не обещается и автоматическое удаление не добавлялось.

**Crossref.** Реальная DOI10.64701/jdpa/345/9096 имела published2026-12-31 и deposited2026-11-10. Generic future-date validation ошибочно останавливала страницу. Валидная дата сохраняется как future metadata без recency bonus; неполные/невалидные даты не выдумываются, исходная metadata сохраняется приватно. Cursor считает все raw API results и коммитится вместе с данными. После24 естественных успешных batch выявлен отдельный предел500: поднят только Crossref bound до10000 raw результатов/2MiB state, по25/запуск; будущие окна6h с1h overlap. Старый opaque cursor500, bounds, checkpoint и retry сохранены байт-в-байт. Новые архивы metadata разделены по странице; прежние сохранены. Новые лимиты не проверены реальным повтором до истечения backoff.

**Sophos.** TCP/public DNS/TLS проходят; штатный клиент и естественная попытка13ноября получили curl92/http2_stream, HTTP отсутствует. Отдельный HTTP1.1 probe11ноября — curl28 после12002ms, также без HTTP. Это подтверждает недоступность endpoint из данного runtime в заданном бюджете, но не доказывает намеренную блокировку провайдером. UA/TLS/SSRF/redirect/proxy ограничения не ослаблялись; обходов/спекулятивного fallback нет. Источник не объявлен восстановленным.

**Telemetry/UI/CLI.** --scheduled передаётся до Service для фактических запросов; inserted/updated/unchanged различаются, rollback не оставляет ложный last_new_item. После recovery сохраняется bounded last_failure, stale HTTP200 не выдаётся за transport response. Dispatcher возвращает failure exit при ошибке collector. Dashboard сохраняет сортировку публикаций и6 графиков, добавляет First received, Source/NVD sync, scope latest12/latest6, scheduled/retry/checkpoint-age. CSS/JS/SEO/navigation/Pulse2.1 не менялись. Root-owned пустой локальный wp-cli.yml останавливает поиск project config внутри прежнего open_basedir; sandbox не расширялся.

## Измерения и естественные циклы

| Метрика | До / после |
|---|---|
| NVD в исходном backup11ноября17:00:09 | 4139 |
| NVD перед deploy11ноября17:26 | 4219 |
| NVD13ноября15:13:44 | 7567 |
| KEV / advisories сейчас | 1779 /118 |
| Crossref | 169 →488 |
| Вся Research Queue | 6705 →10655 |
| NVD completed checkpoint | 2026-11-10 14:19:06 →2026-11-11 19:35:17 UTC |
| Crossref checkpoint | 2026-11-10 15:21:46 UTC; новое окно cursor500 сохранён |
| Последний валидированный NVD API success | 2026-11-12 19:30:13 UTC; это не Complete окна |
| Последний целиком успешный NVD batch по log | 2026-11-12 19:10:39 UTC |
| Последний Crossref success | 2026-11-13 02:25:12 UTC |
| Posts / Content | 61 / прежний TEST MOCK job1/version1 |

За11–13ноября после deploy в живом журнале: NVD81 sync_complete,6 transport и8 nvd_dense_slice; Crossref24 sync_complete и8 academic_window_capacity. Первый NVD batch17:45:44 UTC11ноября; Crossref18:25:06 UTC11ноября. Последнее completed NVD окно16:35:17→19:35:17 UTC11ноября содержит243 уникальных CVE,3 завершённых сегмента; completed_at12ноября15:25:45 UTC. В текущем окне17:35:17→20:35:17 UTC11ноября подтверждено212 уникальных CVE,6 сегментов,8 pending; covered_until20:10:00. Старое исходное окно до05:35:17 UTC11ноября поэтому действительно завершено.

Read-only NVD проверки13ноября14:56:08 и15:01:07 получили timeout28 и HTTP503 соответственно; source health/cursor не переписывались. Последняя установка13ноября15:07:03 UTC сохраняет исходные health/checkpoints/backoff.

## Проверки

- PASS: 30 Research,15 Discovery,25 Content,24 Evidence проверок на TEMPORARY таблицах. Реальные4 Content inputs — только read-only/copies into TEMP, генерации и обработки живого job нет.
- PASS:14 offline suites; changing totals/membership, interrupted/resumed sync, transaction rollback, rate/Retry-After, boundary dedup, dense250 single response и safe block2001, future/incomplete Crossref dates, resume cursor500→525, source security, Dashboard/filter/escaping, brief/2 и Python mock-worker contracts.
- PASS: все4139 исходных NVD IDs присутствуют; missing certified IDs0; duplicate source IDs0. Это не утверждение о полноте всей NVD или о защите от произвольного backdated indexing вне overlap.
- PASS:16 SQL-схем неизменны; свежий SQL восстановлен в16 TEMPORARY таблиц, items/state JSON валиден. Все6 Content таблиц совпали с первоначальным backup по всем колонкам;8 auth/role/URL/indexing/theme options также совпали.
- PASS: Dashboard/Home/filter HTTP200, Pulse2.1,6 charts; anonymous401, noindex. Authenticated Research/Content HTTP20013ноября15:13:32; тестовая сессия завершена, пароли/права не менялись.
- PASS: с11ноября17:26:39 UTC новых PHP fatal/warning/SQL indicators0 в обоих staging logs; точный CLI cwd/open_basedir тест без warning. Публичный дизайн/SEO/Analytics JS и Content code hashes неизменны; production files/configs совпадают.
- VPS: load≈0.22/0.19/0.18; MemAvailable≈2.16GiB из3.83GiB; DB≈55.8MiB. Нагрузочных тестов, новых служб или изменений частот нет.

## UNVERIFIED / ограничения

- NVD after latest fix: next_due2026-11-13 19:09:18 UTC; фактический запрос зависит от следующего допустимого штатного job. Crossref next_due2026-11-14 01:05:18 UTC; Sophos2026-11-14 08:25:05 UTC. Эти времена не сбрасывались. Реальный успешный retry последних исправлений ещё не наблюдался; текущий Sync Error намеренно не очищен вручную.
- Реальный browser/responsive/JS console недоступен; скриншоты не созданы. MFA/OTP не подтверждён: обычный существующий login сработал без OTP challenge; MFA не обходилась/не перенастраивалась.
- Нет API snapshot token: доказано покрытие фактически полученных диапазонов и сохранность IDs, не глобальная историческая полнота. Сверх2000 CVE в неделимом диапазоне/4MiB и общий capacity12000 остаются видимыми ограничениями.

## Backup, rollback, Git

Основной полный backup: `/var/backups/cyberdat-staging/research-0.8.3-20261111T170009Z`.
Свежий backup: `/var/backups/cyberdat-staging/research-0.8.3-continuation-20261113T145510Z`.
Оба проверены; live SQL restore не выполнялся. Read-only rollback-preflight PASS:

```sh
sudo /usr/bin/python3 -I /home/cyberdat/cyberdat-deploy/research-0.8.3-prepared/rollback-continuation.py
```

Явный `--apply` возвращает только Research code до13ноября под ingestion lock, сохраняет новые SQL/CVE/checkpoints/cursors/backoff, Content/theme/production не меняет. Старые dense/capacity ограничения вернутся. Live rollback не запускался. Полный rollback к0.8.2 требует отдельной проверки совместимости time-proof; старый SQL нельзя восстанавливать поверх новых записей. Подробности в README.

Ветка `feat/cyberdat-research-agent-0.8.3`, база Content `d0df9ca3698336ea0ee770c00821f04adeaf61af`, первый implementation commit `c3f9a5e7172f83006f3b078705a9d89e709619f8`; финальный SHA указан в ответе/истории ветки. Main не менялся. [Доказательства JSON](acceptance-2026-11-13.json).

После отчёта работа остановлена; Content/LLM/GPU/Ollama/Social/публикация не запускались.
