# D14 remediation — LOG

10/10 original cases PASS in each of Chromium, Firefox and WebKit. Original expectations unchanged.

| ID | Scenario | Original expected | Actual | Result | Limits |
|---|---|---|---|---|---|
| LA01 | Reverse-proxy request and session cookie | Скрыть IP, username, email и session cookie; сохранить маршрут, время и статус. | Required redactions 4/4; context and format criteria PASS. CR=0, LF=2. | PASS | Поддержанные поля обработаны; это не доказательство покрытия всех HTTP-заголовков. |
| LA02 | Structured auth event with IPv6 and workstation | Скрыть учётную запись, email, IPv6 и hostname; сохранить тип события и код. | Required redactions 4/4; context and format criteria PASS. CR=0, LF=0. | PASS | Произвольные дополнительные JSON-поля этим примером не проверены. |
| LA03 | Database URL in an application exception | Скрыть пользователя/пароль/хост PostgreSQL URL; сохранить SQLSTATE и request ID. | Required redactions 3/3; context and format criteria PASS. CR=0, LF=1. | PASS | Проверен один вид DSN; другие схемы и кодировки не гарантированы. |
| LA04 | Known service token and JWT in debug headers | Скрыть синтетический provider token и JWT; сохранить версию компонента. | Required redactions 2/2; context and format criteria PASS. CR=0, LF=3. | PASS | Проверены эти форматы и расположения, не все возможные секреты. |
| LA05 | Unicode full name and telephone in a support note | Убрать ФИО и телефон из support-лога. | Required redactions 2/2; context and format criteria PASS. CR=0, LF=1. | PASS | Explicit person/contact fields only; arbitrary prose and unknown fields may be missed. |
| LA06 | CEF extension carries an indirectly labeled credential | Скрыть src, suser, shost и credential, обозначенный через cs1Label. | Required redactions 4/4; context and format criteria PASS. CR=0, LF=1. | PASS | CEF cs1..cs6 labels are event-local; unknown labels, unsupported or oversized formats may be missed. |
| LA07 | Multiline synthetic private-key block with CRLF | Скрыть оба body-фрагмента тестового ключа, оставить маркеры и CRLF. | Required redactions 2/2; context and format criteria PASS. CR=6, LF=6. | PASS | Untouched supported text files retain line endings; editing a textarea switches to browser-normalized text. |
| LA08 | Benign build identifiers must remain unchanged | Оставить benign-лог с версиями, checksum, UUID и числами неизменным. | Required redactions 0/0; context and format criteria PASS. CR=0, LF=1. | PASS | Ложного редактирования в этом примере нет; вывод не обобщается на все идентификаторы. |
| LA09 | Windows event XML with an account and workstation | Скрыть Windows account/workstation и username в пути, сохранить record ID. | Required redactions 2/2; context and format criteria PASS. CR=0, LF=0. | PASS | Проверена конкретная XML-разметка; SID и другие форматы PII здесь не проверялись. |
| LA10 | CSV export with identities and an unrelated request ID | Скрыть username/email/hostname в двух CSV-строках, оставить header/request IDs. | Required redactions 6/6; context and format criteria PASS. CR=0, LF=3. | PASS | Проверен согласованный CSV header; произвольные табличные схемы не охвачены. |
