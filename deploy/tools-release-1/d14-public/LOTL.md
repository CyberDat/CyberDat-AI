# D14 — LotL Analyzer

**10 PASS / 0 FAIL** из 10 новых замороженных примеров.

Точные входы и машиночитаемые ожидания: приватный CASES.json (хеш в PROTOCOL.json). Для каждой строки ссылка ведёт к минимизированной сводке ожидаемого/фактического результата и хешу приватного подробного артефакта. Ожидания после запуска не менялись. Все входы синтетические. Полные входы, сырые результаты и проверочный код сохранены приватно; здесь публикуются только безопасные сводки после оценки, не изменяющие исходные результаты.

| Пример | Ожидаемый результат | Фактический результат | Статус | Ограничения и возможный риск |
|---|---|---|---|---|
| [LO01](cases/LO01.json) — Certificate utility downloads an executable | Отметить certutil download исполняемого файла как минимум medium. | level=high; commands=1; categories=Download | PASS | High совпадение требует проверки контекста; команда не запускалась. |
| [LO02](cases/LO02.json) — HTML application host executes a remote HTA | Отметить remote HTA через mshta как минимум medium. | level=medium; commands=1; categories=Execute, Download | PASS | Remote execution-pattern распознан; URL не запрашивался. |
| [LO03](cases/LO03.json) — System DLL used to dump a process | Отметить comsvcs MiniDump как минимум medium. | level=high; commands=1; categories=Dump | PASS | Dump-pattern распознан; реального процесса/дампа нет. |
| [LO04](cases/LO04.json) — Encoded PowerShell download and execution | Отметить encoded PowerShell и показать декодированный URL. | level=high; commands=1; categories=—; encoded URL показан | PASS | Полезная нагрузка декодирована как текст, не выполнена. |
| [LO05](cases/LO05.json) — Registration utility loads a remote scriptlet | Отметить remote scriptlet через regsvr32 как минимум medium. | level=high; commands=1; categories=AWL Bypass, Execute | PASS | Совпадение не доказывает успешную атаку или злонамеренность оператора. |
| [LO06](cases/LO06.json) — Legitimate installer checksum verification | Не поднимать локальную проверку SHA256 через certutil выше low. | level=info; commands=1; categories=— | PASS | Info не считается ложным тревожным срабатыванием по замороженному критерию. |
| [LO07](cases/LO07.json) — Read-only process troubleshooting | Не поднимать read-only Get-Process диагностику выше low. | level=low; commands=1; categories=— | PASS | Low-review допустим; реальное происхождение команды не проверялось. |
| [LO08](cases/LO08.json) — Administrator schedules a local backup task | Не давать high локальной backup-задаче; medium-review допустим. | level=info; commands=1; categories=— | PASS | Планировщик dual-use; существование/безопасность backup.exe не проверялись. |
| [LO09](cases/LO09.json) — Internal document replication | Не давать high внутреннему копированию документов по UNC. | level=low; commands=1; categories=— | PASS | Low-сигнал есть; принадлежность NAS организации не проверялась. |
| [LO10](cases/LO10.json) — Documented local software installation with logging | Не поднимать локальную установку MSI с логированием выше low. | level=low; commands=1; categories=Execute | PASS | В этом примере FP нет; прежние ограничения на других holdout-входах этим не отменяются. |
