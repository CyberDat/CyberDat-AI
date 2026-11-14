# D14 remediation — LOTL

10/10 original cases PASS in each of Chromium, Firefox and WebKit. Original expectations unchanged.

| ID | Scenario | Original expected | Actual | Result | Limits |
|---|---|---|---|---|---|
| LO01 | Certificate utility downloads an executable | Отметить certutil download исполняемого файла как минимум medium. | level=high; all original detection/export/sanitization predicates PASS. | PASS | High совпадение требует проверки контекста; команда не запускалась. |
| LO02 | HTML application host executes a remote HTA | Отметить remote HTA через mshta как минимум medium. | level=medium; all original detection/export/sanitization predicates PASS. | PASS | Remote execution-pattern распознан; URL не запрашивался. |
| LO03 | System DLL used to dump a process | Отметить comsvcs MiniDump как минимум medium. | level=high; all original detection/export/sanitization predicates PASS. | PASS | Dump-pattern распознан; реального процесса/дампа нет. |
| LO04 | Encoded PowerShell download and execution | Отметить encoded PowerShell и показать декодированный URL. | level=high; all original detection/export/sanitization predicates PASS. | PASS | Полезная нагрузка декодирована как текст, не выполнена. |
| LO05 | Registration utility loads a remote scriptlet | Отметить remote scriptlet через regsvr32 как минимум medium. | level=high; all original detection/export/sanitization predicates PASS. | PASS | Совпадение не доказывает успешную атаку или злонамеренность оператора. |
| LO06 | Legitimate installer checksum verification | Не поднимать локальную проверку SHA256 через certutil выше low. | level=info; all original detection/export/sanitization predicates PASS. | PASS | Info не считается ложным тревожным срабатыванием по замороженному критерию. |
| LO07 | Read-only process troubleshooting | Не поднимать read-only Get-Process диагностику выше low. | level=low; all original detection/export/sanitization predicates PASS. | PASS | Low-review допустим; реальное происхождение команды не проверялось. |
| LO08 | Administrator schedules a local backup task | Не давать high локальной backup-задаче; medium-review допустим. | level=info; all original detection/export/sanitization predicates PASS. | PASS | Планировщик dual-use; существование/безопасность backup.exe не проверялись. |
| LO09 | Internal document replication | Не давать high внутреннему копированию документов по UNC. | level=low; all original detection/export/sanitization predicates PASS. | PASS | Low-сигнал есть; принадлежность NAS организации не проверялась. |
| LO10 | Documented local software installation with logging | Не поднимать локальную установку MSI с логированием выше low. | level=low; all original detection/export/sanitization predicates PASS. | PASS | В этом примере FP нет; прежние ограничения на других holdout-входах этим не отменяются. |
