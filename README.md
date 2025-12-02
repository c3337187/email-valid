# Email list validator

Скрипт `email_filter.py` проверяет список адресов и делит его на валидные и невалидные.

## Возможности
- чтение CSV (с автоопределением разделителя) и TXT файлов;
- удаление дублей с сохранением порядка;
- проверка синтаксиса адреса;
- фильтрация по списку разрешённых доменов и временных почтовых сервисов;
- опциональная SMTP‑проверка существования ящика (выключена по умолчанию);
- вывод результатов в два CSV файла с причинами.

## Установка зависимостей
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Использование
```bash
python email_filter.py \
  --input all-list.csv \
  --valid-output valid_emails.csv \
  --invalid-output invalid_emails.csv \
  --log-level INFO \
  --smtp-check --smtp-timeout 5
```

Опции:
- `--input` — путь к исходному файлу (CSV или TXT).
- `--valid-output` / `--invalid-output` — пути для результатов (по умолчанию `valid_emails.csv` и `invalid_emails.csv`).
- `--allowed-domains` / `--temp-domains` — файлы с доменами (по одному в строке) для переопределения встроенных списков.
- `--smtp-check` — включает SMTP‑проверку существования ящика. Без этой опции проверяется только синтаксис и домен.
- `--smtp-timeout` — таймаут SMTP‑проверки в секундах.
- `--log-level` — уровень логирования (`DEBUG`, `INFO`, `WARNING`, `ERROR`).

## Пример результатов
Валидные и невалидные адреса сохраняются в отдельных CSV с колонками `email`, `status`, `reason`.

## Сборка EXE
Скрипт `build_exe.py` автоматизирует установку зависимостей и сборку однопроходного EXE (PyInstaller). Работает на Windows; команду следует выполнять из корня репозитория.

1. Подготовьте окружение (желательно внутри виртуального окружения):
   ```bash
   python -m venv .venv
   .venv\\Scripts\\activate  # для PowerShell: .venv\\Scripts\\Activate.ps1
   ```
2. Запустите сборку (установит зависимости и PyInstaller автоматически):
   ```bash
   python build_exe.py --entry email_filter.py --name email_filter
   ```
3. Результат: файл `dist/email_filter.exe`. В каталоге `build/` появятся временные артефакты PyInstaller; их можно удалить после сборки.

Опции скрипта:
- `--entry` — путь к исходному `.py` файлу, который нужно упаковать (по умолчанию `email_filter.py`).
- `--name` — имя итогового EXE (по умолчанию `email_filter`).
- `--requirements` — путь к `requirements.txt` (по умолчанию корневой файл проекта).
- `--skip-install` — пропускает установку зависимостей и PyInstaller, если они уже стоят в текущем окружении.

Перед запуском EXE положите входной файл (например, `all-list.csv` или `all-list.txt`) рядом с EXE или укажите полный путь в параметре `--input` при запуске.
