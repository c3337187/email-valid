"""Командный фильтр email-адресов.

Особенности:
- запуск без параметров — берёт `LIST-EMAIL.txt` рядом с exe/скриптом;
- поддержка CSV/TXT, игнор `#` и удаление дублей;
- лог с `[INFO]/[ERROR]` в файл и консоль;
- отдельные файлы валидных и невалидных адресов с причинами;
- опциональная SMTP‑проверка наличия ящика.
"""
from __future__ import annotations

import argparse
import csv
import logging
import re
import smtplib
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Set, Tuple

import dns.resolver

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$"
)

DEFAULT_ALLOWED_DOMAINS: Set[str] = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "mail.ru",
    "bk.ru",
    "list.ru",
    "inbox.ru",
    "yandex.ru",
    "ya.ru",
    "yandex.com",
    "rambler.ru",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "gmx.com",
    "gmx.de",
    "qq.com",
    "163.com",
    "hey.com",
    "fastmail.com",
    "mail.com",
    "pm.me",
}

TEMP_EMAIL_DOMAINS: Set[str] = {
    "tempmail.world",
    "vsmailpro.com",
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "yopmail.com",
    "trashmail.com",
    "tempmailo.com",
    "maildrop.cc",
    "getnada.com",
}

# Файлы по умолчанию создаются рядом с исполняемым файлом (или текущим .py при разработке)
DEFAULT_INPUT_NAME = "LIST-EMAIL.txt"
DEFAULT_VALID_NAME = "VALID-EMAIL.txt"
DEFAULT_INVALID_NAME = "INVALID-EMAIL.txt"
DEFAULT_LOG_NAME = "RESULT-LOG.txt"


@dataclass
class ValidationResult:
    email: str
    status: str
    reason: str


def load_domains_from_file(path: Path) -> Set[str]:
    domains: Set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                domains.add(domain)
    return domains


def detect_csv_dialect(path: Path) -> csv.Dialect:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(2048)
        try:
            return csv.Sniffer().sniff(sample)
        except csv.Error:
            return csv.get_dialect("excel")


def flatten_csv_cells(reader: Iterable[Sequence[str]]) -> Iterable[str]:
    for row in reader:
        for cell in row:
            if cell:
                yield cell


def load_emails(path: Path) -> List[str]:
    emails: List[str] = []
    if path.suffix.lower() == ".csv":
        dialect = detect_csv_dialect(path)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, dialect=dialect)
            for raw_email in flatten_csv_cells(reader):
                email = raw_email.strip()
                if email and not email.startswith("#"):
                    emails.append(email)
    else:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                email = line.strip()
                if email and not email.startswith("#"):
                    emails.append(email)
    logging.info("Загружено %s адресов из %s", len(emails), path)
    return emails


def normalize_email(email: str) -> str:
    return email.strip().lower()


def check_syntax(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))


def lookup_mx_records(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        logging.debug("No MX records found for %s; falling back to domain", domain)
        return [domain]
    hosts: List[str] = []
    for answer in answers:
        host = str(answer.exchange).rstrip(".")
        hosts.append(host)
    return hosts or [domain]


def smtp_exists(email: str, timeout: float, helo_host: str = "localhost") -> Tuple[bool, str]:
    local_part, domain = email.split("@", 1)
    for host in lookup_mx_records(domain):
        try:
            with smtplib.SMTP(host, 25, timeout=timeout) as server:
                server.helo(name=helo_host)
                server.mail(f"check@{helo_host}")
                code, _ = server.rcpt(email)
                if 200 <= code < 300:
                    return True, "принят SMTP сервером"
                if code == 550:
                    return False, "почтовый ящик недоступен"
        except (socket.timeout, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as exc:
            logging.debug("SMTP connection to %s failed: %s", host, exc)
            continue
        except smtplib.SMTPResponseException as exc:
            logging.debug("SMTP response error from %s: %s", host, exc)
            if exc.smtp_code == 550:
                return False, "почтовый ящик недоступен"
            continue
        except OSError as exc:
            logging.debug("Network error while contacting %s: %s", host, exc)
            continue
    return False, "SMTP проверка не дала результата"


def deduplicate(emails: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    unique: List[str] = []
    for email in emails:
        normalized = normalize_email(email)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(email)
    return unique


def validate_email(
    email: str,
    allowed_domains: Set[str],
    temp_domains: Set[str],
    smtp_check: bool,
    smtp_timeout: float,
) -> ValidationResult:
    normalized = normalize_email(email)
    if not check_syntax(normalized):
        return ValidationResult(normalized, "invalid", "невалидный формат")

    _, domain = normalized.split("@", 1)

    if domain in temp_domains:
        return ValidationResult(normalized, "invalid", "удалён (временный сервис)")

    if allowed_domains and domain not in allowed_domains:
        return ValidationResult(normalized, "invalid", "домен не разрешён")

    if smtp_check:
        exists, reason = smtp_exists(normalized, timeout=smtp_timeout)
        if not exists:
            return ValidationResult(normalized, "invalid", reason)

    return ValidationResult(normalized, "valid", "пройдено")


def write_results(path: Path, results: Iterable[ValidationResult]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(f"{result.email}\n")
    logging.info("Сохранено: %s", path)


def determine_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def ensure_input_file(path: Path) -> None:
    if path.exists():
        return
    path.write_text("", encoding="utf-8")
    logging.info("Создан пустой входной файл: %s", path)


def parse_args(base_dir: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter and validate email addresses")
    parser.add_argument(
        "--input",
        type=Path,
        default=base_dir / DEFAULT_INPUT_NAME,
        help="Input CSV or TXT file (default: LIST-EMAIL.txt рядом с exe)",
    )
    parser.add_argument(
        "--valid-output",
        type=Path,
        default=base_dir / DEFAULT_VALID_NAME,
        help="File to write valid emails (one per line)",
    )
    parser.add_argument(
        "--invalid-output",
        type=Path,
        default=base_dir / DEFAULT_INVALID_NAME,
        help="File to write invalid emails with reasons",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=base_dir / DEFAULT_LOG_NAME,
        help="Log file path (default: validation.log рядом с exe)",
    )
    parser.add_argument(
        "--allowed-domains",
        type=Path,
        help="Optional file with allowed domains (one per line)",
    )
    parser.add_argument(
        "--temp-domains",
        type=Path,
        help="Optional file with temporary domains (one per line)",
    )
    parser.add_argument(
        "--smtp-check",
        action="store_true",
        help="Perform SMTP mailbox existence checks (slower)",
    )
    parser.add_argument(
        "--smtp-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for SMTP connections",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Do not ask to press Enter at the end (useful for scripts)",
    )
    return parser.parse_args()


def main() -> None:
    base_dir = determine_base_dir()
    args = parse_args(base_dir)

    args.log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="[%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(args.log_file, encoding="utf-8"),
        ],
    )

    ensure_input_file(args.input)

    allowed_domains = DEFAULT_ALLOWED_DOMAINS.copy()
    if args.allowed_domains:
        allowed_domains = load_domains_from_file(args.allowed_domains)
        logging.info("Загружено %s разрешённых доменов из %s", len(allowed_domains), args.allowed_domains)

    temp_domains = TEMP_EMAIL_DOMAINS.copy()
    if args.temp_domains:
        temp_domains = load_domains_from_file(args.temp_domains)
        logging.info("Загружено %s временных доменов из %s", len(temp_domains), args.temp_domains)

    raw_emails = load_emails(args.input)
    unique_emails = deduplicate(raw_emails)
    logging.info("Удалено дубликатов, осталось %s адресов", len(unique_emails))

    valid_results: List[ValidationResult] = []
    invalid_results: List[ValidationResult] = []

    for email in unique_emails:
        result = validate_email(
            email=email,
            allowed_domains=allowed_domains,
            temp_domains=temp_domains,
            smtp_check=args.smtp_check,
            smtp_timeout=args.smtp_timeout,
        )
        if result.status == "valid":
            valid_results.append(result)
            logging.info("Проверка адреса: %s - валидный", result.email)
        else:
            invalid_results.append(result)
            logging.error("Проверка адреса: %s - не валидный (%s)", result.email, result.reason)

    write_results(args.valid_output, valid_results)
    write_results(args.invalid_output, invalid_results)

    print("\nГотово. Результаты сохранены:")
    print(f"  - Валидные: {args.valid_output}")
    print(f"  - Невалидные: {args.invalid_output}")
    print(f"  - Лог: {args.log_file}")

    if not args.no_pause:
        input("\nНажмите Enter, чтобы закрыть окно...")


if __name__ == "__main__":
    main()
