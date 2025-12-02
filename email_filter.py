"""Command-line tool to filter and validate email addresses.

Features
- Load emails from CSV or plain text files.
- Remove duplicates while preserving order.
- Filter by allowed domains and temporary email domains.
- Validate syntax with a strict-ish regular expression.
- Optional SMTP existence checks with timeouts.
- Write valid and invalid addresses to separate CSV files with reasons.
"""
from __future__ import annotations

import argparse
import csv
import logging
import re
import smtplib
import socket
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
                if email:
                    emails.append(email)
    else:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                email = line.strip()
                if email:
                    emails.append(email)
    logging.info("Loaded %s addresses from %s", len(emails), path)
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
                    return True, "accepted"
                if code == 550:
                    return False, "mailbox unavailable"
        except (socket.timeout, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as exc:
            logging.debug("SMTP connection to %s failed: %s", host, exc)
            continue
        except smtplib.SMTPResponseException as exc:
            logging.debug("SMTP response error from %s: %s", host, exc)
            if exc.smtp_code == 550:
                return False, "mailbox unavailable"
            continue
        except OSError as exc:
            logging.debug("Network error while contacting %s: %s", host, exc)
            continue
    return False, "smtp check inconclusive"


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
        return ValidationResult(normalized, "invalid", "invalid syntax")

    _, domain = normalized.split("@", 1)

    if domain in temp_domains:
        return ValidationResult(normalized, "invalid", "temporary domain")

    if allowed_domains and domain not in allowed_domains:
        return ValidationResult(normalized, "invalid", "domain not allowed")

    if smtp_check:
        exists, reason = smtp_exists(normalized, timeout=smtp_timeout)
        if not exists:
            return ValidationResult(normalized, "invalid", reason)

    return ValidationResult(normalized, "valid", "accepted")


def write_results(path: Path, results: Iterable[ValidationResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["email", "status", "reason"])
        for result in results:
            writer.writerow([result.email, result.status, result.reason])
    logging.info("Wrote %s", path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter and validate email addresses")
    parser.add_argument("--input", required=True, type=Path, help="Input CSV or TXT file")
    parser.add_argument(
        "--valid-output",
        type=Path,
        default=Path("valid_emails.csv"),
        help="Path to write valid emails CSV",
    )
    parser.add_argument(
        "--invalid-output",
        type=Path,
        default=Path("invalid_emails.csv"),
        help="Path to write invalid emails CSV",
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="[%(levelname)s] %(message)s")

    allowed_domains = DEFAULT_ALLOWED_DOMAINS.copy()
    if args.allowed_domains:
        allowed_domains = load_domains_from_file(args.allowed_domains)
        logging.info("Loaded %s allowed domains from %s", len(allowed_domains), args.allowed_domains)

    temp_domains = TEMP_EMAIL_DOMAINS.copy()
    if args.temp_domains:
        temp_domains = load_domains_from_file(args.temp_domains)
        logging.info("Loaded %s temporary domains from %s", len(temp_domains), args.temp_domains)

    raw_emails = load_emails(args.input)
    unique_emails = deduplicate(raw_emails)
    logging.info("Deduplicated to %s unique addresses", len(unique_emails))

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
        else:
            invalid_results.append(result)
        logging.info("Checked %s - %s (%s)", result.email, result.status, result.reason)

    write_results(args.valid_output, valid_results)
    write_results(args.invalid_output, invalid_results)


if __name__ == "__main__":
    main()
