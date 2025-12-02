"""Автоматическая сборка EXE + подготовка папки `complite`.

Что делает скрипт:
1. Устанавливает зависимости из requirements.txt и выполняет `pip check`.
2. Ставит PyInstaller (если нужен).
3. Собирает однопроходный EXE из указанного entrypoint.
4. Создаёт папку `complite`, кладёт туда EXE, шаблон входного файла
   `emails_input.txt` и краткую инструкцию по запуску.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
import shutil
import textwrap

REPO_ROOT = Path(__file__).parent
DEFAULT_ENTRY = REPO_ROOT / "email_filter.py"
DEFAULT_REQUIREMENTS = REPO_ROOT / "requirements.txt"
COMPLITE_DIR = REPO_ROOT / "complite"

DEFAULT_INPUT_NAME = "emails_input.txt"
DEFAULT_VALID_NAME = "valid_emails.txt"
DEFAULT_INVALID_NAME = "invalid_emails.txt"
DEFAULT_LOG_NAME = "validation.log"


def run_command(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, check=True)


def install_requirements(requirements_path: Path) -> None:
    if not requirements_path.exists():
        raise FileNotFoundError(f"Cannot find requirements file: {requirements_path}")
    run_command([sys.executable, "-m", "pip", "install", "-r", str(requirements_path)])


def verify_requirements() -> None:
    run_command([sys.executable, "-m", "pip", "check"])


def ensure_pyinstaller() -> None:
    run_command([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build_executable(entry: Path, name: str, onefile: bool = True) -> Path:
    if not entry.exists():
        raise FileNotFoundError(f"Cannot find entry script: {entry}")

    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(entry),
        "--name",
        name,
        "--clean",
    ]

    if onefile:
        pyinstaller_cmd.append("--onefile")

    run_command(pyinstaller_cmd)
    return REPO_ROOT / "dist" / f"{name}.exe"


def clean_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for item in path.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()


def ensure_input_file(path: Path) -> None:
    if path.exists():
        return
    template = (
        "# Вставьте адреса, по одному в строке.\n"
        "# Пустые строки и строки с # в начале игнорируются.\n"
        "example1@gmail.com\nexample2@mail.ru\n"
    )
    path.write_text(template, encoding="utf-8")


def stage_complite_folder(exe_path: Path) -> Path:
    clean_directory(COMPLITE_DIR)
    target_exe = COMPLITE_DIR / exe_path.name
    shutil.copy2(exe_path, target_exe)

    input_path = COMPLITE_DIR / DEFAULT_INPUT_NAME
    ensure_input_file(input_path)

    for sample in (REPO_ROOT / "all-list.txt", REPO_ROOT / "all-list.csv"):
        if sample.exists():
            shutil.copy2(sample, COMPLITE_DIR / sample.name)

    readme_text = textwrap.dedent(
        f"""
        Сборка завершена.

        1) Откройте {DEFAULT_INPUT_NAME} и вставьте адреса (по одному в строке).
        2) Запустите {target_exe.name} двойным кликом или через консоль.
           Можно просто запустить без параметров — файлы создаются рядом с EXE.
        3) После проверки появятся файлы:
           - {DEFAULT_LOG_NAME} — подробный лог ([INFO]/[ERROR]) с причинами.
           - {DEFAULT_VALID_NAME} — только валидные адреса (по одному в строке).
           - {DEFAULT_INVALID_NAME} — невалидные адреса с причинами.
        4) По завершении программа попросит нажать Enter, чтобы закрыть окно.
        """
    ).strip()
    (COMPLITE_DIR / "README.txt").write_text(readme_text, encoding="utf-8")

    print(f"Собранный комплект: {COMPLITE_DIR}")
    return target_exe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a standalone EXE for email_filter.py")
    parser.add_argument(
        "--entry",
        type=Path,
        default=DEFAULT_ENTRY,
        help="Entry script to package (default: email_filter.py)",
    )
    parser.add_argument(
        "--name",
        default="email_filter",
        help="Name of the generated executable (default: email_filter)",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        default=DEFAULT_REQUIREMENTS,
        help="Path to requirements.txt for installing dependencies",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip installing requirements and PyInstaller",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.skip_install:
        install_requirements(args.requirements)
        verify_requirements()
        ensure_pyinstaller()

    output_path = build_executable(entry=args.entry, name=args.name)
    print(f"Executable created at: {output_path}")

    staged_exe = stage_complite_folder(output_path)
    print(f"Комплект готов в: {staged_exe.parent}")


if __name__ == "__main__":
    main()
