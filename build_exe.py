"""Helper script to build a Windows-ready EXE for the email validator.

Steps performed:
1. Install project dependencies from requirements.txt.
2. Ensure PyInstaller is present.
3. Run PyInstaller to produce a single-file executable.

Usage example (from repository root):
    python build_exe.py --entry email_filter.py --name email_filter

The resulting executable will be written to dist/<name>.exe.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent
DEFAULT_ENTRY = REPO_ROOT / "email_filter.py"
DEFAULT_REQUIREMENTS = REPO_ROOT / "requirements.txt"


def run_command(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, check=True)


def install_requirements(requirements_path: Path) -> None:
    if not requirements_path.exists():
        raise FileNotFoundError(f"Cannot find requirements file: {requirements_path}")
    run_command([sys.executable, "-m", "pip", "install", "-r", str(requirements_path)])


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
        ensure_pyinstaller()

    output_path = build_executable(entry=args.entry, name=args.name)
    print(f"Executable created at: {output_path}")


if __name__ == "__main__":
    main()
