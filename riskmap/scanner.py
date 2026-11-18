"""Run Nmap against a target and return the XML report."""

import ipaddress
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Non-intrusive NSE scripts: they check a configuration, they do not exploit anything.
DEFAULT_SCRIPTS = ("ftp-anon", "mysql-empty-password", "smb-protocols")


def validate_target(target: str) -> None:
    """Accept an IPv4 address (192.168.1.10) or network (192.168.1.0/24), reject anything else."""
    try:
        ipaddress.IPv4Network(target, strict=False)
    except ValueError:
        raise ValueError(f"Invalid target: {target!r} (expected an IPv4 address or network)") from None


def run_nmap(target: str, scripts: tuple[str, ...] = DEFAULT_SCRIPTS, timeout: int = 1800) -> str:
    """Scan the target and return the XML produced by Nmap."""
    validate_target(target)

    if shutil.which("nmap") is None:
        raise RuntimeError("Nmap is not installed or not in the PATH.")

    command = [
        "nmap",
        "-sV",                          # detect service versions
        "--script", ",".join(scripts),  # run the NSE scripts
        "-oX", "-",                     # write the XML report to stdout
        target,
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed (code {result.returncode}): {result.stderr.strip()}")
    return result.stdout


def save_xml(xml: str, folder: str = "scans") -> Path:
    """Save the XML to scans/scan_YYYYMMDD_HHMMSS.xml and return the path."""
    Path(folder).mkdir(exist_ok=True)
    path = Path(folder) / f"scan_{datetime.now():%Y%m%d_%H%M%S}.xml"
    path.write_text(xml, encoding="utf-8")
    return path


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m riskmap.scanner <IPv4 address or network>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        validate_target(target)
        print(f"[*] Scanning {target}... (this can take a few minutes)")
        xml = run_nmap(target)
    except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"[!] {error}")
        sys.exit(1)

    path = save_xml(xml)
    print(f"[+] XML report saved to {path}")


if __name__ == "__main__":
    main()
   
