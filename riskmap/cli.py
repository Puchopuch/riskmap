"""Command line interface: python -m riskmap scan <target> / python -m riskmap report <file.xml>."""

import argparse
import subprocess
from collections import Counter

import yaml
from defusedxml import DefusedXmlException
from defusedxml import ElementTree as ET

from riskmap import __version__
from riskmap.checks import run_checks
from riskmap.parser import Host, parse_file, parse_nmap_xml
from riskmap.report import write_reports
from riskmap.rules import DEFAULT_RULES, SEVERITY_ORDER, Finding, evaluate, load_rules
from riskmap.scanner import run_nmap, save_xml, validate_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="riskmap", description="Turn an Nmap scan into a prioritized risk report.")
    parser.add_argument("--version", action="version", version=f"riskmap {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a target with Nmap, then analyze the results")
    scan.add_argument("target", help="IPv4 address or network, e.g. 192.168.1.10 or 192.168.1.0/24")
    scan.add_argument("--no-checks", action="store_true", help="skip the active checks (login attempts)")

    report = commands.add_parser("report", help="analyze an existing Nmap XML file (no network traffic)")
    report.add_argument("xml_file", help="Nmap XML report (made with nmap -oX)")
    report.add_argument("--checks", action="store_true", help="also run the active checks against the hosts in the file")

    for command in (scan, report):
        command.add_argument("--rules", default=DEFAULT_RULES, help="rules file in YAML (default: the built-in rules)")
        command.add_argument("--output-dir", default="reports", help="folder for the reports (default: reports)")
        command.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                             help="exit with code 2 if a finding is at least this severe (useful in CI pipelines)")
    return parser


def print_summary(hosts: list[Host], findings: list[Finding]) -> None:
    counts = Counter(finding.rule.severity for finding in findings)
    open_ports = sum(len(host.services) for host in hosts)
    summary = ", ".join(f"{counts[level]} {level}" for level in SEVERITY_ORDER)
    print(f"\n[+] {len(hosts)} host(s), {open_ports} open ports, {len(findings)} findings: {summary}")
    for finding in findings:
        if finding.rule.severity == "critical":
            print(f"    [CRITICAL] {finding.location:<25} {finding.rule.title}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
        print(f"[!] Cannot load the rules: {error}")
        return 1

    try:
        if args.command == "scan":
            validate_target(args.target)
            print(f"[*] Scanning {args.target} with Nmap... (this can take a few minutes)")
            xml = run_nmap(args.target)
            print(f"[+] Nmap XML saved to {save_xml(xml)}")
            hosts = parse_nmap_xml(xml)
            if not args.no_checks:
                run_checks(hosts)
        else:
            hosts = parse_file(args.xml_file)
            if args.checks:
                run_checks(hosts)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired, ET.ParseError, DefusedXmlException) as error:
        print(f"[!] {error}")
        return 1

    findings = evaluate(hosts, rules)
    print_summary(hosts, findings)
    html_path, json_path = write_reports(hosts, findings, args.output_dir)
    print(f"[+] HTML report: {html_path}")
    print(f"[+] JSON report: {json_path}")

    if args.fail_on and any(SEVERITY_ORDER[f.rule.severity] <= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 2
    return 0
