"""Write the findings as an HTML report (for people) and a JSON file (for other tools)."""

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from riskmap import __version__
from riskmap.checks import run_checks
from riskmap.parser import Host, parse_file
from riskmap.rules import SEVERITY_ORDER, Finding, evaluate, load_rules

TEMPLATES = Path(__file__).parent / "templates"


def to_html(hosts: list[Host], findings: list[Finding]) -> str:
    """Fill the HTML template. autoescape=True turns < > & " into harmless text (no XSS)."""
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    template = env.get_template("report.html.j2")
    return template.render(
        version=__version__,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        hosts=hosts,
        open_ports=sum(len(host.services) for host in hosts),
        findings=findings,
        severities=list(SEVERITY_ORDER),
        counts=Counter(finding.rule.severity for finding in findings),
    )


def to_json(hosts: list[Host], findings: list[Finding]) -> str:
    """Same content as plain data, easy to load in a SIEM or another script."""
    data = {
        "tool": f"riskmap {__version__}",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": {level: sum(f.rule.severity == level for f in findings) for level in SEVERITY_ORDER},
        "findings": [
            {
                "id": f.rule.id,
                "severity": f.rule.severity,
                "title": f.rule.title,
                "host": f.host.ip,
                "port": f.service.port if f.service else None,
                "protocol": f.service.protocol if f.service else None,
                "evidence": f.evidence,
                "description": f.rule.description,
                "recommendation": f.rule.recommendation,
            }
            for f in findings
        ],
        "hosts": [
            {
                "ip": host.ip,
                "hostname": host.hostname,
                "services": [
                    {"port": s.port, "protocol": s.protocol, "name": s.name, "banner": s.banner}
                    for s in host.services
                ],
            }
            for host in hosts
        ],
    }
    return json.dumps(data, indent=2)


def write_reports(hosts: list[Host], findings: list[Finding], folder: str = "reports") -> tuple[Path, Path]:
    """Save reports/report_YYYYMMDD_HHMMSS.html and .json, return both paths."""
    Path(folder).mkdir(exist_ok=True)
    base = Path(folder) / f"report_{datetime.now():%Y%m%d_%H%M%S}"
    html_path, json_path = base.with_suffix(".html"), base.with_suffix(".json")
    html_path.write_text(to_html(hosts, findings), encoding="utf-8")
    json_path.write_text(to_json(hosts, findings), encoding="utf-8")
    return html_path, json_path


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m riskmap.report <nmap_report.xml>")
        sys.exit(1)

    hosts = parse_file(sys.argv[1])
    run_checks(hosts)
    findings = evaluate(hosts, load_rules())
    html_path, json_path = write_reports(hosts, findings)
    print(f"[+] {len(findings)} findings")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] JSON report: {json_path}")


if __name__ == "__main__":
    main()
