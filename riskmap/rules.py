"""Load the risk rules (YAML) and apply them to the hosts found by the parser."""

import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from riskmap.parser import Host, Service, parse_file

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_RULES = Path(__file__).parent / "rules.yaml"
SERVICE_CONDITIONS = {"services", "ports", "banner_contains", "banner_not_contains",
                      "version_below", "script", "output_contains"}
HOST_CONDITIONS = {"host_script", "output_contains"}


@dataclass
class Rule:
    """One risk rule from the YAML file."""

    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    match: dict


@dataclass
class Finding:
    """A rule that matched a host, or one of its open ports."""

    rule: Rule
    host: Host
    service: Service | None  # None when the rule is about the whole host
    evidence: str

    @property
    def location(self) -> str:
        if self.service is None:
            return self.host.ip
        return f"{self.host.ip}:{self.service.port}/{self.service.protocol}"


def load_rules(path: str | Path = DEFAULT_RULES) -> list[Rule]:
    """Read the rules file. safe_load only builds plain data: lists, dicts, strings, numbers."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(**item) for item in data]
    for rule in rules:
        if rule.severity not in SEVERITY_ORDER:
            raise ValueError(f"Rule {rule.id}: unknown severity {rule.severity!r}")
        # A typo like "service:" instead of "services:" would silently match every port: refuse it.
        allowed = HOST_CONDITIONS if "host_script" in rule.match else SERVICE_CONDITIONS
        unknown = set(rule.match) - allowed
        if not rule.match or unknown:
            raise ValueError(f"Rule {rule.id}: empty or unknown conditions {sorted(unknown)}")
    return rules


def version_tuple(text: str) -> tuple[int, ...] | None:
    """Keep the leading numbers of a version: '4.7p1' gives (4, 7), '5.0.51a-3ubuntu5' gives (5, 0, 51)."""
    found = re.match(r"\d+(?:\.\d+)*", text.strip())
    if found is None:
        return None
    return tuple(int(part) for part in found.group().split("."))


def _match_service(match: dict, service: Service) -> str | None:
    """Return the evidence if the open port meets every condition of the rule, otherwise None."""
    if "services" in match and service.name not in match["services"]:
        return None
    if "ports" in match and service.port not in match["ports"]:
        return None
    if "banner_contains" in match and match["banner_contains"].lower() not in service.banner.lower():
        return None
    if "banner_not_contains" in match and match["banner_not_contains"].lower() in service.banner.lower():
        return None
    if "version_below" in match:
        current = version_tuple(service.version)
        if current is None or current >= version_tuple(str(match["version_below"])):
            return None

    evidence = f"{service.name} {service.banner}".strip()
    if "script" in match:
        output = service.scripts.get(match["script"])
        if output is None or match.get("output_contains", "").lower() not in output.lower():
            return None
        first_line = output.strip().split("\n")[0]
        evidence = f"{match['script']}: {first_line}"
    return evidence


def _match_host(match: dict, host: Host) -> str | None:
    """Same idea for the rules that look at the whole host (host scripts like smb-protocols)."""
    output = host.scripts.get(match["host_script"])
    if output is None or match.get("output_contains", "").lower() not in output.lower():
        return None
    return f"{match['host_script']}: {' '.join(output.split())}"


def evaluate(hosts: list[Host], rules: list[Rule]) -> list[Finding]:
    """Apply every rule to every host and every open port. The most severe findings come first."""
    findings = []
    for host in hosts:
        for rule in rules:
            if "host_script" in rule.match:
                evidence = _match_host(rule.match, host)
                if evidence:
                    findings.append(Finding(rule, host, None, evidence))
                continue
            for service in host.services:
                evidence = _match_service(rule.match, service)
                if evidence:
                    findings.append(Finding(rule, host, service, evidence))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.rule.severity], f.host.ip, f.service.port if f.service else 0))
    return findings


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m riskmap.rules <nmap_report.xml>")
        sys.exit(1)

    findings = evaluate(parse_file(sys.argv[1]), load_rules())
    for finding in findings:
        print(f"[{finding.rule.severity.upper():<8}] {finding.location:<25} {finding.rule.title}  ({finding.evidence})")

    counts = Counter(finding.rule.severity for finding in findings)
    summary = ", ".join(f"{counts[level]} {level}" for level in SEVERITY_ORDER)
    print(f"\n{len(findings)} findings: {summary}")


if __name__ == "__main__":
    main()
