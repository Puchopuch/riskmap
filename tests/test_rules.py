from collections import Counter
from pathlib import Path

import pytest
import yaml

from riskmap.parser import Host, Service, parse_file
from riskmap.rules import evaluate, load_rules, version_tuple

DATA = Path(__file__).parent / "data"


def test_metasploitable_findings():
    findings = evaluate(parse_file(DATA / "metasploitable.xml"), load_rules())
    counts = Counter(finding.rule.severity for finding in findings)
    assert counts == {"critical": 6, "high": 4, "medium": 8}
    assert findings[0].rule.severity == "critical"  # most severe first


@pytest.mark.parametrize("text, expected", [
    ("4.7p1", (4, 7)),
    ("5.0.51a-3ubuntu5", (5, 0, 51)),
    ("11.00.2100.00; RTM", (11, 0, 2100, 0)),
    ("unknown", None),
])
def test_version_tuple(text, expected):
    assert version_tuple(text) == expected


def test_mariadb_is_not_reported_as_old_mysql():
    host = Host(ip="10.0.0.5", services=[Service(3306, "tcp", "mysql", "MySQL", "5.5.5-10.11.6-MariaDB")])
    rule_ids = {finding.rule.id for finding in evaluate([host], load_rules())}
    assert "MYSQL_OUTDATED" not in rule_ids
    assert "DATABASE_EXPOSED" in rule_ids


def test_rule_with_a_typo_is_refused(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- id: TYPO\n"
        "  title: Typo\n"
        "  severity: high\n"
        "  match:\n"
        "    service: [telnet]\n"
        "  description: d\n"
        "  recommendation: r\n"
    )
    with pytest.raises(ValueError):
        load_rules(rules_file)


def test_malicious_yaml_is_not_executed(tmp_path):
    rules_file = tmp_path / "evil.yaml"
    rules_file.write_text('- !!python/object/apply:os.system ["echo PWNED"]\n')
    with pytest.raises(yaml.YAMLError):
        load_rules(rules_file)
