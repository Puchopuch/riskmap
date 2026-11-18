"""Parse an Nmap XML report into Python objects."""

import sys
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as ET


@dataclass
class Service:
    """An open port and what runs on it."""

    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        """Product and version in one string, e.g. 'vsftpd 2.3.4'."""
        return " ".join(part for part in (self.product, self.version) if part)


@dataclass
class Host:
    """A machine that answered the scan."""

    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    services: list[Service] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # host-level scripts, e.g. smb-protocols


def _scripts(element) -> dict[str, str]:
    """Collect the NSE script results found under an element: {script id: output}."""
    return {script.get("id", ""): script.get("output", "").strip() for script in element.findall("script")}


def parse_nmap_xml(xml_text: str) -> list[Host]:
    """Turn Nmap XML into a list of hosts (only hosts that are up, only open ports)."""
    root = ET.fromstring(xml_text)
    hosts = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        host = Host(ip="")
        for address in host_el.findall("address"):
            if address.get("addrtype") == "ipv4":
                host.ip = address.get("addr", "")
            elif address.get("addrtype") == "mac":
                host.mac = address.get("addr", "")
                host.vendor = address.get("vendor", "")

        hostname = host_el.find("hostnames/hostname")
        if hostname is not None:
            host.hostname = hostname.get("name", "")

        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_el = port_el.find("service")
            info = service_el.attrib if service_el is not None else {}
            host.services.append(Service(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                name=info.get("name", ""),
                product=info.get("product", ""),
                version=info.get("version", ""),
                extrainfo=info.get("extrainfo", ""),
                scripts=_scripts(port_el),
            ))

        hostscript = host_el.find("hostscript")
        if hostscript is not None:
            host.scripts = _scripts(hostscript)

        hosts.append(host)
    return hosts


def parse_file(path: str | Path) -> list[Host]:
    """Read an Nmap XML file and parse it."""
    return parse_nmap_xml(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m riskmap.parser <nmap_report.xml>")
        sys.exit(1)

    try:
        hosts = parse_file(sys.argv[1])
    except (OSError, ET.ParseError, DefusedXmlException) as error:
        print(f"[!] Cannot read this report: {error}")
        sys.exit(1)

    for host in hosts:
        print(f"\n[{host.ip}] {host.hostname} - {len(host.services)} open ports")
        for service in host.services:
            print(f"  {service.port:>5}/{service.protocol}  {service.name:<12} {service.banner}")
            for script_id, output in service.scripts.items():
                first_line = output.split("\n")[0]
                print(f"           {script_id}: {first_line}")
        for script_id, output in host.scripts.items():
            print(f"  host script {script_id}: {' '.join(output.split())}")


if __name__ == "__main__":
    main()
