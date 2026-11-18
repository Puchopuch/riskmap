"""The authorized scope: the networks you have written permission to test."""

import ipaddress
from pathlib import Path


def load_scope(path: str | Path) -> list[ipaddress.IPv4Network]:
    """Read one IPv4 address or network per line. Empty lines and # comments are ignored."""
    networks = []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        entry = line.split("#")[0].strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.IPv4Network(entry, strict=False))
        except ValueError:
            raise ValueError(f"Scope file, line {number}: {entry!r} is not an IPv4 address or network") from None
    if not networks:
        raise ValueError("The scope file is empty: list at least one authorized address or network")
    return networks


def in_scope(target: str, scope: list[ipaddress.IPv4Network]) -> bool:
    """True if the address, or the whole network, is inside one of the authorized networks."""
    try:
        network = ipaddress.IPv4Network(target, strict=False)
    except ValueError:
        return False
    return any(network.subnet_of(allowed) for allowed in scope)
