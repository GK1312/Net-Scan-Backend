from __future__ import annotations

import ipaddress

from src.exceptions import ValidationError


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def expand_targets(
    targets: list[str], max_count: int = 100_000
) -> tuple[list[str], list[str]]:
    if not targets:
        raise ValidationError("targets must not be empty")

    seen: set[str] = set()
    valid: list[str] = []
    invalid: list[str] = []

    for raw in targets:
        target = raw.strip()
        if not target:
            invalid.append(raw)
            continue

        try:
            if "/" in target:
                addresses = ipaddress.ip_network(target, strict=False).hosts()
            else:
                addresses = [ipaddress.ip_address(target)]
        except ValueError:
            invalid.append(target)
            continue

        for address in addresses:
            ip = str(address)
            if ip not in seen:
                seen.add(ip)
                valid.append(ip)
                if len(valid) > max_count:
                    raise ValidationError(
                        f"too many IPs: expansion exceeds limit of {max_count}"
                    )

    return valid, invalid
