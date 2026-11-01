"""Group reported devices without treating missing identity as a single PC."""


def _known(value):
    value = str(value or "").strip()
    return "" if value.lower() in {"", "unknown", "none", "null", "-"} else value


def summarize_hosts(logs):
    groups = {}
    identities = {}
    for log in logs:
        device = _known(log.get("deviceId"))
        if device:
            identities.setdefault(device, set()).add((_known(log.get("pcName")), _known(log.get("ip"))))
    for log in logs:  # newest first
        device = _known(log.get("deviceId"))
        pc, ip = _known(log.get("pcName")), _known(log.get("ip"))
        mode = "device" if device else "legacy" if pc and ip else "unidentified"
        # MachineGuid-derived IDs may be duplicated by cloned Windows images.
        # Keep distinct reported name/IP combinations separate even with the same ID.
        key = (mode, device, pc, ip)
        group = groups.setdefault(key, {
            "pcName": pc or "PC 이름 미수집", "ip": ip or "IP 미수집",
            "deviceId": device, "identityMode": mode, "count": 0,
            "lastTime": log["time"], "user": log["user"], "ips": [],
            "identityConflict": bool(device and len(identities[device]) > 1),
        })
        group["count"] += 1
        if ip and ip not in group["ips"]:
            group["ips"].append(ip)
    return list(groups.values())
