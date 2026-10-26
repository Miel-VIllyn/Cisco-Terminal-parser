#!/usr/bin/env python3
"""
Cisco terminal output -> structured Markdown network documentation.

Standard-library only. Drop terminal captures into ./data. The program watches
for new/changed files and writes device pages and overview.md into ./parsed.
Run once with --once to process the current files and exit.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
OUT_DIR = ROOT / "parsed"
PLACEHOLDER = "put terminal output in files here"
LOG = logging.getLogger("cisco-md")

PROMPT_RE = re.compile(
    r"^\s*(?P<host>[A-Za-z0-9_.:/-]+)"
    r"(?P<mode>\([^)]+\))?(?P<ending>[#>])\s*(?P<cmd>.*?)\s*$"
)
SYSLOG_RE = re.compile(
    r"^(?:\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\s*:?\s*)?"
    r"%(?:[A-Z0-9_-]+-\d-[A-Z0-9_-]+|[A-Z0-9_-]+):"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})\b")
MASK_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})\b")
SECRET_RE = re.compile(
    r"(?i)^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d+\s+)?).+$"
)
SENSITIVE_RE = re.compile(
    r"(?i)^(\s*(?:username\s+\S+\s+.*?(?:secret|password)|"
    r"snmp-server community|radius-server key|tacacs-server key|"
    r"key-string|crypto isakmp key)\s+).+$"
)

def clean_cell(value: Any) -> str:
    """Keep Markdown tables safe and compact."""
    if value is None or str(value).strip() == "":
        return "Not supplied"
    return str(value).strip().replace("|", r"\|").replace("\n", " ")

def table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No matching data found in the supplied terminal output._\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(clean_cell(v) for v in row) + " |")
    return "\n".join(out) + "\n"

def valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False

def network_from_address(address: str, mask_or_prefix: str) -> str:
    try:
        if "." in mask_or_prefix:
            return str(ipaddress.IPv4Network(f"{address}/{mask_or_prefix}", strict=False))
        return str(ipaddress.IPv4Network(f"{address}/{int(mask_or_prefix)}", strict=False))
    except (ValueError, ipaddress.AddressValueError):
        return "Not supplied"

def mask_to_prefix(mask: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen)
    except ValueError:
        return "Not supplied"

def redact(line: str) -> str:
    """Avoid publishing common plaintext/hashed secrets in generated docs."""
    if SECRET_RE.match(line) or SENSITIVE_RE.match(line):
        prefix = line.split()[0] if line.split() else "credential"
        return f"{prefix} <redacted>"
    return line

def split_sessions(text: str) -> list[dict[str, Any]]:
    """
    Split terminal captures into command/output sessions using prompts.
    Configuration-mode prompts are excluded as command boundaries.
    """
    sessions: list[dict[str, Any]] = []
    host = None
    command = None
    output: list[str] = []
    current_host = None

    def flush():
        nonlocal command, output, current_host
        if command:
            sessions.append({"host": current_host or host or "unknown-device",
                             "command": command.strip(), "output": output[:]})
        command, output = None, []

    for raw in text.splitlines():
        line = raw.rstrip()
        match = PROMPT_RE.match(line)
        if match:
            mode = (match.group("mode") or "").lower()
            # Prompt is a command boundary only in exec mode, not (config)/(if)/(router).
            if mode:
                continue
            prompt_host = match.group("host")
            cmd = match.group("cmd").strip()
            host = prompt_host
            if cmd:
                flush()
                current_host = prompt_host
                command = cmd
                output = []
            else:
                flush()
                current_host = prompt_host
            continue
        if not command:
            # Some pasted running-configs have no leading command prompt.
            # Collect them under a synthetic running-config session.
            if line.strip() and not line.lstrip().startswith("%"):
                command = "unlabelled terminal output"
                current_host = host or "unknown-device"
                output = []
            else:
                continue
        if SYSLOG_RE.match(line.strip()):
            continue
        if re.match(r"^\s*\S+\(config[^)]*\)#", line, re.I):
            continue
        output.append(redact(line))
    flush()
    # If the input had no prompt at all, the fallback above is still retained.
    return sessions

def parse_running_config(output: list[str], device: dict[str, Any]) -> None:
    interfaces: dict[str, dict[str, Any]] = device["interfaces"]
    vlans = device["vlans"]
    acls = device["acls"]
    dhcp = device["dhcp"]
    routes = device["routes"]
    etherchannels = device["etherchannels"]
    ospf = device["ospf"]
    hsrp = device["hsrp"]
    current_if = None
    current_acl = None
    current_dhcp_pool = None
    current_router = None

    for raw in output:
        line = raw.strip()
        if not line or line == "!":
            continue
        m = re.match(r"hostname\s+(\S+)", line, re.I)
        if m:
            device["hostname"] = m.group(1)
            continue
        m = re.match(r"interface\s+(\S+)", line, re.I)
        if m:
            current_if = m.group(1)
            interfaces.setdefault(current_if, {"interface": current_if})
            current_acl = current_dhcp_pool = None
            current_router = None
            continue
        m = re.match(r"ip access-list\s+(standard|extended)\s+(\S+)", line, re.I)
        if m:
            current_acl = m.group(2)
            acls.setdefault(current_acl, {"name": current_acl, "type": m.group(1), "entries": []})
            current_if = current_dhcp_pool = None
            current_router = None
            continue
        m = re.match(r"access-list\s+(\S+)\s+(.+)", line, re.I)
        if m:
            name = m.group(1)
            acls.setdefault(name, {"name": name, "type": "numbered", "entries": []})["entries"].append(m.group(2))
            continue
        m = re.match(r"ip dhcp pool\s+(.+)", line, re.I)
        if m:
            current_dhcp_pool = m.group(1)
            dhcp.setdefault(current_dhcp_pool, {"pool": current_dhcp_pool})
            current_if = current_acl = None
            current_router = None
            continue
        m = re.match(r"router\s+(ospf|eigrp|bgp)\s+(\S+)", line, re.I)
        if m:
            current_router = (m.group(1).lower(), m.group(2))
            if current_router[0] == "ospf":
                ospf.setdefault(current_router[1], {"process": current_router[1], "networks": [], "router_id": None, "passive": []})
            current_if = current_acl = current_dhcp_pool = None
            continue

        if current_if:
            obj = interfaces[current_if]
            if line.startswith("description "): obj["description"] = line[len("description "):]
            elif line.startswith("ip address "):
                parts = line.split()
                if len(parts) >= 4 and parts[2].lower() != "dhcp":
                    obj["ip"] = parts[2]
                    obj["mask"] = parts[3]
                    obj["subnet"] = network_from_address(parts[2], parts[3])
                elif len(parts) >= 3: obj["ip"] = "DHCP"
            elif line.startswith("encapsulation dot1Q "): obj["vlan"] = line.split()[2]
            elif line.startswith("ip helper-address "): obj.setdefault("dhcp_helpers", []).append(line.split()[-1])
            elif line.startswith("ip access-group "):
                parts = line.split()
                if len(parts) >= 4: obj[f"acl_{parts[3].lower()}"] = parts[2]
            elif line == "shutdown": obj["admin_status"] = "Shutdown"
            elif line == "no shutdown": obj["admin_status"] = "Enabled"
            elif line.startswith("channel-group "):
                parts = line.split()
                obj["channel_group"] = parts[1]
                if "mode" in parts:
                    obj["channel_mode"] = parts[parts.index("mode") + 1]
                etherchannels.setdefault(parts[1], {"group": parts[1], "members": []})["members"].append(current_if)
            elif line.startswith("standby "):
                parts = line.split()
                if len(parts) >= 3:
                    group = parts[1]
                    entry = hsrp.setdefault((current_if, group), {"interface": current_if, "group": group})
                    if parts[2] == "ip" and len(parts) > 3: entry["virtual_ip"] = parts[3]
                    elif parts[2] == "priority" and len(parts) > 3: entry["priority"] = parts[3]
                    elif parts[2] == "preempt": entry["preempt"] = "Yes"
            elif line.startswith("switchport mode "): obj["switchport_mode"] = line.split()[-1]
            elif line.startswith("switchport access vlan "): obj["access_vlan"] = line.split()[-1]
            elif line.startswith("switchport trunk allowed vlan "): obj["trunk_vlans"] = line[len("switchport trunk allowed vlan "):]
        elif current_acl:
            if line.startswith(("permit ", "deny ")):
                acls[current_acl]["entries"].append(line)
            elif line.startswith("remark "):
                acls[current_acl].setdefault("remarks", []).append(line[7:])
        elif current_dhcp_pool:
            obj = dhcp[current_dhcp_pool]
            if line.startswith("network "):
                p = line.split()
                if len(p) >= 3: obj["network"] = network_from_address(p[1], p[2])
            elif line.startswith("default-router "): obj["default_router"] = line[len("default-router "):]
            elif line.startswith("dns-server "): obj["dns_servers"] = line[len("dns-server "):]
            elif line.startswith("domain-name "): obj["domain_name"] = line[len("domain-name "):]
            elif line.startswith("lease "): obj["lease"] = line[len("lease "):]
        elif current_router and current_router[0] == "ospf":
            obj = ospf[current_router[1]]
            if line.startswith("router-id "): obj["router_id"] = line.split()[-1]
            elif line.startswith("network "): obj["networks"].append(line[len("network "):])
            elif line.startswith("passive-interface "): obj["passive"].append(line.split()[-1])

        m = re.match(r"ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?", line, re.I)
        if m:
            dest, mask, next_hop, extra = m.groups()
            routes.append({"destination": network_from_address(dest, mask), "next_hop": next_hop,
                           "distance_or_tag": extra or "Not supplied", "source": "running-config"})
        m = re.match(r"vlan\s+(\d+)", line, re.I)
        if m:
            vid = m.group(1)
            vlans.setdefault(vid, {"vlan_id": vid})
            current_if = current_acl = current_dhcp_pool = None
            current_router = None
            continue
        if re.match(r"name\s+", line, re.I) and current_if is None and current_acl is None:
            # VLAN names are usually under a vlan stanza; handled in parser below.
            pass

    # Router-on-a-stick subinterfaces imply VLAN IDs even without `show vlan`.
    for intf, obj in interfaces.items():
        vid = obj.get("vlan")
        if vid:
            vlans.setdefault(str(vid), {"vlan_id": str(vid)})
            if obj.get("description") and not vlans[str(vid)].get("name"):
                vlans[str(vid)]["name"] = obj["description"]


def parse_session(session: dict[str, Any], devices: dict[str, dict[str, Any]]) -> None:
    prompt_host = session["host"]
    command = session["command"].lower().strip()
    output = session["output"]
    if not output and command.lower() not in ("", "exit"):
        return
    dev = devices.setdefault(prompt_host, new_device(prompt_host))
    dev["commands"].add(session["command"])
    if "show running-config" in command or "show run" == command or command == "unlabelled terminal output":
        parse_running_config(output, dev)
    if "show vlan" in command:
        for line in output:
            m = re.match(r"^\s*(\d+)\s+(\S+)\s+(active|act/lshut|suspend|shutdown)", line, re.I)
            if m:
                vid, name, status = m.groups()
                dev["vlans"].setdefault(vid, {}).update({"vlan_id": vid, "name": name, "status": status})
    if "show ip interface brief" in command or "show ip int br" in command:
        for line in output:
            m = re.match(r"^\s*(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.+?)\s{2,}(\S+)\s*$", line)
            if m:
                intf, ip, status, protocol = m.groups()
                if intf.lower() == "interface" or ip.lower() == "ip-address":
                    continue
                obj = dev["interfaces"].setdefault(intf, {"interface": intf})
                if ip.lower() != "unassigned": obj["ip"] = ip
                obj["status"] = status.strip()
                obj["protocol"] = protocol.strip()
                if "ip" in obj and valid_ipv4(obj["ip"]) and "subnet" not in obj:
                    obj["subnet"] = "Not supplied (mask unavailable)"
    if "show ip interface" in command:
        current = None
        for line in output:
            m = re.match(r"^(\S+) is (up|down|administratively down), line protocol is (up|down)", line, re.I)
            if m:
                current = m.group(1)
                dev["interfaces"].setdefault(current, {"interface": current}).update({"status": m.group(2), "protocol": m.group(3)})
            m = re.match(r"\s*Internet address is ((?:\d{1,3}\.){3}\d{1,3})/(\d+)", line)
            if current and m:
                ip, prefix = m.groups()
                obj = dev["interfaces"][current]
                obj["ip"], obj["subnet"] = ip, network_from_address(ip, prefix)
            m = re.match(r"\s*Inbound access list is (.+)", line)
            if current and m and m.group(1).lower() != "not set":
                dev["interfaces"][current]["acl_in"] = m.group(1)
            m = re.match(r"\s*Outgoing access list is (.+)", line)
            if current and m and m.group(1).lower() != "not set":
                dev["interfaces"][current]["acl_out"] = m.group(1)
    if "show ip route" in command:
        for line in output:
            m = re.match(r"^\s*([SCDROBLI*]+)\s+((?:\d{1,3}\.){3}\d{1,3}/\d+)\s+\[([^\]]+)\]\s+via\s+((?:\d{1,3}\.){3}\d{1,3})", line)
            if m:
                code, dest, metric, hop = m.groups()
                dev["routes"].append({"destination": dest, "next_hop": hop, "distance_or_tag": metric, "source": code})
            m = re.match(r"^\s*S\*\s+0\.0\.0\.0/0\s+\[([^\]]+)\]\s+via\s+(\S+)", line)
            if m:
                dev["routes"].append({"destination": "0.0.0.0/0", "next_hop": m.group(2), "distance_or_tag": m.group(1), "source": "S*"})
    if "show access-lists" in command or "show ip access-lists" in command:
        current = None
        for line in output:
            m = re.match(r"^\s*(Standard|Extended) IP access list (\S+)", line, re.I)
            if m:
                current = m.group(2)
                dev["acls"].setdefault(current, {"name": current, "type": m.group(1).lower(), "entries": []})
            elif current and line.strip():
                dev["acls"][current]["entries"].append(line.strip())
    if "show etherchannel summary" in command:
        for line in output:
            m = re.match(r"^\s*(\d+)\s+\S+\(([^)]*)\)\s+\S+\s+\S+\s+(.+)", line)
            if m:
                group, flags, ports = m.groups()
                obj = dev["etherchannels"].setdefault(group, {"group": group, "members": []})
                obj["flags"] = flags
                obj["members"] = sorted(set(obj["members"] + re.findall(r"[A-Za-z]+Ethernet[\w/.:]+", ports)))
    if "show interfaces trunk" in command:
        for line in output:
            m = re.match(r"^\s*(\S+)\s+(\d+)\s+\S+\s+(\S+)\s+(.+)", line)
            if m and m.group(2).isdigit():
                intf, native, status, allowed = m.groups()
                obj = dev["interfaces"].setdefault(intf, {"interface": intf})
                obj.update({"switchport_mode": "trunk", "native_vlan": native, "trunk_status": status,
                            "trunk_vlans": allowed.strip()})
    if "show standby" in command or "show hsrp" in command:
        for line in output:
            m = re.search(r"(\S+)\s+(\d+)\s+.*Active\s+(\S+)\s+Standby\s+(\S+)", line, re.I)
            if m:
                intf, group, active, standby = m.groups()
                dev["hsrp"].setdefault((intf, group), {"interface": intf, "group": group}).update(
                    {"active_router": active, "standby_router": standby})
    if "show ip ospf neighbor" in command:
        for line in output:
            m = re.match(r"^\s*(\S+)\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)", line)
            if m:
                dev["ospf_neighbors"].append({"neighbor_id": m.group(1), "state": m.group(2), "address_or_interface": m.group(3)})
    if "show cdp neighbors" in command or "show lldp neighbors" in command:
        for line in output:
            # Best-effort summary parser; detailed output is handled below.
            m = re.match(r"^\s*(\S+)\s+\S+\s+\d+\s+\S+\s+\S+\s+(\S+)\s*$", line)
            if m:
                dev["neighbors"].append({"device": m.group(1), "local_interface": "Not supplied", "remote_interface": m.group(2), "source": "CDP/LLDP"})
    if "show ip dhcp pool" in command:
        for line in output:
            m = re.match(r"^\s*(\S+)\s+((?:\d{1,3}\.){3}\.\d+/\d+|\S+)\s+", line)
            if m:
                dev["dhcp"].setdefault(m.group(1), {"pool": m.group(1), "network": m.group(2)})

def new_device(host: str) -> dict[str, Any]:
    return {
        "hostname": host, "commands": set(), "interfaces": {}, "vlans": {},
        "acls": {}, "dhcp": {}, "routes": [], "etherchannels": {}, "ospf": {},
        "hsrp": {}, "ospf_neighbors": [], "neighbors": [], "sources": set(),
    }

def dedupe_records(records: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    result, seen = [], set()
    for record in records:
        sig = tuple(record.get(k) for k in keys)
        if sig not in seen:
            seen.add(sig)
            result.append(record)
    return result

def device_markdown(dev: dict[str, Any]) -> str:
    host = dev["hostname"]
    lines = [f"# {host}", "", "> Generated from Cisco terminal captures. Missing values are marked `Not supplied`.", ""]
    lines += ["## Source commands", ""]
    lines += [f"- `{c}`" for c in sorted(dev["commands"])] or ["- Not supplied"]
    lines += ["", "## Interfaces", "",
              table(["Interface", "Description", "IP address", "Subnet (CIDR)", "VLAN", "Mode", "Status", "Protocol", "ACL in", "ACL out", "Channel group"],
                    [[n, x.get("description"), x.get("ip"), x.get("subnet"), x.get("vlan") or x.get("access_vlan"),
                      x.get("switchport_mode"), x.get("status") or x.get("admin_status"), x.get("protocol"),
                      x.get("acl_in") or x.get("acl_inbound"), x.get("acl_out") or x.get("acl_outbound"), x.get("channel_group")]
                     for n, x in sorted(dev["interfaces"].items())])]
    lines += ["", "## VLANs", "",
              table(["VLAN ID", "Name", "Status"],
                    [[k, v.get("name"), v.get("status")] for k, v in sorted(dev["vlans"].items(), key=lambda p: int(p[0]) if p[0].isdigit() else 99999)])]
    lines += ["", "## Routing table and static routes", "",
              table(["Destination", "Next hop", "Metric / distance", "Source"],
                    [[r.get("destination"), r.get("next_hop"), r.get("distance_or_tag"), r.get("source")] for r in dedupe_records(dev["routes"], ("destination","next_hop","distance_or_tag","source"))])]
    lines += ["", "## ACLs", ""]
    if dev["acls"]:
        for name, acl in sorted(dev["acls"].items()):
            lines += [f"### {name}", "", f"- Type: {clean_cell(acl.get('type'))}"]
            if acl.get("remarks"): lines.append(f"- Remarks: {clean_cell('; '.join(acl['remarks']))}")
            lines += ["", table(["Sequence / rule"], [[e] for e in acl.get("entries", [])])]
    else:
        lines += ["_No ACL data found._", ""]
    lines += ["", "## DHCP pools", "",
              table(["Pool", "Network", "Default router", "DNS servers", "Domain", "Lease"],
                    [[k, v.get("network"), v.get("default_router"), v.get("dns_servers"), v.get("domain_name"), v.get("lease")] for k,v in sorted(dev["dhcp"].items())])]
    lines += ["", "## EtherChannels / LACP", "",
              table(["Group", "Member interfaces", "Flags / mode"],
                    [[k, ", ".join(v.get("members", [])), v.get("flags") or v.get("mode")] for k,v in sorted(dev["etherchannels"].items())])]
    lines += ["", "## HSRP", "",
              table(["Interface", "Group", "Virtual IP", "Priority", "Preempt", "Active router", "Standby router"],
                    [[v.get("interface"), v.get("group"), v.get("virtual_ip"), v.get("priority"), v.get("preempt"), v.get("active_router"), v.get("standby_router")] for _,v in sorted(dev["hsrp"].items())])]
    lines += ["", "## OSPF", ""]
    if dev["ospf"]:
        lines += [table(["Process", "Router ID", "Networks", "Passive interfaces"],
                        [[k, v.get("router_id"), ", ".join(v.get("networks", [])), ", ".join(v.get("passive", []))] for k,v in sorted(dev["ospf"].items())])]
    else: lines += ["_No OSPF configuration found._", ""]
    lines += ["", "### OSPF neighbors", "",
              table(["Neighbor ID", "State", "Address / interface"],
                    [[v.get("neighbor_id"), v.get("state"), v.get("address_or_interface")] for v in dedupe_records(dev["ospf_neighbors"], ("neighbor_id","state","address_or_interface"))])]
    lines += ["", "## Discovered neighbors", "",
              table(["Neighbor device", "Local interface", "Remote interface", "Discovery method"],
                    [[v.get("device"), v.get("local_interface"), v.get("remote_interface"), v.get("source")] for v in dedupe_records(dev["neighbors"], ("device","local_interface","remote_interface","source"))])]
    lines += ["", "## Notes", "",
              "- Only information present in the supplied terminal captures is documented.",
              "- An empty section means the relevant command/configuration was not recognized or was not included.",
              "- ACL entries are documented as observed; this report does not determine the full effective security policy.", ""]
    return "\n".join(lines)

def overview_markdown(devices: dict[str, dict[str, Any]]) -> str:
    lines = ["# Network overview", "", "Generated by Cisco Markdown Compiler.", "",
             "## Devices", "", "| Device | Interfaces | VLANs | Routed networks | Source commands |",
             "| --- | ---: | ---: | --- | --- |"]
    all_vlans: dict[str, list[str]] = defaultdict(list)
    network_owners: dict[str, list[str]] = defaultdict(list)
    for host, d in sorted(devices.items()):
        nets = sorted({x.get("subnet") for x in d["interfaces"].values()
                       if x.get("subnet") and x.get("subnet") != "Not supplied"})
        for vid, v in d["vlans"].items():
            all_vlans[vid].append(host)
        for n in nets: network_owners[n].append(host)
        lines.append(f"| [{host}]({host}.md) | {len(d['interfaces'])} | {len(d['vlans'])} | {', '.join(nets) or 'Not supplied'} | {len(d['commands'])} |")
    lines += ["", "## VLAN inventory", "",
              table(["VLAN ID", "Known name(s)", "Seen on device(s)"],
                    [[vid, ", ".join(sorted({devices[h]["vlans"][vid].get("name", "Not supplied") for h in hosts})),
                      ", ".join(sorted(hosts))] for vid, hosts in sorted(all_vlans.items(), key=lambda p: int(p[0]) if p[0].isdigit() else 99999)])]
    lines += ["", "## Subnet inventory", "",
              table(["Subnet (CIDR)", "Device(s) with an interface in subnet"],
                    [[net, ", ".join(sorted(hosts))] for net, hosts in sorted(network_owners.items())])]
    lines += ["", "## Inferred relationships", "",
              "Relationships below are hints from shared subnets and discovered neighbors, not a verified physical topology.", ""]
    relationships = set()
    for host, d in devices.items():
        for neighbor in d["neighbors"]:
            other = neighbor.get("device", "")
            if other and other.lower() not in {"device", "switch", "router"}:
                relationships.add(tuple(sorted((host, other))))
    for net, hosts in network_owners.items():
        if len(hosts) > 1:
            for i, a in enumerate(hosts):
                for b in hosts[i+1:]:
                    relationships.add(tuple(sorted((a, b))))
    if relationships:
        lines += ["| Device A | Device B | Evidence |", "| --- | --- | --- |"]
        for a, b in sorted(relationships):
            shared = sorted(set(
                x.get("subnet") for x in devices[a]["interfaces"].values()
                if x.get("subnet") and x.get("subnet") != "Not supplied"
            ) & set(
                x.get("subnet") for x in devices[b]["interfaces"].values()
                if x.get("subnet") and x.get("subnet") != "Not supplied"
            ))
            evidence = "Shared subnet: " + ", ".join(shared) if shared else "CDP/LLDP neighbor hint"
            lines.append(f"| [{a}]({a}.md) | [{b}]({b}.md) | {evidence} |")
    else:
        lines += ["_No reliable inter-device relationships could be inferred from the current input._", ""]
    lines += ["", "## Routing matrix (best-effort)", "",
              "This matrix shows whether a device has a known interface subnet matching another device's known interface subnet. It is **not** an ACL/firewall policy matrix.", ""]
    hosts = sorted(devices)
    if hosts:
        lines.append("| Source / destination | " + " | ".join(hosts) + " |")
        lines.append("| " + " | ".join(["---"] * (len(hosts)+1)) + " |")
        for a in hosts:
            cells = []
            anets = {x.get("subnet") for x in devices[a]["interfaces"].values() if x.get("subnet")}
            for b in hosts:
                if a == b: cells.append("Same device")
                else:
                    bnets = {x.get("subnet") for x in devices[b]["interfaces"].values() if x.get("subnet")}
                    cells.append("Shared subnet" if (anets - {"Not supplied"}) & (bnets - {"Not supplied"}) else "Unknown")
            lines.append("| " + a + " | " + " | ".join(cells) + " |")
    lines += ["", "## Limitations", "",
              "- A shared subnet does not prove that two devices can communicate.",
              "- `Unknown` means the captures do not provide enough evidence; it does not mean traffic is denied.",
              "- For a security-policy matrix, provide relevant ACLs and interface directions on all participating devices.", ""]
    return "\n".join(lines)

def ensure_folders() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    placeholder = DATA_DIR / PLACEHOLDER
    if not placeholder.exists():
        placeholder.write_text(
            "Put raw Cisco terminal output in this folder as .txt, .log, or other text files.\n",
            encoding="utf-8"
        )

def process_file(path: Path, devices: dict[str, dict[str, Any]]) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        LOG.warning("Cannot read %s: %s", path, exc)
        return
    sessions = split_sessions(text)
    for session in sessions:
        # Prefer hostname declared in running-config, but prompt host remains a device key.
        parse_session(session, devices)
    # Associate config-declared hostname with prompt device and keep canonical name.
    # Most normal captures already use the same hostname in prompt and config.
    LOG.info("Processed %s (%d command/output section(s))", path.name, len(sessions))

def compile_all() -> None:
    ensure_folders()
    devices: dict[str, dict[str, Any]] = {}
    inputs = sorted(p for p in DATA_DIR.iterdir()
                    if p.is_file() and p.name != PLACEHOLDER and not p.name.startswith("."))
    for path in inputs:
        process_file(path, devices)
    # Canonicalize hostnames discovered in config and merge duplicate device records.
    canonical: dict[str, dict[str, Any]] = {}
    for key, dev in devices.items():
        name = dev.get("hostname") or key
        if name not in canonical:
            dev["hostname"] = name
            canonical[name] = dev
        elif canonical[name] is not dev:
            target = canonical[name]
            target["commands"].update(dev["commands"])
            for field in ("interfaces", "vlans", "acls", "dhcp", "etherchannels", "ospf"):
                target[field].update(dev[field])
            for field in ("routes", "ospf_neighbors", "neighbors"):
                target[field].extend(dev[field])
            target["hsrp"].update(dev["hsrp"])
    for name, dev in sorted(canonical.items()):
        # Restrict output path to a safe filename.
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._") or "unknown-device"
        (OUT_DIR / f"{safe}.md").write_text(device_markdown(dev), encoding="utf-8")
    (OUT_DIR / "overview.md").write_text(overview_markdown(canonical), encoding="utf-8")
    LOG.info("Wrote %d device page(s) and overview.md to %s", len(canonical), OUT_DIR)

def watch(poll_seconds: float) -> None:
    ensure_folders()
    seen: dict[str, tuple[int, int]] = {}
    LOG.info("Watching %s (Ctrl+C to stop)", DATA_DIR)
    while True:
        changed = False
        for path in DATA_DIR.iterdir():
            if not path.is_file() or path.name == PLACEHOLDER or path.name.startswith("."):
                continue
            try:
                stat = path.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                continue
            if seen.get(str(path)) != signature:
                # Wait briefly for a copy operation to finish.
                time.sleep(min(0.25, poll_seconds))
                try:
                    stat2 = path.stat()
                    signature2 = (stat2.st_size, stat2.st_mtime_ns)
                except OSError:
                    continue
                if signature2 != signature:
                    continue
                seen[str(path)] = signature
                changed = True
        # Also recompile if an input file was removed.
        existing = {str(p) for p in DATA_DIR.iterdir() if p.is_file() and p.name != PLACEHOLDER and not p.name.startswith(".")}
        if set(seen) - existing:
            for gone in set(seen) - existing:
                seen.pop(gone, None)
            changed = True
        if changed:
            compile_all()
        time.sleep(poll_seconds)

def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Cisco terminal captures into Markdown network documentation.")
    parser.add_argument("--once", action="store_true", help="Process current input files once and exit.")
    parser.add_argument("--poll", type=float, default=1.0, help="Seconds between folder scans (default: 1).")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s: %(message)s")
    ensure_folders()
    try:
        if args.once:
            compile_all()
        else:
            compile_all()
            watch(max(0.2, args.poll))
    except KeyboardInterrupt:
        LOG.info("Stopped.")

if __name__ == "__main__":
    main()
