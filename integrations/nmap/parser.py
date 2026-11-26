from __future__ import annotations

from xml.etree import ElementTree as ET
from typing import Any


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse Nmap XML output into normalized records. Raw XML should be preserved separately."""
    if not xml_text.strip():
        return {"hosts": [], "stats": {}, "error": "empty xml"}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"hosts": [], "stats": {}, "error": f"xml_parse_error: {e}"}

    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        addr_els = host.findall("address")
        addresses = {a.attrib.get("addrtype"): a.attrib.get("addr") for a in addr_els}
        hostnames = []
        for hn in host.findall("hostnames/hostname"):
            hostnames.append({"name": hn.attrib.get("name"), "type": hn.attrib.get("type")})

        ports = []
        for p in host.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            scripts = []
            for s in p.findall("script"):
                scripts.append({"id": s.attrib.get("id"), "output": s.attrib.get("output")})
            cpes = [c.text for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text]
            ports.append(
                {
                    "port": int(p.attrib.get("portid", "0")),
                    "protocol": p.attrib.get("protocol"),
                    "state": state_el.attrib.get("state") if state_el is not None else None,
                    "reason": state_el.attrib.get("reason") if state_el is not None else None,
                    "service": {
                        "name": svc_el.attrib.get("name") if svc_el is not None else None,
                        "product": svc_el.attrib.get("product") if svc_el is not None else None,
                        "version": svc_el.attrib.get("version") if svc_el is not None else None,
                        "extrainfo": svc_el.attrib.get("extrainfo") if svc_el is not None else None,
                        "tunnel": svc_el.attrib.get("tunnel") if svc_el is not None else None,
                        "method": svc_el.attrib.get("method") if svc_el is not None else None,
                        "conf": svc_el.attrib.get("conf") if svc_el is not None else None,
                        "cpes": cpes,
                    },
                    "scripts": scripts,
                }
            )

        os_matches = []
        for osmatch in host.findall("os/osmatch"):
            os_matches.append(
                {
                    "name": osmatch.attrib.get("name"),
                    "accuracy": float(osmatch.attrib.get("accuracy", "0")),
                    "cpes": [c.text for c in osmatch.findall("osclass/cpe") if c.text],
                }
            )

        host_scripts = []
        for s in host.findall("hostscript/script"):
            host_scripts.append({"id": s.attrib.get("id"), "output": s.attrib.get("output")})

        hosts.append(
            {
                "status": status_el.attrib.get("state") if status_el is not None else None,
                "addresses": addresses,
                "ip": addresses.get("ipv4") or addresses.get("ipv6"),
                "mac": addresses.get("mac"),
                "hostnames": hostnames,
                "ports": ports,
                "os_matches": os_matches,
                "host_scripts": host_scripts,
            }
        )

    runstats = root.find("runstats/finished")
    hosts_stat = root.find("runstats/hosts")
    stats = {
        "finished_time": runstats.attrib.get("timestr") if runstats is not None else None,
        "elapsed": runstats.attrib.get("elapsed") if runstats is not None else None,
        "hosts_up": hosts_stat.attrib.get("up") if hosts_stat is not None else None,
        "hosts_down": hosts_stat.attrib.get("down") if hosts_stat is not None else None,
        "hosts_total": hosts_stat.attrib.get("total") if hosts_stat is not None else None,
        "args": root.attrib.get("args"),
    }
    return {"hosts": hosts, "stats": stats}
