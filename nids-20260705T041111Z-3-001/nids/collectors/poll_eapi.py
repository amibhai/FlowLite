import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set

import requests
import urllib3

from utils.csv_writer import append_rows

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_FIELDNAMES = [
    "timestamp", "switch_ip",
    "arp_table_size", "arp_changed_count", "arp_new_count",
    "mac_table_size", "mac_new_count", "mac_lost_count",
    "route_count", "route_delta",
    "total_iface_errors", "total_iface_discards", "iface_down_count",
]

_CMDS = [
    "show arp",
    "show mac address-table",
    "show ip route summary",
    "show interfaces",
]


def _poll(host: str, user: str, password: str, timeout: int, verify: bool):
    url = f"https://{host}/command-api"
    payload = {
        "jsonrpc": "2.0",
        "method": "runCmds",
        "params": {
            "version": 1,
            "cmds": _CMDS,
            "format": "json",
        },
        "id": "nids-poller",
    }
    resp = requests.post(
        url,
        json=payload,
        auth=(user, password),
        verify=verify,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["result"]


def _parse_result(result, prev_arp, prev_mac, prev_routes, prev_errors):
    # ARP
    neighbors = result[0].get("ipV4Neighbors", [])
    curr_arp: Dict[str, str] = {n["ip"]: n["hwAddress"] for n in neighbors}
    arp_changed = sum(1 for ip, mac in curr_arp.items()
                      if ip in prev_arp and prev_arp[ip] != mac)
    arp_new = sum(1 for ip in curr_arp if ip not in prev_arp)

    # MAC
    entries = (
        result[1]
        .get("unicastTable", {})
        .get("tableEntries", [])
    )
    curr_mac: Set[str] = {e["macAddress"] for e in entries}
    mac_new  = len(curr_mac - prev_mac)
    mac_lost = len(prev_mac - curr_mac)

    # Routes
    curr_routes = (
        result[2]
        .get("vrfs", {})
        .get("default", {})
        .get("totalRoutes", 0)
    )
    route_delta = curr_routes - prev_routes

    # Interfaces
    ifaces = result[3].get("interfaces", {})
    total_errors = 0
    total_discards = 0
    iface_down = 0
    for name, data in ifaces.items():
        status = data.get("interfaceStatus", "")
        if status not in ("connected", "up"):
            iface_down += 1
        counters = data.get("interfaceCounters", {})
        total_discards += counters.get("inDiscards", 0)
        total_discards += counters.get("outDiscards", 0)
        err_detail = counters.get("inputErrorsDetail", None)
        if err_detail is not None:
            total_errors += sum(
                v for v in err_detail.values()
                if isinstance(v, (int, float))
            )
        else:
            total_errors += counters.get("totalInputErrors", 0)

    errors_delta = total_errors - prev_errors

    return (
        curr_arp, curr_mac, curr_routes, total_errors,
        {
            "arp_table_size":     len(curr_arp),
            "arp_changed_count":  arp_changed,
            "arp_new_count":      arp_new,
            "mac_table_size":     len(curr_mac),
            "mac_new_count":      mac_new,
            "mac_lost_count":     mac_lost,
            "route_count":        curr_routes,
            "route_delta":        route_delta,
            "total_iface_errors": errors_delta,
            "total_iface_discards": total_discards,
            "iface_down_count":   iface_down,
        },
    )


def _zero_row(host: str) -> Dict:
    return {
        "timestamp":           datetime.utcnow().isoformat(),
        "switch_ip":           host,
        "arp_table_size":      0,
        "arp_changed_count":   0,
        "arp_new_count":       0,
        "mac_table_size":      0,
        "mac_new_count":       0,
        "mac_lost_count":      0,
        "route_count":         0,
        "route_delta":         0,
        "total_iface_errors":  0,
        "total_iface_discards": 0,
        "iface_down_count":    0,
    }


def run(cfg, stop_event, log, status_dict: Optional[Dict] = None):
    host     = cfg.switch.host
    user     = cfg.switch.user
    password = getattr(cfg.switch, "pass")
    verify   = cfg.switch.verify_ssl
    interval = cfg.eapi.poll_interval_s
    timeout  = cfg.eapi.timeout_s
    out_path = Path(cfg.paths.eapi_out)

    prev_arp:    Dict[str, str] = {}
    prev_mac:    Set[str]       = set()
    prev_routes: int            = 0
    prev_errors: int            = 0

    log.info("eAPI poller started — %s every %ds", host, interval)

    while not stop_event.is_set():
        t0 = time.monotonic()
        row = _zero_row(host)

        try:
            result = _poll(host, user, password, timeout, verify)
            prev_arp, prev_mac, prev_routes, prev_errors, metrics = _parse_result(
                result, prev_arp, prev_mac, prev_routes, prev_errors
            )
            row.update(metrics)
            row["timestamp"] = datetime.utcnow().isoformat()
            row["switch_ip"] = host
            log.debug(
                "eAPI poll: arp=%d routes=%d errors=%d",
                row["arp_table_size"], row["route_count"], row["total_iface_errors"],
            )
        except Exception as e:
            log.error("eAPI poll error: %s", e)

        if status_dict is not None:
            status_dict["running"]   = True
            status_dict["last_poll"] = datetime.now().strftime("%H:%M:%S")

        try:
            append_rows(out_path, [row], _FIELDNAMES)
        except Exception as e:
            log.error("eAPI CSV write error: %s", e)

        elapsed = time.monotonic() - t0
        wait = max(0.0, interval - elapsed)
        stop_event.wait(timeout=wait)

    log.info("eAPI poller stopped")
