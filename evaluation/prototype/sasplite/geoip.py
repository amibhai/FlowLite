import ipaddress
import logging
from typing import Dict, Optional

log = logging.getLogger(__name__)

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


class GeoIPLookup:
    def __init__(self, asn_db_path: str, city_db_path: str) -> None:
        self._asn_reader = None
        self._city_reader = None
        self._asn_cache: Dict[str, str] = {}
        self._city_cache: Dict[str, str] = {}

        try:
            import geoip2.database
            self._asn_reader = geoip2.database.Reader(asn_db_path)
        except Exception as e:
            log.warning("ASN GeoIP DB unavailable (%s): %s", asn_db_path, e)

        try:
            import geoip2.database
            self._city_reader = geoip2.database.Reader(city_db_path)
        except Exception as e:
            log.warning("City GeoIP DB unavailable (%s): %s", city_db_path, e)

    def get_asn(self, ip: str) -> str:
        if _is_private(ip):
            return "PRIVATE"
        if ip in self._asn_cache:
            return self._asn_cache[ip]
        result = "UNKNOWN"
        if self._asn_reader is not None:
            try:
                resp = self._asn_reader.asn(ip)
                result = f"AS{resp.autonomous_system_number}"
            except Exception:
                pass
        self._asn_cache[ip] = result
        return result

    def get_city(self, ip: str) -> str:
        if _is_private(ip):
            return "PRIVATE"
        if ip in self._city_cache:
            return self._city_cache[ip]
        result = "UNKNOWN"
        if self._city_reader is not None:
            try:
                resp = self._city_reader.city(ip)
                result = resp.city.name or "UNKNOWN"
            except Exception:
                pass
        self._city_cache[ip] = result
        return result

    def close(self) -> None:
        if self._asn_reader is not None:
            try:
                self._asn_reader.close()
            except Exception:
                pass
        if self._city_reader is not None:
            try:
                self._city_reader.close()
            except Exception:
                pass
