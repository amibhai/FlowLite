"""Optional MaxMind GeoLite2 enrichment.

GeoIP is strictly optional. When ``geoip2`` is absent, the databases are missing
or a lookup fails, enrichment returns empty strings and the pipeline continues:
an ASN lookup must never be able to stop a capture from being processed.

``geoip2.database.Reader`` is documented as thread-safe for reads, but the
memoisation caches around it are guarded anyway because several pipeline threads
share one instance.
"""

from __future__ import annotations

import threading
from typing import Dict, Tuple

from .addresses import classify_address, is_private

__all__ = ["Enricher", "NullEnricher", "GeoIPLookup", "build_enricher"]

_CACHE_LIMIT = 200_000


class Enricher:
    """Interface used by the flow writer. Scope only; no external databases."""

    def scope(self, ip: str) -> str:
        return classify_address(ip)

    def asn(self, ip: str) -> Tuple[str, str]:
        """Return ``(asn, organisation)``; empty strings when unknown."""
        return ("", "")

    def country(self, ip: str) -> str:
        return ""

    def close(self) -> None:
        return None

    def __enter__(self) -> Enricher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class NullEnricher(Enricher):
    """Enricher that reports nothing at all, including scope."""

    def scope(self, ip: str) -> str:
        return ""


class GeoIPLookup(Enricher):
    """ASN and country enrichment backed by MaxMind GeoLite2 databases."""

    def __init__(
        self,
        asn_db: str = "",
        city_db: str = "",
        logger=None,
    ) -> None:
        self.log = logger
        self._asn_reader = None
        self._city_reader = None
        self._lock = threading.Lock()
        self._asn_cache: Dict[str, Tuple[str, str]] = {}
        self._country_cache: Dict[str, str] = {}
        self.available = False

        if not asn_db and not city_db:
            return

        try:
            import geoip2.database  # type: ignore
        except ImportError:
            if logger is not None:
                logger.warning(
                    "GeoIP enrichment is enabled but the 'geoip2' package is not installed; "
                    "continuing without ASN and country data (pip install 'flowlite[geoip]')"
                )
            return

        if asn_db:
            self._asn_reader = self._open(geoip2.database, asn_db, "ASN")
        if city_db:
            self._city_reader = self._open(geoip2.database, city_db, "City")
        self.available = self._asn_reader is not None or self._city_reader is not None

    def _open(self, module, path: str, label: str):
        try:
            return module.Reader(path)
        except Exception as exc:
            if self.log is not None:
                self.log.warning(
                    "GeoIP %s database unavailable (%s): %s. Continuing without it.",
                    label,
                    path,
                    exc,
                )
            return None

    def asn(self, ip: str) -> Tuple[str, str]:
        if self._asn_reader is None or is_private(ip):
            return ("", "")
        with self._lock:
            cached = self._asn_cache.get(ip)
        if cached is not None:
            return cached
        result: Tuple[str, str] = ("", "")
        try:
            response = self._asn_reader.asn(ip)
            number = getattr(response, "autonomous_system_number", None)
            org = getattr(response, "autonomous_system_organization", "") or ""
            if number is not None:
                result = (f"AS{number}", org)
        except Exception:
            result = ("", "")
        with self._lock:
            if len(self._asn_cache) < _CACHE_LIMIT:
                self._asn_cache[ip] = result
        return result

    def country(self, ip: str) -> str:
        if self._city_reader is None or is_private(ip):
            return ""
        with self._lock:
            cached = self._country_cache.get(ip)
        if cached is not None:
            return cached
        result = ""
        try:
            response = self._city_reader.city(ip)
            result = getattr(getattr(response, "country", None), "iso_code", "") or ""
        except Exception:
            result = ""
        with self._lock:
            if len(self._country_cache) < _CACHE_LIMIT:
                self._country_cache[ip] = result
        return result

    def close(self) -> None:
        for reader in (self._asn_reader, self._city_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
        self._asn_reader = None
        self._city_reader = None
        self.available = False


def build_enricher(cfg, logger=None) -> Enricher:
    """Construct the enricher implied by configuration; never raises."""
    try:
        geo = cfg.enrich.geoip
        if geo.enabled and (geo.asn_db or geo.city_db):
            return GeoIPLookup(geo.asn_db, geo.city_db, logger=logger)
        if cfg.enrich.classify_addresses:
            return Enricher()
        return NullEnricher()
    except Exception as exc:  # configuration shapes are validated, but be safe
        if logger is not None:
            logger.warning("Falling back to scope-only enrichment: %s", exc)
        return Enricher()
