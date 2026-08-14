"""Address classification and optional GeoIP enrichment."""

from .addresses import SCOPES, classify_address, is_private
from .geoip import Enricher, GeoIPLookup, NullEnricher, build_enricher

__all__ = [
    "classify_address",
    "is_private",
    "SCOPES",
    "GeoIPLookup",
    "Enricher",
    "NullEnricher",
    "build_enricher",
]
