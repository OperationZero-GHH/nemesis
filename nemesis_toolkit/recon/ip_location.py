"""IP geolocation with optional local MaxMind databases or ipinfo.io."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

from ..core.config import get_settings
from ..core.http_client import AsyncHTTPClient
from ..core.models import Finding

HOSTING_KEYWORDS = (
    "hosting",
    "host",
    "cloud",
    "server",
    "data center",
    "datacenter",
    "colo",
    "digitalocean",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "ovh",
    "hetzner",
    "linode",
    "leaseweb",
    "vultr",
    "contabo",
    "m247",
    "choopa",
    "gcore",
    "oracle",
    "alibaba",
    "tencent",
    "cdn",
    "fastly",
    "akamai",
    "cloudflare",
)
VPN_KEYWORDS = ("vpn", "proxy", "tor", "exit node", "private internet", "nordvpn", "expressvpn")


def _resolve_ip(target: str) -> str:
    try:
        return str(ipaddress.ip_address(target.strip().strip("[]")))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {target!r}: {exc}") from exc
    preferred = [info[4][0] for info in infos if info[0] == socket.AF_INET]
    values = preferred or [info[4][0] for info in infos]
    if not values:
        raise ValueError(f"No addresses found for {target!r}.")
    return values[0]


def _is_public(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)


def _keyword_flags(org: str) -> tuple[bool, bool]:
    text = org.lower()
    hosting = any(keyword in text for keyword in HOSTING_KEYWORDS)
    vpn = any(keyword in text for keyword in VPN_KEYWORDS)
    return hosting, vpn


def _local_lookup(ip: str) -> dict[str, Any] | None:
    settings = get_settings()
    city_path = Path(settings.geoip_db_path).expanduser() if settings.geoip_db_path else None
    asn_path = (
        Path(settings.geoip_asn_db_path).expanduser() if settings.geoip_asn_db_path else None
    )
    if not city_path and not asn_path:
        return None
    data: dict[str, Any] = {"source": "maxmind"}
    try:
        from geoip2.database import Reader  # type: ignore
        from geoip2.errors import AddressNotFoundError  # type: ignore
    except ImportError:
        return {"source": "maxmind", "error": "geoip2 package is not installed"}
    city = None
    asn = None
    try:
        if city_path and city_path.exists():
            with Reader(str(city_path)) as reader:
                try:
                    city = reader.city(ip)
                except AddressNotFoundError:
                    city = None
        if asn_path and asn_path.exists():
            with Reader(str(asn_path)) as reader:
                try:
                    asn = reader.asn(ip)
                except AddressNotFoundError:
                    asn = None
    except Exception as exc:
        data["error"] = f"MaxMind lookup failed: {exc}"
        return data
    if city:
        data.update(
            {
                "country": city.country.name,
                "country_code": city.country.iso_code,
                "city": city.city.name,
                "region": city.subdivisions.most_specific.name if city.subdivisions else None,
                "latitude": city.location.latitude,
                "longitude": city.location.longitude,
                "timezone": city.location.time_zone,
                "postal_code": city.postal.code,
            }
        )
    if asn:
        data.update(
            {
                "asn": f"AS{asn.autonomous_system_number}" if asn.autonomous_system_number else None,
                "org": asn.autonomous_system_organization,
                "asn_number": asn.autonomous_system_number,
            }
        )
    return data


async def _ipinfo_lookup(ip: str, *, aggressive: bool) -> dict[str, Any]:
    settings = get_settings()
    token = settings.api_key("ipinfo_token")
    params: dict[str, str] = {}
    if token:
        params["token"] = token
    async with AsyncHTTPClient(module="iplocation", aggressive=aggressive) as client:
        response = await client.get(
            f"https://ipinfo.io/{ip}/json",
            module="iplocation",
            params=params or None,
            timeout=15.0,
        )
    if response.status_code == 429:
        raise RuntimeError("ipinfo.io rate limit reached. Configure ipinfo_token or a local MaxMind database.")
    if response.status_code != 200:
        raise RuntimeError(f"ipinfo.io returned HTTP {response.status_code}.")
    try:
        data: dict[str, Any] = response.json()
    except ValueError as exc:
        raise RuntimeError("ipinfo.io returned invalid JSON.") from exc
    data["source"] = "ipinfo"
    return data


async def run(
    target: str,
    *,
    aggressive: bool = False,
) -> list[Finding]:
    """Geolocate a public IP or hostname without scanning it."""
    ip = _resolve_ip(target)
    if not _is_public(ip):
        return [
            Finding(
                type="ip_location",
                target=target,
                module="iplocation",
                evidence=f"{ip} is a private, loopback, link-local or reserved address.",
                severity="info",
                confidence="high",
                metadata={"ip": ip, "private": True},
            )
        ]
    data = _local_lookup(ip)
    source = "maxmind"
    if not data or not data.get("country"):
        source = "ipinfo"
        data = await _ipinfo_lookup(ip, aggressive=aggressive)
    org = str(data.get("org") or data.get("asn") or "")
    hosting, vpn = _keyword_flags(org)
    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    if isinstance(privacy, dict):
        vpn = vpn or bool(privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"))
        hosting = hosting or bool(privacy.get("hosting"))
    asn = data.get("asn")
    # ipinfo.io embeds ASN in the org field (e.g. "AS15169 Google LLC")
    if not asn and org and org.upper().startswith("AS"):
        asn = org.split(" ", 1)[0]
    if isinstance(asn, str) and " " in asn:
        asn = asn.split(" ", 1)[0]
    location = data.get("city") or data.get("region") or data.get("country") or "unknown"
    evidence_parts = [
        f"{ip} — {location}",
        f"country: {data.get('country') or data.get('country_code') or 'unknown'}",
        f"ASN: {asn or 'unknown'}",
        f"org: {org or 'unknown'}",
        f"hosting: {'yes' if hosting else 'no/unknown'}",
        f"VPN/proxy: {'yes' if vpn else 'no/unknown'}",
    ]
    metadata = {
        "ip": ip,
        "source": source,
        "country": data.get("country") or data.get("country_code"),
        "city": data.get("city"),
        "region": data.get("region"),
        "asn": asn,
        "org": org,
        "hosting": hosting,
        "vpn": vpn,
        "latitude": data.get("latitude") or data.get("loc", "").split(",")[0] if data.get("loc") else data.get("latitude"),
        "longitude": data.get("longitude") or data.get("loc", "").split(",")[-1] if data.get("loc") else data.get("longitude"),
        "timezone": data.get("timezone"),
    }
    return [
        Finding(
            type="ip_location",
            target=target,
            module="iplocation",
            evidence=" — ".join(evidence_parts),
            severity="info",
            confidence="high" if source == "maxmind" else "medium",
            metadata=metadata,
        )
    ]
