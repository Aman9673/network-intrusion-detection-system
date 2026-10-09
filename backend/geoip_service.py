import ipaddress
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError


# ============================================================
# GEOIP DATABASE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

GEOIP_DB = (
    BASE_DIR
    / "geoip"
    / "GeoLite2-City.mmdb"
)


_reader = None


# ============================================================
# LOAD DATABASE
# ============================================================

def get_reader():

    global _reader

    if _reader is not None:
        return _reader

    if not GEOIP_DB.exists():

        print(
            f"[GeoIP] Database not found: {GEOIP_DB}"
        )

        return None

    try:

        _reader = geoip2.database.Reader(
            str(GEOIP_DB)
        )

        print(
            "[GeoIP] Database loaded successfully"
        )

        return _reader

    except Exception as error:

        print(
            f"[GeoIP] Database loading error: {error}"
        )

        return None


# ============================================================
# PRIVATE IP CHECK
# ============================================================

def is_private_ip(ip):

    try:

        address = ipaddress.ip_address(
            str(ip)
        )

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )

    except ValueError:

        return True


# ============================================================
# GEOIP LOOKUP
# ============================================================

def lookup_ip(ip):

    ip = str(ip or "").strip()

    if not ip:

        return {
            "ip": ip,
            "status": "invalid",
            "country": None,
            "country_code": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }


    # --------------------------------------------------------
    # PRIVATE IP
    # --------------------------------------------------------

    if is_private_ip(ip):

        return {
            "ip": ip,
            "status": "private",
            "country": "Private Network",
            "country_code": None,
            "city": "Local Network",
            "latitude": None,
            "longitude": None,
        }


    reader = get_reader()

    if reader is None:

        return {
            "ip": ip,
            "status": "database_unavailable",
            "country": None,
            "country_code": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }


    try:

        response = reader.city(ip)

        country = (
            response.country.name
            or "Unknown"
        )

        country_code = (
            response.country.iso_code
        )

        city = (
            response.city.name
            or "Unknown"
        )

        latitude = (
            response.location.latitude
        )

        longitude = (
            response.location.longitude
        )

        return {
            "ip": ip,
            "status": "success",
            "country": country,
            "country_code": country_code,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
        }


    except AddressNotFoundError:

        return {
            "ip": ip,
            "status": "not_found",
            "country": "Unknown",
            "country_code": None,
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }


    except Exception as error:

        print(
            f"[GeoIP] Lookup error for {ip}: {error}"
        )

        return {
            "ip": ip,
            "status": "error",
            "country": None,
            "country_code": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }