from urllib.parse import quote


def encode_location_path(path: str) -> str:
    """Encode a decoded URL path for use in a Location header."""
    return quote(path, safe="/:@")


def location_for(path: str, lookup_value: object, *, safe: str = "") -> str:
    """Append an encoded lookup value to an encoded collection path."""
    return encode_location_path(path) + quote(str(lookup_value), safe=safe)
